# Credential / Secrets Exposure Hunter — Detection Ruleset (master spec)

**Authored by:** Fable (design artifact — the "rules"). Implemented independently in each host
project (`a separate OSINT project`, `the project root`) as its own copy. **The two host projects do NOT share
code or bridge** — this doc is copied into each; the runtime modules are separate.

## 0. Scope & posture (read first)

Purpose: find **our own** leaked credentials/secrets before an attacker does — in homelab repos,
in our GitHub/GitLab orgs' commit history, and in public paste-style feeds mentioning our org — so we
can rotate them. This is **defensive exposure monitoring** (class: gitleaks / trufflehog /
detect-secrets / GitHub secret-scanning).

**In scope:** detection, classification, confidence scoring, redaction, alerting, and exporting hits
as *footholds* to the attack-path engine (blast-radius modeling).

**Explicitly OUT of scope (deliberate safety choice):** the hunter never authenticates with, replays,
or otherwise *uses* a discovered credential. There is **no live credential validation**. False
positives are cut with entropy + a classifier + denylists (§5), not by testing secrets against
providers. Only detect/score/redact/report. (If validity-checking is ever wanted it is a separate,
explicitly-gated capability — not built here.)

Every persisted record stores a **redacted** secret only (§8). Raw secrets never hit disk/DB/logs.

## 1. Detection architecture — 4 layers (defense-in-depth for precision)

```
candidate string ─▶ L1 signature match ─▶ L2 entropy gate ─▶ L3 context boost ─▶ L4 FP classifier ─▶ finding
                    (provider regex)       (Shannon)          (key-name/path)     (confidence + verdict)
```

- **L1 Signatures (high fidelity):** provider-specific regex with known prefixes/structure. A match
  is high base-confidence on its own.
- **L2 Entropy (recall for unknown secrets):** for generic assignments (`key = "…"`) with no L1 hit,
  gate on Shannon entropy + length + charset (§4). Catches bespoke/unknown tokens.
- **L3 Context (precision boost):** key-name (`password`, `secret`, `api_key`, `token`,
  `private_key`), assignment form, file path/type, proximity keywords → adjust confidence.
- **L4 FP classifier (precision):** feature-scored verdict that suppresses placeholders, test data,
  hashes/UUIDs/git-SHAs, and doc examples (§5). Deterministic scorer by default; optional trained
  model slot.

## 2. Signature catalog (L1) — the core rule set

Each rule: `id`, `provider`, `type`, `regex` (PCRE), `confidence` (base, 0–1), `entropy_floor`
(min Shannon on the captured secret, or `null` if structure alone suffices), `foothold_kind`.
Regexes anchor on prefix/length/charset to minimize FPs. (Implement the capture group as group 1.)

| id | provider / type | pattern sketch | conf | entropy_floor |
|----|-----------------|----------------|------|---------------|
| aws_akia | AWS access key id | `\b(AKIA[0-9A-Z]{16})\b` | 0.9 | null |
| aws_secret | AWS secret key | 40-char base64 near `aws`/`secret` | 0.75 | 4.2 |
| aws_session | AWS session token | `\b(ASIA[0-9A-Z]{16})\b` | 0.85 | null |
| gcp_api | Google API key | `\b(AIza[0-9A-Za-z\-_]{35})\b` | 0.9 | null |
| gcp_sa_key | GCP service-account JSON | `"private_key":\s*"-----BEGIN PRIVATE KEY` | 0.95 | null |
| azure_sas | Azure SAS / storage key | `sig=[A-Za-z0-9%]{43,}` / 88-char b64 | 0.7 | 4.5 |
| github_pat | GitHub PAT (classic/fine) | `\b((ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36})\b` | 0.95 | null |
| github_fine | GitHub fine-grained | `\b(github_pat_[0-9A-Za-z_]{82})\b` | 0.95 | null |
| gitlab_pat | GitLab PAT | `\b(glpat-[0-9A-Za-z\-_]{20})\b` | 0.95 | null |
| slack_token | Slack token | `\b(xox[baprs]-[0-9A-Za-z-]{10,})\b` | 0.9 | null |
| slack_webhook | Slack webhook | `hooks.slack.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]{24}` | 0.9 | null |
| stripe_live | Stripe secret | `\b((sk|rk)_live_[0-9A-Za-z]{24,})\b` | 0.95 | null |
| twilio | Twilio SID/token | `\bAC[0-9a-f]{32}\b` + `SK[0-9a-f]{32}` | 0.85 | null |
| sendgrid | SendGrid key | `\b(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b` | 0.9 | null |
| npm_token | npm token | `\b(npm_[0-9A-Za-z]{36})\b` | 0.9 | null |
| pypi_token | PyPI token | `\b(pypi-AgEIcHlwaS[0-9A-Za-z\-_]{50,})\b` | 0.9 | null |
| jwt | JSON Web Token | `\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b` | 0.6 | null |
| private_key | PEM private key | `-----BEGIN (RSA\|EC\|OPENSSH\|DSA\|PGP\|PRIVATE) (PRIVATE )?KEY-----` | 0.97 | null |
| ssh_privkey | OpenSSH key body | `-----BEGIN OPENSSH PRIVATE KEY-----` | 0.97 | null |
| db_url | DB connection string w/ creds | `(postgres\|mysql\|mongodb(\+srv)?\|redis)://[^:@\s]+:[^@\s]+@` | 0.85 | null |
| basic_auth_url | creds in URL | `https?://[^:@/\s]+:[^@/\s]+@` | 0.7 | null |
| generic_secret | high-entropy assigned to secret key | key-name + quoted value | 0.4 | 4.0 |
| jenkins | Jenkins/CI token | `\b[0-9a-f]{32,34}\b` near `token` | 0.5 | 3.7 |
| dockerhub | Docker registry auth | `"auths":\s*{[^}]*"auth":\s*"[A-Za-z0-9+/=]{20,}"` | 0.8 | null |
| heroku | Heroku API key | UUID near `heroku` | 0.7 | null |
| openai | OpenAI key | `\b(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})\b` | 0.9 | null |
| anthropic | Anthropic key | `\b(sk-ant-[0-9A-Za-z\-_]{90,})\b` | 0.9 | null |

Catalog is extensible — this is the seed set (~28 rules). Provider prefixes/lengths are the public,
documented token formats. Keep the table data-driven (one JSON/TS/py structure) so new signatures are
a data edit, not code.

## 3. Contextual detection (L3)

- **Key-name triggers:** `password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|
  client[_-]?secret|auth|credential|bearer` (case-insensitive) on the LHS of an assignment.
- **Assignment forms:** `KEY = "…"`, `KEY: "…"`, `KEY=…` (env/dotenv), YAML/JSON `"key": "…"`,
  `export KEY=…`, `--key=…` (CLI), HTTP `Authorization: Bearer …`.
- **Path/type weighting:** `.env`, `.pem`, `.pfx`, `id_rsa`, `credentials`, `.npmrc`, `.pypirc`,
  `*.tfvars`, `settings.py`, `application*.yml`, dockerfiles, CI YAML → boost. `*.md`, `*.example`,
  `test/`, `fixtures/`, `__mocks__/`, `spec/` → damp.

## 4. Entropy model (L2)

Shannon entropy H(s) = −Σ p(c)·log2 p(c) over the char distribution of the captured value.
- **Charset-aware floors:** base64/base62 secrets → H ≥ 4.0 bits/char; hex → H ≥ 3.0 (hex maxes ~4).
- **Length floor:** ≥ 16 chars for generic; provider rules use their own length.
- **Normalize** by max entropy for the detected charset to get a 0–1 `entropy_score`.
- Entropy is a *gate + feature*, never a sole trigger (too noisy alone) — it only fires generic
  detections and feeds the classifier.

## 5. False-positive classifier (L4) — precision

Default = **deterministic feature scorer** (no training-data dependency); optional trained-model slot
(logistic regression / gradient-boosted trees) if a labeled corpus is provided.

**Features** (per candidate): `entropy_score`, `length`, `charset_diversity`, `has_provider_prefix`,
`key_name_hit`, `path_weight`, `looks_like_hash` (matches md5/sha1/sha256/git-sha regex),
`looks_like_uuid`, `is_sequential_or_repeated`, `in_denylist`, `is_placeholder`, `dictionary_ratio`
(fraction of value that is english words → likely prose), `distance_to_secret_keyword`.

**Hard suppressors (verdict = false_positive regardless of score):**
- **Denylist** of famous example creds: `AKIAIOSFODNN7EXAMPLE`,
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, `EXAMPLE`, `xxxxxxxx`, `0000…`, `1234…`,
  `changeme`, `your_api_key`, `<...>`, `${...}`, `{{...}}` (template vars), `process.env.*`,
  `os.environ*`.
- **Placeholder shape:** all-same-char, sequential runs, `redacted`, `dummy`, `sample`, `test`,
  `foo/bar/baz`.
- **Structural non-secret:** valid UUID, git SHA (40-hex in a `.git`/commit context), md5/sha of a
  known file, base64 that decodes to printable english.

**Confidence** = `base_signature_conf × classifier_score`, clamped [0,1]. Map to severity:
`≥0.85 Critical · 0.65 High · 0.45 Medium · else Low/Info`. Below a `min_report` threshold (default
0.4) → dropped or parked as "suspected" (host-project decides).

## 6. Scan surfaces (sources)

Pluggable **source adapters** — a small interface (`enumerate() -> stream of {content, location}`),
so each project wires the adapters it wants:

1. **git_history** — walk full commit history across all branches/refs of a local repo (secrets live
   in *deleted* lines; scan the diff of every commit, not just HEAD). Report commit + file + line.
2. **repo_fs** — walk a working tree (respect `.gitignore` optionally); for homelab repos on disk.
3. **github_org / gitlab_group** — via API token (read-only scopes): enumerate org repos, scan
   default branch + optionally history; and consume push/webhook events for near-real-time. **Scope =
   our own orgs** (configured allowlist of org/group names). Rate-limit aware.
4. **paste_monitor** — poll public paste-style feeds for content matching our **org selectors**
   (domains, internal hostnames, project code-names, known key prefixes). Detection only; we monitor
   for *our* exposure. Configurable, off by default, with backoff + ToS-respecting polling.

Each adapter is config-driven (allowlists, tokens via the host project's secret store — never
hardcoded). Adapters are independent; a project can enable a subset.

## 7. Output finding schema (host-native + foothold mapping)

Canonical finding (each project maps it into its own store/types):
```json
{
  "id": "SEC-<hash>",
  "secret_type": "aws_akia",
  "provider": "AWS",
  "confidence": 0.93,
  "severity": "Critical",
  "verdict": "confirmed|suspected|false_positive",
  "source": "github_org|gitlab_group|git_history|repo_fs|paste_monitor",
  "location": { "repo": "...", "ref": "commit_sha", "path": "...", "line": 42, "url": "..." },
  "redacted": "AKIA…7QET",
  "secret_sha256": "<hex>",
  "first_seen": "<iso8601>", "last_seen": "<iso8601>",
  "remediation": "rotate + revoke; scrub history",
  "foothold": { "ref": "<AKIA… | principal | host>", "kind": "leaked_access_key|hardcoded_cred|exposed_token",
                "source": "<adapter>", "note": "<secret_type @ location>" }
}
```

## 8. Redaction & safe storage (mandatory)

- Store `redacted` = first4 + `…` + last4 (or provider-appropriate mask) and `secret_sha256` only.
- **Never** persist or log the raw secret. Scanners hold it in-memory only long enough to hash+redact.
- Dedup by `secret_sha256 + location`. Re-detections update `last_seen`.

## 9. Foothold export to the attack-path engine

Emit a feed compatible with the engine's recon hook (`osint_exposed_creds.json` shape):
`{ "exposed": [ { "ref", "kind", "source", "note" }, … ] }`, derived from `finding.foothold` of all
`confirmed` findings. This is a one-way *export/ingest* (a file/endpoint the engine reads) — **not a
bridge between osint and deep-vigilance**; each project emits its own feed independently.

## 10. Evaluation harness (ship with each build)

A seeded **fixture corpus**: a `positives/` set (one file per signature type with a synthetic but
format-valid secret) + a `negatives/` set (placeholders, hashes, UUIDs, example keys, prose). The
build must include a test that runs the detector over the corpus and asserts **precision ≥ 0.95 and
recall ≥ 0.90** on it. Synthetic secrets only — never real ones.
