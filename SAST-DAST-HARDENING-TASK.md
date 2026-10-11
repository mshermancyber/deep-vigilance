# Deep Vigilance — SAST/DAST Detection Hardening (CTI Advisory + Implementation Task)

**Author:** Fable, acting as cyber threat-intel advisor. **Executor:** Cobra Commander orchestrator →
OpenAI workers. **Target project:** the project root (work in place — no links, no moves).
**Do NOT bridge to osint.** Do NOT run/authenticate against the live DV backend — build code + rules
+ tests only. `npm run build` (tsc, both packages) must stay green.

---

## A. Threat-intel assessment (current state)

DV has broad rule *breadth* but shallow detection *depth*.

- **SAST is ~115–130 LIVE regex rules, matched single-line** (`scanners/src/sast/all-rules.ts`
  `scanFileWithAllRules`, mirrored in `sast-worker.ts`). Single-line regex cannot follow taint across
  lines or functions → high false-negatives on renamed variables, multi-line sinks, interprocedural
  flows. Rule sources: `engine.ts` (15 core), `rule-expansion.ts` (~84 generated — note it *claims*
  620), `framework-rules.ts` (17), `semgrep-rules-bundle.ts`.
- **Sophisticated engines exist but are DORMANT — not invoked by `sast-worker.ts`:**
  `ast-engine.ts` (CFG/call-graph, TaintSource/TaintSink), `dataflow-engine.ts` (source→sink→sanitizer
  maps), `reachability-engine.ts`, `precision-engine.ts`, `custom-rule-engine.ts` (Semgrep-style YAML).
  **The teeth are built and sitting on the bench.**
- **DAST breadth is decent** (`dast/engine.ts` 10 active, `enterprise-dast.ts` 8 advanced,
  `blind-sqli.ts` time/boolean, `passive-scanner.ts` ~34 checks, nuclei/nikto shell-outs) but detection
  is **payload + regex-on-response + timing only. No out-of-band (OOB) interaction server**, so blind
  SSRF / blind RCE / blind XXE / OOB SQLi are effectively undetected.
- **Empty categories:** the "Infrastructure/IaC" SAST category claims 43 rules and **generates none** —
  no Terraform/K8s/Docker/cloud-misconfig detection despite a cloud-heavy estate.

Prioritization below is threat-informed (CISA KEV, OWASP Top 10 2021, OWASP API Top 10 2023, CWE Top
25) — weighted by what attackers actually exploit, not checklist completeness.

---

## B. P0 — highest teeth-per-effort (do first)

### P0.1 — Activate the dormant taint/dataflow engine in the SAST worker
The single biggest sharpening move, and it is mostly WIRING, not net-new.
- In `sast-worker.ts`, after the regex pass, run `dataflow-engine.ts` (+ `ast-engine.ts` where a parse
  is available) for the injection classes (SQLi, CMDi, XSS, SSRF, path-traversal, deserialization,
  SSTI, open-redirect). Emit a finding only when a **tainted source reaches a dangerous sink** without
  a recognized sanitizer; carry the source→sink trace in `metadata`.
- Use `reachability-engine.ts` + `precision-engine.ts` to set `confidence` (regex-only = lower;
  taint-confirmed = high). Keep the regex rules as a fast pre-filter/candidate generator.
- **Framework-aware sources/sinks:** wire the source/sink maps for Express (`req.query/body/params`),
  Flask/Django (`request.args/form`), Spring (`@RequestParam/@PathVariable`), and their sinks
  (`exec`, `query`, `innerHTML`, `render_template_string`, `ObjectInputStream`, url-fetch).
- Acceptance: a multi-line SQLi/XSS fixture where source and sink are on different lines is now caught,
  and a sanitized fixture is NOT (proves taint, not regex).

### P0.2 — DAST out-of-band (OOB) interaction server for blind vulns
- Add `scanners/src/dast/oob-interaction.ts`: a lightweight self-hosted HTTP(+DNS if feasible)
  listener that mints unique correlation tokens/subdomains per probe and records callbacks
  (collaborator-style, but self-hosted — no third-party service).
- Wire OOB payloads into SSRF, XXE, RCE/CMDi, and SQLi checks (e.g. `http://<token>.oob.local/`,
  XXE external entity to the listener, `nslookup <token>.oob.local`). A recorded callback = confirmed
  blind finding (severity High/Critical, `evidence` = interaction record).
- This directly closes **blind SSRF → cloud credential theft** (the primitive our attack-path engine
  models). Acceptance: a blind-SSRF test app triggers an OOB callback and produces a finding.

---

## C. P1 — fill the exploited-class gaps (data-driven rule packs)

Add these as **data rules in the existing shapes** — `SastRule` (`engine.ts` interface:
`id,name,severity,cweId,owaspCategory,languages[],patterns:RegExp[],excludePatterns?,recommendation,
cvssScore,cvssVector,category`) and `DastAttack` (`engine.ts`: `id,payloads[],attackType,
detectPatterns:RegExp[],cvss…`). Prefer the richer `custom-rule-engine.ts` `CustomRule` (Semgrep-style)
for anything needing patternEither/context. Register new SAST rule arrays into `ALL_RULES`.

### P1.1 — IaC / cloud / container misconfig (populate the EMPTY Infrastructure category)
High value given the cloud estate. New file `scanners/src/sast/iac-rules.ts`:
- **Terraform:** ingress `cidr_blocks = ["0.0.0.0/0"]`; S3 `acl = "public-read"` / public bucket
  policy; EC2 `metadata_options` without `http_tokens = "required"` (IMDSv1); IAM policy `"Action":"*"`
  or `"Principal":"*"` / wildcard AssumeRole trust; unencrypted EBS/RDS/S3; public RDS
  `publicly_accessible = true`.
- **Dockerfile:** no/`USER root`; `ADD` from remote URL; `:latest`; secrets in `ENV`/`ARG`; `curl … |
  sh`; running as UID 0.
- **Kubernetes YAML:** `privileged: true`, `hostNetwork/hostPID/hostIPC`, `allowPrivilegeEscalation`,
  `runAsNonRoot: false`, missing resource limits, wildcard RBAC (`verbs/resources: ["*"]`),
  `automountServiceAccountToken` unset.
- **CloudFormation:** the S3/SG/IAM equivalents.
Map to CWE-16/CWE-732/CWE-284 and OWASP A05:2021. These findings should also be shaped to export as
attack-path footholds where relevant (e.g. IMDSv1, wildcard trust) — DV-local feed only.

### P1.2 — API security (OWASP API Top 10 2023) — DAST
New file `scanners/src/dast/api-security.ts` (auth-context aware; needs two credential sets in scan
config):
- **BOLA/IDOR (API1):** enumerate/swap object IDs across two sessions; unauthorized access = finding.
- **BFLA (API5):** invoke privileged/admin endpoints with a low-priv token.
- **Mass assignment (API6):** add unexpected fields (`"role":"admin"`, `"isAdmin":true`, `"verified":
  true`) to write requests; reflected/persisted = finding.
- **Excessive data exposure (API3)** and **no rate limiting (API4)** passive/active checks.
- Prefer OpenAPI/Swagger-driven enumeration when a spec URL is provided.

### P1.3 — Threat-informed SAST rule pack (RCE-class first)
New file `scanners/src/sast/threat-pack-rules.ts`:
- **Insecure deserialization (CWE-502, RCE):** Java `ObjectInputStream.readObject`, `XMLDecoder`,
  SnakeYAML `Yaml().load(`, Jackson `enableDefaultTyping`/`@JsonTypeInfo`; Python `pickle.load(s)`,
  `yaml.load(` w/o SafeLoader, `marshal.loads`; PHP `unserialize(`; .NET `BinaryFormatter`/`LosFormatter`
  /`TypeNameHandling=All`; Ruby `Marshal.load`/`YAML.load`.
- **SSTI (CWE-1336/94, RCE):** Jinja2 `render_template_string(`/`Template(`+var; Spring SpEL
  `SpelExpressionParser`; Freemarker/Velocity/Handlebars/Twig/ERB/Pug with interpolated user input.
- **JNDI / Log4Shell (CWE-917):** `${jndi:`, `InitialContext().lookup(`+var, vulnerable Log4j versions.
- **JWT flaws (CWE-347):** `algorithms:['none']`/alg:none accepted, `decode()` without `verify()`,
  hardcoded HMAC secret, `kid`/`jku`/`x5u` taken from token → SSRF/confusion.
- **NoSQL injection (CWE-943):** Mongo `$where`+var, `find(req.body)`, `$regex` from input.
- **GraphQL:** introspection enabled in prod, no depth/complexity limit, batching DoS.
- **Go (gosec-style):** `fmt.Sprintf`→SQL, `exec.Command`+input, `math/rand` for tokens,
  `http.Get(userURL)` SSRF, `tls.Config{InsecureSkipVerify:true}`.
- **Rust:** `Command::new`+input, `unsafe` blocks around FFI with external data.
- **CI / supply chain:** GitHub Actions `pull_request_target` + `actions/checkout` of PR ref;
  `${{ github.event.* }}` interpolated into `run:` (script injection); unpinned `uses: …@main`.
- **De-dup note:** hardcoded-secret SAST should DEFER to the new secret scanner
  (`secrets-engine.ts`) to avoid double-reporting — keep only a high-entropy inline heuristic.

---

## D. P2 — precision + correlation (fewer false positives, richer findings)
- Wire `precision-engine.ts` + `reachability-engine.ts` so confidence reflects reachability; suppress
  findings in dead/test code.
- Add **CVE/EPSS correlation** to the live SAST path (fields exist in the store: `cve_id`, `epss`) —
  when a rule maps to a known-exploited pattern, attach KEV/EPSS context to raise priority.
- **DAST auth/session depth:** session-fixation active probe, CSRF token presence+validation check,
  privilege-escalation via IDOR with dual sessions, OAuth/OIDC redirect-uri/`state` checks.
- Make nuclei/nikto **optional/graceful** — never fail a scan if the external binary is absent
  (the core teeth must be self-contained).

---

## E. Deliverables & acceptance criteria
1. P0.1 wiring + P0.2 OOB server; P1.1/P1.2/P1.3 new rule files registered; P2 where scoped.
2. All new SAST rules appended into `ALL_RULES`; new DAST checks into the attack arrays; use the
   existing `SastRule`/`DastAttack`/`CustomRule` shapes — **data-driven, no bespoke per-rule code.**
3. Every new rule carries `cweId`, `owaspCategory`, `severity`+rank, `cvssScore/Vector`,
   `recommendation`, `references`.
4. **Fixture tests (mandatory):** a `true-positive` corpus (one vulnerable snippet per new class) and a
   `false-positive` corpus (sanitized/benign equivalents). Assert new-class recall ≥0.90 and that the
   sanitized equivalents do NOT fire (proves taint/precision, not blind regex). Synthetic code only.
5. `npm run build` green (backend + scanners tsc). No regression in existing rule pass.
6. Report a coverage delta: live rule count before/after, new vuln classes, new languages (Go/Rust/
   IaC), and blind-vuln (OOB) capability status.

## F. Scope discipline
Prioritize P0 then P1; P2 if budget allows. Do NOT invent a new engine — REUSE the dormant
`dataflow-engine.ts`/`ast-engine.ts`/`custom-rule-engine.ts` already on disk. Keep detection
deterministic and self-contained (no reliance on external binaries or third-party services for core
teeth). Work in the project root in place.
