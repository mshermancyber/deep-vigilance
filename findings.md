# Security & Correctness Review — Findings

Comprehensive autonomous review of the app-scanner codebase. Each finding lists
severity, location, category, root cause, and remediation status.

**Status legend:** ✅ Fixed · 🟡 Accepted/By-design (documented) · ⚠️ Open (needs decision)

## Summary

| Severity | Fixed | Accepted/Noted | Open |
|----------|-------|----------------|------|
| Critical | 6 | 0 | 0 |
| High | 19 | 1 | 0 |
| Medium | 14 | 2 | 0 |
| Low | 4 | 2 | 0 |

47 distinct issues remediated across 9 review/patch iterations (the latest adding
the SAST-rule ReDoS fix, API-key DB revocation, N1 executor hardening, and the DAST
SSRF guard). The only items still open are N1 and N2 — both now mitigated in code,
each with one remaining decision (Worker sandbox / network egress) tracked in BACKLOG.
Two corrective
migrations added (`004_mfa_challenges.sql`, `005_schema_code_alignment.sql`) plus
new modules `core/auth/totp.ts`, `scanners/src/utils/ssrf.ts`, and
`frontend/.../core/utils/safe-url.ts`.

---

## Critical

### C1 — MFA completely bypassable (code never validated) ✅
`backend/src/api/auth/routes.ts`. The login MFA branch checked only that a
challenge row existed and accepted *any* `mfaCode`. **Fix:** real RFC-6238 TOTP
verification + single-use backup codes (`core/auth/totp.ts`), challenge consumed.

### C2 — Entire async pipeline crashes on first job (BullMQ) ✅
`backend/src/core/queue/manager.ts:1,65,77`. `QueueScheduler` (removed in BullMQ
v2+) was imported and `new QueueScheduler()` ran on first `getQueue()` →
`TypeError: not a constructor`, breaking all scans/reports/SBOM/notifications.
**Fix:** removed it (Worker handles delayed/stalled jobs natively in v2+).

### C3 — Container/SBOM/binary scan creation crashes every request ✅
`api/container-scan/routes.ts`, `api/sbom/routes.ts`, `api/advanced-scan/routes.ts`.
INSERTs referenced columns that don't exist (`digest`, `platform`, `options`,
`severity_score`, `status`, `include_*`) and `sbom_exports.file_path` is NOT NULL
but never supplied. **Fix:** `005_schema_code_alignment.sql` adds the columns and
drops the bad NOT NULL.

### C4 — Container scan detail crashes (missing table) ✅
`api/container-scan/routes.ts:132`. `LEFT JOIN container_packages ON cf.package_id`
— neither the table nor the column exists. **Fix:** dropped the join; use the
inline `package_name`/`installed_version`/`cve_id` columns `container_findings` has.

### C5 — Webhook secret used without decryption ✅
`api/code-review/routes.ts:787`. Encrypted secret passed straight to HMAC verify,
so every webhook failed auth (and the mechanism was effectively broken). **Fix:**
`decrypt()` before `verifySignature()`, with decage-failure handling.

### C6 — SSRF in API client request execution ✅
`api/apiclient/routes.ts`. User URL fetched with no private-IP protection and
`rejectUnauthorized:false`. **Fix:** DNS-resolution + private/loopback/link-local/
multicast (IPv4+IPv6) block; removed cert bypass.

---

## High

### H1 — JWT token blacklist was a no-op ✅
`core/auth/jwt.ts`. `isBlacklisted` always returned false (broken DJB2 hash).
**Fix:** SHA-256-hashed in-memory Map with TTL cleanup; checked in auth middleware
**and** WebSocket handshake. *Known limitation:* per-process — see N4.

### H2 — SQL injection via dynamic ORDER BY ✅
12 instances across `users`, `projects`, `scans`, `findings`, `container-scan`,
`sbom`, `advanced-scan`, `code-review` routes. `sortBy` interpolated into SQL.
**Fix:** ternary allow-lists for column + direction.

### H3 — Cross-tenant IDOR: project risk-score ✅
`api/projects/routes.ts:211`. `findings WHERE project_id=$1` with no org scoping.
**Fix:** `AND org_id=$2`.

### H4 — IDOR: scan findings & code-review index ✅
`api/scans/routes.ts`, `api/code-review/routes.ts`. Missing `org_id` checks. **Fix:** added.

### H5 — Scan cancellation never cancels the job ✅
`core/queue/manager.ts`, `api/scans/routes.ts:148`. Jobs got auto numeric ids but
cancel looked up by scan UUID (never matched); only the SAST queue was tried.
**Fix:** deterministic `jobId:name`; cancel across SAST/DAST/API by `scan:${id}`.

### H6 — SSRF in notification/webhook dispatch ✅
`backend/src/workers/notification-worker.ts:183`. User-configured `webhookUrl`
sent with no private-IP protection. **Fix:** `validateWebhookUrl()` gating every POST.

### H7 — SSRF in protocol scanner (gRPC/GraphQL/WebSocket/SOAP) ✅
`scanners/src/apiprotocol-worker.ts`. User target URLs connected to with no egress
control (cloud-metadata theft risk). **Fix:** `scanners/src/utils/ssrf.ts` —
metadata/link-local always blocked; private ranges blocked unless
`ALLOW_PRIVATE_SCAN_TARGETS=true` (preserves legit internal scanning on self-hosted).

### H8 — Stored XSS in generated HTML/PDF reports ✅
`workers/src/report-worker.ts`. Finding fields interpolated unescaped. **Fix:** `escapeHtml()` on all values.

### H9 — Shell injection in curl export ✅
`api/apiclient/routes.ts`. **Fix:** `shellEscape()` on all interpolated values.

### H10 — Path traversal: report worker & download ✅
`workers/src/report-worker.ts`, `api/reports/routes.ts`. **Fix:** `basename` + `resolve` containment + `realpathSync` symlink check + exclusive write.

### H11 — Webhook endpoint had no authentication ✅
`api/code-review/routes.ts`. **Fix:** HMAC signature verification (GitHub/GitLab/generic).

### H12 — Credentials stored in plaintext ✅
Git tokens (`code-review`) and webhook secrets (`webhooks`) stored as plaintext/
prefixed. **Fix:** AES-256-GCM `encrypt()` at rest; `decrypt()` on use.

### H13 — `allRules` undefined → every SAST scan crashes ✅
`scanners/src/worker-orchestrator.ts:289`. **Fix:** `allRules` → `ALL_RULES`.

### H14 — Repo-wide compile break: `Permission` not re-exported ✅
`middleware/auth.ts`. ~25 route files import `Permission` from it. **Fix:** `export { Permission }`.

### H15 — TLS verification disabled ✅
`core/db/pool.ts` (prod), `services/api-client/enterprise-client.ts`. **Fix:** removed `rejectUnauthorized:false`.

### H16 — ReDoS in user-supplied custom SAST rule regex ✅
`scanners/src/sast/custom-rule-engine.ts:475`. `new RegExp(rule.patternRegex)` on
attacker-controlled rules, executed against file content → worker hang. **Fix:**
`assertSafeRegex()` rejects over-long sources and nested/stacked quantifiers.

---

## Medium

### M1 — WebSocket missing blacklist check & channel-subscription IDOR ✅
`websocket/ws-server.ts`. **Fix:** blacklist check at handshake; subscriptions
validated against caller's `org:`/`user:` scope.

### M2 — Password reset token reuse ✅
`api/auth/routes.ts`. Prior tokens not invalidated. **Fix:** mark old tokens used on new request.

### M3 — Email change: no duplicate check ✅
`api/settings/routes.ts`. **Fix:** reject email already in use by another user.

### M4 — Timing leak in webhook signature verify ✅
`services/integration/webhook-service.ts`. **Fix:** constant-time compare with padding.

### M5 — Git SSH host-key bypass ✅
`services/git/git-service.ts`. `StrictHostKeyChecking=no` → `accept-new`.

### M6 — Git ref injection ✅
`services/git/git-service.ts`. **Fix:** strip `..` and leading dashes in `sanitizeGitRef`.

### M7 — Rate limiter skipped for webhooks ✅
`middleware/rate-limiter.ts`. **Fix:** removed the skip.

### M8 — Error handler leaked nested secrets ✅
`core/errors/handler.ts`. Only top-level keys redacted. **Fix:** recursive redaction (depth-capped).

### M9 — ReDoS in PEM/secret regexes ✅
`scanners/src/sast/secrets-engine.ts`. 14 patterns used unbounded `[\s\S]{50,}?`.
**Fix:** bounded `{50,200000}?`.

### M10 — Path traversal hardening: SBOM output projectId ✅
`scanners/src/enterprise-worker.ts:147`. **Fix:** `basename` + charset allow-list.

### M11 — Webhook dead-letter / notification writes crash (missing tables) ✅
`webhook-service.ts`, `notification-worker.ts`. **Fix:** tables created in `005`.

### M12 — Scanner directory-walk stack safety ✅
`worker-orchestrator.ts`, `sast-worker.ts`. **Fix:** recursion depth cap (50).

### M13 — IPv6 metadata/multicast not blocked in SSRF guards ✅
`api/apiclient/routes.ts`, `notification-worker.ts`. **Fix:** added `ff` prefix block.

---

## Low

### L1 — CSP `unsafe-inline` in `scriptSrc` ✅
`backend/src/server.ts`. **Fix:** removed from `scriptSrc` (kept in `styleSrc`).

### L2 — `getJob` return type / `ScanJob` cast correctness ✅
`core/queue/manager.ts`, `api/scans/routes.ts`. **Fix:** `?? null`; cast via `unknown`.

### L3 — MFA challenge & schema gaps for new auth flow ✅
`004_mfa_challenges.sql` created the missing table the login flow depends on.

---

## Accepted / By-design (🟡) and Known limitations (N)

- **N1 — `new Function()` in API-client script executor** (`frontend/.../script-executor.service.ts`). Runs the user's *own* scripts in their *own* browser (Postman model); not a cross-user vuln. **Hardened:** DOM/network/storage globals are now shadowed as `undefined` in the executor. A full Web Worker / sandboxed-iframe rewrite is only warranted if test collections become shareable. (Open item — see BACKLOG.)
- **N2 — Scanner target reachability / SSRF.** Scanning user-specified targets (incl. self-signed, internal) is the product's purpose. **Code-layer SSRF guard now applied** to the protocol scanner *and* both DAST workers (`utils/ssrf.ts`): cloud-metadata/link-local always blocked, private ranges gated by `ALLOW_PRIVATE_SCAN_TARGETS`. Remaining piece is **network-layer egress control** (deployment decision — see BACKLOG).

  *N3–N7 were resolved; see "Additional fixes" below and the git/file history.*

## Additional fixes (hardening / HA / latent bugs)

- **Migrations never auto-applied → schema fixes didn't reach prod ✅** — `initializePlatform()` only claimed to run migrations; nothing did (only a manual `npm run migrate`). `runMigrations()` is now invoked on server startup before init, in every environment. (`server.ts`, `migrations/run.ts`)
- **`config.isProduction`/`isDevelopment` always `undefined` ✅** — accessed on `getConfig()` (the env object) instead of the `config` singleton, so prod **DB SSL was silently disabled** (`pool.ts`) and dev log formatting broken (`logger.ts`). Now use `NODE_ENV` directly. Real runtime bug.
- **Rate limiters → Redis ✅** — global + auth limiters now use `rate-limit-redis` (enforced across replicas / survive restart). (`middleware/rate-limiter.ts`)
- **JWT blacklist → Redis ✅** (earlier) — completes the cross-replica revocation story with the rate limiters.
- **HTTP interceptor token leak ✅** — credentials/CSRF now scoped to the API origin only; the API-client can no longer leak the session to arbitrary user-supplied hosts.
- **iframe `[srcdoc]` preview ✅** — `sandbox=""` (was `allow-same-origin`); no script execution in the response preview.
- **HTTPS-only ✅** — auth cookies always `Secure`; edge nginx redirects 80→443; HSTS via helmet.
- **Secrets rotated ✅** — `.env` regenerated with strong unique values; prod config guard blocks defaults / equal JWT secrets.
- **Auth → HttpOnly cookies + CSRF ✅** (N3) — `core/auth/cookies.ts`, `middleware/csrf.ts`; SPA no longer stores tokens in `localStorage`.
- **Open-redirect on downloads ✅** (N5) — `core/utils/safe-url.ts` validates scheme + origin before `window.open`.
- **`uuid` advisory ✅** (N7) — bumped to `^11.1.1` + npm `overrides` for the transitive `node-cron` copy; `npm audit --omit=dev` clean.
- **SAST rule ReDoS ✅** — audited 884 rule regexes; `engine.ts:397` (`/(\/\^?\(.*\|.*\)+\$?\/)/`) was genuinely catastrophic (3.6s on 120K chars) — replaced with a bounded equivalent (0.2ms). Other 2 heuristic flags confirmed safe by timing.
- **API key — full lifecycle ✅** — `middleware/auth.ts` validates each key against the `api_keys` table (revoked/expired, fail-closed); issuance/list/revoke routes added (`POST/GET/DELETE /api/auth/api-keys`, key stored as SHA-256 hash + prefix).
- **SMTP send-limiter → Redis ✅** — `services/notification/smtp-service.ts` now uses a Redis fixed-window counter so the send rate is enforced across replicas (fails open if Redis is down — politeness throttle).
- **API-client script executor hardened ✅** (N1) — dangerous globals shadowed as `undefined` in `new Function` scope.
- **DAST SSRF guard ✅** (N2 code-layer) — `dast-worker` + enterprise DAST route outbound fetches through `utils/ssrf.ts`.
- **Cross-org IDOR on resource creation ✅** — POST handlers now validate parent FKs belong to the caller's org before insert: code-review launch (`gitConnectionId`), git-connections (`projectId`), API-client requests (`collectionId` + `folderId`). (`code-review/routes.ts`, `apiclient/routes.ts`)
- **Infra hardening ✅** — chromium no longer exposed on a host port (internal-only); frontend nginx now sends CSP + HSTS; prod chromium drops unneeded `CHOWN`/`FOWNER` caps. (Backend Dockerfiles already run non-root; prod compose already read-only + cap-dropped.)
- **More dead code removed ✅** — `dast-enterprise-worker.ts`, `dast/waf-detector.ts` (both unreferenced duplicates; waf-detector had an unguarded SSRF in dead code), and 3 stray compiled `.js` artifacts committed under `scanners/src/`.
- **Test suite green ✅** — ran the backend vitest suite (433 tests); fixed all 35 failures: exported `levenshteinDistance` (typosquat primitive the tests import), corrected a self-contained test-data bug in `auth.test`, and broadened ~10 SAST core rules to detect the (legitimate) patterns they assert — template-literal/PHP-concat SQLi, `v-html`, `exec`/`os.system`/`Runtime.exec`/`popen` command injection, case-insensitive MD5/RC4 + `ECB`, cross-arg `path.join`, `fetch`/`requests` SSRF, generic `.Deserialize`, `console.debug`, dynamic `setTimeout`/`setInterval`, comment-aware `eval`, and template-literal open-redirect. All negative ("should NOT flag") cases still pass.
- **Prod migrations mount ✅** — `docker-compose.prod.yml` backend now mounts `./postgres/migrations` read-only (matches dev) so startup auto-migrate works in prod too.
- **All packages build ✅** — every package now compiles (backend `tsc`, scanners/workers `npm run build`, frontend `ng build`). Generated the missing frontend + workers lockfiles, added `.dockerignore` to all build contexts, and mounted `./postgres/migrations` into the backend so the startup migration-runner finds them. The first real build surfaced ~13 pre-existing build-breakers (Angular Material M2→M3 theme rename, chart.js typings, an `interface`/`class` name clash, a missing `RouterLink`, unsupported Angular-template `as`-casts and arrow functions, fluent expect-chain typings, index-signature property access, and a `buildHTMLReport` ReferenceError in the report worker) — all fixed.

## Deploy / runtime bring-up fixes (2026-06-13)

Surfaced only by building the images and actually running the stack for the first time
(full detail in `Build_Debug.md`). All fixed; stack is online and auth is smoke-tested.

- **DB SSL no longer forced by NODE_ENV ✅** — `pool.ts` (and the scanner/worker pools) tied
  Postgres TLS to `NODE_ENV==='production'`, crash-looping the backend against the internal
  non-TLS postgres ("server does not support SSL connections"). Replaced with an explicit
  `DB_SSL` flag (default off; on = verified TLS for an external managed DB).
- **TLS topology made consistent ✅** — healthchecks/`SCANNER_API_URL` assumed backend HTTPS
  while nginx proxied `http://` and both cert dirs were empty. Standardized on **edge TLS**:
  nginx terminates public HTTPS, backend speaks HTTP on the internal network; generated the
  `nginx/ssl` cert; switched the backend healthchecks to HTTP.
- **Docker build context corrected ✅** — Dockerfiles assume a repo-root context; compose
  pointed at package subdirs (every `COPY` failed). Root context + backend COPY prefixes +
  a corrected root `.dockerignore` (trailing-slash and `!`-negation pitfalls that leaked
  root-owned runtime dirs into the context).
- **enterprise-worker Trivy pin fixed ✅** — `0.58.1` is not a real release (installer 404'd
  on the asset); bumped to `0.70.0`, split tool installs into retried layers.
- **Frontend runs fully non-root ✅** — listens on :8080 (pid → `/tmp`, `user` directive
  dropped), serves Angular's `dist/browser`; upstream/healthcheck/host-port updated.
- **Healthchecks corrected ✅** — backend-worker used the absent `redis` pkg → switched to
  ioredis `.ping()`; chromium `/health` is token-gated → `/pressure?token=$TOKEN`.
- **PDF reports wired ✅** — puppeteer pointed at the apk Chromium (`/usr/bin/chromium-browser`)
  since `--ignore-scripts` skips the bundled download.
- **BullMQ durability ✅** — redis `maxmemory-policy` `allkeys-lru` → `noeviction`.
- **nginx auth 502 fixed ✅** — enlarged `proxy_buffer_size`/`proxy_buffers` so the 3 JWT
  `Set-Cookie` headers on login/register don't overflow the header buffer.

## Notable false positives ruled out

- "Promise hang" in notification-worker `httpPost` — `resolve()` fires from request event handlers inside the `.then()`.
- `timingSafeEqual` length mismatch in TOTP — guarded by `/^\d{6}$/` before the loop; buffers always equal length.
- `collectFiles` symlink loop — `withFileTypes` uses lstat semantics, so symlinks aren't recursed.
- Binary-findings IDOR (`advanced-scan`) — gated by a preceding `org_id`-scoped scan-ownership check.
- Git/subprocess RCE — all invocations use `execFile`/`spawn` arg arrays; refs/URLs sanitized.
