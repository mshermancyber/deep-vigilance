# Build & Deploy Debug Log

Run started: 2026-06-13. Records problems encountered during the dev + prod build,
Docker image rebuilds, and bringing the stack online. Successful steps are noted briefly;
failures get root cause + fix.

## Environment
- node v22.22.2 / npm 11.16.0
- Docker 29.5.2 / Docker Compose 5.1.4
- Docker daemon: running (other unrelated stacks already up)

---

## Phase 1 — Package builds (tsc / ng)

All four packages built clean via `npm ci && npm run build`:

| Package  | npm ci | build | exit |
|----------|--------|-------|------|
| backend  | ok     | `tsc && tsc-alias` | 0 |
| scanners | ok     | `tsc` | 0 |
| workers  | ok     | `tsc` | 0 |
| frontend | ok     | `ng build` → `frontend/dist` | 0 |

**Non-fatal warnings (build still succeeds — not blockers):**
- `npm audit`: backend reports 5 vulns (3 moderate / 1 high / 1 critical) — all in the
  **dev/test** toolchain (esbuild/vite/vitest). `npm audit --omit=dev` is clean; not shipped
  to prod. Tracked in BACKLOG §2.
- Angular **NG8011** content-projection warnings on `binary-scan.component.ts` and
  `container-scan.component.ts` (`<mat-icon>` inside an `@if`/`@else` with multiple root
  nodes). Cosmetic — icons still render; left as-is.
- Angular CSS budget: `api-client.component.ts` styles 11.25 kB vs 10.24 kB budget
  (over by 1.01 kB). Warning only.
- `npm warn allow-scripts`: install scripts (esbuild/sharp/puppeteer/etc.) not auto-run
  under npm's allow-scripts policy — expected; native deps that need them are not used at
  runtime in these images.

## Phase 2 — Docker image builds (dev + prod)

**Result: ✅ all 8 images build for both dev and prod (exit 0).**
Prod (`-f docker-compose.yml -f docker-compose.prod.yml`) has no `build:` overrides — it
inherits the base build blocks, so it produces the same images.

### Problems found & fixed

**P2-1 — Build context mismatch (blocked ALL custom images).**
The scanner/report/backend Dockerfiles are written for a **repo-root** build context
(they `COPY scanners/src`, `workers/src`, `shared`, `certs`, `scripts/...`), but
`docker-compose.yml` set each service's `context:` to its package subdir (`./scanners`,
`./workers`, `./backend`). Every COPY failed with `failed to compute cache key: "/shared":
not found` (and `/scripts/health`, `/scanners/src`, etc.).
*Fix:* set `context: .` + `dockerfile: docker/Dockerfile.*` for backend, backend-worker,
sast/dast/api/enterprise workers, and report-worker; prefixed the backend builder COPYs
with `backend/`; added a root `.dockerignore` (per-package `.dockerignore` files do NOT
apply when the context is the repo root — without it the ~885 MB of node_modules + .git
would be sent to the daemon). Frontend keeps its own `./frontend` context (self-contained).

**P2-2 — Vestigial COPY of non-existent dirs.**
`Dockerfile.sast` did `COPY scanners/sast/rules ./rules` and `Dockerfile.report` did
`COPY workers/report-templates ./templates`; neither path exists, and nothing reads them at
runtime (SAST rules are compiled in via `FRAMEWORK_RULES`/`ALL_RULES`; report HTML is built
in code). *Fix:* dropped both COPYs; sast now `mkdir -p ./rules` as a mount point for the
optional `sast_rules` custom-rule volume.

**P2-3 — `enterprise-worker`: pinned Trivy version does not exist.**
`ARG TRIVY_VERSION=0.58.1` is not a published Trivy release. The upstream installer found
the version via the GitHub **API** but then 404'd downloading the release asset
(`trivy_0.58.1_Linux-64bit.tar.gz` → 404; the naming scheme is correct, the tag just
doesn't exist). *Fix:* bumped to `0.70.0` (verified real), split the trivy/syft/apktool
installs into separate RUN layers with `curl --retry 3`. Now installs trivy 0.70.0 +
syft 1.18.1 + apktool 2.10.0, all self-tested in-layer.

**P2-4 — Obsolete `version:` key.** Removed `version: '3.9'` from all three compose files
(Compose v2 warns and ignores it).

### Image sizes (built)
backend/backend-worker 648 MB · frontend 79 MB · sast/api 455 MB · dast 1.55 GB ·
report 1.57 GB · enterprise 2.28 GB (trivy DB + chromium + JRE).

## Phase 3 — Bring stack online

**Deploy target chosen: base `docker-compose.yml`** (built images, default `node dist/...`
CMD, secrets from `.env`). Reasons the other two stacks aren't the right "bring-online"
target in this single-host env:
- **Dev override** runs `npx tsx watch`, but `tsx` is a **devDependency** and the images
  `npm prune --production`, so it's absent from the image → dev hot-reload can't start
  against the prod images (pre-existing; see BACKLOG). Also re-declared `build.context:
  ./backend` (fixed to `.` so dev *builds*).
- **Prod override** uses `secrets: external: true` (Docker **Swarm** only) + read-only
  rootfs — a real orchestrated deploy, not `docker compose up`.

### Problems found & fixed (runtime wiring)

**P3-1 — TLS topology was internally inconsistent.** Backend healthchecks (compose +
Dockerfile) and `SCANNER_API_URL` assumed backend HTTPS on :3000, but nginx proxies
`http://backend_api`/`backend_ws`, and `nginx/ssl/` + `certs/` were both **empty** (so the
backend actually falls back to HTTP). Never caught because the app had never run.
*Resolution:* standardized on **edge TLS** — nginx terminates public HTTPS (:443→host
8443), backend speaks HTTP on the private `appsec-internal` network. This matches nginx's
existing `http://` upstreams and needs the fewest changes. Public posture is unchanged
(browser only ever talks HTTPS to nginx; `X-Forwarded-Proto: https` → Secure cookies still
valid). `SCANNER_API_URL` is dead (scanners are decoupled via Redis + their own pg pool), so
nothing else needed backend HTTPS.
  - Generated `nginx/ssl/server.{crt,key}` — self-signed RSA-2048, CN=localhost,
    SAN localhost/nginx/127.0.0.1, 825 days (nginx mounts `./nginx/ssl:ro`).
  - Switched both backend healthchecks `https`→`http` (+ `.on('error',…)` guard).

**P3-2 — runtime dirs.** Created `data/postgres`, `data/redis`, `data/reports` (bind-mount
targets for the postgres_data/redis_data volumes).

Verified pre-launch: all `${VAR:?}` secrets present in `.env`; ENCRYPTION_KEY exactly 32
chars; JWT access≠refresh; postgres `POSTGRES_PASSWORD` and redis `--requirepass` both bound
to the same `.env` values the backend uses.

**P3-3 — `sast_rules` bind volume target missing.** The `sast_rules` volume binds
`./scanners/sast/rules`, which didn't exist → "failed to populate volume … no such file or
directory". Created the dir (with `.gitkeep`).

**P3-4 — `.dockerignore` not excluding root-owned runtime dirs → build context EACCES.**
After the first `up`, postgres/nginx wrote root-owned dirs (`data/postgres` `drwx------`
uid 70, `nginx/cache/client_temp`) *inside* the repo-root build context → "error from
sender: open … permission denied". Two real `.dockerignore` bugs surfaced: (a) trailing
slashes don't exclude dirs in BuildKit's matcher (`data/` ✗ → `data` ✓), and (b) **any `!`
re-include pattern** (`!**/.env.example`) forces the walker to recurse into *every* excluded
dir to check for re-includes — so it still opened the unreadable `data/postgres`. Removed the
negation, dropped trailing slashes, added `nginx/cache`/`nginx/dev-cache`. Proven with an
isolated probe build.

**P3-5 — Backend forced TLS to a non-TLS postgres.** A prior fix tied DB SSL to
`NODE_ENV==='production'`; the containerized postgres has no TLS → boot crash-loop ("The
server does not support SSL connections"). Replaced with an explicit **`DB_SSL`** flag
(default off; set true only for an external managed DB that requires TLS). Applied in
`backend/src/core/db/pool.ts` + the scanner/worker pools (`scanners`/`workers/src/utils/db.ts`).

**P3-6 — Frontend image couldn't run nginx as non-root.** As user `appsec` it failed to
write `/var/run/nginx.pid` (crash-loop) and can't bind :80. Switched the frontend to listen
on **8080** (pid → `/tmp/nginx.pid`, dropped the no-op `user` directive) and updated the
reverse-proxy upstream (`frontend:8080`), the compose healthcheck, the host port
mapping, and `frontend-health.sh`.

**P3-7 — SPA 403.** Angular 18 emits to `dist/browser/`, but the Dockerfile copied `dist/`,
so the web root had no `index.html`. Changed the COPY to `dist/browser`.

**P3-8 — backend-worker false "unhealthy".** Its healthcheck did `require('redis')`, but the
app uses **ioredis** (the `redis` package isn't installed) → healthcheck always threw.
Rewrote it to use ioredis `.ping()`.

**P3-9 — chromium false "unhealthy".** browserless gates every endpoint behind the token;
`/health` → 403. Switched the healthcheck to `/pressure?token=$TOKEN` (the in-container env
var is `TOKEN`).

**P3-10 — PDF reports would fail at runtime.** Images build deps with `--ignore-scripts`, so
puppeteer's bundled Chromium is never downloaded, and `puppeteer.launch()` had no
`executablePath`. The report image installs apk `chromium`; pointed launch at
`/usr/bin/chromium-browser` + set `PUPPETEER_SKIP_DOWNLOAD`/`PUPPETEER_EXECUTABLE_PATH`.

**P3-11 — BullMQ eviction policy.** redis ran `--maxmemory-policy allkeys-lru`; BullMQ
requires `noeviction` (jobs must not be evicted). Fixed in base compose + dev override.

**P3-12 — nginx 502 on auth (`upstream sent too big header`).** Login/register set 3 JWT
cookies whose `Set-Cookie` headers overflow nginx's default 4k/8k proxy header buffer.
Added `proxy_buffer_size 16k; proxy_buffers 8 16k; proxy_busy_buffers_size 32k;`.

### Result: ✅ stack online, all services healthy, auth smoke-tested

`docker compose -f docker-compose.yml up -d` → all 13 services Up; postgres/redis/backend/
backend-worker/frontend/nginx/sast-worker/chromium **healthy** (the api/dast/enterprise/report
workers and mailhog define no healthcheck → "Up"). Migrations 001–005 applied; platform
initialized. End-to-end smoke test through the nginx HTTPS edge:
- `GET https://localhost:8443/` → 200 (Angular SPA)
- `GET …/api/health` → 200 `{"status":"healthy","checks":{"database":"ok"}}`
- `POST …/api/auth/register` → 201, `…/login` → 200 (sets access/refresh/csrf cookies)
- `GET …/api/auth/me` (cookie auth) → 200 full profile + permissions
- `POST …/api/auth/logout` (cookie + CSRF header) → 200
- `http://localhost:8080/` → 301 → https
(smoke user/org/audit rows deleted afterward; only the seed admin/org remain).

### Access ports (host) — locked down to the nginx edge only
| URL / port | Service |
|------------|---------|
| **https://localhost:8443** | **Main app** (nginx TLS edge → frontend + `/api` + `/api/ws`) — self-signed cert. **The only entry point.** |
| http://localhost:8080 | nginx HTTP → 301 → `https://localhost:8443` (port-preserving) |
| ~~frontend / backend / WS host ports~~ | **removed** — no longer published to the host; reachable only container-to-container. No edge bypass. |
| localhost:5432 / 6379 | postgres / redis — **only in the dev override**, not base |

### P3-15 — SPA stuck on a spinner (all bundle assets 404)
The reverse-proxy `location /` proxied to `frontend_app`, but its **nested**
`location ~* \.(js|css|…)$` (added for cache headers) had **no `proxy_pass`** — and an
nginx nested location does not inherit the parent's. So every `*.js`/`*.css` request fell
through to the local filesystem (`/etc/nginx/html`, nonexistent) → 404. The SPA shell
(`index.html`) loaded but no JavaScript ran → infinite spinner. **Fix:** re-declared
`proxy_pass http://frontend_app;` inside the nested asset location. All bundle assets now
200; SPA route fallback (e.g. `/login`) serves index.html.

### Multi-app-localhost safety (P3-13/14, found while reviewing alongside other local tools)
- **HTTP→HTTPS redirect dropped the custom port** — `return 301 https://$host…` (and even
  `$server_port`, which is the container-internal 80) sent `http://localhost:8080` to
  `https://localhost` (:443), landing on another local app (code-pilot). Fixed with a
  `map $http_host` that rewrites `localhost:8080 → localhost:8443` (default passes
  through, so prod `example.com`→`:443` still works).
- **HSTS was poisoning all of `localhost`** — `Strict-Transport-Security … includeSubDomains;
  preload` is keyed to hostname, not port, so once a browser saw it on `localhost:8443` it
  force-upgraded every other `http://localhost:<port>` tool to HTTPS for 2 years. Gated HSTS
  behind a `map $host` so it's emitted only for real domains, never localhost/127.*/[::1];
  removed the duplicate unconditional HSTS from the frontend nginx conf.
- **Note (unavoidable):** cookies are not port-scoped, so the Secure auth cookies set by
  `https://localhost:8443` are also sent to any other HTTPS app on `https://localhost:443`.
  They're HttpOnly and other apps ignore them; only relevant in a shared-localhost dev box.

### Issues found during real browser use (2026-06-13)

**P3-16 — Default admin credentials live; `.env` ADMIN_PASSWORD ignored.**
Login with the strong `.env` `ADMIN_PASSWORD` returned 401. Root cause: the backend service
in `docker-compose.yml` is **not passed `ADMIN_EMAIL`/`ADMIN_PASSWORD`**, so `init.ts` fell
back to its hardcoded defaults when it first seeded the super-admin:
`admin@example.com` / `Admin123!@#ChangeMe`. So a **well-known default password is
live on a `super_admin` account**, and rotating `.env` has no effect (the platform is
"already initialized" and won't re-seed). *Status: identified, fix options given (recommended:
add `ADMIN_EMAIL`/`ADMIN_PASSWORD` to the backend compose env + reset the existing admin's
bcrypt hash to the `.env` value). Not yet applied — awaiting go-ahead.*

**P3-17 — Scan "Launch" → 400 "validation failed".**
`POST /api/scans/launch` 400'd because the scans UI never sent `projectId`, which the schema
requires (`projectId: z.string().uuid()`). Two compounding gaps:
1. `scans.component.ts` built the payload as `{name, scanType, options}` — **no `projectId`**,
   and the launch panel had no project selector.
2. The org had **zero projects**, so there was nothing to attach a scan to anyway.
*Fix:* rewrote the scans component to load projects (`GET /api/projects`), add a **project
dropdown**, include `projectId` in the payload, support **inline project creation** when none
exist, and route the target to `targetUrl` vs `targetPath` by whether it's a URL (avoids a
second `z.string().url()` validation error). Requires a frontend rebuild to go live.

### End-to-end scan smoke test (DAST + SAST) — 2026-06-13

Target: `https://binary-analysis.internal:8443` (a host on the private network). Debugged via `docker logs` with
`SCANNER_LOG_LEVEL=debug` (new compose-controlled var) until DAST ran clean.

**P3-18 — Scan enqueue threw `Custom Id cannot contain :`.** Every `POST /scans/launch`
500'd (after inserting the `scans` row, so scans showed "queued" forever with no job).
`queueManager.addJob` set `jobId: name`, and the launch passes `scan:${scanId}` — BullMQ
forbids `:` in a custom job id. *Fix:* sanitize the job id (`name.replace(/:/g,'-')`) in
`addJob`/`addBulk`; the human-readable job name keeps its colon. Verified: jobs now enqueue
(`jobId: scan-<uuid>`) and the worker consumes them.

**P3-19 — Workers never persisted scan results.** `sast-worker.ts` and `dast-worker.ts`
computed findings and returned them as the BullMQ job result but **never wrote to Postgres**
(no status update, no findings rows) — so scans stayed `queued`/showed nothing even when they
ran. *Fix:* added `startScan`/`storeFinding`/`completeScan`/`failScan` (scan-store) wiring to
both workers (status queued→running→completed/failed + findings persisted).

**P3-20 — Two workers raced the same queues; the stub always won.** `backend-worker`
(`appsec-worker`, `dist/workers/main.js`) registered **stub** `sast-scan`/`dast-scan`
processors — `performStaticAnalysis()` returned `[]`, DAST did nothing — and marked scans
`completed` with 0 findings in ~20 ms. Being instant, it beat the real scanner containers
(BullMQ delivers each job once), so scans "completed" with 0 findings and empty metadata.
*Fix:* **removed the backend-worker service** from base/override/prod compose (its only role
was these harmful stubs; nothing `depends_on` it). Real scanning is the dedicated
`*-worker` containers. (`backend/src/workers/main.ts` is now dead — left in tree, not run.)

**P3-21 — Scanner workers had no network egress.** All `*-worker` services were on
`appsec-internal` (`internal: true`) → `ENETUNREACH` for any external target. *Fix:* added
the non-internal `appsec-public` network to the dast/api/enterprise workers (SAST stays
internal — it scans local code). Verified a worker can now reach the the private network target
(routes out the host's private-network interface via a dedicated `ip rule` table). Note: this relaxes the N2
egress-isolation hardening by design — re-tighten with an egress proxy for production.

**P3-22 — `findings.type` CHECK constraint rejected stored findings.** The first successful
DAST run crawled 33 URLs / 18 attack modules / 50 findings, but **every** `storeFinding`
failed: `findings_type_check` allows only `sast|dast|api|manual`, and the workers put the
rule/attack id (`DAST-CSRF-001`, the SAST rule category) in `type`. So `findings_count`
showed 50 but 0 rows persisted. *Fix:* set `type` to the scan category (`'dast'` / `'sast'`);
the attack/rule id stays in `rule_id`.

**New compose control:** `SCANNER_LOG_LEVEL` (default `info`, set to `debug` in `.env`)
drives `LOG_LEVEL` on all scanner workers for verbose troubleshooting.

**P3-23 — Findings not viewable in the UI.** Findings existed and `GET /api/findings`
returned all 50, but the Findings page only rendered a flat table with no detail view —
clicking a finding did nothing, and the scan-row "Findings" link ignored its `scanId`.
*Fix:* rewrote `findings.component.ts` to honor the `scanId` query param (so a scan's
"Findings" link shows just that scan's results, with a clear-filter button) and added a
click-to-expand **detail panel** per finding (location/endpoint, rule, OWASP, CVSS+vector,
confidence, method, description, recommendation, evidence). Frontend rebuilt.

**✅ Result — scan pipeline verified end-to-end (2026-06-13).** After P3-18→22:
- **DAST** of `https://binary-analysis.internal:8443`: queued→running→**completed, 50 findings**, and
  **50 finding rows persisted** (`type=dast`; e.g. missing-permissions-policy,
  missing-cross-origin-resource-policy). Metadata: 33 URLs crawled, 18 attack modules, WAF none.
- **SAST** of `/app/dist`: queued→running→**completed, 0 findings** (expected — that path is
  compiled/minified JS). Status now persists correctly (no longer stuck "queued"); to get SAST
  findings, point a project at real source (repo clone / mounted code).

### Findings UX, exports, and the real overlay bug — 2026-06-13

**P3-24 — Material overlays render in the bottom-left corner (all panels).** The resolution
menu (findings/scans) and the API-client method dropdown (mat-select) appeared bottom-left
over the sidebar. First attempt added `@include mat.core()` (it was genuinely missing), but
the bug persisted. Root cause: the CSS optimizer split the grouped CDK rule
`.cdk-overlay-container, .cdk-global-overlay-wrapper { top:0;left:0;width/height:100% }` and
**dropped those props from `.cdk-overlay-container`**, leaving it `position:fixed` only → a
fixed element with no offsets collapses to the bottom-left, and every CDK overlay anchors
there. *Fix:* re-assert the full-viewport `.cdk-overlay-container` rule in global
`styles.scss` (kept `mat.core()` too). Verified in the deployed bundle. Fixes ALL panels at
once (findings, scans, api-client, layout).

**P3-25 — Findings page: limit cap + no targets/URL view.** (a) The redesign requested
`limit=500`/`1000` but the API caps `limit` at 200 → 400, so the findings table AND JSON
export came back empty. Capped both at 200. (b) Rebuilt Findings as **scan-targets list →
drill-down**: landing lists scans with Target/Asset (from `options.targetUrl|targetPath`),
type, status, finding count, date; row/▸ opens that scan's findings (`scanId` filter) with a
**Target/Asset column** + click-to-expand detail. Truncated long URLs (ellipsis + title) and
fixed table cell padding (was cramped).

**P3-26 — Exports.** JSON export = client-side download of the scan's findings (verified:
50 rows). PDF export = backend report flow; fixed two breaks: the frontend POSTed
`/api/reports` (404 — real path is `/api/reports/generate`), and the **report-worker never
persisted completion** (generated the file but left the row `queued`) + the **backend didn't
mount the reports volume** where the download route reads (`/data/reports`). *Fixes:*
report-worker now `UPDATE reports SET status='completed', file_size=…`; backend mounts
`reports_data:/data/reports:ro`. Verified end-to-end: generate→completed→download =
HTTP 200, `application/pdf`, 153 KB, 3 pages.

**API client verified (P3 misc).** Drove the app's server-side request proxy
(`POST /api/api-client/{collections,requests,requests/:id/execute}`) — note it's mounted at
`/api/api-client` (hyphen). `GET https://jsonplaceholder.typicode.com/users` → 200, 10 users.
OpenAI `…/anthropic/v1/models` → reached upstream, returned **401 (needs an API key)** — the
app/egress works; auth must be supplied as an `x-api-key` header on the request.

**P3-27 — App only worked from localhost (login failed via the private network/phone).** The
frontend `environment.{ts,prod.ts}` hardcoded `apiUrl: https://localhost:8443/api` — so a
remote client (phone over the private network) had the Angular app call `localhost` = the *phone*, not
the server → login failed. *Fix:* made API/WS **same-origin/relative** (`apiUrl:'/api'`, WS
derived from `location.host`), so it works from any host. Also made backend **CORS reflect
the request origin** (`resolveCorsOrigin()`; `CORS_ORIGIN=*` → reflect, with credentials) so
non-localhost origins aren't blocked. Verified: off-origin login → 200; 0 hardcoded
`localhost` left in the bundle. (Self-signed cert is still CN=localhost → IP access shows a
cert warning; front the open `:8443` with a firewall / the private network ACL.)

**P3-28 — ALL Material overlays (selects/menus/tooltips/dialogs) rendered bottom-left —
true root cause.** Earlier guesses (`mat.core()`, a re-asserted `.cdk-overlay-container`
rule) didn't fix it. Headless inspection (Brave + puppeteer-core) showed the overlay
container computed `position: static` even though `styles.css` contained
`.cdk-overlay-container{position:fixed}`. Reason: the production build's **`inlineCritical`
(critters)** inlines critical CSS and defers the full stylesheet with
`<link rel="stylesheet" media="print" onload="this.media='all'">` — but our **CSP
`script-src 'self'` blocks that inline `onload`**, so the media never flips to `all`.
Result: `styles.css` stayed `media="print"` → every non-critical rule (all the CDK overlay
positioning) never applied → overlay container is `static` → panels flow to the bottom-left
of `<body>`. The page still looked themed because critters had inlined the visible CSS.
*Fix:* disabled critical-CSS inlining in `angular.json`
(`optimization.styles.inlineCritical=false`); styles.css now loads as a normal blocking
sheet. Verified headlessly: container `position: fixed`, the select panel opens at its
trigger (x301,y213 vs trigger x317,y173), option height 48px. Fixes **every** overlay app-
wide in one shot (selects, the finding/scan action menus, tooltips, dialogs).

**P3-29 — SAST source inputs: Git repos + local filesystem.** SAST could only scan a
pre-mounted container path. Added: (a) **Git clone-and-scan** — `options.repoUrl` (+`branch`,
+`gitToken` for private repos, injected into the https URL, never logged); the worker
shallow-clones to a temp dir via `execFile git` (no shell), scans, and deletes it; added
`git` to the SAST image and **egress** (`appsec-public`) to the sast-worker (the GitHub scan
first failed with `Unable to resolve host` because SAST was internal-only). (b) **Local FS**
— host code mounted read-only at `/scan` via `SCAN_SOURCE_DIR` (.env, default `./scan-sources`).
Frontend SAST form now offers "Git repo URL or local path" + Branch + Git-token fields.
Verified: cloned `github.com/mshermancyber/security-hub` (131 files) → 113 findings.

**P3-30 — JSON export 200-cap removed.** `exportJson` now paginates (`limit=200&page=N`
until a short page) so it includes ALL findings, not just the first 200.

> The deferred prod stack (`docker-compose.prod.yml`) still needs Docker **Swarm** external
> secrets + a real TLS cert and is not started here; the dev override needs `tsx` added to
> the images to hot-reload. Both tracked in BACKLOG.

---

## Session 2026-07-04 — backend image made recreate-safe; inline scan deployable

Three latent breaks surfaced only in the PRODUCTION image build (`npm run build` → `tsc`), which
the dev `tsx watch` mode never exercises. Fixed all three; a clean `docker compose up -d
--force-recreate backend` now boots healthy on its own.

1. **tsx stripped from the runtime image.** `tsx` was a devDependency; `Dockerfile.backend` runs
   `npm prune --production`, removing it. The dev override starts the backend with `npx tsx watch`,
   which then tries to refetch tsx at runtime — fails offline → container crash-loops on every
   RECREATE (a fresh container has no npx cache). **Fix:** moved `"tsx"` to `dependencies` in
   `backend/package.json` + updated `package-lock.json` (`npm install --package-lock-only`).

2. **Inline scan endpoint crash-looped the backend.** `backend/src/api/scan-inline/routes.ts`
   imported `@appsec/scanners/src/...` at module top level; the scanners package isn't in the
   backend container → `ERR_MODULE_NOT_FOUND` on boot. **Fix (two parts):**
   - Converted to runtime-only **lazy dynamic import** with a non-literal specifier so `tsc` never
     resolves it at build time; endpoint returns 503 if the engine can't load (server still boots).
   - Mounted the scanners package into the backend container at
     `/app/node_modules/@appsec/scanners:ro` (docker-compose.override.yml). The engine files only
     import node built-ins + `pino` (resolved upward from the backend's own node_modules), so no
     extra deps needed.

3. **`ignoreDeprecations` / `baseUrl` broke `tsc`.** `backend/tsconfig.json` had
   `ignoreDeprecations: "6.0"` (rejected by the installed TS) then `"5.0"` (which TS 5.9.3 rejected,
   demanding `"6.0"`) — a version deadlock triggered by the deprecated `baseUrl`. **Fix:** removed
   `baseUrl` + the entire `paths` block (no `@`-aliases are actually imported — dead config) +
   `ignoreDeprecations`. No deprecation → no version-specific value to get wrong. `tsc --noEmit`
   clean across backend + scanners + frontend.

Rebuilt `deep-vigilance-backend:latest` with all three; recreate verified healthy, reaper running,
inline endpoint returning findings.
