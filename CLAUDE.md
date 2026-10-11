# CLAUDE.md — Deep Vigilance (AppSec Platform)

Self-hosted web app security platform: SAST + DAST + API security + SCA + vuln management.
Angular frontend, Node/Express (TypeScript) backend, standalone TypeScript scanners, BullMQ/Redis
queues, PostgreSQL, nginx TLS edge. Docker Compose.

## Running

- **Dev (current):** `docker-compose.override.yml` runs the backend as
  `npx tsx watch src/server.ts` with `backend/src` bind-mounted — code edits hot-reload.
- **Prod:** the image runs `node dist/server.js` (compiled). `docker/Dockerfile.backend` does
  `npm ci --ignore-scripts && npm run build && npm prune --production`.
- **Edge:** `deep-vigilance-nginx-1` on `:8443` (TLS). Backend container is `appsec-backend`.
- DB: `deep-vigilance-postgres-1`, db `appsec_platform`, user `appsec_user` (password in `.env`).

## Architecture invariants (read before touching scanners/queues)

- **Scanners persist via `scanners/src/utils/scan-store.ts`** — every worker MUST call
  `startScan(scanId)` → `storeFinding(scanId, projectId, orgId, finding)` per finding →
  `completeScan(scanId, count, meta)` → `failScan` on error. A worker that only computes and
  `return`s results persists NOTHING — the scan stays `queued`/`running` forever with 0 findings
  (the results are stranded in the BullMQ job `returnvalue`). This bit the API scanner (see below).
- The backend `QueueEvents('completed')` handler now reconciles: if a scan is still queued/running
  when its job completes, it reads `job.returnvalue` and persists — a safety net for the above.
- Backend and scanners are **separate packages**. The backend cannot import `@appsec/scanners` at
  build time (scanners aren't in the backend build context). Use **runtime-only dynamic import with
  a non-literal specifier** so `tsc` never resolves it, and mount the package into the container.

## Scanners → queues → workers

| Scan type | Queue | Worker (scanners/src) | Persists? |
|-----------|-------|-----------------------|-----------|
| SAST | `sast-scan` | sast-worker.ts | ✅ scan-store |
| DAST | `dast-scan` | dast-worker.ts | ✅ scan-store |
| API | `api-scan` | api-scanner-worker.ts | ✅ (fixed this session) |
| SCA | `sca-scan` | sca-worker.ts | ✅ scan-store |
| container/binary/protocol | (enterprise) | enterprise-worker.ts | ✅ scan-store |

## Inline scan API (IDE / editor / Claude Code)

- **`POST /api/scan/inline`** (`backend/src/api/scan-inline/routes.ts`) — SYNCHRONOUS, single-file,
  no queue, no DB write, <1s, line-numbered findings. SAST + secrets + SCA-manifest. Reuses the
  `@appsec/scanners` engine (`scanFile` / `scanFileWithAllRules` / `scanFileForSecrets` /
  `matchVulnerabilities`) via lazy dynamic import; returns 503 if the engine can't load.
- DAST is deliberately NOT inline (needs a running target). Call it async from external tools:
  **`POST /api/scans/launch {name, scanType:'dast', targetUrl, projectId}`** → `{scanId}`; poll
  `GET /api/scans/:id` and `GET /api/scans/:id/findings`.

## Stuck-scan reaper

- `backend/src/core/reaper.ts` — runs every 20 min, marks scans stuck in `queued`/`running` past
  `SCAN_MAX_RUNTIME_MIN` (default 30) as `failed`, guarded so it never kills a genuinely live scan.
- **Must be started from `backend/src/server.ts`** (the always-on API entry the container runs) —
  NOT `workers/main.ts` (the container does not run that entry).
- Why dead scans accumulate: workers run under `tsx watch` and reload on every code change,
  orphaning in-flight scans (worker dies before `completeScan`); with no reaper they pile up.

## Gotchas (this dev/prod split has bitten us)

- **`tsx` must be in `dependencies`**, not `devDependencies` — `npm prune --production` strips
  devDeps, and the dev override runs `npx tsx watch`, which can't refetch tsx offline → every
  container RECREATE crash-loops. (Fixed.)
- **`backend/tsconfig.json`** has no `baseUrl`/`paths`/`ignoreDeprecations` — they were removed
  (no `@`-aliases are actually imported, and the `ignoreDeprecations` value fights across TS
  versions; TS is 5.9.3). Don't re-add `baseUrl`.
- The scanners package is mounted into the backend container at
  `/app/node_modules/@appsec/scanners` (docker-compose.override.yml) so the inline endpoint
  resolves it; the engine needs only node built-ins + `pino` (resolved from the backend's deps).

## Docs

- `PROGRESS.md` — task/feature completion log. `Build_Debug.md` — build/deploy debug log.
- `README.md`, `DEPLOYMENT.md`, `SAST_TUNING.md`, `BACKLOG.md`, `MANIFEST.md`, `STUB_REPORT.md`.
