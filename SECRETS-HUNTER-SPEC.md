# Handoff Task — Secrets Exposure Hunter → the project root (orchestrator spec)

**Target:** the project root (AppSec platform; Node20+TS, Express, BullMQ/Redis, Postgres16,
Angular18, docker-compose; backend on its internal :3000, nginx edge :8443).
**Do NOT bridge to any other project.** Self-contained inside this repository.
**Conformance doc:** `./SECRETS-HUNTER-RULESET.md` (Fable's ruleset). Use it as the
CONFORMANCE CHECKLIST — schema, redaction, severity mapping, signature gap-check, foothold export.

## KEY FACT — do NOT rebuild detection
A full secrets engine ALREADY EXISTS: `scanners/src/sast/secrets-engine.ts` (~2310 lines, 50+ pattern
families, Shannon entropy, `scanFileForSecrets` / `scanGitHistory` / `scanEnvironmentFiles`, optional
live validation). A `secret-scan` queue is already DECLARED in `backend/src/core/queue/
queue-definitions.ts` but has NO worker and is NOT in the QueueName enum (half-built scaffolding).

**The job is to FINISH THE WIRING to make secrets a first-class async scan type — not to write a new
detector.** Reuse the existing engine. Follow the most-recent scanner as the template: `sca-worker.ts`
+ migration `006_sca_scan_type.sql` + `Dockerfile.sca`.

## Work items (worker breakdown)
1. **Migration** `postgres/migrations/00N_secret_scan_type.sql` (mirror 006): add `'secret'` to the
   `scans.scan_type` CHECK and `findings.type` CHECK constraints.
2. **Queue registration**: add `SECRET_SCAN='secret-scan'` to the `QueueName` enum
   (`backend/src/core/queue/manager.ts`) and to the `SCAN_QUEUES` set. (Queue def already exists.)
3. **Worker** `scanners/src/secret-worker.ts`: `Worker('secret-scan', processJob)` that clones the
   target repo (reuse the sca/sast `cloneRepo` pattern) → runs the existing engine
   (`scanFileForSecrets` + `scanGitHistory` + `scanEnvironmentFiles`) with **live validation DISABLED**
   → `startScan` / `storeFinding({type:'secret', ...})` / `completeScan`/`failScan` from
   `scanners/src/utils/scan-store.ts`. Map each hit to `StoredFinding` (title, severity from confidence
   per RULESET §5, rule_id = signature id, file_path/line_number, recommendation="rotate+revoke+scrub
   history", confidence, `metadata` = { secret_type, provider, redacted, secret_sha256, source,
   location, foothold }).
4. **Launch/enum plumbing**: extend `queueMap`/scanType enum in `backend/src/api/scans/routes.ts` and
   `scan-orchestrator.ts`; extend the `type` Zod enum in `backend/src/api/findings/routes.ts` (and any
   scan-launch Zod enum) to include `'secret'`.
5. **Docker**: `docker/Dockerfile.secret` (mirror Dockerfile.sca) + a `secret-worker` service in
   `docker-compose.yml` (+ override for dev bind-mount/tsx-watch).
6. **REDACTION ENFORCEMENT (mandatory, RULESET §8)**: ensure NO raw secret is ever persisted or logged
   — `storeFinding` receives only `redacted` + `secret_sha256`. If the engine currently emits raw
   values into findings/metadata, add a redaction pass before storeFinding. Verify Pino logs don't leak
   secrets.
7. **Signature gap-check (RULESET §2)**: confirm the engine covers the catalog; add any missing
   provider signatures as data. Do not remove existing ones.
8. **Foothold export**: after a completed secret scan, write DV's OWN feed
   `./data/exposed-creds.feed.json`
   (`{ "exposed":[{ref,kind,source,note}] }`) from confirmed secret findings, for the attack-path
   engine to ingest. DV-local, one-way export — NOT a bridge to osint.
9. **API surface**: findings already flow through `GET /api/findings` + `GET /api/scans/:id/findings`;
   confirm `type=secret` filters work end-to-end and SARIF export includes them.
10. **Tests**: fixture eval harness (RULESET §10, precision≥0.95/recall≥0.90, synthetic secrets only)
    + a launch→worker→findings integration smoke via the queue.

## Constraints
- `npm run build` (tsc, both packages) clean. Postgres migration applies cleanly.
- Rebuild path: `docker compose build secret-worker && docker compose up -d secret-worker`
  (a helper agent can assist with container/queue wiring issues).
- No live credential validation (disable the engine's optional validator). Detect/score/redact/report.
- Reuse nothing from osint. DV owns its copy.
