# Deep Vigilance — Secret Scan (ops runbook)

The `secret` scan type is live: `secret-worker` container consumes the `secret-scan` BullMQ queue,
runs the existing `scanners/src/sast/secrets-engine.ts`, stores `type='secret'` findings, and emits a
foothold feed. Migration `postgres/migrations/008_secret_scan_type.sql` adds `secret` to the
`scans.scan_type` + `findings.type` CHECK constraints (applied to the live DB 2026-07-05).

## Launch a scan (the payload that actually works)

**CRITICAL:** the target path goes under **`options.targetPath`**, NOT `target.targetPath`. If wrong,
the worker defaults to `targetPath = '/scan'` = **the entire mounted source tree** (the host directory in SCAN_SOURCE_DIR is mounted as `/scan`)
and scans gigabytes at 100% CPU forever. This was the #1 footgun.

```bash
API=https://127.0.0.1:8443; COOKIE=/tmp/dv-cookie.txt
# 1. login (sets access + csrf cookies)
curl -sk -c "$COOKIE" -X POST "$API/api/auth/login" -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"MultiIDE2026!"}'
CSRF=$(grep csrf_token "$COOKIE" | awk '{print $NF}')
# 2. launch — note options.targetPath, X-CSRF-Token header, name + valid projectId
curl -sk -b "$COOKIE" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -X POST "$API/api/scans/launch" -d '{
    "name":"secret scan",
    "projectId":"<UUID from GET /api/projects>",
    "scanType":"secret",
    "options":{"targetPath":"/scan/<project-under-/data>/src"},
    "priority":"high"}'
# 3. poll: GET /api/scans/<id>  → status completed + findingsCount
#    findings: GET /api/scans/<id>/findings
```

Container path mapping: host `/data/foo` → container `/scan/foo`.

## Operational fixes / gotchas

- **Big/binary files:** the engine skips files >5 MB and binary/archive extensions (`.tar/.gz/.db/…`).
  Without this it OOMs on large tarballs. (in `secrets-engine.ts` `fullSecretsScan` walk.)
- **Git history:** only scanned for freshly *cloned* repos (`repoUrl`), not local dir targets — the
  container's git discovery walks up the `/scan` mount and hangs. (`secret-worker.ts`.)
- **Drain a stuck queue** (redis needs auth): `RPW=$(grep ^REDIS_PASSWORD= .env|cut -d= -f2)`
  `docker compose stop secret-worker` →
  `docker exec deep-vigilance-redis-1 sh -c "redis-cli -a '$RPW' --no-auth-warning --scan --pattern 'bull:secret-scan:*' | xargs -r redis-cli -a '$RPW' --no-auth-warning DEL"`
  → `docker compose up -d secret-worker`.
- **Reap stuck `running` scans:** `UPDATE scans SET status='failed' WHERE status IN ('running','queued');`
- **Rebuild:** `docker compose build secret-worker && docker compose up -d secret-worker`. Dev runs
  `tsx` on bind-mounted `./scanners/src`, so src edits apply on `docker compose restart secret-worker`.

## Verified 2026-07-05
Scan of `/scan/torrent-bot/src` (planted `secrets.env`) → completed ~6 s → 2 CRITICAL findings
(AWS Access Key ID, token; CWE-798) rendered in the Findings UI. Playwright-verified.
