# Installing Deep Vigilance

Version 0.1.0

Deep Vigilance ships as a Docker Compose stack: fifteen services — the nginx TLS edge, the
Angular frontend, the Express API, six scan workers, a report worker, PostgreSQL, Redis, headless
Chromium and (in development) MailHog. There is no host-level install; everything runs in
containers.

---

## 1. Requirements

| | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 20 GB free | 50 GB+ |
| OS | Any Linux with Docker; macOS and Windows via Docker Desktop | Linux |

Software:

- **Docker Engine 24+** with the Compose v2 plugin (`docker compose`, not `docker-compose`)
- **OpenSSL** — for the one-time certificate generation
- **git**

Check what you have:

```bash
docker --version
docker compose version
openssl version
```

The services declare memory *limits* totalling 35 GB, but those are ceilings, not allocations.
Actual reservations total roughly 8 GB. The headless Chromium and SAST workers are the heavy
components; if you are tight on memory, scale them down (see §8).

---

## 2. Get the code

```bash
git clone https://github.com/mshermancyber/deep-vigilance.git
cd deep-vigilance
```

---

## 3. Generate certificates

nginx terminates TLS and mounts `nginx/ssl` **read-only**, so the certificates must exist on the
host before the first start.

```bash
chmod +x scripts/generate-certs.sh
./scripts/generate-certs.sh
```

This writes a self-signed edge certificate to `nginx/ssl/server.{crt,key}` and an internal
service certificate to `certs/internal.{crt,key}`. Both are git-ignored.

Your browser will warn about the self-signed certificate — expected for a local or internal
deployment. To serve a real hostname, set the subject before generating:

```bash
CERT_CN=appsec.example.com \
CERT_SAN=DNS:appsec.example.com \
./scripts/generate-certs.sh
```

For a public deployment, replace `nginx/ssl/server.crt` and `server.key` with a certificate from
a real CA (Let's Encrypt, your internal PKI) and reload nginx:

```bash
docker compose exec nginx nginx -s reload
```

---

## 4. Configure `.env`

```bash
cp .env.example .env
```

Now edit `.env`. **Six secrets must be changed** — the backend refuses to start in production
with any of them left at a placeholder value:

```bash
# Generate real values:
openssl rand -base64 48      # JWT_SECRET
openssl rand -base64 48      # JWT_REFRESH_SECRET  (must differ from JWT_SECRET)
openssl rand -base64 32      # DB_PASSWORD
openssl rand -base64 32      # REDIS_PASSWORD
openssl rand -base64 32      # CHROMIUM_TOKEN
openssl rand -hex 16         # ENCRYPTION_KEY      (must be exactly 32 characters)
```

| Variable | Notes |
|---|---|
| `DB_PASSWORD` | PostgreSQL password. Set before first start — it is baked into the database on initialisation. |
| `REDIS_PASSWORD` | Redis AUTH password. |
| `JWT_SECRET` / `JWT_REFRESH_SECRET` | Minimum 32 characters, and they must differ from each other. |
| `ENCRYPTION_KEY` | Exactly 32 characters. Encrypts stored integration credentials at rest. **Changing it later makes existing stored secrets unreadable.** |
| `CHROMIUM_TOKEN` | Auth token for the headless browser service. |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | The first-run admin account, created once on first boot. |

Then review the rest:

```ini
# Host ports for the nginx edge. Change these if 8443/8080 are taken.
HTTPS_PORT=8443
HTTP_PORT=8080

# Pin this to your real origin on anything reachable from outside.
CORS_ORIGIN=*

# The host directory exposed to the scanners as /scan (read-only).
SCAN_SOURCE_DIR=./scan-sources
```

> **`DB_PASSWORD` is set at database initialisation.** If you change it after the first start,
> PostgreSQL keeps the old password and the backend cannot connect. Either change it inside
> PostgreSQL with `ALTER USER`, or delete `data/postgres/` and start over (which destroys all data).

---

## 5. First start

```bash
docker compose up --build -d
```

The first build compiles the frontend and four TypeScript packages; expect 5–15 minutes. Then
watch it come up:

```bash
docker compose ps
docker compose logs -f backend
```

On startup the backend applies every migration in `postgres/migrations/` and, on a fresh
database, creates the default organization and the admin account from `ADMIN_EMAIL` /
`ADMIN_PASSWORD`. Look for:

```
Migrations applied
Platform initialized
Reaper: scheduling
Cleanup: scheduling retention jobs
```

All services healthy:

```bash
docker compose ps --format 'table {{.Service}}\t{{.Status}}'
curl -k https://localhost:8443/api/health
```

Then open **<https://localhost:8443>** and sign in with your `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
**Change the admin password immediately after the first login.**

In development, MailHog catches all outbound mail at <http://localhost:8025>.

---

## 6. Verify the install

```bash
./scripts/smoke-test.sh
```

Override the base URL if you changed the ports:

```bash
BASE=https://localhost:9443/api ./scripts/smoke-test.sh
```

A quick manual check of the synchronous scan endpoint, which needs no queue or database write:

```bash
TOKEN=$(curl -sk -X POST https://localhost:8443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"<your ADMIN_PASSWORD>"}' \
  | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)

curl -sk -X POST https://localhost:8443/api/scan/inline \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"filename":"t.js","content":"const q = \"SELECT * FROM users WHERE id=\" + req.query.id;"}'
```

---

## 7. Optional features

Everything here is off by default. Nothing breaks when it is absent — the features simply report
themselves as not configured.

### AI finding triage

Rates each finding's false-positive probability with reasoning, root cause, exploitability and a
suggested fix, and parses natural-language finding searches. Defaults to the OpenAI (ChatGPT) API.

```ini
OPENAI_API_KEY=sk-...
OPENAI_API_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini
```

With no key set, every AI endpoint falls back to a local heuristic engine — the platform stays
fully functional and **no finding data leaves your host**. Enabling this does send finding
metadata (title, severity, CWE, file path, a code snippet) to the provider you configure.

Any OpenAI-compatible endpoint works instead — Azure OpenAI, or a local llama.cpp / Ollama / vLLM
gateway — by pointing the URL at it:

```ini
AI_API_KEY=not-needed
AI_API_URL=http://ollama.internal:11434/v1
AI_MODEL=qwen2.5-coder
```

### Mail

```ini
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=appsec@example.com
SMTP_PASS=...
SMTP_FROM=appsec@example.com
```

Leave `SMTP_HOST` empty to disable outbound mail entirely.

### External integrations

```ini
# Binary / malware submission and detonation reports.
FRAUDVAULT_URL=https://binary-analysis.internal:8443
FRAUDVAULT_EMAIL=...
FRAUDVAULT_PASSWORD=...

# Interactive dependency-graph rendering for SBOM exports.
SBOM_VISUALIZER_URL=https://sbom-viz.internal:8443
SBOM_VISUALIZER_TOKEN=...

# Vulnerability feed for SCA enrichment (EPSS / KEV / NVD).
VULN_FEEDS_URL=http://vuln-feeds:9000
VULN_FEEDS_API_KEY=...
```

---

## 8. Retention and cleanup jobs

A housekeeping cycle prunes data nobody reads again — finished scans and their findings,
generated reports and their files, audit entries, delivered notifications, API request history,
webhook dead letters, expired sessions, and completed BullMQ jobs in Redis.

```ini
CLEANUP_INTERVAL_MIN=360     # how often a cycle runs; 0 disables cleanup entirely

RETAIN_SCANS_DAYS=90
RETAIN_AUDIT_LOG_DAYS=365
RETAIN_REPORTS_DAYS=90
RETAIN_NOTIFICATIONS_DAYS=30
RETAIN_CODE_REVIEWS_DAYS=90
RETAIN_API_HISTORY_DAYS=30
RETAIN_WEBHOOK_DLQ_DAYS=30
RETAIN_QUEUE_JOBS_DAYS=7

CLEANUP_BATCH_SIZE=5000
CLEANUP_MAX_TABLE_FRACTION=0.5
```

Any threshold set to `0` means *never prune that table*.

Safety properties worth knowing before you tune these:

- **Only terminal-state rows are touched.** A `queued` or `running` scan, or a code review that is
  cloning/indexing/analyzing, is never pruned regardless of age. Abandoning scans is the reaper's
  job (`SCAN_MAX_RUNTIME_MIN`), which marks them `failed` first.
- **Deletes run in batches** of `CLEANUP_BATCH_SIZE`, so a first run against a large database never
  holds a table lock for minutes.
- **`CLEANUP_MAX_TABLE_FRACTION` aborts a prune** that would delete more than that share of a table
  (default: half), which catches a mistyped retention window before it removes live data. The check
  is skipped for tables under 1,000 rows. Set it to `1` to disable.
- Findings are deleted before their scans, because `findings.scan_id` has no `ON DELETE CASCADE`.

Inspect the active configuration, and trigger a cycle on demand:

```bash
curl -sk https://localhost:8443/api/admin/cleanup -H "Authorization: Bearer $TOKEN"
curl -sk -X POST https://localhost:8443/api/admin/cleanup/run -H "Authorization: Bearer $TOKEN"
```

The `POST` returns exactly what was removed, per table. Both require the `settings:manage`
permission. Run it manually once after setting your retention windows, so the first (largest)
prune happens while you are watching rather than at 4 a.m.

---

## 9. Production hardening

The defaults target a local or trusted-network install. Before exposing an instance:

1. **Replace the self-signed certificate** with one from a real CA (§3).
2. **Pin `CORS_ORIGIN`** to your actual origin. `*` reflects whatever origin asks.
3. **Set `NODE_ENV=production`.** This activates the secret assertions that refuse placeholder
   values.
4. **Leave `ALLOW_PRIVATE_SCAN_TARGETS=false`** unless you deliberately scan internal hosts. It
   gates the SSRF guard on private and loopback ranges; cloud metadata and link-local addresses
   stay blocked either way.
5. **Unset `NODE_TLS_REJECT_UNAUTHORIZED`** (or set it to `1`). `0` disables certificate
   verification for outbound requests — only appropriate when talking to internal services with
   self-signed certs.
6. **Do not use `docker-compose.override.yml`.** It publishes PostgreSQL, Redis, Chromium and a
   Node debugger to the host, and runs the backend under `tsx watch`. Compose loads it
   automatically when present, so in production start with the file list pinned:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```

7. **Firewall the host.** Only the nginx port needs to be reachable.
8. **Change the admin password** and create per-person accounts with appropriate roles rather than
   sharing the admin login.
9. **Back up `data/postgres/`** and your `ENCRYPTION_KEY` — without the key, stored integration
   credentials cannot be decrypted from a restored backup.

### Scaling workers down on a small host

```yaml
# docker-compose.prod.yml
services:
  chromium:
    deploy:
      resources:
        limits:
          memory: 2G
  sast-worker:
    deploy:
      resources:
        limits:
          memory: 2G
```

---

## 10. Upgrading

```bash
cd deep-vigilance
git pull
docker compose up --build -d
```

Migrations are applied automatically on backend startup and are additive. Back up the database
first:

```bash
docker compose exec postgres pg_dump -U appsec_user appsec_platform | gzip > backup-$(date +%F).sql.gz
```

---

## 11. Troubleshooting

**`docker compose ps` shows a service restarting.**
```bash
docker compose logs --tail 100 <service>
```

**Backend exits immediately with a secret error.** A required secret is missing or still at a
placeholder. The log names the offending variable. See §4.

**Backend cannot connect to PostgreSQL.** Usually `DB_PASSWORD` changed after the database was
initialised — see the warning in §4.

**nginx fails to start: cannot load certificate.** Certificates were never generated. Run
`./scripts/generate-certs.sh` (§3), then `docker compose up -d nginx`.

**Port already in use.** Set `HTTPS_PORT` / `HTTP_PORT` in `.env` to free ports and recreate:
```bash
docker compose up -d --force-recreate nginx
```

**Browser shows a certificate warning.** Expected with a self-signed certificate. Proceed, or
install a real certificate (§3).

**A scan sits in `queued` forever.** Check that the matching worker is running and consuming its
queue:
```bash
docker compose logs --tail 50 sast-worker
```
Scans stuck past `SCAN_MAX_RUNTIME_MIN` are marked `failed` by the reaper within 20 minutes.

**A scan runs forever at 100% CPU.** It is almost certainly scanning more than you intended.
`SCAN_SOURCE_DIR` is mounted at `/scan`, and a scan launched without an explicit target path
defaults to all of `/scan`. Point `SCAN_SOURCE_DIR` at a specific project, and pass the target
under `options.targetPath` — see `SECRET-SCAN-OPS.md`.

**Everything is healthy but the UI will not load.** Confirm you are using **https**, on the
`HTTPS_PORT` you configured, and that `CORS_ORIGIN` allows the origin you are browsing from.

**Start completely over** (destroys all scan data):
```bash
docker compose down -v
rm -rf data/postgres data/redis
docker compose up --build -d
```

---

## 12. Where to go next

- **[USER-GUIDE.md](./USER-GUIDE.md)** — creating projects, running each scan type, triaging
  findings, reporting, scheduling, and the REST API.
- **[docs/inline-scan-api.md](./docs/inline-scan-api.md)** — the synchronous single-file endpoint
  for editors, hooks and CI.
- **[cicd/](./cicd/)** — GitHub Action, GitLab CI template, Jenkins pipeline and CLI.
- **[SECURITY.md](./SECURITY.md)** — security policy and how to report a vulnerability.
