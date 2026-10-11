# DeepVigilance App Scanner — Deployment Guide

## Quick Start

```bash
cp .env.example .env
# Edit .env — replace all __CHANGE_ME__ values (see "Environment Variables" below)
# Generate secrets:  openssl rand -base64 48  (JWT), openssl rand -hex 16 (ENCRYPTION_KEY)

docker compose up -d
# Override file (docker-compose.override.yml) is auto-loaded for dev mode
```

## Services (13 containers)

| Service | Image / Build | Internal Port | Host Port (dev) | Notes |
|---|---|---|---|---|
| **nginx** | `nginx:1.25-alpine` | 80, 443 | 8080, 8080, 8443 | Edge proxy, terminates TLS |
| **backend** | `docker/Dockerfile.backend` | 3000, 3001, 3002 | 3002 (HTTP fallback), 9229 (debugger) | API + WebSocket server |
| **frontend** | `docker/Dockerfile.frontend` | 8080 | — (via nginx) | Angular SPA, nginx-served |
| **postgres** | `postgres:16-alpine` | 5432 | 5432 | Primary datastore |
| **redis** | `redis:7-alpine` | 6379 | 6379 | Queue broker (BullMQ) + cache |
| **sast-worker** | `docker/Dockerfile.sast` | — | — | Static analysis scanner |
| **dast-worker** | `docker/Dockerfile.dast` | — | — | Dynamic analysis scanner |
| **api-scanner-worker** | `docker/Dockerfile.api-scanner` | — | — | API endpoint scanner |
| **enterprise-worker** | `docker/Dockerfile.enterprise-worker` | 9300 | 9300 | Runs 5 enterprise scanners |
| **code-review-worker** | `docker/Dockerfile.code-review` | — | — | Regex-based code review |
| **report-worker** | `docker/Dockerfile.report` | — | — | PDF/HTML report generation |
| **chromium** | `browserless/chrome:latest` | 3000 | 3000 | Headless browser for DAST/reports |
| **mailhog** | `mailhog/mailhog:latest` | 1025, 8025 | 1025, 8025 | Dev SMTP sink (port forwarding broken on current host — Docker proxy issue, needs daemon restart) |

## Host Ports Summary

| Port | Service |
|---|---|
| 8080 | HTTP (nginx) |
| 8080 | HTTP alt (dev override) |
| 8443 | HTTPS (nginx) |
| 3002 | Backend HTTP fallback |
| 3000 | Chromium/Browserless debug |
| 9229 | Node.js debugger (inspect) |
| 9300 | Enterprise worker health/debug |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 1025 | MailHog SMTP (currently broken) |
| 8025 | MailHog Web UI (currently broken) |

## Environment Variables (.env)

Copy `.env.example` to `.env` and set all values. The backend refuses to start in production if secrets are left at defaults.

| Variable | Purpose |
|---|---|
| `DB_PASSWORD` | PostgreSQL password |
| `REDIS_PASSWORD` | Redis auth |
| `JWT_SECRET` | Access token signing (min 32 chars) |
| `JWT_REFRESH_SECRET` | Refresh token signing (must differ from JWT_SECRET) |
| `ENCRYPTION_KEY` | Data encryption (exactly 32 chars) |
| `CHROMIUM_TOKEN` | Browserless auth token |
| `SMTP_HOST` | Mail server (`mailhog` for dev) |
| `SMTP_PORT` | Mail port (`1025` for dev) |
| `SMTP_USER` | SMTP auth user (blank for dev) |
| `SMTP_PASS` | SMTP auth password (blank for dev) |
| `SMTP_FROM` | Sender address |
| `ADMIN_EMAIL` | Initial admin account email |
| `ADMIN_PASSWORD` | Initial admin account password |
| `SCANNER_LOG_LEVEL` | Log verbosity (`debug` for dev) |
| `ALLOW_PRIVATE_SCAN_TARGETS` | `true` to allow scanning RFC1918/loopback targets (SSRF guard) |
| `SCAN_SOURCE_DIR` | Host path for source code uploads (default `./scan-sources`) |

## Docker Volumes (persistent data)

| Volume | Purpose |
|---|---|
| `postgres_data` | Database files |
| `redis_data` | Redis AOF persistence |
| `reports_data` | Generated scan reports (shared between report-worker and backend) |
| `sast_rules` | SAST rule definitions |
| `trivy_cache` | Trivy vulnerability DB cache |

## TLS / SSL

Self-signed certs live in `nginx/ssl/` (`server.crt`, `server.key`). Nginx terminates TLS on port 443 (host 8443). Generate new ones for the dev server:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/server.key -out nginx/ssl/server.crt \
  -subj "/CN=deep-vigilance.local"
```

## Database

- PostgreSQL 16 with 5 migration files in `postgres/migrations/` (auto-applied on first boot via init scripts)
- 1 seed file in `postgres/seeds/`
- Init scripts in `postgres/init/`

## Bind Mounts (source code — dev override)

The override file mounts local source into containers for hot-reload:

- `backend/src` → backend container
- `scanners/src` → sast, dast, api-scanner, enterprise workers
- `workers/src` → report-worker
- `shared/` → backend + all scanner workers
- `nginx/` → nginx config, SSL, cache
- `postgres/` → migrations, seeds, init

## Networks

- `appsec-internal` — all services communicate here
- `appsec-public` — nginx edge only

## Volume Backups (volume-backups/)

All Docker volume data was exported from the laptop on 2026-06-17. These contain the
full database, queue state, scan reports, and caches — everything needed to restore
the exact state from the laptop.

| Directory | Source Volume | Size | Contents |
|---|---|---|---|
| `volume-backups/postgres_data/` | `app-scanner_postgres_data` | 76M | PostgreSQL 16 data directory — all scan results, users, settings, scan history |
| `volume-backups/redis_data/` | `app-scanner_redis_data` | 26M | Redis AOF + RDB — BullMQ job queues, cached sessions, rate limit state |
| `volume-backups/reports_data/` | `app-scanner_reports_data` | 456K | Generated PDF/HTML scan reports (3 reports) |
| `volume-backups/sast_rules/` | `app-scanner_sast_rules` | 0 | SAST rule overrides (empty — using built-in rules) |
| `volume-backups/trivy_cache/` | `app-scanner_trivy_cache` | 1.1G | Trivy vulnerability DB cache (will auto-update on first scan if stale) |

## Deploying on Dev Server

### Step 1: Copy the folder

Copy the entire `app-scanner/` directory to the dev server. Everything is included:
source code, Dockerfiles, configs, .env, SSL certs, and volume backups.

### Step 2: Restore volume data

Before starting containers, create the Docker volumes and load the backed-up data into them.
Run from inside the `app-scanner/` directory:

```bash
# Create the volumes
docker volume create app-scanner_postgres_data
docker volume create app-scanner_redis_data
docker volume create app-scanner_reports_data
docker volume create app-scanner_sast_rules
docker volume create app-scanner_trivy_cache

# Restore data into each volume
docker run --rm -v app-scanner_postgres_data:/dest -v "$(pwd)/volume-backups/postgres_data:/source:ro" alpine sh -c "cp -a /source/. /dest/"
docker run --rm -v app-scanner_redis_data:/dest -v "$(pwd)/volume-backups/redis_data:/source:ro" alpine sh -c "cp -a /source/. /dest/"
docker run --rm -v app-scanner_reports_data:/dest -v "$(pwd)/volume-backups/reports_data:/source:ro" alpine sh -c "cp -a /source/. /dest/"
docker run --rm -v app-scanner_sast_rules:/dest -v "$(pwd)/volume-backups/sast_rules:/source:ro" alpine sh -c "cp -a /source/. /dest/"
docker run --rm -v app-scanner_trivy_cache:/dest -v "$(pwd)/volume-backups/trivy_cache:/source:ro" alpine sh -c "cp -a /source/. /dest/"
```

Ownership note: PostgreSQL expects uid 70 (postgres user inside the container) to own its
data files. The restore copies preserve the original ownership from the volume, but if
postgres fails to start with permission errors, fix it:

```bash
docker run --rm -v app-scanner_postgres_data:/data alpine sh -c "chown -R 70:70 /data"
```

Similarly for Redis (uid 999):
```bash
docker run --rm -v app-scanner_redis_data:/data alpine sh -c "chown -R 999:999 /data"
```

### Step 3: Update .env if needed

The `.env` file is included as-is from the laptop. If you want fresh secrets, regenerate them:

```bash
# Generate new secrets
openssl rand -base64 48   # for JWT_SECRET
openssl rand -base64 48   # for JWT_REFRESH_SECRET (must be different)
openssl rand -hex 16      # for ENCRYPTION_KEY (exactly 32 hex chars)
openssl rand -base64 32   # for DB_PASSWORD, REDIS_PASSWORD, CHROMIUM_TOKEN
```

If you change `DB_PASSWORD` or `REDIS_PASSWORD`, the restored volume data still has
the old passwords baked in. Either keep the same passwords, or start fresh (delete the
postgres and redis volumes and let init scripts recreate everything).

### Step 4: Regenerate SSL certs (optional)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/server.key -out nginx/ssl/server.crt \
  -subj "/CN=$(hostname)"
```

### Step 5: Start the stack

```bash
docker compose up -d
```

All 13 services will build from local Dockerfiles (no registry needed) and start.
The restored postgres volume means migrations do NOT re-run — the database is already
populated with your scan data, user accounts, and settings from the laptop.

### Step 6: Verify

```bash
# HTTPS should return 200
curl -sk https://localhost:8443

# Backend health check
curl -sk https://localhost:8443/api/health

# Check all containers are healthy
docker compose ps
```

### Starting fresh instead (no data restore)

If you don't need the laptop data, skip step 2 entirely. Docker compose will create
empty volumes, postgres init scripts will run migrations + seeds, and the admin account
from `ADMIN_EMAIL`/`ADMIN_PASSWORD` in `.env` will be created automatically.

## Cleanup (laptop)

After confirming the dev server is working, you can remove everything from the laptop:

```bash
# Remove the Docker volumes (data is already in volume-backups/)
docker volume rm app-scanner_postgres_data app-scanner_redis_data app-scanner_reports_data app-scanner_sast_rules app-scanner_trivy_cache

# Remove built images
docker compose down --rmi local

# Delete the folder
rm -rf app-scanner/
```
