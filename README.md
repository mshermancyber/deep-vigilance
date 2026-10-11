# Deep Vigilance

**Self-hosted application security platform.** SAST across 25+ languages, DAST with a
headless-Chromium crawler, API security testing, SCA with EPSS/KEV enrichment, and secret
scanning — unified into one vulnerability queue with RBAC, scheduling, SARIF/PDF reporting,
and a synchronous single-file endpoint for editors and CI.

Version **0.1.0** · GPL-3.0-or-later · by Mark Sherman

---

## What it is

Most teams run four or five separate security tools and reconcile the output by hand. Deep
Vigilance runs the scanners itself and puts every result — static finding, live vulnerability,
exposed secret, vulnerable dependency — into a single findings table with consistent severity,
CWE, CVSS and EPSS scoring, assignment and triage state.

It runs entirely on your own hardware. Nothing is sent anywhere unless you explicitly configure
an integration.

```bash
git clone https://github.com/mshermancyber/deep-vigilance.git
cd deep-vigilance
cp .env.example .env     # then edit: see INSTALL.md
docker compose up --build -d
```

Then open <https://localhost:8443>. Full instructions, including TLS and production hardening,
are in **[INSTALL.md](./INSTALL.md)**. Day-to-day usage is in
**[USER-GUIDE.md](./USER-GUIDE.md)**.

---

## Scanning

| Scan type | What it does |
|---|---|
| **SAST** | Static analysis over 25+ languages — Java, C#, Go, Python, JS/TS, Ruby, PHP, Rust, Swift, Kotlin, plus Terraform, Dockerfiles and Kubernetes manifests. 150+ rules covering SQL injection, XSS, command injection, SSRF, path traversal, weak crypto, XXE, deserialization, prototype pollution, open redirect and insecure JWT handling. Incremental re-scans and per-rule overrides. |
| **DAST** | Crawls a running target with headless Chromium, so single-page apps and JS-rendered routes are reachable. Form discovery, authenticated replay, and WAF-aware probing. |
| **API** | Discovers endpoints or imports OpenAPI/Swagger/Postman collections, then fuzzes parameters and scores each endpoint's risk. |
| **SCA** | Reads dependency manifests, matches against vulnerability data, and enriches with EPSS probability and CISA KEV membership so you can rank by real-world exploitation rather than CVSS alone. |
| **Secrets** | Dedicated high-signal secret engine with provider-specific patterns and false-positive suppression for test fixtures and vendored code. |
| **Container / binary / protocol** | Image layer scanning and, with the optional integrations configured, binary submission and detonation reports. |

Scans run as BullMQ jobs against Redis. A **stuck-scan reaper** marks abandoned scans failed so
they never accumulate, and **retention jobs** prune old data on a schedule (see below).

## Working with findings

- One findings table across every scan type, with severity, CWE, CVE, CVSS, EPSS and KEV match.
- Status workflow: open → in progress → resolved / closed / false positive / won't fix.
- Comments, assignment, and SLA tracking per finding.
- **Natural-language search** — "critical sql injection from last month" is parsed into filters.
  Works without an LLM via a keyword parser; sharper with one configured.
- **AI triage (optional)** — rates each finding's false-positive probability with reasoning, root
  cause, exploitability and a suggested fix. Set `OPENAI_API_KEY` in `.env` to enable. With no key
  the platform falls back to a local heuristic engine, so nothing breaks and no data leaves the host.

## Reporting and export

Five formats — PDF, HTML, JSON, CSV, Markdown — across Executive, Developer, Compliance, OWASP,
API, SAST, DAST and Summary templates. **SARIF 2.1.0** export for GitHub code scanning, and
CycloneDX **SBOM** generation.

## Editor and CI integration

`POST /api/scan/inline` is synchronous, single-file, sub-second, writes nothing to the database,
and returns line-numbered findings. It is built for editors, pre-commit hooks and agents — see
[docs/inline-scan-api.md](./docs/inline-scan-api.md). DAST is deliberately *not* inline since it
needs a running target; launch it asynchronously via `POST /api/scans/launch` and poll.

A GitHub Action, GitLab CI template, Jenkins pipeline and standalone CLI live under
[`cicd/`](./cicd/).

## Administration

- Organizations, teams and projects.
- Seven roles — super admin, admin, security lead, security analyst, developer, viewer, service
  account — with granular permissions.
- JWT with refresh-token rotation, TOTP MFA, service-account API keys.
- Immutable audit log.
- Scan scheduling: now, hourly, daily, weekly, monthly, or a custom cron expression with timezone.
- Integrations for GitHub, GitLab, Bitbucket, Jira, Slack, Teams, Discord, generic webhooks, SMTP
  and SIEM forwarding.

## Retention and cleanup jobs

A long-lived install accumulates data nobody reads again. A housekeeping cycle prunes it on a
timer, entirely driven from `.env`:

```ini
CLEANUP_INTERVAL_MIN=360     # how often a cycle runs; 0 disables cleanup
RETAIN_SCANS_DAYS=90         # finished scans and their findings
RETAIN_AUDIT_LOG_DAYS=365
RETAIN_REPORTS_DAYS=90       # report rows and the files on disk
RETAIN_QUEUE_JOBS_DAYS=7     # completed BullMQ jobs in Redis
```

Any threshold set to `0` means *never prune that table*. Only terminal-state rows are ever
touched — a running scan or an in-flight code review survives regardless of age. Deletes run in
bounded batches so a first run on a large database never holds a long table lock, and a safety
rail (`CLEANUP_MAX_TABLE_FRACTION`) aborts a prune that would remove more than half a table,
which catches a mistyped retention window before it destroys live data.

Operators can inspect the configuration at `GET /api/admin/cleanup` and trigger a cycle on
demand with `POST /api/admin/cleanup/run`, which returns exactly what was removed.

---

## Architecture

```
                      ┌─────────────────────────────┐
                      │   nginx — TLS edge :8443    │
                      │  the only published ingress │
                      └──────────────┬──────────────┘
                                     │
                ┌────────────────────┴────────────────────┐
                │                                         │
      ┌─────────▼─────────┐                   ┌───────────▼──────────┐
      │ Frontend          │                   │ Backend API + WS     │
      │ Angular 18        │                   │ Node 20 / Express    │
      └───────────────────┘                   └───────────┬──────────┘
                                                          │
                     ┌────────────────────────────────────┼───────────────┐
                     │                                    │               │
            ┌────────▼────────┐                 ┌─────────▼────────┐  ┌───▼────┐
            │ PostgreSQL 16   │                 │ Redis 7 + BullMQ │  │Chromium│
            └─────────────────┘                 └─────────┬────────┘  └───┬────┘
                                                          │               │
        ┌──────────┬──────────┬──────────┬────────────────┴───┬───────────┘
        │          │          │          │                    │
   ┌────▼───┐ ┌────▼───┐ ┌────▼───┐ ┌────▼─────┐ ┌────────────▼──┐
   │  SAST  │ │  DAST  │ │  API   │ │   SCA    │ │ secret/report │
   │ worker │ │ worker │ │ worker │ │  worker  │ │    workers    │
   └────────┘ └────────┘ └────────┘ └──────────┘ └───────────────┘
```

**Only nginx publishes a host port.** The API (`3000`), WebSocket (`3001`), PostgreSQL and Redis
are reachable solely over internal Docker networks — there is no way to bypass the TLS edge and
its access controls. `docker-compose.override.yml` additionally exposes Postgres, Redis and a
debugger for local development; it is not used in production.

| Service | Image / stack | Published | Role |
|---|---|---|---|
| nginx | nginx:1.25-alpine | `8080`, `8443` | TLS termination, reverse proxy, the only ingress |
| frontend | Angular 18 | — | Web UI, standalone components, dark mode |
| backend | Node 20 / Express 4 | — | REST API + WebSocket, migrations, reaper, cleanup jobs |
| sast / dast / api / sca / secret workers | Node 20 | — | Scan execution |
| report-worker | Node 20 | — | PDF / HTML / JSON / CSV / Markdown generation |
| postgres | PostgreSQL 16 | — | Primary datastore |
| redis | Redis 7 | — | Queue backend, cache, pub/sub |
| chromium | browserless/chrome | — | Headless browser for DAST |
| mailhog | mailhog/mailhog | `1025`, `8025` | Mail interception, development only |

Ports are set by `HTTP_PORT` / `HTTPS_PORT` in `.env` if the defaults collide with something else
on the host.

### Scanner persistence invariant

Every worker persists through `scanners/src/utils/scan-store.ts`:
`startScan(scanId)` → `storeFinding(...)` per finding → `completeScan(scanId, count, meta)`, with
`failScan` on error. A worker that merely computes and returns results persists **nothing** — the
scan sits queued forever with the results stranded in the BullMQ job's `returnvalue`. The
backend's `QueueEvents('completed')` handler reconciles that case as a safety net, but workers are
expected to call the store directly.

---

## Security posture

- Helmet security headers — CSP, HSTS, X-Frame-Options.
- JWT with refresh-token rotation; TOTP MFA; rate limiting on auth endpoints.
- AES-256-GCM encryption at rest for stored integration secrets.
- Parameterized SQL throughout; Zod request validation; HTML sanitization.
- CSRF protection, request IDs, and an immutable audit log.
- Internal Docker networks for datastores, with no published ports.
- SSRF guard on scan targets: private, loopback, link-local and cloud-metadata addresses are
  blocked by default. `ALLOW_PRIVATE_SCAN_TARGETS=true` permits private and loopback ranges for
  self-hosted internal scanning; metadata and link-local stay blocked either way.
- The backend refuses to start in production if any secret is left at a placeholder value.

Please read [SECURITY.md](./SECURITY.md) before exposing an instance beyond a trusted network, and
for how to report a vulnerability.

---

## Documentation

| Document | Contents |
|---|---|
| [INSTALL.md](./INSTALL.md) | Requirements, configuration, TLS, first run, upgrades, production hardening, troubleshooting |
| [USER-GUIDE.md](./USER-GUIDE.md) | Projects, running each scan type, triage, reporting, scheduling, API usage |
| [docs/inline-scan-api.md](./docs/inline-scan-api.md) | The synchronous single-file scan endpoint |
| [docs/architecture/ARCHITECTURE.md](./docs/architecture/ARCHITECTURE.md) | Component and data-flow detail |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Deployment reference |
| [SAST_TUNING.md](./SAST_TUNING.md) | Rule tuning and false-positive reduction, with corpus results |
| [SECURITY.md](./SECURITY.md) | Security policy and vulnerability reporting |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Development setup and contribution workflow |
| [CHANGELOG.md](./CHANGELOG.md) | Release history |

Internal engineering notes kept with the release — a feature log, build/debug history, backlog and
file manifest — are listed in [CHANGELOG.md](./CHANGELOG.md) under *Repository layout*.

---

## Tech stack

**Frontend** Angular 18, TypeScript, Angular Material, RxJS, Chart.js, Socket.IO client
**Backend** Node 20, Express 4, TypeScript 5.9, PostgreSQL 16, Redis 7, BullMQ, Socket.IO, Pino, Zod
**Infrastructure** Docker Compose, nginx

---

## License

GNU General Public License v3.0 or later — see [LICENSE](./LICENSE).

Deep Vigilance is distributed in the hope that it will be useful, but **without any warranty**;
without even the implied warranty of merchantability or fitness for a particular purpose.

---

## A note on authorized use

Deep Vigilance performs active security testing. DAST and API scans send real traffic to whatever
target you point them at, which can trigger rate limits, create records, or degrade a service.

**Only scan systems you own or have explicit written authorization to test.** Unauthorized
scanning is illegal in most jurisdictions. The SSRF guard is on by default for this reason;
turning it off is a deliberate choice for internal scanning on infrastructure you control.
