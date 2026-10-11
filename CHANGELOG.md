# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-11

First public release.

Deep Vigilance has been running as a working self-hosted platform; this is its first release as a
self-contained, portable repository. Everything host-specific has been replaced with
configuration, and no credential, address or hostname from the development environment ships in
the tree.

### Added

- **Five scan types in one findings model** — SAST (150+ rules across 25+ languages, plus
  Terraform, Dockerfiles and Kubernetes manifests), DAST (headless-Chromium crawler with
  authenticated replay), API security (endpoint discovery, OpenAPI/Swagger/Postman import,
  parameter fuzzing), SCA (manifest matching with EPSS probability and CISA KEV enrichment), and a
  dedicated secret-detection engine. Container, binary and protocol scanning round it out.
- **Unified finding triage** — one table across every scan type with severity, CWE, CVE, CVSS,
  EPSS and KEV match; a six-state status workflow; assignment, comments and SLA tracking.
- **Synchronous inline scan endpoint** — `POST /api/scan/inline`: single file, sub-second, no
  queue and no database write, returning line-numbered findings. Built for editors, pre-commit
  hooks and coding agents.
- **Retention and cleanup jobs** (`backend/src/core/cleanup.ts`) — a scheduled housekeeping cycle
  prunes finished scans and their findings, report rows and the files on disk, audit entries,
  delivered notifications, API request history, webhook dead letters, expired sessions and
  completed BullMQ jobs. Every window is set in `.env`, `0` disables a table, only terminal-state
  rows are ever touched, deletes run in bounded batches, and a configurable fraction guard aborts
  a prune that would remove more than half a table. Exposed at `GET /api/admin/cleanup` and
  `POST /api/admin/cleanup/run`.
- **Stuck-scan reaper** — marks scans abandoned past `SCAN_MAX_RUNTIME_MIN` as failed, so a worker
  restart no longer leaves phantom running scans behind.
- **AI finding triage, optional and provider-agnostic** — false-positive probability with
  reasoning, root cause, exploitability and a suggested fix, plus natural-language finding search.
  Defaults to the OpenAI (ChatGPT) API, reading `OPENAI_API_KEY` from `.env`. Any
  OpenAI-compatible endpoint works by pointing `AI_API_URL` at it. With no key configured every
  endpoint falls back to a local heuristic engine, so the platform is fully functional and no
  finding data leaves the host.
- **Reporting** — PDF, HTML, JSON, CSV and Markdown across Executive, Developer, Compliance,
  OWASP, API, SAST, DAST and Summary templates; SARIF 2.1.0 export for GitHub code scanning;
  CycloneDX SBOM generation; OWASP Top 10 (2021) mapping and license auditing.
- **Scheduling** — now, hourly, daily, weekly, monthly or a custom cron expression with full IANA
  timezone support, and an overlap guard that skips a firing while the previous run is still going.
- **Access control** — organizations, teams and projects; seven roles with granular per-endpoint
  permissions; JWT with refresh-token rotation; TOTP MFA; service-account API keys; an immutable
  audit log.
- **Integrations** — GitHub, GitLab, Bitbucket, Jira, Slack, Teams, Discord, generic webhooks with
  a dead-letter queue, SMTP and SIEM forwarding. Stored credentials are encrypted at rest with
  AES-256-GCM.
- **CI/CD wrappers** — GitHub Action, GitLab CI template, Jenkins pipeline and a standalone CLI
  under `cicd/`.
- **Documentation** — `INSTALL.md` (requirements, configuration, TLS, first run, optional
  features, retention tuning, production hardening, upgrades, troubleshooting), `USER-GUIDE.md`
  (projects, every scan type, triage, search, reporting, scheduling, API usage) and
  `REPO-DESCRIPTION.txt`.
- **GPL-3.0-or-later licensing** across all four packages.

### Changed

- **AI provider defaults moved to OpenAI/ChatGPT.** All references to the previous default provider
  were removed. Configuration is read from the environment first — `OPENAI_API_KEY`,
  `OPENAI_API_URL`, `OPENAI_MODEL`, with the generic `AI_*` names accepted as aliases — and the
  encrypted `platform_settings` rows now act as an optional in-app override rather than the
  primary source.
- **Report paths unified.** The backend report service, the report worker and the download route
  disagreed on where report files live (`/tmp/appsec-reports`, `/app/reports` and a path derived
  from the working directory). All three now resolve `REPORT_DIR`, the compose volume mounts at
  one path, and the backend's mount is writable so the retention job can unlink files.
- **Published ports are configuration, not constants.** The nginx edge reads `HTTPS_PORT` /
  `HTTP_PORT` (defaults `8443` / `8080`), and every development-only port in
  `docker-compose.override.yml` is overridable. Only nginx publishes a host port; the API,
  WebSocket, PostgreSQL and Redis stay on internal networks.
- **Certificate generation works from a checkout.** `scripts/generate-certs.sh` previously wrote
  to a hardcoded `/etc/nginx/ssl`, which fails on the host, where nginx mounts the directory
  read-only. It now resolves paths relative to the repository root and takes `CERT_DIR`,
  `INTERNAL_CERT_DIR`, `CERT_CN`, `CERT_SAN`, `CERT_SUBJ` and `CERT_DAYS` overrides, with no
  machine identity baked into the subject.
- **Product version reported from one place.** `APP_VERSION` in `backend/src/version.ts` now backs
  the API root, the health endpoint and SARIF tool metadata, which previously carried independent
  hardcoded strings.
- **Optional integrations self-disable.** The FraudVault and SBOM Visualizer clients no longer
  carry fallback URLs or credentials. Each reports itself unconfigured unless the matching `.env`
  variables are set, and the features they back degrade cleanly rather than failing.

### Fixed

- `OPENAI_*` variables set in `.env` never reached the containers — only the generic `AI_*` names
  were forwarded by compose, so a key set under the documented name was silently ignored.
- The retention cycle's `code_reviews` filter excluded a status (`running`) that does not exist in
  the schema while leaving six real in-flight states (`cloning`, `indexing`, `analyzing`,
  `reviewing`, `fuzzing`, `queued`) eligible for deletion. It now matches terminal states
  explicitly. The `notifications` filter likewise referenced a non-existent `delivered` status.
- Several directories required by compose bind mounts were absent from a fresh checkout
  (`nginx/ssl`, `nginx/cache`, `certs`, `data/*`, `scan-sources`, `postgres/init`,
  `scanners/sast/rules`). Each now ships a visible `PLACEHOLDER.md`, so the layout survives both
  `git clone` and a GitHub web-UI upload, with contents git-ignored.
- Removed stray directories created by an unexpanded shell brace (`scanners/sast/{rules/...}`) and
  empty scaffolding directories that were never used.

### Security

- No secret, credential, API key, IP address, hostname, username or host filesystem path from the
  development environment is present in the release. The live `.env` is excluded; `.env.example`
  carries placeholders only, and the backend refuses to start in production with any secret left
  at a placeholder value.
- A hardcoded vulnerability-feed API key and a hardcoded integration email/password pair that had
  been compose and source defaults were removed.
- SSRF guard on scan targets: private, loopback, link-local and cloud-metadata addresses are
  blocked by default. `ALLOW_PRIVATE_SCAN_TARGETS` relaxes only the private and loopback ranges;
  metadata and link-local remain blocked unconditionally.
- Report-file deletion in the retention job is bounded to `REPORT_DIR`, and filenames are derived
  from a UUID and a `CHECK`-constrained format rather than from stored path data.
- Helmet security headers, CSRF protection, rate limiting on auth endpoints, parameterized SQL,
  Zod request validation, HTML sanitization, and an immutable audit log.

### Known limitations

- Self-signed certificates are generated by default, so browsers warn until a real certificate is
  installed. See [INSTALL.md §3](./INSTALL.md#3-generate-certificates).
- `CORS_ORIGIN` defaults to `*`, which reflects the requesting origin. Convenient on a private
  network; pin it before exposing an instance.
- DAST is the slowest scan type and benefits from a conservative `maxDepth` on a first run.
- Container, binary and protocol scanning depend on optional external services; without them
  configured, those scan types report as unconfigured.
- The first retention cycle on a long-running database can delete a large number of rows. Trigger
  it manually once via `POST /api/admin/cleanup/run` and watch the result before leaving it on a
  timer.

### Repository layout

Alongside the code and the user-facing documentation, the release carries the engineering notes
accumulated while building the platform, sanitized of host-specific detail:

| File | Contents |
|---|---|
| `PROGRESS.md` | Feature and task completion log |
| `Build_Debug.md` | Build and deployment debugging history |
| `MANIFEST.md` | Full file-by-file manifest |
| `BACKLOG.md`, `FEATURE_BACKLOG.md`, `ACTION_LIST.md` | Outstanding work, prioritized |
| `STUB_REPORT.md` | Audit of remaining stubs and placeholders |
| `findings.md` | Self-review of the platform's own code |
| `SAST_TUNING.md` | Rule tuning methodology and corpus results |
| `SECRETS-HUNTER-SPEC.md`, `SECRETS-HUNTER-RULESET.md`, `SECRET-SCAN-OPS.md` | Secret-engine specification, ruleset and operational runbook |
| `SAST-DAST-HARDENING-TASK.md` | Scanner hardening notes |
| `DEPLOYMENT.md` | Deployment reference |
| `mobile.md` | Task brief for a future mobile-optimized layout (not implemented) |
| `CLAUDE.md` | Repository conventions and architecture invariants for AI coding assistants |

[0.1.0]: https://github.com/mshermancyber/deep-vigilance/releases/tag/v0.1.0
