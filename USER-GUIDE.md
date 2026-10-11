# Deep Vigilance — User Guide

Version 0.1.0

This guide covers day-to-day use: setting up projects, running each scan type, triaging findings,
reporting, scheduling, and driving the platform from the API. For getting the stack running, see
**[INSTALL.md](./INSTALL.md)**.

> **Scan only what you are authorized to scan.** DAST and API scans send real traffic to the
> target. See [*Authorized use*](#authorized-use) at the end.

---

## Contents

1. [Signing in and user management](#1-signing-in-and-user-management)
2. [Projects](#2-projects)
3. [Running scans](#3-running-scans)
4. [Triaging findings](#4-triaging-findings)
5. [Searching](#5-searching)
6. [AI triage](#6-ai-triage)
7. [Reports and exports](#7-reports-and-exports)
8. [Scheduling](#8-scheduling)
9. [Integrations and notifications](#9-integrations-and-notifications)
10. [Editor, hook and CI integration](#10-editor-hook-and-ci-integration)
11. [Using the REST API](#11-using-the-rest-api)
12. [Housekeeping and retention](#12-housekeeping-and-retention)
13. [Authorized use](#authorized-use)

---

## 1. Signing in and user management

Open `https://<host>:8443` and sign in with the `ADMIN_EMAIL` / `ADMIN_PASSWORD` you set in
`.env`. **Change that password immediately**, then create individual accounts rather than sharing
the admin login.

### Roles

| Role | Intended for |
|---|---|
| `super_admin` | Full control, including all organizations and platform settings |
| `admin` | Organization administration, users, integrations |
| `security_lead` | Owns the security programme: launch any scan, triage, assign, close findings |
| `security_analyst` | Runs scans and triages findings; cannot change org settings |
| `developer` | Sees findings for their projects, comments, marks work resolved |
| `viewer` | Read-only |
| `service_account` | Non-human API access via an API key |

Permissions are granular and checked per endpoint, so a role change takes effect immediately on
the next request.

### MFA

TOTP-based MFA is available per user under **Settings → Security**. Scan the QR code with any
authenticator app and confirm one code to enable it.

### Service accounts

For CI, editors and scripts, create a service account under **Admin → Service Accounts** rather
than using a personal login. You get an API key that carries only the permissions you grant, can
be revoked independently, and shows up distinctly in the audit log.

---

## 2. Projects

A **project** is the unit everything attaches to: scans, findings, reports, schedules. Create one
per application or repository.

**Projects → New Project.** Useful fields:

| Field | Used by |
|---|---|
| `name` | Everything |
| `repository` | SAST — the git URL to clone and scan |
| `targetUrl` | DAST — the running application to crawl |
| `apiBaseUrl` | API scanning — base URL for discovered or imported endpoints |
| `authType` + credentials | DAST and API scans needing an authenticated session. Supports none, basic, bearer, jwt, oauth, api_key, mtls and digest. Credentials are encrypted at rest with AES-256-GCM. |

Severity thresholds and ignore patterns can be set per project so a noisy vendored directory does
not have to be re-excluded on every scan.

---

## 3. Running scans

**Scans → New Scan**, or `POST /api/scans/launch`. Pick the project, the scan type, and a name you
will recognise later.

Every scan is queued to Redis and picked up by its worker. Progress streams to the UI over
WebSocket — the scan page updates live without refreshing.

### SAST — static analysis

Scans source code without running it. 150+ rules across 25+ languages, plus Terraform, Dockerfiles
and Kubernetes manifests.

Two ways to point it at code:

- **Mounted path** — put the code under `SCAN_SOURCE_DIR` (mounted into the workers as `/scan`)
  and set `options.targetPath` to the subdirectory, e.g. `/scan/my-app`.
- **Git clone** — set `options.repoUrl`, plus `options.branch` and `options.gitToken` for a private
  repository. The token is injected into the clone URL and is never logged.

> **Always set `options.targetPath`.** A SAST or secret scan launched without one defaults to all
> of `/scan`. If you mounted a large directory, the scan will grind for hours at full CPU. This is
> the single most common mistake — see `SECRET-SCAN-OPS.md`.

Narrow the scope with `options.includePatterns` / `options.excludePatterns`. Re-scans of an
already-indexed project are incremental.

### DAST — dynamic analysis

Crawls a **running** application with headless Chromium, so JS-rendered routes and single-page
apps are reachable, then probes what it finds.

Set `options.targetUrl`, or leave it off to use the project's `targetUrl`. For authenticated
scanning, attach a DAST auth profile so the crawler can log in and replay the session;
`options.customHeaders` works for simple token auth.

By default, private, loopback, link-local and cloud-metadata addresses are refused — an SSRF
guard, since a scan target is attacker-influenced input. To scan internal hosts on infrastructure
you control, set `ALLOW_PRIVATE_SCAN_TARGETS=true` in `.env`. Metadata and link-local addresses
stay blocked either way.

DAST is the slowest scan type. Start with a narrow `maxDepth`.

### API security

Point it at an API and it will discover endpoints, or import a spec:

- `options.openApiSpec` / `options.swaggerDoc` — inline OpenAPI/Swagger
- Import a Postman collection through **API Client → Import**

It then fuzzes parameters and scores each endpoint's risk. Results land in the same findings table
as everything else.

### SCA — dependency scanning

Reads dependency manifests under the target path and matches them against vulnerability data.
Findings carry CVE, CVSS, **EPSS** (probability of exploitation in the wild) and **KEV** (CISA
Known Exploited Vulnerabilities) membership.

Rank by EPSS and KEV rather than CVSS alone — a KEV-listed medium is a more urgent problem than a
critical nobody has ever exploited.

### Secret scanning

A dedicated engine with provider-specific patterns (AWS, GCP, GitHub, Slack, Stripe, private keys,
JWTs and more) and suppression for test fixtures, vendored code and generated files.

Scope it with `options.targetPath`, as with SAST.

### `full`

Runs the applicable scan types for the project in one go. Convenient for a scheduled nightly job.

### If a scan gets stuck

Scans sitting in `queued` or `running` past `SCAN_MAX_RUNTIME_MIN` (default 30) are marked
`failed` by the reaper, which runs every 20 minutes. It will not touch a scan that is genuinely
progressing. If scans never start at all, the worker for that type probably is not running:

```bash
docker compose logs --tail 50 sast-worker
```

---

## 4. Triaging findings

**Findings** shows every result from every scan type in one table, sorted by severity rank.

Each finding carries severity, type, CWE, CVE, CVSS, EPSS, KEV match, file path and line number,
the offending code snippet, a description, and a recommendation. DAST findings additionally carry
request/response evidence.

### Status workflow

| Status | Meaning |
|---|---|
| `open` | New, untriaged |
| `in_progress` | Being worked on |
| `resolved` | Fixed, pending verification |
| `closed` | Verified fixed |
| `false_positive` | Not a real issue |
| `wont_fix` | Real, accepted as risk |

Change status in the UI, or `PATCH /api/findings/:id`. Assign findings to a user, and discuss them
in per-finding comments. Marking something `false_positive` or `wont_fix` is the right move — it
keeps the open count meaningful, and the decision stays recorded in the audit log.

### Reducing noise

If a rule is consistently wrong for your codebase, do not ignore findings one at a time:

- Add project-level exclude patterns for vendored, generated or test directories.
- Create a per-rule override under **Settings → SAST Rules** to downgrade or disable it.
- See **[SAST_TUNING.md](./SAST_TUNING.md)**, which documents tuning against a 19-repository
  corpus and the false-positive rates that resulted.

---

## 5. Searching

The findings filter bar covers project, scan, severity, status, type, CWE, assignee and free text
across title, description and file path.

**Search** also accepts natural language:

```
critical sql injection findings from last month
high severity secrets in python files
open xss findings assigned to me
```

This works with no AI configured — a keyword parser maps severities, vulnerability names to CWE
IDs, scan types and relative dates ("last week", "last 30 days", "yesterday") into real filters.
With an LLM configured it handles phrasing the keyword parser misses. Either way the parsed
filters are shown, so you can see how your query was interpreted.

---

## 6. AI triage

Optional. Set `OPENAI_API_KEY` in `.env` (see [INSTALL.md §7](./INSTALL.md#7-optional-features)).

With a key configured you get, per finding:

- a **false-positive probability** with a confidence score,
- short **reasoning** for the verdict,
- a **root cause** and **exploitability** assessment,
- a **suggested fix**.

Select multiple findings and **Batch Review** to triage up to 30 at once — useful for working
through a first scan's backlog.

With no key set, the same endpoints answer from a local heuristic engine that scores based on CWE
base rates, whether the path looks like a test or vendor directory, severity and scanner
confidence. Less sharp, but it runs locally and **no finding data leaves your host**.

The `provider` field on every AI response tells you which path answered — `local` or
`llm:<model>`.

> With a key configured, finding metadata — title, severity, CWE, file path, a code snippet and
> the description — is sent to that provider. If your code cannot leave your network, either leave
> the key unset or point `AI_API_URL` at a local model gateway.

AI output is advisory. A high false-positive probability is a hint about where to look first, not
permission to close a finding unread.

---

## 7. Reports and exports

**Reports → New Report.** Choose a template and a format:

| Templates | Formats |
|---|---|
| Executive, Developer, Compliance, OWASP, API, SAST, DAST, Summary | PDF, HTML, JSON, CSV, Markdown |

Reports generate asynchronously; the page updates when the file is ready, then downloads via
`GET /api/reports/:id/download`.

Filter the contents by project, severity, status, date range or scan before generating — an
executive PDF of every informational finding is not useful to anyone.

### SARIF

`GET /api/findings/sarif` exports SARIF 2.1.0, which GitHub code scanning, GitLab and most IDEs
ingest directly. The `cicd/github-action` wrapper uploads it for you.

### SBOM

Generate a CycloneDX SBOM for a project under **SBOM**. With `SBOM_VISUALIZER_URL` configured you
also get an interactive dependency graph; without it, the SBOM still exports normally.

### Compliance

**Compliance** maps findings onto OWASP Top 10 (2021) and generates license-audit reports from SCA
results.

---

## 8. Scheduling

**Scheduler → New Schedule**, or `POST /api/scheduler`:

```json
{
  "name": "Nightly SAST — checkout service",
  "projectId": "<uuid>",
  "scanType": "sast",
  "schedule": "daily",
  "timezone": "America/New_York",
  "options": { "targetPath": "/scan/checkout" }
}
```

`schedule` is one of `now`, `hourly`, `daily`, `weekly`, `monthly` or `cron`. With `cron`, supply
a standard five-field `cronExpression`. `timezone` is a full IANA name and defaults to `UTC` —
set it, or "daily" will fire at UTC midnight.

Schedules have an overlap guard: if the previous run of a schedule is still going, the next firing
is skipped rather than queued behind it. The schedule list shows last run and next run, and any
schedule can be disabled without deleting it.

A practical pattern: nightly SAST, SCA and secret scans per project; weekly DAST, since it is
slower and noisier.

---

## 9. Integrations and notifications

**Integrations** connects: GitHub, GitLab, Bitbucket, Jira, Slack, Teams, Discord, generic
webhooks, SMTP email and SIEM forwarding. Credentials are encrypted at rest.

Typical setup:

- **Slack / Teams / Discord** — notify a channel on new critical or high findings.
- **Jira** — open a ticket from a finding, keeping the link both ways.
- **GitHub / GitLab** — attach a repository for SAST cloning, and push SARIF back to code scanning.
- **Webhooks** — POST finding events anywhere. Failed deliveries land in a dead-letter queue
  visible under **Admin**, retried and eventually pruned by the retention job.

Tune notifications to new **critical and high** findings only. A notification on every
informational finding gets muted within a day, and then the critical one gets missed too.

---

## 10. Editor, hook and CI integration

### Synchronous single-file scan

`POST /api/scan/inline` is built for interactive use: synchronous, single file, sub-second, no
queue, no database write. It runs SAST, secret detection and SCA-manifest matching, and returns
line-numbered findings.

```bash
curl -sk -X POST https://localhost:8443/api/scan/inline \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "filename": "src/db.js",
        "content": "const q = \"SELECT * FROM users WHERE id = \" + req.query.id;"
      }'
```

Ideal for editor plugins, pre-commit hooks and coding agents. Full reference:
**[docs/inline-scan-api.md](./docs/inline-scan-api.md)**.

DAST is deliberately *not* available inline, because it needs a running target. Launch it
asynchronously and poll:

```bash
# launch
curl -sk -X POST https://localhost:8443/api/scans/launch \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"projectId":"<uuid>","scanType":"dast","name":"staging sweep",
       "options":{"targetUrl":"https://staging.example.com"}}'
# → {"scanId":"..."}

# poll
curl -sk https://localhost:8443/api/scans/<scanId>          -H "Authorization: Bearer $TOKEN"
curl -sk https://localhost:8443/api/scans/<scanId>/findings -H "Authorization: Bearer $TOKEN"
```

### CI

Ready-made wrappers live in **[`cicd/`](./cicd/)**: a GitHub Action, a GitLab CI template, a
Jenkins pipeline, and a standalone CLI. They launch a scan, wait for it, upload SARIF, and can
fail the build on a severity threshold.

Authenticate CI with a **service account** API key, not a personal login.

---

## 11. Using the REST API

Everything the UI does is the same REST API, under `/api`.

```bash
# Log in
TOKEN=$(curl -sk -X POST https://localhost:8443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"..."}' \
  | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)

# Use it
curl -sk https://localhost:8443/api/dashboard/summary -H "Authorization: Bearer $TOKEN"
```

Access tokens are short-lived; refresh with `POST /api/auth/refresh`. For non-interactive use, a
service-account API key avoids the refresh dance entirely.

### Main route groups

| Route | Purpose |
|---|---|
| `/api/auth` | Login, refresh, logout, MFA |
| `/api/projects` | Project CRUD |
| `/api/scans` | Launch, list, inspect, cancel scans |
| `/api/findings` | List, filter, update, comment; SARIF export |
| `/api/scan/inline` | Synchronous single-file scan |
| `/api/reports` | Generate and download reports |
| `/api/scheduler` | Scheduled scans |
| `/api/search` | Natural-language and structured search |
| `/api/dashboard` | Summary metrics and trends |
| `/api/ai` | Finding analysis, batch review, AI status |
| `/api/sbom` | SBOM generation and analysis |
| `/api/compliance` | OWASP mapping, license audit |
| `/api/integrations`, `/api/webhooks` | Outbound integrations |
| `/api/admin` | Audit log, orgs, service accounts, system health, cleanup |
| `/api/settings` | Platform and scanner settings |
| `/api/users` | User management |
| `/api/api-client` | Built-in API client: collections, environments, history |
| `/api/code-review`, `/api/container-scan`, `/api/advanced-scan` | Code review, image and binary scanning |

Useful filters on `GET /api/findings`: `projectId`, `scanId`, `severity`, `status`, `type`,
`cweId`, `assignedTo`, `search`, plus `sortBy` (`severity_rank`, `cvss_score`, `created_at`,
`title`), `sortOrder`, `page` and `limit`.

`GET /api/health` needs no authentication and is what the container health checks use.

---

## 12. Housekeeping and retention

Two background jobs keep a long-lived install from degrading:

- **The reaper** marks scans abandoned past `SCAN_MAX_RUNTIME_MIN` as `failed`, every 20 minutes.
  Without it, every worker restart leaves phantom "running" scans behind.
- **Retention jobs** prune data nobody reads again — finished scans and their findings, reports and
  their files, audit entries, delivered notifications, API request history, webhook dead letters,
  expired sessions, and completed queue jobs in Redis.

Retention windows are set in `.env`; see
[INSTALL.md §8](./INSTALL.md#8-retention-and-cleanup-jobs) for the full list and the safety rails.
Defaults keep 90 days of scans, 365 days of audit log and 7 days of queue jobs. Any value of `0`
means *never prune that table*.

Inspect the configuration and trigger a cycle from **Admin**, or:

```bash
curl -sk https://localhost:8443/api/admin/cleanup          -H "Authorization: Bearer $TOKEN"
curl -sk -X POST https://localhost:8443/api/admin/cleanup/run -H "Authorization: Bearer $TOKEN"
```

The `POST` returns exactly what was deleted, per table. Run it once by hand after you settle on
retention windows, so the first and largest prune happens while you are watching.

A running scan or an in-flight code review is never pruned regardless of age, and a prune that
would delete more than half a table aborts with a warning rather than proceeding.

---

## Authorized use

Deep Vigilance performs active security testing. DAST and API scans send real requests to the
target: they submit forms, follow links, fuzz parameters and can create records, trigger rate
limits, fire alerts or degrade a service under load.

**Only scan systems you own or have explicit written authorization to test.** Unauthorized
scanning is illegal in most jurisdictions, and "I was just testing" is not a defence.

Practical guidance:

- Scan staging before production. If you must scan production, agree a window with whoever is on
  call.
- Keep `ALLOW_PRIVATE_SCAN_TARGETS=false` unless you deliberately scan internal hosts on
  infrastructure you control. It is the SSRF guard, and it is on by default for a reason.
- Treat scan output as sensitive. A findings list is a map of how to attack your application, and
  secret-scan results may contain live credentials — rotate anything the scanner finds, because
  discovery means it was exposed.
