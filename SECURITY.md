# Security Policy

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting on this repository:

**<https://github.com/mshermancyber/deep-vigilance/security/advisories/new>**

Include, as far as you can:

- what the issue is and which component it affects,
- the version or commit you tested,
- steps to reproduce, or a proof of concept,
- the impact you think it has.

You will get an acknowledgement, and a fix or an explanation of why something is working as
intended. Please give a reasonable window before disclosing publicly. This is a single-maintainer
project, so response times are best-effort rather than contractual.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

Deep Vigilance is pre-1.0. Security fixes land on the latest release.

## Scope

In scope: authentication and session handling, the RBAC permission model, SQL injection, SSRF in
scan-target handling, path traversal in report and scan paths, secret handling and encryption at
rest, container and compose configuration that weakens the default posture, and anything that lets
one organization read another's data.

Out of scope: findings produced by the scanners against *your* code (that is the tool working);
false positives and false negatives in scan rules — report those as ordinary issues; the browser
certificate warning from the default self-signed certificate; and anything that requires an
operator to have already disabled a documented safeguard.

## Deploying this safely

Deep Vigilance holds a map of how to attack the applications it scans, and secret-scan results may
contain live credentials. Treat an instance as a sensitive system.

Before exposing one beyond a trusted network, work through
[INSTALL.md §9, *Production hardening*](./INSTALL.md#9-production-hardening). The essentials:

- Replace the self-signed certificate with one from a real CA.
- Pin `CORS_ORIGIN` to your actual origin instead of `*`.
- Set `NODE_ENV=production`, which activates the assertions that refuse placeholder secrets.
- Generate every secret in `.env` with `openssl rand`. Never reuse the examples.
- Leave `ALLOW_PRIVATE_SCAN_TARGETS=false` unless you deliberately scan internal hosts on
  infrastructure you control. It gates the SSRF guard on private and loopback ranges; cloud
  metadata and link-local addresses stay blocked regardless.
- Leave `NODE_TLS_REJECT_UNAUTHORIZED` unset or `1`. Setting `0` disables outbound certificate
  verification.
- Do not run `docker-compose.override.yml` in production — it publishes PostgreSQL, Redis,
  Chromium and a Node debugger to the host. Start with the file list pinned:
  `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`.
- Firewall the host so only the nginx port is reachable.
- Back up `data/postgres/` **and** your `ENCRYPTION_KEY` — without the key, stored integration
  credentials cannot be decrypted from a restored backup.
- Rotate anything a secret scan finds. Discovery means it was exposed.

## Authorized use

DAST and API scans send real traffic to whatever target you point them at. **Only scan systems you
own or have explicit written authorization to test.** Unauthorized scanning is illegal in most
jurisdictions.
