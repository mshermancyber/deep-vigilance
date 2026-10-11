# Contributing to Deep Vigilance

Thanks for your interest. Issues, bug reports and pull requests are welcome.

**Security issues do not belong here** — see [SECURITY.md](./SECURITY.md) for private reporting.

## Getting a development stack running

Follow [INSTALL.md](./INSTALL.md) first so you have certificates and a `.env`. Then, instead of
the production start, let Compose pick up the development override:

```bash
docker compose up -d          # docker-compose.override.yml is applied automatically
```

The override bind-mounts `backend/src` and runs the API under `tsx watch`, so backend edits
hot-reload. It also publishes PostgreSQL, Redis, Chromium and a Node debugger to the host for
local tooling — which is exactly why it must not be used in production.

## Repository layout

Four separate npm packages, each with its own `package.json` and `tsconfig.json`:

| Path | Contents |
|---|---|
| `backend/` | Express API, auth, queue wiring, migrations, reaper, retention jobs |
| `frontend/` | Angular 18 single-page app |
| `scanners/` | SAST, DAST, API, SCA and secret engines, plus their workers |
| `workers/` | Report generation worker |
| `shared/` | Types shared across packages |
| `postgres/migrations/` | Schema, applied automatically on backend startup |
| `cicd/` | GitHub Action, GitLab CI, Jenkins and CLI wrappers |

`CLAUDE.md` documents the architecture invariants worth reading before touching the scanners or
the queues.

## Before opening a pull request

Typecheck every package you touched:

```bash
cd backend  && npm ci && npx tsc --noEmit
cd scanners && npm ci && npx tsc --noEmit
cd workers  && npm ci && npx tsc --noEmit
```

Run the tests:

```bash
cd backend  && npm test
cd scanners && npm test
```

And the smoke test against a running stack:

```bash
./scripts/smoke-test.sh
```

## Things that will come up in review

- **Scanner workers must persist through `scan-store.ts`.** Every worker calls
  `startScan(scanId)`, then `storeFinding(...)` per finding, then
  `completeScan(scanId, count, meta)`, with `failScan` on error. A worker that computes results
  and merely returns them persists **nothing** — the scan sits queued forever with the results
  stranded in the BullMQ job's `returnvalue`.
- **The backend cannot import `@appsec/scanners` at build time.** The packages are separate and
  the scanners are not in the backend's build context. Use a runtime dynamic import with a
  non-literal specifier so `tsc` never resolves it.
- **Long-lived jobs start from `backend/src/server.ts`**, not `workers/main.ts` — the backend
  container runs the server entry, not that one.
- **Don't re-add `baseUrl` or `paths` to `backend/tsconfig.json`.** No `@`-aliases are actually
  imported, and they were removed deliberately.
- **`tsx` belongs in `dependencies`, not `devDependencies`.** `npm prune --production` strips
  devDependencies, and the development override runs `npx tsx watch`, which cannot refetch it
  offline — every container recreate then crash-loops.
- **Adding a new scan type** means a migration extending the `scan_type` / `type` CHECK
  constraints, a queue in `QueueName`, a worker that uses `scan-store`, and an entry in the
  retention job if it creates rows that should age out.
- **New retention logic must respect the invariants** in `backend/src/core/cleanup.ts`: terminal
  states only, batched deletes, the table-fraction guard, and correct foreign-key ordering —
  `findings.scan_id` has no `ON DELETE CASCADE`, so findings are deleted before their scans.
- **No host-specific values in the tree.** No IP addresses, hostnames, usernames, absolute host
  paths, real ports or credentials. Anything environment-dependent goes in `.env.example` with a
  safe default.

## Style

Match the surrounding code — it is reasonably consistent. Comment the *why*, not the *what*;
the existing comments on the non-obvious parts are the model to follow.

## License

Deep Vigilance is GPL-3.0-or-later. By contributing you agree your contributions are licensed
under the same terms.
