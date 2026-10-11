# Security Review — Backlog (outstanding only)

What's left after the security/correctness review. Fixed items live in `findings.md`,
not here. **No known-exploitable open bugs remain** — this is decisions, deferred
hardening, deploy steps, and unreviewed surface.

Last updated: 2026-06-13.

---

## 1. Needs a product / architecture decision

- [ ] **N2 — Network-layer egress controls for scanners.** Fully addressed **in code**
  (SSRF guard on the protocol scanner + both DAST workers: metadata/link-local always
  blocked, private ranges gated by `ALLOW_PRIVATE_SCAN_TARGETS`). The only remaining
  piece is **not code** — a deployment network policy (run scanner containers behind an
  egress proxy / segmented network). Nothing more to write here.
- [ ] **N1 — Full Web Worker sandbox for API-client scripts** *(optional)*. Hardened in
  code (dangerous globals shadowed in `script-executor.service.ts`), which closes the
  realistic threat (it's the user's own browser). A true Worker/iframe sandbox only
  matters **if test collections become shareable between users**; it's a larger frontend
  rewrite best done with the frontend build available. No open bug today.

## 2. Deferred hardening (lower priority)

- [ ] **Dev-only npm advisories** — `esbuild` (high) + 1 critical via the vite/vitest test
  stack. Not shipped to prod (`npm audit --omit=dev` is clean). Clearing = major bump of
  test tooling.

## 3. Deploy / first-run steps

- [x] **All four packages now compile/build** — backend (`tsc` 0 errors), scanners
  (`npm run build`), workers (`npm run build`), **frontend (`ng build` succeeds)**. Lockfiles
  generated for frontend + workers; `.dockerignore` added to every build context. Fixed ~13
  pre-existing build-breakers surfaced by the first real build (Material M2→M3 theme,
  chart typings, SBOM interface/class name clash, missing `RouterLink`, Angular-template
  `as`-casts + arrow functions, expect-chain typing, index-signature access, a worker
  `buildHTMLReport` ReferenceError).
- [x] **All Docker images build for dev + prod** (2026-06-13). Fixed build-context mismatch
  (root context), bad pinned Trivy version (0.58.1→0.70.0), vestigial COPYs, and a
  `.dockerignore` that didn't exclude root-owned runtime dirs. See `Build_Debug.md`.
- [x] **Stack brought online and smoke-tested** via base `docker-compose.yml`. All 13
  services Up/healthy; migrations 001–005 applied on boot; cookie-auth flow
  (register/login/me/logout) verified end-to-end through the nginx HTTPS edge
  (`https://localhost:8443`). Runtime wiring fixes (DB_SSL flag, edge-TLS topology, non-root
  frontend on :8080, SPA `dist/browser` root, ioredis/chromium healthchecks, puppeteer
  executablePath, BullMQ `noeviction`, nginx proxy buffers) all in `Build_Debug.md`.
- [x] **enterprise-worker image builds** with Trivy 0.70.0 / Syft 1.18.1 / apktool 2.10.0
  baked in. Live container/SBOM/APK scans still want a functional run (no job pushed yet).
- [ ] **Set `ALLOW_PRIVATE_SCAN_TARGETS` per deployment** — unset (default) blocks
  private/loopback scan targets; self-hosted internal scanning needs `=true`.
- [ ] **Run one real scan of each type** (container/SBOM/APK/SAST/DAST/API) end-to-end to
  confirm the workers process BullMQ jobs and persist findings (stack is up; not yet exercised).
- [ ] **Prod stack (`docker-compose.prod.yml`) not yet started** — it uses Docker **Swarm**
  `external: true` secrets (db/redis/jwt) + a read-only rootfs and needs a real TLS cert.
  Build is verified; bringing it up requires `docker swarm init` + `docker secret create …`
  (or converting the secrets to file-based) and a CA-issued or self-signed `nginx/ssl` cert.
- [ ] **Dev hot-reload override needs `tsx` in the images** — the override runs `npx tsx
  watch`, but `tsx` is a devDependency and images `npm prune --production`. Add a dev build
  target that keeps devDeps (or `npm i -g tsx`) before using `docker compose up` with the
  override. The base compose (built `node dist/...`) is unaffected and is the online stack.

## 4. Surface not yet fully reviewed

- [x] Scanner files — all reviewed; dead duplicates (`dast-enterprise-worker.ts`,
  `dast/waf-detector.ts`) + stray compiled `.js` removed.
- [x] nginx + Dockerfiles — reviewed and hardened (Dockerfiles already non-root; nginx
  CSP/HSTS added; chromium host-port removed; prod caps trimmed). nginx already had rate
  limiting + `client_max_body_size`.
- [x] Business-logic authz — every route traced; cross-org IDORs on resource creation
  (code-review `gitConnectionId`/`projectId`, API-client `collectionId`/`folderId`) fixed.
- [x] **Backend test suite** — `npm test` now passes **433/433** (was 35 failing; fixed via
  rule-coverage + an exported helper + a test-data fix). Unit-level behavior verified.
- [x] **First-run cookie-auth smoke test done** — register/login/me/logout verified through
  the nginx HTTPS edge (2026-06-13). WebSocket connect + real scan jobs not yet exercised.

> Optional infra hardening not applied (would risk breaking unverifiable builds): pin
> `browserless/chrome:latest` to a specific digest/tag.

---

## Suggested order
1. Exercise one real scan of each type end-to-end (workers + findings persistence).
2. Stand up the prod stack (Swarm secrets + TLS cert) when deploying for real.
3. N2 network-layer egress controls.
