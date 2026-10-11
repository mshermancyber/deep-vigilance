# Feature Backlog — Scan Capability Gaps

Priority items to close the remaining ~20% gap with enterprise AppSec tools.
Generated from parity analysis against Burp Suite, Checkmarx, Snyk, Trivy, Veracode, ZAP.

Last updated: 2026-06-19.

---

## P1 — High Impact (closes major capability gaps)

- [ ] **Authenticated DAST scanning** — Add login sequence support (form-based, OAuth2, bearer token, basic auth) with session management, re-auth on expiry, and cookie/token replay. The enterprise DAST engine has auth stubs (`enterprise-dast.ts`) but the main DAST worker doesn't wire them. Without this, anything behind a login page is invisible. *~2-3 days.*

- [ ] **Out-of-band vulnerability detection** — Add callback infrastructure for blind SSRF, blind XXE, and blind RCE detection. Either self-hosted (simple HTTP/DNS listener that logs inbound connections and correlates to scan IDs) or integrate interactsh. Currently missing an entire class of blind vulnerabilities. *~2-3 days.*

- [ ] **Container image layer scanning** — Call Trivy on actual built images (not just Dockerfiles) to detect OS-level CVEs in installed packages. The enterprise scanner already has Trivy integration for Dockerfile analysis; extend it to accept image refs and parse Trivy's JSON output for OS package vulns. *~1-2 days.*

## P2 — Medium Impact (improves accuracy and depth)

- [ ] **Interprocedural type resolution for taint tracking** — Current taint tracking follows call graph edges by function name but doesn't resolve polymorphic dispatch, interface implementations, or generic type parameters. Needs class hierarchy analysis and virtual method table construction per language. Reduces FP rate on OOP-heavy codebases. *~5-7 days.*

- [ ] **Path-sensitive analysis / constraint solving** — Add basic constraint propagation to prune infeasible taint paths (e.g., `if (input === null) return` should kill taint on the else branch). Currently all paths are treated as reachable, inflating FP count. *~3-5 days.*

- [ ] **Auto-fix PR generation for SCA** — When SCA finds a vulnerable dependency with a known safe version, auto-generate a PR that bumps the version in the lockfile/manifest. Snyk and Dependabot do this; it's the difference between reporting and remediating. *~2-3 days.*

## P3 — Nice to Have (niche or polish)

- [ ] **WebSocket and GraphQL fuzzing** — Dedicated fuzz testing for WebSocket frames and GraphQL queries/mutations (batching attacks, introspection, field suggestion abuse). Enterprise DAST has detection stubs but no active fuzzing. *~2-3 days.*

- [ ] **API spec conformance validation** — Validate that API responses match their OpenAPI schema (correct status codes, required fields, response types). Currently API scanner only tests for injection vulns, not spec drift. *~1-2 days.*

- [ ] **DAST crawl depth expansion** — Increase default from 30 pages with better DOM event-driven crawling (click handlers, dynamic route discovery, infinite scroll). Current Puppeteer crawler is shallow compared to Burp/ZAP. *~2-3 days.*

- [ ] **Transitive dependency graph visualization** — Show full dependency trees with exploitability paths highlighted. SCA already resolves transitive deps; this is a frontend display feature. *~1-2 days.*

---

## Already at parity (no action needed)

- SAST language coverage (10 languages with tree-sitter AST)
- Cross-file taint tracking with call graphs
- Secrets detection (100+ patterns, entropy filtering, git history)
- SCA vulnerability matching (OSV + NVD + EPSS + KEV)
- Supply chain checks (typosquatting, dependency confusion, protestware)
- SBOM generation (CycloneDX + SPDX)
- Compliance mapping (OWASP ASVS, PCI DSS, SOC2, HIPAA, NIST 800-53)
- AI-assisted FP triage (ahead of most enterprise tools)
- Code review with AI batch analysis
- PDF/JSON report generation
- CI/CD webhook integration
