# Priority-Ordered Action List

> Generated: 2026-06-13 | Based on comprehensive code audit

---

## CRITICAL — Blocks Platform from Functioning

### C1. Replace stub workers with real implementations
**Files:** `container-worker.ts`, `dast-enterprise-worker.ts`, `sbom-worker.ts`, `binary-worker.ts`, `apiprotocol-worker.ts`
**Problem:** All these workers return hardcoded mock data instead of calling the real scanner implementations that exist (container-scanner.ts, browser-crawler.ts, sbom-generator.ts, engine.ts).
**Fix:** Wire each worker to call its corresponding real scanner module. The real code exists — the workers just bypass it.
**Depends on:** Milestones M5h, M5i, M5j, M5k, M6a-M6g

### C2. Replace advanced-scanners.ts stubs with real scanner calls
**Files:** `scanners/src/sast/advanced-scanners.ts`
**Problem:** Contains `scanContainerImage()`, `scanBinaryArtifact()`, `generateSBOM()`, `scanAPIProtocols()` — all return hardcoded data. Real implementations exist in separate files (container-scanner.ts, sbom-generator.ts) but aren't called.
**Fix:** Delete or refactor so each function delegates to the real scanner implementation.
**Depends on:** Milestones M5h, M5i, M5j, M5k

### C3. Implement real script execution engine
**Files:** `backend/src/services/api-client/enterprise-client.ts` — `ScriptEngine` class
**Problem:** `executePreRequest()` and `executePostResponse()` parse regexes but do not actually run JavaScript. No sandboxed VM, no `pm.*` API implementation.
**Fix:** Use Node.js `vm` module (or isolated-vm for production) to execute user scripts in a sandbox with `pm.variables`, `pm.request`, `pm.environment`, `pm.expect` APIs.
**Depends on:** Milestone M7a

### C4. Implement real HTTP/WebSocket/gRPC/GraphQL client connections
**Files:** `backend/src/services/api-client/enterprise-client.ts` — `testWebSocket()`, `testGrpc()`, `testGraphQL()`
**Problem:** All return hardcoded responses. No actual protocol connections.
**Fix:** Use `ws` library for WebSocket, `@grpc/grpc-js` for gRPC, raw HTTP requests for GraphQL. Wire to real endpoints.
**Depends on:** Milestone M7c

### C5. Connect enterprise-dast.ts browserCrawl() to real browser-crawler.ts
**Files:** `scanners/src/dast/enterprise-dast.ts` — `browserCrawl()`
**Problem:** Returns hardcoded URLs. A real implementation (`browser-crawler.ts`) already exists with full HTTP crawling.
**Fix:** Delete the stub `browserCrawl()` and call `crawlWebsite()` from browser-crawler.ts instead. Add headless Chromium support via Puppeteer for SPA rendering.
**Depends on:** Milestone M6a

---

## HIGH — Major Feature Gaps

### H1. Build AST engine with real parsers
**Files:** `scanners/src/sast/ast-engine.ts`
**Problem:** Current implementation uses regex-based heuristic parsers (comments admit this is a fallback). No tree-sitter WASM bindings, no Eclipse JDT, no Roslyn integration.
**Fix:** Integrate tree-sitter WASM grammars for supported languages. Replace heuristic parsers with real AST parsing.
**Deliverable:** Milestone M5b — AST-Based Analysis Engine

### H2. Expand SAST rules to 500+
**Files:** `scanners/src/sast/rule-expansion.ts`
**Problem:** Generates ~70 rules from category templates. Far short of 500+. Many rules lack `recommendation`, `cvssVector`, `owaspCategory`.
**Fix:** Add hand-crafted rules for remaining CWE categories. Fill in missing metadata fields.
**Deliverable:** Milestone M5a — Rule Expansion

### H3. Expand framework rules coverage
**Files:** `scanners/src/sast/framework-rules.ts`
**Problem:** Only 11 rules across 8 frameworks. Manifest lists 12 frameworks but Vue, Next.js, Flask, Ruby on Rails have 0 rules.
**Fix:** Add framework-specific rules for Vue, Flask, Next.js, Laravel (more), Rails (more), Gin (more).
**Deliverable:** Milestone M5c — Framework-Specific Rules

### H4. Implement real compliance mapping
**Files:** None exist yet
**Need:** Rule-to-ASVS mapping, CWE Top 25 coverage report, PCI DSS mapping, regulatory packs (GDPR, HIPAA, SOX).
**Deliverable:** Milestone M5g — Compliance Coverage

### H5. Implement real dataflow/taint tracking
**Files:** `scanners/src/sast/ast-engine.ts` has basic source/sink identification
**Problem:** No real cross-function taint tracking, no sanitizer recognition, no taint path visualization.
**Fix:** Build proper taint propagator that follows variable assignments and function call arguments across IR nodes.
**Deliverable:** Milestone M5d — Dataflow & Taint Tracking

### H6. Implement auth replay and session management
**Need:** Login sequence recorder, cookie jar, token refresh, MFA handling (TOTP/push), session validation.
**Deliverable:** Milestone M6b — Authentication Replay & Session Management

### H7. Implement precision/performance system
**Need:** Per-rule FP/TP metrics, incremental scanning (file-hash based), parallel file scanning, scan result caching.
**Deliverable:** Milestone M5e — Precision & Performance

### H8. Implement custom rule language
**Need:** YAML pattern syntax parser, Semgrep-compatible rule format, visual rule builder, rule test sandbox.
**Deliverable:** Milestone M5f — Custom Rule Language

---

## MEDIUM — Important Features

### M1. Implement universal rule importer
**Files:** `backend/src/services/rule-ecosystem/manager.ts` — `syncRuleSource()` returns hardcoded
**Problem:** No actual cloning/parsing of any golden source repos (Semgrep, CodeQL, Nuclei, etc.).
**Fix:** Implement `git clone` for each source, parse the rules into canonical format, store in DB.
**Deliverable:** Milestone M18 — Universal Rule Importer

### M2. Implement comprehensive rule management
**Files:** `backend/src/services/rule-ecosystem/manager.ts` — `getRuleLibraryStats()` returns hardcoded
**Problem:** No actual rule library dashboard, versioning, enable/disable, or effectiveness tracking.
**Fix:** Build rule CRUD API, version diff, enable/disable per project, effectiveness dashboard.
**Deliverable:** Milestone M19 — Central Rule Management

### M3. Implement collection runner with data-driven testing
**Files:** `backend/src/services/api-client/enterprise-client.ts` — `runCollection()` returns hardcoded
**Problem:** No actual sequential/parallel request execution with CSV/JSON data iteration.
**Fix:** Build actual request execution engine that iterates over collection requests, supports data iteration.
**Deliverable:** Milestone M7b — Collection Runner & CLI

### M4. Implement workspaces and catalog
**Files:** `backend/src/services/api-client/enterprise-client.ts` — `createWorkspace()` is a factory function
**Problem:** No workspace CRUD, API catalog, version control, scratch pad.
**Fix:** Build full workspace management with team membership, API catalog with versioning, scratch pad.
**Deliverable:** Milestone M7e — Workspaces & Catalog

### M5. Implement mock server
**Files:** `backend/src/services/api-client/enterprise-client.ts` — `createMockServer()` returns hardcoded
**Problem:** No actual HTTP server that responds to requests.
**Fix:** Build Express-based mock server that matches request patterns and returns configured responses.
**Deliverable:** Milestone M7d — Mock Server

### M6. Implement AI-powered review engine
**Files:** `backend/src/services/platform/enterprise-platform.ts` — `generateAIAnalysis()` returns hardcoded text
**Problem:** No LLM integration. Use Anthropic/OpenAI API for real AI analysis.
**Fix:** Integrate LLM API for finding explanation, root cause analysis, fix suggestions, natural language rule creation.
**Deliverable:** Milestone M15, M26 — AI Review & Remediation

### M7. Implement granular DAST attack execution
**Files:** `scanners/src/dast/enterprise-dast.ts` has attack definitions but the execution is skipped
**Problem:** The 35+ advanced attack modules exist as data definitions but the worker doesn't execute them.
**Fix:** Build the attack execution pipeline: send each payload, analyze response, detect vulnerability.
**Deliverable:** Milestone M6c — Advanced Attack Modules

### M8. Implement enterprise SSO/RBAC
**Files:** `backend/src/services/platform/enterprise-platform.ts` — basic SAML attribute mapping exists
**Problem:** No actual SAML/OIDC/LDAP integration. No SSO enforcement, MFA, SCIM provisioning.
**Fix:** Integrate passport-saml, passport-azure-ad, passport-ldapauth. Build SSO configuration UI.
**Deliverable:** Milestone M22 — Enterprise SSO & RBAC

---

## LOW — Polish and Expansion

### L1. Add screenshot/evidence capture
**Need:** Puppeteer screenshots on findings, HAR recording, PoC script generation.
**Deliverable:** Milestone M6f — Evidence Capture (partial)

### L2. Implement compliance scanning profiles
**Need:** Expand `runPCIComplianceScan()` to support custom compliance profiles, ASVS coverage reports, NIST mapping.
**Deliverable:** Milestone M6g — Compliance Scanning

### L3. Implement pre-commit hooks
**Need:** Git pre-commit hook installer, staged file scanning, commit blocking on secrets.
**Deliverable:** Milestone M14d, M21 — Developer Experience & Secrets

### L4. Implement IDE plugins
**Need:** VS Code extension, JetBrains plugin for inline findings.
**Deliverable:** Milestone M14d — IDE Integration

### L5. Implement reachability analysis
**Files:** `backend/src/services/code-review/enterprise-review.ts` — `analyzeReachability()` returns hardcoded
**Problem:** No real call graph analysis from source code.
**Fix:** Use the call graph from ast-engine.ts to compute actual reachability.
**Deliverable:** Milestone M14e — Reachability Analysis

### L6. Implement interprocedural analysis
**Files:** `backend/src/services/platform/enterprise-platform.ts` — `analyzeInterprocedural()` has real BFS
**Problem:** Framework context is hardcoded. No cross-file/cross-function analysis.
**Fix:** Integrate with SAST AST engine for real call graph construction.
**Deliverable:** Milestone M25 — Interprocedural Analysis

### L7. Implement WAF bypass execution
**Files:** `scanners/src/dast/enterprise-dast.ts` — evasion encoders exist but aren't applied
**Problem:** The encoding functions exist but no payload is actually encoded and retried after a WAF block.
**Fix:** Build retry logic: if original payload gets 403, try each encoding technique until one bypasses.
**Deliverable:** Milestone M6d — WAF Evasion

### L8. CI/CD GitHub Action / GitLab CI template
**Files:** `backend/src/services/rule-ecosystem/manager.ts` — YAML generation exists but isn't a real action
**Problem:** No published GitHub Action, no GitLab CI template, no Jenkins plugin.
**Fix:** Package the CLI and publish as GitHub Action, GitLab CI template, Jenkins shared library.
**Deliverable:** Milestone M20 — CI/CD Integration

---

## Quick Wins (can be done immediately)

| # | Task | Effort | Impact |
|---|------|--------|--------|
| Q1 | Wire `dast-worker.ts` to call `engine.ts` instead of standalone logic | 2h | Fixes DAST worker returning wrong data |
| Q2 | Wire `container-worker.ts` to call `container-scanner.ts` `scanDockerfile()` | 2h | Container scanning becomes real |
| Q3 | Wire `sbom-worker.ts` to call `sbom-generator.ts` `generateSbom()` | 1h | SBOM generation becomes real |
| Q4 | Wire `dast-enterprise-worker.ts` to call `crawlWebsite()` from browser-crawler.ts | 4h | Enterprise DAST becomes functional |
| Q5 | Fill in missing rule metadata (recommendation, cvssVector) | 3h | All existing rules have complete data |
