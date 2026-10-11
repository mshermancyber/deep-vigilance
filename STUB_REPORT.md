# Stub Report — Files Containing Hardcoded Mock Data, Fake Returns, or Placeholder Logic

> Generated: 2026-06-13 | Audit of all milestone code files

---

## Critical Stubs (return hardcoded/mock data only)

### 1. `scanners/src/sast/advanced-scanners.ts`
- `scanContainerImage()` — Returns hardcoded findings array, no real CVE database query or layer analysis. Uses fake CVE IDs (`CVE-2024-1234`, `CVE-2024-5678`).
- `scanBinaryArtifact()` — Returns hardcoded findings based on `artifactType` string switch. No real bytecode/JAR/APK decompilation.
- `generateSBOM()` — Returns hardcoded SBOM with 3 fake components and 2 fake CVEs. Ignores the real `sbom-generator.ts` implementation.
- `scanAPIProtocols()` — Returns hardcoded gRPC/GraphQL/WebSocket/SOAP findings. No actual protocol connections or attacks.
- **Impact:** Milestones M5h, M5i, M5j, M5k rely on stub data.

### 2. `scanners/src/dast-enterprise-worker.ts`
- `processJob()` — Returns hardcoded crawl results, hardcoded auth cookies, hardcoded WAF detection, hardcoded attack findings, hardcoded PCI compliance.
- Does not call the real `browser-crawler.ts`, real `enterprise-dast.ts` functions, or real `engine.ts`.
- **Impact:** Enterprise DAST worker is non-functional in production.

### 3. `scanners/src/container-worker.ts`
- `processJob()` — Returns hardcoded scan result with fake layer count, package count, CVE counts. Does not call the real `container-scanner.ts`.
- **Impact:** Container scan worker reports nonsense data.

### 4. `scanners/src/sbom-worker.ts`
- `processJob()` — Returns hardcoded SBOM with 2 components (express, lodash). Does not call the real `sbom-generator.ts`.
- **Impact:** SBOM worker returns fake data.

### 5. `backend/src/services/api-client/enterprise-client.ts`
- `ScriptEngine.executePreRequest()` — Only parses regex patterns from script text, does NOT execute JavaScript. Uses regex match count as fake success.
- `ScriptEngine.executePostResponse()` — Only extracts test names via regex. All tests marked `passed: true`.
- `runCollection()` — Returns hardcoded collection run with 3 fake requests and pass/fail data.
- `testWebSocket()` — Returns hardcoded success with no real WS connection.
- `testGrpc()` — Returns hardcoded success with cached response.
- `testGraphQL()` — Returns hardcoded schema type count (always 142).
- `createMockServer()` — Returns hardcoded mock rules.
- **Impact:** M7a, M7b, M7c are non-functional.

---

## Partial Stubs (some real logic mixed with hardcoded returns)

### 6. `scanners/src/dast/enterprise-dast.ts`
- `browserCrawl()` — Returns hardcoded URL list. Does not call `browser-crawler.ts`.
- `authenticateAndReplay()` — Returns hardcoded cookies and JWT token.
- `runPCIComplianceScan()` — Uses hardcoded requirement list, computes score from input findings but the framework is hardcoded.
- **PARTIAL:** `passiveScanResponse()` has real header/body analysis. `captureEvidence()` has real cURL generation. `detectWAF()` has real header inspection. `EVASION_ENCODERS` are real functions. Attack module definitions are real arrays.

### 7. `backend/src/services/code-review/enterprise-review.ts`
- `verifyFix()` — Returns hardcoded `{verified: true}` regardless of input.
- `runPreCommitScan()` — Always returns `passed: true, findings: 0`.
- `analyzeReachability()` — Returns hardcoded reachable path.
- `generateAIAnalysis()` — Returns hardcoded analysis text based on CWE ID lookup table.
- `generateAIFix()` — Returns generic placeholder fix text.
- **PARTIAL:** `generatePRDecoration()` has real counting logic. `createBaseline()` has real hashing. `checkSLAs()` has real time computation. `detectHotspots()` has real keyword matching. `calculateSecurityDebt()` has real scoring.

### 8. `backend/src/services/platform/enterprise-platform.ts`
- `generateAIAnalysis()` — Returns hardcoded CWE-specific analysis text.
- `analyzeInterprocedural()` — While it has a real BFS search function, the result construction is partial and uses hardcoded framework context.
- **PARTIAL:** `mapSAMLToRole()` has real group matching. `exportAuditLogs()` has real CEF formatting. `getRecommendedDeployment()` has real tier logic. `validatePlugin()` has real validation.

### 9. `backend/src/services/rule-ecosystem/manager.ts`
- `syncRuleSource()` — Returns hardcoded sync result (15 added, 3 updated, 1 removed).
- `getRuleLibraryStats()` — Returns hardcoded statistics.
- **PARTIAL:** `scanForSecrets()` has real regex pattern matching. `generateCICDYaml()` has real YAML generation.

---

## Placeholder / Configuration-Only Implementations

### 10. `scanners/src/sast/ast-engine.ts`
- Uses regex-based heuristic parsing instead of real tree-sitter WASM bindings.
- Line 67 comment: "Language-specific heuristic parsers (production would use tree-sitter WASM bindings)"
- Functions like `parseCStyleToIR`, `parseJavaStyleToIR` are simplified regex fallbacks.
- **Assessment:** Real computation but functionally limited. Not a stub but not production-ready.

### 11. `scanners/src/sast/rule-expansion.ts`
- Generates rules programmatically from category templates.
- All rule `recommendation` and `cvssVector` fields are empty strings.
- Many rules have duplicate-like patterns because they're template-generated.
- Only generates ~70 rules, not the 500+ claimed.
- **Assessment:** Real generation logic but the volume is far below what's claimed.

### 12. `scanners/src/sast/framework-rules.ts`
- Contains only 11 framework rules total (across Spring, Django, Express, ASP.NET, React, Rails, Laravel, Gin).
- Many frameworks in the manifest have no rules at all (Vue, Next.js, Flask, Ruby on Rails, etc.).
- **Assessment:** Real rules but coverage is minimal.

---

## Summary

| Category | Count |
|----------|-------|
| Files returning hardcoded/mock data | 7 |
| Files partially stubbed (mixed real/hardcoded) | 4 |
| Files with placeholder/simplified logic | 3 |
| **Total files needing remediation** | **14** |
