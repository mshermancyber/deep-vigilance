# SAST Rule Tuning — Observations & Changes (2026-06-13)

Corpus: **19 public repos** of `github.com/mshermancyber` (Python/TS/JS/HTML), scanned via the
Git-clone SAST workflow, over 3 rounds.

## Results
| Round | Rules | Total findings | Notes |
|-------|-------|----------------|-------|
| 1 (baseline) | as-shipped | **~2,232** | dominated by confirmed false positives |
| 2 (tuning pass 1) | comment-skip, crypto/xss tightened, broken absence-rules disabled | **622** | −72% |
| 3 (tuning pass 2) | + dangerous-function tightened | **540** | −76% |
| 4 (tuning pass 3) | + auth-context suppression, lockfile/minified exclude | **418** | −81% |
| 5 (tuning pass 4) | + extended auth markers, SQLi param-exclude, fixed/disabled noisy rules | **327** | **−85% vs baseline** |

### Pass 4 changes (Round 5)
- **Extended auth markers** — added `requireSession/requireSudo/requireAccess/requireRole/
  getServerSession/…` so IDOR/auth FPs in `nist-express` (which uses those) are suppressed:
  IDOR 60→10.
- **SQLi param-exclude** — suppress when the line is parameterized (`$1`/`$2`, `, params`,
  `?` markers) — kills the parameterized-query FPs.
- **Insecure-RNG rule was inverted** (fired on `Math.random` in math/simulation, suppressed
  the security cases) — rewritten to fire only when a weak RNG feeds a security value
  (token/key/secret/nonce/…).
- **Disabled** `AUTHZ-EXPOSED-001` (matched "/admin/" in OpenAPI specs/docstrings) and
  `XSS-CSS-001` (React static `style={{…}}` objects) — low value, FP-heavy.

## DAST tuning
The DAST detection logic is sound, but it **reported host-level issues once per crawled URL**
— missing-header checks are a property of the server response, identical on every page.
Example (security-hub @ :11443): "Missing Security Headers" appeared **56×** across 27 URLs;
`missing-csp/hsts/…` 6–7× each.

**Fix:** dedupe in the DAST worker — host-level findings (missing headers / passive issues)
collapse to one per type; injection findings (SQLi/XSS/CSRF) stay per `(attack, URL, param)`.
Result for security-hub: **141 → 40** findings; each missing-header now reported **once**.
CSRF remains per-endpoint (32) by design — can be collapsed to a single systemic finding if
preferred (and is arguably low-value on a no-auth API where there's no session to ride).

### Pass 3 changes (Round 4)
- **Auth/authz context suppression** — for `AUTH-MISSING`/`AUTHZ-MISSING`/`IDOR`/`EXPRESS-AUTH`,
  suppress a finding when an auth marker (`Depends(`, `login_required`, `current_user`,
  `requireAuth`, `@PreAuthorize`, `passport.`, etc.) appears within ±10–18 lines of the handler
  (decorators above / dependencies around). Replaces the broken per-line negative-lookahead.
- **Exclude generated/minified files** from collection: `*-lock.json`, `yarn.lock`,
  `poetry.lock`, `go.sum`, `*.min.js/css`, `*.bundle.js`, `*.map`.

### Validation — the remaining auth findings are TRUE POSITIVES
Spot-checked the top remaining bucket against source: `security-hub/backend/app/routes/workspace.py`
**does not import `Depends`**, its `APIRouter(prefix="/api/workspace")` has no `dependencies=`,
and `main.py` includes it with none — so `delete_saved`, the annotation/watchlist
delete/update endpoints, `orgs_admin`, etc. are genuinely **unauthenticated state-changing
endpoints**. The tuning correctly suppressed the auth'd handlers (Missing-Auth 77→58) while
keeping these real gaps. Net: the dominant remaining category is now real, actionable signal.

## Root-cause observation
The biggest FP source was **rules written for multi-line/full-file matching being applied
per-line**. Their `(?![\s\S]{0,N}…)` "absence" lookaheads only see one line, so the lookahead
is vacuously true and the rule fires on *every* match.

## Baseline top false positives (Round 1)
| Rule | Count | Why it was wrong |
|------|------:|------------------|
| Dockerfile: Running as Root | 676 | `/(?![\s\S]*USER…)/` matched **every line** of a Dockerfile |
| Weak Crypto | 267 | bare words `MD5`/`SHA1`/`DES` in comments, IOC strings, identifiers |
| Race Condition | 172 | flagged any var named `state`/`cache`/`global` being assigned (`state = "GROWING"`) |
| XSS | 157 | `innerHTML = '<static html>'` (no dynamic content) |
| Unclosed DB Conn / File Handle | 200 | per-line `(?!…close)` always true → every `connect()`/`open()` |
| Missing HSTS / CSP / Cookie flags / CSRF | ~250 | per-line absence checks; fire on every `app.use`/`Set-Cookie`/POST |
| Use of Dangerous Function | 122 | matched `.exec()` **method** calls (Qt `dlg.exec()`, regex), Splunk `eval()` |

## Changes made
- **Comment-line skip** (`isCommentLine` in `engine.ts`, applied in both match loops) — skips
  pure comment lines, killing keyword-in-comment FPs across all rules.
- **Weak Crypto** → match real crypto-API usage only (`hashlib.md5(`, `createHash('md5')`,
  `MessageDigest.getInstance("MD5")`, `Cipher.getInstance("DES"/ECB)`, `CryptoJS.*`, ECB
  ciphers), not the bare words.
- **XSS** → dynamic sinks only (variable / `+` concat / `` `${}` `` template); static string
  literals no longer flagged.
- **Dangerous Function** → bare `eval(`/`exec(` (negative lookbehind excludes `.exec()`
  methods) + real shell APIs (`child_process.exec`, `os.system`, `subprocess`); removed the
  `assert(` pattern (matched every test).
- **Dockerfile root** → flags an explicit `USER root` line (true positive) instead of
  matching every line.
- **Disabled** (can't work with per-line regex; better covered by DAST or need dataflow):
  `CONC-RACE-001`, `RES-LEAK-001/002`, `CONF-HEADER-HSTS/CSP-001`, `CONF-COOKIE-001/002/003`,
  `API-CSRF-001`.

## Remaining limitations / next steps
- **Auth/Authz/IDOR rules are now the top bucket (~218)** and still over-fire — per-line
  matching can't see auth applied via FastAPI `Depends(...)`, router-level `dependencies`, or
  Express middleware on adjacent lines. **Proper fix:** match these rules over a multi-line
  window (handler body) so their negative-lookaheads work. That's the highest-value next
  improvement; until then, treat auth/authz hits as "triage," not confirmed.
- `Exposed Admin Functionality` still has FPs (lockfiles, rate-limit config) — needs a path/
  file-type exclude (skip `*-lock.json`, config tuples).
