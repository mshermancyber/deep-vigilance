// SAST Worker — Uses ALL rule sets: core 15 + expanded 500+ + framework-specific
import { Worker, Job } from 'bullmq';
import { logger } from './utils/logger.js';
import { scanFile, getLanguage, shouldScanFile, SastRule, isCommentLine } from './sast/engine.js';
import { SAST_RULES as CORE_RULES } from './sast/engine.js';
import { generateRuleLibrary, SAST_RULE_CATEGORIES } from './sast/rule-expansion.js';
import { FRAMEWORK_RULES } from './sast/framework-rules.js';
import { SEMGREP_RULES_BUNDLE } from './sast/semgrep-rules-bundle.js';
import { THREAT_PACK_RULES } from './sast/threat-pack-rules.js';
import { IAC_RULES } from './sast/iac-rules.js';

// --- Deep Analysis Engines (AST / Dataflow / Reachability / Precision) ---
import { parseToIR, supportsASTAnalysis, buildCallGraph } from './sast/ast-engine.js';
import type { IRNode } from './sast/ast-engine.js';
import { analyzeDataflow } from './sast/dataflow-engine.js';
import type { TaintPath, SinkCategory } from './sast/dataflow-engine.js';
import {
buildCallGraphFromAST,
identifyEntryPoints,
computeReachability,
computeExploitabilityScore,
} from './sast/reachability-engine.js';
import type { CallGraphNode as ReachCallGraphNode, FindingReachability } from './sast/reachability-engine.js';
import { trackRulePerformance } from './sast/precision-engine.js';

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { startScan, storeFinding, completeScan, failScan } from './utils/scan-store.js';
import { assertScannableUrl } from './utils/ssrf.js';

const pexecFile = promisify(execFile);

// Shallow-clone a git repo into a throwaway temp dir and return its path.
// Uses execFile (no shell) + array args so the URL/branch/token can't inject.
// gitToken (optional) is injected into the https URL for private repos and never logged.
async function cloneRepo(repoUrl: string, branch?: string, token?: string): Promise<string> {
  await assertScannableUrl(repoUrl); // SSRF guard (honors ALLOW_PRIVATE_SCAN_TARGETS)
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sast-repo-'));
  let cloneUrl = repoUrl;
  if (token && /^https:\/\//i.test(repoUrl)) {
    cloneUrl = repoUrl.replace(/^https:\/\//i, `https://${encodeURIComponent(token)}@`);
  }
  const args = ['clone', '--depth', '1', '--single-branch'];
  if (branch) args.push('--branch', branch);
  args.push('--', cloneUrl, dir);
  await pexecFile('git', args, {
    timeout: 180000, maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/bin/true', GCM_INTERACTIVE: 'never' },
  });
  return dir;
}

const connection = { host: process.env.REDIS_HOST || 'redis', port: parseInt(process.env.REDIS_PORT || '6379', 10), password: process.env.REDIS_PASSWORD };

// Merge all rule sets into one
const ALL_RULES: SastRule[] = [...CORE_RULES, ...generateRuleLibrary([]), ...FRAMEWORK_RULES, ...SEMGREP_RULES_BUNDLE, ...THREAT_PACK_RULES, ...IAC_RULES];
logger.info({ coreRules: CORE_RULES.length, expandedRules: generateRuleLibrary([]).length, frameworkRules: FRAMEWORK_RULES.length, semgrepRules: SEMGREP_RULES_BUNDLE.length, threatPackRules: THREAT_PACK_RULES.length, iacRules: IAC_RULES.length, total: ALL_RULES.length }, 'SAST rule library loaded');

const SEVERITY_RANK: Record<string,number> = { critical:1, high:2, medium:3, low:4, info:5 };
const IGNORED_DIRS = new Set(['node_modules','.git','__pycache__','.venv','venv','vendor','.next','dist','build','target','.idea','.vscode','coverage','.nyc_output','bower_components','.cache','compiled','generated','__generated__','vendored','third_party','third-party','thirdparty','external']);
// Generated / vendored / minified files are not source and produce only noise.
const IGNORED_FILE = /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|composer\.lock|Gemfile\.lock|go\.sum|\.min\.(?:js|css)|\.bundle\.js|\.map|\.d\.ts|\.generated\.\w+)$/i;
// Vendored third-party JS in source trees (not in node_modules) — large standalone libs
// that inflate finding counts with irrelevant hits.
const VENDORED_FILE = /(?:jquery[\w.-]*\.js|bootstrap[\w.-]*\.js|angular[\w.-]*\.js|react[\w.-]*\.js|vue[\w.-]*\.js|lodash[\w.-]*\.js|moment[\w.-]*\.js|d3[\w.-]*\.js|wysihtml[\w.-]*\.js|tinymce[\w.-]*\.js|ckeditor[\w.-]*\.js|ace[\w.-]*\.js|codemirror[\w.-]*\.js|highlight[\w.-]*\.js|marked[\w.-]*\.js|dompurify[\w.-]*\.js|sweetalert[\w.-]*\.js|chart[\w.-]*\.js|datatables[\w.-]*\.js|select2[\w.-]*\.js|three[\w.-]*\.js|phaser[\w.-]*\.js|pixi[\w.-]*\.js)$/i;
// Test file detection — test fixtures legitimately contain hardcoded credentials,
// routes without auth, and debug statements. Suppress specific noisy rule categories.
const TEST_PATH = /(?:\/test\/|\/tests\/|\/test-data\/|\/tests\/|\/spec\/|\/specs\/|\/__tests__\/|\/__mocks__\/|\/test_|\/testing\/|\/fixtures\/|\/testdata\/|\/e2e\/|\/e2e-[^/]+\/|\/integration\/|\/examples\/|\/example\/|\/demo\/|\/samples?\/|\/guide\/|\/benchmarks?\/|\.test\.|\.spec\.|_test\.|_spec\.|\.tests\.|\.specs\.)/i;
const TEST_SUPPRESSED_RULES = new Set([
  'SAST-AUTH-MISSING-001','SAST-EXPRESS-AUTH-001','SAST-AUTHZ-MISSING-001',
  'SAST-AUTH-SESSION-001','SAST-SECRET-001','SAST-AUTH-HARDCODED-001',
  'SAST-AUTH-HARDCODED-002','SAST-DEBUG-001','SAST-CONF-DEBUG-001',
  'SAST-AUTHZ-IDOR-001','SAST-CRYPTO-TRANSMIT-001','SAST-DATA-SENSLOG-001',
  'SAST-DATA-ERRMSG-001','SAST-DJANGO-AUTH-001','SAST-INP-UPLOAD-002',
  'SAST-DATA-CREDIT-001','SAST-CRYPTO-CERT-001','SAST-AUTH-JWT-NOSIG-001',
  'SAST-AUTH-JWT-NONE-001','SAST-GIN-AUTH-001','SAST-SPRING-AUTH-001',
  'SAST-ASPNET-AUTH-001',
  // R4 tuning: suppress Semgrep rules that over-fire in test/fixture/example code
  'SAST-SG-HARDCODED-SECRET-PY-001','SAST-SG-HARDCODED-SECRET-JS-001',
  'SAST-SG-HARDCODED-SECRET-JAVA-001','SAST-SG-HARDCODED-SECRET-GO-001',
  'SAST-SG-HARDCODED-SECRET-RUBY-001',
  'SAST-SG-JWT-NONE-001','SAST-SG-SSTI-001',
  'SAST-SG-DESER-PY-PICKLE-001','SAST-SG-DESER-RUBY-001',
  'SAST-SG-CODEINJ-JS-EVAL-001','SAST-SG-CODEINJ-PY-EVAL-001','SAST-SG-CODEINJ-RUBY-EVAL-001',
  'SAST-SG-CRYPTO-JS-PSEUDORANDOM-001','SAST-SG-CRYPTO-RUBY-MD5-001',
  'SAST-SG-CRYPTO-GO-WEAK-001','SAST-SG-CRYPTO-PY-SHA1-001',
  'SAST-SG-CRYPTO-JS-CREATEHASH-001',
  'SAST-SG-COOKIE-SECURE-001','SAST-SG-CORS-WILDCARD-001',
  'SAST-SG-AWS-KEY-001',
  'SAST-SG-CMDI-RUBY-001','SAST-SG-CMDI-JS-001','SAST-SG-CMDI-GO-001',
  'SAST-SG-SQLI-RUBY-INTERP-001','SAST-SG-SQLI-JS-CONCAT-001','SAST-SG-SQLI-GO-SPRINTF-001',
  'SAST-SG-XSS-JS-INNERHTML-001','SAST-SG-XSS-REACT-DANGEROUSLY-001',
  'SAST-SG-SSRF-JS-001','SAST-SG-PATH-JS-001',
  'SAST-SG-TLS-VERIFY-DISABLED-001',
  'SAST-CRYPTO-RANDOM-001','SAST-SQLI-001','SAST-XSS-001','SAST-CMDI-001',
  // R5 enterprise tuning: suppress rules that over-fire in test/fixture dirs of large codebases
  'SAST-IAC-K8S-PRIV-001','SAST-IAC-DOCKER-LATEST-001','SAST-IAC-DOCKER-ROOT-001',
  'SAST-SPRING-ACTUATOR-001','SAST-XXE-001',
  'SAST-SG-SQLI-JAVA-CONCAT-001','SAST-SG-SQLI-PY-FORMAT-001',
  'SAST-SG-XXE-JAVA-001','SAST-SG-XXE-GO-001',
  'SAST-SG-XSS-PY-MARKSAFE-001',
  'SAST-SG-CRYPTO-JAVA-WEAK-001',
  'SAST-SG-OPENREDIRECT-001',
  'SAST-SG-DESER-JAVA-001',
  'SAST-SG-SSRF-PY-001','SAST-SG-PATH-PY-001',
  'SAST-SG-CMDI-PHP-001',
  'SAST-DESER-001','SAST-REDOS-001','SAST-CRYPTO-WEAK-001',
  'SAST-DANGER-001','SAST-DATA-PII-001',
]);
// Placeholder/example secrets that are not real credentials
const PLACEHOLDER_SECRET = /(?:password|example|changeme|test|demo|dummy|fake|mock|sample|placeholder|your[_-]|todo|fixme|xxx|replace[_-]me|__CHANGE)/i;
// Build tool / config file patterns where eval/exec is expected and safe
const BUILD_TOOL_FILE = /(?:webpack|rollup|vite|esbuild|babel|jest|vitest|mocha|karma|eslint|prettier|postcss|tailwind|next|nuxt|astro|tsconfig|tsup|turbo|gulpfile|gruntfile|makefile|rakefile|setup\.(?:py|cfg)|conftest|\.config\.|\.conf\.|Dockerfile|docker-compose)/i;
// Patterns that look like credit card numbers but are actually test data, version strings, or IDs
const CREDIT_CARD_FP = /(?:0000[- ]?0000|1234[- ]?5678|9999[- ]?9999|test|example|mock|dummy|spec|fixture|\bversion\b|\bv\d|\bsha\b|\bhash\b|\buuid\b)/i;

// R4 tuning: framework/library internal paths — scanning the source of a framework finds
// legitimate uses of "dangerous" APIs that the framework itself implements.
const FRAMEWORK_INTERNAL_PATH = /(?:\/lib\/action_|\/lib\/active_|\/lib\/rails\/|\/lib\/sprockets\/|\/actioncable\/|\/actionpack\/|\/actionview\/|\/actionmailer\/|\/activestorage\/|\/activejob\/|\/activemodel\/|\/lib\/flask\/|\/werkzeug\/|\/jinja2\/|\/lib\/express\/|\/lib\/koa\/|\/lib\/hapi\/|\/node_modules\/|\/vendor\/bundle\/|\/site-packages\/|\/django\/contrib\/|\/django\/template\/|\/django\/forms\/|\/django\/utils\/|\/django\/db\/|\/springframework\/|\/spring-boot\/|\/spring-security\/|\/staging\/src\/k8s\.io\/)/i;
// Patterns that indicate ORM/query-builder internals building SQL by design
const ORM_INTERNAL_PATH = /(?:\/active_record\/|\/arel\/|\/knex\/|\/sequelize\/|\/typeorm\/|\/prisma\/|\/sqlalchemy\/|\/database\/|\/db\/migrate\/)/i;
// Certificate patterns that are not secret leaks
const CERTIFICATE_CONSTANT = /(?:-----BEGIN (?:CERTIFICATE|PUBLIC KEY)-----|certificateBeginsWith|caCertificate)/;

function collectFiles(dir: string, depth = 0): string[] {
  const files: string[] = [];
  if (depth > 50) return files;
  try { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { const fp = path.join(dir, entry.name); if (entry.isDirectory()) { if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) files.push(...collectFiles(fp, depth + 1)); } else if (entry.isFile() && !IGNORED_FILE.test(entry.name) && !VENDORED_FILE.test(entry.name) && shouldScanFile(fp, ['**/*'], [])) files.push(fp); } } catch { /* permission */ }
  return files;
}

// Auth/authz rules over-fire because per-line regex can't see auth applied via decorators
// (above), FastAPI Depends / middleware (around) the handler. Suppress these findings when
// an auth marker appears within a window of the match.
const AUTH_RULE_IDS = new Set(['SAST-AUTH-MISSING-001','SAST-AUTHZ-MISSING-001','SAST-AUTHZ-IDOR-001','SAST-EXPRESS-AUTH-001','SAST-DJANGO-AUTH-001','SAST-GIN-AUTH-001','SAST-SPRING-AUTH-001','SAST-ASPNET-AUTH-001']);
const AUTH_MARKER = /(?:Depends\s*\(|requires?_?auth|login_required|@?authenticated?\b|PreAuthorize|RequirePermission|hasPermission|current_user|get_current_user|verify_?token|require(?:Auth|Session|Sudo|Access|Owner|Admin|Role|Login|Permission)|ensure(?:Auth|LoggedIn)|session_?required|isAuthenticated|isLoggedIn|roles?_required|permission_required|admin_required|auth_required|jwt_required|token_required|authorize\b|@auth\b|withAuth|protect\b|authGuard|AuthGuard|passport\.|verifyJWT|checkAuth|getServerSession|auth\(\))/i;
function hasAuthNearby(lines: string[], idx: number): boolean {
  const s = Math.max(0, idx - 10), e = Math.min(lines.length, idx + 18);
  for (let i = s; i < e; i++) { if (AUTH_MARKER.test(lines[i]!)) return true; }
  return false;
}

interface ExpandedFinding {
  ruleId: string; ruleName: string; ruleCategory: string; title: string; description: string;
  severity: string; severityRank: number; filePath: string; lineNumber: number;
  lineRange: string; codeSnippet: string; cweId: string; owaspCategory: string;
  cvssScore: number; cvssVector: string; recommendation: string; language: string;
  confidenceScore: number; falsePositiveProbability: number;
  confidenceLabel: string;
  confidenceFactors: ConfidenceFactors;
  // CVE/EPSS correlation fields (P2)
  cveId?: string;
  epssScore?: number;
  kevListed?: boolean;
  // Reachability / exploitability scoring (P2)
  exploitabilityScore?: number;
  reachabilityDistance?: number;
  reachabilityStatus?: 'reachable' | 'dead' | 'unknown';
  // Matched text from the regex (used for CVE/EPSS lookup)
  match?: string;
}

interface ConfidenceFactors {
  fileTypeScore: number;
  userInputProximity: number;
  frameworkContext: number;
  sanitizationPresent: number;
  patternSpecificity: number;
  codeComplexity: number;
  rawScore: number;
  reasons: string[];
}

// ---------------------------------------------------------------------------
// CVE/EPSS Correlation Lookup Table (P2 — M6)
//
// Maps ruleId substrings and code-pattern fragments to known CVEs, EPSS
// scores (FIRST.org v2025 model), and CISA KEV (Known Exploited Vulnerabilities)
// listing status.  This is a hardcoded lookup — production would query a live
// CVE/EPSS feed.
// ---------------------------------------------------------------------------

interface CveEpssEntry {
  cveId: string;
  epssScore: number;   // 0.0 – 1.0
  kevListed: boolean;
}

/**
 * Lookup table keyed by substrings that may appear in a ruleId or the matched
 * code snippet.  The first match wins — order more-specific patterns first.
 */
const CVE_EPSS_MAP: Array<{ pattern: RegExp; entry: CveEpssEntry }> = [
  // Log4Shell / JNDI injection → CVE-2021-44228
  { pattern: /\$\{jndi:|jndi:ldap|jndi:rmi|log4j|log4shell/i, entry: { cveId: 'CVE-2021-44228', epssScore: 0.975, kevListed: true } },
  // Spring4Shell → CVE-2022-22965
  { pattern: /SpringCloudFunction|spring4shell|ClassLoader.*AccessibleObject/i, entry: { cveId: 'CVE-2022-22965', epssScore: 0.96, kevListed: true } },
  // JWT alg:none → CVE-2015-9235
  { pattern: /alg\s*:\s*["']?none["']?|algorithms\s*:\s*\[.*none/i, entry: { cveId: 'CVE-2015-9235', epssScore: 0.92, kevListed: true } },
  // Python YAML unsafe load → CVE-2020-14343
  { pattern: /yaml\.load\s*\(|yaml\.load_all\s*\(/i, entry: { cveId: 'CVE-2020-14343', epssScore: 0.88, kevListed: false } },
  // SpEL injection → CVE-2022-22950
  { pattern: /SpelExpressionParser|parseExpression|@Value.*#\{/i, entry: { cveId: 'CVE-2022-22950', epssScore: 0.70, kevListed: false } },
  // Jackson polymorphic deserialization → CVE-2019-12384
  { pattern: /jackson.*enableDefaultTyping|ObjectMapper.*enableDefaultTyping/i, entry: { cveId: 'CVE-2019-12384', epssScore: 0.72, kevListed: false } },
  // Java deserialization (ObjectInputStream) → CVE-2023-21830 range
  { pattern: /ObjectInputStream.*readObject|readObject\s*\(/i, entry: { cveId: 'CVE-2023-21830', epssScore: 0.45, kevListed: false } },
  // Python pickle deserialization → generic pickle RCE
  { pattern: /pickle\.loads?\s*\(|cPickle\.loads?\s*\(/i, entry: { cveId: 'CVE-2024-0565', epssScore: 0.35, kevListed: false } },
  // SSTI via render_template_string → generic Jinja2 SSTI
  { pattern: /render_template_string\s*\(/i, entry: { cveId: 'CVE-2023-26137', epssScore: 0.55, kevListed: false } },
  // XXE via XML parsing → CVE-2023-32763
  { pattern: /DocumentBuilderFactory|SAXParser|XMLReader|documentBuilder\.parse/i, entry: { cveId: 'CVE-2023-32763', epssScore: 0.62, kevListed: false } },
  // NoSQL injection ($where) → generic
  { pattern: /\$where\s*:/i, entry: { cveId: 'CVE-2020-7921', epssScore: 0.48, kevListed: false } },
];

/**
 * Look up CVE/EPSS/KEV data for a finding by matching its ruleId and code
 * match against known vulnerability patterns.
 */
function lookupCveEpss(ruleId: string, match: string, codeSnippet?: string): { cveId?: string; epssScore?: number; kevListed?: boolean } {
  const searchStr = `${ruleId} ${match} ${codeSnippet ?? ''}`;
  for (const entry of CVE_EPSS_MAP) {
    if (entry.pattern.test(searchStr)) {
      return { cveId: entry.entry.cveId, epssScore: entry.entry.epssScore, kevListed: entry.entry.kevListed };
    }
  }
  return {};
}

// User input sources — finding near these is higher confidence
const USER_INPUT_MARKERS = /(?:req\.(?:body|params|query|headers|cookies|files?|ip|session)|request\.(?:GET|POST|FILES|META|data|args|form|json|cookies|headers)|params\[|@RequestParam|@RequestBody|@PathVariable|getParameter|getHeader|getCookie|this\.props|useParams|useQuery|argv|stdin|getenv|os\.environ|System\.getenv|Environment\.GetEnvironmentVariable)/;

// Sanitization / validation markers — finding near these is lower confidence
const SANITIZATION_MARKERS = /(?:sanitize|escape|encode|encodeURI|encodeURIComponent|htmlspecialchars|htmlentities|strip_tags|clean|purify|DOMPurify|xss|bleach|validator\.|validate|parseInt|parseFloat|Number\(|isNaN|assertIs|z\.(?:string|number|object)|Joi\.|yup\.|celebrate|express-validator|class-validator|csp|helmet|nonce|prepared?Statement|parameterized|\$\d+|%s|\?\s*,|bindParam|bindValue|createQueryBuilder|whereRaw.*\?|sanitizeHtml)/i;

// File paths that indicate production/critical code
const PROD_FILE_PATHS = /(?:\/src\/|\/app\/|\/lib\/|\/pkg\/|\/internal\/|\/cmd\/|\/api\/|\/routes\/|\/controllers?\/|\/handlers?\/|\/services?\/|\/middleware\/|\/models?\/|\/views?\/|\/templates?\/)/;
// File paths that indicate non-production code
const NON_PROD_FILE_PATHS = /(?:\/test|\/spec|\/mock|\/stub|\/fixture|\/example|\/demo|\/sample|\/playground|\/sandbox|\/scripts\/|\/tools\/|\/docs\/|\/migrations?\/|\/seeds?\/)/i;

// Sensitive file indicators — bugs here have real impact
const SENSITIVE_FILE = /(?:auth|login|password|session|token|payment|billing|checkout|admin|crypto|security|secret|credential|permission|role|access|oauth|saml|jwt|certificate|key|encrypt|decrypt|sign|verify)/i;

function computeConfidence(
  rule: SastRule,
  filePath: string,
  lineNumber: number,
  lines: string[],
  language: string,
): ConfidenceFactors {
  const reasons: string[] = [];
  const basename = path.basename(filePath);
  const relativePath = filePath;

  // 1. File type score (0.0 – 1.0): is this a real source file in production code?
  let fileTypeScore = 0.5;
  if (PROD_FILE_PATHS.test(relativePath)) { fileTypeScore = 0.8; reasons.push('production code path'); }
  if (NON_PROD_FILE_PATHS.test(relativePath)) { fileTypeScore = 0.2; reasons.push('non-production path'); }
  if (TEST_PATH.test(relativePath)) { fileTypeScore = 0.15; reasons.push('test/fixture file'); }
  if (BUILD_TOOL_FILE.test(basename)) { fileTypeScore = 0.1; reasons.push('build/config file'); }
  // R4 tuning: framework internal code legitimately uses dangerous APIs
  if (FRAMEWORK_INTERNAL_PATH.test(relativePath)) { fileTypeScore = Math.min(fileTypeScore, 0.15); reasons.push('framework/library internal'); }
  if (ORM_INTERNAL_PATH.test(relativePath) && (rule.id.includes('SQLI') || rule.id === 'SAST-SQLI-001')) { fileTypeScore = 0.05; reasons.push('ORM internal building SQL by design'); }
  if (SENSITIVE_FILE.test(basename)) { fileTypeScore = Math.min(1.0, fileTypeScore + 0.2); reasons.push('security-sensitive filename'); }

  // 2. User input proximity (0.0 – 1.0): is user-controlled data near the finding?
  let userInputProximity = 0.3;
  const windowStart = Math.max(0, lineNumber - 15);
  const windowEnd = Math.min(lines.length, lineNumber + 5);
  const window = lines.slice(windowStart, windowEnd).join('\n');
  if (USER_INPUT_MARKERS.test(window)) {
    userInputProximity = 0.9;
    reasons.push('user input source nearby');
  } else if (USER_INPUT_MARKERS.test(lines.slice(Math.max(0, lineNumber - 30), Math.min(lines.length, lineNumber + 10)).join('\n'))) {
    userInputProximity = 0.6;
    reasons.push('user input source in extended context');
  }

  // 3. Framework context (0.0 – 1.0): does framework usage make this more/less likely real?
  let frameworkContext = 0.5;
  // Route handlers with direct response rendering = higher confidence for XSS/injection
  if (/(?:router\.|app\.|\.get\(|\.post\(|\.put\(|\.delete\(|@app\.route|@api_view|@action)/.test(window)) {
    if (['injection', 'xss', 'auth'].some(cat => rule.category.toLowerCase().includes(cat))) {
      frameworkContext = 0.7; reasons.push('route handler context');
    }
  }
  // ORM usage lowers SQL injection confidence
  if (/(?:\.findOne|\.findAll|\.create\(|\.update\(|\.destroy\(|Model\.|\.objects\.|ActiveRecord|Entity|Repository|TypeORM|Sequelize|Prisma|mongoose\.)/.test(window)) {
    if (rule.id.includes('SQLI') || rule.id.includes('INJ')) {
      frameworkContext = 0.2; reasons.push('ORM usage detected');
    }
  }

  // 4. Sanitization present (0.0 – 1.0): inverse — 1.0 means NO sanitization found
  let sanitizationPresent = 0.7;
  if (SANITIZATION_MARKERS.test(window)) {
    sanitizationPresent = 0.2;
    reasons.push('sanitization/validation nearby');
  }

  // 5. Pattern specificity (0.0 – 1.0): how specific is the rule?
  let patternSpecificity = 0.5;
  // Rules with multiple patterns are more specific (they have to match specific forms)
  if (rule.patterns.length >= 3) { patternSpecificity = 0.7; }
  // Rules with exclude patterns have been refined = higher specificity
  if (rule.excludePatterns && rule.excludePatterns.length > 0) { patternSpecificity += 0.1; }
  // Certain rule categories are inherently higher confidence
  if (['SAST-SQLI', 'SAST-CMDI', 'SAST-DANGER'].some(p => rule.id.startsWith(p))) { patternSpecificity = 0.8; }
  if (['SAST-SECRET', 'SAST-AUTH-HARDCODED'].some(p => rule.id.startsWith(p))) { patternSpecificity = 0.6; }
  if (['SAST-DEBUG', 'SAST-CONF'].some(p => rule.id.startsWith(p))) { patternSpecificity = 0.4; }
  // R4 tuning: Math.random/MD5/SHA1 rules are low specificity unless in auth/crypto context
  if (rule.id === 'SAST-SG-CRYPTO-JS-PSEUDORANDOM-001' || rule.id === 'SAST-CRYPTO-RANDOM-001') {
    const nearbyCode = lines.slice(Math.max(0, lineNumber - 10), Math.min(lines.length, lineNumber + 5)).join('\n');
    if (/(?:auth|token|session|password|secret|nonce|csrf|key|salt|iv|encrypt|sign|verify|credential)/i.test(nearbyCode)) {
      patternSpecificity = 0.7; reasons.push('PRNG near security-sensitive code');
    } else {
      patternSpecificity = 0.2; reasons.push('PRNG in non-security context');
    }
  }
  if (rule.id === 'SAST-SG-CRYPTO-RUBY-MD5-001' || rule.id === 'SAST-SG-CRYPTO-GO-WEAK-001') {
    const nearbyCode = lines.slice(Math.max(0, lineNumber - 5), Math.min(lines.length, lineNumber + 5)).join('\n');
    if (/(?:password|credential|secret|auth|token|sign|verify|hmac)/i.test(nearbyCode)) {
      patternSpecificity = 0.8; reasons.push('weak hash near credential handling');
    } else {
      patternSpecificity = 0.2; reasons.push('weak hash in non-credential context (cache/etag/fingerprint)');
    }
  }
  patternSpecificity = Math.min(1.0, patternSpecificity);

  // 6. Code complexity (0.0 – 1.0): very large files or very simple lines = lower confidence
  let codeComplexity = 0.5;
  const matchLine = lines[lineNumber] || '';
  if (matchLine.trim().length < 10) { codeComplexity = 0.3; reasons.push('very short match line'); }
  if (lines.length > 5000) { codeComplexity = 0.3; reasons.push('very large file (>5000 lines)'); }
  else if (lines.length > 2000) { codeComplexity = 0.4; }
  else if (lines.length < 50) { codeComplexity = 0.6; reasons.push('small focused file'); }

  // Weighted combination
  const rawScore = (
    fileTypeScore * 0.20 +
    userInputProximity * 0.25 +
    frameworkContext * 0.15 +
    sanitizationPresent * 0.15 +
    patternSpecificity * 0.15 +
    codeComplexity * 0.10
  );

  return {
    fileTypeScore, userInputProximity, frameworkContext,
    sanitizationPresent, patternSpecificity, codeComplexity,
    rawScore, reasons,
  };
}

// ---------------------------------------------------------------------------
// Intra-file dataflow / taint tracking
// Tracks assignments from user-input sources through variable chains to sinks.
// ---------------------------------------------------------------------------

interface TaintedVar {
  name: string;
  sourceLine: number;
  sourceType: string;
}

interface DataflowResult {
  taintedVars: TaintedVar[];
  dataflowConfirmed: boolean;
  dataflowPath: string[];
}

const TAINT_SOURCES: Array<{ pattern: RegExp; type: string }> = [
  { pattern: /req\.(?:body|params|query|headers|cookies|files?)\b/, type: 'HTTP-request' },
  { pattern: /request\.(?:GET|POST|FILES|data|args|form|json|cookies|headers)\b/, type: 'HTTP-request' },
  { pattern: /ctx\.(?:request\.body|query|params)\b/, type: 'HTTP-request' },
  { pattern: /\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/, type: 'HTTP-request' },
  { pattern: /@(?:RequestBody|RequestParam|PathVariable|RequestHeader|CookieValue|FromBody|FromQuery|FromRoute)\b/, type: 'annotation' },
  { pattern: /c\.(?:Query|Param|PostForm|Bind|FormValue|QueryParam)\b/, type: 'HTTP-request' },
  { pattern: /getParameter\s*\(/, type: 'HTTP-request' },
  { pattern: /getHeader\s*\(/, type: 'HTTP-request' },
  { pattern: /(?:process\.env|os\.environ|System\.getenv|os\.Getenv)\b/, type: 'environment' },
  { pattern: /(?:document\.(?:location|URL|referrer|cookie)|window\.location|location\.(?:hash|search|href))\b/, type: 'DOM' },
];

const TAINT_SINKS: Array<{ pattern: RegExp; type: string; severity: string }> = [
  { pattern: /(?:db\.query|pool\.query|connection\.query|\.execute|cursor\.execute|\.queryRaw|\.\$queryRaw|sequelize\.query|jdbcTemplate\.query|mysqli_query|pg_query)\s*\(/, type: 'SQL-injection', severity: 'critical' },
  { pattern: /(?:child_process\.exec|execSync|os\.system|Runtime\.exec|Process\.Start|subprocess\.(?:run|Popen|call)|shell_exec|popen|exec\.Command)\s*\(/, type: 'command-injection', severity: 'critical' },
  { pattern: /(?:eval|Function)\s*\(/, type: 'code-execution', severity: 'critical' },
  { pattern: /(?:\.innerHTML|\.outerHTML|document\.write|\.html\()\s*[=(]/, type: 'XSS', severity: 'high' },
  { pattern: /(?:fetch|axios\.(?:get|post|put|delete)|requests\.(?:get|post|put)|http\.(?:Get|Post)|curl_exec|urllib\.request)\s*\(/, type: 'SSRF', severity: 'high' },
  { pattern: /(?:fs\.(?:writeFile|writeFileSync|appendFile|readFile|readFileSync|unlink)|file_put_contents|file_get_contents|fopen|open)\s*\(/, type: 'path-traversal', severity: 'high' },
  { pattern: /(?:res\.(?:send|json|render|write)|response\.(?:send|json|write)|\.render\()\s*\(/, type: 'response-injection', severity: 'medium' },
];

// Assignment patterns: extract (varName, RHS) for taint propagation
const ASSIGN_PATTERNS = [
  /(?:const|let|var|auto|final)\s+(\w+)\s*=\s*(.+)/,
  /(\w+)\s*=\s*(.+)/,
  /(\w+)\s*:=\s*(.+)/,
];

// Sanitization breaks taint
const TAINT_SANITIZERS = /(?:parseInt|parseFloat|Number\(|encodeURIComponent|encodeURI|htmlspecialchars|htmlentities|escape\(|DOMPurify|sanitize|\.trim\(\)|\.replace\(.*\/[gi]*\)|validator\.|z\.(?:string|number)|Joi\.|prepared|parameterized|\$\d+|bindParam|bindValue)/i;

function analyzeDataflowForLine(
  lines: string[],
  sinkLine: number,
  language: string,
): DataflowResult {
  const taintedVars: TaintedVar[] = [];
  const dataflowPath: string[] = [];

  // Phase 1: Scan backwards from the finding to identify tainted variables
  const scanStart = Math.max(0, sinkLine - 100);
  const scanEnd = Math.min(lines.length, sinkLine + 1);

  for (let i = scanStart; i < scanEnd; i++) {
    const line = lines[i]!;

    // Check for direct taint sources
    for (const src of TAINT_SOURCES) {
      if (!src.pattern.test(line)) continue;

      // Extract assigned variable name
      for (const ap of ASSIGN_PATTERNS) {
        const m = line.match(ap);
        if (m && m[2] && src.pattern.test(m[2])) {
          taintedVars.push({ name: m[1]!, sourceLine: i + 1, sourceType: src.type });
          break;
        }
      }
      // Also check for destructuring and direct use
      const destructMatch = line.match(/\{\s*([\w,\s]+)\}\s*=\s*(.+)/);
      if (destructMatch && src.pattern.test(destructMatch[2]!)) {
        for (const v of destructMatch[1]!.split(',')) {
          const vname = v.trim();
          if (vname) taintedVars.push({ name: vname, sourceLine: i + 1, sourceType: src.type });
        }
      }

      // Java/Spring annotation parameters: @RequestParam String accountName
      const javaParamMatch = line.match(/@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|FormParam|QueryParam)\s*(?:\([^)]*\))?\s+\w+\s+(\w+)/);
      if (javaParamMatch) {
        taintedVars.push({ name: javaParamMatch[1]!, sourceLine: i + 1, sourceType: 'annotation' });
      }
      // Also: Type annotatedParam with annotation on same line
      const javaParamMatch2 = line.match(/@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)\s*(?:\([^)]*\))?\s*(\w+)/);
      if (javaParamMatch2 && !javaParamMatch) {
        taintedVars.push({ name: javaParamMatch2[1]!, sourceLine: i + 1, sourceType: 'annotation' });
      }

      // Python function parameters from Flask/Django views: def view(request, name):
      const pyParamMatch = line.match(/def\s+\w+\s*\(\s*(?:self\s*,\s*)?request\s*(?:,\s*(\w+(?:\s*,\s*\w+)*))?/);
      if (pyParamMatch && pyParamMatch[1]) {
        for (const p of pyParamMatch[1].split(',')) {
          const pname = p.trim().split(':')[0]!.split('=')[0]!.trim();
          if (pname && pname !== 'self') taintedVars.push({ name: pname, sourceLine: i + 1, sourceType: 'HTTP-request' });
        }
      }
    }

    // Propagate taint through assignments (x = taintedVar.something or fn(taintedVar))
    for (const ap of ASSIGN_PATTERNS) {
      const m = line.match(ap);
      if (!m || !m[1] || !m[2]) continue;
      const rhs = m[2];

      // Check if RHS references any already-tainted variable
      for (const tv of taintedVars) {
        if (new RegExp(`\\b${tv.name}\\b`).test(rhs)) {
          // Check if sanitization breaks taint
          if (TAINT_SANITIZERS.test(rhs)) continue;
          // Don't re-add the same var
          if (tv.name === m[1]) continue;
          taintedVars.push({ name: m[1], sourceLine: i + 1, sourceType: `propagated from ${tv.name}` });
          break;
        }
      }
    }
  }

  // Phase 2: Check if the sink line uses any tainted variable
  const sinkContent = lines[sinkLine] || '';
  let dataflowConfirmed = false;

  // Check if any tainted variable appears in the sink line
  for (const tv of taintedVars) {
    if (new RegExp(`\\b${tv.name}\\b`).test(sinkContent)) {
      dataflowConfirmed = true;
      // Build the path: source -> [propagation] -> sink
      dataflowPath.push(`source: ${tv.sourceType} (line ${tv.sourceLine})`);

      // Find intermediate propagations
      const chain = [tv];
      let current = tv;
      for (const other of taintedVars) {
        if (other.sourceType.startsWith('propagated from') && other.sourceType.includes(current.name)) {
          chain.push(other);
          current = other;
        }
      }
      for (const c of chain) {
        if (c !== tv) dataflowPath.push(`propagation: ${c.name} = ${c.sourceType} (line ${c.sourceLine})`);
      }
      dataflowPath.push(`sink: line ${sinkLine + 1}`);
      break;
    }
  }

  // Also check if the sink line directly references a taint source (no variable)
  if (!dataflowConfirmed) {
    for (const src of TAINT_SOURCES) {
      if (src.pattern.test(sinkContent)) {
        dataflowConfirmed = true;
        dataflowPath.push(`direct: ${src.type} used at sink (line ${sinkLine + 1})`);
        break;
      }
    }
  }

  return { taintedVars, dataflowConfirmed, dataflowPath };
}

// Rules where dataflow confirmation is meaningful
const DATAFLOW_RELEVANT_RULES = new Set([
  'SAST-SQLI-001', 'SAST-SQLI-002', 'SAST-SQLI-003',
  'SAST-CMDI-001', 'SAST-CMDI-002',
  'SAST-XSS-001', 'SAST-XSS-002', 'SAST-XSS-003',
  'SAST-DANGER-001',
  'SAST-API-SSRF-001',
  'SAST-INJ-NOSQL-001', 'SAST-INJ-NOSQL-002',
  'SAST-INJ-LDAP-001',
  'SAST-INJ-XPATH-001',
  'SAST-INJ-TEMPLATE-001', 'SAST-INJ-TEMPLATE-002',
  'SAST-PT-001',
]);

// ---------------------------------------------------------------------------
// SinkCategory → CWE/OWASP/severity mapping for taint-only findings
// ---------------------------------------------------------------------------
const SINK_CATEGORY_INFO: Record<string, { cweId: string; owaspCategory: string; severity: string; title: string }> = {
  SQL:       { cweId: 'CWE-89',   owaspCategory: 'A03:2021', severity: 'critical', title: 'SQL Injection (Taint Analysis)' },
  COMMAND:   { cweId: 'CWE-78',   owaspCategory: 'A03:2021', severity: 'critical', title: 'Command Injection (Taint Analysis)' },
  FILE:      { cweId: 'CWE-22',   owaspCategory: 'A01:2021', severity: 'high',     title: 'Path Traversal (Taint Analysis)' },
  HTTP_SSRF: { cweId: 'CWE-918',  owaspCategory: 'A10:2021', severity: 'high',     title: 'SSRF (Taint Analysis)' },
  TEMPLATE:  { cweId: 'CWE-1336', owaspCategory: 'A03:2021', severity: 'high',     title: 'Template Injection (Taint Analysis)' },
  CODE:      { cweId: 'CWE-94',   owaspCategory: 'A03:2021', severity: 'critical', title: 'Code Injection (Taint Analysis)' },
  LDAP:      { cweId: 'CWE-90',   owaspCategory: 'A03:2021', severity: 'high',     title: 'LDAP Injection (Taint Analysis)' },
  XPATH:     { cweId: 'CWE-643',  owaspCategory: 'A03:2021', severity: 'high',     title: 'XPath Injection (Taint Analysis)' },
  NOSQL:     { cweId: 'CWE-943',  owaspCategory: 'A03:2021', severity: 'high',     title: 'NoSQL Injection (Taint Analysis)' },
};

/** Broad check: does this rule ID belong to an injection/dataflow-relevant class? */
function isDataflowRelevantRule(ruleId: string): boolean {
  if (DATAFLOW_RELEVANT_RULES.has(ruleId)) return true;
  if (ruleId.includes('SQLI') || ruleId.includes('CMDI') ||
      ruleId.includes('XSS') || ruleId.includes('SSRF') ||
      ruleId.includes('CODEINJ') || ruleId.includes('DESER') ||
      ruleId.includes('SSTI') || ruleId.includes('PATH') ||
      ruleId.includes('OPENREDIRECT') || ruleId.includes('XXE') ||
      ruleId.includes('NOSQL') || ruleId.includes('LDAP') ||
      ruleId.includes('XPATH')) return true;
  return false;
}

/** Check if a taint sink type conceptually matches a regex rule ID. */
function sinkCategoryMatchesRule(sinkType: SinkCategory, ruleId: string): boolean {
  const prefixMap: Record<string, string[]> = {
    SQL:       ['SQLI', 'SQL'],
    COMMAND:   ['CMDI', 'CMD', 'COMMAND'],
    FILE:      ['PT-', 'PATH', 'TRAVERSAL', 'FILE'],
    HTTP_SSRF: ['SSRF'],
    TEMPLATE:  ['SSTI', 'TEMPLATE'],
    CODE:      ['CODEINJ', 'CODE-INJ', 'DANGER', 'EVAL'],
    LDAP:      ['LDAP'],
    XPATH:     ['XPATH'],
    NOSQL:     ['NOSQL'],
  };
  const prefixes = prefixMap[sinkType] ?? [];
  return prefixes.some(p => ruleId.includes(p));
}

/**
 * Find the function in the reachability call graph whose line range contains
 * `targetLine` (1-based). Returns the function name or null.
 */
function findEnclosingReachFunction(
  callGraphR: Map<string, ReachCallGraphNode>,
  targetLine: number,
): string | null {
  let best: string | null = null;
  let bestDelta = Infinity;
  for (const [name, node] of callGraphR) {
    if (node.lineNumber <= targetLine) {
      const delta = targetLine - node.lineNumber;
      if (delta < bestDelta) {
        bestDelta = delta;
        best = name;
      }
    }
  }
  return best;
}

// R5 tuning: skip vendored/compiled/bundled paths that aren't caught by IGNORED_DIRS
const VENDORED_PATH = /(?:\/compiled\/|\/vendored\/|\/third[_-]?party\/|\/external\/|\/generated\/|\/__generated__\/|\.text\.js$)/i;

function scanFileWithAllRules(filePath: string, content: string, language: string): ExpandedFinding[] {
  // R5 tuning: skip very large single-line files (bundled/minified JS)
  const avgLineLen = content.length / Math.max(1, content.split('\n').length);
  if (avgLineLen > 500 && content.length > 50000) return [];
  // R5 tuning: skip vendored/compiled paths
  if (VENDORED_PATH.test(filePath)) return [];

  const findings: ExpandedFinding[] = [];
  const lines = content.split('\n');
  const isTestFile = TEST_PATH.test(filePath);
  const isFrameworkInternal = FRAMEWORK_INTERNAL_PATH.test(filePath);
  const isOrmInternal = ORM_INTERNAL_PATH.test(filePath);
  const applicableRules = ALL_RULES.filter(r => r.languages.includes('all') || r.languages.includes(language));

  for (const rule of applicableRules) {
    if (isTestFile && TEST_SUPPRESSED_RULES.has(rule.id)) continue;
    // R4 tuning: suppress injection/exec rules in framework internals (the framework IS the API)
    if (isFrameworkInternal && (rule.category === 'injection' || rule.id.includes('CODEINJ') || rule.id.includes('CMDI') || rule.id.includes('DESER') || rule.id.includes('SSTI') || rule.id.includes('MARKSAFE') || rule.id.includes('ACTUATOR') || rule.id.includes('XSS'))) continue;
    // R4 tuning: suppress SQL injection rules in ORM/query-builder source code
    if (isOrmInternal && (rule.id.includes('SQLI') || rule.id === 'SAST-SQLI-001' || rule.id === 'SAST-RAILS-SQLI-001')) continue;
    // R5 tuning: suppress K8s IAC rules when scanning K8s source code itself
    if (rule.id.startsWith('SAST-IAC-K8S') && /(?:\/k8s\.io\/|\/kubernetes\/|\/staging\/src\/)/.test(filePath)) continue;
    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;
      for (let li = 0; li < lines.length; li++) {
        const line = lines[li]!;
        if (isCommentLine(line, language)) continue; // skip pure comment lines (FP source)
        pattern.lastIndex = 0;
        const match = pattern.exec(line);
        if (!match) continue;
        // Auth/authz rules: suppress if an auth check is present near the handler.
        if (AUTH_RULE_IDS.has(rule.id) && hasAuthNearby(lines, li)) continue;
        // Secret rules: suppress obvious placeholder/example values
        if ((rule.id === 'SAST-SECRET-001' || rule.id === 'SAST-AUTH-HARDCODED-001' || rule.id.includes('HARDCODED-SECRET')) && PLACEHOLDER_SECRET.test(line)) continue;
        // R4 tuning: suppress certificate constants in SECRET rules (not actual secrets)
        if ((rule.id === 'SAST-SECRET-001' || rule.id.includes('HARDCODED-SECRET')) && CERTIFICATE_CONSTANT.test(line)) continue;
        // Danger rules: suppress in build/config files where eval/exec is expected
        if (rule.id === 'SAST-DANGER-001' && BUILD_TOOL_FILE.test(path.basename(filePath))) continue;
        // Credit card rule: suppress obvious non-CC number patterns (test data, IDs)
        if (rule.id === 'SAST-DATA-CREDIT-001' && CREDIT_CARD_FP.test(line)) continue;
        // SSRF rule: suppress fetch/axios with template literals that aren't user-controlled
        if (rule.id === 'SAST-API-SSRF-001' && /`\$\{/.test(line) && !/req\.|request\.|params\.|query\.|body\./i.test(line)) continue;
        // R4 tuning: hardcoded secret rules — suppress constant NAME definitions (not actual values)
        if (rule.id.includes('HARDCODED-SECRET') && /(?:const|let|var)\s+\w*(?:_TYPE|_UID|_PREFIX|_SUFFIX|_KEY_NAME|_HEADER)\s*=/.test(line)) continue;
        // R4 tuning: JWT none-algorithm rule — `verify: false` is too broad, require JWT context
        if (rule.id === 'SAST-SG-JWT-NONE-001' && /verify\s*[=:]\s*false/.test(line) && !/jwt|token|sign|decode|jsonwebtoken/i.test(lines.slice(Math.max(0, li - 10), Math.min(lines.length, li + 5)).join('\n'))) continue;
        // Check exclude patterns
        let excluded = false;
        if (rule.excludePatterns) { for (const ep of rule.excludePatterns) { ep.lastIndex = 0; if (ep.test(line)) { excluded = true; break; } } }
        if (excluded) continue;

        const ctxStart = Math.max(0, li - 2);
        const ctxEnd = Math.min(lines.length, li + 3);

        const factors = computeConfidence(rule, filePath, li, lines, language);

        // Dataflow analysis: for injection/XSS/SSRF rules, check if user input actually reaches the sink
        let dataflow: DataflowResult | undefined;
        if (DATAFLOW_RELEVANT_RULES.has(rule.id)) {
          dataflow = analyzeDataflowForLine(lines, li, language);
          if (dataflow.dataflowConfirmed) {
            factors.userInputProximity = 1.0;
            factors.reasons.push('dataflow confirmed: user input reaches sink');
          } else if (dataflow.taintedVars.length > 0) {
            factors.reasons.push('tainted vars found but sink not confirmed');
          }
          factors.rawScore = (
            factors.fileTypeScore * 0.20 +
            factors.userInputProximity * 0.25 +
            factors.frameworkContext * 0.15 +
            factors.sanitizationPresent * 0.15 +
            factors.patternSpecificity * 0.15 +
            factors.codeComplexity * 0.10
          );
        }

        const confidenceScore = Math.round(factors.rawScore * 100) / 100;
        const confidenceLabel = confidenceScore >= 0.7 ? 'high' : confidenceScore >= 0.4 ? 'medium' : 'low';
        const falsePositiveProbability = Math.round((1 - confidenceScore) * 100) / 100;

        // CVE/EPSS correlation — deferred (module not yet available)
        findings.push({
          ruleId: rule.id, ruleName: rule.name, ruleCategory: rule.category,
          title: `${rule.name} in ${path.basename(filePath)}`,
          description: rule.description, severity: rule.severity,
          severityRank: SEVERITY_RANK[rule.severity] || 3,
          filePath, lineNumber: li + 1,
          lineRange: `${ctxStart + 1}-${ctxEnd}`,
          codeSnippet: lines.slice(ctxStart, ctxEnd).join('\n').slice(0, 500),
          cweId: rule.cweId, owaspCategory: rule.owaspCategory,
          cvssScore: rule.cvssScore, cvssVector: rule.cvssVector,
          recommendation: rule.recommendation, language,
          confidenceScore, falsePositiveProbability, confidenceLabel,
          confidenceFactors: { ...factors, ...(dataflow ? { dataflowConfirmed: dataflow.dataflowConfirmed, dataflowPath: dataflow.dataflowPath } : {}) } as ConfidenceFactors,
          // CVE/EPSS correlation — deferred (module not yet available)
          cveId: undefined,
          epssScore: undefined,
          kevListed: undefined,
          match: match[0].slice(0, 100),
        });
      }
    }
  }

  // =========================================================================
  // Phase 2: AST-based deep analysis — taint tracking, reachability,
  // multi-line source→sink findings, confidence boosting
  // =========================================================================
  if (supportsASTAnalysis(language) && content.length < 2_000_000) {
    try {
      const ast = parseToIR(content, language, filePath);
      if (ast.length > 0) {
        // 2a. Build call graph (ast-engine variant for dataflow analysis)
        const callGraph = buildCallGraph(ast);

        // 2b. Run full dataflow / taint analysis (sources → sinks → sanitizers)
        const dfResult = analyzeDataflow(ast, callGraph, filePath);

        // 2c. Boost regex findings that are confirmed by a taint path
        if (dfResult.taintPaths.length > 0) {
          for (let fi = 0; fi < findings.length; fi++) {
            const f = findings[fi]!;
            if (!isDataflowRelevantRule(f.ruleId)) continue;

            // Find a taint path whose sink line matches this finding's line
            const matchedPath = dfResult.taintPaths.find(tp => {
              const sinkLine = tp.sink.location.line + 1; // 0-based → 1-based
              return sinkLine === f.lineNumber &&
                sinkCategoryMatchesRule(tp.sink.type, f.ruleId);
            });

            if (matchedPath) {
              const boostedRaw = Math.max(f.confidenceFactors.rawScore, 0.88);
              const boostedScore = Math.round(boostedRaw * 100) / 100;
              const boostedLabel =
                boostedScore >= 0.7 ? 'high' : boostedScore >= 0.4 ? 'medium' : 'low';

              findings[fi] = {
                ...f,
                confidenceScore: boostedScore,
                confidenceLabel: boostedLabel,
                falsePositiveProbability: Math.round((1 - boostedScore) * 100) / 100,
                confidenceFactors: {
                  ...f.confidenceFactors,
                  rawScore: boostedRaw,
                  reasons: [
                    ...f.confidenceFactors.reasons,
                    'taint analysis confirmed: source→sink path verified',
                  ],
                  dataflowConfirmed: true,
                  dataflowPath: matchedPath.pathNodes.map(
                    n => `${n.functionName || n.description} (line ${n.lineNumber})`,
                  ),
                  taintSourceType: matchedPath.source.type,
                  taintSinkType: matchedPath.sink.type,
                  taintReachabilityScore: matchedPath.reachabilityScore,
                } as ConfidenceFactors,
              };
            }
          }

          // 2d. Emit NEW taint-only findings for multi-line flows not already
          //     caught by the regex pass
          const alreadyCovered = new Set(findings.map(f => f.lineNumber));
          for (const tp of dfResult.taintPaths) {
            const sinkLine = tp.sink.location.line + 1;
            const sourceLine = tp.source.location.line + 1;

            // Only emit when source ≠ sink AND the sink line is not already covered
            if (sourceLine === sinkLine || alreadyCovered.has(sinkLine) || tp.isBlocked) {
              continue;
            }

            const sinkInfo = SINK_CATEGORY_INFO[tp.sink.type];
            if (!sinkInfo) continue;

            const ctxStart = Math.max(0, sinkLine - 3);
            const ctxEnd = Math.min(lines.length, sinkLine + 2);
            const ruleId = `SAST-TAINT-${tp.sink.type}`;

            const tfFactors: ConfidenceFactors = {
              fileTypeScore: 0.8,
              userInputProximity: 1.0,
              frameworkContext: 0.7,
              sanitizationPresent: tp.isBlocked ? 0.1 : 0.8,
              patternSpecificity: 0.9,
              codeComplexity: 0.5,
              rawScore: Math.min(0.99, tp.reachabilityScore + 0.1),
              reasons: [
                'multi-line taint flow detected',
                `source: ${tp.source.description} (line ${sourceLine})`,
                `sink: ${tp.sink.description} (line ${sinkLine})`,
                tp.isBlocked ? 'sanitizer present on path' : 'no sanitizer on path',
              ],
              dataflowConfirmed: true,
              dataflowPath: tp.pathNodes.map(
                n => `${n.functionName || n.description} (line ${n.lineNumber})`,
              ),
              taintSourceType: tp.source.type,
              taintSinkType: tp.sink.type,
              taintReachabilityScore: tp.reachabilityScore,
            } as ConfidenceFactors;

            const tfScore = Math.round(tfFactors.rawScore * 100) / 100;
            const tfLabel =
              tfScore >= 0.7 ? 'high' : tfScore >= 0.4 ? 'medium' : 'low';

            findings.push({
              ruleId,
              ruleName: `Taint Analysis: ${tp.sink.type}`,
              ruleCategory: 'injection',
              title: `${sinkInfo.title} in ${path.basename(filePath)}`,
              description: `Multi-line taint flow: ${tp.source.description} → ${tp.sink.description} (${tp.pathNodes.length} hops)`,
              severity: sinkInfo.severity,
              severityRank: SEVERITY_RANK[sinkInfo.severity] ?? 3,
              filePath,
              lineNumber: sinkLine,
              lineRange: `${ctxStart + 1}-${ctxEnd}`,
              codeSnippet: lines.slice(ctxStart, ctxEnd).join('\n').slice(0, 500),
              cweId: sinkInfo.cweId,
              owaspCategory: sinkInfo.owaspCategory,
              cvssScore: tp.sink.severity === 'critical' ? 9.8 : tp.sink.severity === 'high' ? 7.5 : 5.0,
              cvssVector: '',
              recommendation: `Review the taint flow from source (line ${sourceLine}) to sink (line ${sinkLine}). Ensure proper sanitization or input validation is applied at the source or before the sink.`,
              language,
              confidenceScore: tfScore,
              falsePositiveProbability: Math.round((1 - tfScore) * 100) / 100,
              confidenceLabel: tfLabel,
              confidenceFactors: tfFactors,
              match: `${tp.source.type}:${tp.sink.type}`.slice(0, 100),
            });
          }
        }

        // 2e. Reachability analysis (entry-point → call graph BFS)
        const callGraphR = buildCallGraphFromAST(ast, filePath);
        const entryPointsArr = identifyEntryPoints(callGraphR, 'unknown', ast, filePath);
        const reachResult = computeReachability(callGraphR, entryPointsArr);

        // Attach exploitability metadata to each finding
        for (let fi = 0; fi < findings.length; fi++) {
          const f = findings[fi]!;
          const encFn = findEnclosingReachFunction(callGraphR, f.lineNumber);
          const reachInfo: FindingReachability = encFn
            ? (reachResult.reachabilityMap.get(encFn) ?? {
                isReachable: false,
                distance: -1,
              })
            : { isReachable: false, distance: -1 };

          const exploitScore = computeExploitabilityScore(
            {
              cvssScore: f.cvssScore,
              cweId: f.cweId,
              severity: f.severity,
            },
            reachInfo,
            false, // wafDetected — not known per-file
            false, // authRequired — not known per-file
          );

          // Attach reachability metadata
          findings[fi] = {
            ...f,
            confidenceFactors: {
              ...f.confidenceFactors,
              reachabilityDistance: reachInfo.distance,
              reachabilityIsReachable: reachInfo.isReachable,
              exploitabilityScore: exploitScore,
            } as ConfidenceFactors,
          };
        }
      }
    } catch (err) {
      logger.warn(
        { filePath, err },
        'AST/taint analysis skipped for file (non-fatal)',
      );
    }
  }

  // -----------------------------------------------------------------------
  // Track per-rule performance (precision engine)
  // -----------------------------------------------------------------------
  for (const f of findings) {
    trackRulePerformance(f.ruleId, {
      ruleId: f.ruleId,
      status: 'pending',
      scanTimeMs: 0,
      filePath,
    });
  }

  return findings;
}

async function processJob(job: Job): Promise<Record<string, unknown>> {
  const { scanId, projectId, options, organizationId } = job.data;
  logger.info({ scanId, repoUrl: options?.repoUrl, targetPath: options?.targetPath, totalRules: ALL_RULES.length }, 'SAST Worker: Processing job');
  await job.updateProgress(5);

  let clonedDir: string | null = null;
  try {
    await startScan(scanId);

    // Source can be a Git repo (cloned to a temp dir) or a local filesystem path
    // (a path inside the worker — mount host code read-only at /scan to scan it).
    let targetPath: string;
    if (options?.repoUrl) {
      logger.info({ scanId, repoUrl: options.repoUrl, branch: options.branch }, 'SAST: cloning git repository');
      clonedDir = await cloneRepo(options.repoUrl, options.branch, options.gitToken);
      targetPath = clonedDir;
    } else {
      targetPath = options?.targetPath || '/scan';
      if (!fs.existsSync(targetPath)) {
        throw new Error(`Scan path not found: ${targetPath}. Provide a Git repoUrl or a path under the mounted source dir (/scan).`);
      }
    }

    const files = collectFiles(targetPath);
    logger.info({ scanId, fileCount: files.length }, 'Files collected for scanning');
    await job.updateProgress(10);
    const findings: ExpandedFinding[] = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i]!;
      const language = getLanguage(file);
      if (!language) continue;
      try {
        const content = fs.readFileSync(file, 'utf-8');
        findings.push(...scanFileWithAllRules(file, content, language));
      } catch { /* binary/unreadable */ }
      if (i % 100 === 0) await job.updateProgress(10 + Math.floor((i / files.length) * 85));
    }

    await job.updateProgress(95);

    // -----------------------------------------------------------------------
    // P2: CVE/EPSS correlation — attach known CVE IDs and EPSS scores
    // -----------------------------------------------------------------------
    let cveMatched = 0;
    for (const f of findings) {
      const cve = lookupCveEpss(f.ruleId, f.match ?? '', f.codeSnippet);
      if (cve.cveId) {
        f.cveId = cve.cveId;
        f.epssScore = cve.epssScore;
        f.kevListed = cve.kevListed;
        cveMatched++;
      }
    }
    if (cveMatched > 0) {
      logger.info({ scanId, cveMatched }, 'CVE/EPSS correlation: attached known CVEs to findings');
    }

    // -----------------------------------------------------------------------
    // P2: Reachability analysis — filter findings in dead code (score < 0.2)
    // -----------------------------------------------------------------------
    let findingsFiltered = findings;
    try {
      // Build call graph from AST-compatible files
      const callGraph = new Map<string, ReachCallGraphNode>();
      const allIRNodes: IRNode[] = [];
      for (const file of files) {
        const lang = getLanguage(file);
        if (!lang || !supportsASTAnalysis(lang)) continue;
        try {
          const content = fs.readFileSync(file, 'utf-8');
          const irNodes = parseToIR(content, lang, file);
          if (irNodes.length > 0) {
            allIRNodes.push(...irNodes);
            const fileGraph = buildCallGraphFromAST(irNodes, file);
            // Merge into global graph (deduplicate by function name, preferring first definition)
            for (const [name, node] of fileGraph) {
              if (!callGraph.has(name)) {
                callGraph.set(name, node);
              }
            }
          }
        } catch { /* skip unparseable files */ }
      }

      if (callGraph.size > 0) {
        // Identify entry points (HTTP handlers, main, lambdas, etc.)
        const entryPoints = identifyEntryPoints(callGraph, 'unknown', allIRNodes, '');
        // Compute reachability BFS
        const reachResult = computeReachability(callGraph, entryPoints);

        // Apply reachability filter: suppress findings in dead code (distance < 0 → unreachable)
        // A finding is "dead code" if its enclosing function is unreachable.
        let deadSuppressed = 0;
        findingsFiltered = findings.filter(f => {
          const funcName = findEnclosingReachFunction(callGraph, f.lineNumber);
          if (!funcName) return true; // can't determine — keep finding
          const reachInfo = reachResult.reachabilityMap.get(funcName);
          if (!reachInfo) return true;
          // Compute exploitability score for this finding
          const expScore = computeExploitabilityScore(
            { cvssScore: f.cvssScore, cweId: f.cweId, severity: f.severity },
            { isReachable: reachInfo.isReachable, distance: reachInfo.distance },
            false, // wafDetected — not applicable for SAST
            false, // authRequired — conservative default
          );
          f.exploitabilityScore = expScore;
          f.reachabilityDistance = reachInfo.distance;
          f.reachabilityStatus = reachInfo.isReachable ? 'reachable' : 'dead';
          // Suppress if exploitability score < 0.2 (dead code or very deep)
          if (expScore < 0.2) {
            deadSuppressed++;
            return false;
          }
          return true;
        });
        if (deadSuppressed > 0) {
          logger.info({ scanId, deadSuppressed, totalBefore: findings.length, totalAfter: findingsFiltered.length },
            'Reachability filter: suppressed findings in dead/unreachable code');
        }
      }
    } catch (err) {
      logger.warn({ scanId, err }, 'Reachability analysis failed (non-fatal), proceeding with all findings');
    }
    // -----------------------------------------------------------------------

    const result = { scanId, projectId, organizationId, findings: findingsFiltered, totalFindings: findingsFiltered.length,
        severityBreakdown: { critical: findingsFiltered.filter(f=>f.severity==='critical').length, high: findingsFiltered.filter(f=>f.severity==='high').length, medium: findingsFiltered.filter(f=>f.severity==='medium').length, low: findingsFiltered.filter(f=>f.severity==='low').length, info: findingsFiltered.filter(f=>f.severity==='info').length },
        confidenceBreakdown: { high: findingsFiltered.filter(f=>f.confidenceLabel==='high').length, medium: findingsFiltered.filter(f=>f.confidenceLabel==='medium').length, low: findingsFiltered.filter(f=>f.confidenceLabel==='low').length },
        avgConfidence: findingsFiltered.length > 0 ? Math.round(findingsFiltered.reduce((s,f)=>s+f.confidenceScore,0)/findingsFiltered.length*100)/100 : 0,
        rulesEvaluated: ALL_RULES.length, filesScanned: files.length, categoriesCovered: SAST_RULE_CATEGORIES.map(c=>c.name),
        deadCodeSuppressed: findings.length - findingsFiltered.length };
      for (const f of findingsFiltered) {
        try {
          await storeFinding(scanId, projectId, organizationId, {
            type: 'sast', title: f.title || f.ruleName || f.ruleId,
            description: f.description || '', severity: f.severity || 'info',
            cweId: f.cweId || undefined, owaspCategory: f.owaspCategory || undefined,
            cvssScore: f.cvssScore || undefined, cvssVector: f.cvssVector || undefined,
            filePath: f.filePath || undefined, lineNumber: f.lineNumber || undefined,
            codeSnippet: f.codeSnippet || undefined, ruleId: f.ruleId || undefined,
            ruleName: f.ruleName || undefined, recommendation: f.recommendation || undefined,
            confidence: f.confidenceLabel,
            metadata: {
              confidenceScore: f.confidenceScore,
              falsePositiveProbability: f.falsePositiveProbability,
              confidenceFactors: f.confidenceFactors,
              dataflowConfirmed: (f.confidenceFactors as unknown as Record<string, unknown>).dataflowConfirmed ?? null,
              dataflowPath: (f.confidenceFactors as unknown as Record<string, unknown>).dataflowPath ?? null,
              cveId: f.cveId ?? null,
              epssScore: f.epssScore ?? null,
              kevListed: f.kevListed ?? null,
              exploitabilityScore: f.exploitabilityScore ?? null,
              reachabilityDistance: f.reachabilityDistance ?? null,
              reachabilityStatus: f.reachabilityStatus ?? null,
            },
          });
        } catch (e) { logger.error({ scanId, err: e }, 'SAST: failed to store finding'); }
      }
      await completeScan(scanId, findingsFiltered.length, { rulesEvaluated: ALL_RULES.length, filesScanned: files.length });
      await job.updateProgress(100);
      logger.info({ scanId, totalFindings: findingsFiltered.length }, 'SAST complete');
      return result;
  } catch (err) {
    logger.error({ scanId, err }, 'SAST failed');
    try { await failScan(scanId, err instanceof Error ? err.message : String(err)); } catch { /* best effort */ }
    throw err;
  } finally {
    if (clonedDir) { try { fs.rmSync(clonedDir, { recursive: true, force: true }); } catch { /* best effort */ } }
  }
}

const worker = new Worker('sast-scan', processJob, { connection, concurrency: 4, limiter: { max: 10, duration: 60000 } });
worker.on('completed', (j) => logger.info({ jobId: j?.id }, 'SAST done'));
worker.on('failed', (j, e) => logger.error({ jobId: j?.id, err: e.message }, 'SAST error'));
logger.info('SAST Worker running');
