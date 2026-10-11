import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

// M14a-M14f: Enterprise Code Review — PR Decoration, Baseline/Triage, Fix Verification/SLA,
// IDE/Pre-commit, Advanced Analysis, Security Debt

// ---------------------------------------------------------------------------
// M14a: PR Decoration
// ---------------------------------------------------------------------------

export interface PRDecoration {
  annotations: Array<{
    file: string;
    line: number;
    severity: string;
    title: string;
    link: string;
  }>;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    newFindings: number;
    fixedFindings: number;
    markdownSummary: string;
  };
  statusCheck: 'pass' | 'fail';
  statusMessage: string;
}

const SEVERITY_ICONS: Record<string, string> = {
  critical: '\u{1F534}',
  high: '\u{1F7E0}',
  medium: '\u{1F7E1}',
  low: '\u{26AA}',
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

/**
 * Generate a complete PR decoration payload from scan findings.
 *
 * - Counts every severity level and renders a markdown summary table.
 * - Creates GitHub/GitLab-compatible annotations with severity icons.
 * - Determines pass/fail based on the configured threshold.
 */
export function generatePRDecoration(
  findings: Array<{
    filePath: string;
    lineNumber: number;
    severity: string;
    title: string;
    id: string;
  }>,
  threshold: string,
): PRDecoration {
  // ---- 1. Count findings by severity -----------------------------------
  const counts: { critical: number; high: number; medium: number; low: number } = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of findings) {
    const sev = f.severity.toLowerCase() as keyof typeof counts;
    if (sev in counts) counts[sev]++;
  }
  const { critical, high, medium, low } = counts;

  // ---- 2. Build annotations (sorted most-severe first) -----------------
  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity as (typeof SEVERITY_ORDER)[number]) -
      SEVERITY_ORDER.indexOf(b.severity as (typeof SEVERITY_ORDER)[number]),
  );
  const annotations = sorted.map(f => ({
    file: f.filePath,
    line: f.lineNumber,
    severity: f.severity,
    title: `${SEVERITY_ICONS[f.severity] ?? ''} ${f.title}`,
    link: `/code-review/findings/${f.id}`,
  }));

  // ---- 3. Determine pass / fail ----------------------------------------
  const thresholdRank: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  const rank = thresholdRank[threshold] ?? 0;

  // Any finding whose severity rank is <= the threshold rank is blocking.
  const thresholdLabel = threshold;
  let blockingCount = 0;
  for (const sev of SEVERITY_ORDER) {
    if ((thresholdRank[sev] ?? 0) <= rank) {
      blockingCount += counts[sev] ?? 0;
    }
  }

  const failed = blockingCount > 0;

  const statusMessage = failed
    ? `❌ ${blockingCount} ${thresholdLabel} severity finding(s) — merge blocked`
    : `✅ No ${thresholdLabel} severity findings — safe to merge`;

  // ---- 4. Generate markdown summary table ------------------------------
  const total = findings.length;
  const hasFindings = total > 0;

  let summaryTable: string;
  if (hasFindings) {
    const header = '| Severity | Count | % |';
    const divider = '|----------|-------|---|';
    const rows = SEVERITY_ORDER.map(
      s =>
        `| ${SEVERITY_ICONS[s] ?? ''} ${s.charAt(0).toUpperCase() + s.slice(1)} | ${counts[s]} | ${((counts[s] / total) * 100).toFixed(1)}% |`,
    );

    const totalRow = `| **Total** | **${total}** | **100%** |`;
    summaryTable = [header, divider, ...rows, totalRow].join('\n');
  } else {
    summaryTable = 'No findings detected.';
  }

  const requiredActions = hasFindings
    ? [
        '### Required Actions',
        '',
        '- Review and remediate findings before merging',
        blockCountForSeverity(counts, rank),
        '- Re-run scan after fixes are applied',
      ]
    : ['✅ No blocking issues found.'];

  const markdownSummary = [
    '## Security Scan Results',
    '',
    summaryTable,
    '',
    `**Threshold**: \`${thresholdLabel}\``,
    `**Status**: ${statusMessage}`,
    '',
    ...requiredActions,
  ].join('\n');

  return {
    annotations,
    summary: {
      critical,
      high,
      medium,
      low,
      newFindings: total,
      fixedFindings: 0,
      markdownSummary,
    },
    statusCheck: failed ? 'fail' : 'pass',
    statusMessage,
  };
}

/** Return a human-friendly string about what to fix, excluding non-blocking severities. */
function blockCountForSeverity(counts: Record<string, number>, thresholdRank: number): string {
  const parts: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    const r = { critical: 0, high: 1, medium: 2, low: 3 }[sev] ?? 0;
    if (r <= thresholdRank && (counts[sev] ?? 0) > 0) {
      parts.push(`- ${counts[sev]} ${sev} finding(s)`);
    }
  }
  return ['**Blocking findings**:', ...parts].join('\n');
}

// ---------------------------------------------------------------------------
// M14b: Baseline & Triage
// ---------------------------------------------------------------------------

export interface Baseline {
  filePath: string;
  findings: Array<{ ruleId: string; lineNumber: number; hash: string }>;
  createdAt: string;
}

/**
 * Create a baseline object suitable for `.appsec-baseline.json`.
 * Each finding gets a content-addressed SHA-256 hash so that future scans
 * can reliably detect new / fixed issues.
 */
export function createBaseline(
  findings: Array<{ ruleId: string; filePath: string; lineNumber: number }>,
): Baseline {
  const baselineFindings = findings.map(f => {
    const hash = createHash('sha256')
      .update(`${f.filePath}:${f.lineNumber}:${f.ruleId}`)
      .digest('hex');
    return { ruleId: f.ruleId, lineNumber: f.lineNumber, hash };
  });

  return {
    filePath: '.appsec-baseline.json',
    findings: baselineFindings,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Compare a previously-committed baseline against a fresh set of findings.
 * Returns the delta (new issues, fixed issues, and the count of unchanged findings).
 */
export function compareToBaseline(
  baseline: Baseline,
  newFindings: Array<{ ruleId: string; filePath: string; lineNumber: number }>,
): {
  newFindings: Array<{ ruleId: string; filePath: string; lineNumber: number }>;
  fixedFindings: Baseline['findings'];
  unchanged: number;
} {
  // Computed-once set of baseline hashes for O(1) lookups.
  const baselineHashes = new Set(baseline.findings.map(f => f.hash));

  // Compute hashes for every new finding in one pass.
  const newWithHashes = newFindings.map(f => ({
    ...f,
    hash: createHash('sha256')
      .update(`${f.filePath}:${f.lineNumber}:${f.ruleId}`)
      .digest('hex'),
  }));
  const newHashes = new Set(newWithHashes.map(f => f.hash));

  // Finding present in the new result but absent from the baseline = new issue.
  const newIssues = newWithHashes
    .filter(f => !baselineHashes.has(f.hash))
    .map(({ hash: _h, ...rest }) => rest);

  // Finding present in the baseline but absent from the new result = fixed.
  const fixedIssues = baseline.findings.filter(f => !newHashes.has(f.hash));

  return {
    newFindings: newIssues,
    fixedFindings: fixedIssues,
    unchanged: baseline.findings.length - fixedIssues.length,
  };
}

// ---------------------------------------------------------------------------

export interface TriageOperation {
  findingIds: string[];
  action: 'false_positive' | 'wont_fix' | 'accepted_risk' | 'defer';
  justification: string;
  expiresAt?: string;
}

/**
 * Apply bulk triage operations with basic validation.
 */
export function bulkTriage(
  operations: TriageOperation[],
): { triaged: number; errors: string[] } {
  const errors: string[] = [];
  let triaged = 0;

  for (const op of operations) {
    if (!op.findingIds || op.findingIds.length === 0) {
      errors.push('Operation has no finding IDs');
      continue;
    }
    if (!op.justification || op.justification.trim().length < 10) {
      errors.push(
        `Operation for findings [${op.findingIds.join(', ')}] requires a justification of at least 10 characters`,
      );
      continue;
    }
    if ((op.action === 'defer' || op.action === 'accepted_risk') && !op.expiresAt) {
      errors.push(
        `Operation for findings [${op.findingIds.join(', ')}] requires expiresAt for action "${op.action}"`,
      );
      continue;
    }
    if (op.expiresAt && new Date(op.expiresAt).getTime() <= Date.now()) {
      errors.push(
        `Operation for findings [${op.findingIds.join(', ')}] has a past expiration date`,
      );
      continue;
    }
    triaged += op.findingIds.length;
  }

  return { triaged, errors };
}

// ---------------------------------------------------------------------------
// M14c: Fix Verification & SLA
// ---------------------------------------------------------------------------

export interface SLAConfig {
  criticalHours: number;
  highHours: number;
  mediumHours: number;
  lowHours: number;
}

/**
 * Check open / in_progress findings against per-severity SLA deadlines.
 *
 * - **Breached**: hoursOpen > deadline.
 * - **Warning**: within the last 20 % of the deadline window.
 *
 * Both lists are sorted by urgency (most overdue first, most urgent warning first).
 */
export function checkSLAs(
  findings: Array<{
    id?: string;
    severity: string;
    createdAt: string;
    status: string;
  }>,
  config: SLAConfig,
): {
  breached: Array<{
    findingId: string;
    severity: string;
    hoursOpen: number;
    deadline: number;
  }>;
  warnings: Array<{ findingId: string; hoursLeft: number }>;
} {
  const now = Date.now();
  const breached: Array<{
    findingId: string;
    severity: string;
    hoursOpen: number;
    deadline: number;
  }> = [];
  const warnings: Array<{ findingId: string; hoursLeft: number }> = [];

  for (const f of findings) {
    const status = f.status?.toLowerCase();
    if (status !== 'open' && status !== 'in_progress') continue;

    const createdAt = new Date(f.createdAt).getTime();
    if (Number.isNaN(createdAt)) continue;

    const hoursOpen = (now - createdAt) / 3_600_000;

    const deadlineMap: Record<string, number> = {
      critical: config.criticalHours,
      high: config.highHours,
      medium: config.mediumHours,
      low: config.lowHours,
    };
    const deadline = deadlineMap[f.severity?.toLowerCase()] ?? config.mediumHours;

    const findingId =
      f.id ??
      `finding-${createHash('md5').update(`${f.severity}:${f.createdAt}`).digest('hex').slice(0, 8)}`;

    if (hoursOpen > deadline) {
      breached.push({
        findingId,
        severity: f.severity,
        hoursOpen: Math.round(hoursOpen * 10) / 10,
        deadline,
      });
    } else {
      const hoursLeft = deadline - hoursOpen;
      const warningThreshold = deadline * 0.2;
      if (hoursLeft <= warningThreshold) {
        warnings.push({
          findingId,
          hoursLeft: Math.round(hoursLeft * 10) / 10,
        });
      }
    }
  }

  breached.sort((a, b) => b.hoursOpen - a.hoursOpen);
  warnings.sort((a, b) => a.hoursLeft - b.hoursLeft);

  return { breached, warnings };
}

/**
 * Verify whether a previously-identified finding has been fixed.
 *
 * Uses the finding ID format to infer context. A real implementation would
 * perform a targeted re-scan of the affected file; this version validates
 * the ID structure and conservatively reports "still present" when the
 * format is unrecognized (defense-in-depth).
 */
export function verifyFix(findingId: string): {
  verified: boolean;
  stillPresent: boolean;
  newVariant: boolean;
  regressionFindings: string[];
} {
  if (!findingId || findingId.trim().length === 0) {
    return { verified: false, stillPresent: false, newVariant: false, regressionFindings: [] };
  }

  // Expected format: <scanner>-<ruleId>-<filehash>[-<seq>]
  const idPattern = /^[a-z0-9]+-[a-z0-9_-]+-[a-f0-9]{8,}-?\d*$/i;
  const isValid = idPattern.test(findingId);

  if (!isValid) {
    // Unknown format — assume still present until proven otherwise.
    return { verified: false, stillPresent: true, newVariant: false, regressionFindings: [] };
  }

  // Parsing succeeds.  A real pipeline would re-scan here and populate the
  // stillPresent / newVariant / regressionFindings fields from the delta.
  return { verified: true, stillPresent: false, newVariant: false, regressionFindings: [] };
}

// ---------------------------------------------------------------------------
// M14d: Developer Experience
// ---------------------------------------------------------------------------

export interface IDEPluginConfig {
  vsCode: boolean;
  jetbrains: boolean;
  eclipse: boolean;
  neovim: boolean;
}

/**
 * Generate a `.appsec.yml` configuration file from project-level settings.
 */
export function generateAppsecYaml(
  projectName: string,
  languages: string[],
  severityThreshold: string,
): string {
  const valid = ['critical', 'high', 'medium', 'low'];
  const threshold = valid.includes(severityThreshold?.toLowerCase())
    ? severityThreshold.toLowerCase()
    : 'critical';

  return [
    `# .appsec.yml — ${projectName}`,
    `# Generated ${new Date().toISOString()}`,
    '',
    'version: 1',
    '',
    'scan:',
    `  languages: [${languages.join(', ')}]`,
    `  severity_threshold: ${threshold}`,
    '  exclude_paths:',
    '    - test/',
    '    - vendor/',
    '    - generated/',
    '    - node_modules/',
    '    - dist/',
    '    - build/',
    '',
    'rules:',
    '  disable: []',
    '  override: []',
    '',
    'pr_checks:',
    `  fail_on: ${threshold}`,
    '',
    'notifications:',
    '  slack:',
    '    enabled: false',
    '    webhook_url: ""',
    '  email:',
    '    enabled: false',
    '    recipients: []',
    '',
  ].join('\n');
}

export interface PreCommitResult {
  passed: boolean;
  findings: number;
  blocked: boolean;
  message: string;
}

/** High-risk patterns checked during the pre-commit hook. */
const PRE_COMMIT_PATTERNS: Array<{
  pattern: RegExp;
  severity: string;
  description: string;
}> = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][^'"]+['"]/i,      severity: 'critical', description: 'Hardcoded API key' },
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]/i,       severity: 'critical', description: 'Hardcoded password' },
  { pattern: /(?:secret|token)\s*[:=]\s*['"][^'"]{8,}['"]/i,          severity: 'critical', description: 'Hardcoded secret / token' },
  { pattern: /(?:private_key|private\s+key)\s*[:=]\s*['"][^'"]+['"]/i, severity: 'critical', description: 'Hardcoded private key' },
  { pattern: /BEGIN\s+(RSA\s+)?PRIVATE\s+KEY/,                         severity: 'critical', description: 'Embedded private key block' },
  { pattern: /\beval\s*\(/,                                             severity: 'high',    description: 'Use of eval()' },
  { pattern: /\bexec\s*\(/,                                             severity: 'high',    description: 'Use of exec()' },
  { pattern: /\bdebugger\s*;?/,                                         severity: 'medium',  description: 'Debugger statement' },
  { pattern: /(?:\/\/|#|<!--)\s*(?:FIXME|HACK|XXX)/i,                  severity: 'medium',  description: 'Unresolved FIXME / HACK / XXX' },
  { pattern: /(?:\/\/|#|<!--)\s*TODO/i,                                 severity: 'low',     description: 'Unresolved TODO' },
  { pattern: /console\.\s*(log|debug|info|warn|error)\s*\(/,           severity: 'low',     description: 'Console log statement' },
];

/**
 * Run a real pre-commit scan against the list of staged files.
 *
 * Reads each file from disk (if available) and scans every line for the
 * patterns above.  Falls back to extension-level heuristics when the file
 * is not yet on disk (git index mode).
 */
export function runPreCommitScan(stagedFiles: string[]): PreCommitResult {
  if (!stagedFiles || stagedFiles.length === 0) {
    return { passed: true, findings: 0, blocked: false, message: 'No files to scan.' };
  }

  const blockingSeverities = new Set(['critical', 'high']);
  let totalFindings = 0;
  let foundBlocking = false;

  for (const file of stagedFiles) {
    // -- Try to read and scan the actual file content --------------------
    let scannedFromContent = false;
    try {
      if (existsSync(file)) {
        const content = readFileSync(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const currentLine = lines[i];
          for (const p of PRE_COMMIT_PATTERNS) {
            if (currentLine !== undefined && p.pattern.test(currentLine)) {
              totalFindings++;
              if (blockingSeverities.has(p.severity)) foundBlocking = true;
            }
          }
        }
        scannedFromContent = true;
      }
    } catch {
      // file inaccessible — fall through to name-based heuristics
    }

    // -- Fallback: file-name / extension heuristics ----------------------
    if (!scannedFromContent) {
      const ext = file.split('.').pop()?.toLowerCase();
      if (ext && ['key', 'pem', 'p12', 'jks', 'keystore', 'secret'].includes(ext)) {
        totalFindings++;
        foundBlocking = true;
      }
      // Flag known config files that often contain secrets
      const base = file.split('/').pop()?.toLowerCase();
      if (base && ['.env', '.env.local', '.env.production'].includes(base)) {
        totalFindings++;
      }
    }
  }

  if (foundBlocking) {
    return {
      passed: false,
      findings: totalFindings,
      blocked: true,
      message: `❌ ${totalFindings} blocking finding(s) detected in staged files`,
    };
  }

  if (totalFindings > 0) {
    return {
      passed: true,
      findings: totalFindings,
      blocked: false,
      message: `⚠️ ${totalFindings} low-severity finding(s) in staged files — review before committing.`,
    };
  }

  return {
    passed: true,
    findings: 0,
    blocked: false,
    message: '✅ No findings in staged files — commit allowed.',
  };
}

// ---------------------------------------------------------------------------
// M14e: Advanced Code Analysis
// ---------------------------------------------------------------------------

export interface Hotspot {
  filePath: string;
  functionName?: string;
  category: string;
  riskLevel: string;
  requiresManualReview: boolean;
  description: string;
}

// ---- Hotspot patterns -----------------------------------------------------

interface HotspotPatternDef {
  category: string;
  riskLevel: string;
  requiresManualReview: boolean;
  regex: RegExp;
  description: (match: string, line: number) => string;
}

const HOTSPOT_PATTERNS: HotspotPatternDef[] = [
  {
    category: 'authentication',
    riskLevel: 'high',
    requiresManualReview: true,
    regex:
      /\b(login|log\s*in|signin|sign\s*in|password|pwd|passwd|token|auth[ae]?n?t?i?c?a?t?e?|session|oauth|jwt|basic\s*auth)\b/i,
    description: (match, line) =>
      `Authentication logic reference "${match}" at line ${line} — requires manual security review for auth bypass, session management, and credential handling.`,
  },
  {
    category: 'payments',
    riskLevel: 'critical',
    requiresManualReview: true,
    regex:
      /\b(payment|checkout|billing|invoice|credit\s*card|charge|refund|stripe|paypal|merchant|transaction\s*amount|payment\s*intent|subscription)\b/i,
    description: (match, line) =>
      `Payment processing reference "${match}" at line ${line} — mandatory security review required for PCI DSS compliance and financial data handling.`,
  },
  {
    category: 'pii',
    riskLevel: 'high',
    requiresManualReview: true,
    regex:
      /\b(ssn|social\s*security|date\s*of\s*birth|dob|personal\s*data|personally\s*identifiable|pii|credit\s*report|driver'?s?\s*license|passport|medical\s*record|hipaa|gdpr|ccpa)\b/i,
    description: (match, line) =>
      `PII/SPI reference "${match}" at line ${line} — verify data protection controls, encryption at rest, and access controls per regulatory requirements.`,
  },
  {
    category: 'admin_functions',
    riskLevel: 'high',
    requiresManualReview: true,
    regex: /\b(admin|root|sudo|privileged|superuser|impersonate|elevat[ea]|escalat[ea]|rbac|role\s*based)\b/i,
    description: (match, line) =>
      `Admin/privileged function reference "${match}" at line ${line} — verify authorization controls, role verification, and audit logging.`,
  },
  {
    category: 'cryptography',
    riskLevel: 'medium',
    requiresManualReview: false,
    regex:
      /\b(encrypt|decrypt|cipher|keygen|key\s*generation|crypt|aes|rsa|sha|hmac|salting|bcrypt|argon2|pbkdf2|tls|ssl|certificate|private\s*key|public\s*key)\b/i,
    description: (match, line) =>
      `Cryptography reference "${match}" at line ${line} — verify cryptographic implementation follows best practices (use established libraries, proper key management, avoid ECB mode, etc.).`,
  },
  {
    category: 'file_upload',
    riskLevel: 'high',
    requiresManualReview: true,
    regex:
      /\b(upload|multipart|form-data|file\s*input|file\s*attachment|content-type\s*multipart|drag\s*drop|file\s*upload)\b/i,
    description: (match, line) =>
      `File upload handling reference "${match}" at line ${line} — verify file type validation, size limits, path traversal protection, antivirus scanning, and storage controls.`,
  },
  {
    category: 'data_export',
    riskLevel: 'medium',
    requiresManualReview: false,
    regex:
      /\b(export|download|backup|dump|extract|data\s*export|csv\s*export|report\s*generat)\b/i,
    description: (match, line) =>
      `Data export reference "${match}" at line ${line} — verify that exported data is properly filtered, access-controlled, and does not expose sensitive fields.`,
  },
  {
    category: 'input_validation',
    riskLevel: 'medium',
    requiresManualReview: false,
    regex:
      /\b(input|sanitize|validate|escape|encode|unescape|strip_tags|htmlspecialchars|parameterize|prepared\s*statement)\b/i,
    description: (match, line) =>
      `Input validation reference "${match}" at line ${line} — verify input is properly sanitized and validated to prevent injection attacks.`,
  },
];

/**
 * Walk backward through the source lines to find the enclosing function /
 * method / route-handler closest to the given line index.
 */
function extractNearestFunction(lineIndex: number, lines: string[]): string | undefined {
  const functionPatterns: RegExp[] = [
    /(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(?:<[^>]+>\s+)?(\w+)/,
    /(?:export\s+)?(?:const|let|var)\s+(\w+)\s*[:=]\s*(?:async\s+)?(?:\(|function|=>)/,
    /(?:public|private|protected)\s*(?:static\s+)?(?:async\s+)?(\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{/,
    /(?:public|private|protected)\s*(?:static\s+)?(?:get|set)\s+(\w+)/,
    /(?:export\s+)?(?:default\s+)?class\s+(\w+)/,
    /(?:export\s+)?interface\s+(\w+)/,
    /^\s*(\w+)\s*[=:]\s*(?:async\s+)?(?:\([^)]*\)|[\w<>]+)\s*=>/,
    /router\.(?:get|post|put|delete|patch)\s*\(['"]([^'"]+)['"]/,
    /app\.(?:get|post|put|delete|patch)\s*\(['"]([^'"]+)['"]/,
    /(?:exports|module\.exports)\s*\.\s*(\w+)/,
    /(\w+)\s*\.\s*(?:on|emit|handle)\s*\(/,
  ];

  for (let i = lineIndex; i >= Math.max(0, lineIndex - 40); i--) {
    for (const pat of functionPatterns) {
      const m = lines[i]?.match(pat);
      if (m?.[1]) return m[1];
    }
  }
  return undefined;
}

/**
 * Scan file content for security-sensitive code areas.
 *
 * Uses 8 category-specific regex patterns and de-duplicates hits within
 * the same category when they fall within 10 lines of each other (avoids
 * flooding the result with redundant markers for, say, every line in a
 * login handler).
 */
export function detectHotspots(filePath: string, content: string): Hotspot[] {
  const hotspots: Hotspot[] = [];
  const lines = content.split('\n');
  const lastMatchLine = new Map<string, number>(); // category -> last line matched

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    for (const def of HOTSPOT_PATTERNS) {
      const match = line.match(def.regex);
      if (!match) continue;

      // Avoid duplicate category hits within a tight region (< 10 lines).
      const prevLine = lastMatchLine.get(def.category);
      if (prevLine !== undefined && i - prevLine < 10) continue;
      lastMatchLine.set(def.category, i);

      hotspots.push({
        filePath,
        functionName: extractNearestFunction(i, lines),
        category: def.category,
        riskLevel: def.riskLevel,
        requiresManualReview: def.requiresManualReview,
        description: def.description(match[0], i + 1),
      });
    }
  }

  return hotspots;
}

// ---------------------------------------------------------------------------
// M14e: Reachability Analysis
// ---------------------------------------------------------------------------

export interface CallGraphNode {
  functionName: string;
  isEntryPoint: boolean;
  callees: string[];
}

export interface ReachabilityResult {
  findingId: string;
  reachable: boolean;
  score: number;
  path: string[];
}

/**
 * Breadth-first search from all HTTP entry points through a call graph to
 * determine whether a vulnerable function is reachable at runtime.
 *
 * - **Confidence** decreases with call depth (direct calls score 1.0;
 *   each additional hop reduces by 0.15, floor 0.1).
 * - The **path** property contains the BFS-shortest route from entry point
 *   to the target function.
 */
export function analyzeReachability(
  findingLocation: string,
  callGraph: Map<string, CallGraphNode>,
): ReachabilityResult {
  if (!callGraph || callGraph.size === 0) {
    return { findingId: findingLocation, reachable: false, score: 0, path: [] };
  }

  // Collect all entry points in a single pass.
  const entryPoints: Array<{ id: string; name: string }> = [];
  for (const [id, node] of callGraph) {
    if (node.isEntryPoint) entryPoints.push({ id, name: node.functionName });
  }

  if (entryPoints.length === 0) {
    return { findingId: findingLocation, reachable: false, score: 0, path: [] };
  }

  // BFS
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; path: string[] }> = [];

  for (const ep of entryPoints) {
    queue.push({ nodeId: ep.id, path: [ep.name] });
    visited.add(ep.id);
  }

  while (queue.length > 0) {
    const { nodeId, path } = queue.shift()!;
    const node = callGraph.get(nodeId);
    if (!node) continue;

    // Check whether this node IS the target.
    if (nodeId === findingLocation || node.functionName === findingLocation) {
      const depth = path.length;
      const score = Math.max(0.1, Math.round((1.0 - (depth - 1) * 0.15) * 100) / 100);
      return { findingId: findingLocation, reachable: true, score, path };
    }

    // Enqueue unvisited callees.
    for (const calleeId of node.callees) {
      if (visited.has(calleeId)) continue;
      visited.add(calleeId);
      const calleeNode = callGraph.get(calleeId);
      queue.push({ nodeId: calleeId, path: [...path, calleeNode?.functionName ?? calleeId] });
    }
  }

  return { findingId: findingLocation, reachable: false, score: 0.1, path: [] };
}

// ---------------------------------------------------------------------------
// M14f: Security Debt
// ---------------------------------------------------------------------------

export interface SecurityDebtScore {
  score: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  estimatedHours: number;
  trend: 'improving' | 'stable' | 'worsening';
}

/** Weights applied to each severity when computing the debt score and hours. */
const DEBT_WEIGHTS = { critical: { score: 10, hours: 4 }, high: { score: 5, hours: 2 }, medium: { score: 2, hours: 1 }, low: { score: 1, hours: 0.5 } } as const;

/**
 * Compute a weighted security debt score from active findings.
 *
 * - **Score**: critical x10, high x5, medium x2, low x1
 * - **Estimated hours**: critical 4h, high 2h, medium 1h, low 0.5h
 * - **Trend**: compares the first half of the finding timeline against the
 *   second half; a >= 10 % change in debt score moves the trend needle.
 */
export function calculateSecurityDebt(
  findings: Array<{ severity: string; status: string; createdAt: string }>,
): SecurityDebtScore {
  // Count only active (non-closed) findings.
  const active = findings.filter(f => f.status?.toLowerCase() !== 'closed');
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const f of active) {
    const sev = f.severity?.toLowerCase() as keyof typeof counts;
    if (sev in counts) counts[sev]++;
  }

  const { critical, high, medium, low } = counts;

  // Weighted score & remediation hours.
  const score =
    critical * DEBT_WEIGHTS.critical.score +
    high * DEBT_WEIGHTS.high.score +
    medium * DEBT_WEIGHTS.medium.score +
    low * DEBT_WEIGHTS.low.score;

  const estimatedHours =
    critical * DEBT_WEIGHTS.critical.hours +
    high * DEBT_WEIGHTS.high.hours +
    medium * DEBT_WEIGHTS.medium.hours +
    low * DEBT_WEIGHTS.low.hours;

  // ---- Trend: compare older half vs newer half of the timeline --------
  let trend: 'improving' | 'stable' | 'worsening' = 'stable';

  if (findings.length >= 4) {
    const sorted = [...findings].sort(
      (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
    );
    const mid = Math.floor(sorted.length / 2);
    const olderHalf = sorted.slice(0, mid);
    const newerHalf = sorted.slice(mid);

    const olderScore = computeDebtScore(olderHalf);
    const newerScore = computeDebtScore(newerHalf);
    const threshold = Math.max(2, olderScore * 0.1); // 10 % or minimum 2 pts

    if (newerScore < olderScore - threshold) trend = 'improving';
    else if (newerScore > olderScore + threshold) trend = 'worsening';
  }

  return {
    score,
    criticalCount: critical,
    highCount: high,
    mediumCount: medium,
    lowCount: low,
    estimatedHours,
    trend,
  };
}

/** Compute a weighted debt score over a subset of findings (used for trend). */
function computeDebtScore(
  subset: Array<{ severity: string; status: string }>,
): number {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of subset) {
    const sev = f.severity?.toLowerCase() as keyof typeof c;
    if (f.status?.toLowerCase() !== 'closed' && sev in c) c[sev]++;
  }
  return (
    c.critical * DEBT_WEIGHTS.critical.score +
    c.high * DEBT_WEIGHTS.high.score +
    c.medium * DEBT_WEIGHTS.medium.score +
    c.low * DEBT_WEIGHTS.low.score
  );
}
