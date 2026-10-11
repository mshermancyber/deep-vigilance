import fs from 'fs';
import path from 'path';
import yaml from 'yaml';
import { logger } from '../utils/logger.js';
import type { SastRule } from './engine.js';

// ─── Types for parsed Semgrep YAML ────────────────────────────────────────────

interface SemgrepMetadata {
  cwe?: string | string[];
  owasp?: string | string[];
  category?: string;
  technology?: string[];
  subcategory?: string[];
  likelihood?: string;
  impact?: string;
  confidence?: string;
  references?: string[];
  [key: string]: unknown;
}

interface SemgrepRule {
  id: string;
  message?: string;
  severity?: string;
  languages?: string[];
  metadata?: SemgrepMetadata;
  mode?: string;
  pattern?: string;
  patterns?: SemgrepPatternClause[];
  'pattern-either'?: SemgrepPatternClause[];
  'pattern-regex'?: string;
  'pattern-sources'?: unknown[];
  'pattern-sinks'?: unknown[];
  'pattern-inside'?: string;
  fix?: string;
  'fix-regex'?: unknown;
}

interface SemgrepPatternClause {
  pattern?: string;
  'pattern-regex'?: string;
  'pattern-either'?: SemgrepPatternClause[];
  'pattern-not'?: string;
  'pattern-not-regex'?: string;
  'pattern-inside'?: string;
  'pattern-not-inside'?: string;
  patterns?: SemgrepPatternClause[];
  'metavariable-regex'?: unknown;
  'metavariable-pattern'?: unknown;
  'metavariable-comparison'?: unknown;
  'metavariable-analysis'?: unknown;
}

interface SemgrepRuleFile {
  rules?: SemgrepRule[];
}

// ─── Skip reasons ─────────────────────────────────────────────────────────────

type SkipReason =
  | 'taint-mode'
  | 'metavariable-pattern'
  | 'metavariable-comparison'
  | 'metavariable-analysis'
  | 'complex-pattern-inside'
  | 'no-convertible-patterns'
  | 'invalid-regex'
  | 'parse-error'
  | 'no-rules-field'
  | 'generic-language'
  | 'non-security';

// ─── Severity mapping ─────────────────────────────────────────────────────────

function mapSeverity(semgrepSeverity: string | undefined): SastRule['severity'] {
  switch (semgrepSeverity?.toUpperCase()) {
    case 'ERROR': return 'high';
    case 'WARNING': return 'medium';
    case 'INFO': return 'low';
    default: return 'medium';
  }
}

/**
 * Refine severity based on Semgrep metadata likelihood/impact fields.
 */
function refineSeverity(
  baseSeverity: SastRule['severity'],
  metadata?: SemgrepMetadata,
): SastRule['severity'] {
  if (!metadata) return baseSeverity;
  const impact = metadata.impact?.toUpperCase();
  const likelihood = metadata.likelihood?.toUpperCase();

  // Promote to critical if both impact and likelihood are HIGH
  if (impact === 'HIGH' && likelihood === 'HIGH' && baseSeverity === 'high') {
    return 'critical';
  }
  // Demote if both are LOW
  if (impact === 'LOW' && likelihood === 'LOW' && baseSeverity === 'medium') {
    return 'low';
  }
  return baseSeverity;
}

// ─── CWE extraction ──────────────────────────────────────────────────────────

function extractCweId(metadata?: SemgrepMetadata): string {
  if (!metadata?.cwe) return '';
  const cweEntries = Array.isArray(metadata.cwe) ? metadata.cwe : [metadata.cwe];
  for (const entry of cweEntries) {
    const match = String(entry).match(/CWE-(\d+)/);
    if (match) return `CWE-${match[1]}`;
  }
  return '';
}

function extractAllCweIds(metadata?: SemgrepMetadata): string[] {
  if (!metadata?.cwe) return [];
  const cweEntries = Array.isArray(metadata.cwe) ? metadata.cwe : [metadata.cwe];
  const ids: string[] = [];
  for (const entry of cweEntries) {
    const match = String(entry).match(/CWE-(\d+)/);
    if (match) ids.push(`CWE-${match[1]}`);
  }
  return ids;
}

// ─── OWASP extraction ─────────────────────────────────────────────────────────

function extractOwaspCategory(metadata?: SemgrepMetadata): string {
  if (!metadata?.owasp) return '';
  const owaspEntries = Array.isArray(metadata.owasp) ? metadata.owasp : [metadata.owasp];
  // Prefer 2021 mapping, fall back to any
  for (const entry of owaspEntries) {
    if (String(entry).includes('2021')) return String(entry);
  }
  return String(owaspEntries[0] || '');
}

// ─── Category mapping ─────────────────────────────────────────────────────────

function mapCategory(cweId: string, metadata?: SemgrepMetadata): string {
  const cweNum = parseInt(cweId.replace('CWE-', ''), 10);
  const categoryMap: Record<number, string> = {
    78: 'injection',
    89: 'injection',
    94: 'injection',
    79: 'xss',
    22: 'path-traversal',
    798: 'credentials',
    259: 'credentials',
    321: 'credentials',
    327: 'cryptography',
    328: 'cryptography',
    330: 'cryptography',
    338: 'cryptography',
    502: 'deserialization',
    611: 'xxe',
    918: 'ssrf',
    319: 'cryptography',
    377: 'access-control',
    284: 'access-control',
    285: 'access-control',
    352: 'csrf',
    601: 'open-redirect',
    1275: 'sensitive-cookies',
    614: 'sensitive-cookies',
  };

  if (cweNum && categoryMap[cweNum]) return categoryMap[cweNum];

  // Fall back to technology/path-based heuristics
  const tech = metadata?.technology || [];
  if (tech.some(t => ['crypto', 'pycryptodome', 'hashlib'].includes(t))) return 'cryptography';
  if (tech.some(t => ['sqlalchemy', 'pymongo', 'sequelize'].includes(t))) return 'injection';

  return metadata?.category || 'security';
}

// ─── CVSS estimation ──────────────────────────────────────────────────────────

interface CvssEstimate {
  score: number;
  vector: string;
}

function estimateCvss(
  severity: SastRule['severity'],
  cweId: string,
  metadata?: SemgrepMetadata,
): CvssEstimate {
  // High-confidence CVSS for well-known CWEs
  const cweCvss: Record<string, CvssEstimate> = {
    'CWE-89':  { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    'CWE-78':  { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    'CWE-94':  { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    'CWE-502': { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    'CWE-79':  { score: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
    'CWE-798': { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    'CWE-327': { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    'CWE-328': { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    'CWE-338': { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    'CWE-918': { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    'CWE-22':  { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    'CWE-611': { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    'CWE-319': { score: 5.9, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    'CWE-352': { score: 8.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H' },
    'CWE-601': { score: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
    'CWE-377': { score: 3.3, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N' },
  };

  if (cweId && cweCvss[cweId]) return cweCvss[cweId];

  // Fallback by severity
  const severityCvss: Record<string, CvssEstimate> = {
    critical: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    high:     { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    medium:   { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    low:      { score: 3.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N' },
    info:     { score: 0.0, vector: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N' },
  };
  return severityCvss[severity] || severityCvss.medium;
}

// ─── Language normalization ───────────────────────────────────────────────────

function normalizeLanguages(langs: string[] | undefined): string[] {
  if (!langs || langs.length === 0) return ['all'];
  const langMap: Record<string, string> = {
    python: 'python',
    py: 'python',
    javascript: 'javascript',
    js: 'javascript',
    typescript: 'typescript',
    ts: 'typescript',
    java: 'java',
    go: 'go',
    golang: 'go',
    ruby: 'ruby',
    rb: 'ruby',
    php: 'php',
    csharp: 'csharp',
    'c#': 'csharp',
    c: 'cpp',
    cpp: 'cpp',
    'c++': 'cpp',
    kotlin: 'kotlin',
    scala: 'java',
    swift: 'swift',
    rust: 'rust',
    bash: 'bash',
    shell: 'bash',
    sh: 'bash',
    yaml: 'yaml',
    json: 'json',
    hcl: 'hcl',
    terraform: 'hcl',
    dockerfile: 'dockerfile',
    generic: 'all',
    regex: 'all',
    none: 'all',
  };
  return langs
    .map(l => langMap[l.toLowerCase()] || l.toLowerCase())
    .filter((v, i, a) => a.indexOf(v) === i); // deduplicate
}

// ─── Pattern conversion ──────────────────────────────────────────────────────

/**
 * Check if a Semgrep pattern string can be converted to a regex.
 * Simple patterns (function calls, string literals, dot chains) can be escaped.
 * Patterns with complex Semgrep-specific syntax ($...ARGS, nested blocks) cannot.
 */
function canConvertPatternToRegex(pattern: string): boolean {
  const trimmed = pattern.trim();
  // Skip multi-line patterns with indentation (code blocks)
  if (trimmed.includes('\n') && trimmed.split('\n').some(l => /^\s{4,}/.test(l))) {
    return false;
  }
  // Skip patterns with $...VARNAME (variadic metavariables)
  if (/\$\.\.\.[A-Z]/.test(trimmed)) return false;
  // Skip patterns with complex nesting indicators
  if (/\.\.\.\s*\n/.test(trimmed)) return false;
  // Simple single-line patterns are usually convertible
  return true;
}

/**
 * Convert a simple Semgrep pattern to a RegExp.
 * - `...` becomes `.*?` (non-greedy wildcard)
 * - `$VAR` becomes `\S+` (any non-whitespace token)
 * - Literal characters are escaped
 */
function convertPatternToRegex(pattern: string): RegExp | null {
  try {
    const trimmed = pattern.trim();
    if (!trimmed) return null;

    // Split on Semgrep metavariables and ellipsis, escape the rest
    let regexStr = '';
    let remaining = trimmed;

    while (remaining.length > 0) {
      // Match $VARNAME (metavariable)
      const metavarMatch = remaining.match(/^(\$[A-Z_][A-Z0-9_]*)/);
      if (metavarMatch) {
        regexStr += '\\S+';
        remaining = remaining.slice(metavarMatch[0].length);
        continue;
      }

      // Match ... (ellipsis - Semgrep wildcard)
      if (remaining.startsWith('...')) {
        regexStr += '.*?';
        remaining = remaining.slice(3);
        continue;
      }

      // Match f"...{...}..." style (Python f-string in Semgrep)
      const fstrMatch = remaining.match(/^f"\.\.\.(\{\.\.\.\})?\.\.\.\s*"/);
      if (fstrMatch) {
        regexStr += 'f"[^"]*"';
        remaining = remaining.slice(fstrMatch[0].length);
        continue;
      }

      // Match "=~/regex/" (Semgrep inline regex in pattern)
      const inlineRegex = remaining.match(/^"=~\/(.*?)\/"/);
      if (inlineRegex) {
        regexStr += `"${inlineRegex[1]}"`;
        remaining = remaining.slice(inlineRegex[0].length);
        continue;
      }

      // Escape and append the next literal character
      const ch = remaining[0];
      if ('.+*?^${}()|[]\\'.includes(ch)) {
        regexStr += '\\' + ch;
      } else {
        regexStr += ch;
      }
      remaining = remaining.slice(1);
    }

    // Allow flexible whitespace
    regexStr = regexStr.replace(/\s+/g, '\\s+');

    return new RegExp(regexStr, 'i');
  } catch {
    return null;
  }
}

/**
 * Try to compile a pattern-regex string into a RegExp, with safety checks.
 */
function compilePatternRegex(regexStr: string): RegExp | null {
  try {
    const trimmed = regexStr.trim();
    if (!trimmed) return null;

    // Basic ReDoS safety: reject patterns with nested quantifiers
    if (/(\.\*|\.\+|\[.+?\])\{.*?\}\{/.test(trimmed)) return null;
    if (/(\+|\*)\+/.test(trimmed)) return null;

    return new RegExp(trimmed, 'i');
  } catch {
    return null;
  }
}

// ─── Recommendation generation ───────────────────────────────────────────────

function generateRecommendation(
  rule: SemgrepRule,
  cweId: string,
): string {
  // Use Semgrep message as base
  const message = rule.message || '';
  const refs = rule.metadata?.references || [];
  const refStr = refs.length > 0
    ? ` See: ${refs.slice(0, 2).join(', ')}`
    : '';

  // CWE-specific recommendations
  const cweRecommendations: Record<string, string> = {
    'CWE-89':  'Use parameterized queries or prepared statements instead of string concatenation for SQL queries.',
    'CWE-78':  'Avoid passing user input to shell commands. Use safe APIs with argument arrays instead of shell strings.',
    'CWE-79':  'Sanitize and encode all user input before rendering in HTML. Use context-appropriate output encoding.',
    'CWE-94':  'Never execute dynamically constructed code from user input. Use safer alternatives like sandboxed environments.',
    'CWE-798': 'Remove hard-coded credentials and use environment variables, secrets managers, or vault services.',
    'CWE-327': 'Replace weak/broken cryptographic algorithms with modern alternatives (AES-256, SHA-256, etc.).',
    'CWE-328': 'Use strong hash functions (SHA-256/SHA-3) instead of weak ones (MD5, SHA-1).',
    'CWE-338': 'Use cryptographically secure random number generators (CSPRNG) instead of weak PRNGs.',
    'CWE-502': 'Avoid deserializing untrusted data. Use safe formats like JSON with strict schemas.',
    'CWE-611': 'Disable external entity processing in XML parsers. Use defused XML libraries.',
    'CWE-918': 'Validate and whitelist URLs before making server-side requests. Block internal/private IP ranges.',
    'CWE-22':  'Validate and sanitize file paths. Use path canonicalization and restrict access to allowed directories.',
    'CWE-319': 'Use TLS/HTTPS for all data transmission. Enforce secure transport protocols.',
    'CWE-352': 'Implement CSRF tokens on all state-changing requests.',
    'CWE-377': 'Use secure temporary file creation APIs that set proper permissions.',
    'CWE-601': 'Validate redirect URLs against a whitelist. Do not redirect to user-supplied URLs.',
  };

  if (cweId && cweRecommendations[cweId]) {
    return `${cweRecommendations[cweId]}${refStr}`;
  }

  // Truncate message if too long, use as recommendation
  const shortened = message.length > 300 ? message.slice(0, 297) + '...' : message;
  return shortened ? `${shortened}${refStr}` : `Review this code for security issues.${refStr}`;
}

// ─── Rule ID generation ──────────────────────────────────────────────────────

const importedIds = new Set<string>();

function generateRuleId(semgrepId: string): string {
  // Convert semgrep ID (e.g., "detect-pseudoRandomBytes") to SAST format
  const sanitized = semgrepId
    .replace(/[^a-zA-Z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .toUpperCase()
    .slice(0, 40);

  let id = `SAST-SG-${sanitized}`;

  // Handle collisions
  let suffix = 0;
  let candidate = id;
  while (importedIds.has(candidate)) {
    suffix++;
    candidate = `${id}-${suffix}`;
  }
  importedIds.add(candidate);
  return candidate;
}

// ─── Advanced feature detection ──────────────────────────────────────────────

interface SkipAnalysis {
  skip: boolean;
  reason?: SkipReason;
}

function shouldSkipRule(rule: SemgrepRule): SkipAnalysis {
  // Skip taint-mode rules (need dataflow analysis)
  if (rule.mode === 'taint') {
    return { skip: true, reason: 'taint-mode' };
  }
  if (rule['pattern-sources'] || rule['pattern-sinks']) {
    return { skip: true, reason: 'taint-mode' };
  }

  // Skip non-security rules
  if (rule.metadata?.category && rule.metadata.category !== 'security') {
    return { skip: true, reason: 'non-security' };
  }

  // Skip generic/regex-only language rules (handled separately)
  const langs = rule.languages || [];
  if (langs.length === 1 && ['regex', 'generic', 'none'].includes(langs[0])) {
    // Unless it has a usable pattern-regex
    if (!rule['pattern-regex']) {
      return { skip: true, reason: 'generic-language' };
    }
  }

  // Check patterns for advanced features we cannot handle
  if (rule.patterns) {
    if (hasAdvancedFeatures(rule.patterns)) {
      return { skip: true, reason: 'metavariable-pattern' };
    }
  }

  return { skip: false };
}

function hasAdvancedFeatures(clauses: SemgrepPatternClause[]): boolean {
  for (const clause of clauses) {
    if (clause['metavariable-pattern']) return true;
    if (clause['metavariable-comparison']) return true;
    if (clause['metavariable-analysis']) return true;

    // Complex pattern-inside with nested patterns is too hard
    if (clause['pattern-inside'] && clause.patterns) return true;

    // Recurse into nested patterns
    if (clause.patterns && hasAdvancedFeatures(clause.patterns)) return true;
    if (clause['pattern-either'] && hasAdvancedFeatures(clause['pattern-either'])) return true;
  }
  return false;
}

// ─── Pattern extraction ──────────────────────────────────────────────────────

/**
 * Extract all convertible patterns from a Semgrep rule as RegExp[].
 * Returns null if no patterns could be converted.
 */
function extractPatterns(rule: SemgrepRule): { patterns: RegExp[]; excludePatterns: RegExp[] } | null {
  const patterns: RegExp[] = [];
  const excludePatterns: RegExp[] = [];

  // Direct pattern-regex
  if (rule['pattern-regex']) {
    const compiled = compilePatternRegex(rule['pattern-regex']);
    if (compiled) patterns.push(compiled);
  }

  // Simple pattern
  if (rule.pattern) {
    if (canConvertPatternToRegex(rule.pattern)) {
      const compiled = convertPatternToRegex(rule.pattern);
      if (compiled) patterns.push(compiled);
    }
  }

  // pattern-either (top-level)
  if (rule['pattern-either']) {
    for (const clause of rule['pattern-either']) {
      extractFromClause(clause, patterns, excludePatterns);
    }
  }

  // patterns (top-level)
  if (rule.patterns) {
    for (const clause of rule.patterns) {
      extractFromClause(clause, patterns, excludePatterns);
    }
  }

  if (patterns.length === 0) return null;
  return { patterns, excludePatterns: excludePatterns.length > 0 ? excludePatterns : [] };
}

function extractFromClause(
  clause: SemgrepPatternClause,
  patterns: RegExp[],
  excludePatterns: RegExp[],
): void {
  // pattern-regex in a clause
  if (clause['pattern-regex']) {
    const compiled = compilePatternRegex(clause['pattern-regex']);
    if (compiled) patterns.push(compiled);
  }

  // Simple pattern in a clause
  if (clause.pattern) {
    if (canConvertPatternToRegex(clause.pattern)) {
      const compiled = convertPatternToRegex(clause.pattern);
      if (compiled) patterns.push(compiled);
    }
  }

  // pattern-not and pattern-not-regex become excludePatterns
  if (clause['pattern-not']) {
    if (canConvertPatternToRegex(clause['pattern-not'])) {
      const compiled = convertPatternToRegex(clause['pattern-not']);
      if (compiled) excludePatterns.push(compiled);
    }
  }
  if (clause['pattern-not-regex']) {
    const compiled = compilePatternRegex(clause['pattern-not-regex']);
    if (compiled) excludePatterns.push(compiled);
  }

  // Recurse into nested pattern-either
  if (clause['pattern-either']) {
    for (const sub of clause['pattern-either']) {
      extractFromClause(sub, patterns, excludePatterns);
    }
  }

  // Recurse into nested patterns array
  if (clause.patterns) {
    for (const sub of clause.patterns) {
      extractFromClause(sub, patterns, excludePatterns);
    }
  }
}

// ─── Single rule conversion ──────────────────────────────────────────────────

function convertRule(rule: SemgrepRule, sourceFile: string): SastRule | null {
  const skipAnalysis = shouldSkipRule(rule);
  if (skipAnalysis.skip) return null;

  const extracted = extractPatterns(rule);
  if (!extracted) return null;

  const severity = refineSeverity(mapSeverity(rule.severity), rule.metadata);
  const cweId = extractCweId(rule.metadata);
  const owaspCategory = extractOwaspCategory(rule.metadata);
  const category = mapCategory(cweId, rule.metadata);
  const cvss = estimateCvss(severity, cweId, rule.metadata);
  const languages = normalizeLanguages(rule.languages);

  return {
    id: generateRuleId(rule.id),
    name: rule.id.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
    description: rule.message || `Security rule imported from Semgrep: ${rule.id}`,
    severity,
    cweId,
    owaspCategory,
    languages,
    patterns: extracted.patterns,
    excludePatterns: extracted.excludePatterns.length > 0 ? extracted.excludePatterns : undefined,
    recommendation: generateRecommendation(rule, cweId),
    cvssScore: cvss.score,
    cvssVector: cvss.vector,
    category,
  };
}

// ─── Directory scanning ──────────────────────────────────────────────────────

/**
 * Recursively find all .yaml and .yml files in a directory.
 */
function findYamlFiles(dir: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // Skip test directories and hidden dirs
      if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
      results.push(...findYamlFiles(fullPath));
    } else if (
      entry.isFile() &&
      (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) &&
      !entry.name.includes('.test.')
    ) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * Check if a YAML file path is likely a security-related rule.
 */
function isSecurityPath(filePath: string): boolean {
  const lowerPath = filePath.toLowerCase();
  const securityIndicators = [
    '/security/',
    '/audit/',
    '/injection/',
    '/xss/',
    '/sqli/',
    '/crypto/',
    '/deserialization/',
    '/ssrf/',
    '/traversal/',
    '/xxe/',
    '/credentials/',
    '/secrets/',
    '/jwt/',
    '/owasp/',
    '/vulnerability/',
  ];
  return securityIndicators.some(indicator => lowerPath.includes(indicator));
}

// ─── Public API ──────────────────────────────────────────────────────────────

export interface SemgrepRuleStats {
  total: number;
  imported: number;
  skipped: number;
  byLanguage: Record<string, number>;
  byCwe: Record<string, number>;
  byCategory: Record<string, number>;
  skipReasons: Record<string, number>;
}

/**
 * Import all convertible Semgrep community rules from a directory.
 *
 * Scans the directory recursively for YAML files in security-related paths,
 * parses each rule, and converts those with pattern-regex or simple pattern
 * fields into the SastRule format used by the deep-vigilance SAST engine.
 *
 * Rules using advanced Semgrep features (taint mode, metavariable-pattern,
 * complex pattern-inside nesting) are skipped.
 *
 * @param rulesDir - Path to the cloned semgrep-rules repository
 * @returns Array of converted SastRule objects
 */
export function importSemgrepRules(rulesDir: string): SastRule[] {
  logger.info({ rulesDir }, 'Starting Semgrep community rules import');

  // Reset ID tracker for clean import
  importedIds.clear();

  const yamlFiles = findYamlFiles(rulesDir);
  const securityFiles = yamlFiles.filter(f => isSecurityPath(f));

  logger.info(
    { totalYaml: yamlFiles.length, securityYaml: securityFiles.length },
    'Found YAML files in rules directory',
  );

  const importedRules: SastRule[] = [];
  const skipReasons: Record<string, number> = {};
  let totalRules = 0;
  let parseErrors = 0;

  for (const filePath of securityFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const parsed = yaml.parse(content) as SemgrepRuleFile | null;

      if (!parsed || !parsed.rules || !Array.isArray(parsed.rules)) {
        skipReasons['no-rules-field'] = (skipReasons['no-rules-field'] || 0) + 1;
        continue;
      }

      for (const rule of parsed.rules) {
        totalRules++;

        // Check for skip conditions
        const skipAnalysis = shouldSkipRule(rule);
        if (skipAnalysis.skip) {
          const reason = skipAnalysis.reason || 'unknown';
          skipReasons[reason] = (skipReasons[reason] || 0) + 1;
          continue;
        }

        const converted = convertRule(rule, filePath);
        if (converted) {
          importedRules.push(converted);
        } else {
          skipReasons['no-convertible-patterns'] =
            (skipReasons['no-convertible-patterns'] || 0) + 1;
        }
      }
    } catch (err) {
      parseErrors++;
      logger.debug({ filePath, error: (err as Error).message }, 'Failed to parse YAML file');
      skipReasons['parse-error'] = (skipReasons['parse-error'] || 0) + 1;
    }
  }

  // Build language stats
  const byLanguage: Record<string, number> = {};
  const byCwe: Record<string, number> = {};
  for (const rule of importedRules) {
    for (const lang of rule.languages) {
      byLanguage[lang] = (byLanguage[lang] || 0) + 1;
    }
    if (rule.cweId) {
      byCwe[rule.cweId] = (byCwe[rule.cweId] || 0) + 1;
    }
  }

  logger.info(
    {
      total: totalRules,
      imported: importedRules.length,
      skipped: totalRules - importedRules.length,
      parseErrors,
      byLanguage,
      skipReasons,
    },
    'Semgrep community rules import complete',
  );

  return importedRules;
}

/**
 * Get statistics about what Semgrep rules can be imported from a directory.
 *
 * @param rulesDir - Path to the cloned semgrep-rules repository
 * @returns Statistics object with counts by language, CWE, category, and skip reasons
 */
export function getSemgrepRuleStats(rulesDir: string): SemgrepRuleStats {
  // Reset ID tracker
  importedIds.clear();

  const yamlFiles = findYamlFiles(rulesDir);
  const securityFiles = yamlFiles.filter(f => isSecurityPath(f));

  let totalRules = 0;
  let importedCount = 0;
  const byLanguage: Record<string, number> = {};
  const byCwe: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  const skipReasons: Record<string, number> = {};

  for (const filePath of securityFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const parsed = yaml.parse(content) as SemgrepRuleFile | null;

      if (!parsed?.rules || !Array.isArray(parsed.rules)) {
        skipReasons['no-rules-field'] = (skipReasons['no-rules-field'] || 0) + 1;
        continue;
      }

      for (const rule of parsed.rules) {
        totalRules++;

        const skipAnalysis = shouldSkipRule(rule);
        if (skipAnalysis.skip) {
          const reason = skipAnalysis.reason || 'unknown';
          skipReasons[reason] = (skipReasons[reason] || 0) + 1;
          continue;
        }

        const converted = convertRule(rule, filePath);
        if (converted) {
          importedCount++;
          for (const lang of converted.languages) {
            byLanguage[lang] = (byLanguage[lang] || 0) + 1;
          }
          if (converted.cweId) {
            byCwe[converted.cweId] = (byCwe[converted.cweId] || 0) + 1;
          }
          byCategory[converted.category] = (byCategory[converted.category] || 0) + 1;
        } else {
          skipReasons['no-convertible-patterns'] =
            (skipReasons['no-convertible-patterns'] || 0) + 1;
        }
      }
    } catch {
      skipReasons['parse-error'] = (skipReasons['parse-error'] || 0) + 1;
    }
  }

  return {
    total: totalRules,
    imported: importedCount,
    skipped: totalRules - importedCount,
    byLanguage,
    byCwe,
    byCategory,
    skipReasons,
  };
}
