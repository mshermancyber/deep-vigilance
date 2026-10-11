// =====================================================================
// Custom SAST Rule Engine — M5f
// Semgrep-style YAML rule parsing, pattern compilation, rule execution,
// validation, and testing. No mock data, fully functional.
// =====================================================================

import yaml from 'yaml';
import path from 'path';

// =====================================================================
// Types & Interfaces
// =====================================================================

export interface CustomRuleMetadata {
  cwe: string;
  owasp: string;
  cvss: number;
  [key: string]: unknown;
}

/** A single rule as parsed from Semgrep-style YAML. */
export interface CustomRule {
  id: string;
  name: string;
  languages: string[];
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  pattern?: string;
  patternEither?: { pattern: string }[];
  patternRegex?: string;
  metadata: CustomRuleMetadata;
}

/** A rule whose pattern(s) have been compiled to an executable RegExp. */
export interface CompiledCustomRule {
  id: string;
  name: string;
  languages: string[];
  severity: string;
  severityRank: number;
  message: string;
  compiledPattern: RegExp;
  sourcePattern: string;
  patternType: 'pattern' | 'pattern-either' | 'pattern-regex';
  metadata: CustomRuleMetadata;
}

/** A finding produced by running compiled rules against source code. */
export interface CustomFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: string;
  severityRank: number;
  filePath: string;
  lineNumber: number;
  columnNumber: number;
  cweId: string;
  owaspCategory: string;
  cvssScore: number;
  matchedText: string;
  capturedVariables: Record<string, string>;
  language: string;
}

export interface RuleValidation {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface RuleTestResult {
  matches: boolean;
  findings: CustomFinding[];
  errors: string[];
}

export interface ParseResult {
  rules: CustomRule[];
  errors: string[];
}

export interface ScanFilesOptions {
  rules: string | CustomRule[];
  files: Map<string, string>;
  targetLanguages?: string[];
}

// =====================================================================
// Constants
// =====================================================================

const SEVERITY_RANK: Record<string, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  info: 5,
};

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

const VALID_LANGUAGES = new Set([
  'java', 'python', 'javascript', 'typescript', 'csharp', 'go',
  'ruby', 'php', 'rust', 'swift', 'kotlin', 'cpp', 'all',
]);

const EXT_TO_LANGUAGE: Record<string, string> = {
  '.java': 'java',
  '.kt': 'kotlin',
  '.cs': 'csharp',
  '.cpp': 'cpp',
  '.cc': 'cpp',
  '.cxx': 'cpp',
  '.c': 'cpp',
  '.h': 'cpp',
  '.hpp': 'cpp',
  '.go': 'go',
  '.py': 'python',
  '.rb': 'ruby',
  '.php': 'php',
  '.phtml': 'php',
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.jsx': 'javascript',
  '.rs': 'rust',
  '.swift': 'swift',
};

// =====================================================================
// YAML Rule Parser
// =====================================================================

/**
 * Parse a Semgrep-style YAML rule string into CustomRule objects.
 *
 * Expected YAML structure:
 * ```yaml
 * rules:
 *   - id: my-rule
 *     languages: [java, python]
 *     severity: critical
 *     message: "Description of the finding"
 *     pattern: |
 *       $DB.execute("SELECT..." + $INPUT)
 *     metadata:
 *       cwe: CWE-89
 *       owasp: A03:2021
 *       cvss: 9.8
 * ```
 *
 * Supports:
 *   - pattern       — single pattern string
 *   - pattern-either — multiple sub-patterns combined with OR
 *   - pattern-regex — raw regex passed through as-is
 */
export function parseRuleYaml(yamlStr: string): ParseResult {
  const errors: string[] = [];
  const rules: CustomRule[] = [];

  if (typeof yamlStr !== 'string' || yamlStr.trim().length === 0) {
    return { rules: [], errors: ['YAML string is empty'] };
  }

  let parsed: unknown;
  try {
    parsed = yaml.parse(yamlStr);
  } catch (err) {
    return {
      rules: [],
      errors: [`YAML parse error: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  if (!parsed || typeof parsed !== 'object') {
    return { rules: [], errors: ['YAML root must be an object'] };
  }

  const root = parsed as Record<string, unknown>;
  const rulesArray = root.rules;

  if (!Array.isArray(rulesArray)) {
    return { rules: [], errors: ['YAML must contain a "rules" array at the root level'] };
  }

  for (let i = 0; i < rulesArray.length; i++) {
    const rule = rulesArray[i];
    if (!rule || typeof rule !== 'object') {
      errors.push(`Rule at index ${i} must be an object`);
      continue;
    }

    const r = rule as Record<string, unknown>;

    // -- Validate required fields --
    const fieldErrors = validateRequiredFields(r, i);
    if (fieldErrors.length > 0) {
      errors.push(...fieldErrors);
      continue; // skip incomplete rule
    }

    // Normalize languages to lowercase strings
    let languages: string[] = [];
    if (Array.isArray(r.languages)) {
      languages = r.languages.map((l: unknown) => String(l).toLowerCase());
    }

    const severityRaw = String(r.severity).toLowerCase();

    // Build metadata
    const metaIn = (r.metadata as Record<string, unknown>) || {};
    const metadata: CustomRuleMetadata = {
      cwe: metaIn.cwe ? String(metaIn.cwe) : '',
      owasp: metaIn.owasp ? String(metaIn.owasp) : '',
      cvss: typeof metaIn.cvss === 'number' ? metaIn.cvss : Number(metaIn.cvss) || 0,
    };
    // Carry through any additional metadata keys
    for (const [k, v] of Object.entries(metaIn)) {
      if (!['cwe', 'owasp', 'cvss'].includes(k)) {
        metadata[k] = v;
      }
    }

    // patternEither can appear under either key name (snake_case or camelCase)
    const patternEitherArr = (r['pattern-either'] as { pattern: string }[] | undefined)
                         ?? (r.patternEither as { pattern: string }[] | undefined);

    const customRule: CustomRule = {
      id: String(r.id),
      name: r.name ? String(r.name) : String(r.id),
      languages,
      severity: severityRaw as CustomRule['severity'],
      message: String(r.message),
      pattern: typeof r.pattern === 'string' ? r.pattern : undefined,
      patternEither: patternEitherArr,
      patternRegex: typeof r['pattern-regex'] === 'string'
        ? r['pattern-regex']
        : typeof r.patternRegex === 'string'
          ? r.patternRegex
          : undefined,
      metadata,
    };

    rules.push(customRule);
  }

  return { rules, errors };
}

/** Validate required fields on a single raw YAML rule object. */
function validateRequiredFields(rule: Record<string, unknown>, index: number): string[] {
  const errs: string[] = [];
  const label = (rule.id ? `"${rule.id}"` : `at index ${index}`);

  if (!rule.id || typeof rule.id !== 'string' || rule.id.trim().length === 0) {
    errs.push(`Rule ${label}: missing or invalid "id" (required non-empty string)`);
  }

  if (!Array.isArray(rule.languages) || rule.languages.length === 0) {
    errs.push(`Rule ${label}: missing or invalid "languages" (required non-empty array)`);
  }

  if (!rule.severity || typeof rule.severity !== 'string' || !VALID_SEVERITIES.has(rule.severity.toLowerCase())) {
    errs.push(`Rule ${label}: missing or invalid "severity" (must be one of: ${[...VALID_SEVERITIES].join(', ')})`);
  }

  if (!rule.message || typeof rule.message !== 'string') {
    errs.push(`Rule ${label}: missing or invalid "message" (required string)`);
  }

  // Must have exactly one pattern type
  const hasPattern = typeof rule.pattern === 'string' && rule.pattern.length > 0;
  const hasPatternEither = Array.isArray(rule['pattern-either'] ?? rule.patternEither);
  const hasPatternRegex = typeof rule['pattern-regex'] === 'string'
                       || typeof rule.patternRegex === 'string';

  if (!hasPattern && !hasPatternEither && !hasPatternRegex) {
    errs.push(`Rule ${label}: must have one of: pattern, pattern-either, pattern-regex`);
  }

  return errs;
}

// =====================================================================
// Pattern Compiler
// =====================================================================

/**
 * Build a safe JS-identifier-compatible capture-group name from a
 * Semgrep variable name, deduplicating against already-used names.
 *
 * The optional `prefix` is used by pattern-either alternatives so each
 * branch gets globally unique capture-group names.
 */
function safeName(
  baseName: string,
  usedNames: Set<string>,
  prefix: string = '',
): string {
  // Ensure it can be a valid JS identifier
  let name = String(baseName).replace(/[^a-zA-Z0-9_$]/g, '_');
  if (name.length === 0 || name === '_') name = 'v';
  if (/^\d/.test(name)) name = `_${name}`;

  const fullName = prefix + name;

  if (!usedNames.has(fullName)) {
    usedNames.add(fullName);
    return fullName;
  }

  let counter = 2;
  while (usedNames.has(`${fullName}_${counter}`)) counter++;
  usedNames.add(`${fullName}_${counter}`);
  return `${fullName}_${counter}`;
}

/**
 * Recursively compile a Semgrep-like pattern string into a regex source
 * string, tracking used capture-group names.
 *
 * Token handling:
 *   $FOO         - (?<FOO>\w+)                   (identifier placeholder)
 *   $FOO(...)    - (?<FOO>\w+)\s*\(<args>\)      (function call)
 *   ...          - .*?                            (ellipsis / any chars lazy)
 *   whitespace   - \s*                            (flexible whitespace)
 *   regex chars  - escaped                        (literal matching)
 */
function compilePatternInner(
  pattern: string,
  usedNames: Set<string>,
  namePrefix: string = '',
): string {
  let result = '';
  let i = 0;

  while (i < pattern.length) {
    // ---- $FUNC(...) — function call with arguments ----
    // Must be checked before plain $VAR so the entire call is consumed
    // as a single unit.
    const funcMatch = pattern.slice(i).match(/^\$(\w+)\s*\(/);
    if (funcMatch) {
      const varName = funcMatch[1];
      const groupName = safeName(varName, usedNames, namePrefix);
      result += `(?<${groupName}>\\w+)\\s*\\(`;
      i += funcMatch[0].length; // advance past $FUNC(

      // Find the matching closing paren (handles nesting)
      let depth = 1;
      const argsStart = i;
      while (i < pattern.length && depth > 0) {
        if (pattern[i] === '(') depth++;
        else if (pattern[i] === ')') depth--;
        i++;
      }

      if (depth !== 0) {
        throw new Error(
          `Unmatched opening parenthesis in pattern at position ${argsStart}`,
        );
      }

      // Recursively compile the content between the parens
      const argsContent = pattern.slice(argsStart, i - 1);
      result += compilePatternInner(argsContent, usedNames, namePrefix);
      result += '\\)';
      continue;
    }

    // ---- $VAR — simple identifier placeholder ----
    const varMatch = pattern.slice(i).match(/^\$(\w+)/);
    if (varMatch) {
      const groupName = safeName(varMatch[1], usedNames, namePrefix);
      result += `(?<${groupName}>\\w+)`;
      i += varMatch[0].length;
      continue;
    }

    // ---- ... — ellipsis (lazy match any characters) ----
    if (
      i + 2 < pattern.length &&
      pattern[i] === '.' &&
      pattern[i + 1] === '.' &&
      pattern[i + 2] === '.'
    ) {
      result += '.*?';
      i += 3;
      continue;
    }

    // ---- Whitespace — flexible matching ----
    if (/\s/.test(pattern[i])) {
      result += '\\s*';
      while (i < pattern.length && /\s/.test(pattern[i])) i++;
      continue;
    }

    // ---- Standalone $ (not part of $VAR / $FUNC) ----
    if (pattern[i] === '$') {
      result += '\\$';
      i++;
      continue;
    }

    // ---- Literal character — escape regex metacharacters ----
    const ch = pattern[i];
    if (/[.*+?^${}()|[\]\\]/.test(ch)) {
      result += '\\' + ch;
    } else {
      result += ch;
    }
    i++;
  }

  return result;
}

/**
 * Compile a single Semgrep-like pattern string into a regular expression.
 * The returned regex uses the `m` (multiline) and `s` (dotAll) flags so
 * that `^`/`$` work per-line and `.` matches newline characters.
 *
 * @example
 * compilePattern('$DB.execute("SELECT..." + $INPUT)')
 * // => /(?<DB>\w+)\.execute\("SELECT.*?"\s*\+\s*(?<INPUT>\w+)\)/ms
 */
export function compilePattern(semgrepPattern: string): RegExp {
  const usedNames = new Set<string>();
  const regexStr = compilePatternInner(semgrepPattern, usedNames);
  return new RegExp(regexStr, 'ms');
}

/**
 * Compile a pattern-either array into a single alternation regex.
 * Each alternative gets a unique capture-group prefix so that JS does
 * not reject duplicate named groups across branches.
 */
function compilePatternEither(subPatterns: { pattern: string }[]): RegExp {
  const parts: string[] = [];

  for (let altIdx = 0; altIdx < subPatterns.length; altIdx++) {
    const sp = subPatterns[altIdx];
    if (!sp || typeof sp.pattern !== 'string' || sp.pattern.length === 0) continue;

    const usedNames = new Set<string>();
    // Per-alternative prefix keeps capture group names globally unique
    const prefix = `a${altIdx}_`;
    const regexStr = compilePatternInner(sp.pattern, usedNames, prefix);
    parts.push(`(?:${regexStr})`);
  }

  if (parts.length === 0) {
    throw new Error('pattern-either must contain at least one sub-pattern');
  }

  return new RegExp(parts.join('|'), 'ms');
}

// =====================================================================
// Rule Compilation
// =====================================================================

/**
 * Compile a single parsed CustomRule into an executable CompiledCustomRule.
 */
/**
 * Reject user-supplied regexes that are prone to catastrophic backtracking
 * (ReDoS). JS has no native regex timeout, so a malicious `pattern-regex` like
 * `(a+)+$` run against attacker-controlled file content can hang the scan
 * worker indefinitely. This blocks the classic dangerous shapes at compile time.
 */
const MAX_REGEX_SOURCE_LEN = 1000;
export function assertSafeRegex(source: string): void {
  if (source.length > MAX_REGEX_SOURCE_LEN) {
    throw new Error(`Regex too long (${source.length} > ${MAX_REGEX_SOURCE_LEN} chars)`);
  }
  // Nested quantifier inside a group that is itself quantified: (x+)+ (x*)* (.*)+ (\d+){2,}
  if (/\([^()]*[+*][^()]*\)\s*[*+{]/.test(source)) {
    throw new Error('Regex contains a nested quantifier prone to catastrophic backtracking');
  }
  if (/\([^()]*\{\d+,\d*\}[^()]*\)\s*[*+{]/.test(source)) {
    throw new Error('Regex contains a nested bounded quantifier prone to catastrophic backtracking');
  }
  // Quantified group followed by another quantifier: (...)+* (...)*+ (...){n,}+
  if (/\)[*+]\s*[*+]/.test(source)) {
    throw new Error('Regex contains stacked quantifiers prone to catastrophic backtracking');
  }
}

export function compileRule(rule: CustomRule): CompiledCustomRule {
  let compiledPattern: RegExp;
  let sourcePattern: string;
  let patternType: 'pattern' | 'pattern-either' | 'pattern-regex';

  if (rule.patternRegex) {
    assertSafeRegex(rule.patternRegex);
    compiledPattern = new RegExp(rule.patternRegex, 'ms');
    sourcePattern = rule.patternRegex;
    patternType = 'pattern-regex';
  } else if (rule.patternEither && rule.patternEither.length > 0) {
    compiledPattern = compilePatternEither(rule.patternEither);
    sourcePattern = rule.patternEither.map((p) => p.pattern).join(' | ');
    patternType = 'pattern-either';
  } else if (rule.pattern) {
    compiledPattern = compilePattern(rule.pattern);
    sourcePattern = rule.pattern;
    patternType = 'pattern';
  } else {
    throw new Error(
      `Rule "${rule.id}" has no pattern, pattern-either, or pattern-regex`,
    );
  }

  return {
    id: rule.id,
    name: rule.name || rule.id,
    languages: rule.languages,
    severity: rule.severity,
    severityRank: SEVERITY_RANK[rule.severity] ?? 3,
    message: rule.message,
    compiledPattern,
    sourcePattern,
    patternType,
    metadata: { ...rule.metadata },
  };
}

/**
 * Compile an array of parsed CustomRules.
 */
export function compileRules(rules: CustomRule[]): CompiledCustomRule[] {
  return rules.map((r) => compileRule(r));
}

// =====================================================================
// Helper: strip compiler-injected name decorations to recover the
// original Semgrep variable name.
// =====================================================================

const ALT_PREFIX_RE = /^a\d+_/;
const DEDUP_SUFFIX_RE = /_\d+$/;

function normalizeVarName(name: string): string {
  return name.replace(ALT_PREFIX_RE, '').replace(DEDUP_SUFFIX_RE, '');
}

// =====================================================================
// Rule Execution
// =====================================================================

/**
 * Execute a single compiled rule against source code, returning all
 * findings for every match.
 *
 * Matching is done against the full file content (not line-by-line) so
 * that multi-line patterns with `...` ellipsis work correctly. Line and
 * column numbers are derived from the match index.
 */
export function executeRule(
  compiledRule: CompiledCustomRule,
  sourceCode: string,
  filePath: string,
  language: string,
): CustomFinding[] {
  const findings: CustomFinding[] = [];

  // Skip if rule does not apply to this language
  if (
    !compiledRule.languages.includes('all') &&
    !compiledRule.languages.includes(language)
  ) {
    return findings;
  }

  // Construct a global regex so exec() properly advances between matches.
  // The base regex from compileRule does not have the 'g' flag, because
  // the 'g' flag would interfere with external uses of .test() / .match().
  const regex = new RegExp(compiledRule.compiledPattern.source, 'gms');
  regex.lastIndex = 0;

  let match: RegExpExecArray | null;
  while ((match = regex.exec(sourceCode)) !== null) {
    if (match.index === undefined) continue;

    // 1-based line number
    const lineNumber = sourceCode.slice(0, match.index).split('\n').length;

    // 1-based column number
    const lastNl = sourceCode.lastIndexOf('\n', match.index);
    const columnNumber = match.index - lastNl;

    // Extract captured variables, normalising compiler-injected
    // prefixes (a0_, a1_, ...) and dedup suffixes (_2, _3, ...)
    const capturedVariables: Record<string, string> = {};
    if (match.groups) {
      for (const [rawName, value] of Object.entries(match.groups)) {
        if (value !== undefined) {
          const clean = normalizeVarName(rawName);
          capturedVariables[clean] = value;
        }
      }
    }

    findings.push({
      ruleId: compiledRule.id,
      title: compiledRule.message,
      description: compiledRule.message,
      severity: compiledRule.severity,
      severityRank: compiledRule.severityRank,
      filePath,
      lineNumber,
      columnNumber,
      cweId: compiledRule.metadata.cwe || '',
      owaspCategory: compiledRule.metadata.owasp || '',
      cvssScore: compiledRule.metadata.cvss || 0,
      matchedText: match[0],
      capturedVariables,
      language,
    });

    // Prevent infinite loop on zero-length matches
    if (match[0].length === 0) {
      regex.lastIndex++;
    }
  }

  return findings;
}

/**
 * Execute multiple compiled rules against source code, returning all
 * findings sorted by severity (most severe first) then line number.
 *
 * Only rules whose `languages` array includes `language` or `"all"`
 * are applied.
 */
export function executeRules(
  compiledRules: CompiledCustomRule[],
  sourceCode: string,
  filePath: string,
  language: string,
): CustomFinding[] {
  const allFindings: CustomFinding[] = [];

  for (const rule of compiledRules) {
    const applicable =
      rule.languages.includes('all') || rule.languages.includes(language);
    if (!applicable) continue;

    const findings = executeRule(rule, sourceCode, filePath, language);
    allFindings.push(...findings);
  }

  // Sort: most severe first, then by line number
  allFindings.sort((a, b) => {
    if (a.severityRank !== b.severityRank) return a.severityRank - b.severityRank;
    return a.lineNumber - b.lineNumber;
  });

  return allFindings;
}

// =====================================================================
// Rule Validation
// =====================================================================

/**
 * Fully validate a Semgrep-style YAML rule string.
 *
 * Checks performed:
 *   1. YAML parses correctly
 *   2. Required fields exist (id, languages, severity, message, one pattern type)
 *   3. Each pattern compiles without error
 *   4. No duplicate rule IDs
 *   5. Language values are known
 */
export function validateRule(ruleYaml: string): RuleValidation {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Step 1 — Parse
  const { rules, errors: parseErrors } = parseRuleYaml(ruleYaml);
  errors.push(...parseErrors);

  if (rules.length === 0 && errors.length === 0) {
    errors.push('No rules were found in the YAML document');
    return { valid: false, errors, warnings };
  }

  // Step 2 — Compile each rule's pattern(s)
  for (const rule of rules) {
    try {
      if (rule.pattern) {
        const re = compilePattern(rule.pattern);
        if (re.source === '(?:)' || re.source === '.*?') {
          warnings.push(
            `Rule "${rule.id}": compiled pattern is trivially matching`,
          );
        }
      }

      if (rule.patternEither) {
        for (let si = 0; si < rule.patternEither.length; si++) {
          try {
            compilePattern(rule.patternEither[si].pattern);
          } catch (spErr) {
            errors.push(
              `Rule "${rule.id}": pattern-either[${si}] compilation error: ${
                spErr instanceof Error ? spErr.message : String(spErr)
              }`,
            );
          }
        }
      }

      if (rule.patternRegex) {
        try {
          new RegExp(rule.patternRegex, 'ms');
        } catch (reErr) {
          errors.push(
            `Rule "${rule.id}": pattern-regex compilation error: ${
              reErr instanceof Error ? reErr.message : String(reErr)
            }`,
          );
        }
      }

      // Warn about unknown languages
      for (const lang of rule.languages) {
        if (!VALID_LANGUAGES.has(lang) && lang !== 'all') {
          warnings.push(`Rule "${rule.id}": unknown language "${lang}"`);
        }
      }
    } catch (err) {
      errors.push(
        `Rule "${rule.id}": compilation error: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }

  // Step 3 — Check for duplicate rule IDs
  const seen = new Set<string>();
  for (const rule of rules) {
    if (seen.has(rule.id)) {
      warnings.push(`Duplicate rule ID: "${rule.id}"`);
    }
    seen.add(rule.id);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

// =====================================================================
// Rule Testing
// =====================================================================

/**
 * Test a Semgrep-style YAML rule string against sample source code.
 *
 * Parses the first rule from the YAML, compiles it, runs it against
 * the provided test code, and returns whether any matches were found
 * together with the full set of findings.
 */
export function testRule(ruleYaml: string, testCode: string): RuleTestResult {
  const errors: string[] = [];
  const findings: CustomFinding[] = [];

  const { rules, errors: parseErrors } = parseRuleYaml(ruleYaml);
  errors.push(...parseErrors);

  if (rules.length === 0) {
    return {
      matches: false,
      findings: [],
      errors: errors.length > 0 ? errors : ['No rules could be parsed from the YAML'],
    };
  }

  // Test the first rule
  const rule = rules[0];
  try {
    const compiled = compileRule(rule);
    const testLang = rule.languages[0] || 'all';
    const ruleFindings = executeRule(compiled, testCode, '(test)', testLang);
    findings.push(...ruleFindings);
  } catch (err) {
    errors.push(
      `Rule execution error: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return {
    matches: findings.length > 0,
    findings,
    errors,
  };
}

// =====================================================================
// Convenience: Bulk file scan with custom rules
// =====================================================================

/**
 * Determine the language for a file from its extension.
 * Returns `null` if the extension is not recognised.
 */
export function getLanguageFromExt(ext: string): string | null {
  return EXT_TO_LANGUAGE[ext.toLowerCase()] ?? null;
}

/**
 * Scan a collection of files with a set of custom rules (provided either
 * as a YAML string or as pre-parsed CustomRule objects).
 *
 * Throws if the YAML rules string fails to parse.
 */
export function scanWithCustomRules(options: ScanFilesOptions): CustomFinding[] {
  let rules: CustomRule[];

  if (typeof options.rules === 'string') {
    const result = parseRuleYaml(options.rules);
    if (result.errors.length > 0) {
      throw new Error(
        `Failed to parse custom rules:\n  ${result.errors.join('\n  ')}`,
      );
    }
    rules = result.rules;
  } else {
    rules = options.rules;
  }

  if (rules.length === 0) return [];

  const compiledRules = compileRules(rules);
  const allFindings: CustomFinding[] = [];

  for (const [filePath, sourceCode] of options.files) {
    const ext = path.extname(filePath);
    const language = getLanguageFromExt(ext) || 'all';

    if (
      options.targetLanguages &&
      !options.targetLanguages.includes(language)
    ) {
      continue;
    }

    const fileFindings = executeRules(compiledRules, sourceCode, filePath, language);
    allFindings.push(...fileFindings);
  }

  // Global severity + line sort
  allFindings.sort((a, b) => {
    if (a.severityRank !== b.severityRank) return a.severityRank - b.severityRank;
    return a.lineNumber - b.lineNumber;
  });

  return allFindings;
}
