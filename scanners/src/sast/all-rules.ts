/**
 * SAST All-Rules Scanner — merges core rules, expanded rule library,
 * framework-specific rules, and Semgrep community rules into a single
 * scan function for inline use.
 */
import { SastRule, SastFinding, isCommentLine } from './engine.js';
import { SAST_RULES as CORE_RULES } from './engine.js';
import { generateRuleLibrary } from './rule-expansion.js';
import { FRAMEWORK_RULES } from './framework-rules.js';
import { SEMGREP_RULES_BUNDLE } from './semgrep-rules-bundle.js';
import { THREAT_PACK_RULES } from './threat-pack-rules.js';
import { IAC_RULES } from './iac-rules.js';
import path from 'path';

const ALL_RULES: SastRule[] = [
...CORE_RULES,
...generateRuleLibrary([]),
...FRAMEWORK_RULES,
...SEMGREP_RULES_BUNDLE,
...THREAT_PACK_RULES,
...IAC_RULES,
];

const SEVERITY_RANK: Record<string, number> = {
  critical: 1, high: 2, medium: 3, low: 4, info: 5,
};

/**
 * Scan a single file with ALL rule sets (core + expanded + framework + semgrep).
 * Returns SastFinding[] compatible with the engine's interface.
 */
export function scanFileWithAllRules(
  filePath: string,
  content: string,
  language: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  const lines = content.split('\n');

  const relevantRules = ALL_RULES.filter(
    (rule) => rule.languages.includes('all') || rule.languages.includes(language),
  );

  for (const rule of relevantRules) {
    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;

      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx]!;
        if (isCommentLine(line, language)) continue;
        pattern.lastIndex = 0;
        const match = pattern.exec(line);

        if (match) {
          // Check exclude patterns
          let excluded = false;
          if (rule.excludePatterns) {
            for (const ep of rule.excludePatterns) {
              ep.lastIndex = 0;
              if (ep.test(line)) {
                excluded = true;
                break;
              }
            }
          }
          if (excluded) continue;

          const contextStart = Math.max(0, lineIdx - 2);
          const contextEnd = Math.min(lines.length, lineIdx + 3);
          const codeSnippet = lines.slice(contextStart, contextEnd).join('\n');

          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            ruleCategory: rule.category,
            title: `${rule.name} in ${path.basename(filePath)}`,
            description: rule.description,
            severity: rule.severity,
            severityRank: SEVERITY_RANK[rule.severity] ?? 3,
            filePath,
            lineNumber: lineIdx + 1,
            lineRange: `${contextStart + 1}-${contextEnd}`,
            codeSnippet: codeSnippet.slice(0, 500),
            cweId: rule.cweId,
            owaspCategory: rule.owaspCategory,
            cvssScore: rule.cvssScore,
            cvssVector: rule.cvssVector,
            recommendation: rule.recommendation,
            references: [
              `https://cwe.mitre.org/data/definitions/${rule.cweId.replace('CWE-', '')}.html`,
            ],
            language,
            match: match[0].slice(0, 100),
          });
        }
      }
    }
  }

  return findings;
}

/** Re-export for convenience */
export { getLanguage } from './engine.js';
