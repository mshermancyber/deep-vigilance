// AI Analysis Service — OpenAI-compatible chat-completions client.
//
// Defaults to the OpenAI (ChatGPT) API. Configuration is read from the
// environment, i.e. from the project's .env file:
//
//   OPENAI_API_KEY   your OpenAI secret key (sk-...). Required to enable the LLM.
//   OPENAI_API_URL   API base, default https://api.openai.com/v1
//   OPENAI_MODEL     chat model, default gpt-4o-mini
//
// The generic AI_API_KEY / AI_API_URL / AI_MODEL names are also accepted, so any
// other OpenAI-compatible endpoint (Azure OpenAI, a local llama.cpp/Ollama
// gateway, vLLM, ...) works by pointing AI_API_URL at it.
//
// With no key configured the service degrades gracefully to the local heuristic
// engine below — every endpoint keeps working, just without LLM reasoning.
import { logger } from '../../core/logging/logger.js';
import { query } from '../../core/db/pool.js';
import { decrypt } from '../../core/encryption/cipher.js';

// ============================================================================
// Types
// ============================================================================

export interface AIAnalysisResult {
  falsePositiveProbability: number;
  confidence: number;
  reasoning: string;
  rootCause: string;
  exploitability: string;
  suggestedFix: string;
  provider: string;
}

export interface AIBatchResult {
  totalReviewed: number;
  likelyFalsePositives: number;
  likelyTruePositives: number;
  uncertain: number;
  findings: Array<{
    findingId: string;
    title: string;
    severity: string;
    fpProbability: number;
    reasoning: string;
  }>;
  provider: string;
}

export interface AISearchResult {
  query: string;
  parsedFilters: Record<string, unknown>;
  results: Array<Record<string, unknown>>;
  totalCount: number;
  provider: string;
}

export interface AIStatusResult {
  provider: string;
  model: string;
  available: boolean;
  capabilities: string[];
}

interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface ChatCompletion {
  choices: Array<{ message: { content: string } }>;
}

// ============================================================================
// Provider Configuration
//
// Precedence: .env  →  encrypted platform_settings rows (optional in-app
// override set from Settings → AI). .env is the documented path; the DB rows
// exist only so an operator can swap keys from the UI without a redeploy.
// ============================================================================

/** OpenAI's public API base. Overridden by OPENAI_API_URL / AI_API_URL. */
const DEFAULT_API_URL = 'https://api.openai.com/v1';
/** Default ChatGPT model — cheap, fast, and strong enough for triage. */
const DEFAULT_MODEL = 'gpt-4o-mini';

interface AIConfig { url: string; key: string; model: string }

let _aiConfig: AIConfig | null = null;
let _configLoaded = false;

/** Read provider config from the environment (.env). */
function envConfig(): AIConfig {
  return {
    url: (process.env.OPENAI_API_URL || process.env.AI_API_URL || DEFAULT_API_URL).trim(),
    key: (process.env.OPENAI_API_KEY || process.env.AI_API_KEY || '').trim(),
    model: (process.env.OPENAI_MODEL || process.env.AI_MODEL || DEFAULT_MODEL).trim(),
  };
}

/** Optional in-app override from the encrypted platform_settings table. */
async function dbOverride(): Promise<Partial<AIConfig>> {
  try {
    const result = await query(
      `SELECT key, value, type FROM platform_settings WHERE key LIKE 'ai.%' LIMIT 10`,
    );
    const settings: Record<string, string> = {};
    for (const row of result.rows as Array<Record<string, unknown>>) {
      const val = typeof row.value === 'string' ? row.value : JSON.stringify(row.value);
      const clean = val.replace(/^"|"$/g, '');
      if (row.type === 'encrypted') {
        try { settings[row.key as string] = decrypt(clean); }
        catch { settings[row.key as string] = ''; }
      } else {
        settings[row.key as string] = clean;
      }
    }
    const out: Partial<AIConfig> = {};
    if (settings['ai.api_key']) out.key = settings['ai.api_key'];
    if (settings['ai.api_url']) out.url = settings['ai.api_url'];
    if (settings['ai.model']) out.model = settings['ai.model'];
    return out;
  } catch (err) {
    logger.debug({ err }, 'No AI override in platform_settings; using .env configuration');
    return {};
  }
}

async function loadAIConfig(): Promise<AIConfig> {
  if (_configLoaded && _aiConfig) return _aiConfig;

  const env = envConfig();
  const override = await dbOverride();
  _aiConfig = { ...env, ...override };
  _configLoaded = true;

  if (_aiConfig.key) {
    logger.info(
      { model: _aiConfig.model, url: _aiConfig.url, source: override.key ? 'platform_settings' : 'env' },
      'AI provider configured',
    );
  } else {
    logger.info('No OPENAI_API_KEY set — AI endpoints will use the local heuristic engine');
  }
  return _aiConfig;
}

/** Drop the cached config so the next call re-reads env/DB (used after settings writes). */
export function resetAIConfigCache(): void {
  _aiConfig = null;
  _configLoaded = false;
}

function isLLMConfigured(): boolean {
  return !!(_aiConfig && _aiConfig.url && _aiConfig.key);
}

async function isLLMAvailableAsync(): Promise<boolean> {
  await loadAIConfig();
  return isLLMConfigured();
}

// ============================================================================
// OpenAI-Compatible API Client (OpenAI/ChatGPT by default; any OpenAI-format
// endpoint works by overriding OPENAI_API_URL)
// ============================================================================

async function chatCompletion(messages: ChatMessage[], maxTokens = 2000): Promise<string> {
  const cfg = await loadAIConfig();
  if (!cfg.url || !cfg.key) throw new Error('AI provider not configured (set OPENAI_API_KEY in .env)');

  const baseUrl = cfg.url.replace(/\/+$/, '');
  const url = `${baseUrl}/chat/completions`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${cfg.key}`,
    },
    body: JSON.stringify({
      model: cfg.model,
      messages,
      max_tokens: maxTokens,
      temperature: 0.1,
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`AI API error ${res.status}: ${errText.slice(0, 500)}`);
  }

  const data = await res.json() as ChatCompletion;
  return data.choices?.[0]?.message?.content || '';
}

// ============================================================================
// System Prompts
// ============================================================================

const SECURITY_ANALYSIS_PROMPT = `You are an expert application security analyst. Analyze security findings and determine if they are true positives or false positives.

For each finding, provide:
1. False positive probability (0.0 to 1.0)
2. Confidence in your assessment (0.0 to 1.0)
3. Brief reasoning (1-2 sentences)
4. Root cause analysis (1 sentence)
5. Exploitability assessment (1 sentence)
6. Suggested fix (1-2 sentences)

Respond in JSON format:
{"fpProbability": 0.0, "confidence": 0.85, "reasoning": "...", "rootCause": "...", "exploitability": "...", "suggestedFix": "..."}`;

const NL_SEARCH_PROMPT = `You are a security finding search assistant. Parse natural language queries into structured search filters.

Available filter fields:
- severity: critical, high, medium, low, info
- type: sast, dast, sca, api, code-review
- cweId: CWE-XX format
- filePath: file path pattern (use % for wildcard)
- status: open, in_progress, resolved, closed, false_positive
- dateAfter: ISO date string
- dateBefore: ISO date string
- title: text search pattern

Respond ONLY with a JSON object of filters. Example:
Query: "critical sql injection findings from last month"
Response: {"severity": "critical", "cweId": "CWE-89", "dateAfter": "2026-05-19"}`;

// ============================================================================
// Local Heuristic Fallback
// ============================================================================

const CWE_FP_PATTERNS: Record<string, { baseFpRate: number; testFileMultiplier: number; vendorMultiplier: number }> = {
  'CWE-79': { baseFpRate: 0.3, testFileMultiplier: 2.5, vendorMultiplier: 3.0 },
  'CWE-89': { baseFpRate: 0.2, testFileMultiplier: 2.0, vendorMultiplier: 2.5 },
  'CWE-78': { baseFpRate: 0.25, testFileMultiplier: 2.0, vendorMultiplier: 3.0 },
  'CWE-22': { baseFpRate: 0.35, testFileMultiplier: 2.0, vendorMultiplier: 2.5 },
  'CWE-327': { baseFpRate: 0.5, testFileMultiplier: 3.0, vendorMultiplier: 3.0 },
  'CWE-798': { baseFpRate: 0.4, testFileMultiplier: 3.0, vendorMultiplier: 2.0 },
  'CWE-502': { baseFpRate: 0.3, testFileMultiplier: 2.0, vendorMultiplier: 3.0 },
};

const TEST_PATH_RE = /(?:test|spec|__test__|__spec__|fixture|mock|fake|stub|e2e|cypress|playwright)\b/i;
const VENDOR_PATH_RE = /(?:node_modules|vendor|third.?party|external|dist|build|compiled|generated)\b/i;

function localAnalyzeFinding(finding: Record<string, unknown>): AIAnalysisResult {
  const filePath = (finding.filePath as string) || '';
  const cweId = (finding.cweId as string) || '';
  const severity = (finding.severity as string) || 'medium';
  const confidence_score = finding.confidenceScore as number || 0.5;

  let fpProb = 0.3;
  const patterns = CWE_FP_PATTERNS[cweId];
  if (patterns) fpProb = patterns.baseFpRate;

  if (TEST_PATH_RE.test(filePath)) fpProb = Math.min(fpProb * (patterns?.testFileMultiplier || 2.0), 0.95);
  if (VENDOR_PATH_RE.test(filePath)) fpProb = Math.min(fpProb * (patterns?.vendorMultiplier || 2.5), 0.95);
  if (filePath.endsWith('.d.ts') || filePath.includes('.generated.')) fpProb = 0.9;

  if (severity === 'critical') fpProb *= 0.6;
  if (severity === 'info') fpProb = Math.min(fpProb * 1.5, 0.95);

  if (confidence_score > 0.8) fpProb *= 0.5;
  if (confidence_score < 0.3) fpProb = Math.min(fpProb * 1.8, 0.95);

  const severityExploit: Record<string, string> = {
    critical: 'Likely exploitable with significant impact',
    high: 'Potentially exploitable with moderate effort',
    medium: 'Exploitable under specific conditions',
    low: 'Low exploitability, limited impact',
    info: 'Informational, not directly exploitable',
  };

  return {
    falsePositiveProbability: Math.round(fpProb * 100) / 100,
    confidence: 0.6,
    reasoning: fpProb > 0.7
      ? `Likely false positive: ${TEST_PATH_RE.test(filePath) ? 'test file' : VENDOR_PATH_RE.test(filePath) ? 'vendor code' : 'low-confidence pattern'}`
      : fpProb < 0.3
      ? `Likely true positive: ${severity} severity ${cweId || 'finding'} in production code`
      : `Uncertain: requires manual review of ${cweId || 'this finding'}`,
    rootCause: cweId ? `Potential ${cweId} vulnerability in application code` : 'Security finding detected by scanner rules',
    exploitability: severityExploit[severity] || 'Unknown exploitability',
    suggestedFix: finding.recommendation as string || 'Review and apply appropriate security controls',
    provider: 'local',
  };
}

function localParseSearchQuery(q: string): Record<string, unknown> {
  const filters: Record<string, unknown> = {};
  const lower = q.toLowerCase();

  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  for (const s of severities) {
    if (lower.includes(s)) { filters.severity = s; break; }
  }

  const typeMap: Record<string, string> = {
    'sql injection': 'CWE-89', 'sqli': 'CWE-89', 'xss': 'CWE-79', 'cross-site': 'CWE-79',
    'command injection': 'CWE-78', 'cmdi': 'CWE-78', 'path traversal': 'CWE-22',
    'deserialization': 'CWE-502', 'ssrf': 'CWE-918', 'hardcoded': 'CWE-798', 'secret': 'CWE-798',
  };
  for (const [keyword, cwe] of Object.entries(typeMap)) {
    if (lower.includes(keyword)) { filters.cweId = cwe; break; }
  }

  const scanTypes: Record<string, string> = { sast: 'sast', dast: 'dast', sca: 'sca', 'code review': 'code-review', 'api': 'api' };
  for (const [keyword, type] of Object.entries(scanTypes)) {
    if (lower.includes(keyword)) { filters.type = type; break; }
  }

  const timePatterns: Array<[RegExp, number]> = [
    [/last\s+week/i, 7], [/last\s+month/i, 30], [/last\s+(\d+)\s+days?/i, 0],
    [/yesterday/i, 1], [/today/i, 0],
  ];
  for (const [re, days] of timePatterns) {
    const m = lower.match(re);
    if (m) {
      const d = days === 0 && m[1] ? parseInt(m[1]) : days;
      const date = new Date();
      date.setDate(date.getDate() - d);
      filters.dateAfter = date.toISOString().slice(0, 10);
      break;
    }
  }

  if (!filters.severity && !filters.cweId && !filters.type && !filters.dateAfter) {
    filters.title = `%${q}%`;
  }

  return filters;
}

// ============================================================================
// Public API
// ============================================================================

export async function analyzeFinding(finding: Record<string, unknown>): Promise<AIAnalysisResult> {
  if (!(await isLLMAvailableAsync())) return localAnalyzeFinding(finding);

  try {
    const context = [
      `Title: ${finding.title}`,
      `Severity: ${finding.severity}`,
      `CWE: ${finding.cweId || 'N/A'}`,
      `File: ${finding.filePath || 'N/A'}`,
      `Line: ${finding.lineNumber || 'N/A'}`,
      finding.codeSnippet ? `Code:\n${(finding.codeSnippet as string).slice(0, 500)}` : '',
      `Description: ${(finding.description as string || '').slice(0, 300)}`,
    ].filter(Boolean).join('\n');

    const response = await chatCompletion([
      { role: 'system', content: SECURITY_ANALYSIS_PROMPT },
      { role: 'user', content: `Analyze this security finding:\n\n${context}` },
    ]);

    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      return {
        falsePositiveProbability: parsed.fpProbability ?? 0.5,
        confidence: parsed.confidence ?? 0.5,
        reasoning: parsed.reasoning || 'AI analysis complete',
        rootCause: parsed.rootCause || 'See reasoning',
        exploitability: parsed.exploitability || 'Unknown',
        suggestedFix: parsed.suggestedFix || finding.recommendation as string || 'Review finding',
        provider: `llm:${_aiConfig?.model}`,
      };
    }

    return { ...localAnalyzeFinding(finding), provider: `llm:${_aiConfig?.model}:parse-fallback` };
  } catch (err) {
    logger.warn({ err }, 'AI analysis failed, using local heuristics');
    return localAnalyzeFinding(finding);
  }
}

export async function batchReviewFindings(
  findingIds: string[], orgId: string, source: 'findings' | 'code_review' = 'findings',
): Promise<AIBatchResult> {
  const sql = source === 'code_review'
    ? `SELECT id, title, severity, category AS type, rule_id AS "cweId", file_path AS "filePath",
              line_number AS "lineNumber", code_snippet AS "codeSnippet",
              description, root_cause AS recommendation, confidence_score AS confidence
       FROM code_review_findings
       WHERE id = ANY($1) AND org_id = $2`
    : `SELECT id, title, severity, type, cwe_id AS "cweId", file_path AS "filePath",
              line_number AS "lineNumber", code_snippet AS "codeSnippet",
              description, recommendation, confidence
       FROM findings
       WHERE id = ANY($1) AND org_id = $2`;
  const findingsResult = await query(sql, [findingIds, orgId]);

  const rows = findingsResult.rows as Array<Record<string, unknown>>;
  const results: AIBatchResult['findings'] = [];

  if ((await isLLMAvailableAsync()) && rows.length <= 30) {
    try {
      const summaries = rows.map((f, i) =>
        `[${i + 1}] ${f.severity} | ${f.cweId || 'N/A'} | ${f.title} | ${f.filePath || 'N/A'}:${f.lineNumber || ''}`
      ).join('\n');

      const response = await chatCompletion([
        { role: 'system', content: `You are a security analyst. Review these findings and assess false positive probability for each.
Respond with a JSON array: [{"index": 1, "fpProbability": 0.0, "reasoning": "..."}]` },
        { role: 'user', content: `Review these ${rows.length} security findings:\n\n${summaries}` },
      ], 4000);

      const jsonMatch = response.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]) as Array<{ index: number; fpProbability: number; reasoning: string }>;
        for (const item of parsed) {
          const finding = rows[item.index - 1];
          if (finding) {
            results.push({
              findingId: finding.id as string,
              title: finding.title as string,
              severity: finding.severity as string,
              fpProbability: item.fpProbability,
              reasoning: item.reasoning,
            });
          }
        }
      }
    } catch (err) {
      logger.warn({ err }, 'Batch AI review failed, using local heuristics');
    }
  }

  if (results.length === 0) {
    for (const f of rows) {
      const analysis = localAnalyzeFinding(f);
      results.push({
        findingId: f.id as string,
        title: f.title as string,
        severity: f.severity as string,
        fpProbability: analysis.falsePositiveProbability,
        reasoning: analysis.reasoning,
      });
    }
  }

  return {
    totalReviewed: results.length,
    likelyFalsePositives: results.filter(r => r.fpProbability > 0.7).length,
    likelyTruePositives: results.filter(r => r.fpProbability < 0.3).length,
    uncertain: results.filter(r => r.fpProbability >= 0.3 && r.fpProbability <= 0.7).length,
    findings: results,
    provider: isLLMConfigured() ? `llm:${_aiConfig?.model}` : 'local',
  };
}

export async function searchFindings(
  naturalLanguageQuery: string, orgId: string,
): Promise<AISearchResult> {
  let filters: Record<string, unknown>;

  if (await isLLMAvailableAsync()) {
    try {
      const response = await chatCompletion([
        { role: 'system', content: NL_SEARCH_PROMPT },
        { role: 'user', content: naturalLanguageQuery },
      ], 500);

      const jsonMatch = response.match(/\{[\s\S]*\}/);
      filters = jsonMatch ? JSON.parse(jsonMatch[0]) : localParseSearchQuery(naturalLanguageQuery);
    } catch {
      filters = localParseSearchQuery(naturalLanguageQuery);
    }
  } else {
    filters = localParseSearchQuery(naturalLanguageQuery);
  }

  const conditions = ['f.org_id = $1'];
  const params: unknown[] = [orgId];
  let idx = 2;

  if (filters.severity) { conditions.push(`f.severity = $${idx++}`); params.push(filters.severity); }
  if (filters.type) { conditions.push(`f.type = $${idx++}`); params.push(filters.type); }
  if (filters.cweId) { conditions.push(`f.cwe_id = $${idx++}`); params.push(filters.cweId); }
  if (filters.status) { conditions.push(`f.status = $${idx++}`); params.push(filters.status); }
  if (filters.filePath) { conditions.push(`f.file_path ILIKE $${idx++}`); params.push(filters.filePath); }
  if (filters.title) { conditions.push(`f.title ILIKE $${idx++}`); params.push(filters.title); }
  if (filters.dateAfter) { conditions.push(`f.created_at >= $${idx++}`); params.push(filters.dateAfter); }
  if (filters.dateBefore) { conditions.push(`f.created_at <= $${idx++}`); params.push(filters.dateBefore); }

  const where = conditions.join(' AND ');
  const result = await query(
    `SELECT f.id, f.title, f.severity, f.type, f.status,
            f.cwe_id AS "cweId", f.cve_id AS "cveId", f.cvss_score AS "cvssScore",
            f.file_path AS "filePath", f.line_number AS "lineNumber",
            f.epss_score AS "epssScore", f.kev_match AS "kevMatch"
     FROM findings f
     WHERE ${where}
     ORDER BY f.severity_rank ASC, f.created_at DESC
     LIMIT 50`,
    params,
  );

  return {
    query: naturalLanguageQuery,
    parsedFilters: filters,
    results: result.rows as Array<Record<string, unknown>>,
    totalCount: result.rows.length,
    provider: isLLMConfigured() ? `llm:${_aiConfig?.model}` : 'local',
  };
}

export async function getStatus(): Promise<AIStatusResult> {
  const cfg = await loadAIConfig();
  const llm = isLLMConfigured();
  return {
    provider: llm ? 'openai' : 'local',
    model: llm ? cfg.model : 'heuristic-v1',
    available: true,
    capabilities: [
      'analyze-finding',
      'batch-review',
      'search',
      ...(llm ? ['llm-analysis', 'natural-language-search'] : ['heuristic-analysis', 'keyword-search']),
    ],
  };
}
