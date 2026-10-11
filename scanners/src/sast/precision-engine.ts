// ============================================================
// Precision Engine — Rule Performance Tracking & False-Positive
// Analysis for SAST Scanning (M5c)
//
// Tracks per-rule precision, recall, F1, noise, and trend.
// Computes coverage gaps against CWE Top 25.
// Supports incremental rescan via file hash comparison.
// ============================================================

import fs from 'fs';
import { createHash } from 'crypto';
import { logger } from '../utils/logger.js';
import { SastRule } from './engine.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RulePerformanceMetrics {
  ruleId: string;
  truePositives: number;
  falsePositives: number;
  suppressedFindings: number;
  confirmedFindings: number;
  totalFindings: number;
  scanTimeTotal: number;   // cumulative milliseconds
  scanRuns: number;
  lastScanned: string;     // ISO date
  dailyMetrics: DailyMetric[];
}

export interface DailyMetric {
  date: string;            // YYYY-MM-DD
  truePositives: number;
  falsePositives: number;
  totalFindings: number;
  scanTimeTotal: number;
  scanRuns: number;
}

export interface ScanResultInput {
  ruleId: string;
  status: 'confirmed' | 'false_positive' | 'suppressed' | 'pending';
  scanTimeMs: number;
  filePath: string;
}

export interface RuleEffectivenessReport {
  ruleId: string;
  ruleName: string;
  precision: number;
  recall: number;
  f1Score: number;
  signalToNoiseRatio: number;
  totalFindings: number;
  confirmed: number;
  falsePositives: number;
  averageScanTimeMs: number;
  averageScanTimePerFile: number;
  trend: 'improving' | 'worsening' | 'stable';
  trendConfidence: number;
}

export interface NoisyRule {
  ruleId: string;
  ruleName: string;
  falsePositiveRate: number;
  totalFindings: number;
  falsePositives: number;
  recommendation: string;
}

export interface TopPerformer {
  ruleId: string;
  ruleName: string;
  precision: number;
  recall: number;
  f1Score: number;
  totalFindings: number;
}

export interface CoverageGapReport {
  coveredCWEs: string[];
  missingCWEs: string[];
  coveragePct: number;
  recommendations: string[];
}

export interface FileHashIndex {
  [filePath: string]: string;
}

export interface FileChangeRecord {
  filePath: string;
  previousHash: string | undefined;
  currentHash: string;
  changed: boolean;
}

export interface CallGraphNodeInfo {
  functionName: string;
  filePath: string;
  callers: string[];
  callees: string[];
}

// ---------------------------------------------------------------------------
// In-Memory Metrics Store
// ---------------------------------------------------------------------------

class MetricsStore {
  private metrics = new Map<string, RulePerformanceMetrics>();

  get(ruleId: string): RulePerformanceMetrics | undefined {
    return this.metrics.get(ruleId);
  }

  set(ruleId: string, data: RulePerformanceMetrics): void {
    this.metrics.set(ruleId, data);
  }

  getAll(): RulePerformanceMetrics[] {
    return Array.from(this.metrics.values());
  }

  has(ruleId: string): boolean {
    return this.metrics.has(ruleId);
  }

  size(): number {
    return this.metrics.size;
  }

  clear(): void {
    this.metrics.clear();
  }
}

const store = new MetricsStore();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function todayString(): string {
  return new Date().toISOString().slice(0, 10);
}

function daysAgo(n: number): Date {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

function computePrecision(tp: number, fp: number): number {
  const denominator = tp + fp;
  if (denominator === 0) return 1; // no findings — technically perfect
  return tp / denominator;
}

function computeRecall(tp: number, fn: number): number {
  const denominator = tp + fn;
  if (denominator === 0) return 1;
  return tp / denominator;
}

function computeF1Score(precision: number, recall: number): number {
  if (precision === 0 && recall === 0) return 0;
  return 2 * (precision * recall) / (precision + recall);
}

// ---------------------------------------------------------------------------
// 1. trackRulePerformance
// ---------------------------------------------------------------------------

export function trackRulePerformance(ruleId: string, scanResult: ScanResultInput): RulePerformanceMetrics {
  let metrics = store.get(ruleId);
  const today = todayString();

  if (!metrics) {
    metrics = {
      ruleId,
      truePositives: 0,
      falsePositives: 0,
      suppressedFindings: 0,
      confirmedFindings: 0,
      totalFindings: 0,
      scanTimeTotal: 0,
      scanRuns: 0,
      lastScanned: new Date().toISOString(),
      dailyMetrics: [],
    };
  }

  // Update counters
  switch (scanResult.status) {
    case 'confirmed':
      metrics.truePositives++;
      metrics.confirmedFindings++;
      break;
    case 'false_positive':
      metrics.falsePositives++;
      break;
    case 'suppressed':
      metrics.suppressedFindings++;
      break;
  }
  metrics.totalFindings++;
  metrics.scanTimeTotal += scanResult.scanTimeMs;
  metrics.scanRuns++;
  metrics.lastScanned = new Date().toISOString();

  // Update daily aggregate
  let daily = metrics.dailyMetrics.find(d => d.date === today);
  if (!daily) {
    daily = { date: today, truePositives: 0, falsePositives: 0, totalFindings: 0, scanTimeTotal: 0, scanRuns: 0 };
    metrics.dailyMetrics.push(daily);
  }

  switch (scanResult.status) {
    case 'confirmed':
      daily.truePositives++;
      break;
    case 'false_positive':
      daily.falsePositives++;
      break;
  }
  daily.totalFindings++;
  daily.scanTimeTotal += scanResult.scanTimeMs;
  daily.scanRuns++;

  store.set(ruleId, metrics);

  // Periodic logging for observability
  if (metrics.totalFindings % 100 === 0) {
    const precision = computePrecision(metrics.truePositives, metrics.falsePositives);
    logger.info(
      { ruleId, totalFindings: metrics.totalFindings, precision, fps: metrics.falsePositives },
      'Rule performance snapshot',
    );
  }

  return metrics;
}

// ---------------------------------------------------------------------------
// 2. computeRuleEffectiveness
// ---------------------------------------------------------------------------

export function computeRuleEffectiveness(ruleId: string, ruleName?: string): RuleEffectivenessReport | null {
  const metrics = store.get(ruleId);
  if (!metrics) {
    logger.warn({ ruleId }, 'No metrics found for rule; cannot compute effectiveness');
    return null;
  }

  const tp = metrics.truePositives;
  const fp = metrics.falsePositives;

  // Precision = TP / (TP + FP)
  const precision = computePrecision(tp, fp);

  // Estimate false negatives as 10 % of confirmed findings.
  // In production this would come from ground-truth baseline comparisons or
  // manual review sampling.
  const estimatedFalseNegatives = Math.max(1, Math.round(metrics.confirmedFindings * 0.1));
  const recall = computeRecall(metrics.confirmedFindings, estimatedFalseNegatives);

  // F1 = 2 * (precision * recall) / (precision + recall)
  const f1Score = computeF1Score(precision, recall);

  // Signal-to-noise ratio: TP / FP
  const signalToNoiseRatio = fp > 0
    ? tp / fp
    : tp > 0
      ? Number.POSITIVE_INFINITY
      : 0;

  // Average scan time per run
  const averageScanTimeMs = metrics.scanRuns > 0
    ? metrics.scanTimeTotal / metrics.scanRuns
    : 0;

  // Average scan time attributed per finding
  const averageScanTimePerFile = metrics.scanRuns > 0 && metrics.totalFindings > 0
    ? metrics.scanTimeTotal / (metrics.scanRuns * Math.max(1, metrics.totalFindings / metrics.scanRuns))
    : 0;

  // Trend analysis over the trailing 30 days
  const trendResult = computeTrend(metrics);

  return {
    ruleId,
    ruleName: ruleName ?? ruleId,
    precision: Math.round(precision * 1000) / 1000,
    recall: Math.round(recall * 1000) / 1000,
    f1Score: Math.round(f1Score * 1000) / 1000,
    signalToNoiseRatio: signalToNoiseRatio === Number.POSITIVE_INFINITY
      ? Number.MAX_VALUE
      : Math.round(signalToNoiseRatio * 100) / 100,
    totalFindings: metrics.totalFindings,
    confirmed: metrics.confirmedFindings,
    falsePositives: metrics.falsePositives,
    averageScanTimeMs: Math.round(averageScanTimeMs * 100) / 100,
    averageScanTimePerFile: Math.round(averageScanTimePerFile * 100) / 100,
    trend: trendResult.label,
    trendConfidence: trendResult.confidence,
  };
}

/**
 * Compare the most-recent 14 days against the prior 16 days (within the
 * trailing 30-day window) to detect precision improvement or degradation.
 */
function computeTrend(metrics: RulePerformanceMetrics): {
  label: 'improving' | 'worsening' | 'stable';
  confidence: number;
} {
  const cutoffRecent = daysAgo(14); // recent = last 14 days
  const cutoffWindow = daysAgo(30);

  const older: DailyMetric[] = [];
  const recent: DailyMetric[] = [];

  for (const d of metrics.dailyMetrics) {
    const date = new Date(d.date + 'T00:00:00Z');
    if (date < cutoffWindow) continue;
    if (date >= cutoffRecent) {
      recent.push(d);
    } else {
      older.push(d);
    }
  }

  if (older.length < 2 || recent.length < 2) {
    return { label: 'stable', confidence: 0.3 };
  }

  // Average precision per day for each period
  const avgPrecision = (entries: DailyMetric[]): number => {
    if (entries.length === 0) return 1;
    return entries.reduce((sum, d) => {
      const denom = d.truePositives + d.falsePositives;
      return sum + (denom > 0 ? d.truePositives / denom : 1);
    }, 0) / entries.length;
  };

  // Average false-positive rate per day for each period
  const avgFpRate = (entries: DailyMetric[]): number => {
    if (entries.length === 0) return 0;
    return entries.reduce((sum, d) => {
      return sum + (d.totalFindings > 0 ? d.falsePositives / d.totalFindings : 0);
    }, 0) / entries.length;
  };

  const olderPrecision = avgPrecision(older);
  const recentPrecision = avgPrecision(recent);
  const olderFpRate = avgFpRate(older);
  const recentFpRate = avgFpRate(recent);

  const precisionDelta = recentPrecision - olderPrecision;
  const fpRateDelta = olderFpRate - recentFpRate; // positive = FP rate dropped

  // Combined signal: precision improvement (60 %) + FP rate reduction (40 %)
  const score = precisionDelta * 0.6 + fpRateDelta * 0.4;

  if (score > 0.05) {
    return { label: 'improving', confidence: Math.min(Math.abs(score) * 2, 0.95) };
  }
  if (score < -0.05) {
    return { label: 'worsening', confidence: Math.min(Math.abs(score) * 2, 0.95) };
  }
  return { label: 'stable', confidence: 0.6 };
}

// ---------------------------------------------------------------------------
// 3. getNoisiestRules
// ---------------------------------------------------------------------------

const RECOMMENDATIONS_BY_CATEGORY: Record<string, string[]> = {
  injection: [
    'Add exclude pattern for test/ directory (many injection patterns match test fixtures)',
    'Increase confidence threshold for this rule',
    'Add context pattern to require user-input proximity before flagging',
  ],
  xss: [
    'Add exclude pattern for test/ directory (XSS patterns frequently match test HTML)',
    'Increase confidence threshold for this rule',
    'Require DOM sink proximity (innerHTML, document.write) to reduce FPs',
  ],
  authentication: [
    'Add context pattern to reduce FPs — most auth rule FPs come from auth middleware libraries',
    'Exclude known authentication library files from scanning',
    'Lower severity to "medium" to reduce noise in results',
  ],
  credentials: [
    'Add exclude pattern for generated/configuration files (many patterns match test keys)',
    'Increase minimum key length threshold to reduce matches on legitimate short tokens',
    'Exclude .env.example and documentation files from this rule',
  ],
  cryptography: [
    'Increase minimum key length threshold to reduce matches on legitimate short hashes',
    'Add exclude pattern for known-safe cryptographic library imports',
    'Narrow patterns to only match assignment contexts, not references',
  ],
  debug: [
    'Exclude debug/console statements in test files and example code',
    'Add exclude pattern for files in test/ and spec/ directories',
    'Require contextual evidence of production deployment to reduce FPs',
  ],
};

function generateFpRecommendation(ruleId: string, fpRate: number): string {
  const categoryKey = Object.keys(RECOMMENDATIONS_BY_CATEGORY).find(k =>
    ruleId.toLowerCase().includes(k) ||
    ruleId.toLowerCase().includes(k.slice(0, 4)),
  );

  const category = categoryKey ? RECOMMENDATIONS_BY_CATEGORY[categoryKey] : null;

  if (category) {
    return fpRate > 0.7
      ? category.join('; ')
      : category[0];
  }

  // Fallback generic recommendations
  if (fpRate > 0.7) {
    return 'Add exclude pattern for test/ directory; Increase confidence threshold; Add context pattern to reduce FPs';
  }
  return 'Add exclude pattern for test/ directory';
}

export function getNoisiestRules(limit: number = 10, rules?: Map<string, { name: string }>): NoisyRule[] {
  const allMetrics = store.getAll();

  const noisy = allMetrics
    .filter(m => m.totalFindings > 0)
    .map(m => {
      const fpRate = m.totalFindings > 0
        ? m.falsePositives / m.totalFindings
        : 0;

      const ruleName = rules?.get(m.ruleId)?.name ?? m.ruleId;

      return {
        ruleId: m.ruleId,
        ruleName,
        falsePositiveRate: Math.round(fpRate * 1000) / 1000,
        totalFindings: m.totalFindings,
        falsePositives: m.falsePositives,
        recommendation: generateFpRecommendation(m.ruleId, fpRate),
      };
    })
    .sort((a, b) => b.falsePositiveRate - a.falsePositiveRate || b.falsePositives - a.falsePositives);

  return noisy.slice(0, Math.max(1, limit));
}

// ---------------------------------------------------------------------------
// 4. getTopPerformers
// ---------------------------------------------------------------------------

export function getTopPerformers(limit: number = 10, rules?: Map<string, { name: string }>): TopPerformer[] {
  const allMetrics = store.getAll();

  // Require at least 5 findings for statistical significance
  const performers = allMetrics
    .filter(m => m.totalFindings >= 5)
    .map(m => {
      const tp = m.truePositives;
      const fp = m.falsePositives;
      const precision = computePrecision(tp, fp);
      const estimatedFn = Math.max(1, Math.round(m.confirmedFindings * 0.1));
      const recall = computeRecall(m.confirmedFindings, estimatedFn);
      const f1Score = computeF1Score(precision, recall);

      return {
        ruleId: m.ruleId,
        ruleName: rules?.get(m.ruleId)?.name ?? m.ruleId,
        precision: Math.round(precision * 1000) / 1000,
        recall: Math.round(recall * 1000) / 1000,
        f1Score: Math.round(f1Score * 1000) / 1000,
        totalFindings: m.totalFindings,
      };
    })
    .sort((a, b) => {
      // Primary sort: precision descending
      if (b.precision !== a.precision) return b.precision - a.precision;
      // Tie-breaker: F1 score descending
      if (b.f1Score !== a.f1Score) return b.f1Score - a.f1Score;
      // Final tie-breaker: total findings (more is better for significance)
      return b.totalFindings - a.totalFindings;
    });

  return performers.slice(0, Math.max(1, limit));
}

// ---------------------------------------------------------------------------
// 5. computeCoverageGap
// ---------------------------------------------------------------------------

// CWE Top 25 (2024) — authoritative list published by MITRE / CISA
const CWE_TOP_25: Record<string, string> = {
  'CWE-79':  'Improper Neutralization of Input During Web Page Generation (XSS)',
  'CWE-89':  'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
  'CWE-78':  'Improper Neutralization of Special Elements used in an OS Command (Command Injection)',
  'CWE-20':  'Improper Input Validation',
  'CWE-22':  'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
  'CWE-352': 'Cross-Site Request Forgery (CSRF)',
  'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
  'CWE-476': 'NULL Pointer Dereference',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-287': 'Improper Authentication',
  'CWE-798': 'Use of Hard-coded Credentials',
  'CWE-862': 'Missing Authorization',
  'CWE-863': 'Incorrect Authorization',
  'CWE-77':  'Improper Neutralization of Special Elements used in a Command (Command Injection)',
  'CWE-306': 'Missing Authentication for Critical Function',
  'CWE-119': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
  'CWE-276': 'Incorrect Default Permissions',
  'CWE-918': 'Server-Side Request Forgery (SSRF)',
  'CWE-362': 'Race Condition',
  'CWE-400': 'Uncontrolled Resource Consumption',
  'CWE-611': 'Improper Restriction of XML External Entity Reference (XXE)',
  'CWE-94':  'Improper Control of Generation of Code (Code Injection)',
  'CWE-522': 'Insufficiently Protected Credentials',
  'CWE-295': 'Improper Certificate Validation',
  'CWE-327': 'Use of a Broken or Risky Cryptographic Algorithm',
};

export function computeCoverageGap(ruleLibrary: SastRule[], scanTarget: string): CoverageGapReport {
  const coveredCWESet = new Set<string>();
  const cweRuleCount = new Map<string, number>();

  for (const rule of ruleLibrary) {
    const cwe = rule.cweId;
    if (cwe && cwe !== 'CWE-N/A') {
      coveredCWESet.add(cwe);
      cweRuleCount.set(cwe, (cweRuleCount.get(cwe) ?? 0) + 1);
    }
  }

  const coveredFromTop25: string[] = [];
  const missingFromTop25: string[] = [];

  const top25Entries = Object.entries(CWE_TOP_25);
  for (const [cweId, cweName] of top25Entries) {
    if (coveredCWESet.has(cweId)) {
      const ruleCount = cweRuleCount.get(cweId) ?? 0;
      coveredFromTop25.push(`${cweId} - ${cweName} (${ruleCount} rules)`);
    } else {
      missingFromTop25.push(`${cweId} - ${cweName}`);
    }
  }

  const coveragePct = top25Entries.length > 0
    ? Math.round((coveredFromTop25.length / top25Entries.length) * 100)
    : 0;

  // ---- Generate actionable recommendations ----

  const recommendations: string[] = [];

  // Missing CWE Top 25 entries
  if (missingFromTop25.length > 0) {
    const top5 = missingFromTop25.slice(0, 5).map(e => e.split(' - ')[0]);
    recommendations.push(
      `Create rules covering missing CWE Top 25 entries: ${top5.join(', ')}${
        missingFromTop25.length > 5 ? ` and ${missingFromTop25.length - 5} more` : ''
      }`,
    );
  }

  // Tech-stack-specific insights
  const techRecs = analyzeTargetForRecommendations(scanTarget, missingFromTop25);
  recommendations.push(...techRecs);

  // Category-level low-coverage warnings
  const lowCoverageCategories = findLowCoverageRuleCategories(ruleLibrary, coveredCWESet);
  if (lowCoverageCategories.length > 0) {
    recommendations.push(`Expand rule coverage in areas with sparse CWE mapping: ${lowCoverageCategories.join(', ')}`);
  }

  // Overall coverage guidance
  if (coveragePct < 50) {
    recommendations.push('CRITICAL: Less than 50 % of CWE Top 25 covered. Prioritize rules for high-impact vulnerability categories.');
  } else if (coveragePct < 80) {
    recommendations.push('MODERATE GAP: Focus on the remaining CWE Top 25 entries to reach 80 %+ coverage.');
  } else if (coveragePct < 100) {
    recommendations.push('MINOR GAP: The remaining uncovered CWE Top 25 entries should be addressed for complete coverage.');
  }

  return {
    coveredCWEs: coveredFromTop25,
    missingCWEs: missingFromTop25,
    coveragePct,
    recommendations,
  };
}

function analyzeTargetForRecommendations(scanTarget: string, missingCWEs: string[]): string[] {
  const recs: string[] = [];
  const target = scanTarget.toLowerCase();

  const missingCweIds = new Set(missingCWEs.map(e => e.split(' - ')[0]));

  const webSuggestions: Array<{ cwePrefix: string; message: string }> = [
    { cwePrefix: 'CWE-79', message: 'Web/API target missing XSS (CWE-79) coverage — critical for web applications' },
    { cwePrefix: 'CWE-352', message: 'Web/API target missing CSRF (CWE-352) coverage — essential for state-changing endpoints' },
    { cwePrefix: 'CWE-918', message: 'Web/API target missing SSRF (CWE-918) coverage — important for API security' },
    { cwePrefix: 'CWE-89', message: 'Web/API target missing SQL Injection (CWE-89) coverage — critical for database-backed apps' },
    { cwePrefix: 'CWE-22', message: 'Web/API target missing Path Traversal (CWE-22) coverage — important for file-serving endpoints' },
  ];

  if (target.includes('web') || target.includes('api') || target.includes('http')) {
    for (const s of webSuggestions) {
      if (missingCweIds.has(s.cwePrefix)) {
        recs.push(s.message);
      }
    }
  }

  if (target.includes('mobile') || target.includes('android') || target.includes('ios')) {
    if (missingCweIds.has('CWE-522')) {
      recs.push('Mobile target missing credential protection (CWE-522) coverage — critical for device-local storage');
    }
    recs.push('Consider adding mobile-specific CWEs: CWE-927 (exported activities), CWE-312 (cleartext storage)');
  }

  if (target.includes('cloud') || target.includes('aws') || target.includes('gcp') || target.includes('k8s')) {
    if (missingCweIds.has('CWE-276')) {
      recs.push('Cloud/IaC target missing default permissions (CWE-276) coverage — crucial for Infrastructure-as-Code scanning');
    }
  }

  // Language-specific notes
  if (target.includes('javascript') || target.includes('typescript') || target.includes('node')) {
    recs.push('JS/TS target: ensure rules cover Prototype Pollution (CWE-1321) and npm supply-chain risks');
  }
  if (target.includes('python')) {
    recs.push('Python target: ensure rules cover pickle deserialization (CWE-502) and Jinja2 SSTI');
  }
  if (target.includes('java')) {
    recs.push('Java target: ensure rules cover Spring EL injection (CWE-917) and Log4Shell patterns');
  }
  if (target.includes('csharp') || target.includes('.net')) {
    recs.push('.NET target: ensure rules cover BinaryFormatter deserialization and ViewState tampering');
  }

  return recs;
}

function findLowCoverageRuleCategories(ruleLibrary: SastRule[], coveredCWEs: Set<string>): string[] {
  const perCategory = new Map<string, { total: number; cweMapped: number }>();

  for (const rule of ruleLibrary) {
    const cat = rule.category || 'general';
    if (!perCategory.has(cat)) perCategory.set(cat, { total: 0, cweMapped: 0 });
    const stats = perCategory.get(cat)!;
    stats.total++;
    if (rule.cweId && rule.cweId !== 'CWE-N/A' && coveredCWEs.has(rule.cweId)) {
      stats.cweMapped++;
    }
  }

  const low: string[] = [];
  for (const [cat, stats] of perCategory) {
    if (stats.total >= 3) {
      const pct = (stats.cweMapped / stats.total) * 100;
      if (pct < 30) {
        low.push(`${cat} (${Math.round(pct)}% CWE-mapped)`);
      }
    }
  }

  return low;
}

// ---------------------------------------------------------------------------
// 6a. Incremental Scan — getFilesToRescan
// ---------------------------------------------------------------------------

export function getFilesToRescan(
  changedFiles: string[],
  fileHashIndex: FileHashIndex,
): FileChangeRecord[] {
  const records: FileChangeRecord[] = [];

  for (const filePath of changedFiles) {
    let currentHash: string;
    let readable = true;

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      currentHash = createHash('sha256').update(content).digest('hex');
    } catch {
      // File deleted, moved, or unreadable
      currentHash = '';
      readable = false;
    }

    const previousHash = fileHashIndex[filePath];

    if (!readable) {
      // File is gone — flag as changed (deletion) and clean up index
      records.push({ filePath, previousHash, currentHash: '', changed: true });
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete fileHashIndex[filePath];
      continue;
    }

    if (previousHash === undefined) {
      // Brand new file
      records.push({ filePath, previousHash: undefined, currentHash, changed: true });
      fileHashIndex[filePath] = currentHash;
      continue;
    }

    if (previousHash !== currentHash) {
      // Content changed
      records.push({ filePath, previousHash, currentHash, changed: true });
      fileHashIndex[filePath] = currentHash;
      continue;
    }

    // Hash unchanged — no rescan needed
    records.push({ filePath, previousHash, currentHash, changed: false });
  }

  return records;
}

// ---------------------------------------------------------------------------
// 6b. Incremental Scan — getAffectedCallers
//
// Given a changed function name and a call graph, return the transitive
// closure of callers that need re-analysis.
// ---------------------------------------------------------------------------

export function getAffectedCallers(
  changedFunction: string,
  callGraph: Map<string, CallGraphNodeInfo>,
): string[] {
  const affected = new Set<string>();
  const visited = new Set<string>();
  const queue: string[] = [changedFunction];
  const maxTraversalDepth = 100; // guard against extremely deep call chains

  let depth = 0;

  while (queue.length > 0 && depth < maxTraversalDepth) {
    const current = queue.shift()!;
    if (visited.has(current)) continue;
    visited.add(current);
    depth++;

    const node = callGraph.get(current);

    // Always include the changed function itself
    affected.add(current);

    // Traverse callers (reverse edges) to find everything that depends on this
    if (node) {
      for (const caller of node.callers) {
        if (!visited.has(caller)) {
          affected.add(caller);
          queue.push(caller);
        }
      }
    }
  }

  if (depth >= maxTraversalDepth) {
    logger.warn(
      { changedFunction, visitedCount: visited.size },
      'Call graph traversal hit max depth — result may be incomplete',
    );
  }

  return Array.from(affected);
}

// ---------------------------------------------------------------------------
// Testing / Debugging Utilities
// ---------------------------------------------------------------------------

/** Expose the store for testing and inspection. */
export function getStore(): { get: typeof store.get; getAll: typeof store.getAll; size: typeof store.size } {
  return store;
}

/** Clear all stored metrics (e.g., between test runs). */
export function resetMetrics(): void {
  store.clear();
}

/** Seed the store from an array of metric data (used in tests or migrations). */
export function importMetrics(data: RulePerformanceMetrics[]): void {
  for (const m of data) {
    store.set(m.ruleId, m);
  }
}
