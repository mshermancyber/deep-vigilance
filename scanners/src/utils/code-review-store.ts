// Persistence for the Code Review engines (writes code_review_findings + updates code_reviews).
import crypto from 'node:crypto';
import { query } from './db.js';

const RANK: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
const VALID_TYPE = new Set(['semantic','security','quality','performance','logic','dependency','fuzz','style','architecture','configuration','license','supply_chain','iac','cicd']);
const VALID_SEV = new Set(['critical','high','medium','low','info']);

export function normSeverity(s: string | undefined): string {
  const v = (s || '').toLowerCase();
  return VALID_SEV.has(v) ? v : 'medium';
}
export function normType(t: string | undefined): string {
  const v = (t || '').toLowerCase();
  return VALID_TYPE.has(v) ? v : 'semantic';
}

export interface ReviewFinding {
  findingType: string; category?: string; ruleId?: string; ruleName?: string;
  title: string; description?: string; severity: string;
  confidenceScore?: number; filePath?: string; lineNumber?: number; lineRange?: string;
  functionName?: string; className?: string; codeSnippet?: string;
  rootCause?: string; securityImpact?: string; recommendedFix?: string; secureCodeExample?: string;
  cweId?: string; owaspCategory?: string; cvssScore?: number; cvssVector?: string;
}

export async function startReview(reviewId: string): Promise<void> {
  await query(
    `UPDATE code_reviews SET status='analyzing', started_at=COALESCE(started_at,NOW()), updated_at=NOW()
     WHERE id=$1 AND status IN ('queued','cloning','indexing','paused')`,
    [reviewId],
  );
}

export async function storeReviewFinding(reviewId: string, projectId: string | null, orgId: string, f: ReviewFinding): Promise<void> {
  const sev = normSeverity(f.severity);
  await query(
    `INSERT INTO code_review_findings
      (id, org_id, review_id, project_id, finding_type, category, rule_id, rule_name, title, description,
       severity, severity_rank, confidence_score, file_path, line_number, line_range, function_name, class_name,
       code_snippet, root_cause, security_impact, recommended_fix, secure_code_example, cwe_id, owasp_category,
       cvss_score, cvss_vector, status, created_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,'open',NOW(),NOW())`,
    [crypto.randomUUID(), orgId, reviewId, projectId, normType(f.findingType), f.category || null, f.ruleId || null,
      f.ruleName || null, f.title, f.description || null, sev, RANK[sev] ?? 3, f.confidenceScore ?? null,
      f.filePath || null, f.lineNumber ?? null, f.lineRange || null, f.functionName || null, f.className || null,
      f.codeSnippet || null, f.rootCause || null, f.securityImpact || null, f.recommendedFix || null,
      f.secureCodeExample || null, f.cweId || null, f.owaspCategory || null, f.cvssScore ?? null, f.cvssVector || null],
  );
}

export async function completeReview(reviewId: string, findings: ReviewFinding[], meta: {
  filesScanned?: number; linesScanned?: number; languages?: string[]; durationMs?: number; extra?: Record<string, unknown>;
}): Promise<void> {
  const c = (s: string) => findings.filter((f) => normSeverity(f.severity) === s).length;
  await query(
    `UPDATE code_reviews SET status='completed', completed_at=NOW(), updated_at=NOW(),
       total_findings=$2, critical_count=$3, high_count=$4, medium_count=$5, low_count=$6, info_count=$7,
       files_scanned=$8, lines_scanned=$9, languages_detected=$10, scan_duration_ms=$11,
       metadata=COALESCE(metadata,'{}'::jsonb) || $12::jsonb
     WHERE id=$1`,
    [reviewId, findings.length, c('critical'), c('high'), c('medium'), c('low'), c('info'),
      meta.filesScanned ?? 0, meta.linesScanned ?? 0, meta.languages ?? [], meta.durationMs ?? null,
      JSON.stringify(meta.extra ?? {})],
  );
}

export async function failReview(reviewId: string, errorMessage: string): Promise<void> {
  await query(`UPDATE code_reviews SET status='failed', error_message=$2, updated_at=NOW() WHERE id=$1`,
    [reviewId, errorMessage.slice(0, 2000)]);
}

export interface HealthMetrics {
  totalFiles: number; totalLines: number; codeLines: number; commentLines: number; blankLines: number;
  totalFunctions: number; totalClasses: number;
  cyclomaticComplexityAvg: number; cyclomaticComplexityMax: number; cognitiveComplexityAvg: number;
  maintainabilityIndex: number; technicalDebtRatio: number; technicalDebtMinutes: number;
  duplicationPct: number; duplicatedBlocks: number; duplicatedLines: number;
  codeChurnPct: number; commentDensityPct: number; unusedCodePct: number; deadCodePct: number;
  securityDensity: number;
  complexMethodsCount: number; largeClassesCount: number; longMethodsCount: number; tooManyParamsCount: number;
  architectureSmells: unknown[]; riskScore: number;
}

export async function storeHealthMetrics(reviewId: string, orgId: string, projectId: string | null, m: HealthMetrics): Promise<void> {
  await query(
    `INSERT INTO repo_health_metrics
      (id, org_id, project_id, review_id, total_files, total_lines, code_lines, comment_lines, blank_lines,
       total_functions, total_classes, cyclomatic_complexity_avg, cyclomatic_complexity_max, cognitive_complexity_avg,
       maintainability_index, technical_debt_ratio, technical_debt_minutes, duplication_pct, duplicated_blocks,
       duplicated_lines, code_churn_pct, comment_density_pct, unused_code_pct, dead_code_pct, security_density,
       complex_methods_count, large_classes_count, long_methods_count, too_many_params_count,
       architecture_smells, risk_score, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,NOW())`,
    [crypto.randomUUID(), orgId, projectId, reviewId,
      m.totalFiles, m.totalLines, m.codeLines, m.commentLines, m.blankLines,
      m.totalFunctions, m.totalClasses, m.cyclomaticComplexityAvg, m.cyclomaticComplexityMax, m.cognitiveComplexityAvg,
      m.maintainabilityIndex, m.technicalDebtRatio, m.technicalDebtMinutes,
      m.duplicationPct, m.duplicatedBlocks, m.duplicatedLines,
      m.codeChurnPct, m.commentDensityPct, m.unusedCodePct, m.deadCodePct, m.securityDensity,
      m.complexMethodsCount, m.largeClassesCount, m.longMethodsCount, m.tooManyParamsCount,
      JSON.stringify(m.architectureSmells), m.riskScore],
  );
}

export interface DepScanInput {
  ecosystem: string;
  manifestFile?: string;
  lockFile?: string;
  totalPackages: number;
  vulnerablePackages: number;
  deprecatedPackages: number;
  endOfLifePackages: number;
  licenseIssues: number;
  supplyChainRisks: number;
  durationMs?: number;
}

export async function storeDependencyScan(
  reviewId: string, orgId: string, projectId: string | null, scan: DepScanInput,
): Promise<string> {
  const id = crypto.randomUUID();
  await query(
    `INSERT INTO dependency_scans
      (id, org_id, project_id, review_id, name, ecosystem, manifest_file, lock_file,
       total_packages, vulnerable_packages, deprecated_packages, end_of_life_packages,
       license_issues, supply_chain_risks, status, scan_duration_ms, created_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'completed',$15,NOW(),NOW())`,
    [id, orgId, projectId, reviewId, `${scan.ecosystem} dependencies`, scan.ecosystem,
      scan.manifestFile || null, scan.lockFile || null,
      scan.totalPackages, scan.vulnerablePackages, scan.deprecatedPackages, scan.endOfLifePackages,
      scan.licenseIssues, scan.supplyChainRisks, scan.durationMs ?? null],
  );
  return id;
}

export interface DepFindingInput {
  packageName: string;
  packageVersion: string;
  ecosystem: string;
  vulnerabilityType: string;
  cveId?: string;
  cweId?: string;
  cvssScore?: number;
  epssScore?: number;
  kevMatch?: boolean;
  severity: string;
  title: string;
  description?: string;
  fixedInVersion?: string;
  recommendation?: string;
  references?: string[];
}

export async function storeDependencyFinding(scanId: string, orgId: string, f: DepFindingInput): Promise<void> {
  await query(
    `INSERT INTO dependency_findings
      (id, scan_id, org_id, package_name, package_version, ecosystem, vulnerability_type,
       cve_id, cwe_id, cvss_score, epss_score, kev_match, severity, title, description,
       fixed_in_version, recommendation, references_data, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())`,
    [crypto.randomUUID(), scanId, orgId, f.packageName, f.packageVersion, f.ecosystem,
      f.vulnerabilityType, f.cveId || null, f.cweId || null, f.cvssScore ?? null,
      f.epssScore ?? null, f.kevMatch ?? false, normSeverity(f.severity), f.title,
      f.description || null, f.fixedInVersion || null, f.recommendation || null,
      JSON.stringify(f.references || [])],
  );
}
