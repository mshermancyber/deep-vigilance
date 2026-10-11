// Scanner-local persistence for finding/scan results.
//
// The scanner processes run in their own containers and do NOT share the
// backend's in-process Socket.IO server, so this module only writes to the
// database (the backend emits real-time updates separately). It deliberately
// has no dependency on backend source, so the scanner image builds standalone.
import crypto from 'node:crypto';
import { query } from './db.js';

const SEVERITY_RANK: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

export interface StoredFinding {
  type: string;
  title: string;
  description: string;
  severity: string;
  cweId?: string;
  owaspCategory?: string;
  cvssScore?: number;
  cvssVector?: string;
  cveId?: string;
  epssScore?: number;
  kevMatch?: boolean;
  filePath?: string;
  lineNumber?: number;
  codeSnippet?: string;
  ruleId?: string;
  ruleName?: string;
  recommendation?: string;
  confidence?: string;
  metadata?: Record<string, unknown>;
}

export async function storeFinding(
  scanId: string,
  projectId: string,
  orgId: string,
  finding: StoredFinding,
): Promise<string> {
  const findingId = crypto.randomUUID();
  const severityRank = SEVERITY_RANK[finding.severity] ?? 3;

  await query(
    `INSERT INTO findings (id, org_id, project_id, scan_id, type, title, description, severity, severity_rank,
      cwe_id, owasp_category, cvss_score, cvss_vector, cve_id, epss_score, kev_match,
      file_path, line_number, code_snippet, rule_id, rule_name, recommendation,
      confidence, metadata, created_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,NOW(),NOW())`,
    [findingId, orgId, projectId, scanId, finding.type, finding.title, finding.description, finding.severity, severityRank,
      finding.cweId, finding.owaspCategory, finding.cvssScore, finding.cvssVector,
      finding.cveId, finding.epssScore ?? 0, finding.kevMatch ?? false,
      finding.filePath, finding.lineNumber, finding.codeSnippet, finding.ruleId, finding.ruleName, finding.recommendation,
      finding.confidence || 'medium', JSON.stringify(finding.metadata || {})],
  );

  return findingId;
}

export async function startScan(scanId: string): Promise<void> {
  await query(
    `UPDATE scans SET status = 'running', started_at = COALESCE(started_at, NOW()), updated_at = NOW()
     WHERE id = $1 AND status IN ('queued','paused')`,
    [scanId],
  );
}

export async function completeScan(scanId: string, findingsCount: number, metadata?: Record<string, unknown>): Promise<void> {
  await query(
    `UPDATE scans SET status = 'completed', completed_at = NOW(), findings_count = $2,
       metadata = COALESCE(metadata,'{}'::jsonb) || $3::jsonb, updated_at = NOW()
     WHERE id = $1`,
    [scanId, findingsCount, JSON.stringify(metadata || {})],
  );
}

export async function failScan(scanId: string, errorMessage: string): Promise<void> {
  await query(
    `UPDATE scans SET status = 'failed', error_message = $2, updated_at = NOW() WHERE id = $1`,
    [scanId, errorMessage],
  );
}
