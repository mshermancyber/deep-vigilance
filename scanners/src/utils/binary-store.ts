import crypto from 'node:crypto';
import { query } from './db.js';

export async function startBinaryScan(scanId: string): Promise<void> {
  await query(
    `UPDATE binary_scans SET status = 'analyzing', updated_at = NOW()
     WHERE id = $1 AND status IN ('queued','pending')`,
    [scanId],
  );
}

export interface BinaryFindingInput {
  findingType: string;
  severity: string;
  title: string;
  description?: string;
  cweId?: string;
  cvssScore?: number;
  filePath?: string;
  className?: string;
  methodName?: string;
  codeSnippet?: string;
  recommendation?: string;
}

export async function storeBinaryFinding(scanId: string, orgId: string, f: BinaryFindingInput): Promise<void> {
  await query(
    `INSERT INTO binary_findings (id, scan_id, org_id, finding_type, severity, title, description,
       cwe_id, cvss_score, file_path, class_name, method_name, code_snippet, recommendation, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW())`,
    [crypto.randomUUID(), scanId, orgId, f.findingType, f.severity, f.title, f.description || null,
      f.cweId || null, f.cvssScore ?? null, f.filePath || null, f.className || null,
      f.methodName || null, f.codeSnippet || null, f.recommendation || null],
  );
}

export async function completeBinaryScan(scanId: string, totalFindings: number, metadata?: Record<string, unknown>): Promise<void> {
  await query(
    `UPDATE binary_scans SET status = 'completed', total_findings = $2,
       metadata = COALESCE(metadata,'{}'::jsonb) || $3::jsonb, updated_at = NOW()
     WHERE id = $1`,
    [scanId, totalFindings, JSON.stringify(metadata || {})],
  );
}

export async function failBinaryScan(scanId: string, errorMessage: string): Promise<void> {
  await query(
    `UPDATE binary_scans SET status = 'failed',
       metadata = COALESCE(metadata,'{}'::jsonb) || $2::jsonb, updated_at = NOW()
     WHERE id = $1`,
    [scanId, JSON.stringify({ error: errorMessage })],
  );
}
