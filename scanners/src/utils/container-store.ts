import crypto from 'node:crypto';
import { query } from './db.js';

export interface ContainerFindingRow {
  cveId?: string;
  severity: string;
  cvssScore?: number;
  packageName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  layerIdx?: number;
  title?: string;
  description?: string;
  recommendation?: string;
}

export async function startContainerScan(scanId: string): Promise<void> {
  await query(
    `UPDATE container_scans SET status = 'scanning', updated_at = NOW()
     WHERE id = $1 AND status = 'queued'`,
    [scanId],
  );
}

export async function storeContainerFinding(
  scanId: string,
  orgId: string,
  finding: ContainerFindingRow,
): Promise<string> {
  const id = crypto.randomUUID();
  await query(
    `INSERT INTO container_findings
       (id, scan_id, org_id, cve_id, severity, cvss_score, package_name,
        installed_version, fixed_version, layer_idx, title, description, recommendation, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())`,
    [id, scanId, orgId, finding.cveId, finding.severity, finding.cvssScore ?? null,
      finding.packageName, finding.installedVersion, finding.fixedVersion,
      finding.layerIdx ?? null, finding.title, finding.description ?? null,
      finding.recommendation ?? null],
  );
  return id;
}

export async function completeContainerScan(
  scanId: string,
  stats: {
    layers?: number;
    totalPackages?: number;
    vulnerablePackages?: number;
    criticalCves?: number;
    highCves?: number;
    mediumCves?: number;
    lowCves?: number;
    baseImage?: string;
    durationMs?: number;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  const severityScore =
    (stats.criticalCves ?? 0) * 10 +
    (stats.highCves ?? 0) * 5 +
    (stats.mediumCves ?? 0) * 2 +
    (stats.lowCves ?? 0);

  await query(
    `UPDATE container_scans SET
       status = 'completed',
       layers_count = COALESCE($2, layers_count),
       total_packages = COALESCE($3, total_packages),
       vulnerable_packages = COALESCE($4, vulnerable_packages),
       critical_cves = COALESCE($5, critical_cves),
       high_cves = COALESCE($6, high_cves),
       medium_cves = COALESCE($7, medium_cves),
       low_cves = COALESCE($8, low_cves),
       base_image = COALESCE($9, base_image),
       scan_duration_ms = $10,
       severity_score = $11,
       metadata = COALESCE(metadata,'{}'::jsonb) || COALESCE($12::jsonb,'{}'::jsonb),
       updated_at = NOW()
     WHERE id = $1`,
    [scanId, stats.layers ?? null, stats.totalPackages ?? null,
      stats.vulnerablePackages ?? null, stats.criticalCves ?? null,
      stats.highCves ?? null, stats.mediumCves ?? null, stats.lowCves ?? null,
      stats.baseImage ?? null, stats.durationMs ?? null, severityScore,
      JSON.stringify(stats.metadata ?? {})],
  );
}

export async function failContainerScan(scanId: string, errorMessage: string): Promise<void> {
  await query(
    `UPDATE container_scans SET status = 'failed',
       metadata = COALESCE(metadata,'{}'::jsonb) || jsonb_build_object('error', $2),
       updated_at = NOW()
     WHERE id = $1`,
    [scanId, errorMessage],
  );
}
