// Scan Orchestrator — ties all engines together into real scan pipelines
import { v4 as uuidv4 } from 'uuid';
import { query } from '../core/db/pool.js';
import { queueManager, QueueName, JobPriority } from '../core/queue/manager.js';
import { logger } from '../core/logging/logger.js';
import { broadcastScanUpdate, broadcastFindingUpdate } from '../websocket/ws-server.js';
import { dispatchEvent, WebhookEventType } from './integration/webhook-service.js';

export interface ScanRequest {
  projectId: string;
  scanTypes: ('sast'|'dast'|'api'|'container'|'binary'|'deps'|'fuzz'|'health'|'protocol'|'secret')[];
  targetUrl?: string;
  targetPath?: string;
  imageName?: string;
  artifactPath?: string;
  artifactType?: string;
  options?: Record<string, unknown>;
  priority?: 'low'|'normal'|'high'|'critical';
  userId: string;
  orgId: string;
}

export interface ScanPipeline {
  masterScanId: string;
  subScans: Array<{scanId:string;type:string;queueName:QueueName;jobId?:string}>;
}

export async function launchScanPipeline(req: ScanRequest): Promise<ScanPipeline> {
  const masterScanId = uuidv4();
  const subScans: ScanPipeline['subScans'] = [];
  const priority = req.priority || 'normal';
  const priorityMap: Record<string, JobPriority> = { low: JobPriority.LOW, normal: JobPriority.NORMAL, high: JobPriority.HIGH, critical: JobPriority.CRITICAL };

  logger.info({ masterScanId, scanTypes: req.scanTypes, projectId: req.projectId }, 'Launching scan pipeline');

  // Create master scan record
  await query(`INSERT INTO scans (id, org_id, project_id, scan_type, name, status, options, started_by, created_at, updated_at)
    VALUES ($1,$2,$3,'full',$4,'queued',$5,$6,NOW(),NOW())`,
    [masterScanId, req.orgId, req.projectId, `Scan Pipeline: ${req.scanTypes.join(', ')}`, JSON.stringify(req.options || {}), req.userId]);

  // SAST scan
  if (req.scanTypes.includes('sast')) {
    const scanId = uuidv4();
    await query(`INSERT INTO scans (id, org_id, project_id, scan_type, name, status, options, started_by, created_at, updated_at)
      VALUES ($1,$2,$3,'sast',$4,'queued',$5,$6,NOW(),NOW())`,
      [scanId, req.orgId, req.projectId, `SAST: ${req.targetPath || 'codebase'}`, JSON.stringify({ parentScanId: masterScanId, ...req.options }), req.userId]);
    const job = await queueManager.addJob(QueueName.SAST_SCAN, `sast:${scanId}`, { scanId, projectId: req.projectId, targetPath: req.targetPath, options: req.options, userId: req.userId, organizationId: req.orgId } as Record<string,unknown>, priorityMap[priority]);
    subScans.push({ scanId, type: 'sast', queueName: QueueName.SAST_SCAN, jobId: job.id });
    broadcastScanUpdate(req.orgId, scanId, { status: 'queued', type: 'sast' });
  }

  // DAST scan
  if (req.scanTypes.includes('dast')) {
    const scanId = uuidv4();
    await query(`INSERT INTO scans (id, org_id, project_id, scan_type, name, status, options, started_by, created_at, updated_at)
      VALUES ($1,$2,$3,'dast',$4,'queued',$5,$6,NOW(),NOW())`,
      [scanId, req.orgId, req.projectId, `DAST: ${req.targetUrl || 'target'}`, JSON.stringify({ parentScanId: masterScanId, ...req.options }), req.userId]);
    const job = await queueManager.addJob(QueueName.DAST_SCAN, `dast:${scanId}`, { scanId, projectId: req.projectId, targetUrl: req.targetUrl, options: req.options, userId: req.userId, organizationId: req.orgId } as Record<string,unknown>, priorityMap[priority]);
    subScans.push({ scanId, type: 'dast', queueName: QueueName.DAST_SCAN, jobId: job.id });
    broadcastScanUpdate(req.orgId, scanId, { status: 'queued', type: 'dast' });
  }

  // API scan
  if (req.scanTypes.includes('api')) {
    const scanId = uuidv4();
    await query(`INSERT INTO scans (id, org_id, project_id, scan_type, name, status, options, started_by, created_at, updated_at)
      VALUES ($1,$2,$3,'api',$4,'queued',$5,$6,NOW(),NOW())`,
      [scanId, req.orgId, req.projectId, `API Scan: ${req.targetUrl || 'target'}`, JSON.stringify({ parentScanId: masterScanId, ...req.options }), req.userId]);
    const job = await queueManager.addJob(QueueName.API_SCAN, `api:${scanId}`, { scanId, projectId: req.projectId, targetUrl: req.targetUrl, options: req.options, userId: req.userId, organizationId: req.orgId } as Record<string,unknown>, priorityMap[priority]);
    subScans.push({ scanId, type: 'api', queueName: QueueName.API_SCAN, jobId: job.id });
  }

  // Container scan
  if (req.scanTypes.includes('container')) {
    const scanId = uuidv4();
    await query(`INSERT INTO container_scans (id, org_id, project_id, image_name, status, started_by, created_at, updated_at)
      VALUES ($1,$2,$3,$4,'queued',$5,NOW(),NOW())`,
      [scanId, req.orgId, req.projectId, req.imageName, req.userId]);
    await queueManager.addJob(QueueName.SAST_SCAN, `container:${scanId}`, { scanId, imageName: req.imageName, projectId: req.projectId, orgId: req.orgId, userId: req.userId } as Record<string,unknown>, priorityMap[priority]);
    subScans.push({ scanId, type: 'container', queueName: QueueName.SAST_SCAN });
  }

  // Binary scan
  if (req.scanTypes.includes('binary')) {
    const scanId = uuidv4();
    await query(`INSERT INTO binary_scans (id, org_id, project_id, artifact_type, artifact_path, status, started_by, created_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,'queued',$6,NOW(),NOW())`,
      [scanId, req.orgId, req.projectId, req.artifactType, req.artifactPath, req.userId]);
    await queueManager.addJob(QueueName.SAST_SCAN, `binary:${scanId}`, { scanId, artifactPath: req.artifactPath, artifactType: req.artifactType, orgId: req.orgId } as Record<string,unknown>);
    subScans.push({ scanId, type: 'binary', queueName: QueueName.SAST_SCAN });
  }

  // Secret scan
  if (req.scanTypes.includes('secret')) {
    const scanId = uuidv4();
    await query(`INSERT INTO scans (id, org_id, project_id, scan_type, name, status, options, started_by, created_at, updated_at)
      VALUES ($1,$2,$3,'secret',$4,'queued',$5,$6,NOW(),NOW())`,
      [scanId, req.orgId, req.projectId, `Secret Scan: ${req.targetPath || 'codebase'}`, JSON.stringify({ parentScanId: masterScanId, ...req.options }), req.userId]);
    const job = await queueManager.addJob(QueueName.SECRET_SCAN, `secret:${scanId}`, { scanId, projectId: req.projectId, targetPath: req.targetPath, targetUrl: req.targetUrl, options: req.options, userId: req.userId, organizationId: req.orgId } as Record<string,unknown>, priorityMap[priority]);
    subScans.push({ scanId, type: 'secret', queueName: QueueName.SECRET_SCAN, jobId: job.id });
    broadcastScanUpdate(req.orgId, scanId, { status: 'queued', type: 'secret' });
  }

  // Update master scan with sub-scans
  const subScanIds = subScans.map(s => s.scanId);
  await query(`UPDATE scans SET options = options || $2::jsonb, updated_at = NOW() WHERE id = $1`,
    [masterScanId, JSON.stringify({ subScans: subScanIds, pipelineStatus: 'launched' })]);

  logger.info({ masterScanId, subScanCount: subScans.length }, 'Scan pipeline launched');
  return { masterScanId, subScans };
}

export async function storeFinding(
  scanId: string, projectId: string, orgId: string, finding: {
    type: string; title: string; description: string; severity: string;
    cweId?: string; owaspCategory?: string; cvssScore?: number; cvssVector?: string;
    filePath?: string; lineNumber?: number; codeSnippet?: string;
    ruleId?: string; ruleName?: string; recommendation?: string;
    confidenceScore?: number; falsePositiveProbability?: number;
  }
): Promise<string> {
  const findingId = uuidv4();
  const severityRank = { critical: 1, high: 2, medium: 3, low: 4, info: 5 }[finding.severity] || 3;

  await query(`INSERT INTO findings (id, org_id, project_id, scan_id, type, title, description, severity, severity_rank,
    cwe_id, owasp_category, cvss_score, cvss_vector, file_path, line_number, code_snippet, rule_id, rule_name, recommendation, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NOW(),NOW())`,
    [findingId, orgId, projectId, scanId, finding.type, finding.title, finding.description, finding.severity, severityRank,
      finding.cweId, finding.owaspCategory, finding.cvssScore, finding.cvssVector,
      finding.filePath, finding.lineNumber, finding.codeSnippet, finding.ruleId, finding.ruleName, finding.recommendation]);

  broadcastFindingUpdate(orgId, findingId, { scanId, severity: finding.severity, title: finding.title });

  dispatchEvent(WebhookEventType.FINDING_CREATED, { findingId, scanId, projectId, type: finding.type, severity: finding.severity, title: finding.title }, orgId).catch(() => {});
  if (finding.severity === 'critical') {
    dispatchEvent(WebhookEventType.FINDING_CRITICAL, { findingId, scanId, projectId, type: finding.type, title: finding.title, cweId: finding.cweId }, orgId).catch(() => {});
  }

  return findingId;
}

export async function completeScan(scanId: string, findingsCount: number, metadata?: Record<string, unknown>): Promise<void> {
  await query(`UPDATE scans SET status = 'completed', completed_at = NOW(), findings_count = $2, metadata = COALESCE(metadata,'{}'::jsonb) || $3::jsonb, updated_at = NOW() WHERE id = $1`,
    [scanId, findingsCount, JSON.stringify(metadata || {})]);
  const scan = await query('SELECT org_id, project_id, scan_type FROM scans WHERE id = $1', [scanId]);
  if (scan.rows[0]) {
    const row = scan.rows[0] as Record<string, unknown>;
    const orgId = row.org_id as string;
    broadcastScanUpdate(orgId, scanId, { status: 'completed', findingsCount });
    dispatchEvent(WebhookEventType.SCAN_COMPLETED, { scanId, projectId: row.project_id, scanType: row.scan_type, findingsCount, ...metadata }, orgId).catch(() => {});
  }
}

export async function failScan(scanId: string, errorMessage: string): Promise<void> {
  await query(`UPDATE scans SET status = 'failed', error_message = $2, updated_at = NOW() WHERE id = $1`, [scanId, errorMessage]);
  const scan = await query('SELECT org_id, project_id, scan_type FROM scans WHERE id = $1', [scanId]);
  if (scan.rows[0]) {
    const row = scan.rows[0] as Record<string, unknown>;
    const orgId = row.org_id as string;
    broadcastScanUpdate(orgId, scanId, { status: 'failed', errorMessage });
    dispatchEvent(WebhookEventType.SCAN_FAILED, { scanId, projectId: row.project_id, scanType: row.scan_type, errorMessage }, orgId).catch(() => {});
  }
}
