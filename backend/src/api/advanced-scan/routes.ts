import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery, validateParams } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { queueManager, JobPriority } from '../../core/queue/manager.js';
import { logger } from '../../core/logging/logger.js';
import {
  submitUrlToFraudVault, isFraudVaultConfigured,
  getFraudVaultSubmission, getFraudVaultReport, listFraudVaultSubmissions,
  getFraudVaultAnalysisJobs, getFraudVaultDetectionResults, searchFraudVault,
  getFraudVaultDashboard,
} from '../../services/integration/fraudvault-service.js';
import {
  isSbomVisualizerConfigured, sbomHealth, parseSbom, parseSbomFromUrl,
  scanSbom, assessSbom, getSbomReport, exportSarif, getSbomSources,
  listSbomScans, getSbomScan,
} from '../../services/integration/sbom-service.js';

export const advancedScanRouter = Router();

// ==========================================
// Binary/Mobile scans (M5i)
// ==========================================

function detectArtifactType(artifactPath: string): string {
  const ext = artifactPath.replace(/\?.*$/, '').split('.').pop()?.toLowerCase() || '';
  const map: Record<string, string> = {
    jar: 'jar', war: 'war', ear: 'ear', aar: 'aar',
    dll: 'dll', exe: 'exe', so: 'elf', elf: 'elf',
    wasm: 'wasm', apk: 'apk', ipa: 'ipa', aab: 'apk',
  };
  return map[ext] || 'exe';
}

const launchBinaryScanSchema = z.object({
  artifactPath: z.string().min(1),
  artifactType: z.enum(['jar', 'war', 'ear', 'aar', 'dll', 'exe', 'elf', 'macho', 'wasm', 'apk', 'ipa']).optional(),
  projectId: z.string().uuid().optional(),
  name: z.string().min(1).max(255).optional(),
  options: z.object({
    enableDecompilation: z.boolean().optional().default(false),
    enableSecretsScan: z.boolean().optional().default(true),
    enableMalwareScan: z.boolean().optional().default(false),
    maxFileSizeMb: z.number().min(1).max(500).optional().default(100),
  }).optional().default({}),
  priority: z.enum(['low', 'normal', 'high', 'critical']).optional().default('normal'),
});

advancedScanRouter.get('/binary-scans',
  requirePermission(Permission.SCAN_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    projectId: z.string().uuid().optional(),
    artifactType: z.enum(['jar', 'war', 'ear', 'aar', 'dll', 'exe', 'elf', 'macho', 'wasm', 'apk', 'ipa']).optional(),
    status: z.enum(['queued', 'analyzing', 'completed', 'failed', 'cancelled']).optional(),
    sortBy: z.enum(['artifact_type', 'artifact_path', 'created_at', 'status', 'severity_score']).optional().default('created_at'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, artifactType, status, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['bs.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`bs.project_id = $${idx++}`); params.push(projectId); }
      if (artifactType) { conditions.push(`bs.artifact_type = $${idx++}`); params.push(artifactType); }
      if (status) { conditions.push(`bs.status = $${idx++}`); params.push(status); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM binary_scans bs WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT bs.*, p.name as project_name,
                (SELECT COUNT(*) FROM binary_findings bf WHERE bf.scan_id = bs.id) as finding_count,
                (SELECT COUNT(*) FROM binary_findings bf WHERE bf.scan_id = bs.id AND bf.severity IN ('critical','high')) as high_risk_count
         FROM binary_scans bs
         LEFT JOIN projects p ON bs.project_id = p.id
         WHERE ${where}
         ORDER BY bs.${sortBy === 'artifact_type' ? 'artifact_type' : sortBy === 'artifact_path' ? 'artifact_path' : sortBy === 'status' ? 'status' : sortBy === 'severity_score' ? 'severity_score' : 'created_at'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.post('/binary-scans',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(launchBinaryScanSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanId = uuidv4();
      const { artifactPath, projectId, name, options, priority } = req.body;
      const artifactType = req.body.artifactType || detectArtifactType(artifactPath);

      if (projectId) {
        const projectCheck = await query('SELECT id FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [projectId, req.orgId]);
        if (projectCheck.rows.length === 0) throw AppError.notFound('Project not found');
      }

      await query(
        `INSERT INTO binary_scans (id, org_id, project_id, name, artifact_type, artifact_path,
          options, status, severity_score, started_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'queued',0,$8,NOW(),NOW())`,
        [scanId, req.orgId, projectId, name || `Binary scan: ${artifactPath}`, artifactType, artifactPath,
          JSON.stringify(options), req.userId],
      );

      const priorityMap: Record<string, JobPriority> = {
        low: JobPriority.LOW, normal: JobPriority.NORMAL,
        high: JobPriority.HIGH, critical: JobPriority.CRITICAL,
      };

      await queueManager.addJob(
        'binary-scan' as any,
        `binary-scan:${scanId}`,
        {
          scanId, artifactPath, artifactType, projectId, name, options,
          userId: req.userId, organizationId: req.orgId,
        } as Record<string, unknown>,
        priorityMap[priority] || JobPriority.NORMAL,
      );

      // Forward to FraudVault for deep analysis if configured and artifact is a URL
      if (isFraudVaultConfigured() && /^https?:\/\//i.test(artifactPath)) {
        submitUrlToFraudVault(artifactPath).then((sub) => {
          if (sub?.id) {
            query(
              `UPDATE binary_scans SET metadata = COALESCE(metadata, '{}'::jsonb) || $2::jsonb WHERE id = $1`,
              [scanId, JSON.stringify({ fraudvault_submission_id: sub.id })],
            ).catch(() => {});
          }
        }).catch(() => {});
      }

      logger.info({ scanId, artifactType, artifactPath }, 'Binary scan launched');
      res.status(201).json({ id: scanId, status: 'queued', artifactType });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/binary-scans/:id',
  requirePermission(Permission.SCAN_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanResult = await query(
        `SELECT bs.*, p.name as project_name
         FROM binary_scans bs LEFT JOIN projects p ON bs.project_id = p.id
         WHERE bs.id = $1 AND bs.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (scanResult.rows.length === 0) throw AppError.notFound('Binary scan not found');

      const findingsResult = await query(
        `SELECT bf.*
         FROM binary_findings bf
         WHERE bf.scan_id = $1
         ORDER BY bf.severity DESC, bf.cvss_score DESC NULLS LAST`,
        [req.params.id],
      );

      res.json({
        ...scanResult.rows[0] as Record<string, unknown>,
        findings: findingsResult.rows,
      });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/binary-scans/:id/fraudvault',
  requirePermission(Permission.SCAN_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanResult = await query(
        `SELECT metadata FROM binary_scans WHERE id = $1 AND org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (scanResult.rows.length === 0) throw AppError.notFound('Binary scan not found');

      const meta = (scanResult.rows[0] as Record<string, unknown>).metadata as Record<string, unknown> | null;
      const fvId = meta?.fraudvault_submission_id as string | undefined;
      if (!fvId) {
        res.json({ configured: isFraudVaultConfigured(), submitted: false });
        return;
      }

      const { getFraudVaultSubmission, getFraudVaultReport } = await import('../../services/integration/fraudvault-service.js');
      const [submission, report] = await Promise.all([
        getFraudVaultSubmission(fvId),
        getFraudVaultReport(fvId),
      ]);

      res.json({
        configured: true,
        submitted: true,
        submissionId: fvId,
        status: submission?.status,
        threatLevel: submission?.threat_level ?? submission?.threatLevel,
        report: report || null,
      });
    } catch (err) { next(err); }
  },
);

// ==========================================
// FraudVault direct API (proxied)
// ==========================================

advancedScanRouter.get('/fraudvault/status',
  requirePermission(Permission.SCAN_READ),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      res.json({ configured: isFraudVaultConfigured() });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/fraudvault/dashboard',
  requirePermission(Permission.SCAN_READ),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      if (!isFraudVaultConfigured()) throw AppError.badRequest('FraudVault is not configured');
      const data = await getFraudVaultDashboard();
      if (!data) throw AppError.internal('Failed to reach FraudVault');
      res.json({ data });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/fraudvault/submissions',
  requirePermission(Permission.SCAN_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    pageSize: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('25'),
    status: z.string().optional(),
    threatLevel: z.string().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!isFraudVaultConfigured()) throw AppError.badRequest('FraudVault is not configured');
      const { page, pageSize, status, threatLevel } = req.query as any;
      const data = await listFraudVaultSubmissions({ page: Number(page), pageSize: Number(pageSize), status, threatLevel });
      if (!data) throw AppError.internal('Failed to reach FraudVault');
      res.json({ data });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/fraudvault/submissions/:submissionId',
  requirePermission(Permission.SCAN_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!isFraudVaultConfigured()) throw AppError.badRequest('FraudVault is not configured');
      const data = await getFraudVaultSubmission(req.params.submissionId!);
      if (!data) throw AppError.notFound('Submission not found');
      res.json({ data });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/fraudvault/submissions/:submissionId/report',
  requirePermission(Permission.SCAN_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!isFraudVaultConfigured()) throw AppError.badRequest('FraudVault is not configured');
      const data = await getFraudVaultReport(req.params.submissionId!);
      if (!data) throw AppError.notFound('Report not found');
      res.json({ data });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/fraudvault/submissions/:submissionId/jobs',
  requirePermission(Permission.SCAN_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!isFraudVaultConfigured()) throw AppError.badRequest('FraudVault is not configured');
      const data = await getFraudVaultAnalysisJobs(req.params.submissionId!);
      if (!data) throw AppError.notFound('Jobs not found');
      res.json({ data });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/fraudvault/submissions/:submissionId/detection',
  requirePermission(Permission.SCAN_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!isFraudVaultConfigured()) throw AppError.badRequest('FraudVault is not configured');
      const data = await getFraudVaultDetectionResults(req.params.submissionId!);
      if (!data) throw AppError.notFound('Detection results not found');
      res.json({ data });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/fraudvault/search',
  requirePermission(Permission.SCAN_READ),
  validateQuery(z.object({
    q: z.string().min(1),
    field: z.enum(['all', 'hash', 'filename', 'domain', 'url', 'ip']).optional().default('all'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!isFraudVaultConfigured()) throw AppError.badRequest('FraudVault is not configured');
      const { q, field } = req.query as any;
      const data = await searchFraudVault(q, field);
      if (!data) throw AppError.internal('Failed to reach FraudVault');
      res.json({ data });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.post('/fraudvault/submit-url',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(z.object({
    url: z.string().url(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!isFraudVaultConfigured()) throw AppError.badRequest('FraudVault is not configured');
      const result = await submitUrlToFraudVault(req.body.url);
      if (!result) throw AppError.internal('FraudVault submission failed');
      res.status(201).json({ data: result });
    } catch (err) { next(err); }
  },
);

// ==========================================
// DAST enterprise scan (M6a-M6g)
// ==========================================

advancedScanRouter.post('/dast-enterprise',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(z.object({
    targetUrl: z.string().url(),
    authProfile: z.object({
      type: z.enum(['form', 'oauth2', 'jwt', 'apikey', 'mtls']),
      loginUrl: z.string().optional(),
      credentials: z.object({}).passthrough().optional(),
    }).optional(),
    enableBrowserCrawl: z.boolean().optional().default(true),
    enableWAFEvasion: z.boolean().optional().default(true),
    projectId: z.string().uuid().optional(),
    priority: z.enum(['low', 'normal', 'high', 'critical']).optional().default('normal'),
    options: z.object({
      maxCrawlDepth: z.number().min(1).max(20).optional().default(5),
      maxCrawlPages: z.number().min(1).max(10000).optional().default(500),
      includePaths: z.array(z.string()).optional(),
      excludePaths: z.array(z.string()).optional(),
      customHeaders: z.record(z.string()).optional(),
      attackSpeed: z.enum(['slow', 'normal', 'fast', 'aggressive']).optional().default('normal'),
    }).optional().default({}),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanId = uuidv4();
      const { targetUrl, authProfile, enableBrowserCrawl, enableWAFEvasion, projectId, priority, options } = req.body;

      const enterpriseOptions = { authProfile, enableBrowserCrawl, enableWAFEvasion, ...options };

      await query(
        `INSERT INTO scans (id, org_id, project_id, scan_type, name, status, options, started_by, created_at, updated_at)
         VALUES ($1,$2,$3,'dast',$4,'queued',$5,$6,NOW(),NOW())`,
        [scanId, req.orgId, projectId, `Enterprise DAST: ${targetUrl}`, JSON.stringify(enterpriseOptions), req.userId],
      );

      const priorityMap: Record<string, JobPriority> = {
        low: JobPriority.LOW, normal: JobPriority.NORMAL,
        high: JobPriority.HIGH, critical: JobPriority.CRITICAL,
      };

      await queueManager.addJob(
        'dast-enterprise' as any,
        `dast-enterprise:${scanId}`,
        {
          scanId, targetUrl, authProfile, enableBrowserCrawl, enableWAFEvasion, projectId, options,
          userId: req.userId, organizationId: req.orgId,
        } as Record<string, unknown>,
        priorityMap[priority] || JobPriority.NORMAL,
      );

      logger.info({ scanId, targetUrl, projectId }, 'Enterprise DAST scan launched');
      res.status(201).json({ id: scanId, status: 'queued', scanType: 'dast-enterprise' });
    } catch (err) { next(err); }
  },
);

// ==========================================
// API Protocol scan (M5k)
// ==========================================

advancedScanRouter.post('/api-protocol-scan',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(z.object({
    grpcEndpoint: z.string().url().optional(),
    graphqlEndpoint: z.string().url().optional(),
    wsEndpoint: z.string().url().optional(),
    soapWSDL: z.string().url().optional(),
    restEndpoint: z.string().url().optional(),
    projectId: z.string().uuid().optional(),
    priority: z.enum(['low', 'normal', 'high', 'critical']).optional().default('normal'),
    options: z.object({
      enableAuthBypass: z.boolean().optional().default(true),
      enableInjectionTests: z.boolean().optional().default(true),
      enableRateLimitTests: z.boolean().optional().default(false),
      customSpecPath: z.string().optional(),
    }).optional().default({}),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanId = uuidv4();
      const { grpcEndpoint, graphqlEndpoint, wsEndpoint, soapWSDL, restEndpoint, projectId, priority, options } = req.body;

      const protocolTargets = { grpcEndpoint, graphqlEndpoint, wsEndpoint, soapWSDL, restEndpoint };

      await query(
        `INSERT INTO scans (id, org_id, project_id, scan_type, name, status, options, started_by, created_at, updated_at)
         VALUES ($1,$2,$3,'api',$4,'queued',$5,$6,NOW(),NOW())`,
        [scanId, req.orgId, projectId, 'API Protocol Security Scan', JSON.stringify({ targets: protocolTargets, options }), req.userId],
      );

      const priorityMap: Record<string, JobPriority> = {
        low: JobPriority.LOW, normal: JobPriority.NORMAL,
        high: JobPriority.HIGH, critical: JobPriority.CRITICAL,
      };

      await queueManager.addJob(
        'apiprotocol-scan' as any,
        `apiprotocol:${scanId}`,
        {
          scanId, targets: protocolTargets, projectId, options,
          userId: req.userId, organizationId: req.orgId,
        } as Record<string, unknown>,
        priorityMap[priority] || JobPriority.NORMAL,
      );

      logger.info({ scanId, endpoints: Object.entries(protocolTargets).filter(([,v]) => v).map(([k]) => k) }, 'API protocol scan launched');
      res.status(201).json({ id: scanId, status: 'queued', scanType: 'api-protocol' });
    } catch (err) { next(err); }
  },
);

// ==========================================
// Hotspot review (M14e)
// ==========================================

advancedScanRouter.get('/hotspots',
  requirePermission(Permission.FINDING_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(200)).optional().default('50'),
    projectId: z.string().uuid().optional(),
    riskLevel: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    status: z.enum(['open', 'reviewing', 'reviewed', 'accepted', 'mitigated', 'false_positive']).optional(),
    hotspotType: z.string().optional(),
    assignedTo: z.string().uuid().optional(),
    sortBy: z.enum(['risk_level', 'created_at', 'priority_score', 'hotspot_type']).optional().default('risk_level'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, riskLevel, status, hotspotType, assignedTo, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['sh.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`sh.project_id = $${idx++}`); params.push(projectId); }
      if (riskLevel) { conditions.push(`sh.risk_level = $${idx++}`); params.push(riskLevel); }
      if (status) { conditions.push(`sh.status = $${idx++}`); params.push(status); }
      if (hotspotType) { conditions.push(`sh.hotspot_type = $${idx++}`); params.push(hotspotType); }
      if (assignedTo) { conditions.push(`sh.assigned_to = $${idx++}`); params.push(assignedTo); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM security_hotspots sh WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT sh.*, p.name as project_name, u.name as assignee_name
         FROM security_hotspots sh
         LEFT JOIN projects p ON sh.project_id = p.id
         LEFT JOIN users u ON sh.assigned_to = u.id
         WHERE ${where}
         ORDER BY sh.${sortBy === 'priority_score' ? 'priority_score' : sortBy === 'hotspot_type' ? 'hotspot_type' : sortBy === 'risk_level' ? 'risk_level' : 'created_at'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.patch('/hotspots/:id',
  requirePermission(Permission.FINDING_UPDATE),
  validateParams(z.object({ id: z.string().uuid() })),
  validateBody(z.object({
    status: z.enum(['open', 'reviewing', 'reviewed', 'accepted', 'mitigated', 'false_positive']).optional(),
    assignedTo: z.string().uuid().nullable().optional(),
    reviewNotes: z.string().max(5000).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const existing = await query('SELECT id FROM security_hotspots WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (existing.rows.length === 0) throw AppError.notFound('Hotspot not found');

      const { status, assignedTo, reviewNotes } = req.body;
      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      if (status) { updates.push(`status = $${idx++}`); params.push(status); }
      if (assignedTo !== undefined) { updates.push(`assigned_to = $${idx++}`); params.push(assignedTo); }
      if (reviewNotes) { updates.push(`review_notes = $${idx++}`); params.push(reviewNotes); }

      if (updates.length > 0) {
        updates.push('updated_at = NOW()');
        params.push(req.params.id);
        await query(`UPDATE security_hotspots SET ${updates.join(', ')} WHERE id = $${idx}`, params);
      }

      logger.info({ hotspotId: req.params.id, status }, 'Hotspot updated');
      res.json({ message: 'Hotspot updated successfully' });
    } catch (err) { next(err); }
  },
);

// ==========================================
// Security debt (M14f)
// ==========================================

advancedScanRouter.get('/security-debt',
  requirePermission(Permission.FINDING_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('30'),
    projectId: z.string().uuid().optional(),
    sortBy: z.enum(['snapshot_date', 'debt_score', 'critical_count', 'high_count', 'total_findings']).optional().default('snapshot_date'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['sds.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`sds.project_id = $${idx++}`); params.push(projectId); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM security_debt_snapshots sds WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT sds.*, p.name as project_name
         FROM security_debt_snapshots sds
         LEFT JOIN projects p ON sds.project_id = p.id
         WHERE ${where}
         ORDER BY sds.${sortBy === 'debt_score' ? 'debt_score' : sortBy === 'critical_count' ? 'critical_count' : sortBy === 'high_count' ? 'high_count' : sortBy === 'total_findings' ? 'total_findings' : 'snapshot_date'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

// ==========================================
// SLA tracking (M14c)
// ==========================================

advancedScanRouter.get('/sla-status',
  requirePermission(Permission.FINDING_READ),
  validateQuery(z.object({
    projectId: z.string().uuid().optional(),
    includeBreachedOnly: z.string().transform((v) => v === 'true').optional().default('false'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { projectId, includeBreachedOnly } = req.query as any;

      const baseConditions = ['fst.org_id = $1'];
      const baseParams: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { baseConditions.push(`fst.project_id = $${idx++}`); baseParams.push(projectId); }

      const breachCondition = includeBreachedOnly ? ' AND fst.sla_breached = true' : '';

      const summaryResult = await query(
        `SELECT
           COUNT(*) as total_tracked,
           COUNT(*) FILTER (WHERE fst.sla_breached = true) as breached_count,
           COUNT(*) FILTER (WHERE fst.resolved_at IS NULL AND fst.sla_breached = false) as within_sla_count,
           COUNT(*) FILTER (WHERE fst.resolved_at IS NULL AND fst.sla_breached = true) as overdue_count,
           COUNT(*) FILTER (WHERE fst.resolved_at IS NOT NULL) as resolved_count,
           ROUND(AVG(EXTRACT(EPOCH FROM (COALESCE(fst.resolved_at, NOW()) - fst.created_at)) / 3600)::numeric, 1) as avg_resolution_hours,
           ROUND(AVG(EXTRACT(EPOCH FROM (fst.sla_deadline - fst.created_at)) / 3600)::numeric, 1) as avg_sla_hours
         FROM finding_sla_tracking fst
         WHERE ${baseConditions.join(' AND ')}${breachCondition}`,
        baseParams,
      );

      const bySeverityResult = await query(
        `SELECT
           f.severity,
           COUNT(*) as total,
           COUNT(*) FILTER (WHERE fst.sla_breached = true) as breached,
           COUNT(*) FILTER (WHERE fst.resolved_at IS NULL) as active
         FROM finding_sla_tracking fst
         JOIN findings f ON fst.finding_id = f.id
         WHERE ${baseConditions.join(' AND ')}
         GROUP BY f.severity
         ORDER BY f.severity`,
        baseParams,
      );

      res.json({
        summary: summaryResult.rows[0] || { total_tracked: 0, breached_count: 0, within_sla_count: 0, overdue_count: 0, resolved_count: 0 },
        bySeverity: bySeverityResult.rows,
      });
    } catch (err) { next(err); }
  },
);

// ==========================================
// Rule sync (M18, M19)
// ==========================================

advancedScanRouter.get('/rule-sources',
  requirePermission(Permission.SCAN_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'SELECT * FROM rule_sync_sources WHERE org_id = $1 ORDER BY source_name',
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.post('/rule-sources/:id/sync',
  requirePermission(Permission.SCAN_LAUNCH),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const sourceCheck = await query('SELECT id FROM rule_sync_sources WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (sourceCheck.rows.length === 0) throw AppError.notFound('Rule source not found');

      const syncId = uuidv4();
      await query(
        `INSERT INTO rule_sync_history (id, source_id, rules_added, rules_updated, rules_removed, status, synced_at)
         VALUES ($1,$2,$3,$4,$5,'queued',NOW())`,
        [syncId, req.params.id, 0, 0, 0],
      );

      await query('UPDATE rule_sync_sources SET last_synced_at = NOW() WHERE id = $1', [req.params.id]);

      await queueManager.addJob(
        'rule-sync' as any,
        `rule-sync:${req.params.id}`,
        {
          sourceId: req.params.id, syncId,
          organizationId: req.orgId,
        } as Record<string, unknown>,
      );

      logger.info({ sourceId: req.params.id, syncId }, 'Rule sync queued');
      res.json({ message: 'Rule sync queued', syncId, status: 'queued' });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/rule-sync-history',
  requirePermission(Permission.SCAN_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT rsh.*, rss.source_name
         FROM rule_sync_history rsh
         JOIN rule_sync_sources rss ON rsh.source_id = rss.id
         WHERE rss.org_id = $1
         ORDER BY rsh.synced_at DESC
         LIMIT 50`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

// ==========================================
// SBOM Visualizer Integration
// ==========================================

advancedScanRouter.get('/sbom/status',
  requirePermission(Permission.SCAN_READ),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const configured = isSbomVisualizerConfigured();
      if (!configured) { res.json({ configured: false, healthy: false }); return; }
      const health = await sbomHealth();
      res.json({ configured: true, healthy: !!health, version: health?.version });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/sbom/sources',
  requirePermission(Permission.SCAN_READ),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const sources = await getSbomSources();
      if (!sources) throw AppError.internal('Failed to reach SBOM Visualizer');
      res.json({ data: sources });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.post('/sbom/parse',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(z.object({
    raw: z.object({}).passthrough().optional(),
    url: z.string().url().optional(),
  }).refine(d => d.raw || d.url, { message: 'Provide either raw SBOM JSON or a URL' })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = req.body.url
        ? await parseSbomFromUrl(req.body.url)
        : await parseSbom(req.body.raw);
      if (!result) throw AppError.internal('SBOM parse failed');
      res.json({ data: result.sbom });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.post('/sbom/scan',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(z.object({
    sbom: z.object({}).passthrough(),
    options: z.object({
      kev: z.boolean().optional(),
      epss: z.boolean().optional(),
    }).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await scanSbom(req.body.sbom as any, req.body.options);
      if (!result) throw AppError.internal('SBOM vulnerability scan failed');
      res.json({ data: result });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.post('/sbom/assess',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(z.object({
    sbom: z.object({}).passthrough(),
    findings: z.array(z.object({}).passthrough()),
    summary: z.object({}).passthrough(),
    policy: z.enum(['strict', 'standard', 'lenient']).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await assessSbom(
        req.body.sbom as any,
        req.body.findings as any,
        req.body.summary as any,
        req.body.policy,
      );
      if (!result) throw AppError.internal('SBOM risk assessment failed');
      res.json({ data: result.assessment });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.post('/sbom/report',
  requirePermission(Permission.SCAN_READ),
  validateBody(z.object({
    sbom: z.object({}).passthrough(),
    findings: z.array(z.object({}).passthrough()),
    summary: z.object({}).passthrough(),
    assessment: z.object({}).passthrough().nullable().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const html = await getSbomReport(
        req.body.sbom as any,
        req.body.findings as any,
        req.body.summary as any,
        req.body.assessment as any,
      );
      if (!html) throw AppError.internal('SBOM report generation failed');
      res.setHeader('Content-Type', 'text/html');
      res.send(html);
    } catch (err) { next(err); }
  },
);

advancedScanRouter.post('/sbom/export/sarif',
  requirePermission(Permission.SCAN_READ),
  validateBody(z.object({
    sbom: z.object({}).passthrough(),
    findings: z.array(z.object({}).passthrough()),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const sarif = await exportSarif(req.body.sbom as any, req.body.findings as any);
      if (!sarif) throw AppError.internal('SARIF export failed');
      res.json({ data: sarif });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/sbom/scans',
  requirePermission(Permission.SCAN_READ),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const scans = await listSbomScans();
      if (!scans) throw AppError.internal('Failed to list SBOM scans');
      res.json({ data: scans });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.get('/sbom/scans/:scanId',
  requirePermission(Permission.SCAN_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scan = await getSbomScan(req.params.scanId!);
      if (!scan) throw AppError.notFound('SBOM scan not found');
      res.json({ data: scan });
    } catch (err) { next(err); }
  },
);

advancedScanRouter.post('/sbom/full-analysis',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(z.object({
    raw: z.object({}).passthrough().optional(),
    url: z.string().url().optional(),
    policy: z.enum(['strict', 'standard', 'lenient']).optional(),
  }).refine(d => d.raw || d.url, { message: 'Provide either raw SBOM JSON or a URL' })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const parseResult = req.body.url
        ? await parseSbomFromUrl(req.body.url)
        : await parseSbom(req.body.raw);
      if (!parseResult) throw AppError.internal('SBOM parse failed');

      const sbom = parseResult.sbom;
      const scanResult = await scanSbom(sbom);
      if (!scanResult) throw AppError.internal('SBOM vulnerability scan failed');

      const assessResult = await assessSbom(
        sbom, scanResult.findings, scanResult.summary, req.body.policy,
      );

      res.json({
        data: {
          sbom: { id: sbom.id, format: sbom.format, name: sbom.name, componentCount: sbom.components.length },
          scan: { summary: scanResult.summary, scanId: scanResult.scanId, errors: scanResult.errors },
          assessment: assessResult?.assessment || null,
        },
      });
    } catch (err) { next(err); }
  },
);
