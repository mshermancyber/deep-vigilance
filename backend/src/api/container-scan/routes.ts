import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery, validateParams } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { queueManager, JobPriority } from '../../core/queue/manager.js';
import { logger } from '../../core/logging/logger.js';

export const containerScanRouter = Router();

const launchScanSchema = z.object({
  imageName: z.string().min(1).max(500),
  registry: z.string().max(500).optional(),
  tag: z.string().max(200).optional(),
  projectId: z.string().uuid().optional(),
  digest: z.string().optional(),
  platform: z.string().optional(),
  priority: z.enum(['low', 'normal', 'high', 'critical']).optional().default('normal'),
  options: z.object({
    enableSecretsScan: z.boolean().optional().default(true),
    enableMalwareScan: z.boolean().optional().default(false),
    enableLicenseScan: z.boolean().optional().default(true),
    scanLayers: z.boolean().optional().default(true),
    sbomFormat: z.enum(['cyclonedx', 'spdx']).optional(),
  }).optional().default({}),
});

containerScanRouter.get('/scans',
  requirePermission(Permission.SCAN_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    projectId: z.string().uuid().optional(),
    imageName: z.string().max(500).optional(),
    registry: z.string().max(500).optional(),
    status: z.enum(['queued', 'scanning', 'analyzing', 'completed', 'failed', 'cancelled']).optional(),
    sortBy: z.enum(['image_name', 'created_at', 'status', 'severity_score']).optional().default('created_at'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, imageName, registry, status, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['cs.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`cs.project_id = $${idx++}`); params.push(projectId); }
      if (imageName) { conditions.push(`cs.image_name ILIKE $${idx++}`); params.push(`%${imageName}%`); }
      if (registry) { conditions.push(`cs.registry = $${idx++}`); params.push(registry); }
      if (status) { conditions.push(`cs.status = $${idx++}`); params.push(status); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM container_scans cs WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT cs.*, p.name as project_name,
                (SELECT COUNT(*) FROM container_findings cf WHERE cf.scan_id = cs.id) as finding_count,
                (SELECT COUNT(*) FROM container_findings cf WHERE cf.scan_id = cs.id AND cf.severity IN ('critical','high')) as high_risk_count
         FROM container_scans cs
         LEFT JOIN projects p ON cs.project_id = p.id
         WHERE ${where}
         ORDER BY cs.${sortBy === 'image_name' ? 'image_name' : sortBy === 'status' ? 'status' : sortBy === 'severity_score' ? 'severity_score' : 'created_at'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

containerScanRouter.post('/scans',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(launchScanSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanId = uuidv4();
      const { imageName, registry, tag, projectId, digest, platform, priority, options } = req.body;

      if (projectId) {
        const projectCheck = await query('SELECT id FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [projectId, req.orgId]);
        if (projectCheck.rows.length === 0) throw AppError.notFound('Project not found');
      }

      await query(
        `INSERT INTO container_scans (id, org_id, project_id, image_name, registry, tag, digest, platform,
          options, status, severity_score, started_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'queued',0,$10,NOW(),NOW())`,
        [scanId, req.orgId, projectId, imageName, registry || null, tag || null,
          digest || null, platform || null, JSON.stringify(options), req.userId],
      );

      const priorityMap: Record<string, JobPriority> = {
        low: JobPriority.LOW, normal: JobPriority.NORMAL,
        high: JobPriority.HIGH, critical: JobPriority.CRITICAL,
      };

      await queueManager.addJob(
        'container-scan' as any,
        `container-scan:${scanId}`,
        {
          scanId, imageName, registry, tag, projectId, digest, platform, options,
          userId: req.userId, organizationId: req.orgId,
        } as Record<string, unknown>,
        priorityMap[priority] || JobPriority.NORMAL,
      );

      logger.info({ scanId, imageName, registry: registry || 'dockerhub' }, 'Container scan launched');
      res.status(201).json({ id: scanId, status: 'queued', imageName });
    } catch (err) { next(err); }
  },
);

containerScanRouter.get('/scans/:id',
  requirePermission(Permission.SCAN_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanResult = await query(
        `SELECT cs.*, p.name as project_name
         FROM container_scans cs
         LEFT JOIN projects p ON cs.project_id = p.id
         WHERE cs.id = $1 AND cs.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (scanResult.rows.length === 0) throw AppError.notFound('Container scan not found');

      const findingsResult = await query(
        `SELECT cf.*, cf.installed_version AS package_version, cf.cve_id AS vulnerability_id
         FROM container_findings cf
         WHERE cf.scan_id = $1
         ORDER BY cf.severity DESC, cf.cvss_score DESC NULLS LAST`,
        [req.params.id],
      );

      const summaryResult = await query(
        `SELECT
           COUNT(*) as total_findings,
           COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
           COUNT(*) FILTER (WHERE severity = 'high') as high_count,
           COUNT(*) FILTER (WHERE severity = 'medium') as medium_count,
           COUNT(*) FILTER (WHERE severity = 'low') as low_count,
           MAX(cvss_score) as max_cvss,
           AVG(cvss_score) FILTER (WHERE cvss_score > 0) as avg_cvss,
           COUNT(DISTINCT cf.package_name) as affected_packages
         FROM container_findings cf
         WHERE cf.scan_id = $1`,
        [req.params.id],
      );

      res.json({
        ...scanResult.rows[0] as Record<string, unknown>,
        findings: findingsResult.rows,
        summary: summaryResult.rows[0] || { total_findings: 0 },
      });
    } catch (err) { next(err); }
  },
);

containerScanRouter.get('/scans/:id/findings',
  requirePermission(Permission.SCAN_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  validateQuery(z.object({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(500)).optional().default('200'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanCheck = await query(
        'SELECT id FROM container_scans WHERE id = $1 AND org_id = $2',
        [req.params.id, req.orgId],
      );
      if (scanCheck.rows.length === 0) throw AppError.notFound('Container scan not found');

      const { severity, page, limit } = req.query as any;
      const conditions = ['cf.scan_id = $1'];
      const params: unknown[] = [req.params.id];
      let idx = 2;
      if (severity) { conditions.push(`cf.severity = $${idx++}`); params.push(severity); }
      const where = conditions.join(' AND ');
      const offset = (Number(page) - 1) * Number(limit);

      const countResult = await query(`SELECT COUNT(*) FROM container_findings cf WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string, 10);

      const result = await query(
        `SELECT cf.*
         FROM container_findings cf
         WHERE ${where}
         ORDER BY
           CASE cf.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
           cf.cvss_score DESC NULLS LAST
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

containerScanRouter.get('/scans/:id/sbom',
  requirePermission(Permission.SCAN_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanCheck = await query(
        'SELECT id, image_name, tag FROM container_scans WHERE id = $1 AND org_id = $2',
        [req.params.id, req.orgId],
      );
      if (scanCheck.rows.length === 0) throw AppError.notFound('Container scan not found');
      const scan = scanCheck.rows[0] as Record<string, unknown>;
      const imageName = scan.tag ? `${scan.image_name}:${scan.tag}` : scan.image_name as string;

      await queueManager.addJob(
        'sbom-generation' as any,
        `sbom:${req.params.id}:${Date.now()}`,
        {
          scanId: req.params.id,
          projectId: req.params.id,
          imageName,
          format: req.query.format || 'cyclonedx',
          organizationId: req.orgId,
        } as Record<string, unknown>,
      );

      logger.info({ scanId: req.params.id, imageName, format: req.query.format || 'cyclonedx' }, 'Container SBOM generation queued');
      res.json({ message: 'SBOM generation queued', scanId: req.params.id });
    } catch (err) { next(err); }
  },
);
