import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery, validateParams } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';
import { queueManager, QueueName, JobPriority, ScanJob } from '../../core/queue/manager.js';

export const scansRouter = Router();

const launchScanSchema = z.object({
  projectId: z.string().uuid(),
  scanType: z.enum(['sast', 'dast', 'api', 'sca', 'secret', 'full']),
  name: z.string().min(1).max(200),
  options: z.object({
    targetPath: z.string().optional(),
    targetUrl: z.string().url().optional(),
    // SAST: clone & scan a git repository (http/https). gitToken is injected into
    // the clone URL for private repos and is never logged.
    repoUrl: z.string().url().max(2000).optional(),
    gitToken: z.string().max(500).optional(),
    branch: z.string().max(255).optional(),
    includePatterns: z.array(z.string()).optional(),
    excludePatterns: z.array(z.string()).optional(),
    maxDepth: z.number().min(1).max(100).optional(),
    authProfile: z.string().uuid().optional(),
    customHeaders: z.record(z.string()).optional(),
    scanConfig: z.record(z.unknown()).optional(),
    swaggerDoc: z.record(z.unknown()).optional(),
    openApiSpec: z.record(z.unknown()).optional(),
  }).optional().default({}),
  priority: z.enum(['low', 'normal', 'high', 'critical']).optional().default('normal'),
});

scansRouter.get('/',
  requirePermission(Permission.SCAN_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    projectId: z.string().uuid().optional(),
    scanType: z.enum(['sast', 'dast', 'api', 'sca', 'secret', 'full']).optional(),
    status: z.enum(['queued', 'running', 'completed', 'failed', 'cancelled', 'paused']).optional(),
    sortBy: z.enum(['name', 'created_at', 'status']).optional().default('created_at'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, scanType, status, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['s.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`s.project_id = $${idx++}`); params.push(projectId); }
      if (scanType) { conditions.push(`s.scan_type = $${idx++}`); params.push(scanType); }
      if (status) { conditions.push(`s.status = $${idx++}`); params.push(status); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM scans s WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT s.*, p.name as project_name,
                (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) as finding_count
         FROM scans s JOIN projects p ON s.project_id = p.id
         WHERE ${where}
         ORDER BY s.${sortBy === 'name' ? 'name' : sortBy === 'status' ? 'status' : 'created_at'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

scansRouter.get('/:id',
  requirePermission(Permission.SCAN_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT s.*, p.name as project_name
         FROM scans s JOIN projects p ON s.project_id = p.id
         WHERE s.id = $1 AND s.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Scan not found');
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

scansRouter.post('/launch',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(launchScanSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { projectId, scanType, name, options, priority } = req.body;
      const scanId = uuidv4();

      const projectResult = await query('SELECT id, name FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [projectId, req.orgId]);
      if (projectResult.rows.length === 0) throw AppError.notFound('Project not found');

      await query(
        `INSERT INTO scans (id, org_id, project_id, scan_type, name, status, options, started_by, started_at, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,'queued',$6,$7,NOW(),NOW(),NOW())`,
        [scanId, req.orgId, projectId, scanType, name, JSON.stringify(options), req.userId],
      );

      const priorityMap: Record<string, JobPriority> = {
        low: JobPriority.LOW, normal: JobPriority.NORMAL, high: JobPriority.HIGH, critical: JobPriority.CRITICAL,
      };

      const scanJob: ScanJob = {
        scanId, projectId, targetUrl: options.targetUrl,
        targetPath: options.targetPath, options, userId: req.userId!, organizationId: req.orgId!,
      };

      const queueMap: Record<string, QueueName> = {
        sast: QueueName.SAST_SCAN, dast: QueueName.DAST_SCAN,
        api: QueueName.API_SCAN, sca: QueueName.SCA_SCAN,
        secret: QueueName.SECRET_SCAN, full: QueueName.SAST_SCAN,
      };

      const queueName = queueMap[scanType] || QueueName.SAST_SCAN;
      await queueManager.addJob(queueName, `scan:${scanId}`, scanJob as unknown as Record<string, unknown>, priorityMap[priority] || JobPriority.NORMAL);

      if (scanType === 'full') {
        await queueManager.addJob(QueueName.DAST_SCAN, `scan:${scanId}`, scanJob as unknown as Record<string, unknown>, priorityMap[priority] || JobPriority.NORMAL);
        await queueManager.addJob(QueueName.API_SCAN, `scan:${scanId}`, scanJob as unknown as Record<string, unknown>, priorityMap[priority] || JobPriority.NORMAL);
        await queueManager.addJob(QueueName.SCA_SCAN, `scan:${scanId}`, scanJob as unknown as Record<string, unknown>, priorityMap[priority] || JobPriority.NORMAL);
        await queueManager.addJob(QueueName.SECRET_SCAN, `scan:${scanId}`, scanJob as unknown as Record<string, unknown>, priorityMap[priority] || JobPriority.NORMAL);
      }

      logger.info({ scanId, projectId, scanType }, 'Scan launched');
      res.status(201).json({ id: scanId, status: 'queued', scanType });
    } catch (err) { next(err); }
  },
);

scansRouter.post('/:id/cancel',
  requirePermission(Permission.SCAN_CANCEL),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query('SELECT * FROM scans WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (result.rows.length === 0) throw AppError.notFound('Scan not found');

      const scan = result.rows[0] as Record<string, unknown>;
      if (!['queued', 'running', 'paused'].includes(scan.status as string)) {
        throw AppError.badRequest(`Cannot cancel scan with status: ${scan.status}`);
      }

      const jobName = `scan:${req.params.id}`;
      await Promise.all([
        queueManager.cancelJob(QueueName.SAST_SCAN, jobName),
        queueManager.cancelJob(QueueName.DAST_SCAN, jobName),
        queueManager.cancelJob(QueueName.API_SCAN, jobName),
        queueManager.cancelJob(QueueName.SCA_SCAN, jobName),
        queueManager.cancelJob(QueueName.SECRET_SCAN, jobName),
      ]);
      await query(`UPDATE scans SET status = 'cancelled', completed_at = NOW(), updated_at = NOW() WHERE id = $1 AND org_id = $2`, [req.params.id, req.orgId]);

      logger.info({ scanId: req.params.id }, 'Scan cancelled');
      res.json({ message: 'Scan cancelled' });
    } catch (err) { next(err); }
  },
);

scansRouter.get('/:id/findings',
  requirePermission(Permission.SCAN_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanCheck = await query('SELECT id FROM scans WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (scanCheck.rows.length === 0) throw AppError.notFound('Scan not found');

      const result = await query(
        `SELECT f.* FROM findings f
         WHERE f.scan_id = $1 AND f.org_id = $2
         ORDER BY f.severity_rank ASC, f.created_at DESC`,
        [req.params.id, req.orgId],
      );
      res.json({ data: result.rows, total: result.rows.length });
    } catch (err) { next(err); }
  },
);
