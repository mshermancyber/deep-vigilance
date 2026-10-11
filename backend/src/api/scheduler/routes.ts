import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';
import { queueManager, QueueName } from '../../core/queue/manager.js';

export const schedulerRouter = Router();

const createScheduleSchema = z.object({
  name: z.string().min(1).max(200),
  projectId: z.string().uuid(),
  scanType: z.enum(['sast', 'dast', 'api', 'sca', 'secret', 'full']),
  schedule: z.enum(['now', 'hourly', 'daily', 'weekly', 'monthly', 'cron']),
  cronExpression: z.string().optional(),
  timezone: z.string().optional().default('UTC'),
  options: z.object({
    targetUrl: z.string().url().optional(),
    targetPath: z.string().optional(),
    branch: z.string().optional(),
    includePatterns: z.array(z.string()).optional(),
    excludePatterns: z.array(z.string()).optional(),
  }).optional().default({}),
  enabled: z.boolean().optional().default(true),
});

schedulerRouter.get('/',
  requirePermission(Permission.SCHEDULER_VIEW),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    enabled: z.string().transform(v => v === 'true').optional(),
    projectId: z.string().uuid().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, enabled, projectId } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['sch.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (enabled !== undefined) { conditions.push(`sch.enabled = $${idx++}`); params.push(enabled); }
      if (projectId) { conditions.push(`sch.project_id = $${idx++}`); params.push(projectId); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM scheduled_scans sch WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT sch.*, p.name as project_name
         FROM scheduled_scans sch JOIN projects p ON sch.project_id = p.id
         WHERE ${where}
         ORDER BY sch.created_at DESC
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

schedulerRouter.post('/',
  requirePermission(Permission.SCHEDULER_MANAGE),
  validateBody(createScheduleSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, projectId, scanType, schedule, cronExpression, timezone, options, enabled } = req.body;
      const scheduleId = uuidv4();

      const projectResult = await query('SELECT id FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [projectId, req.orgId]);
      if (projectResult.rows.length === 0) throw AppError.notFound('Project not found');

      await query(
        `INSERT INTO scheduled_scans (id, org_id, project_id, name, scan_type, schedule, cron_expression, timezone, options, enabled, created_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())`,
        [scheduleId, req.orgId, projectId, name, scanType, schedule, cronExpression, timezone, JSON.stringify(options), enabled, req.userId],
      );

      if (schedule === 'now') {
        const queueMap: Record<string, QueueName> = {
          sast: QueueName.SAST_SCAN, dast: QueueName.DAST_SCAN,
          api: QueueName.API_SCAN, sca: QueueName.SCA_SCAN, secret: QueueName.SECRET_SCAN, full: QueueName.SAST_SCAN,
        };
        const queueName = queueMap[scanType as string] || QueueName.SAST_SCAN;
        await queueManager.addJob(
          queueName,
          `scheduled-scan:${scheduleId}`,
          { scanId: scheduleId, projectId, options, userId: req.userId, organizationId: req.orgId },
        );
      }

      logger.info({ scheduleId, name, schedule }, 'Scan schedule created');
      res.status(201).json({ id: scheduleId, name, schedule });
    } catch (err) { next(err); }
  },
);

schedulerRouter.patch('/:id',
  requirePermission(Permission.SCHEDULER_MANAGE),
  validateBody(z.object({
    name: z.string().min(1).max(200).optional(),
    schedule: z.enum(['hourly', 'daily', 'weekly', 'monthly', 'cron']).optional(),
    cronExpression: z.string().optional(),
    enabled: z.boolean().optional(),
    options: z.object({}).passthrough().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      const fields = ['name', 'schedule', 'cron_expression', 'enabled', 'options'];
      for (const field of fields) {
        const val = field === 'cron_expression' ? req.body.cronExpression :
                    field === 'options' ? (req.body.options ? JSON.stringify(req.body.options) : undefined) :
                    req.body[field];
        if (val !== undefined) {
          updates.push(`${field} = $${idx++}`);
          params.push(val);
        }
      }

      if (updates.length > 0) {
        updates.push('updated_at = NOW()');
        params.push(req.params.id, req.orgId);
        await query(`UPDATE scheduled_scans SET ${updates.join(', ')} WHERE id = $${idx} AND org_id = $${idx + 1}`, params);
      }

      res.json({ message: 'Schedule updated' });
    } catch (err) { next(err); }
  },
);

schedulerRouter.delete('/:id',
  requirePermission(Permission.SCHEDULER_MANAGE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query('DELETE FROM scheduled_scans WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (result.rowCount === 0) throw AppError.notFound('Schedule not found');
      res.json({ message: 'Schedule deleted' });
    } catch (err) { next(err); }
  },
);
