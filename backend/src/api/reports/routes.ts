import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';
import { queueManager, QueueName } from '../../core/queue/manager.js';
import { getConfig } from '../../config/index.js';

export const reportsRouter = Router();

const generateReportSchema = z.object({
  name: z.string().min(1).max(200),
  projectId: z.string().uuid(),
  templateType: z.enum(['executive', 'developer', 'compliance', 'owasp', 'api', 'sast', 'dast', 'sca', 'code-review', 'binary', 'summary']),
  format: z.enum(['pdf', 'html', 'json', 'csv', 'markdown']),
  filters: z.object({
    severity: z.array(z.enum(['critical', 'high', 'medium', 'low', 'info'])).optional(),
    status: z.array(z.enum(['open', 'in_progress', 'resolved', 'closed', 'false_positive', 'wont_fix'])).optional(),
    dateFrom: z.string().datetime().optional(),
    dateTo: z.string().datetime().optional(),
    includeEvidence: z.boolean().optional().default(true),
    includeRecommendations: z.boolean().optional().default(true),
    includeCVSS: z.boolean().optional().default(true),
    includeEPSS: z.boolean().optional().default(false),
  }).optional().default({}),
});

reportsRouter.get('/',
  requirePermission(Permission.REPORT_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    projectId: z.string().uuid().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['r.org_id = $1'];
      const params: unknown[] = [req.orgId];
      if (projectId) { conditions.push('r.project_id = $2'); params.push(projectId); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM reports r WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT r.*, p.name as project_name
         FROM reports r JOIN projects p ON r.project_id = p.id
         WHERE ${where}
         ORDER BY r.created_at DESC
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

reportsRouter.get('/:id',
  requirePermission(Permission.REPORT_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT r.*, p.name as project_name FROM reports r
         JOIN projects p ON r.project_id = p.id
         WHERE r.id = $1 AND r.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Report not found');
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

reportsRouter.post('/generate',
  requirePermission(Permission.REPORT_CREATE),
  validateBody(generateReportSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, projectId, templateType, format, filters } = req.body;
      const reportId = uuidv4();

      const projectResult = await query('SELECT id FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [projectId, req.orgId]);
      if (projectResult.rows.length === 0) throw AppError.notFound('Project not found');

      await query(
        `INSERT INTO reports (id, org_id, project_id, name, template_type, format, filters, status, generated_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'queued',$8,NOW(),NOW())`,
        [reportId, req.orgId, projectId, name, templateType, format, JSON.stringify(filters), req.userId],
      );

      await queueManager.addJob(QueueName.REPORT_GENERATION, `report:${reportId}`, {
        reportId, projectId, organizationId: req.orgId, templateType, format, filters, userId: req.userId,
      });

      logger.info({ reportId, format, templateType }, 'Report generation queued');
      res.status(201).json({ id: reportId, status: 'queued', format, templateType });
    } catch (err) { next(err); }
  },
);

reportsRouter.get('/:id/download',
  requirePermission(Permission.REPORT_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query('SELECT * FROM reports WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (result.rows.length === 0) throw AppError.notFound('Report not found');

      const report = result.rows[0] as Record<string, unknown>;
      if (report.status !== 'completed') throw AppError.badRequest(`Report not ready. Status: ${report.status}`);

      const reportDir = path.resolve(getConfig().REPORT_DIR);
      const safeFilename = path.basename(`${report.id}.${report.format}`);
      const filePath = path.join(reportDir, safeFilename);
      const resolvedPath = path.resolve(filePath);
      if (!resolvedPath.startsWith(path.resolve(reportDir) + path.sep) && resolvedPath !== path.resolve(reportDir)) {
        throw AppError.badRequest('Invalid report path');
      }

      if (!fs.existsSync(filePath)) throw AppError.notFound('Report file not found on disk');

      const contentTypeMap: Record<string, string> = {
        pdf: 'application/pdf', html: 'text/html', json: 'application/json',
        csv: 'text/csv', markdown: 'text/markdown',
      };

      res.setHeader('Content-Type', contentTypeMap[report.format as string] || 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${(report.name as string).replace(/[^a-zA-Z0-9_-]/g,'_')}.${report.format}"`);
      fs.createReadStream(filePath).pipe(res);
    } catch (err) { next(err); }
  },
);

reportsRouter.delete('/:id',
  requirePermission(Permission.REPORT_DELETE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query('DELETE FROM reports WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (result.rowCount === 0) throw AppError.notFound('Report not found');
      res.json({ message: 'Report deleted' });
    } catch (err) { next(err); }
  },
);
