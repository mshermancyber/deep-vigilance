import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateQuery } from '../../middleware/validate.js';

export const searchRouter = Router();

searchRouter.get('/',
  requirePermission(Permission.SEARCH_GLOBAL),
  validateQuery(z.object({
    q: z.string().min(1).max(200),
    type: z.enum(['all', 'projects', 'findings', 'scans', 'reports', 'users', 'endpoints']).optional().default('all'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(50)).optional().default('10'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { q, type, limit } = req.query as any;
      const searchTerm = `%${q}%`;
      const results: Record<string, unknown[]> = {};

      if (type === 'all' || type === 'projects') {
        const r = await query(
          `SELECT id, name, description, target_url, tags
           FROM projects WHERE org_id = $1 AND deleted_at IS NULL
           AND (name ILIKE $2 OR description ILIKE $2 OR target_url ILIKE $2 OR $3 = ANY(tags))
           ORDER BY updated_at DESC LIMIT $4`,
          [req.orgId, searchTerm, q, Number(limit)],
        );
        results.projects = r.rows;
      }

      if (type === 'all' || type === 'findings') {
        const r = await query(
          `SELECT f.id, f.title, f.severity, f.status, f.file_path, f.cve_id, p.name as project_name
           FROM findings f JOIN projects p ON f.project_id = p.id
           WHERE f.org_id = $1 AND (f.title ILIKE $2 OR f.description ILIKE $2 OR f.file_path ILIKE $2 OR f.cve_id ILIKE $2)
           ORDER BY f.severity_rank ASC LIMIT $3`,
          [req.orgId, searchTerm, Number(limit)],
        );
        results.findings = r.rows;
      }

      if (type === 'all' || type === 'scans') {
        const r = await query(
          `SELECT s.id, s.name, s.scan_type, s.status, p.name as project_name
           FROM scans s JOIN projects p ON s.project_id = p.id
           WHERE s.org_id = $1 AND s.name ILIKE $2
           ORDER BY s.created_at DESC LIMIT $3`,
          [req.orgId, searchTerm, Number(limit)],
        );
        results.scans = r.rows;
      }

      if (type === 'all' || type === 'reports') {
        const r = await query(
          `SELECT r.id, r.name, r.template_type, r.format, r.status, p.name as project_name
           FROM reports r JOIN projects p ON r.project_id = p.id
           WHERE r.org_id = $1 AND r.name ILIKE $2
           ORDER BY r.created_at DESC LIMIT $3`,
          [req.orgId, searchTerm, Number(limit)],
        );
        results.reports = r.rows;
      }

      if (type === 'all' || type === 'users') {
        const r = await query(
          `SELECT id, name, email, role FROM users
           WHERE org_id = $1 AND deleted_at IS NULL
           AND (name ILIKE $2 OR email ILIKE $2)
           ORDER BY name LIMIT $3`,
          [req.orgId, searchTerm, Number(limit)],
        );
        results.users = r.rows;
      }

      const totalHits = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);

      res.json({
        query: q,
        totalHits,
        results,
      });
    } catch (err) { next(err); }
  },
);
