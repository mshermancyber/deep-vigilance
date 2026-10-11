import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery, validateParams } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';
import { encrypt } from '../../core/encryption/cipher.js';

export const projectsRouter = Router();

const createProjectSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
  ownerId: z.string().uuid().optional(),
  repository: z.string().url().max(500).optional(),
  targetUrl: z.string().url().max(500).optional(),
  apiBaseUrl: z.string().url().max(500).optional(),
  authType: z.enum(['none', 'basic', 'bearer', 'jwt', 'oauth', 'api_key', 'mtls', 'digest']).optional(),
  authCredentials: z.object({
    username: z.string().optional(),
    password: z.string().optional(),
    token: z.string().optional(),
    apiKey: z.string().optional(),
    apiKeyHeader: z.string().optional(),
    clientId: z.string().optional(),
    clientSecret: z.string().optional(),
    tokenUrl: z.string().optional(),
  }).optional(),
  headers: z.record(z.string()).optional(),
  cookies: z.record(z.string()).optional(),
  environmentVariables: z.record(z.string()).optional(),
  tags: z.array(z.string().max(50)).optional(),
  teamId: z.string().uuid().optional(),
  notes: z.string().max(5000).optional(),
});

const updateProjectSchema = createProjectSchema.partial();

projectsRouter.get('/',
  requirePermission(Permission.PROJECT_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    search: z.string().optional(),
    tag: z.string().optional(),
    teamId: z.string().uuid().optional(),
    sortBy: z.enum(['name', 'created_at', 'updated_at', 'risk_score']).optional().default('updated_at'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, search, tag, teamId, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);

      const conditions = ['p.org_id = $1', 'p.deleted_at IS NULL'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (search) { conditions.push(`p.name ILIKE $${idx}`); params.push(`%${search}%`); idx++; }
      if (tag) { conditions.push(`$${idx} = ANY(p.tags)`); params.push(tag); idx++; }
      if (teamId) { conditions.push(`p.team_id = $${idx}`); params.push(teamId); idx++; }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM projects p WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string, 10);

      const result = await query(
        `SELECT p.*, u.name as owner_name,
                (SELECT COUNT(*) FROM scans s WHERE s.project_id = p.id) as scan_count,
                (SELECT COUNT(*) FROM findings f WHERE f.project_id = p.id AND f.severity = 'critical' AND f.status != 'closed') as critical_count,
                (SELECT COUNT(*) FROM findings f WHERE f.project_id = p.id AND f.severity = 'high' AND f.status != 'closed') as high_count
         FROM projects p
         LEFT JOIN users u ON p.owner_id = u.id
         WHERE ${where}
         ORDER BY p.${sortBy === 'name' ? 'name' : sortBy === 'updated_at' ? 'updated_at' : sortBy === 'risk_score' ? 'risk_score' : 'created_at'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

projectsRouter.get('/:id',
  requirePermission(Permission.PROJECT_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT p.*, u.name as owner_name,
                (SELECT json_agg(json_build_object('id', s.id, 'name', s.name, 'status', s.status, 'created_at', s.created_at))
                 FROM scans s WHERE s.project_id = p.id ORDER BY s.created_at DESC LIMIT 5) as recent_scans
         FROM projects p LEFT JOIN users u ON p.owner_id = u.id
         WHERE p.id = $1 AND p.org_id = $2 AND p.deleted_at IS NULL`,
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Project not found');
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

projectsRouter.post('/',
  requirePermission(Permission.PROJECT_CREATE),
  validateBody(createProjectSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const projectId = uuidv4();
      const { name, description, ownerId, repository, targetUrl, apiBaseUrl, authType,
        authCredentials, headers, cookies, environmentVariables, tags, teamId, notes } = req.body;

      const encryptedAuth = authCredentials ? encrypt(JSON.stringify(authCredentials)) : null;

      await query(
        `INSERT INTO projects (id, org_id, name, description, owner_id, repository, target_url, api_base_url,
          auth_type, auth_credentials, headers, cookies, environment_variables, tags, team_id, notes, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW(),NOW())`,
        [projectId, req.orgId, name, description, ownerId || req.userId, repository, targetUrl,
          apiBaseUrl, authType, encryptedAuth, JSON.stringify(headers || {}),
          JSON.stringify(cookies || {}), JSON.stringify(environmentVariables || {}),
          tags || [], teamId, notes],
      );

      logger.info({ projectId, name }, 'Project created');
      res.status(201).json({ id: projectId, name });
    } catch (err) { next(err); }
  },
);

projectsRouter.patch('/:id',
  requirePermission(Permission.PROJECT_UPDATE),
  validateParams(z.object({ id: z.string().uuid() })),
  validateBody(updateProjectSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const existing = await query('SELECT id FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [req.params.id, req.orgId]);
      if (existing.rows.length === 0) throw AppError.notFound('Project not found');

      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      const fields: Record<string, keyof typeof req.body> = {
        name: 'name', description: 'description', owner_id: 'ownerId',
        repository: 'repository', target_url: 'targetUrl', api_base_url: 'apiBaseUrl',
        auth_type: 'authType', tags: 'tags', team_id: 'teamId', notes: 'notes',
      };

      for (const [col, key] of Object.entries(fields)) {
        if (req.body[key] !== undefined) {
          updates.push(`${col} = $${idx++}`);
          params.push(req.body[key]);
        }
      }

      if (req.body.authCredentials) {
        updates.push(`auth_credentials = $${idx++}`);
        params.push(encrypt(JSON.stringify(req.body.authCredentials)));
      }
      if (req.body.headers) { updates.push(`headers = $${idx++}`); params.push(JSON.stringify(req.body.headers)); }
      if (req.body.cookies) { updates.push(`cookies = $${idx++}`); params.push(JSON.stringify(req.body.cookies)); }
      if (req.body.environmentVariables) { updates.push(`environment_variables = $${idx++}`); params.push(JSON.stringify(req.body.environmentVariables)); }

      if (updates.length > 0) {
        updates.push('updated_at = NOW()');
        params.push(req.params.id);
        params.push(req.orgId);
        await query(`UPDATE projects SET ${updates.join(', ')} WHERE id = $${idx} AND org_id = $${idx + 1}`, params);
      }

      logger.info({ projectId: req.params.id }, 'Project updated');
      res.json({ message: 'Project updated successfully' });
    } catch (err) { next(err); }
  },
);

projectsRouter.delete('/:id',
  requirePermission(Permission.PROJECT_DELETE),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'UPDATE projects SET deleted_at = NOW() WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL',
        [req.params.id, req.orgId],
      );
      if (result.rowCount === 0) throw AppError.notFound('Project not found');
      logger.info({ projectId: req.params.id }, 'Project soft-deleted');
      res.json({ message: 'Project deleted successfully' });
    } catch (err) { next(err); }
  },
);

projectsRouter.get('/:id/risk-score',
  requirePermission(Permission.PROJECT_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT
           COUNT(*) FILTER (WHERE severity = 'critical') * 10 +
           COUNT(*) FILTER (WHERE severity = 'high') * 5 +
           COUNT(*) FILTER (WHERE severity = 'medium') * 2 +
           COUNT(*) FILTER (WHERE severity = 'low') as risk_score,
           COUNT(*) FILTER (WHERE severity = 'critical') as critical,
           COUNT(*) FILTER (WHERE severity = 'high') as high,
           COUNT(*) FILTER (WHERE severity = 'medium') as medium,
           COUNT(*) FILTER (WHERE severity = 'low') as low,
           COUNT(*) FILTER (WHERE severity = 'info') as info
         FROM findings
         WHERE project_id = $1 AND org_id = $2 AND status != 'closed'`,
        [req.params.id, req.orgId],
      );
      res.json(result.rows[0] || { risk_score: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    } catch (err) { next(err); }
  },
);
