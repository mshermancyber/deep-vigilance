import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody } from '../../middleware/validate.js';

export const settingsRouter = Router();

settingsRouter.get('/profile',
  requirePermission(Permission.SETTINGS_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT u.id, u.email, u.name, u.role, u.mfa_enabled, u.created_at,
                o.name as org_name, o.id as org_id
         FROM users u JOIN organizations o ON u.org_id = o.id
         WHERE u.id = $1 AND u.deleted_at IS NULL`,
        [req.userId],
      );
      if (result.rows.length === 0) { res.status(404).json({ error: 'User not found' }); return; }
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

settingsRouter.put('/profile',
  requirePermission(Permission.SETTINGS_MANAGE),
  validateBody(z.object({
    name: z.string().min(1).max(100).optional(),
    email: z.string().email().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      if (req.body.name) { updates.push(`name = $${idx++}`); params.push(req.body.name); }
      if (req.body.email) {
        const normalizedEmail = req.body.email.toLowerCase().trim();
        const existing = await query('SELECT id FROM users WHERE email = $1 AND id != $2', [normalizedEmail, req.userId]);
        if (existing.rows.length > 0) {
          res.status(409).json({ error: 'A user with this email already exists' });
          return;
        }
        updates.push(`email = $${idx++}`);
        params.push(normalizedEmail);
      }

      if (updates.length > 0) {
        updates.push('updated_at = NOW()');
        params.push(req.userId);
        await query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${idx}`, params);
      }

      res.json({ message: 'Profile updated' });
    } catch (err) { next(err); }
  },
);

settingsRouter.get('/organization',
  requirePermission(Permission.SETTINGS_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'SELECT * FROM organizations WHERE id = $1',
        [req.orgId],
      );
      res.json(result.rows[0] || {});
    } catch (err) { next(err); }
  },
);

settingsRouter.put('/organization',
  requirePermission(Permission.SETTINGS_MANAGE),
  validateBody(z.object({
    name: z.string().min(1).max(100).optional(),
    settings: z.object({}).passthrough().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      if (req.body.name) { updates.push(`name = $${idx++}`); params.push(req.body.name); }
      if (req.body.settings) { updates.push(`settings = settings || $${idx++}::jsonb`); params.push(JSON.stringify(req.body.settings)); }

      if (updates.length > 0) {
        updates.push('updated_at = NOW()');
        params.push(req.orgId);
        await query(`UPDATE organizations SET ${updates.join(', ')} WHERE id = $${idx}`, params);
      }

      res.json({ message: 'Organization updated' });
    } catch (err) { next(err); }
  },
);

settingsRouter.get('/teams',
  requirePermission(Permission.SETTINGS_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT t.*, (SELECT COUNT(*) FROM user_teams ut WHERE ut.team_id = t.id) as member_count
         FROM teams t WHERE t.org_id = $1 AND t.deleted_at IS NULL
         ORDER BY t.name`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

settingsRouter.post('/teams',
  requirePermission(Permission.TEAM_MANAGE),
  validateBody(z.object({
    name: z.string().min(1).max(100),
    description: z.string().max(500).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { v4: uuidv4 } = await import('uuid');
      const teamId = uuidv4();
      await query(
        `INSERT INTO teams (id, org_id, name, description, created_at, updated_at)
         VALUES ($1,$2,$3,$4,NOW(),NOW())`,
        [teamId, req.orgId, req.body.name, req.body.description],
      );
      res.status(201).json({ id: teamId, name: req.body.name });
    } catch (err) { next(err); }
  },
);

settingsRouter.delete('/teams/:id',
  requirePermission(Permission.TEAM_MANAGE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      await query('UPDATE teams SET deleted_at = NOW() WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      res.json({ message: 'Team deleted' });
    } catch (err) { next(err); }
  },
);
