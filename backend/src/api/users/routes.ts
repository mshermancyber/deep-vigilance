import { Router, Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { Role } from '../../core/auth/permissions.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery, validateParams } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';

export const usersRouter = Router();

const createUserSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(12).max(128),
  name: z.string().min(1).max(100),
  role: z.nativeEnum(Role),
  teamIds: z.array(z.string().uuid()).optional(),
});

const updateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  role: z.nativeEnum(Role).optional(),
  disabled: z.boolean().optional(),
  forcePasswordReset: z.boolean().optional(),
  teamIds: z.array(z.string().uuid()).optional(),
});

const listUsersSchema = z.object({
  page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
  limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
  search: z.string().optional(),
  role: z.nativeEnum(Role).optional(),
  disabled: z.string().transform(v => v === 'true').optional(),
  sortBy: z.enum(['name', 'email', 'role', 'created_at']).optional().default('created_at'),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
});

usersRouter.get('/',
  requirePermission(Permission.USER_READ),
  validateQuery(listUsersSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, search, role, disabled, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);

      const conditions: string[] = ['u.org_id = $1', 'u.deleted_at IS NULL'];
      const params: unknown[] = [req.orgId];
      let paramIdx = 2;

      if (search) {
        conditions.push(`(u.name ILIKE $${paramIdx} OR u.email ILIKE $${paramIdx})`);
        params.push(`%${search}%`);
        paramIdx++;
      }
      if (role) {
        conditions.push(`u.role = $${paramIdx}`);
        params.push(role);
        paramIdx++;
      }
      if (disabled !== undefined) {
        conditions.push(`u.disabled = $${paramIdx}`);
        params.push(disabled);
        paramIdx++;
      }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM users u WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string, 10);

      const usersResult = await query(
        `SELECT u.id, u.email, u.name, u.role, u.disabled, u.mfa_enabled, u.created_at, u.last_login,
                array_agg(DISTINCT t.name) FILTER (WHERE t.name IS NOT NULL) as teams
         FROM users u
         LEFT JOIN user_teams ut ON u.id = ut.user_id
         LEFT JOIN teams t ON ut.team_id = t.id
         WHERE ${where}
         GROUP BY u.id
         ORDER BY u.${sortBy === 'name' ? 'name' : sortBy === 'email' ? 'email' : sortBy === 'role' ? 'role' : 'created_at'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({
        data: usersResult.rows,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

usersRouter.get('/:id',
  requirePermission(Permission.USER_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT u.id, u.email, u.name, u.role, u.disabled, u.mfa_enabled, u.created_at, u.last_login,
                array_agg(json_build_object('id', t.id, 'name', t.name)) FILTER (WHERE t.id IS NOT NULL) as teams
         FROM users u
         LEFT JOIN user_teams ut ON u.id = ut.user_id
         LEFT JOIN teams t ON ut.team_id = t.id
         WHERE u.id = $1 AND u.org_id = $2 AND u.deleted_at IS NULL
         GROUP BY u.id`,
        [req.params.id, req.orgId],
      );

      if (result.rows.length === 0) throw AppError.notFound('User not found');
      res.json(result.rows[0]);
    } catch (err) {
      next(err);
    }
  },
);

usersRouter.post('/',
  requirePermission(Permission.USER_CREATE),
  validateBody(createUserSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password, name, role, teamIds } = req.body;
      const normalizedEmail = email.toLowerCase().trim();

      const existing = await query('SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL', [normalizedEmail]);
      if (existing.rows.length > 0) throw AppError.conflict('A user with this email already exists');

      const userId = uuidv4();
      const passwordHash = await bcrypt.hash(password, 14);

      await query(
        `INSERT INTO users (id, email, password_hash, name, role, org_id, force_password_reset, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, true, NOW(), NOW())`,
        [userId, normalizedEmail, passwordHash, name, role, req.orgId],
      );

      if (teamIds?.length) {
        const values = teamIds.map((_tid: string, i: number) => `($1, $${i + 2})`).join(', ');
        await query(
          `INSERT INTO user_teams (user_id, team_id) VALUES ${values}`,
          [userId, ...teamIds],
        );
      }

      logger.info({ userId, email: normalizedEmail }, 'User created by admin');
      res.status(201).json({ id: userId, email: normalizedEmail, name, role });
    } catch (err) {
      next(err);
    }
  },
);

usersRouter.patch('/:id',
  requirePermission(Permission.USER_UPDATE),
  validateParams(z.object({ id: z.string().uuid() })),
  validateBody(updateUserSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      const { name, role, disabled, forcePasswordReset, teamIds } = req.body;

      if (name !== undefined) { updates.push(`name = $${idx++}`); params.push(name); }
      if (role !== undefined) { updates.push(`role = $${idx++}`); params.push(role); }
      if (disabled !== undefined) { updates.push(`disabled = $${idx++}`); params.push(disabled); }
      if (forcePasswordReset !== undefined) { updates.push(`force_password_reset = $${idx++}`); params.push(forcePasswordReset); }

      if (updates.length === 0 && !teamIds) throw AppError.badRequest('No fields to update');

      if (updates.length > 0) {
        updates.push(`updated_at = NOW()`);
        params.push(req.params.id, req.orgId);
        await query(
          `UPDATE users SET ${updates.join(', ')} WHERE id = $${idx} AND org_id = $${idx + 1}`,
          params,
        );
      }

      if (teamIds !== undefined) {
        await query('DELETE FROM user_teams WHERE user_id = $1', [req.params.id]);
        if (teamIds.length > 0) {
          const values = teamIds.map((_tid: string, i: number) => `($1, $${i + 2})`).join(', ');
          await query(
            `INSERT INTO user_teams (user_id, team_id) VALUES ${values}`,
            [req.params.id, ...teamIds],
          );
        }
      }

      logger.info({ userId: req.params.id }, 'User updated');
      res.json({ message: 'User updated successfully' });
    } catch (err) {
      next(err);
    }
  },
);

usersRouter.delete('/:id',
  requirePermission(Permission.USER_DELETE),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (req.params.id === req.userId) throw AppError.badRequest('Cannot delete your own account');

      const result = await query(
        'UPDATE users SET deleted_at = NOW() WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL',
        [req.params.id, req.orgId],
      );

      if (result.rowCount === 0) throw AppError.notFound('User not found');
      logger.info({ userId: req.params.id }, 'User soft-deleted');
      res.json({ message: 'User deleted successfully' });
    } catch (err) {
      next(err);
    }
  },
);
