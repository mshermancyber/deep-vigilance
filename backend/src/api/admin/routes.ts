import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody } from '../../middleware/validate.js';
import { logger } from '../../core/logging/logger.js';
import { Role } from '../../core/auth/permissions.js';
import { runCleanupCycle } from '../../core/cleanup.js';
import { getConfig } from '../../config/index.js';

export const adminRouter = Router();

adminRouter.get('/audit-log',
  requirePermission(Permission.AUDIT_LOG_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
      const offset = (page - 1) * limit;

      const conditions = ['a.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (req.query.userId) { conditions.push(`a.user_id = $${idx++}`); params.push(req.query.userId); }
      if (req.query.action) { conditions.push(`a.action ILIKE $${idx++}`); params.push(`%${req.query.action}%`); }
      if (req.query.resource) { conditions.push(`a.resource = $${idx++}`); params.push(req.query.resource); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM audit_log a WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT a.*, u.name as user_name, u.email as user_email
         FROM audit_log a LEFT JOIN users u ON a.user_id = u.id
         WHERE ${where}
         ORDER BY a.created_at DESC
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, limit, offset],
      );

      res.json({ data: result.rows, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
    } catch (err) { next(err); }
  },
);

adminRouter.get('/system-health',
  requirePermission(Permission.ADMIN_FULL),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const [dbSize, tableSizes, userCount, activeSessions] = await Promise.all([
        query(`SELECT pg_database_size(current_database()) / 1024 / 1024 as size_mb`),
        query(`SELECT relname as table_name, n_live_tup as row_count,
                  pg_size_pretty(pg_total_relation_size(relid)) as total_size
               FROM pg_stat_user_tables ORDER BY n_live_tup DESC`),
        query(`SELECT COUNT(*) as total,
                  COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') as new_this_week,
                  COUNT(*) FILTER (WHERE last_login > NOW() - INTERVAL '24 hours') as active_today
               FROM users WHERE deleted_at IS NULL`),
        query(`SELECT COUNT(*) as active_connections FROM pg_stat_activity WHERE state = 'active'`),
      ]);

      res.json({
        database: { sizeMb: parseInt((dbSize.rows[0] as Record<string,unknown>).size_mb as string, 10), tables: tableSizes.rows },
        users: userCount.rows[0],
        connections: parseInt((activeSessions.rows[0] as Record<string,unknown>).active_connections as string, 10),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        nodeVersion: process.version,
        timestamp: new Date().toISOString(),
      });
    } catch (err) { next(err); }
  },
);

adminRouter.get('/organizations',
  requirePermission(Permission.ADMIN_FULL),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT o.*,
                (SELECT COUNT(*) FROM users u WHERE u.org_id = o.id AND u.deleted_at IS NULL) as user_count,
                (SELECT COUNT(*) FROM projects p WHERE p.org_id = o.id AND p.deleted_at IS NULL) as project_count,
                (SELECT COUNT(*) FROM scans s WHERE s.org_id = o.id) as scan_count
         FROM organizations o
         ORDER BY o.created_at DESC`,
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

adminRouter.post('/organizations',
  requirePermission(Permission.ADMIN_FULL),
  validateBody(z.object({
    name: z.string().min(1).max(100),
    adminEmail: z.string().email(),
    adminPassword: z.string().min(12),
    adminName: z.string().min(1).max(100),
  })),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      // Admin user creating an organization would be a super-admin operation
      res.status(501).json({ message: 'Super-admin organization creation coming soon' });
    } catch (err) { next(err); }
  },
);

adminRouter.get('/service-accounts',
  requirePermission(Permission.USER_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT sa.id, sa.name, sa.description, sa.role, sa.enabled, sa.last_used, sa.created_at,
                array_agg(ak.name) FILTER (WHERE ak.name IS NOT NULL) as api_keys
         FROM service_accounts sa
         LEFT JOIN api_keys ak ON sa.id = ak.service_account_id AND ak.revoked = false
         WHERE sa.org_id = $1 AND sa.deleted_at IS NULL
         GROUP BY sa.id ORDER BY sa.created_at DESC`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

adminRouter.post('/service-accounts',
  requirePermission(Permission.USER_CREATE),
  validateBody(z.object({
    name: z.string().min(1).max(100),
    description: z.string().max(500).optional(),
    role: z.nativeEnum(Role),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const saId = uuidv4();
      const { name, description, role } = req.body;

      await query(
        `INSERT INTO service_accounts (id, org_id, name, description, role, created_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,NOW(),NOW())`,
        [saId, req.orgId, name, description, role, req.userId],
      );

      logger.info({ saId, name }, 'Service account created');
      res.status(201).json({ id: saId, name });
    } catch (err) { next(err); }
  },
);

adminRouter.get('/settings',
  requirePermission(Permission.SETTINGS_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT key, value, type, description, updated_at
         FROM platform_settings WHERE org_id = $1 ORDER BY key`,
        [req.orgId],
      );
      const settings: Record<string, unknown> = {};
      for (const row of result.rows) {
        const r = row as Record<string, unknown>;
        settings[r.key as string] = r.value;
      }
      res.json(settings);
    } catch (err) { next(err); }
  },
);

adminRouter.put('/settings',
  requirePermission(Permission.SETTINGS_MANAGE),
  validateBody(z.object({}).passthrough()),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      for (const [key, value] of Object.entries(req.body)) {
        await query(
          `INSERT INTO platform_settings (org_id, key, value, type, updated_at)
           VALUES ($1,$2,$3,$4,NOW())
           ON CONFLICT (org_id, key) DO UPDATE SET value = $3, updated_at = NOW()`,
          [req.orgId, key, JSON.stringify(value), typeof value],
        );
      }
      res.json({ message: 'Settings updated' });
    } catch (err) { next(err); }
  },
);

// Retention / housekeeping. The cycle also runs on a timer
// (CLEANUP_INTERVAL_MIN); this endpoint lets an operator trigger it now and see
// exactly what was pruned.
adminRouter.get('/cleanup',
  requirePermission(Permission.SETTINGS_MANAGE),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const c = getConfig();
      res.json({
        success: true,
        data: {
          enabled: c.CLEANUP_INTERVAL_MIN > 0,
          intervalMinutes: c.CLEANUP_INTERVAL_MIN,
          batchSize: c.CLEANUP_BATCH_SIZE,
          maxTableFraction: c.CLEANUP_MAX_TABLE_FRACTION,
          retentionDays: {
            scans: c.RETAIN_SCANS_DAYS,
            auditLog: c.RETAIN_AUDIT_LOG_DAYS,
            reports: c.RETAIN_REPORTS_DAYS,
            notifications: c.RETAIN_NOTIFICATIONS_DAYS,
            codeReviews: c.RETAIN_CODE_REVIEWS_DAYS,
            apiHistory: c.RETAIN_API_HISTORY_DAYS,
            webhookDeadLetters: c.RETAIN_WEBHOOK_DLQ_DAYS,
            queueJobs: c.RETAIN_QUEUE_JOBS_DAYS,
          },
        },
      });
    } catch (err) { next(err); }
  },
);

adminRouter.post('/cleanup/run',
  requirePermission(Permission.SETTINGS_MANAGE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      logger.warn({ userId: req.userId }, 'Admin: manual retention cycle triggered');
      const report = await runCleanupCycle();
      res.json({ success: true, data: report });
    } catch (err) { next(err); }
  },
);
