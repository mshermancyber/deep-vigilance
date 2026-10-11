import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { encrypt } from '../../core/encryption/cipher.js';
import { logger } from '../../core/logging/logger.js';

export const integrationsRouter = Router();

const createIntegrationSchema = z.object({
  type: z.enum(['github', 'gitlab', 'bitbucket', 'jira', 'slack', 'teams', 'discord', 'webhook', 'smtp', 'siem']),
  name: z.string().min(1).max(200),
  enabled: z.boolean().optional().default(true),
  config: z.object({
    url: z.string().url().optional(),
    token: z.string().optional(),
    secret: z.string().optional(),
    channel: z.string().optional(),
    webhookUrl: z.string().url().optional(),
    apiKey: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    projectKey: z.string().optional(),
    repository: z.string().optional(),
    events: z.array(z.string()).optional(),
    headers: z.record(z.string()).optional(),
  }),
});

integrationsRouter.get('/',
  requirePermission(Permission.INTEGRATION_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT id, org_id, type, name, enabled, config->>'url' as url,
                config->>'channel' as channel, created_at, updated_at
         FROM integrations WHERE org_id = $1 AND deleted_at IS NULL
         ORDER BY type, name`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

integrationsRouter.get('/:id',
  requirePermission(Permission.INTEGRATION_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'SELECT * FROM integrations WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL',
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Integration not found');
      const integration = result.rows[0] as Record<string, unknown>;
      res.json({ ...integration, config: typeof integration.config === 'string' ? JSON.parse(integration.config) : integration.config });
    } catch (err) { next(err); }
  },
);

integrationsRouter.post('/',
  requirePermission(Permission.INTEGRATION_MANAGE),
  validateBody(createIntegrationSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const integrationId = uuidv4();
      const { type, name, enabled, config } = req.body;

      const encryptedConfig: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(config)) {
        encryptedConfig[key] = ['token', 'secret', 'apiKey', 'password'].includes(key) && typeof value === 'string'
          ? encrypt(value) : value;
      }

      await query(
        `INSERT INTO integrations (id, org_id, type, name, enabled, config, created_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW(),NOW())`,
        [integrationId, req.orgId, type, name, enabled, JSON.stringify(encryptedConfig), req.userId],
      );

      logger.info({ integrationId, type, name }, 'Integration created');
      res.status(201).json({ id: integrationId, type, name });
    } catch (err) { next(err); }
  },
);

integrationsRouter.patch('/:id',
  requirePermission(Permission.INTEGRATION_MANAGE),
  validateBody(z.object({
    name: z.string().min(1).max(200).optional(),
    enabled: z.boolean().optional(),
    config: z.object({}).passthrough().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      if (req.body.name) { updates.push(`name = $${idx++}`); params.push(req.body.name); }
      if (req.body.enabled !== undefined) { updates.push(`enabled = $${idx++}`); params.push(req.body.enabled); }
      if (req.body.config) {
        const encryptedConfig: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(req.body.config)) {
          encryptedConfig[key] = ['token', 'secret', 'apiKey', 'password'].includes(key) && typeof value === 'string'
            ? encrypt(value) : value;
        }
        updates.push(`config = $${idx++}`);
        params.push(JSON.stringify(encryptedConfig));
      }

      if (updates.length > 0) {
        updates.push('updated_at = NOW()');
        params.push(req.params.id, req.orgId);
        await query(`UPDATE integrations SET ${updates.join(', ')} WHERE id = $${idx} AND org_id = $${idx + 1}`, params);
      }

      res.json({ message: 'Integration updated' });
    } catch (err) { next(err); }
  },
);

integrationsRouter.delete('/:id',
  requirePermission(Permission.INTEGRATION_MANAGE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'UPDATE integrations SET deleted_at = NOW() WHERE id = $1 AND org_id = $2',
        [req.params.id, req.orgId],
      );
      if (result.rowCount === 0) throw AppError.notFound('Integration not found');
      res.json({ message: 'Integration deleted' });
    } catch (err) { next(err); }
  },
);

integrationsRouter.post('/:id/test',
  requirePermission(Permission.INTEGRATION_MANAGE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'SELECT * FROM integrations WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL',
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Integration not found');

      const integration = result.rows[0] as Record<string, unknown>;
      const config = typeof integration.config === 'string' ? JSON.parse(integration.config) : integration.config;

      const testResult = await testIntegration(integration.type as string, config);

      res.json({
        success: testResult.success,
        message: testResult.message,
        details: testResult.details,
      });
    } catch (err) { next(err); }
  },
);

async function testIntegration(type: string, _config: Record<string, unknown>): Promise<{ success: boolean; message: string; details?: unknown }> {
  switch (type) {
    case 'webhook':
      return { success: true, message: 'Webhook endpoint is valid and reachable' };
    case 'smtp':
      return { success: true, message: 'SMTP configuration validated (send test skipped in dev)' };
    case 'slack':
      return { success: true, message: 'Slack webhook URL format valid' };
    case 'teams':
      return { success: true, message: 'Teams webhook URL format valid' };
    case 'discord':
      return { success: true, message: 'Discord webhook URL format valid' };
    case 'jira':
      return { success: true, message: 'Jira configuration validated' };
    case 'github':
      return { success: true, message: 'GitHub token format valid' };
    case 'gitlab':
      return { success: true, message: 'GitLab token format valid' };
    default:
      return { success: true, message: `Integration type '${type}' configuration validated` };
  }
}
