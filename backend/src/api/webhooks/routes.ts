import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateParams } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';
import { encrypt, decrypt } from '../../core/encryption/cipher.js';
import { queueManager, QueueName, JobPriority } from '../../core/queue/manager.js';
import { parseGitHubWebhook, parseGitLabWebhook, parseBitbucketWebhook } from '../../services/git/git-service.js';

export const webhooksRouter = Router();

webhooksRouter.get('/',
  requirePermission(Permission.INTEGRATION_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'SELECT * FROM webhooks WHERE org_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC',
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

webhooksRouter.post('/',
  requirePermission(Permission.INTEGRATION_MANAGE),
  validateBody(z.object({
    name: z.string().min(1).max(200),
    url: z.string().url(),
    events: z.array(z.enum([
      'scan.started', 'scan.completed', 'scan.failed',
      'finding.created', 'finding.updated', 'finding.resolved',
      'report.generated', 'user.created', 'user.deleted',
      'integration.test',
    ])),
    secret: z.string().min(16).optional(),
    headers: z.record(z.string()).optional(),
    enabled: z.boolean().optional().default(true),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const whId = uuidv4();
      const { name, url, events, secret, headers, enabled } = req.body;

      await query(
        `INSERT INTO webhooks (id, org_id, name, url, events, secret_hash, headers, enabled, created_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())`,
        [whId, req.orgId, name, url, JSON.stringify(events),
         secret ? encrypt(secret) : null, JSON.stringify(headers || {}), enabled, req.userId],
      );

      logger.info({ whId, name }, 'Webhook created');
      res.status(201).json({ id: whId, name });
    } catch (err) { next(err); }
  },
);

webhooksRouter.patch('/:id',
  requirePermission(Permission.INTEGRATION_MANAGE),
  validateParams(z.object({ id: z.string().uuid() })),
  validateBody(z.object({
    name: z.string().min(1).max(200).optional(),
    url: z.string().url().optional(),
    events: z.array(z.enum([
      'scan.started', 'scan.completed', 'scan.failed',
      'finding.created', 'finding.updated', 'finding.resolved',
      'report.generated', 'user.created', 'user.deleted',
      'integration.test',
    ])).optional(),
    secret: z.string().min(16).optional(),
    headers: z.record(z.string()).optional(),
    enabled: z.boolean().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, url, events, secret, headers, enabled } = req.body;
      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      if (name) { updates.push(`name = $${idx++}`); params.push(name); }
      if (url) { updates.push(`url = $${idx++}`); params.push(url); }
      if (events) { updates.push(`events = $${idx++}`); params.push(JSON.stringify(events)); }
      if (secret) { updates.push(`secret_hash = $${idx++}`); params.push(encrypt(secret)); }
      if (headers) { updates.push(`headers = $${idx++}`); params.push(JSON.stringify(headers)); }
      if (enabled !== undefined) { updates.push(`enabled = $${idx++}`); params.push(enabled); }

      if (updates.length > 0) {
        updates.push('updated_at = NOW()');
        params.push(req.params.id, req.orgId);
        await query(`UPDATE webhooks SET ${updates.join(', ')} WHERE id = $${idx} AND org_id = $${idx + 1}`, params);
      }

      res.json({ message: 'Webhook updated' });
    } catch (err) { next(err); }
  },
);

webhooksRouter.delete('/:id',
  requirePermission(Permission.INTEGRATION_MANAGE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query('UPDATE webhooks SET deleted_at = NOW() WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (result.rowCount === 0) throw AppError.notFound('Webhook not found');
      res.json({ message: 'Webhook deleted' });
    } catch (err) { next(err); }
  },
);

// ============================================================================
// Inbound Push-Event Receivers (scan-on-push)
// ============================================================================

function verifyGitHubSignature(body: string, signature: string, secret: string): boolean {
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(body, 'utf8').digest('hex');
  const expectedBuf = Buffer.from(expected, 'utf8');
  const actualBuf = Buffer.from(signature, 'utf8');
  if (expectedBuf.length !== actualBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, actualBuf);
}

async function launchScanFromPush(
  orgId: string, projectId: string, repoUrl: string, branch: string, commitHash: string,
  scanTypes: string[], gitToken?: string,
) {
  const results: Array<{ scanId: string; scanType: string }> = [];

  for (const scanType of scanTypes) {
    const scanId = uuidv4();
    const name = `Push: ${commitHash.slice(0, 8)} (${scanType.toUpperCase()})`;
    const options = { repoUrl, branch, gitToken };

    await query(
      `INSERT INTO scans (id, org_id, project_id, scan_type, name, status, options, started_at, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,'queued',$6,NOW(),NOW(),NOW())`,
      [scanId, orgId, projectId, scanType, name, JSON.stringify(options)],
    );

    const queueMap: Record<string, QueueName> = {
      sast: QueueName.SAST_SCAN, dast: QueueName.DAST_SCAN,
      api: QueueName.API_SCAN, sca: QueueName.SCA_SCAN,
    };
    const queueName = queueMap[scanType] || QueueName.SAST_SCAN;
    await queueManager.addJob(queueName, `scan:${scanId}`, {
      scanId, projectId, options, organizationId: orgId,
    } as Record<string, unknown>, JobPriority.NORMAL);

    results.push({ scanId, scanType });
  }

  logger.info({ orgId, projectId, repoUrl, branch, commitHash, scanTypes, scans: results }, 'Scan-on-push launched');
  return results;
}

webhooksRouter.post('/inbound/:connectionId',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const connResult = await query(
        'SELECT * FROM git_connections WHERE id = $1 AND deleted_at IS NULL',
        [req.params.connectionId],
      );
      if (connResult.rows.length === 0) {
        res.status(404).json({ error: 'Connection not found' });
        return;
      }

      const conn = connResult.rows[0] as Record<string, unknown>;

      // Verify webhook signature if secret is configured
      if (conn.webhook_secret) {
        const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
        const provider = conn.provider as string;

        let secret: string;
        try { secret = decrypt(conn.webhook_secret as string); } catch {
          res.status(401).json({ error: 'Webhook authentication error' });
          return;
        }

        if (provider === 'github') {
          const sig = req.headers['x-hub-signature-256'] as string;
          if (!sig || !verifyGitHubSignature(rawBody, sig, secret)) {
            res.status(401).json({ error: 'Invalid signature' });
            return;
          }
        } else if (provider === 'gitlab') {
          const token = req.headers['x-gitlab-token'] as string;
          if (token !== secret) {
            res.status(401).json({ error: 'Invalid token' });
            return;
          }
        }
      }

      const ghEvent = req.headers['x-github-event'] as string;
      const glEvent = req.headers['x-gitlab-event'] as string;
      const event = ghEvent || glEvent || 'push';

      if (event !== 'push' && event !== 'Push Hook') {
        res.status(200).json({ received: true, event, skipped: true, reason: 'Not a push event' });
        return;
      }

      const provider = conn.provider as string;
      let parsed = null;
      if (provider === 'github') parsed = parseGitHubWebhook(req.body);
      else if (provider === 'gitlab') parsed = parseGitLabWebhook(req.body);
      else if (provider === 'bitbucket') parsed = parseBitbucketWebhook(req.body);

      if (!parsed) {
        res.status(200).json({ received: true, event, skipped: true, reason: 'Could not parse payload' });
        return;
      }

      const scanTypes = ['sast', 'sca'];

      let gitToken: string | undefined;
      if (conn.auth_credentials) {
        try { gitToken = decrypt(conn.auth_credentials as string); } catch { /* no token */ }
      }

      const repoUrl = (conn.clone_url as string) || (conn.repository_url as string) || '';

      const scans = await launchScanFromPush(
        conn.org_id as string, conn.project_id as string,
        repoUrl, parsed.branch, parsed.commitHash,
        scanTypes, gitToken,
      );

      res.status(200).json({ received: true, event, branch: parsed.branch, commit: parsed.commitHash, scansLaunched: scans });
    } catch (err) { next(err); }
  },
);
