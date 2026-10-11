import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery, validateParams } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';
import { queueManager, QueueName, JobPriority } from '../../core/queue/manager.js';
import { encrypt, decrypt } from '../../core/encryption/cipher.js';
import { APP_VERSION } from '../../version.js';

export const codeReviewRouter = Router();

// ---- Permissions (extend existing) ----

// ==========================================
// Git Connections
// ==========================================

codeReviewRouter.get('/git-connections',
  requirePermission(Permission.PROJECT_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT gc.*, p.name as project_name
         FROM git_connections gc LEFT JOIN projects p ON gc.project_id = p.id
         WHERE gc.org_id = $1 AND gc.deleted_at IS NULL
         ORDER BY gc.updated_at DESC`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

codeReviewRouter.post('/git-connections',
  requirePermission(Permission.PROJECT_CREATE),
  validateBody(z.object({
    name: z.string().min(1).max(255),
    provider: z.enum(['github', 'gitlab', 'bitbucket', 'azure', 'gitea', 'generic']),
    repositoryUrl: z.string().url(),
    cloneUrl: z.string().url(),
    defaultBranch: z.string().optional().default('main'),
    authType: z.enum(['token', 'ssh', 'oauth', 'app', 'none']).optional().default('token'),
    authToken: z.string().optional(),
    projectId: z.string().uuid().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const connId = uuidv4();
      const { name, provider, repositoryUrl, cloneUrl, defaultBranch, authType, authToken, projectId } = req.body;

      if (projectId) {
        const projectCheck = await query('SELECT id FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [projectId, req.orgId]);
        if (projectCheck.rows.length === 0) throw AppError.notFound('Project not found');
      }

      await query(
        `INSERT INTO git_connections (id, org_id, project_id, name, provider, repository_url, clone_url,
          default_branch, auth_type, auth_credentials, created_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())`,
        [connId, req.orgId, projectId, name, provider, repositoryUrl, cloneUrl,
          defaultBranch, authType, authToken ? encrypt(authToken) : null, req.userId],
      );

      logger.info({ connId, name, provider }, 'Git connection created');
      res.status(201).json({ id: connId, name, provider });
    } catch (err) { next(err); }
  },
);

codeReviewRouter.delete('/git-connections/:id',
  requirePermission(Permission.PROJECT_DELETE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      await query('UPDATE git_connections SET deleted_at = NOW() WHERE id = $1 AND org_id = $2',
        [req.params.id, req.orgId]);
      res.json({ message: 'Git connection removed' });
    } catch (err) { next(err); }
  },
);

// ==========================================
// Code Reviews
// ==========================================

const launchReviewSchema = z.object({
  name: z.string().min(1).max(255),
  projectId: z.string().uuid().optional(),
  gitConnectionId: z.string().uuid().optional(),
  // Direct repo scan (no saved connection needed). gitToken is for private repos.
  repoUrl: z.string().url().max(2000).optional(),
  gitToken: z.string().max(500).optional(),
  reviewType: z.enum(['full', 'semantic', 'security', 'dependency', 'fuzz', 'health', 'incremental']),
  targetType: z.enum(['repository', 'upload', 'folder', 'file', 'monorepo', 'iac', 'cicd']),
  targetPath: z.string().optional(),
  branch: z.string().optional(),
  commitHash: z.string().optional(),
  baseCommitHash: z.string().optional(),
  options: z.object({
    languages: z.array(z.string()).optional(),
    includePatterns: z.array(z.string()).optional(),
    excludePatterns: z.array(z.string()).optional(),
    fuzzIterations: z.number().min(100).max(100000).optional().default(1000),
    fuzzTimeout: z.number().min(60).max(3600).optional().default(300),
    severityThreshold: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional().default('info'),
  }).optional().default({}),
  priority: z.enum(['low', 'normal', 'high', 'critical']).optional().default('normal'),
});

codeReviewRouter.get('/reviews',
  requirePermission(Permission.PROJECT_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    projectId: z.string().uuid().optional(),
    reviewType: z.enum(['full', 'semantic', 'security', 'dependency', 'fuzz', 'health', 'incremental']).optional(),
    status: z.enum(['queued', 'cloning', 'indexing', 'analyzing', 'reviewing', 'fuzzing', 'completed', 'failed', 'cancelled', 'partial']).optional(),
    sortBy: z.enum(['name', 'created_at', 'review_type', 'status']).optional().default('created_at'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, reviewType, status, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['cr.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`cr.project_id = $${idx++}`); params.push(projectId); }
      if (reviewType) { conditions.push(`cr.review_type = $${idx++}`); params.push(reviewType); }
      if (status) { conditions.push(`cr.status = $${idx++}`); params.push(status); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM code_reviews cr WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT cr.*, p.name as project_name, gc.name as git_connection_name,
                (SELECT COUNT(*) FROM code_review_findings crf WHERE crf.review_id = cr.id) as finding_count
         FROM code_reviews cr
         LEFT JOIN projects p ON cr.project_id = p.id
         LEFT JOIN git_connections gc ON cr.git_connection_id = gc.id
         WHERE ${where}
         ORDER BY cr.${sortBy === 'name' ? 'name' : sortBy === 'review_type' ? 'review_type' : sortBy === 'status' ? 'status' : 'created_at'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

codeReviewRouter.get('/reviews/:id',
  requirePermission(Permission.PROJECT_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT cr.*, p.name as project_name
         FROM code_reviews cr LEFT JOIN projects p ON cr.project_id = p.id
         WHERE cr.id = $1 AND cr.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Code review not found');
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

codeReviewRouter.post('/reviews/launch',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(launchReviewSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const reviewId = uuidv4();
      const { name, projectId, gitConnectionId, reviewType, targetType, targetPath,
        branch, commitHash, baseCommitHash, options, priority } = req.body;
      let repoUrl: string | undefined = req.body.repoUrl;
      let gitToken: string | undefined = req.body.gitToken;

      if (projectId) {
        const projectCheck = await query('SELECT id FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [projectId, req.orgId]);
        if (projectCheck.rows.length === 0) throw AppError.notFound('Project not found');
      }

      // Resolve the repo to clone: a saved git connection (clone_url + stored token)
      // takes precedence; otherwise use the direct repoUrl/gitToken from the request.
      if (gitConnectionId) {
        const gc = await query('SELECT clone_url, repository_url, auth_credentials FROM git_connections WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [gitConnectionId, req.orgId]);
        if (gc.rows.length === 0) throw AppError.notFound('Git connection not found');
        const row = gc.rows[0] as Record<string, unknown>;
        repoUrl = repoUrl || (row.clone_url as string) || (row.repository_url as string);
        const creds = typeof row.auth_credentials === 'string' ? JSON.parse(row.auth_credentials || '{}') : (row.auth_credentials || {});
        gitToken = gitToken || creds.token || creds.password || undefined;
      }

      await query(
        `INSERT INTO code_reviews (id, org_id, project_id, git_connection_id, name, review_type,
          target_type, target_path, branch, commit_hash, base_commit_hash, options, status,
          started_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'queued',$13,NOW(),NOW())`,
        [reviewId, req.orgId, projectId, gitConnectionId, name, reviewType,
          targetType, targetPath, branch, commitHash, baseCommitHash,
          JSON.stringify(options), req.userId],
      );

      const priorityMap: Record<string, JobPriority> = {
        low: JobPriority.LOW, normal: JobPriority.NORMAL,
        high: JobPriority.HIGH, critical: JobPriority.CRITICAL,
      };

      await queueManager.addJob(
        QueueName.CODE_REVIEW,
        `code-review:${reviewId}`,
        {
          reviewId, projectId, gitConnectionId, reviewType, targetType,
          targetPath, repoUrl, gitToken, branch, commitHash, baseCommitHash, options,
          userId: req.userId, organizationId: req.orgId,
        } as Record<string, unknown>,
        priorityMap[priority] || JobPriority.NORMAL,
      );

      logger.info({ reviewId, reviewType, targetType, projectId }, 'Code review launched');
      res.status(201).json({ id: reviewId, status: 'queued', reviewType });
    } catch (err) { next(err); }
  },
);

// ==========================================
// Findings
// ==========================================

codeReviewRouter.get('/findings',
  requirePermission(Permission.FINDING_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(200)).optional().default('50'),
    reviewId: z.string().uuid().optional(),
    findingType: z.enum(['semantic', 'security', 'quality', 'performance', 'logic',
      'dependency', 'fuzz', 'style', 'architecture', 'configuration', 'license', 'supply_chain', 'iac', 'cicd']).optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    status: z.enum(['open', 'acknowledged', 'in_progress', 'fixed', 'wont_fix', 'false_positive', 'accepted_risk', 'remediated', 'verified']).optional(),
    language: z.string().optional(),
    search: z.string().optional(),
    sortBy: z.enum(['severity_rank', 'confidence_score', 'created_at', 'line_number']).optional().default('severity_rank'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('asc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, reviewId, findingType, severity, status, language, search, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['crf.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (reviewId) { conditions.push(`crf.review_id = $${idx++}`); params.push(reviewId); }
      if (findingType) { conditions.push(`crf.finding_type = $${idx++}`); params.push(findingType); }
      if (severity) { conditions.push(`crf.severity = $${idx++}`); params.push(severity); }
      if (status) { conditions.push(`crf.status = $${idx++}`); params.push(status); }
      if (language) { conditions.push(`crf.language = $${idx++}`); params.push(language); }
      if (search) { conditions.push(`(crf.title ILIKE $${idx} OR crf.description ILIKE $${idx} OR crf.file_path ILIKE $${idx})`); params.push(`%${search}%`); idx++; }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM code_review_findings crf WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT crf.*, p.name as project_name, cr.name as review_name, u.name as assignee_name
         FROM code_review_findings crf
         LEFT JOIN projects p ON crf.project_id = p.id
         LEFT JOIN code_reviews cr ON crf.review_id = cr.id
         LEFT JOIN users u ON crf.assigned_to = u.id
         WHERE ${where}
         ORDER BY crf.${sortBy === 'confidence_score' ? 'confidence_score' : sortBy === 'created_at' ? 'created_at' : sortBy === 'line_number' ? 'line_number' : 'severity_rank'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

codeReviewRouter.patch('/findings/:id',
  requirePermission(Permission.FINDING_UPDATE),
  validateParams(z.object({ id: z.string().uuid() })),
  validateBody(z.object({
    status: z.enum(['open', 'acknowledged', 'in_progress', 'fixed', 'wont_fix', 'false_positive', 'accepted_risk', 'remediated', 'verified']).optional(),
    assignedTo: z.string().uuid().nullable().optional(),
    comment: z.string().max(2000).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const existing = await query('SELECT id FROM code_review_findings WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (existing.rows.length === 0) throw AppError.notFound('Finding not found');

      const { status, assignedTo, comment } = req.body;
      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      if (status) { updates.push(`status = $${idx++}`); params.push(status); }
      if (assignedTo !== undefined) { updates.push(`assigned_to = $${idx++}`); params.push(assignedTo); }

      if (updates.length > 0) {
        updates.push('updated_at = NOW()');
        params.push(req.params.id);
        params.push(req.orgId);
        await query(`UPDATE code_review_findings SET ${updates.join(', ')} WHERE id = $${idx} AND org_id = $${idx + 1}`, params);
      }

      if (comment) {
        await query(
          `INSERT INTO review_comments (id, finding_id, user_id, comment, created_at)
           VALUES ($1,$2,$3,$4,NOW())`,
          [uuidv4(), req.params.id, req.userId, comment],
        );
      }

      logger.info({ findingId: req.params.id, status, assignedTo }, 'Code review finding updated');
      res.json({ message: 'Finding updated successfully' });
    } catch (err) { next(err); }
  },
);

// ==========================================
// Automated Fixes
// ==========================================

codeReviewRouter.get('/fixes/:findingId',
  requirePermission(Permission.FINDING_READ),
  validateParams(z.object({ findingId: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT * FROM code_fixes WHERE finding_id = $1 AND org_id = $2 ORDER BY confidence_level DESC`,
        [req.params.findingId, req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

codeReviewRouter.post('/fixes/:findingId/apply',
  requirePermission(Permission.FINDING_UPDATE),
  validateParams(z.object({ findingId: z.string().uuid() })),
  validateBody(z.object({ fixId: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const fixResult = await query('SELECT * FROM code_fixes WHERE id = $1 AND org_id = $2', [req.body.fixId, req.orgId]);
      if (fixResult.rows.length === 0) throw AppError.notFound('Fix not found');

      await query(
        'UPDATE code_fixes SET applied = true, applied_by = $1, applied_at = NOW() WHERE id = $2 AND org_id = $3',
        [req.userId, req.body.fixId, req.orgId],
      );

      logger.info({ fixId: req.body.fixId, findingId: req.params.findingId, userId: req.userId }, 'Fix applied');
      res.json({ message: 'Fix applied successfully. Verify the changes before committing.' });
    } catch (err) { next(err); }
  },
);

codeReviewRouter.get('/fixes/:findingId/export',
  requirePermission(Permission.FINDING_EXPORT),
  validateParams(z.object({ findingId: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'SELECT * FROM code_fixes WHERE finding_id = $1 AND org_id = $2 ORDER BY confidence_level DESC',
        [req.params.findingId, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('No fixes found');

      const fixes = result.rows as Array<Record<string, unknown>>;
      const patchContent = fixes.map(f => {
        return `# Fix: ${f.explanation || 'Automated fix'}\n` +
               `# Confidence: ${f.confidence_level}\n` +
               `# File: (apply manually)\n` +
               `--- a/original\n+++ b/fixed\n` +
               `@@ ... @@\n` +
               `-${(f.original_code as string).replace(/\n/g, '\n-')}\n` +
               `+${(f.suggested_code as string).replace(/\n/g, '\n+')}\n`;
      }).join('\n\n');

      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename="fixes-${req.params.findingId}.patch"`);
      res.send(patchContent);
    } catch (err) { next(err); }
  },
);

// ==========================================
// Fuzz Tests
// ==========================================

codeReviewRouter.get('/fuzz-tests',
  requirePermission(Permission.SCAN_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('50'),
    projectId: z.string().uuid().optional(),
    status: z.enum(['queued', 'running', 'completed', 'failed', 'cancelled']).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, status } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['ft.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`ft.project_id = $${idx++}`); params.push(projectId); }
      if (status) { conditions.push(`ft.status = $${idx++}`); params.push(status); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM fuzz_tests ft WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT ft.*, p.name as project_name
         FROM fuzz_tests ft LEFT JOIN projects p ON ft.project_id = p.id
         WHERE ${where}
         ORDER BY ft.created_at DESC
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

codeReviewRouter.post('/fuzz-tests/launch',
  requirePermission(Permission.SCAN_LAUNCH),
  validateBody(z.object({
    name: z.string().min(1).max(255),
    projectId: z.string().uuid().optional(),
    targetType: z.enum(['rest_api', 'graphql', 'soap', 'json_parser', 'xml_parser', 'file_parser',
      'cli_parser', 'config_parser', 'serialization', 'deserialization', 'regex', 'input_validation',
      'auth_workflow', 'custom']),
    targetUrl: z.string().url().optional(),
    targetFile: z.string().optional(),
    targetSpec: z.string().optional(),
    targetFunction: z.string().optional(),
    mutationCount: z.number().min(100).max(100000).optional().default(1000),
    timeoutSeconds: z.number().min(60).max(3600).optional().default(300),
    maxInputSizeBytes: z.number().min(1024).max(104857600).optional().default(1048576),
    fuzzStrategies: z.array(z.string()).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const fuzzId = uuidv4();
      const { name, projectId, targetType, targetUrl, targetFile, targetSpec, targetFunction,
        mutationCount, timeoutSeconds, maxInputSizeBytes, fuzzStrategies } = req.body;

      await query(
        `INSERT INTO fuzz_tests (id, org_id, project_id, name, target_type, target_url, target_file,
          target_spec, target_function, mutation_count, timeout_seconds, max_input_size_bytes,
          fuzz_strategies, status, started_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'queued',$14,NOW(),NOW())`,
        [fuzzId, req.orgId, projectId, name, targetType, targetUrl, targetFile,
          targetSpec, targetFunction, mutationCount, timeoutSeconds, maxInputSizeBytes,
          fuzzStrategies || [], req.userId],
      );

      await queueManager.addJob(QueueName.SAST_SCAN, `fuzz:${fuzzId}`, {
        fuzzId, projectId, targetType, targetUrl, targetFile, targetSpec,
        targetFunction, mutationCount, timeoutSeconds, maxInputSizeBytes, fuzzStrategies,
        userId: req.userId, organizationId: req.orgId,
      } as Record<string, unknown>);

      logger.info({ fuzzId, targetType, name }, 'Fuzz test launched');
      res.status(201).json({ id: fuzzId, status: 'queued', targetType });
    } catch (err) { next(err); }
  },
);

codeReviewRouter.get('/fuzz-tests/:id',
  requirePermission(Permission.SCAN_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT ft.*, p.name as project_name
         FROM fuzz_tests ft LEFT JOIN projects p ON ft.project_id = p.id
         WHERE ft.id = $1 AND ft.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Fuzz test not found');
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

codeReviewRouter.get('/fuzz-tests/:id/crashes',
  requirePermission(Permission.SCAN_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT * FROM fuzz_crashes WHERE fuzz_test_id = $1 AND org_id = $2
         ORDER BY severity DESC, created_at DESC`,
        [req.params.id, req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

// ==========================================
// Dependency Scans
// ==========================================

codeReviewRouter.get('/dependency-scans',
  requirePermission(Permission.SCAN_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    projectId: z.string().uuid().optional(),
    status: z.enum(['queued', 'running', 'completed', 'failed', 'cancelled']).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, status } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['ds.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`ds.project_id = $${idx++}`); params.push(projectId); }
      if (status) { conditions.push(`ds.status = $${idx++}`); params.push(status); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM dependency_scans ds WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT ds.*, p.name as project_name
         FROM dependency_scans ds LEFT JOIN projects p ON ds.project_id = p.id
         WHERE ${where}
         ORDER BY ds.created_at DESC
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

codeReviewRouter.get('/dependency-scans/:id',
  requirePermission(Permission.SCAN_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT ds.*, p.name as project_name
         FROM dependency_scans ds LEFT JOIN projects p ON ds.project_id = p.id
         WHERE ds.id = $1 AND ds.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Dependency scan not found');
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

codeReviewRouter.get('/dependency-scans/:id/findings',
  requirePermission(Permission.FINDING_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT * FROM dependency_findings WHERE scan_id = $1 AND org_id = $2
         ORDER BY severity DESC`,
        [req.params.id, req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

// ==========================================
// Repository Health
// ==========================================

codeReviewRouter.get('/repo-health/:reviewId',
  requirePermission(Permission.PROJECT_READ),
  validateParams(z.object({ reviewId: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT * FROM repo_health_metrics WHERE review_id = $1 AND org_id = $2`,
        [req.params.reviewId, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Health metrics not found');
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

// ==========================================
// JSON Export — structured findings for CI/CD and tool integration
// ==========================================

codeReviewRouter.get('/reviews/:id/export-json',
  requirePermission(Permission.FINDING_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const reviewResult = await query(
        `SELECT cr.id, cr.name, cr.review_type, cr.status, cr.target_type, cr.target_path,
                cr.created_at, cr.updated_at, p.name as project_name, p.id as project_id
         FROM code_reviews cr LEFT JOIN projects p ON cr.project_id = p.id
         WHERE cr.id = $1 AND cr.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (reviewResult.rows.length === 0) throw AppError.notFound('Review not found');
      const review = reviewResult.rows[0] as Record<string, unknown>;

      const findingsResult = await query(
        `SELECT crf.id, crf.title, crf.description, crf.severity, crf.finding_type,
                crf.category, crf.rule_id, crf.rule_name,
                crf.confidence_score, crf.status, crf.file_path, crf.line_number,
                crf.line_range, crf.column_number, crf.function_name, crf.class_name,
                crf.code_snippet, crf.root_cause, crf.recommended_fix,
                crf.language, crf.cwe_id, crf.cvss_score, crf.recommendation,
                crf.created_at
         FROM code_review_findings crf
         WHERE crf.review_id = $1 AND crf.org_id = $2
         ORDER BY crf.severity_rank ASC, crf.created_at ASC`,
        [req.params.id, req.orgId],
      );

      const findings = findingsResult.rows as Record<string, unknown>[];

      const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of findings) {
        const sev = f.severity as string;
        if (sev in severityCounts) severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;
      }

      const report = {
        version: '1.0',
        exportedAt: new Date().toISOString(),
        review: {
          id: review.id,
          name: review.name,
          reviewType: review.review_type,
          status: review.status,
          targetType: review.target_type,
          targetPath: review.target_path,
          projectId: review.project_id,
          projectName: review.project_name,
          startedAt: review.created_at,
          completedAt: review.updated_at,
        },
        summary: {
          totalFindings: findings.length,
          bySeverity: severityCounts,
        },
        findings: findings.map(f => ({
          id: f.id,
          title: f.title,
          description: f.description,
          severity: f.severity,
          findingType: f.finding_type || null,
          category: f.category || null,
          ruleId: f.rule_id || null,
          ruleName: f.rule_name || null,
          confidenceScore: f.confidence_score || null,
          status: f.status,
          filePath: f.file_path || null,
          lineNumber: f.line_number || null,
          lineRange: f.line_range || null,
          columnNumber: f.column_number || null,
          functionName: f.function_name || null,
          className: f.class_name || null,
          codeSnippet: f.code_snippet || null,
          rootCause: f.root_cause || null,
          recommendedFix: f.recommended_fix || null,
          language: f.language || null,
          cweId: f.cwe_id || null,
          cvssScore: f.cvss_score || null,
          recommendation: f.recommendation || null,
          createdAt: f.created_at,
        })),
      };

      res.setHeader('Content-Type', 'application/json');
      res.json(report);
    } catch (err) { next(err); }
  },
);

// ==========================================
// SARIF Export
// ==========================================

codeReviewRouter.get('/reviews/:id/export-sarif',
  requirePermission(Permission.FINDING_EXPORT),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const reviewResult = await query(
        'SELECT * FROM code_reviews WHERE id = $1 AND org_id = $2',
        [req.params.id, req.orgId],
      );
      if (reviewResult.rows.length === 0) throw AppError.notFound('Review not found');

      const findingsResult = await query(
        'SELECT * FROM code_review_findings WHERE review_id = $1 AND org_id = $2 ORDER BY severity_rank ASC',
        [req.params.id, req.orgId],
      );

      const findings = findingsResult.rows as Array<Record<string, unknown>>;

      const rules = new Map<string, Record<string, unknown>>();
      const results = findings.map((f, i) => {
        const ruleId = (f.rule_id as string) || `APP-${i}`;
        if (!rules.has(ruleId)) {
          rules.set(ruleId, {
            id: ruleId,
            name: f.title as string || `Rule ${ruleId}`,
            shortDescription: { text: (f.title as string) || '' },
            fullDescription: { text: (f.description as string) || '' },
            defaultConfiguration: { level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning' },
            helpUri: f.cwe_id ? `https://cwe.mitre.org/data/definitions/${f.cwe_id}.html` : undefined,
            properties: {
              severity: f.severity,
              precision: f.confidence_score && Number(f.confidence_score) > 0.7 ? 'high' : 'medium',
              tags: [f.finding_type, f.language].filter(Boolean),
            },
          });
        }

        const level = f.severity === 'critical' || f.severity === 'high' ? 'error'
          : f.severity === 'medium' ? 'warning' : 'note';

        return {
          ruleId,
          ruleIndex: Array.from(rules.keys()).indexOf(ruleId),
          level,
          message: {
            text: (f.message_text as string) || (f.title as string) || (f.description as string) || 'Finding',
          },
          locations: f.file_path ? [{
            physicalLocation: {
              artifactLocation: {
                uri: f.file_path as string,
                uriBaseId: '%SRCROOT%',
              },
              region: {
                startLine: (f.line_number as number) || 1,
                ...(f.column_number ? { startColumn: f.column_number as number } : {}),
                ...(f.end_line ? { endLine: f.end_line as number } : {}),
              },
            },
            ...(f.logical_location ? {
              logicalLocations: [{ fullyQualifiedName: f.logical_location as string }],
            } : {}),
          }] : [],
          ...(f.code_snippet ? {
            codeFlows: [{
              threadFlows: [{
                locations: [{
                  location: {
                    physicalLocation: {
                      artifactLocation: { uri: f.file_path as string },
                      region: {
                        startLine: (f.line_number as number) || 1,
                        snippet: { text: f.code_snippet as string },
                      },
                    },
                  },
                }],
              }],
            }],
          } : {}),
          properties: {
            severity: f.severity,
            confidence: f.confidence_score,
            precision: f.confidence_score && Number(f.confidence_score) > 0.9 ? 'very-high'
              : Number(f.confidence_score) > 0.7 ? 'high' : 'medium',
            tags: [f.finding_type, f.language].filter(Boolean),
            ...(f.cwe_id ? { cweId: f.cwe_id } : {}),
            ...(f.recommendation ? { recommendation: f.recommendation } : {}),
          },
          ...(f.cwe_id ? {
            relations: [{
              target: 'cwe',
              artifactUri: `https://cwe.mitre.org/data/definitions/${f.cwe_id}.html`,
              kind: f.cwe_id ? 'relevant' : undefined,
            }],
          } : {}),
        };
      });

      const sarif = {
        version: '2.1.0',
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        runs: [{
          tool: {
            driver: {
              name: 'Deep Vigilance Code Review',
              version: APP_VERSION,
              informationUri: 'https://github.com/mshermancyber/deep-vigilance',
              rules: Array.from(rules.values()),
              language: 'en-US',
            },
          },
          results,
          columnKind: 'utf16CodeUnits',
          properties: {
            reviewId: req.params.id,
            organizationId: req.orgId,
            exportedAt: new Date().toISOString(),
          },
        }],
      };

      const exportId = uuidv4();
      await query(
        `INSERT INTO sarif_exports (id, org_id, review_id, file_path, file_size_bytes, finding_count, exported_by, exported_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [exportId, req.orgId, req.params.id, `exports/${req.params.id}.sarif`, JSON.stringify(sarif).length, findings.length, req.userId],
      );

      logger.info({ reviewId: req.params.id, findingCount: findings.length }, 'SARIF export generated');
      res.setHeader('Content-Type', 'application/sarif+json');
      res.setHeader('Content-Disposition', `attachment; filename="review-${req.params.id}.sarif"`);
      res.json(sarif);
    } catch (err) { next(err); }
  },
);

// ==========================================
// Code Index (Incremental)
// ==========================================

codeReviewRouter.get('/reviews/:id/index',
  requirePermission(Permission.PROJECT_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const reviewCheck = await query('SELECT id FROM code_reviews WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (reviewCheck.rows.length === 0) throw AppError.notFound('Review not found');

      const result = await query(
        `SELECT file_path, language, file_size_bytes, line_count, last_indexed_at
         FROM code_index WHERE review_id = $1
         ORDER BY file_path`,
        [req.params.id],
      );
      res.json({ data: result.rows, total: result.rows.length });
    } catch (err) { next(err); }
  },
);

// ==========================================
// Webhook Handler (for CI/CD integration)
// ==========================================

codeReviewRouter.post('/webhook/:connectionId',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const connResult = await query(
        'SELECT * FROM git_connections WHERE id = $1 AND deleted_at IS NULL',
        [req.params.connectionId],
      );
      if (connResult.rows.length === 0) {
        res.status(404).json({ error: 'Not found' });
        return;
      }

      const conn = connResult.rows[0] as Record<string, unknown>;

      const signature = req.headers['x-hub-signature-256'] as string
        || req.headers['x-gitlab-token'] as string
        || req.headers['x-hook-signature'] as string;

      if (conn.webhook_secret) {
        if (!signature) {
          logger.warn({ connId: conn.id }, 'Webhook rejected: missing signature');
          res.status(401).json({ error: 'Missing webhook signature' });
          return;
        }

        const { verifySignature } = await import('../../services/integration/webhook-service.js');
        const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);

        let signatureValue = signature;
        if (signatureValue.startsWith('sha256=')) {
          signatureValue = signatureValue.slice(7);
        }

        let secret: string;
        try {
          secret = decrypt(conn.webhook_secret as string);
        } catch {
          logger.warn({ connId: conn.id }, 'Webhook rejected: failed to decrypt secret');
          res.status(401).json({ error: 'Webhook authentication error' });
          return;
        }

        if (!verifySignature(rawBody, signatureValue, secret)) {
          logger.warn({ connId: conn.id }, 'Webhook rejected: invalid signature');
          res.status(401).json({ error: 'Invalid webhook signature' });
          return;
        }
      }

      const event = req.headers['x-github-event'] || req.headers['x-gitlab-event'] || 'push';

      res.status(200).json({ received: true, event });

      if (event === 'push') {
        const { parseGitHubWebhook, parseGitLabWebhook, parseBitbucketWebhook } = await import('../../services/git/git-service.js');

        let parsed = null;
        if (conn.provider === 'github') parsed = parseGitHubWebhook(req.body);
        else if (conn.provider === 'gitlab') parsed = parseGitLabWebhook(req.body);
        else if (conn.provider === 'bitbucket') parsed = parseBitbucketWebhook(req.body);

        if (parsed && conn.sync_enabled) {
          logger.info({ connId: conn.id, commit: parsed.commitHash }, 'Auto-trigger incremental rescan from webhook');
          const reviewId = uuidv4();
          await query(
            `INSERT INTO code_reviews (id, org_id, project_id, git_connection_id, name, review_type,
              target_type, branch, commit_hash, base_commit_hash, status, started_by, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,'incremental','repository',$6,$7,$8,'queued',$9,NOW(),NOW())`,
            [reviewId, conn.org_id, conn.project_id, conn.id,
              `Auto-rescan: ${parsed.commitHash.slice(0, 8)}`,
              parsed.branch, parsed.commitHash, parsed.baseHash, null],
          );
        }
      }
    } catch (err) { next(err); }
  },
);
