import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody } from '../../middleware/validate.js';
import { analyzeFinding, batchReviewFindings, searchFindings, getStatus } from '../../services/ai/ai-service.js';

export const aiRouter = Router();

aiRouter.post('/analyze',
  requirePermission(Permission.FINDING_READ),
  validateBody(z.object({
    findingId: z.string().uuid().optional(),
    source: z.enum(['findings', 'code_review']).optional(),
    finding: z.object({
      title: z.string(),
      severity: z.string(),
      cweId: z.string().optional(),
      filePath: z.string().optional(),
      lineNumber: z.number().optional(),
      codeSnippet: z.string().optional(),
      description: z.string().optional(),
      recommendation: z.string().optional(),
      confidenceScore: z.number().optional(),
    }).optional(),
  }).refine(d => d.findingId || d.finding, { message: 'Provide findingId or finding object' })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      let finding = req.body.finding;

      if (req.body.findingId && !finding) {
        const { query } = await import('../../core/db/pool.js');
        const table = req.body.source === 'code_review' ? 'code_review_findings' : 'findings';
        const cols = req.body.source === 'code_review'
          ? `id, title, severity, rule_id AS "cweId", file_path AS "filePath",
             line_number AS "lineNumber", code_snippet AS "codeSnippet",
             description, root_cause AS recommendation, confidence_score AS "confidenceScore"`
          : `id, title, severity, cwe_id AS "cweId", file_path AS "filePath",
             line_number AS "lineNumber", code_snippet AS "codeSnippet",
             description, recommendation, confidence AS "confidenceScore"`;
        const result = await query(
          `SELECT ${cols} FROM ${table} WHERE id = $1 AND org_id = $2`,
          [req.body.findingId, req.orgId],
        );
        if (result.rows.length === 0) {
          res.status(404).json({ error: 'Finding not found' });
          return;
        }
        finding = result.rows[0];
      }

      const analysis = await analyzeFinding(finding);
      res.json(analysis);
    } catch (err) {
      next(err);
    }
  },
);

aiRouter.post('/batch-review',
  requirePermission(Permission.FINDING_READ),
  validateBody(z.object({
    findingIds: z.array(z.string().uuid()).min(1).max(100).optional(),
    scanId: z.string().uuid().optional(),
    reviewId: z.string().uuid().optional(),
  }).refine(d => d.findingIds || d.scanId || d.reviewId, { message: 'Provide findingIds, scanId, or reviewId' })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      let { findingIds } = req.body;
      let source: 'findings' | 'code_review' = 'findings';

      if (req.body.reviewId) {
        const { query } = await import('../../core/db/pool.js');
        const result = await query(
          `SELECT id FROM code_review_findings WHERE review_id = $1 AND org_id = $2 LIMIT 100`,
          [req.body.reviewId, req.orgId],
        );
        findingIds = result.rows.map((r: Record<string, unknown>) => r.id as string);
        source = 'code_review';
        if (findingIds.length === 0) {
          res.status(404).json({ error: 'No code review findings found' });
          return;
        }
      } else if (!findingIds && req.body.scanId) {
        const { query } = await import('../../core/db/pool.js');
        const result = await query(
          `SELECT id FROM findings WHERE scan_id = $1 AND org_id = $2 LIMIT 100`,
          [req.body.scanId, req.orgId],
        );
        findingIds = result.rows.map((r: Record<string, unknown>) => r.id as string);
        if (findingIds.length === 0) {
          res.status(404).json({ error: 'No findings found for this scan' });
          return;
        }
      }

      const result = await batchReviewFindings(findingIds, req.orgId!, source);
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

aiRouter.post('/search',
  requirePermission(Permission.SEARCH_GLOBAL),
  validateBody(z.object({
    query: z.string().min(1).max(500),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await searchFindings(req.body.query, req.orgId!);
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

aiRouter.get('/status',
  requirePermission(Permission.FINDING_READ),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      res.json(await getStatus());
    } catch (err) {
      next(err);
    }
  },
);
