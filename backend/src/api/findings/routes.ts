import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery, validateParams } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';
import { APP_VERSION } from '../../version.js';

export const findingsRouter = Router();

findingsRouter.get('/',
  requirePermission(Permission.FINDING_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(200)).optional().default('50'),
    projectId: z.string().uuid().optional(),
    scanId: z.string().uuid().optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    status: z.enum(['open', 'in_progress', 'resolved', 'closed', 'false_positive', 'wont_fix']).optional(),
    type: z.enum(['sast', 'dast', 'api', 'sca', 'secret', 'manual']).optional(),
    cweId: z.string().optional(),
    assignedTo: z.string().uuid().optional(),
    search: z.string().optional(),
    sortBy: z.enum(['severity_rank', 'cvss_score', 'created_at', 'title']).optional().default('severity_rank'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('asc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, scanId, severity, status, type, cweId, assignedTo, search, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['f.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`f.project_id = $${idx++}`); params.push(projectId); }
      if (scanId) { conditions.push(`f.scan_id = $${idx++}`); params.push(scanId); }
      if (severity) { conditions.push(`f.severity = $${idx++}`); params.push(severity); }
      if (status) { conditions.push(`f.status = $${idx++}`); params.push(status); }
      if (type) { conditions.push(`f.type = $${idx++}`); params.push(type); }
      if (cweId) { conditions.push(`f.cwe_id = $${idx++}`); params.push(cweId); }
      if (assignedTo) { conditions.push(`f.assigned_to = $${idx++}`); params.push(assignedTo); }
      if (search) { conditions.push(`(f.title ILIKE $${idx} OR f.description ILIKE $${idx} OR f.file_path ILIKE $${idx})`); params.push(`%${search}%`); idx++; }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM findings f WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT f.*, p.name as project_name, u.name as assignee_name
         FROM findings f
         JOIN projects p ON f.project_id = p.id
         LEFT JOIN users u ON f.assigned_to = u.id
         WHERE ${where}
         ORDER BY f.${sortBy === 'cvss_score' ? 'cvss_score' : sortBy === 'title' ? 'title' : sortBy === 'created_at' ? 'created_at' : 'severity_rank'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

findingsRouter.get('/:id',
  requirePermission(Permission.FINDING_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT f.*, p.name as project_name, u.name as assignee_name,
                s.name as scan_name, s.scan_type
         FROM findings f
         JOIN projects p ON f.project_id = p.id
         LEFT JOIN users u ON f.assigned_to = u.id
         LEFT JOIN scans s ON f.scan_id = s.id
         WHERE f.id = $1 AND f.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Finding not found');
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

findingsRouter.patch('/:id',
  requirePermission(Permission.FINDING_UPDATE),
  validateParams(z.object({ id: z.string().uuid() })),
  validateBody(z.object({
    status: z.enum(['open', 'in_progress', 'resolved', 'closed', 'false_positive', 'wont_fix']).optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    assignedTo: z.string().uuid().nullable().optional(),
    comment: z.string().max(2000).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const existing = await query('SELECT id FROM findings WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (existing.rows.length === 0) throw AppError.notFound('Finding not found');

      const { status, severity, assignedTo, comment } = req.body;
      const updates: string[] = [];
      const params: unknown[] = [];
      let idx = 1;

      if (status) { updates.push(`status = $${idx++}`); params.push(status); }
      if (severity) { updates.push(`severity = $${idx++}`); params.push(severity);
        const rankMap: Record<string,number> = { critical:1, high:2, medium:3, low:4, info:5 };
        updates.push(`severity_rank = $${idx++}`); params.push(rankMap[severity]); }
      if (assignedTo !== undefined) { updates.push(`assigned_to = $${idx++}`); params.push(assignedTo); }

      if (updates.length > 0) {
        updates.push('updated_at = NOW()');
        params.push(req.params.id);
        params.push(req.orgId);
        await query(`UPDATE findings SET ${updates.join(', ')} WHERE id = $${idx} AND org_id = $${idx + 1}`, params);
      }

      if (comment) {
        await query(
          `INSERT INTO finding_comments (id, finding_id, user_id, comment, created_at)
           VALUES ($1, $2, $3, $4, NOW())`,
          [uuidv4(), req.params.id, req.userId, comment],
        );
      }

      logger.info({ findingId: req.params.id }, 'Finding updated');
      res.json({ message: 'Finding updated successfully' });
    } catch (err) { next(err); }
  },
);

findingsRouter.get('/export/sarif/:scanId',
  requirePermission(Permission.FINDING_READ),
  validateParams(z.object({ scanId: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Verify the scan belongs to this org
      const scanResult = await query(
        `SELECT s.id, s.name, s.scan_type, s.created_at, p.name as project_name
         FROM scans s JOIN projects p ON s.project_id = p.id
         WHERE s.id = $1 AND s.org_id = $2`,
        [req.params.scanId, req.orgId],
      );
      if (scanResult.rows.length === 0) throw AppError.notFound('Scan not found');
      const scan = scanResult.rows[0] as Record<string, unknown>;

      // Fetch all findings for this scan
      const findingsResult = await query(
        `SELECT f.id, f.title, f.description, f.severity, f.confidence,
                f.file_path, f.line_number, f.line_range, f.code_snippet,
                f.endpoint, f.http_method, f.rule_id, f.rule_name,
                f.cwe_id, f.cve_id, f.owasp_category, f.cvss_score,
                f.cvss_vector, f.recommendation, f.type
         FROM findings f
         WHERE f.scan_id = $1 AND f.org_id = $2
         ORDER BY f.severity_rank ASC, f.created_at ASC`,
        [req.params.scanId, req.orgId],
      );

      const findings = findingsResult.rows as Record<string, unknown>[];

      // Map severity to SARIF level
      const severityToLevel = (sev: string): string => {
        if (sev === 'critical' || sev === 'high') return 'error';
        if (sev === 'medium') return 'warning';
        return 'note';
      };

      // Build unique rules from findings
      const rulesMap = new Map<string, Record<string, unknown>>();
      for (const f of findings) {
        const ruleId = (f.rule_id as string) || (f.cwe_id as string) || (f.id as string);
        if (!rulesMap.has(ruleId)) {
          const cweId = f.cwe_id as string | null;
          rulesMap.set(ruleId, {
            id: ruleId,
            name: (f.rule_name as string) || (f.title as string),
            shortDescription: { text: f.title as string },
            fullDescription: { text: (f.description as string) || (f.title as string) },
            ...(cweId ? {
              helpUri: `https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`,
            } : {}),
            properties: {
              severity: f.severity as string,
              confidence: (f.confidence as string) || 'medium',
              ...(f.cvss_score ? { cvssScore: f.cvss_score } : {}),
              ...(f.owasp_category ? { owaspCategory: f.owasp_category } : {}),
            },
          });
        }
      }

      // Build SARIF results
      const results = findings.map((f) => {
        const ruleId = (f.rule_id as string) || (f.cwe_id as string) || (f.id as string);
        const locations: Record<string, unknown>[] = [];

        if (f.file_path) {
          locations.push({
            physicalLocation: {
              artifactLocation: { uri: f.file_path as string },
              region: {
                startLine: (f.line_number as number) || 1,
                ...(f.code_snippet ? { snippet: { text: f.code_snippet as string } } : {}),
              },
            },
          });
        } else if (f.endpoint) {
          locations.push({
            physicalLocation: {
              artifactLocation: { uri: f.endpoint as string },
            },
          });
        }

        return {
          ruleId,
          level: severityToLevel(f.severity as string),
          message: { text: (f.description as string) || (f.title as string) },
          locations,
          ...(f.recommendation ? {
            fixes: [{
              description: { text: f.recommendation as string },
            }],
          } : {}),
        };
      });

      const sarif = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
        version: '2.1.0' as const,
        runs: [{
          tool: {
            driver: {
              name: 'Deep Vigilance',
              version: APP_VERSION,
              informationUri: 'https://github.com/mshermancyber/deep-vigilance',
              rules: Array.from(rulesMap.values()),
            },
          },
          results,
          invocations: [{
            executionSuccessful: true,
            startTimeUtc: scan.created_at as string,
          }],
          automationDetails: {
            id: `deep-vigilance/${scan.scan_type}/${req.params.scanId}`,
            description: { text: `${scan.project_name} - ${scan.name}` },
          },
        }],
      };

      res.setHeader('Content-Type', 'application/sarif+json');
      res.setHeader('Content-Disposition', `attachment; filename="dv-scan-${req.params.scanId}.sarif"`);
      res.json(sarif);
    } catch (err) { next(err); }
  },
);

// ==========================================
// JSON Export — structured findings for CI/CD and tool integration
// ==========================================

findingsRouter.get('/export/json/:scanId',
  requirePermission(Permission.FINDING_READ),
  validateParams(z.object({ scanId: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const scanResult = await query(
        `SELECT s.id, s.name, s.scan_type, s.status, s.created_at, s.updated_at,
                p.name as project_name, p.id as project_id
         FROM scans s JOIN projects p ON s.project_id = p.id
         WHERE s.id = $1 AND s.org_id = $2`,
        [req.params.scanId, req.orgId],
      );
      if (scanResult.rows.length === 0) throw AppError.notFound('Scan not found');
      const scan = scanResult.rows[0] as Record<string, unknown>;

      const findingsResult = await query(
        `SELECT f.id, f.title, f.description, f.severity, f.confidence,
                f.file_path, f.line_number, f.line_range, f.code_snippet,
                f.endpoint, f.http_method, f.rule_id, f.rule_name,
                f.cwe_id, f.cve_id, f.owasp_category, f.cvss_score,
                f.cvss_vector, f.recommendation, f.type, f.status,
                f.created_at
         FROM findings f
         WHERE f.scan_id = $1 AND f.org_id = $2
         ORDER BY f.severity_rank ASC, f.created_at ASC`,
        [req.params.scanId, req.orgId],
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
        scan: {
          id: scan.id,
          name: scan.name,
          type: scan.scan_type,
          status: scan.status,
          projectId: scan.project_id,
          projectName: scan.project_name,
          startedAt: scan.created_at,
          completedAt: scan.updated_at,
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
          confidence: f.confidence,
          status: f.status,
          filePath: f.file_path || null,
          lineNumber: f.line_number || null,
          lineRange: f.line_range || null,
          codeSnippet: f.code_snippet || null,
          endpoint: f.endpoint || null,
          httpMethod: f.http_method || null,
          ruleId: f.rule_id || null,
          ruleName: f.rule_name || null,
          cweId: f.cwe_id || null,
          cveId: f.cve_id || null,
          owaspCategory: f.owasp_category || null,
          cvssScore: f.cvss_score || null,
          cvssVector: f.cvss_vector || null,
          recommendation: f.recommendation || null,
          createdAt: f.created_at,
        })),
      };

      res.setHeader('Content-Type', 'application/json');
      res.json(report);
    } catch (err) { next(err); }
  },
);

findingsRouter.get('/stats/summary',
  requirePermission(Permission.FINDING_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT
           COUNT(*) as total,
           COUNT(*) FILTER (WHERE severity = 'critical' AND status != 'closed') as critical,
           COUNT(*) FILTER (WHERE severity = 'high' AND status != 'closed') as high,
           COUNT(*) FILTER (WHERE severity = 'medium' AND status != 'closed') as medium,
           COUNT(*) FILTER (WHERE severity = 'low' AND status != 'closed') as low,
           COUNT(*) FILTER (WHERE severity = 'info' AND status != 'closed') as info,
           COUNT(*) FILTER (WHERE status = 'resolved') as resolved,
           COUNT(*) FILTER (WHERE status = 'false_positive') as false_positives,
           COUNT(*) FILTER (WHERE type = 'sast') as sast_findings,
           COUNT(*) FILTER (WHERE type = 'dast') as dast_findings,
           COUNT(*) FILTER (WHERE type = 'api') as api_findings,
           AVG(cvss_score) FILTER (WHERE cvss_score > 0) as avg_cvss,
           MAX(cvss_score) as max_cvss
         FROM findings
         WHERE org_id = $1 AND status != 'closed'`,
        [req.orgId],
      );
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);
