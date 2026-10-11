import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery, validateParams } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { queueManager, JobPriority } from '../../core/queue/manager.js';
import { logger } from '../../core/logging/logger.js';
import { analyzeSbom, getSbomGraphHtml, isSbomVisualizerConfigured } from '../../services/integration/sbom-service.js';

export const sbomRouter = Router();

const generateSbomSchema = z.object({
  projectId: z.string().uuid().optional(),
  scanId: z.string().uuid().optional(),
  format: z.enum(['cyclonedx', 'spdx']).optional().default('cyclonedx'),
  version: z.string().optional().default('1.5'),
  includeVulnerabilities: z.boolean().optional().default(true),
  includeLicenses: z.boolean().optional().default(true),
  includeMetadata: z.boolean().optional().default(true),
  priority: z.enum(['low', 'normal', 'high', 'critical']).optional().default('normal'),
  options: z.object({
    includeDevDependencies: z.boolean().optional().default(true),
    includeTransitiveDependencies: z.boolean().optional().default(true),
    includeSourceInfo: z.boolean().optional().default(false),
  }).optional().default({}),
});

sbomRouter.get('/exports',
  requirePermission(Permission.SCAN_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    projectId: z.string().uuid().optional(),
    format: z.enum(['cyclonedx', 'spdx']).optional(),
    status: z.enum(['queued', 'generating', 'completed', 'failed']).optional(),
    sortBy: z.enum(['format', 'version', 'created_at', 'status']).optional().default('created_at'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, format, status, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['se.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`se.project_id = $${idx++}`); params.push(projectId); }
      if (format) { conditions.push(`se.format = $${idx++}`); params.push(format); }
      if (status) { conditions.push(`se.status = $${idx++}`); params.push(status); }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM sbom_exports se WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT se.*, p.name as project_name, u.name as generated_by_name,
                se.file_size_bytes, se.component_count
         FROM sbom_exports se
         LEFT JOIN projects p ON se.project_id = p.id
         LEFT JOIN users u ON se.generated_by = u.id
         WHERE ${where}
         ORDER BY se.${sortBy === 'format' ? 'format' : sortBy === 'version' ? 'version' : sortBy === 'status' ? 'status' : 'created_at'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

sbomRouter.post('/generate',
  requirePermission(Permission.REPORT_CREATE),
  validateBody(generateSbomSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const exportId = uuidv4();
      const { projectId, scanId, format, version, includeVulnerabilities, includeLicenses, includeMetadata, priority, options } = req.body;

      if (projectId) {
        const projectCheck = await query('SELECT id FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [projectId, req.orgId]);
        if (projectCheck.rows.length === 0) throw AppError.notFound('Project not found');
      }

      const componentCount = 0;
      const fileSizeBytes = 0;

      await query(
        `INSERT INTO sbom_exports (id, org_id, project_id, scan_id, format, version, status,
          include_vulnerabilities, include_licenses, include_metadata, options,
          component_count, file_size_bytes, generated_by, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,'queued',$7,$8,$9,$10,$11,$12,$13,NOW())`,
        [exportId, req.orgId, projectId || null, scanId || null, format, version,
          includeVulnerabilities, includeLicenses, includeMetadata, JSON.stringify(options),
          componentCount, fileSizeBytes, req.userId],
      );

      const priorityMap: Record<string, JobPriority> = {
        low: JobPriority.LOW, normal: JobPriority.NORMAL,
        high: JobPriority.HIGH, critical: JobPriority.CRITICAL,
      };

      await queueManager.addJob(
        'sbom-generation' as any,
        `sbom:${exportId}`,
        {
          sbomExportId: exportId, projectId, scanId, format, version,
          includeVulnerabilities, includeLicenses, includeMetadata, options,
          userId: req.userId, organizationId: req.orgId,
        } as Record<string, unknown>,
        priorityMap[priority] || JobPriority.NORMAL,
      );

      logger.info({ exportId, format, projectId: projectId || 'global' }, 'SBOM generation queued');
      res.status(201).json({ id: exportId, format, status: 'queued' });
    } catch (err) { next(err); }
  },
);

sbomRouter.get('/exports/:id',
  requirePermission(Permission.REPORT_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT se.*, p.name as project_name, u.name as generated_by_name
         FROM sbom_exports se
         LEFT JOIN projects p ON se.project_id = p.id
         LEFT JOIN users u ON se.generated_by = u.id
         WHERE se.id = $1 AND se.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('SBOM export not found');
      res.json(result.rows[0]);
    } catch (err) { next(err); }
  },
);

sbomRouter.get('/exports/:id/download',
  requirePermission(Permission.REPORT_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT se.*, p.name as project_name
         FROM sbom_exports se
         LEFT JOIN projects p ON se.project_id = p.id
         WHERE se.id = $1 AND se.org_id = $2`,
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('SBOM export not found');

      const exportData = result.rows[0] as Record<string, unknown>;
      if (exportData.status !== 'completed') {
        throw AppError.badRequest('SBOM export is not yet completed');
      }

      const mimeType = exportData.format === 'cyclonedx'
        ? 'application/vnd.cyclonedx+json'
        : 'application/spdx+json';

      res.setHeader('Content-Type', mimeType);
      res.setHeader('Content-Disposition', `attachment; filename="sbom-${req.params.id}.${exportData.format === 'cyclonedx' ? 'cdx.json' : 'spdx.json'}"`);
      res.json(exportData.sbom_content || exportData);
    } catch (err) { next(err); }
  },
);

sbomRouter.get('/exports/:id/enrichment',
  requirePermission(Permission.REPORT_READ),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'SELECT se.id, se.status, se.sbom_content, se.enrichment, se.graph_html, se.enrichment_status, se.org_id FROM sbom_exports se WHERE se.id = $1 AND se.org_id = $2',
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('SBOM export not found');

      const row = result.rows[0] as Record<string, unknown>;
      if (row.status !== 'completed') {
        throw AppError.badRequest('SBOM export is not yet completed');
      }

      // If enrichment hasn't been attempted yet, trigger it (best-effort)
      if (!row.enrichment && row.sbom_content && isSbomVisualizerConfigured()) {
        try {
          const sbomContent = typeof row.sbom_content === 'string' ? JSON.parse(row.sbom_content as string) : row.sbom_content;
          const analyzeResult = await analyzeSbom(sbomContent as object);
          const graphHtml = await getSbomGraphHtml(sbomContent as object);

          const enrichmentData = analyzeResult ? {
            sbom: analyzeResult.sbom,
            findings: analyzeResult.findings,
            summary: analyzeResult.summary,
            scanId: analyzeResult.scanId,
            errors: analyzeResult.errors,
            assessment: analyzeResult.assessment,
          } : null;

          await query(
            'UPDATE sbom_exports SET enrichment = $2::jsonb, graph_html = $3, enrichment_status = $4 WHERE id = $1',
            [req.params.id, enrichmentData ? JSON.stringify(enrichmentData) : null, graphHtml, enrichmentData ? 'completed' : 'failed'],
          );

          row.enrichment = enrichmentData;
          row.graph_html = graphHtml;
          row.enrichment_status = enrichmentData ? 'completed' : 'failed';
        } catch (err) {
          logger.error({ exportId: req.params.id, err }, 'SBOM enrichment failed');
          try {
            await query('UPDATE sbom_exports SET enrichment_status = $2 WHERE id = $1', [req.params.id, 'failed']);
          } catch { /* best-effort */ }
          row.enrichment_status = 'failed';
        }
      }

      const enrichment = row.enrichment as Record<string, unknown> | null;
      res.json({
        findings: enrichment?.findings || [],
        summary: enrichment?.summary || null,
        assessment: enrichment?.assessment || null,
        graphHtml: row.graph_html || null,
        status: row.enrichment_status || 'pending',
      });
    } catch (err) { next(err); }
  },
);

sbomRouter.get('/license-audit',
  requirePermission(Permission.SCAN_READ),
  validateQuery(z.object({
    page: z.string().transform(Number).pipe(z.number().min(1)).optional().default('1'),
    limit: z.string().transform(Number).pipe(z.number().min(1).max(200)).optional().default('50'),
    projectId: z.string().uuid().optional(),
    licenseName: z.string().max(200).optional(),
    riskLevel: z.enum(['restricted', 'high', 'medium', 'low', 'unknown', 'permissive']).optional(),
    search: z.string().optional(),
    sortBy: z.enum(['license_name', 'detected_at', 'risk_level', 'component_name']).optional().default('detected_at'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { page, limit, projectId, licenseName, riskLevel, search, sortBy, sortOrder } = req.query as any;
      const offset = (Number(page) - 1) * Number(limit);
      const conditions = ['la.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (projectId) { conditions.push(`la.project_id = $${idx++}`); params.push(projectId); }
      if (licenseName) { conditions.push(`la.license_name ILIKE $${idx++}`); params.push(`%${licenseName}%`); }
      if (riskLevel) { conditions.push(`la.risk_level = $${idx++}`); params.push(riskLevel); }
      if (search) { conditions.push(`(la.license_name ILIKE $${idx} OR la.component_name ILIKE $${idx} OR la.package_name ILIKE $${idx})`); params.push(`%${search}%`); idx++; }

      const where = conditions.join(' AND ');
      const countResult = await query(`SELECT COUNT(*) FROM license_audit la WHERE ${where}`, params);
      const total = parseInt((countResult.rows[0] as Record<string,unknown>).count as string, 10);

      const result = await query(
        `SELECT la.*, p.name as project_name
         FROM license_audit la
         LEFT JOIN projects p ON la.project_id = p.id
         WHERE ${where}
         ORDER BY la.${sortBy === 'license_name' ? 'license_name' : sortBy === 'risk_level' ? 'risk_level' : sortBy === 'component_name' ? 'component_name' : 'detected_at'} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, Number(limit), offset],
      );

      res.json({ data: result.rows, pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) } });
    } catch (err) { next(err); }
  },
);

sbomRouter.get('/license-audit/summary',
  requirePermission(Permission.SCAN_READ),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const conditions = ['la.org_id = $1'];
      const params: unknown[] = [req.orgId];
      let idx = 2;

      if (req.query.projectId) {
        conditions.push(`la.project_id = $${idx}`);
        params.push(req.query.projectId as string);
      }

      const where = conditions.join(' AND ');

      const result = await query(
        `SELECT
           COUNT(*) as total_licenses,
           COUNT(*) FILTER (WHERE la.risk_level = 'restricted') as restricted_count,
           COUNT(*) FILTER (WHERE la.risk_level = 'high') as high_risk_count,
           COUNT(*) FILTER (WHERE la.risk_level = 'medium') as medium_risk_count,
           COUNT(*) FILTER (WHERE la.risk_level = 'low') as low_risk_count,
           COUNT(*) FILTER (WHERE la.risk_level = 'permissive') as permissive_count,
           COUNT(DISTINCT la.license_name) as unique_licenses,
           COUNT(DISTINCT la.component_name) as affected_components
         FROM license_audit la
         WHERE ${where}`,
        params,
      );

      res.json(result.rows[0] || { total_licenses: 0 });
    } catch (err) { next(err); }
  },
);
