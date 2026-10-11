import { Router, Request, Response, NextFunction } from 'express';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { cacheGet, cacheSet } from '../../core/redis/client.js';

export const dashboardRouter = Router();

dashboardRouter.get('/summary',
  requirePermission(Permission.DASHBOARD_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const cacheKey = `dashboard:summary:${req.orgId}`;
      const cached = await cacheGet(cacheKey);
      if (cached) { res.json(cached); return; }

      const [findings, projects, scans, recentScans, topVulnerable, apiStats] = await Promise.all([
        query(`SELECT
          COUNT(*) FILTER (WHERE status != 'closed') as open_findings,
          COUNT(*) FILTER (WHERE severity = 'critical' AND status != 'closed') as critical,
          COUNT(*) FILTER (WHERE severity = 'high' AND status != 'closed') as high,
          COUNT(*) FILTER (WHERE severity = 'medium' AND status != 'closed') as medium,
          COUNT(*) FILTER (WHERE severity = 'low' AND status != 'closed') as low,
          COUNT(*) FILTER (WHERE severity = 'info' AND status != 'closed') as info,
          ROUND(AVG(cvss_score) FILTER (WHERE cvss_score > 0)::numeric, 1) as avg_cvss,
          MAX(cvss_score) as max_cvss
        FROM findings WHERE org_id = $1`, [req.orgId]),

        query(`SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE deleted_at IS NULL) as active,
          (SELECT COUNT(*) FROM projects WHERE org_id = $1 AND deleted_at IS NULL AND updated_at > NOW() - INTERVAL '7 days') as updated_this_week
        FROM projects WHERE org_id = $1`, [req.orgId]),

        query(`SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE status = 'running') as running,
          COUNT(*) FILTER (WHERE status = 'queued') as queued,
          COUNT(*) FILTER (WHERE status = 'completed') as completed,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h
        FROM scans WHERE org_id = $1`, [req.orgId]),

        query(`SELECT s.id, s.name, s.scan_type, s.status, s.started_at,
                  p.name as project_name,
                  (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) as finding_count
         FROM scans s JOIN projects p ON s.project_id = p.id
         WHERE s.org_id = $1
         ORDER BY s.created_at DESC LIMIT 10`, [req.orgId]),

        query(`SELECT p.id, p.name,
                  COUNT(f.id) FILTER (WHERE f.status != 'closed') as open_findings,
                  COUNT(f.id) FILTER (WHERE f.severity = 'critical' AND f.status != 'closed') as critical,
                  COUNT(f.id) FILTER (WHERE f.severity = 'high' AND f.status != 'closed') as high
         FROM projects p LEFT JOIN findings f ON p.id = f.project_id AND f.status != 'closed'
         WHERE p.org_id = $1 AND p.deleted_at IS NULL
         GROUP BY p.id, p.name
         ORDER BY critical DESC, high DESC LIMIT 10`, [req.orgId]),

        query(`SELECT
          COUNT(*) as total_api_scans,
          COUNT(*) FILTER (WHERE status = 'completed') as completed_api_scans,
          COUNT(*) FILTER (WHERE status = 'running') as running_api_scans,
          COUNT(*) FILTER (WHERE status = 'queued') as queued_api_scans,
          (SELECT COUNT(*) FROM findings f2 JOIN scans s2 ON f2.scan_id = s2.id WHERE s2.scan_type = 'api' AND s2.org_id = $1 AND f2.status != 'closed') as total_api_findings,
          (SELECT COUNT(*) FROM findings f2 JOIN scans s2 ON f2.scan_id = s2.id WHERE s2.scan_type = 'api' AND s2.org_id = $1 AND f2.severity = 'critical' AND f2.status != 'closed') as api_critical,
          (SELECT COUNT(*) FROM findings f2 JOIN scans s2 ON f2.scan_id = s2.id WHERE s2.scan_type = 'api' AND s2.org_id = $1 AND f2.severity = 'high' AND f2.status != 'closed') as api_high,
          (SELECT COUNT(*) FROM findings f2 JOIN scans s2 ON f2.scan_id = s2.id WHERE s2.scan_type = 'api' AND s2.org_id = $1 AND f2.severity = 'medium' AND f2.status != 'closed') as api_medium,
          (SELECT COUNT(*) FROM findings f2 JOIN scans s2 ON f2.scan_id = s2.id WHERE s2.scan_type = 'api' AND s2.org_id = $1 AND f2.severity = 'low' AND f2.status != 'closed') as api_low
        FROM scans WHERE org_id = $1 AND scan_type = 'api'`, [req.orgId]),
      ]);

      const summary = {
        findings: findings.rows[0],
        projects: projects.rows[0],
        scans: scans.rows[0],
        recentScans: recentScans.rows,
        topVulnerableApps: topVulnerable.rows,
        apiStats: apiStats.rows[0],
      };

      await cacheSet(cacheKey, summary, 60);
      res.json(summary);
    } catch (err) { next(err); }
  },
);

dashboardRouter.get('/trend',
  requirePermission(Permission.DASHBOARD_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `WITH date_series AS (
           SELECT generate_series(
             NOW() - INTERVAL '30 days',
             NOW(),
             INTERVAL '1 day'
           )::date as date
         )
         SELECT ds.date,
           COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'critical'), 0) as critical,
           COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'high'), 0) as high,
           COALESCE(COUNT(f.id) FILTER (WHERE f.severity = 'medium'), 0) as medium,
           COALESCE(COUNT(s.id), 0) as scans
         FROM date_series ds
         LEFT JOIN findings f ON f.created_at::date = ds.date AND f.org_id = $1
         LEFT JOIN scans s ON s.created_at::date = ds.date AND s.org_id = $1
         GROUP BY ds.date ORDER BY ds.date`,
        [req.orgId],
      );

      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

dashboardRouter.get('/owasp-top-10',
  requirePermission(Permission.DASHBOARD_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT
           COALESCE(owasp_category, 'Other') as category,
           COUNT(*) as count
         FROM findings
         WHERE org_id = $1 AND status != 'closed' AND owasp_category IS NOT NULL
         GROUP BY owasp_category
         ORDER BY count DESC LIMIT 10`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

dashboardRouter.get('/risk-heatmap',
  requirePermission(Permission.DASHBOARD_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT p.name as project,
           COUNT(f.id) FILTER (WHERE f.severity = 'critical' AND f.status != 'closed') as critical,
           COUNT(f.id) FILTER (WHERE f.severity = 'high' AND f.status != 'closed') as high
         FROM projects p
         LEFT JOIN findings f ON p.id = f.project_id AND f.status != 'closed'
         WHERE p.org_id = $1 AND p.deleted_at IS NULL
         GROUP BY p.id, p.name
         ORDER BY critical DESC, high DESC`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

dashboardRouter.get('/fix-rate',
  requirePermission(Permission.DASHBOARD_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `WITH weekly_stats AS (
           SELECT
             DATE_TRUNC('week', created_at) as week,
             COUNT(*) FILTER (WHERE status IN ('resolved', 'closed')) as fixed,
             COUNT(*) as total
           FROM findings WHERE org_id = $1
           GROUP BY week ORDER BY week DESC LIMIT 12
         )
         SELECT week, total, fixed,
           CASE WHEN total > 0 THEN ROUND((fixed::numeric / total) * 100, 1) ELSE 0 END as fix_rate_pct
         FROM weekly_stats ORDER BY week`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

dashboardRouter.get('/cve-distribution',
  requirePermission(Permission.DASHBOARD_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT
           COALESCE(cve_id, 'No CVE') as cve,
           COUNT(*) as count,
           ROUND(AVG(cvss_score) FILTER (WHERE cvss_score > 0)::numeric, 1) as avg_cvss
         FROM findings WHERE org_id = $1 AND cve_id IS NOT NULL AND status != 'closed'
         GROUP BY cve_id ORDER BY count DESC LIMIT 20`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

dashboardRouter.get('/executive-summary',
  requirePermission(Permission.DASHBOARD_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const [risk, scans, fixRate] = await Promise.all([
        query(`SELECT
          COUNT(*) FILTER (WHERE status != 'closed') as total_open,
          COUNT(*) FILTER (WHERE severity = 'critical') as critical,
          COUNT(*) as total_all
        FROM findings WHERE org_id = $1`, [req.orgId]),
        query(`SELECT COUNT(*) as total FROM scans WHERE org_id = $1`, [req.orgId]),
        query(`SELECT
          ROUND((COUNT(*) FILTER (WHERE status IN ('resolved','closed'))::numeric / NULLIF(COUNT(*),0)) * 100, 1) as rate
        FROM findings WHERE org_id = $1 AND created_at > NOW() - INTERVAL '90 days'`, [req.orgId]),
      ]);

      res.json({
        totalFindings: (risk.rows[0] as Record<string,unknown>).total_all,
        openFindings: (risk.rows[0] as Record<string,unknown>).total_open,
        criticalFindings: (risk.rows[0] as Record<string,unknown>).critical,
        totalScans: (scans.rows[0] as Record<string,unknown>).total,
        fixRate: parseFloat((fixRate.rows[0] as Record<string,unknown>).rate as string) || 0,
        assessmentDate: new Date().toISOString(),
      });
    } catch (err) { next(err); }
  },
);

dashboardRouter.get('/queue-stats',
  requirePermission(Permission.DASHBOARD_ADMIN),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const { queueManager } = await import('../../core/queue/manager.js');
      const [sast, dast, api, report] = await Promise.all([
        queueManager.getQueueStats('sast-scan' as any),
        queueManager.getQueueStats('dast-scan' as any),
        queueManager.getQueueStats('api-scan' as any),
        queueManager.getQueueStats('report-generation' as any),
      ]);
      res.json({ sast, dast, api, report });
    } catch (err) { next(err); }
  },
);
