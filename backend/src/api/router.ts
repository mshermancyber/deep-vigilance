import { Router } from 'express';
import { authRouter } from './auth/routes.js';
import { usersRouter } from './users/routes.js';
import { projectsRouter } from './projects/routes.js';
import { scansRouter } from './scans/routes.js';
import { findingsRouter } from './findings/routes.js';
import { reportsRouter } from './reports/routes.js';
import { schedulerRouter } from './scheduler/routes.js';
import { apiClientRouter } from './apiclient/routes.js';
import { integrationsRouter } from './integrations/routes.js';
import { searchRouter } from './search/routes.js';
import { adminRouter } from './admin/routes.js';
import { dashboardRouter } from './dashboard/routes.js';
import { webhooksRouter } from './webhooks/routes.js';
import { settingsRouter } from './settings/routes.js';
import { codeReviewRouter } from './code-review/routes.js';
import { containerScanRouter } from './container-scan/routes.js';
import { sbomRouter } from './sbom/routes.js';
import { advancedScanRouter } from './advanced-scan/routes.js';
import { complianceRouter } from './compliance/routes.js';
import { aiRouter } from './ai/routes.js';
import { scanInlineRouter } from './scan-inline/routes.js';
import { APP_VERSION } from '../version.js';

export function buildRouter(): Router {
  const router = Router();

  router.use('/auth', authRouter);
  router.use('/users', usersRouter);
  router.use('/projects', projectsRouter);
  router.use('/scans', scansRouter);
  router.use('/findings', findingsRouter);
  router.use('/reports', reportsRouter);
  router.use('/scheduler', schedulerRouter);
  router.use('/api-client', apiClientRouter);
  router.use('/integrations', integrationsRouter);
  router.use('/search', searchRouter);
  router.use('/admin', adminRouter);
  router.use('/dashboard', dashboardRouter);
  router.use('/webhooks', webhooksRouter);
  router.use('/settings', settingsRouter);
  router.use('/code-review', codeReviewRouter);
  router.use('/container-scan', containerScanRouter);
  router.use('/sbom', sbomRouter);
  router.use('/advanced-scan', advancedScanRouter);
  router.use('/compliance', complianceRouter);
  router.use('/ai', aiRouter);
  router.use('/scan', scanInlineRouter);

  router.get('/version', (_req, res) => {
    res.json({
      version: APP_VERSION,
      name: 'Application Security Platform',
      buildDate: '2024-01-01',
    });
  });

  return router;
}
