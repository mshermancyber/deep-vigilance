import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateParams, validateQuery } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';
import {
  type FindingStub,
  type AllFrameworks,
  generateCoreComplianceReport,
  generateAllCoreComplianceReports,
  mapToSOC2,
  mapToHIPAA,
} from '../../services/compliance/compliance-service.js';
import { generateLicenseReport } from '../../services/compliance/license-report-service.js';

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export const complianceRouter = Router();

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const frameworkParamSchema = z.object({
  projectId: z.string().uuid(),
  framework: z.enum(['owasp-asvs', 'cwe-top25', 'pci-dss', 'soc2', 'hipaa']),
});

const projectIdParamSchema = z.object({
  projectId: z.string().uuid(),
});

const exportQuerySchema = z.object({
  format: z.enum(['pdf', 'json', 'csv']).optional().default('json'),
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface FrameworkInfo {
  id: AllFrameworks;
  name: string;
  description: string;
  version: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AVAILABLE_FRAMEWORKS: FrameworkInfo[] = [
  {
    id: 'owasp-asvs',
    name: 'OWASP ASVS v4.0',
    description: 'OWASP Application Security Verification Standard — a framework of security requirements for designing, developing, and testing modern web applications.',
    version: '4.0',
  },
  {
    id: 'cwe-top25',
    name: 'CWE Top 25 (2024)',
    description: 'MITRE CWE Top 25 Most Dangerous Software Weaknesses — the most common and impactful software vulnerabilities.',
    version: '2024',
  },
  {
    id: 'pci-dss',
    name: 'PCI DSS v4.0',
    description: 'Payment Card Industry Data Security Standard — security requirements for organizations that handle cardholder data.',
    version: '4.0',
  },
  {
    id: 'soc2',
    name: 'SOC2 Type II',
    description: 'AICPA SOC2 Type II Trust Service Criteria — controls for security, availability, processing integrity, confidentiality, and privacy.',
    version: 'Type II',
  },
  {
    id: 'hipaa',
    name: 'HIPAA Security Rule',
    description: 'HIPAA Security Rule (45 CFR Part 164 Subpart C) — technical safeguards for electronic protected health information (ePHI).',
    version: '45 CFR 164.312',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Fetch all findings for a project from the database and return them
 * as FindingStub objects suitable for compliance mapping.
 */
async function fetchProjectFindings(
  projectId: string,
  orgId: string,
): Promise<FindingStub[]> {
  const result = await query(
    `SELECT f.id, f.cwe_id, f.title, f.severity, f.rule_id, f.file_path, f.line_number
     FROM findings f
     JOIN scans s ON s.id = f.scan_id
     WHERE s.project_id = $1 AND s.org_id = $2
     ORDER BY f.severity_rank ASC, f.created_at DESC`,
    [projectId, orgId],
  );

  return result.rows.map((row: Record<string, unknown>) => ({
    id: row.id as string,
    cweId: (row.cwe_id as string) ?? '',
    title: (row.title as string) ?? undefined,
    severity: (row.severity as string) ?? undefined,
    ruleId: (row.rule_id as string) ?? undefined,
    filePath: (row.file_path as string) ?? undefined,
    lineNumber: row.line_number != null ? Number(row.line_number) : undefined,
  }));
}

/**
 * Verify that a project exists and belongs to the requesting org.
 */
async function verifyProject(projectId: string, orgId: string): Promise<void> {
  const result = await query(
    'SELECT id FROM projects WHERE id = $1 AND org_id = $2',
    [projectId, orgId],
  );
  if (result.rows.length === 0) {
    throw AppError.notFound(`Project ${projectId} not found`);
  }
}

/**
 * Generate a compliance report for a given framework and findings.
 */
function generateFrameworkReport(
  framework: AllFrameworks,
  findings: FindingStub[],
): Record<string, unknown> {
  switch (framework) {
    case 'owasp-asvs':
    case 'cwe-top25':
    case 'pci-dss':
      return generateCoreComplianceReport(findings, framework) as unknown as Record<string, unknown>;
    case 'soc2':
      return mapToSOC2(findings) as unknown as Record<string, unknown>;
    case 'hipaa':
      return mapToHIPAA(findings) as unknown as Record<string, unknown>;
    default: {
      const _exhaustive: never = framework;
      throw AppError.badRequest(`Unknown compliance framework: ${_exhaustive}`);
    }
  }
}

// ---------------------------------------------------------------------------
// GET /compliance/frameworks
// ---------------------------------------------------------------------------

complianceRouter.get(
  '/frameworks',
  requirePermission(Permission.REPORT_READ),
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      res.json({
        frameworks: AVAILABLE_FRAMEWORKS,
        totalFrameworks: AVAILABLE_FRAMEWORKS.length,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ---------------------------------------------------------------------------
// GET /compliance/report/:projectId/:framework
// ---------------------------------------------------------------------------

complianceRouter.get(
  '/report/:projectId/:framework',
  requirePermission(Permission.REPORT_READ),
  validateParams(frameworkParamSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { projectId, framework } = req.params as { projectId: string; framework: AllFrameworks };
      const orgId = (req as any).orgId as string;

      await verifyProject(projectId, orgId);

      const findings = await fetchProjectFindings(projectId, orgId);
      const report = generateFrameworkReport(framework, findings);

      logger.info({ projectId, framework, findingsCount: findings.length }, 'Compliance report generated');

      res.json({
        projectId,
        framework,
        findingsAnalyzed: findings.length,
        report,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ---------------------------------------------------------------------------
// GET /compliance/summary/:projectId
// ---------------------------------------------------------------------------

complianceRouter.get(
  '/summary/:projectId',
  requirePermission(Permission.REPORT_READ),
  validateParams(projectIdParamSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { projectId } = req.params as { projectId: string };
      const orgId = (req as any).orgId as string;

      await verifyProject(projectId, orgId);

      const findings = await fetchProjectFindings(projectId, orgId);

      // Generate reports for all frameworks
      const coreReports = generateAllCoreComplianceReports(findings);
      const soc2Report = mapToSOC2(findings);
      const hipaaReport = mapToHIPAA(findings);

      // Build per-framework summary
      const frameworkSummaries = [
        {
          framework: 'owasp-asvs' as const,
          name: 'OWASP ASVS v4.0',
          passCount: coreReports['owasp-asvs'].passedCount,
          failCount: coreReports['owasp-asvs'].failedCount,
          partialCount: 0,
          notTestedCount: coreReports['owasp-asvs'].notTestedCount,
          totalRequirements: coreReports['owasp-asvs'].totalRequirements,
          coveragePercent: coreReports['owasp-asvs'].overallCoveragePercent,
        },
        {
          framework: 'cwe-top25' as const,
          name: 'CWE Top 25 (2024)',
          passCount: coreReports['cwe-top25'].passedCount,
          failCount: coreReports['cwe-top25'].failedCount,
          partialCount: 0,
          notTestedCount: coreReports['cwe-top25'].notTestedCount,
          totalRequirements: coreReports['cwe-top25'].totalRequirements,
          coveragePercent: coreReports['cwe-top25'].overallCoveragePercent,
        },
        {
          framework: 'pci-dss' as const,
          name: 'PCI DSS v4.0',
          passCount: coreReports['pci-dss'].passedCount,
          failCount: coreReports['pci-dss'].failedCount,
          partialCount: 0,
          notTestedCount: coreReports['pci-dss'].notTestedCount,
          totalRequirements: coreReports['pci-dss'].totalRequirements,
          coveragePercent: coreReports['pci-dss'].overallCoveragePercent,
        },
        {
          framework: 'soc2' as const,
          name: 'SOC2 Type II',
          passCount: soc2Report.passCount,
          failCount: soc2Report.failCount,
          partialCount: soc2Report.partialCount,
          notTestedCount: 0,
          totalRequirements: soc2Report.totalCriteria,
          coveragePercent: soc2Report.totalCriteria > 0
            ? Math.round(((soc2Report.passCount) / soc2Report.totalCriteria) * 100)
            : 0,
        },
        {
          framework: 'hipaa' as const,
          name: 'HIPAA Security Rule',
          passCount: hipaaReport.passCount,
          failCount: hipaaReport.failCount,
          partialCount: hipaaReport.partialCount,
          notTestedCount: 0,
          totalRequirements: hipaaReport.totalRequirements,
          coveragePercent: hipaaReport.totalRequirements > 0
            ? Math.round(((hipaaReport.passCount) / hipaaReport.totalRequirements) * 100)
            : 0,
        },
      ];

      logger.info({ projectId, findingsCount: findings.length }, 'Compliance summary generated');

      res.json({
        projectId,
        findingsAnalyzed: findings.length,
        generatedAt: new Date().toISOString(),
        frameworks: frameworkSummaries,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ---------------------------------------------------------------------------
// POST /compliance/export/:projectId/:framework
// ---------------------------------------------------------------------------

complianceRouter.post(
  '/export/:projectId/:framework',
  requirePermission(Permission.REPORT_CREATE),
  validateParams(frameworkParamSchema),
  validateQuery(exportQuerySchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { projectId, framework } = req.params as { projectId: string; framework: AllFrameworks };
      const format = (req.query as { format: string }).format;
      const orgId = (req as any).orgId as string;

      await verifyProject(projectId, orgId);

      const findings = await fetchProjectFindings(projectId, orgId);
      const report = generateFrameworkReport(framework, findings);

      logger.info({ projectId, framework, format, findingsCount: findings.length }, 'Compliance export requested');

      switch (format) {
        case 'json': {
          res.setHeader('Content-Type', 'application/json');
          res.setHeader('Content-Disposition', `attachment; filename="compliance-${framework}-${projectId}.json"`);
          res.json({
            exportedAt: new Date().toISOString(),
            projectId,
            framework,
            findingsAnalyzed: findings.length,
            report,
          });
          break;
        }

        case 'csv': {
          const csvContent = buildCsvExport(framework, report);
          res.setHeader('Content-Type', 'text/csv');
          res.setHeader('Content-Disposition', `attachment; filename="compliance-${framework}-${projectId}.csv"`);
          res.send(csvContent);
          break;
        }

        case 'pdf': {
          // Generate HTML template for PDF rendering (PDF rendering is handled by report-service)
          const htmlContent = buildHtmlExport(framework, report, projectId, findings.length);
          res.setHeader('Content-Type', 'text/html');
          res.setHeader('Content-Disposition', `attachment; filename="compliance-${framework}-${projectId}.html"`);
          res.send(htmlContent);
          break;
        }

        default: {
          throw AppError.badRequest(`Unsupported export format: ${format}`);
        }
      }
    } catch (err) {
      next(err);
    }
  },
);

// ---------------------------------------------------------------------------
// GET /compliance/license-report/:projectId
// ---------------------------------------------------------------------------

complianceRouter.get(
  '/license-report/:projectId',
  requirePermission(Permission.REPORT_READ),
  validateParams(projectIdParamSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { projectId } = req.params as { projectId: string };
      const orgId = (req as any).orgId as string;

      await verifyProject(projectId, orgId);

      const licenseReport = await generateLicenseReport(projectId, orgId);

      logger.info({ projectId }, 'License compliance report generated');

      res.json(licenseReport);
    } catch (err) {
      next(err);
    }
  },
);

// ---------------------------------------------------------------------------
// Export Builders
// ---------------------------------------------------------------------------

function buildCsvExport(
  framework: AllFrameworks,
  report: Record<string, unknown>,
): string {
  const rows: string[] = [];

  if (framework === 'soc2') {
    rows.push('Criterion ID,Title,Status,Matching Findings,CWE IDs,Remediation Guidance');
    const criteria = (report as any).criteria ?? [];
    for (const c of criteria) {
      rows.push([
        escapeCsvField(c.criterionId),
        escapeCsvField(c.title),
        escapeCsvField(c.status),
        String(c.matchingFindingsCount),
        escapeCsvField(c.cweIds.join('; ')),
        escapeCsvField(c.remediationGuidance),
      ].join(','));
    }
  } else if (framework === 'hipaa') {
    rows.push('Requirement ID,Title,Status,Matching Findings,CWE IDs,Remediation Guidance');
    const requirements = (report as any).requirements ?? [];
    for (const r of requirements) {
      rows.push([
        escapeCsvField(r.requirementId),
        escapeCsvField(r.title),
        escapeCsvField(r.status),
        String(r.matchingFindingsCount),
        escapeCsvField(r.cweIds.join('; ')),
        escapeCsvField(r.remediationGuidance),
      ].join(','));
    }
  } else {
    // Core frameworks (owasp-asvs, cwe-top25, pci-dss)
    rows.push('Requirement ID,Title,Description,Status,Finding Count');
    const requirements = (report as any).requirements ?? [];
    for (const r of requirements) {
      rows.push([
        escapeCsvField(r.requirementId),
        escapeCsvField(r.title),
        escapeCsvField(r.description),
        escapeCsvField(r.status),
        String(r.findingCount),
      ].join(','));
    }
  }

  return rows.join('\n');
}

function escapeCsvField(value: string): string {
  if (!value) return '""';
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function buildHtmlExport(
  framework: AllFrameworks,
  report: Record<string, unknown>,
  projectId: string,
  findingsCount: number,
): string {
  const frameworkNames: Record<AllFrameworks, string> = {
    'owasp-asvs': 'OWASP ASVS v4.0',
    'cwe-top25': 'CWE Top 25 (2024)',
    'pci-dss': 'PCI DSS v4.0',
    'soc2': 'SOC2 Type II',
    'hipaa': 'HIPAA Security Rule',
  };

  const frameworkName = frameworkNames[framework];
  const generatedAt = new Date().toISOString();

  let tableRows = '';

  if (framework === 'soc2') {
    const criteria = (report as any).criteria ?? [];
    for (const c of criteria) {
      const statusClass = c.status === 'pass' ? 'status-pass' : (c.status === 'fail' ? 'status-fail' : 'status-partial');
      tableRows += `<tr>
        <td>${escapeHtml(c.criterionId)}</td>
        <td>${escapeHtml(c.title)}</td>
        <td class="${statusClass}">${escapeHtml(c.status.toUpperCase())}</td>
        <td>${c.matchingFindingsCount}</td>
        <td>${escapeHtml(c.cweIds.join(', '))}</td>
        <td>${escapeHtml(c.remediationGuidance)}</td>
      </tr>`;
    }
  } else if (framework === 'hipaa') {
    const requirements = (report as any).requirements ?? [];
    for (const r of requirements) {
      const statusClass = r.status === 'pass' ? 'status-pass' : (r.status === 'fail' ? 'status-fail' : 'status-partial');
      tableRows += `<tr>
        <td>${escapeHtml(r.requirementId)}</td>
        <td>${escapeHtml(r.title)}</td>
        <td class="${statusClass}">${escapeHtml(r.status.toUpperCase())}</td>
        <td>${r.matchingFindingsCount}</td>
        <td>${escapeHtml(r.cweIds.join(', '))}</td>
        <td>${escapeHtml(r.remediationGuidance)}</td>
      </tr>`;
    }
  } else {
    const requirements = (report as any).requirements ?? [];
    for (const r of requirements) {
      const statusClass = r.status === 'passed' ? 'status-pass' : (r.status === 'failed' ? 'status-fail' : 'status-partial');
      tableRows += `<tr>
        <td>${escapeHtml(r.requirementId)}</td>
        <td>${escapeHtml(r.title)}</td>
        <td class="${statusClass}">${escapeHtml(r.status.toUpperCase())}</td>
        <td>${r.findingCount}</td>
        <td>${escapeHtml(r.description)}</td>
      </tr>`;
    }
  }

  const executiveSummary = (report as any).executiveSummary ?? '';
  const headerCols = (framework === 'soc2' || framework === 'hipaa')
    ? '<th>ID</th><th>Title</th><th>Status</th><th>Findings</th><th>CWE IDs</th><th>Remediation</th>'
    : '<th>ID</th><th>Title</th><th>Status</th><th>Findings</th><th>Description</th>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${frameworkName} Compliance Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2rem; color: #1a1a1a; }
    h1 { color: #1e3a5f; border-bottom: 2px solid #1e3a5f; padding-bottom: 0.5rem; }
    .meta { color: #666; margin-bottom: 1.5rem; }
    .summary { background: #f4f6f9; border-left: 4px solid #1e3a5f; padding: 1rem; margin-bottom: 2rem; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th { background: #1e3a5f; color: #fff; padding: 0.75rem; text-align: left; }
    td { padding: 0.75rem; border-bottom: 1px solid #ddd; }
    tr:nth-child(even) { background: #f9f9f9; }
    .status-pass { color: #2e7d32; font-weight: bold; }
    .status-fail { color: #c62828; font-weight: bold; }
    .status-partial { color: #e65100; font-weight: bold; }
    @media print { body { margin: 1cm; } }
  </style>
</head>
<body>
  <h1>${frameworkName} Compliance Report</h1>
  <div class="meta">
    <p><strong>Project ID:</strong> ${escapeHtml(projectId)}</p>
    <p><strong>Generated:</strong> ${escapeHtml(generatedAt)}</p>
    <p><strong>Findings Analyzed:</strong> ${findingsCount}</p>
  </div>
  <div class="summary">
    <h2>Executive Summary</h2>
    <p>${escapeHtml(executiveSummary)}</p>
  </div>
  <h2>Detailed Results</h2>
  <table>
    <thead><tr>${headerCols}</tr></thead>
    <tbody>${tableRows}</tbody>
  </table>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
