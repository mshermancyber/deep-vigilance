import { Worker, Job } from 'bullmq';
import fs from 'fs';
import path from 'path';
import { logger } from './utils/logger.js';
import { query, closePool } from './utils/db.js';

const connection = {
  host: process.env.REDIS_HOST || 'redis',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD,
};

const REPORT_DIR = process.env.REPORT_DIR || '/data/reports';

interface ReportData {
  reportId: string;
  projectId: string;
  organizationId: string;
  templateType: string;
  format: 'pdf' | 'html' | 'json' | 'csv' | 'markdown';
  filters: Record<string, unknown>;
  userId: string;
}

/**
 * Loads the project's findings (org-scoped, with optional severity/status/type
 * filters) and a computed risk score from the database.
 */
async function loadReportData(
  data: ReportData,
): Promise<{ findings: Array<Record<string, unknown>>; projectInfo: Record<string, unknown> }> {
  // Code review findings come from a separate table
  if (data.templateType === 'code-review') {
    return loadCodeReviewData(data);
  }

  // Binary analysis reports are fetched from FraudVault
  if (data.templateType === 'binary') {
    return loadBinaryAnalysisData(data);
  }

  const conditions = ['f.project_id = $1', 'f.org_id = $2'];
  const params: unknown[] = [data.projectId, data.organizationId];
  let idx = 3;

  const filters = data.filters || {};
  const toArray = (v: unknown): string[] | null =>
    Array.isArray(v) ? v.map(String) : typeof v === 'string' && v.length > 0 ? [v] : null;

  const severity = toArray(filters.severity);
  if (severity) { conditions.push(`f.severity = ANY($${idx++})`); params.push(severity); }
  const status = toArray(filters.status);
  if (status) { conditions.push(`f.status = ANY($${idx++})`); params.push(status); }
  else { conditions.push(`f.status NOT IN ('closed', 'false_positive', 'wont_fix')`); }
  const type = toArray(filters.type);
  if (type) { conditions.push(`f.type = ANY($${idx++})`); params.push(type); }

  // Auto-filter by scan type when a scan-specific template is used
  const typeMap: Record<string, string> = { sast: 'sast', dast: 'dast', sca: 'sca', api: 'api' };
  if (!type && typeMap[data.templateType]) {
    conditions.push(`f.type = $${idx++}`);
    params.push(typeMap[data.templateType]);
  }

  const where = conditions.join(' AND ');

  const findingsResult = await query(
    `SELECT f.id, f.title, f.severity, f.status, f.type,
            f.cwe_id AS "cweId", f.cve_id AS "cveId", f.cvss_score AS "cvssScore",
            f.cvss_vector AS "cvssVector", f.epss_score AS "epssScore", f.kev_match AS "kevMatch",
            f.file_path AS "filePath", f.line_number AS "lineNumber",
            f.code_snippet AS "codeSnippet", f.description, f.recommendation,
            f.metadata
     FROM findings f
     WHERE ${where}
     ORDER BY f.severity_rank ASC, f.cvss_score DESC NULLS LAST
     LIMIT 500`,
    params,
  );

  const projectResult = await query<Record<string, unknown>>(
    `SELECT p.name,
            COALESCE(SUM(CASE f.severity
              WHEN 'critical' THEN 10 WHEN 'high' THEN 5
              WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
              FILTER (WHERE f.status NOT IN ('closed','false_positive','wont_fix')), 0) AS risk_score
     FROM projects p
     LEFT JOIN findings f ON f.project_id = p.id
     WHERE p.id = $1 AND p.org_id = $2
     GROUP BY p.name`,
    [data.projectId, data.organizationId],
  );

  const project = projectResult.rows[0] || {};
  return {
    findings: findingsResult.rows as Array<Record<string, unknown>>,
    projectInfo: {
      name: project.name || 'Project',
      riskScore: project.risk_score ?? 0,
      findingCount: findingsResult.rows.length,
    },
  };
}

async function loadCodeReviewData(
  data: ReportData,
): Promise<{ findings: Array<Record<string, unknown>>; projectInfo: Record<string, unknown> }> {
  const findingsResult = await query(
    `SELECT f.id, f.title, f.severity, f.finding_type AS type, f.category,
            f.rule_id AS "ruleId", f.rule_name AS "ruleName",
            f.confidence_score AS "confidenceScore",
            f.file_path AS "filePath", f.line_number AS "lineNumber",
            f.function_name AS "functionName", f.class_name AS "className",
            f.code_snippet AS "codeSnippet", f.description, f.recommendation
     FROM code_review_findings f
     WHERE f.project_id = $1 AND f.org_id = $2
     ORDER BY f.severity_rank ASC, f.confidence_score DESC NULLS LAST`,
    [data.projectId, data.organizationId],
  );

  const projectResult = await query<Record<string, unknown>>(
    'SELECT name FROM projects WHERE id = $1 AND org_id = $2', [data.projectId, data.organizationId],
  );

  return {
    findings: findingsResult.rows as Array<Record<string, unknown>>,
    projectInfo: {
      name: (projectResult.rows[0] as Record<string, unknown>)?.name || 'Project',
      riskScore: 0,
      findingCount: findingsResult.rows.length,
      reportType: 'code-review',
    },
  };
}

async function loadBinaryAnalysisData(
  data: ReportData,
): Promise<{ findings: Array<Record<string, unknown>>; projectInfo: Record<string, unknown> }> {
  const filters = data.filters || {};
  const submissionId = (filters as Record<string, unknown>).submissionId as string;

  if (submissionId) {
    try {
      const fraudvaultUrl = process.env.FRAUDVAULT_URL || '';
      if (!fraudvaultUrl || !process.env.FRAUDVAULT_EMAIL || !process.env.FRAUDVAULT_PASSWORD) {
        logger.warn('Binary analysis report requested but the FraudVault integration is not configured (FRAUDVAULT_URL / FRAUDVAULT_EMAIL / FRAUDVAULT_PASSWORD)');
        return { findings: [], projectInfo: {} };
      }
      const https = await import('https');
      const agent = new https.Agent({ rejectUnauthorized: false });

      const loginRes = await fetch(`${fraudvaultUrl}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: process.env.FRAUDVAULT_EMAIL,
          password: process.env.FRAUDVAULT_PASSWORD,
        }),
        // @ts-ignore - node fetch agent
        agent,
      });
      const loginData = await loginRes.json() as Record<string, unknown>;
      const token = (loginData as Record<string, unknown>).token as string;

      if (token) {
        const reportRes = await fetch(`${fraudvaultUrl}/api/v1/submissions/${submissionId}`, {
          headers: { Authorization: `Bearer ${token}` },
          // @ts-ignore
          agent,
        });
        const submission = await reportRes.json() as Record<string, unknown>;

        const findings: Array<Record<string, unknown>> = [];
        const sub = (submission as Record<string, unknown>).submission as Record<string, unknown> || submission;

        if (sub.threat_score !== undefined) {
          findings.push({
            id: submissionId, title: `Binary Analysis: ${sub.filename || 'Unknown'}`,
            severity: (sub.threat_level as string) || 'info',
            description: `Threat Score: ${sub.threat_score}/100. File: ${sub.filename}, Type: ${sub.file_type}, SHA256: ${sub.sha256}`,
            status: 'open', type: 'binary',
          });
        }

        return {
          findings,
          projectInfo: {
            name: `Binary Analysis: ${sub.filename || 'Unknown'}`,
            riskScore: sub.threat_score ?? 0,
            findingCount: findings.length,
            reportType: 'binary',
            submissionData: sub,
          },
        };
      }
    } catch (err) {
      logger.error({ err, submissionId }, 'Failed to fetch FraudVault submission');
    }
  }

  return {
    findings: [],
    projectInfo: { name: 'Binary Analysis', riskScore: 0, findingCount: 0, reportType: 'binary' },
  };
}

async function generatePDFReport(data: ReportData, findings: unknown[], projectInfo: Record<string, unknown>): Promise<Buffer> {
  const puppeteer = await import('puppeteer');
  const browser = await puppeteer.default.launch({
    headless: 'new' as any,
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    protocolTimeout: 60000,
  });

  try {
    const page = await browser.newPage();
    const html = buildHTMLReport(data.templateType, findings, projectInfo, data.reportId);
    await page.setContent(html, { waitUntil: 'domcontentloaded', timeout: 15000 });
    const pdfBuffer = await page.pdf({
      format: 'A4',
      margin: { top: '20mm', bottom: '20mm', left: '20mm', right: '20mm' },
      printBackground: true,
    });
    return Buffer.from(pdfBuffer);
  } finally {
    await browser.close();
  }
}

function escapeHtml(str: unknown): string {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function buildHTMLReport(
  templateType: string,
  findings: unknown[],
  projectInfo: Record<string, unknown>,
  reportId: string,
): string {
  const isSCA = templateType === 'sca';
  const isSAST = templateType === 'sast';
  const isCodeReview = templateType === 'code-review';

  const findingsList = (findings as Array<Record<string, unknown>>)
    .map((f, i) => {
      const extra = isSCA
        ? `<td>${escapeHtml(f.cveId || f.cweId || 'N/A')}</td><td>${escapeHtml(f.epssScore || 'N/A')}</td><td>${f.kevMatch ? 'YES' : 'No'}</td>`
        : isSAST
        ? `<td>${escapeHtml(f.cweId || 'N/A')}</td><td>${escapeHtml(f.filePath ? `${f.filePath}:${f.lineNumber || ''}` : 'N/A')}</td>`
        : isCodeReview
        ? `<td>${escapeHtml(f.category || f.type || 'N/A')}</td><td>${escapeHtml(f.confidenceScore || 'N/A')}</td><td>${escapeHtml(f.filePath ? `${f.filePath}:${f.lineNumber || ''}` : 'N/A')}</td>`
        : `<td>${escapeHtml(f.cweId || 'N/A')}</td><td>${escapeHtml(f.cvssScore || 'N/A')}</td><td>${escapeHtml(f.status || 'open')}</td>`;
      return `<tr><td>${i + 1}</td><td><span class="severity severity-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td><td>${escapeHtml(f.title || 'N/A')}</td>${extra}</tr>`;
    }).join('');

  const severityCounts = ['critical', 'high', 'medium', 'low', 'info']
    .map(s => `${s}: ${(findings as Array<Record<string, unknown>>).filter((f: Record<string, unknown>) => f.severity === s).length}`)
    .join(' | ');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(templateType.toUpperCase())} Security Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 12px; color: #1a1a2e; line-height: 1.6; padding: 40px; }
    .header { text-align: center; border-bottom: 3px solid #2563eb; padding-bottom: 20px; margin-bottom: 30px; }
    .header h1 { font-size: 28px; color: #1e3a5f; margin-bottom: 5px; }
    .header .meta { font-size: 11px; color: #64748b; }
    .section { margin-bottom: 25px; }
    .section h2 { font-size: 18px; color: #2563eb; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-bottom: 15px; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
    .summary-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; text-align: center; }
    .summary-card .value { font-size: 24px; font-weight: bold; color: #1e3a5f; }
    .summary-card .label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; }
    th { background: #f1f5f9; padding: 10px; text-align: left; font-weight: 600; color: #334155; border-bottom: 2px solid #e2e8f0; }
    td { padding: 8px 10px; border-bottom: 1px solid #f1f5f9; }
    tr:hover td { background: #f8fafc; }
    .severity { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; }
    .severity-critical { background: #fef2f2; color: #dc2626; }
    .severity-high { background: #fff7ed; color: #ea580c; }
    .severity-medium { background: #fefce8; color: #ca8a04; }
    .severity-low { background: #f0fdf4; color: #16a34a; }
    .severity-info { background: #eff6ff; color: #2563eb; }
    .footer { margin-top: 30px; padding-top: 15px; border-top: 1px solid #e2e8f0; font-size: 10px; color: #94a3b8; text-align: center; }
    .disclaimer { background: #fefce8; border: 1px solid #fde047; border-radius: 6px; padding: 10px; margin-top: 20px; font-size: 10px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>${escapeHtml(templateType.toUpperCase())} Security Report</h1>
    <div class="meta">
      Project: ${escapeHtml(projectInfo.name || 'N/A')} |
      Generated: ${new Date().toISOString()} |
      Classification: CONFIDENTIAL
    </div>
  </div>

  <div class="section">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="summary-card"><div class="value">${findings.length}</div><div class="label">Total Findings</div></div>
      <div class="summary-card"><div class="value">${(findings as Array<Record<string, unknown>>).filter((f: Record<string, unknown>) => f.severity === 'critical').length}</div><div class="label">Critical</div></div>
      <div class="summary-card"><div class="value">${(findings as Array<Record<string, unknown>>).filter((f: Record<string, unknown>) => f.severity === 'high').length}</div><div class="label">High</div></div>
      <div class="summary-card"><div class="value">${escapeHtml(projectInfo.riskScore || 'N/A')}</div><div class="label">Risk Score</div></div>
    </div>
    <p>Severity breakdown: ${severityCounts}</p>
  </div>

  <div class="section">
    <h2>Findings Detail</h2>
    <table>
      <thead><tr><th>#</th><th>Severity</th><th>Title</th>${
        isSCA ? '<th>CVE</th><th>EPSS</th><th>KEV</th>'
        : isSAST ? '<th>CWE</th><th>Location</th>'
        : isCodeReview ? '<th>Category</th><th>Confidence</th><th>Location</th>'
        : '<th>CWE</th><th>CVSS</th><th>Status</th>'
      }</tr></thead>
      <tbody>${findingsList || '<tr><td colspan="6">No findings to display</td></tr>'}</tbody>
    </table>
  </div>

  <div class="disclaimer">
    <strong>Disclaimer:</strong> This report is generated automatically by the Application Security Platform.
    Findings should be verified by a qualified security professional before remediation.
    This report contains confidential security information and should be handled accordingly.
  </div>

  <div class="footer">
    Deep Vigilance v0.1.0 | Report ID: ${escapeHtml(reportId)} | ${new Date().toISOString()}
  </div>
</body>
</html>`;
}

function generateMarkdownReport(
  findings: unknown[],
  projectInfo: Record<string, unknown>,
): string {
  const f = findings as Array<Record<string, unknown>>;
  const critical = f.filter(x => x.severity === 'critical').length;
  const high = f.filter(x => x.severity === 'high').length;
  const medium = f.filter(x => x.severity === 'medium').length;
  const low = f.filter(x => x.severity === 'low').length;

  return `# Security Report — ${projectInfo.name || 'Project'}

**Generated:** ${new Date().toISOString()}
**Classification:** CONFIDENTIAL

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | ${f.length} |
| Critical | ${critical} |
| High | ${high} |
| Medium | ${medium} |
| Low | ${low} |

## Findings

${f.map((x, i) => `
### ${i + 1}. ${x.title || 'Finding'}

- **Severity:** ${x.severity}
- **CWE:** ${x.cweId || 'N/A'}
- **CVSS:** ${x.cvssScore || 'N/A'}
- **Status:** ${x.status || 'open'}
- **Description:** ${x.description || 'N/A'}
- **Recommendation:** ${x.recommendation || 'N/A'}
`).join('\n')}

---
*Generated by Deep Vigilance v0.1.0*
`;
}

async function processJob(job: Job): Promise<Record<string, unknown>> {
  logger.info({ jobId: job.id }, 'Report Worker: Processing job');

  const data = job.data as ReportData;

  try {
    await job.updateProgress(10);

    const { findings, projectInfo } = await loadReportData(data);

    await job.updateProgress(50);

    let output: Buffer | string;
    const safeId = path.basename(data.reportId).replace(/[^a-zA-Z0-9_-]/g, '');
    if (!safeId) throw new Error('Invalid reportId');
    const filename = `${safeId}.${data.format}`;
    const filepath = path.join(REPORT_DIR, filename);
    const resolvedPath = path.resolve(filepath);
    const resolvedDir = path.resolve(REPORT_DIR);
    if (!resolvedPath.startsWith(resolvedDir + path.sep) && resolvedPath !== resolvedDir) {
      throw new Error('Path traversal detected in report path');
    }

    switch (data.format) {
      case 'pdf':
        output = await generatePDFReport(data, findings, projectInfo);
        break;
      case 'html':
        output = buildHTMLReport(data.templateType, findings, projectInfo, data.reportId);
        break;
      case 'markdown':
        output = generateMarkdownReport(findings, projectInfo);
        break;
      case 'json':
        output = JSON.stringify({
          reportId: data.reportId,
          templateType: data.templateType,
          generatedAt: new Date().toISOString(),
          project: projectInfo,
          findings,
          summary: {
            total: findings.length,
            critical: (findings as Array<Record<string, unknown>>).filter((f: Record<string, unknown>) => f.severity === 'critical').length,
            high: (findings as Array<Record<string, unknown>>).filter((f: Record<string, unknown>) => f.severity === 'high').length,
          },
        }, null, 2);
        break;
      case 'csv':
        output = 'id,title,severity,cwe,cvss,status,file,description\n' +
          (findings as Array<Record<string, unknown>>).map((f: Record<string, unknown>) =>
            `"${f.id || ''}","${f.title || ''}","${f.severity || ''}","${f.cweId || ''}","${f.cvssScore || ''}","${f.status || ''}","${f.filePath || ''}","${(f.description || '').toString().replace(/"/g, '""')}"`,
          ).join('\n');
        break;
      default:
        output = JSON.stringify({ findings, projectInfo }, null, 2);
    }

    await job.updateProgress(80);

    if (!fs.existsSync(REPORT_DIR)) {
      fs.mkdirSync(REPORT_DIR, { recursive: true });
    }

    fs.writeFileSync(filepath, output, { flag: 'wx' });
    const realPath = fs.realpathSync(filepath);
    if (!realPath.startsWith(resolvedDir + path.sep)) {
      fs.unlinkSync(filepath);
      throw new Error('Symlink traversal detected in report path');
    }
    const fileSize = fs.statSync(filepath).size;

    await job.updateProgress(100);

    // Persist completion so the API can serve the download (status gate + file_size).
    await query(
      `UPDATE reports SET status = 'completed', file_size = $2, updated_at = NOW() WHERE id = $1`,
      [data.reportId, fileSize],
    );

    logger.info({ reportId: data.reportId, format: data.format, fileSize }, 'Report generated');

    return {
      reportId: data.reportId,
      status: 'completed',
      fileSize,
      format: data.format,
      filename,
    };
  } catch (err) {
    logger.error({ reportId: data.reportId, err }, 'Report generation failed');
    try { await query(`UPDATE reports SET status = 'failed', updated_at = NOW() WHERE id = $1`, [data.reportId]); } catch { /* best effort */ }
    throw err;
  }
}

const worker = new Worker('report-generation', processJob, {
  connection,
  concurrency: 1,
  limiter: { max: 5, duration: 60000 },
});

worker.on('completed', (job) => logger.info({ jobId: job?.id }, 'Report job completed'));
worker.on('failed', (job, err) => logger.error({ jobId: job?.id, err: err.message }, 'Report job failed'));

logger.info('Report Worker started and waiting for jobs...');

process.on('SIGTERM', async () => { await worker.close(); await closePool(); process.exit(0); });
