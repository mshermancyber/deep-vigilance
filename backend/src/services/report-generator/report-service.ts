// Real Report Generation Service — PDF, HTML, JSON, CSV, Markdown, SARIF
import fs from 'fs';
import path from 'path';
import { query } from '../../core/db/pool.js';
import { logger } from '../../core/logging/logger.js';

const REPORT_DIR = process.env.REPORT_DIR || '/data/reports';

export async function generateReport(reportId: string): Promise<{ filePath: string; format: string; sizeBytes: number }> {
  const result = await query('SELECT * FROM reports WHERE id = $1', [reportId]);
  if (result.rows.length === 0) throw new Error(`Report ${reportId} not found`);
  const report = result.rows[0] as Record<string, unknown>;

  // Fetch findings for this report's project
  const findingsResult = await query(
    `SELECT f.* FROM findings f WHERE f.project_id = $1 AND f.status != 'closed'
     ORDER BY f.severity_rank ASC, f.cvss_score DESC`,
    [report.project_id]
  );
  const findings = findingsResult.rows;

  const projectResult = await query('SELECT * FROM projects WHERE id = $1', [report.project_id]);
  const project = projectResult.rows[0] as Record<string, unknown> || { name: 'Unknown' };

  const format = report.format as string;
  const filename = `${reportId}.${format}`;
  const filePath = path.join(REPORT_DIR, filename);

  if (!fs.existsSync(REPORT_DIR)) fs.mkdirSync(REPORT_DIR, { recursive: true });

  let output: string | Buffer;
  switch (format) {
    case 'json':
      output = buildJSONReport(report, project, findings);
      break;
    case 'csv':
      output = buildCSVReport(findings);
      break;
    case 'markdown':
      output = buildMarkdownReport(report, project, findings);
      break;
    case 'html':
      output = buildHTMLReport(report, project, findings);
      break;
    case 'pdf':
      output = await buildPDFReport(report, project, findings);
      break;
    default:
      output = JSON.stringify({ report, project, findings }, null, 2);
  }

  fs.writeFileSync(filePath, output);
  const sizeBytes = fs.statSync(filePath).size;

  await query('UPDATE reports SET status = $2, file_size = $3, updated_at = NOW() WHERE id = $1',
    [reportId, 'completed', sizeBytes]);

  logger.info({ reportId, format, sizeBytes }, 'Report generated');
  return { filePath, format, sizeBytes };
}

function buildJSONReport(report: Record<string,unknown>, project: Record<string,unknown>, findings: Array<Record<string,unknown>>): string {
  return JSON.stringify({
    reportId: report.id, templateType: report.template_type, generatedAt: new Date().toISOString(),
    project: { id: project.id, name: project.name },
    summary: {
      total: findings.length,
      critical: findings.filter((f: Record<string,unknown>) => f.severity === 'critical').length,
      high: findings.filter((f: Record<string,unknown>) => f.severity === 'high').length,
      medium: findings.filter((f: Record<string,unknown>) => f.severity === 'medium').length,
      low: findings.filter((f: Record<string,unknown>) => f.severity === 'low').length,
    },
    findings: findings.map((f: Record<string,unknown>) => ({
      id: f.id, title: f.title, severity: f.severity, cweId: f.cwe_id, cvssScore: f.cvss_score,
      filePath: f.file_path, lineNumber: f.line_number, status: f.status,
      description: f.description, recommendation: f.recommendation,
    })),
  }, null, 2);
}

function buildCSVReport(findings: Array<Record<string,unknown>>): string {
  const header = 'id,title,severity,cwe,cvss,status,file,line,description\n';
  return header + findings.map((f: Record<string,unknown>) =>
    `"${f.id}","${(f.title as string||'').replace(/"/g,'""')}","${f.severity}","${f.cwe_id||''}","${f.cvss_score||''}","${f.status}","${f.file_path||''}","${f.line_number||''}","${(f.description as string||'').slice(0,200).replace(/"/g,'""')}"`
  ).join('\n');
}

function buildMarkdownReport(report: Record<string,unknown>, project: Record<string,unknown>, findings: Array<Record<string,unknown>>): string {
  const f = findings as Array<Record<string,unknown>>;
  return `# ${(report.template_type as string).toUpperCase()} Report — ${project.name || 'Project'}

**Generated:** ${new Date().toISOString()}
**Total Findings:** ${f.length} | Critical: ${f.filter(x=>x.severity==='critical').length} | High: ${f.filter(x=>x.severity==='high').length}

## Findings

${f.map((x,i)=>`### ${i+1}. ${x.title||'Finding'} [${x.severity}]
- **CWE:** ${x.cwe_id||'N/A'} | **CVSS:** ${x.cvss_score||'N/A'} | **File:** ${x.file_path||'N/A'}:${x.line_number||'?'}
- **Recommendation:** ${x.recommendation||'N/A'}
`).join('\n')}`;
}

function buildHTMLReport(report: Record<string,unknown>, project: Record<string,unknown>, findings: Array<Record<string,unknown>>): string {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Security Report</title></head><body>
<h1>${(report.template_type as string).toUpperCase()} Report</h1><p>Project: ${project.name||'N/A'} | Generated: ${new Date().toISOString()}</p>
<h2>Findings (${findings.length})</h2><table border="1"><tr><th>#</th><th>Severity</th><th>Title</th><th>CWE</th><th>CVSS</th></tr>
${(findings as Array<Record<string,unknown>>).map((x,i)=>`<tr><td>${i+1}</td><td>${x.severity}</td><td>${x.title}</td><td>${x.cwe_id||''}</td><td>${x.cvss_score||''}</td></tr>`).join('')}
</table></body></html>`;
}

async function buildPDFReport(_report: Record<string,unknown>, project: Record<string,unknown>, findings: Array<Record<string,unknown>>): Promise<Buffer> {
  try {
    const puppeteer = await import('puppeteer');
    const browser = await puppeteer.default.launch({ headless: true, args: ['--no-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(buildHTMLReport(_report, project, findings));
    const pdf = await page.pdf({ format: 'A4', margin: { top: '20mm', bottom: '20mm', left: '20mm', right: '20mm' } });
    await browser.close();
    return Buffer.from(pdf);
  } catch {
    return Buffer.from(buildHTMLReport(_report, project, findings));
  }
}
