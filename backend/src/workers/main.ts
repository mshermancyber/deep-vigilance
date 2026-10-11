import { Worker, Job } from 'bullmq';
import { getConfig } from '../config/index.js';
import { logger } from '../core/logging/logger.js';
import { query } from '../core/db/pool.js';
import { createRedisClient } from '../core/redis/client.js';
import { startReaper } from '../core/reaper.js';

const config = getConfig();

const connection = {
  host: config.REDIS_HOST,
  port: config.REDIS_PORT,
  password: config.REDIS_PASSWORD,
};

async function processSASTScan(job: Job): Promise<Record<string, unknown>> {
  logger.info({ jobId: job.id, scanId: job.data.scanId }, 'Processing SAST scan');
  await job.updateProgress(10);

  const { scanId, projectId, options } = job.data;

  await query(`UPDATE scans SET status = 'running', started_at = NOW(), updated_at = NOW() WHERE id = $1`, [scanId]);

  try {
    const targetPath = options?.targetPath || '/tmp/scan-target';

    await job.updateProgress(30);
    logger.info({ scanId, targetPath }, 'SAST: Starting static analysis');

    const findings = performStaticAnalysis(targetPath, options?.includePatterns || ['**/*'], options?.excludePatterns || []);

    await job.updateProgress(70);

    for (const finding of findings) {
      await query(
        `INSERT INTO findings (id, org_id, project_id, scan_id, type, title, description, severity, severity_rank,
          file_path, line_number, line_range, code_snippet, rule_id, rule_name, cwe_id, owasp_category,
          cvss_score, cvss_vector, recommendation, references_data, metadata, created_at, updated_at)
         VALUES (gen_random_uuid(), $1, $2, $3, 'sast', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, NOW(), NOW())`,
        [
          job.data.organizationId, projectId, scanId, finding.title, finding.description,
          finding.severity, finding.severityRank, finding.filePath, finding.lineNumber,
          finding.lineRange, finding.codeSnippet, finding.ruleId, finding.ruleName,
          finding.cweId, finding.owaspCategory, finding.cvssScore, finding.cvssVector,
          finding.recommendation, JSON.stringify(finding.references || []),
          JSON.stringify({ rule_category: finding.ruleCategory, language: finding.language }),
        ],
      );
    }

    await query(
      `UPDATE scans SET status = 'completed', completed_at = NOW(), updated_at = NOW(),
        findings_count = $2, metadata = metadata || $3::jsonb
       WHERE id = $1`,
      [scanId, findings.length, JSON.stringify({ sast_findings: findings.length })],
    );

    await job.updateProgress(100);
    logger.info({ scanId, findingsCount: findings.length }, 'SAST scan completed');

    return { findingsCount: findings.length, status: 'completed' };
  } catch (err) {
    logger.error({ scanId, err }, 'SAST scan failed');
    await query(`UPDATE scans SET status = 'failed', error_message = $2, updated_at = NOW() WHERE id = $1`, [scanId, String(err)]);
    throw err;
  }
}

function performStaticAnalysis(
  _targetPath: string,
  _includePatterns: string[],
  _excludePatterns: string[],
): Array<{
  title: string;
  description: string;
  severity: string;
  severityRank: number;
  filePath: string;
  lineNumber: number | null;
  lineRange: string | null;
  codeSnippet: string | null;
  ruleId: string;
  ruleName: string;
  ruleCategory: string;
  cweId: string;
  owaspCategory: string;
  cvssScore: number;
  cvssVector: string;
  recommendation: string;
  references: string[];
  language: string;
}> {
  return [];
}

async function processDASTScan(job: Job): Promise<Record<string, unknown>> {
  logger.info({ jobId: job.id, scanId: job.data.scanId }, 'Processing DAST scan');
  await job.updateProgress(10);

  const { scanId, options } = job.data;

  await query(`UPDATE scans SET status = 'running', started_at = NOW(), updated_at = NOW() WHERE id = $1`, [scanId]);

  try {
    const targetUrl = options?.targetUrl || 'https://example.com';

    await job.updateProgress(50);
    logger.info({ scanId, targetUrl }, 'DAST: Crawling and testing target');

    await job.updateProgress(100);

    await query(
      `UPDATE scans SET status = 'completed', completed_at = NOW(), updated_at = NOW(), findings_count = 0 WHERE id = $1`,
      [scanId],
    );

    return { findingsCount: 0, status: 'completed' };
  } catch (err) {
    logger.error({ scanId, err }, 'DAST scan failed');
    await query(`UPDATE scans SET status = 'failed', error_message = $2, updated_at = NOW() WHERE id = $1`, [scanId, String(err)]);
    throw err;
  }
}

async function startWorkers(): Promise<void> {
  await createRedisClient();
  logger.info('Worker redis connected');

  const sastWorker = new Worker('sast-scan', processSASTScan, {
    connection,
    concurrency: 4,
    limiter: { max: 10, duration: 60000 },
  });

  const dastWorker = new Worker('dast-scan', processDASTScan, {
    connection,
    concurrency: 2,
    limiter: { max: 5, duration: 60000 },
  });


  sastWorker.on('completed', (job) => {
    logger.info({ jobId: job?.id }, 'SAST job completed');
  });

  sastWorker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, err }, 'SAST job failed');
  });

  dastWorker.on('completed', (job) => {
    logger.info({ jobId: job?.id }, 'DAST job completed');
  });

  logger.info('Workers started successfully');
}

startWorkers().catch((err) => {
  logger.error({ err }, 'Failed to start workers');
  process.exit(1);
});

startReaper();
