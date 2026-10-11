import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { logger } from '../utils/logger.js';
import { DastFinding } from './engine.js';

export interface NucleiResult {
  info: {
    name: string;
    severity: string;
    description?: string;
    reference?: string[];
    classification?: { 'cwe-id'?: string[]; 'cvss-score'?: number; 'cvss-metrics'?: string };
    remediation?: string;
  };
  'matched-at': string;
  'template-id': string;
  type: string;
  host: string;
  'curl-command'?: string;
  'extracted-results'?: string[];
}

const SEVERITY_RANK: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

export async function runNuclei(
  targetUrl: string,
  opts: { templates?: string[]; severity?: string; timeout?: number; rateLimit?: number } = {},
): Promise<DastFinding[]> {
  const findings: DastFinding[] = [];
  const outFile = path.join(os.tmpdir(), `nuclei-${Date.now()}.jsonl`);

  try {
    execSync('which nuclei', { stdio: 'ignore' });
  } catch {
    logger.warn('Nuclei not installed, skipping Nuclei scan');
    return findings;
  }

  const args = [
    'nuclei',
    '-u', targetUrl,
    '-jsonl', '-o', outFile,
    '-silent',
    '-timeout', String(opts.timeout || 10),
    '-rate-limit', String(opts.rateLimit || 50),
    '-no-color',
    '-disable-update-check',
  ];

  if (opts.severity) {
    args.push('-severity', opts.severity);
  } else {
    args.push('-severity', 'critical,high,medium');
  }

  if (opts.templates?.length) {
    for (const t of opts.templates) {
      args.push('-t', t);
    }
  }

  try {
    logger.info({ targetUrl }, 'Running Nuclei scan');
    execSync(args.join(' '), {
      timeout: (opts.timeout || 10) * 60 * 1000,
      stdio: 'ignore',
      env: { ...process.env, HOME: '/home/appsec' },
    });
  } catch (err) {
    logger.warn({ err }, 'Nuclei process exited (may have partial results)');
  }

  if (!fs.existsSync(outFile)) return findings;

  try {
    const lines = fs.readFileSync(outFile, 'utf-8').split('\n').filter(Boolean);
    for (const line of lines) {
      try {
        const result = JSON.parse(line) as NucleiResult;
        const severity = result.info.severity?.toLowerCase() || 'info';
        const cweIds = result.info.classification?.['cwe-id'] || [];

        findings.push({
          attackId: `NUCLEI-${result['template-id']}`,
          attackName: result.info.name,
          target: result['matched-at'] || result.host,
          method: 'GET',
          parameter: result.type || 'http',
          payload: result['curl-command'] || '',
          evidence: result['extracted-results']?.join('; ') || result['matched-at'] || '',
          severity,
          severityRank: SEVERITY_RANK[severity] || 5,
          cweId: cweIds[0] || '',
          owaspCategory: '',
          cvssScore: result.info.classification?.['cvss-score'] || 0,
          cvssVector: result.info.classification?.['cvss-metrics'] || '',
          recommendation: result.info.remediation || `Review and remediate: ${result.info.name}`,
          description: result.info.description || result.info.name,
        });
      } catch { continue; }
    }
    logger.info({ targetUrl, findings: findings.length }, 'Nuclei scan complete');
  } finally {
    try { fs.unlinkSync(outFile); } catch { /* best effort */ }
  }

  return findings;
}
