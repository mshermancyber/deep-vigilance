import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { logger } from '../utils/logger.js';
import { DastFinding } from './engine.js';

const SEVERITY_MAP: Record<string, { severity: string; rank: number; cvss: number }> = {
  'outdated': { severity: 'medium', rank: 3, cvss: 5.3 },
  'dangerous': { severity: 'high', rank: 2, cvss: 7.5 },
  'injection': { severity: 'critical', rank: 1, cvss: 9.8 },
  'xss': { severity: 'high', rank: 2, cvss: 7.5 },
  'default': { severity: 'low', rank: 4, cvss: 3.5 },
};

function classifySeverity(msg: string): { severity: string; rank: number; cvss: number } {
  const lower = msg.toLowerCase();
  if (/sql|inject|rce|command|exec/i.test(lower)) return SEVERITY_MAP['injection']!;
  if (/xss|cross-site|cross_site|<script/i.test(lower)) return SEVERITY_MAP['xss']!;
  if (/outdated|old version|end.of.life|obsolete|vulnerable version/i.test(lower)) return SEVERITY_MAP['outdated']!;
  if (/dangerous|default (password|credential|file)|backup|\.bak|\.old|phpinfo|server-status/i.test(lower)) return SEVERITY_MAP['dangerous']!;
  return SEVERITY_MAP['default']!;
}

// Nikto 2.1.6 CSV has a Perl SCALAR() bug that corrupts field boundaries.
// Use regex to reliably extract OSVDB ID, method, URI, and message.
const NIKTO_LINE_RE = /"(OSVDB-\d+)","(\w+)","([^"]*?)","(.+)"\s*$/;

export async function runNikto(
  targetUrl: string,
  opts: { timeout?: number; tuning?: string; maxTime?: number } = {},
): Promise<DastFinding[]> {
  const findings: DastFinding[] = [];
  const outFile = path.join(os.tmpdir(), `nikto-${Date.now()}.csv`);

  let niktoBin = 'nikto';
  try {
    execSync('which nikto', { stdio: 'ignore' });
  } catch {
    try {
      execSync('which nikto.pl', { stdio: 'ignore' });
      niktoBin = 'nikto.pl';
    } catch {
      logger.warn('Nikto not installed, skipping Nikto scan');
      return findings;
    }
  }

  const parsed = new URL(targetUrl);
  const args = [
    niktoBin,
    '-h', parsed.hostname,
    '-p', parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
    '-Format', 'csv',
    '-output', outFile,
    '-nointeractive',
    '-maxtime', String(opts.maxTime || 300) + 's',
  ];

  if (parsed.protocol === 'https:') {
    args.push('-ssl');
  }

  if (opts.tuning) {
    args.push('-Tuning', opts.tuning);
  }

  try {
    logger.info({ targetUrl }, 'Running Nikto scan');
    execSync(args.join(' '), {
      timeout: (opts.timeout || 10) * 60 * 1000,
      stdio: 'ignore',
      env: { ...process.env },
    });
  } catch (err) {
    logger.warn({ err }, 'Nikto process exited (may have partial results)');
  }

  if (!fs.existsSync(outFile)) return findings;

  try {
    const raw = fs.readFileSync(outFile, 'utf-8');
    const lines = raw.split('\n').filter(Boolean);

    for (const line of lines) {
      const match = NIKTO_LINE_RE.exec(line);
      if (!match) continue;

      const [, osvdb, method, uri, msg] = match;
      if (!msg || !msg.trim()) continue;

      const sev = classifySeverity(msg);
      findings.push({
        attackId: `NIKTO-${osvdb}`,
        attackName: `Nikto: ${msg.slice(0, 80)}`,
        target: `${targetUrl}${uri || '/'}`,
        method: method || 'GET',
        parameter: 'server',
        payload: '',
        evidence: msg,
        severity: sev.severity,
        severityRank: sev.rank,
        cweId: '',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        cvssScore: sev.cvss,
        cvssVector: '',
        recommendation: `Review and remediate: ${msg.slice(0, 100)}`,
        description: msg,
      });
    }
    logger.info({ targetUrl, findings: findings.length }, 'Nikto scan complete');
  } finally {
    try { fs.unlinkSync(outFile); } catch { /* best effort */ }
  }

  return findings;
}
