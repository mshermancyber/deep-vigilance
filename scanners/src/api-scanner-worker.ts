import { Worker, Job } from 'bullmq';
import https from 'https';
import http from 'http';
import { logger } from './utils/logger.js';
import { assertScannableUrl } from './utils/ssrf.js';
import { discoverEndpoints, generateFuzzVectors, analyzeFuzzResponse, calculateRiskScore, FuzzResult } from './api-scanner/engine.js';
import { startScan, storeFinding, completeScan, failScan } from './utils/scan-store.js';

const connection = {
  host: process.env.REDIS_HOST || 'redis',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD,
};

async function makeRequest(
  baseUrl: string,
  method: string,
  params: Record<string, string> = {},
  body?: unknown,
): Promise<{ status: number; body: string; headers: Record<string, string>; timing: number }> {
  const url = new URL(baseUrl);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  await assertScannableUrl(url.href);
  return new Promise((resolve, reject) => {

    const options: https.RequestOptions = {
      hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search, method,
      headers: { 'User-Agent': 'AppSec-API-Scanner/1.0', 'Accept': 'application/json' },
      rejectUnauthorized: false, timeout: 15000,
    };

    const startTime = Date.now();
    const transport = url.protocol === 'https:' ? https : http;

    const req = transport.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (v) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
        }
        resolve({ status: res.statusCode || 0, body: data.slice(0, 100000), headers, timing: Date.now() - startTime });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });

    if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

async function processJob(job: Job): Promise<Record<string, unknown>> {
  logger.info({ jobId: job.id, name: job.name }, 'API Scanner Worker: Processing job');

  const { scanId, projectId, options, organizationId } = job.data;
  const targetUrl = options?.targetUrl || 'https://example.com';
  const fuzzResults: FuzzResult[] = [];

  try {
    await job.updateProgress(10);
    // Mark the scan running in the DB (SAST/DAST workers do the same via
    // scan-store). Without this the row stays 'queued' forever.
    await startScan(scanId);

    const endpoints = discoverEndpoints(options?.swaggerDoc || options?.openApiSpec || { paths: {} });
    if (endpoints.length === 0) {
      const commonPaths = ['/api', '/api/v1', '/api/v2', '/health', '/users', '/auth/login'];
      for (const path of commonPaths) {
        endpoints.push({
          path, method: 'GET',
          parameters: [{ name: 'q', in: 'query', required: false, type: 'string' }],
          responses: {}, authenticated: false,
        });
      }
    }

    logger.info({ scanId, endpointCount: endpoints.length }, 'API Scanner: Endpoints discovered');
    await job.updateProgress(20);

    let processed = 0;
    for (const endpoint of endpoints) {
      processed++;
      await job.updateProgress(20 + Math.floor((processed / endpoints.length) * 70));

      const baseUrl = `${targetUrl.replace(/\/$/, '')}${endpoint.path}`;

      try {
        const baseline = await makeRequest(baseUrl, endpoint.method);
        const vectors = generateFuzzVectors(endpoint);

        for (const vector of vectors.slice(0, 20)) {
          try {
            const params: Record<string, string> = {};
            if (vector.location === 'query') params[vector.parameter] = vector.payload;

            let body: unknown;
            if (vector.location === 'body') {
              try { body = JSON.parse(vector.payload); } catch { body = { [vector.parameter]: vector.payload }; }
            }

            const result = await makeRequest(baseUrl, endpoint.method, params, body);
            const analysis = analyzeFuzzResponse(
              baseline.status, baseline.body.length, baseline.timing,
              { status: result.status, body: result.body, timing: result.timing },
              vector.category,
            );

            if (analysis.anomaly) {
              fuzzResults.push({
                endpoint: endpoint.path, method: endpoint.method,
                parameter: vector.parameter, payload: vector.payload,
                statusCode: result.status, responseLength: result.body.length,
                responseTime: result.timing,
                anomaly: true, anomalyType: analysis.anomalyType, evidence: analysis.evidence,
              });
            }
          } catch { continue; }
        }
      } catch { continue; }
    }

    await job.updateProgress(95);

    const riskScore = calculateRiskScore(endpoints[0]!, fuzzResults);

    const findings = fuzzResults.map(f => ({
      ...f, type: 'api', scanId, projectId, orgId: organizationId,
      severity: f.anomalyType === 'sql_injection' ? 'critical' :
                f.anomalyType === 'auth_change' ? 'high' :
                f.anomalyType === 'server_error' ? 'medium' : 'low',
      title: `API Fuzzing: ${f.anomalyType || 'anomaly'} in ${f.endpoint}`,
      description: `Fuzzing detected an anomaly in ${f.method} ${f.endpoint} parameter ${f.parameter}`,
    }));

    // Persist findings + mark the scan completed in the DB. Previously this
    // worker only returned the result, so results were stranded in the BullMQ
    // job value: scans stayed 'queued' and the UI showed nothing.
    const owaspByType: Record<string, string> = {
      sql_injection: 'A03:2021-Injection', nosql_injection: 'A03:2021-Injection',
      command_injection: 'A03:2021-Injection', xss: 'A03:2021-Injection',
      path_traversal: 'A01:2021-Broken Access Control',
      auth_change: 'A07:2021-Identification and Authentication Failures',
    };
    const cweByType: Record<string, string> = {
      sql_injection: 'CWE-89', nosql_injection: 'CWE-943', command_injection: 'CWE-77',
      xss: 'CWE-79', path_traversal: 'CWE-22', auth_change: 'CWE-287',
    };
    for (const f of findings) {
      await storeFinding(scanId, projectId, organizationId, {
        type: 'api',
        title: f.title,
        description: f.description,
        severity: f.severity,
        cweId: cweByType[f.anomalyType || ''],
        owaspCategory: owaspByType[f.anomalyType || ''],
        recommendation: `Validate and sanitize the '${f.parameter}' parameter on ${f.method} ${f.endpoint}. Use parameterized queries and reject unexpected input.`,
        confidence: 'medium',
        metadata: {
          endpoint: f.endpoint, method: f.method, parameter: f.parameter,
          payload: f.payload, statusCode: f.statusCode, anomalyType: f.anomalyType,
          evidence: f.evidence, responseTime: f.responseTime, responseLength: f.responseLength,
        },
      });
    }

    await completeScan(scanId, findings.length, {
      riskScore, endpointsTested: endpoints.length, targetUrl,
    });

    await job.updateProgress(100);
    logger.info({ scanId, totalFindings: findings.length, riskScore }, 'API Scanner: Scan completed');
    return { scanId, projectId, organizationId, findings, totalFindings: findings.length, riskScore, endpointsTested: endpoints.length };
  } catch (err) {
    logger.error({ scanId, err }, 'API Scanner: Scan failed');
    await failScan(scanId, err instanceof Error ? err.message : String(err));
    throw err;
  }
}

const worker = new Worker('api-scan', processJob, {
  connection, concurrency: 4,
  limiter: { max: 10, duration: 60000 },
});

worker.on('completed', (job) => logger.info({ jobId: job?.id }, 'API scanner job completed'));
worker.on('failed', (job, err) => logger.error({ jobId: job?.id, err: err.message }, 'API scanner job failed'));

logger.info('API Scanner Worker started and waiting for jobs...');

process.on('SIGTERM', async () => { await worker.close(); process.exit(0); });
