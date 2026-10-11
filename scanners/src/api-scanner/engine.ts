import { logger } from '../utils/logger.js';

export interface ApiEndpoint {
  path: string;
  method: string;
  parameters: ApiParameter[];
  requestBody?: Record<string, unknown>;
  responses: Record<string, unknown>;
  authenticated: boolean;
}

export interface ApiParameter {
  name: string;
  in: 'query' | 'header' | 'path' | 'cookie' | 'body';
  required: boolean;
  type: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object';
  description?: string;
  example?: unknown;
}

export interface FuzzResult {
  endpoint: string;
  method: string;
  parameter: string;
  payload: string;
  statusCode: number;
  responseLength: number;
  responseTime: number;
  anomaly: boolean;
  anomalyType?: string;
  evidence?: string;
}

const FUZZ_PAYLOADS: Record<string, string[]> = {
  sql_injection: ["'", "1' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--", "admin'--"],
  xss: ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "javascript:alert(1)"],
  nosql_injection: ['{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}', '{"$regex": ".*"}'],
  command_injection: ["; ls", "| whoami", "$(cat /etc/passwd)", "`id`", "& dir"],
  path_traversal: ["../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "....//....//....//etc/passwd"],
  ssrf: ["http://169.254.169.254/", "http://127.0.0.1:8080", "http://[::1]:6379"],
  overflow: ["A".repeat(10000), "%s%s%s%s%s%s%s%s%s%s", "\x00\x00\x00\x00"],
  format_string: ["%s%s%s%s%s", "%x%x%x%x%x", "%n%n%n%n"],
  unicode: ["%C0%AE%C0%AE", "\\u0000", "\\x00", "␀"],
  xml: ["<xml><![CDATA[<]]></xml>", "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"],
  boundary: ["", "null", "undefined", "NaN", "Infinity", "-1", "0", "99999999999999999999", "true", "false"],
};

export function discoverEndpoints(swaggerDoc: Record<string, unknown>): ApiEndpoint[] {
  const endpoints: ApiEndpoint[] = [];

  try {
    const paths = swaggerDoc.paths || swaggerDoc.swagger || {};
    if (typeof paths === 'object' && paths !== null) {
      for (const [path, methods] of Object.entries(paths as Record<string, unknown>)) {
        if (typeof methods !== 'object' || methods === null) continue;
        for (const [method, details] of Object.entries(methods as Record<string, unknown>)) {
          if (!['get', 'post', 'put', 'patch', 'delete', 'options', 'head'].includes(method)) continue;

          const detail = details as Record<string, unknown>;
          const parameters: ApiParameter[] = [];
          const rawParams = detail.parameters as Array<Record<string, unknown>> | undefined;
          if (rawParams) {
            for (const p of rawParams) {
              parameters.push({
                name: p.name as string || '',
                in: (p.in as ApiParameter['in']) || 'query',
                required: (p.required as boolean) || false,
                type: ((p.schema as Record<string, unknown> | undefined)?.type as ApiParameter['type']) || 'string',
                description: p.description as string,
              });
            }
          }

          if (detail.requestBody) {
            parameters.push({
              name: 'body',
              in: 'body',
              required: true,
              type: 'object',
              description: 'Request body',
            });
          }

          endpoints.push({
            path,
            method: method.toUpperCase(),
            parameters,
            responses: (detail.responses as Record<string, unknown>) || {},
            authenticated: detail.security !== undefined,
          });
        }
      }
    }
  } catch (err) {
    logger.error({ err }, 'Failed to parse OpenAPI/Swagger document');
  }

  return endpoints;
}

export function generateFuzzVectors(endpoint: ApiEndpoint): Array<{ parameter: string; location: string; payload: string; category: string }> {
  const vectors: Array<{ parameter: string; location: string; payload: string; category: string }> = [];

  for (const param of endpoint.parameters) {
    for (const [category, payloads] of Object.entries(FUZZ_PAYLOADS)) {
      for (const payload of payloads.slice(0, 5)) {
        vectors.push({
          parameter: param.name,
          location: param.in,
          payload,
          category,
        });
      }
    }
  }

  if (endpoint.parameters.length === 0) {
    for (const [category, payloads] of Object.entries(FUZZ_PAYLOADS)) {
      vectors.push({
        parameter: 'q',
        location: 'query',
        payload: payloads[0]!,
        category,
      });
    }
  }

  return vectors;
}

export function calculateRiskScore(endpoint: ApiEndpoint, fuzzResults: FuzzResult[]): number {
  let score = 0;

  const anomalies = fuzzResults.filter(r => r.anomaly);
  score += anomalies.length * 10;

  if (!endpoint.authenticated) score += 20;

  const hasSensitiveParams = endpoint.parameters.some(
    p => ['password', 'token', 'secret', 'key', 'auth', 'credit', 'ssn'].some(
      s => p.name.toLowerCase().includes(s),
    ),
  );
  if (hasSensitiveParams) score += 15;

  if (['POST', 'PUT', 'PATCH'].includes(endpoint.method)) score += 5;

  const sqliAnomalies = anomalies.filter(r => r.anomalyType === 'sql_injection');
  if (sqliAnomalies.length > 0) score += 30;

  const authBypass = fuzzResults.filter(r => r.statusCode === 200 && !endpoint.authenticated);
  if (authBypass.length > 0) score += 25;

  return Math.min(100, score);
}

export function analyzeFuzzResponse(
  baselineStatus: number,
  baselineLength: number,
  baselineTime: number,
  testResult: { status: number; body: string; timing: number },
  category: string,
): { anomaly: boolean; anomalyType?: string; evidence?: string } {
  const lengthDiff = Math.abs(testResult.body.length - baselineLength);
  const lengthRatio = baselineLength > 0 ? lengthDiff / baselineLength : 0;

  if (testResult.status === 500) {
    return { anomaly: true, anomalyType: 'server_error', evidence: `Status 500 with ${category} payload` };
  }

  if (lengthRatio > 0.5 && baselineLength > 100) {
    return { anomaly: true, anomalyType: category, evidence: `Response length changed by ${Math.round(lengthRatio * 100)}%` };
  }

  if (testResult.timing > baselineTime * 5 && baselineTime > 100) {
    return { anomaly: true, anomalyType: 'time_based', evidence: `Response time increased from ${baselineTime}ms to ${testResult.timing}ms` };
  }

  if (testResult.status !== baselineStatus && [401, 403].includes(testResult.status)) {
    return { anomaly: true, anomalyType: 'auth_change', evidence: `Auth status changed to ${testResult.status}` };
  }

  return { anomaly: false };
}
