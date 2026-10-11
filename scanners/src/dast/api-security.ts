// API Security DAST Module — OWASP API Top 10 2023
//
// Covers: BOLA, BFLA, Mass Assignment, Excessive Data Exposure, Rate Limiting,
// Shadow/Undocumented Endpoints, and more.
import { DastAttack, DastTarget } from './engine.js';

// =========================================================================
// OWASP API Security Top 10 2023 — Attack Definitions
// =========================================================================

export const API_SECURITY_ATTACKS: DastAttack[] = [
  // -----------------------------------------------------------------------
  // API1:2023 — Broken Object Level Authorization (BOLA)
  // -----------------------------------------------------------------------
  {
    id: 'DAST-API-BOLA-001',
    name: 'Broken Object Level Authorization (BOLA)',
    description:
      'Tests for BOLA by swapping resource IDs between two authenticated sessions. ' +
      'If User A can access User B resources, the API lacks proper object-level authorization.',
    severity: 'critical',
    cweId: 'CWE-639',
    owaspCategory: 'API1:2023 - Broken Object Level Authorization',
    attackType: 'path',
    payloads: [
      // Placeholder — actual payloads generated dynamically by generateBolaPayloads()
      '/api/users/1',
      '/api/users/2',
      '/api/accounts/1',
      '/api/accounts/2',
      '/api/orders/1001',
      '/api/orders/1002',
    ],
    detectPatterns: [
      /"(?:email|ssn|credit|password|token|secret|ssn|address|phone)"/i,
    ],
    cvssScore: 8.6,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
    recommendation:
      'Implement per-object authorization checks. Never rely solely on resource ID ' +
      'obfuscation. Use UUIDs (not sequential IDs) and verify ownership on every request.',
  },

  // -----------------------------------------------------------------------
  // API5:2023 — Broken Function Level Authorization (BFLA)
  // -----------------------------------------------------------------------
  {
    id: 'DAST-API-BFLA-001',
    name: 'Broken Function Level Authorization (BFLA)',
    description:
      'Tests for BFLA by calling administrative/privileged endpoints with a ' +
      'low-privilege user token. Success indicates missing function-level authorization.',
    severity: 'critical',
    cweId: 'CWE-285',
    owaspCategory: 'API5:2023 - Broken Function Level Authorization',
    attackType: 'path',
    payloads: [
      // Placeholder — actual payloads generated dynamically by generateBflaPayloads()
      '/api/admin/users',
      '/api/admin/settings',
      '/api/admin/config',
    ],
    detectPatterns: [
      /200 OK|201 Created/,
    ],
    cvssScore: 8.6,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N',
    recommendation:
      'Deny all access by default. Require explicit grants for every endpoint. ' +
      'Use middleware to enforce role-based access at the function level.',
  },

  // -----------------------------------------------------------------------
  // API6:2023 — Mass Assignment
  // -----------------------------------------------------------------------
  {
    id: 'DAST-API-MASS-001',
    name: 'Mass Assignment',
    description:
      'Tests for mass assignment by appending privileged fields (role, isAdmin, verified) ' +
      'to POST/PUT/PATCH request bodies. If the field is accepted and reflected, the API is vulnerable.',
    severity: 'high',
    cweId: 'CWE-915',
    owaspCategory: 'API6:2023 - Unrestricted Access to Sensitive Business Flows',
    attackType: 'body',
    payloads: [
      '{"role":"admin"}',
      '{"isAdmin":true}',
      '{"verified":true}',
      '{"accountType":"premium"}',
      '{"role":"superuser"}',
      '{"isSuperAdmin":true}',
      '{"approved":true}',
      '{"subscription":"enterprise"}',
    ],
    detectPatterns: [
      /"role"\s*:\s*"admin"/,
      /"isAdmin"\s*:\s*true/,
      /"verified"\s*:\s*true/,
      /"accountType"\s*:\s*"premium"/,
      /"isSuperAdmin"\s*:\s*true/,
    ],
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N',
    recommendation:
      'Use DTOs or allowlists for request body binding. Never bind directly to ' +
      'domain models. Explicitly define which fields clients may set.',
  },

  // -----------------------------------------------------------------------
  // API3:2023 — Excessive Data Exposure
  // -----------------------------------------------------------------------
  {
    id: 'DAST-API-EDATA-001',
    name: 'Excessive Data Exposure',
    description:
      'Tests for excessive data exposure by requesting resource lists without filters ' +
      'and checking responses for sensitive fields (passwords, SSNs, tokens, secrets).',
    severity: 'medium',
    cweId: 'CWE-200',
    owaspCategory: 'API3:2023 - Excessive Data Exposure',
    attackType: 'query',
    payloads: [
      '?include=all',
      '?fields=*',
      '?expand=*',
      '?include=password,ssn,credit_card',
      '?verbose=true',
      '?debug=true',
    ],
    detectPatterns: [
      /"(?:password|ssn|credit_card|secret|token|api_key|private_key)"/i,
      /"(?:hashed_password|password_hash|passwd)"/i,
      /"(?:social_security|tax_id|government_id)"/i,
    ],
    cvssScore: 6.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    recommendation:
      'Use response filtering/DTOs to return only necessary fields. Never rely on ' +
      'the client to filter sensitive data. Implement server-side field selection.',
  },

  // -----------------------------------------------------------------------
  // API4:2023 — Lack of Rate Limiting
  // -----------------------------------------------------------------------
  {
    id: 'DAST-API-RATELIMIT-001',
    name: 'Lack of Rate Limiting',
    description:
      'Tests for rate limiting by sending rapid repeated requests and checking for ' +
      '429 (Too Many Requests) responses. Absence indicates missing rate limiting.',
    severity: 'medium',
    cweId: 'CWE-770',
    owaspCategory: 'API4:2023 - Unrestricted Resource Consumption',
    attackType: 'query',
    payloads: [
      // No payloads — rate limiting is detected via response headers/status
    ],
    detectPatterns: [
      /429 Too Many Requests/i,
      /Retry-After/i,
    ],
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
    recommendation:
      'Implement rate limiting per endpoint, per user, and per IP. Return ' +
      'Retry-After headers and 429 status codes when limits are exceeded.',
  },

  // -----------------------------------------------------------------------
  // API7:2023 — Shadow/Undocumented Endpoints
  // -----------------------------------------------------------------------
  {
    id: 'DAST-API-INVENTORY-001',
    name: 'Shadow / Undocumented Endpoints',
    description:
      'Discovers undocumented/shadow endpoints by probing common paths that may ' +
      'expose sensitive functionality or debug interfaces.',
    severity: 'medium',
    cweId: 'CWE-200',
    owaspCategory: 'API7:2023 - Server Side Request Forgery (SSRF)',
    attackType: 'path',
    payloads: [
      '/api/admin',
      '/api/v2/admin',
      '/actuator',
      '/actuator/health',
      '/actuator/env',
      '/actuator/metrics',
      '/swagger',
      '/swagger-ui.html',
      '/swagger.json',
      '/openapi.json',
      '/.env',
      '/api/debug',
      '/api/internal',
      '/api/private',
      '/api/legacy',
      '/graphql',
      '/graphiql',
      '/api/graphql',
      '/api-docs',
      '/api/docs',
    ],
    detectPatterns: [
      /200 OK/,
    ],
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    recommendation:
      'Maintain an up-to-date API inventory. Disable debug/actuator endpoints in ' +
      'production. Use automated discovery to identify shadow endpoints.',
  },

  // -----------------------------------------------------------------------
  // API2:2023 — Broken Authentication (JWT/Token Testing)
  // -----------------------------------------------------------------------
  {
    id: 'DAST-API-AUTH-001',
    name: 'Broken Authentication — Token Flaws',
    description:
      'Tests for authentication weaknesses including missing auth headers, ' +
      'expired token acceptance, and unauthenticated access to protected endpoints.',
    severity: 'high',
    cweId: 'CWE-287',
    owaspCategory: 'API2:2023 - Broken Authentication',
    attackType: 'header',
    payloads: [],
    detectPatterns: [
      /200 OK/,
    ],
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    recommendation:
      'Validate tokens on every request. Reject expired tokens. Require ' +
      'authentication for all non-public endpoints. Use short-lived access tokens.',
  },

  // -----------------------------------------------------------------------
  // API8:2023 — Injection (API-Specific)
  // -----------------------------------------------------------------------
  {
    id: 'DAST-API-INJECT-001',
    name: 'API Injection (GraphQL / REST)',
    description:
      'Tests for injection flaws specific to API endpoints, including GraphQL ' +
      'query batching attacks and REST parameter injection.',
    severity: 'high',
    cweId: 'CWE-89',
    owaspCategory: 'API8:2023 - Injection',
    attackType: 'body',
    payloads: [
      '{"query":"{ __schema { types { name fields { name } } } }"}',
      '{"query":"{ __typename }"}',
      '{"query":"query { users { id email password } }"}',
      '{"$or":[{"id":1},{"id":2}]}',
    ],
    detectPatterns: [
      /"__schema"/,
      /"__typename"/,
      /"password"\s*:/,
    ],
    cvssScore: 8.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    recommendation:
      'Use query allowlists/whitelists for GraphQL. Disable introspection in ' +
      'production. Set query depth and complexity limits. Validate all inputs.',
  },
];

// =========================================================================
// BOLA Payload Generator — Swap resource IDs between sessions
// =========================================================================

export interface BolaTestVector {
  /** Path with swapped IDs, e.g. "/api/users/42" */
  path: string;
  /** Optional modified body for POST/PUT targeting another resource */
  body?: object;
  /** Description of what the test is doing */
  description: string;
}

/**
 * Generate BOLA (Broken Object Level Authorization) test vectors by swapping
 * object IDs between two different authenticated contexts.
 *
 * @param resourceType  The resource type name (e.g., "users", "orders", "accounts")
 * @param baseId        The primary user's resource ID
 * @param altId         The secondary (victim) user's resource ID
 * @returns Array of test vectors with swapped ID payloads
 */
export function generateBolaPayloads(
  resourceType: string,
  baseId: string,
  altId: string,
): BolaTestVector[] {
  const vectors: BolaTestVector[] = [];

  // Common API patterns for resource access
  const patterns = [
    { path: `/${resourceType}/{id}`, desc: 'Single resource by ID' },
    { path: `/api/${resourceType}/{id}`, desc: 'API single resource' },
    { path: `/api/v1/${resourceType}/{id}`, desc: 'API v1 resource' },
    { path: `/api/v2/${resourceType}/{id}`, desc: 'API v2 resource' },
    { path: `/rest/${resourceType}/{id}`, desc: 'REST resource' },
    { path: `/${resourceType}/{id}/profile`, desc: 'Resource profile' },
    { path: `/${resourceType}/{id}/details`, desc: 'Resource details' },
    { path: `/${resourceType}/{id}/settings`, desc: 'Resource settings' },
  ];

  for (const pattern of patterns) {
    // Test with altId (victim's ID) — this is the actual BOLA test
    vectors.push({
      path: pattern.path.replace('{id}', altId),
      description: `BOLA: Access ${pattern.desc} (${altId}) from another session — ${pattern.desc}`,
    });

    // Also test with numeric variants if IDs look sequential
    if (/^\d+$/.test(baseId)) {
      const baseNum = parseInt(baseId, 10);
      const altNum = parseInt(altId, 10);
      // Test adjacent IDs too
      for (const probeId of [baseNum - 1, baseNum + 1, altNum - 1, altNum + 1]) {
        if (probeId > 0 && probeId !== baseNum && probeId !== altNum) {
          vectors.push({
            path: pattern.path.replace('{id}', String(probeId)),
            description: `BOLA: Enumerate ${pattern.desc} (adjacent ID ${probeId})`,
          });
        }
      }
    }
  }

  return vectors;
}

// =========================================================================
// BFLA Payload Generator — Low-privilege token on high-privilege endpoints
// =========================================================================

/**
 * Generate BFLA (Broken Function Level Authorization) test targets.
 * Takes a low-privilege token and a list of high-privilege endpoints,
 * and produces DastTarget objects that can be sent directly via makeHttpRequest.
 *
 * @param lowPrivToken       The low-privilege user's Bearer token
 * @param highPrivEndpoints  List of URLs/paths that should require admin/privileged access
 * @param baseOrigin         The base origin URL for relative paths
 * @returns Array of DastTarget objects to test
 */
export function generateBflaPayloads(
  lowPrivToken: string,
  highPrivEndpoints: string[],
  baseOrigin?: string,
): DastTarget[] {
  const targets: DastTarget[] = [];

  // Standard high-privilege endpoint patterns to always test
  const standardAdminPaths = [
    '/api/admin',
    '/api/admin/users',
    '/api/admin/settings',
    '/api/admin/config',
    '/api/admin/logs',
    '/api/admin/audit',
    '/api/v1/admin',
    '/api/v2/admin',
    '/admin/api/users',
    '/admin/api/settings',
    '/api/users?role=admin',
    '/api/settings/system',
    '/api/config',
    '/api/system',
    '/api/management',
    '/api/manage',
  ];

  const allEndpoints = [...new Set([...highPrivEndpoints, ...standardAdminPaths])];

  for (const endpoint of allEndpoints) {
    let fullUrl: string;
    if (baseOrigin && endpoint.startsWith('/')) {
      fullUrl = baseOrigin.replace(/\/$/, '') + endpoint;
    } else if (!endpoint.startsWith('http')) {
      fullUrl = (baseOrigin || 'https://localhost').replace(/\/$/, '') + endpoint;
    } else {
      fullUrl = endpoint;
    }

    // GET request with low-priv token
    targets.push({
      url: fullUrl,
      method: 'GET',
      headers: {
        Authorization: `Bearer ${lowPrivToken}`,
        Accept: 'application/json',
      },
      contentType: 'application/json',
    });

    // Also test POST to admin endpoints (more dangerous)
    targets.push({
      url: fullUrl,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${lowPrivToken}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: '{"test":true}',
      contentType: 'application/json',
    });
  }

  return targets;
}

// =========================================================================
// Mass Assignment Payload Generator
// =========================================================================

export interface MassAssignmentPayload {
  /** Human-readable label for the payload */
  label: string;
  /** The extra fields to append to a request body */
  extraFields: Record<string, unknown>;
  /** The merged JSON body including a base object */
  body: string;
}

/**
 * Generate mass assignment payloads that append privilege-escalation fields
 * to existing request bodies.
 *
 * @param baseBody  Optional base body to merge fields into. If omitted, generates standalone payloads.
 * @returns Array of body payloads with escalated privilege fields
 */
export function generateMassAssignmentPayloads(
  baseBody?: Record<string, unknown>,
): MassAssignmentPayload[] {
  const privilegeFields: Array<{
    label: string;
    fields: Record<string, unknown>;
  }> = [
    { label: 'role:admin', fields: { role: 'admin' } },
    { label: 'isAdmin:true', fields: { isAdmin: true } },
    { label: 'verified:true', fields: { verified: true } },
    { label: 'accountType:premium', fields: { accountType: 'premium' } },
    { label: 'role:superuser', fields: { role: 'superuser' } },
    { label: 'isSuperAdmin:true', fields: { isSuperAdmin: true } },
    { label: 'approved:true', fields: { approved: true } },
    { label: 'subscription:enterprise', fields: { subscription: 'enterprise' } },
    { label: 'permissions:admin', fields: { permissions: 'admin' } },
    { label: 'plan:ultimate', fields: { plan: 'ultimate' } },
    { label: 'accessLevel:999', fields: { accessLevel: 999 } },
    { label: 'isStaff:true', fields: { isStaff: true } },
  ];

  const payloads: MassAssignmentPayload[] = [];

  for (const { label, fields } of privilegeFields) {
    const merged = baseBody ? { ...baseBody, ...fields } : { ...fields };
    payloads.push({
      label,
      extraFields: fields,
      body: JSON.stringify(merged),
    });
  }

  return payloads;
}

// =========================================================================
// API-Specific Response Analysis Helpers
// =========================================================================

/**
 * Analyze a response for API-specific BOLA indicators.
 * Checks if the response contains data belonging to a different user/organization.
 */
export function analyzeBolaResponse(
  responseBody: string,
  expectedOwnerFields: string[],
): { exposed: boolean; evidence: string } {
  const lower = responseBody.toLowerCase();

  for (const field of expectedOwnerFields) {
    // Check if sensitive PII-like fields appear in the response
    const pattern = new RegExp(`"${field}"\\s*:\\s*"[^"]+"`, 'i');
    if (pattern.test(responseBody)) {
      return {
        exposed: true,
        evidence: `Response contains "${field}" field — possible cross-user data exposure`,
      };
    }
  }

  // Check for generic indicators: email addresses, IDs that don't match
  const emailPattern = /"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"/;
  if (emailPattern.test(responseBody)) {
    return {
      exposed: true,
      evidence: 'Response contains email addresses — verify these belong to the requesting user',
    };
  }

  return { exposed: false, evidence: '' };
}

/**
 * Check if a response indicates successful access to a privileged endpoint
 * when called with a low-privilege token.
 */
export function analyzeBflaResponse(
  status: number,
  body: string,
): { vulnerable: boolean; evidence: string } {
  // 200/201 on an admin endpoint with a low-priv token = vulnerable
  if (status >= 200 && status < 300 && !isGenericErrorResponse(body)) {
    return {
      vulnerable: true,
      evidence: `Privileged endpoint returned ${status} with valid data — function-level authorization missing`,
    };
  }

  // 401/403 = expected (correctly blocked)
  if (status === 401 || status === 403) {
    return { vulnerable: false, evidence: '' };
  }

  // 404 = endpoint doesn't exist (not vulnerable, but shadow endpoint may exist elsewhere)
  if (status === 404) {
    return { vulnerable: false, evidence: '' };
  }

  return { vulnerable: false, evidence: '' };
}

/**
 * Check if a response body reflects mass assignment fields.
 */
export function analyzeMassAssignmentResponse(
  body: string,
  injectedFieldName: string,
): { reflected: boolean; evidence: string } {
  const lower = body.toLowerCase();
  const fieldLower = injectedFieldName.toLowerCase();

  // Check if the field and a privileged value appear together
  if (lower.includes(fieldLower)) {
    // Look for the field with an admin/privileged value
    const pattern = new RegExp(
      `"${fieldLower}"\\s*:\\s*(true|"admin"|"premium"|"superuser"|"enterprise"|999)`,
      'i',
    );
    if (pattern.test(body)) {
      return {
        reflected: true,
        evidence: `Injected field "${injectedFieldName}" reflected in response with privileged value`,
      };
    }
  }

  return { reflected: false, evidence: '' };
}

// =========================================================================
// Rate Limiting Detection
// =========================================================================

export interface RateLimitResult {
  rateLimited: boolean;
  burstCount: number;
  rateLimitHeaders: Record<string, string>;
  evidence: string;
}

/**
 * Test an endpoint for rate limiting by sending rapid requests.
 * Only sends HEAD/GET requests (safe, non-mutating).
 *
 * @param makeRequest  A function that makes an HTTP request and returns status + headers
 * @param url          The URL to test
 * @param burstSize    Number of rapid requests to send (default 15)
 * @returns RateLimitResult with detection details
 */
export async function testRateLimiting(
  makeRequest: (
    target: DastTarget,
  ) => Promise<{ status: number; headers: Record<string, string>; body: string }>,
  url: string,
  burstSize: number = 15,
): Promise<RateLimitResult> {
  const rateLimitHeaders: Record<string, string> = {};
  let rateLimited = false;
  let burstCount = 0;
  let evidence = '';

  for (let i = 0; i < burstSize; i++) {
    try {
      const resp = await makeRequest({
        url,
        method: 'GET',
        headers: { Accept: '*/*' },
        contentType: 'application/json',
      });

      burstCount++;

      // Check for rate limit indicators
      if (resp.status === 429) {
        rateLimited = true;
        evidence = `Rate limited after ${i + 1} requests (HTTP 429)`;
        if (resp.headers['retry-after']) {
          rateLimitHeaders['retry-after'] = resp.headers['retry-after'];
        }
        break;
      }

      if (resp.headers['retry-after']) {
        rateLimitHeaders['retry-after'] = resp.headers['retry-after'];
      }
      if (resp.headers['x-ratelimit-remaining']) {
        rateLimitHeaders['x-ratelimit-remaining'] =
          resp.headers['x-ratelimit-remaining'];
        const remaining = parseInt(
          resp.headers['x-ratelimit-remaining'],
          10,
        );
        if (remaining <= 0) {
          rateLimited = true;
          evidence = `X-RateLimit-Remaining reached 0 after ${i + 1} requests`;
          break;
        }
      }
      if (resp.headers['x-ratelimit-limit']) {
        rateLimitHeaders['x-ratelimit-limit'] =
          resp.headers['x-ratelimit-limit'];
      }

      // No delay between requests — we want to trigger the limit
    } catch {
      // Request failed — continue with remaining
      continue;
    }
  }

  if (!rateLimited && burstCount >= burstSize) {
    evidence = `No rate limiting detected after ${burstSize} rapid requests`;
  }

  return { rateLimited, burstCount, rateLimitHeaders, evidence };
}

// =========================================================================
// Helpers
// =========================================================================

function isGenericErrorResponse(body: string): boolean {
  // Detect generic error pages/JSON that indicate the endpoint exists but denied access
  const lower = body.slice(0, 1000).toLowerCase();
  return (
    lower.includes('<!doctype') ||
    lower.includes('<html') ||
    lower.includes('internal server error') ||
    lower.includes('not found') ||
    lower.includes('bad request') ||
    (lower.includes('error') && lower.length < 200)
  );
}
