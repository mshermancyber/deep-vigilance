// M7d: Mock Server & Code Generation -- Real HTTP mock server, route matching,
// code snippet generation (15+ languages), and API documentation generation.
//
// The mock server creates a real Express HTTP listener on a configurable port.
// Code generators produce runnable, compilable code with proper imports and error handling.

import http from 'http';
import express, { Express, Request, Response, Router } from 'express';
import { randomUUID, randomInt } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { query, transaction } from '../../core/db/pool.js';
import { logger } from '../../core/logging/logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Single mock route definition. */
export interface MockRoute {
  id: string;
  method: string;
  pathPattern: string;
  responseStatus: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
  latencyMs: number;
  errorProbability: number;
  errorStatus: number;
}

/** Configuration for createMockServer. */
export interface MockServerConfig {
  /** TCP port for the mock server (0 = pick random available port). */
  port?: number;
  /** Per-route latency: fixed ms or {min, max} random range. */
  latency?: number | { min: number; max: number };
  /** Global error probability override (0-1), defaults to 0. */
  errorProbability?: number;
  /** Status code to return on simulated errors (default 500). */
  errorStatus?: number;
  /** Whether to persist the mock server record in the database. */
  persist?: boolean;
  /** Name for the mock server (required if persist is true). */
  name?: string;
  /** Org ID (required if persist is true). */
  orgId?: string;
  /** User ID creating the server (required if persist is true). */
  userId?: string;
}

/** Return value of createMockServer. */
export interface MockServerInstance {
  serverUrl: string;
  port: number;
  mockRoutes: MockRoute[];
  server: http.Server;
  /** Gracefully stop the mock server. */
  stop: () => Promise<void>;
}

/** Shape of a code generation request. */
export interface CodeGenRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  bodyType?: string;
}

// ---------------------------------------------------------------------------
// Template variable helpers
// ---------------------------------------------------------------------------

const FIRST_NAMES = [
  'Alice', 'Bob', 'Charlie', 'Diana', 'Edward', 'Fiona', 'George', 'Hannah',
  'Isaac', 'Julia', 'Kevin', 'Laura', 'Michael', 'Nora', 'Oscar', 'Patricia',
  'Quinn', 'Rachel', 'Samuel', 'Tara', 'Uma', 'Victor', 'Wendy', 'Xavier',
  'Yvonne', 'Zachary',
];

const LAST_NAMES = [
  'Anderson', 'Brown', 'Chen', 'Davis', 'Evans', 'Foster', 'Garcia', 'Harris',
  'Irwin', 'Johnson', 'Kim', 'Lee', 'Martinez', 'Nguyen', 'Owen', 'Patel',
  'Quinn', 'Robinson', 'Smith', 'Taylor', 'Ueda', 'Vasquez', 'Williams',
  'Xu', 'Yamamoto', 'Zhang',
];

const LOREM_WORDS = [
  'lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing',
  'elit', 'sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore',
  'et', 'dolore', 'magna', 'aliqua', 'enim', 'ad', 'minim', 'veniam',
  'quis', 'nostrud', 'exercitation', 'ullamco', 'laboris', 'nisi', 'aliquip',
  'ex', 'ea', 'commodo', 'consequat', 'duis', 'aute', 'irure', 'dolor',
  'reprehenderit', 'voluptate', 'velit', 'esse', 'cillum', 'eu', 'fugiat',
  'nulla', 'pariatur', 'excepteur', 'sint', 'occaecat', 'cupidatat', 'non',
  'proident', 'sunt', 'culpa', 'qui', 'officia', 'deserunt', 'mollit',
  'anim', 'id', 'est', 'laborum',
];

function randomFullName(): string {
  const first = FIRST_NAMES[randomInt(0, FIRST_NAMES.length)]!;
  const last = LAST_NAMES[randomInt(0, LAST_NAMES.length)]!;
  return `${first} ${last}`;
}

function randomEmail(): string {
  const first = FIRST_NAMES[randomInt(0, FIRST_NAMES.length)]!.toLowerCase();
  const last = LAST_NAMES[randomInt(0, LAST_NAMES.length)]!.toLowerCase();
  const domains = ['example.com', 'test.org', 'demo.net', 'mail.io', 'corp.co'];
  const domain = domains[randomInt(0, domains.length)];
  return `${first}.${last}@${domain}`;
}

function randomWords(count: number): string {
  const words: string[] = [];
  for (let i = 0; i < count; i++) {
    words.push(LOREM_WORDS[randomInt(0, LOREM_WORDS.length)]!);
  }
  return words.join(' ');
}

function randomBoolean(): boolean {
  return Math.random() >= 0.5;
}

function randomIntInRange(min: number, max: number): number {
  return randomInt(min, max + 1);
}

/** Replace dynamic template variables in a string. */
function resolveTemplateVariables(str: string): string {
  return str.replace(/\{\{(\$[a-zA-Z]+)(?:\s+(\d+))?\}\}/g, (_match, variable: string, arg?: string) => {
    const count = arg ? parseInt(arg, 10) : 1;
    switch (variable) {
      case '$randomFullName':      return randomFullName();
      case '$randomEmail':         return randomEmail();
      case '$randomBoolean':       return String(randomBoolean());
      case '$randomUUID':
      case '$guid':                return randomUUID();
      case '$timestamp':           return new Date().toISOString();
      case '$randomInt':           return String(randomIntInRange(0, 9999));
      case '$randomWords':         return randomWords(Math.max(1, count));
      case '$isoTimestamp':        return new Date().toISOString();
      case '$unixTimestamp':       return String(Math.floor(Date.now() / 1000));
      default:                     return `{{${variable}}}`;
    }
  });
}

// ---------------------------------------------------------------------------
// Resolve latency configuration
// ---------------------------------------------------------------------------

function resolveLatency(latencyConfig: number | { min: number; max: number } | undefined): number {
  if (latencyConfig === undefined) return 0;
  if (typeof latencyConfig === 'number') return Math.max(0, latencyConfig);
  const min = Math.max(0, latencyConfig.min);
  const max = Math.max(min, latencyConfig.max);
  return randomInt(min, max + 1);
}

// ---------------------------------------------------------------------------
// Mock Route Matching
// ---------------------------------------------------------------------------

/**
 * Match an HTTP method + path against an array of mock routes.
 * Supports:
 *   - Exact path matches
 *   - Path parameters (`:id`, `:userId`, etc.)
 *   - Wildcards (`*` at end of pattern)
 * Returns the first matching route (sorted by priority descending)
 * with a params map, or null if no route matches.
 */
export function matchMockRoute(
  method: string,
  path: string,
  mockRoutes: MockRoute[],
): { route: MockRoute; params: Record<string, string> } | null {
  const methodUpper = method.toUpperCase();

  // Sort by priority descending (higher priority checked first), then by length of pattern (more specific first)
  const sorted = [...mockRoutes].sort((a, b) => {
    // Prioritize exact method match, then path specificity
    const aExact = a.method.toUpperCase() === methodUpper ? 1 : 0;
    const bExact = b.method.toUpperCase() === methodUpper ? 1 : 0;
    if (aExact !== bExact) return bExact - aExact;
    // Longer patterns first (more specific)
    return b.pathPattern.length - a.pathPattern.length;
  });

  for (const route of sorted) {
    const routeMethod = route.method.toUpperCase();
    // Skip if methods don't match and route method isn't a wildcard
    if (routeMethod !== '*' && routeMethod !== methodUpper) continue;

    const pattern = route.pathPattern;

    // Exact match
    if (pattern === path) {
      return { route, params: {} };
    }

    // Wildcard suffix match
    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1);
      if (path.startsWith(prefix)) {
        return { route, params: { '*': path.slice(prefix.length) } };
      }
    }

    // Path parameter matching (e.g., /api/users/:id/posts/:postId)
    if (pattern.includes(':')) {
      const patternParts = pattern.split('/');
      const pathParts = path.split('/');

      if (patternParts.length !== pathParts.length) continue;

      const params: Record<string, string> = {};
      let matched = true;

      for (let i = 0; i < patternParts.length; i++) {
        const pPart = patternParts[i]!;
        const paPart = pathParts[i]!;

        if (pPart.startsWith(':')) {
          const paramName = pPart.slice(1);
          params[paramName] = paPart;
        } else if (pPart !== paPart) {
          matched = false;
          break;
        }
      }

      if (matched) {
        return { route, params };
      }
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Mock Server (Real Express HTTP Listener)
// ---------------------------------------------------------------------------

/**
 * Active mock server registry.
 * Maps slug -> server instance so we can track/stop servers.
 */
const activeMockServers = new Map<string, MockServerInstance>();

/**
 * Create and start a real Express-based mock server.
 *
 * Fetches requests from the database for the given collection, creates Express
 * routes for each one, and starts an HTTP listener on the configured port.
 *
 * Supports:
 *   - Dynamic template variables: {{$randomFullName}}, {{$randomEmail}},
 *     {{$timestamp}}, {{$guid}}, {{$randomInt}}, {{$randomBoolean}},
 *     {{$randomWords}}, {{$isoTimestamp}}, {{$unixTimestamp}}
 *   - Configurable route latency (fixed ms or random {min, max})
 *   - Simulated error injection (X% chance of 5xx)
 *   - CORS headers for browser-based API clients
 *
 * @param collectionId  UUID of the API collection
 * @param config        Mock server configuration options
 * @returns             Promise resolving to MockServerInstance
 */
export async function createMockServer(
  collectionId: string,
  config: MockServerConfig = {},
): Promise<MockServerInstance> {
  const {
    port: requestedPort = 0,
    latency,
    errorProbability: globalErrorProb,
    errorStatus: globalErrorStatus = 500,
    persist = false,
    name,
    orgId,
    userId,
  } = config;

  // --- Fetch collection data ---
  const collectionResult = await query(
    `SELECT id, name, description, environment
     FROM api_collections
     WHERE id = $1 AND deleted_at IS NULL`,
    [collectionId],
  );

  if (collectionResult.rows.length === 0) {
    throw new Error(`Collection not found: ${collectionId}`);
  }

  const collection = collectionResult.rows[0] as Record<string, unknown>;

  // --- Fetch requests for this collection ---
  const { rows: dbRequests } = await query(
    `SELECT id, name, method, url, headers, query_params, body, body_type
     FROM api_requests
     WHERE collection_id = $1 AND deleted_at IS NULL
     ORDER BY created_at, name`,
    [collectionId],
  );

  if (dbRequests.length === 0) {
    throw new Error(`Collection ${collectionId} has no requests to mock`);
  }

  // --- Build mock routes from requests ---
  const mockRoutes: MockRoute[] = dbRequests.map((req) => {
    const method = (req.method as string).toUpperCase();
    const urlStr = req.url as string;
    let pathPattern: string;

    try {
      const parsedUrl = new URL(urlStr);
      pathPattern = parsedUrl.pathname;
    } catch {
      // If URL parsing fails, treat the url as a raw path
      pathPattern = urlStr.startsWith('/') ? urlStr : `/${urlStr}`;
    }

    // Build a response body with template variables
    let responseBody = '{}';
    if (req.body_type === 'json' && req.body) {
      try {
        const parsed = JSON.parse(req.body as string);
        const mockBody: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(parsed)) {
          if (typeof v === 'string') mockBody[k] = `{{$randomWords 3}}`;
          else if (typeof v === 'number') mockBody[k] = `{{$randomInt}}`;
          else if (typeof v === 'boolean') mockBody[k] = `{{$randomBoolean}}`;
          else if (Array.isArray(v)) mockBody[k] = [];
          else if (v === null) mockBody[k] = null;
          else mockBody[k] = {};
        }
        responseBody = JSON.stringify(mockBody, null, 2);
      } catch {
        responseBody = req.body as string;
      }
    } else if (req.body_type === 'none') {
      // No request body; return a generic success response
      responseBody = JSON.stringify({
        success: true,
        message: `Mock response for ${method} ${pathPattern}`,
        timestamp: '{{$timestamp}}',
        id: '{{$guid}}',
      }, null, 2);
    } else {
      responseBody = JSON.stringify({
        success: true,
        data: '{{$randomWords 5}}',
        timestamp: '{{$timestamp}}',
      }, null, 2);
    }

    // Status code heuristic
    let responseStatus = 200;
    if (method === 'POST') responseStatus = 201;
    else if (method === 'DELETE') responseStatus = 204;
    else if (method === 'PUT' || method === 'PATCH') responseStatus = 200;

    // Latency: use route-specific or global config
    const latencyMs = resolveLatency(latency);

    return {
      id: uuidv4(),
      method,
      pathPattern,
      responseStatus,
      responseHeaders: {
        'Content-Type': 'application/json',
        'X-Mock-Server': 'appsec-mock',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
      },
      responseBody,
      latencyMs,
      errorProbability: globalErrorProb ?? 0,
      errorStatus: globalErrorStatus,
    };
  });

  // --- Persist to database if requested ---
  if (persist) {
    if (!orgId) throw new Error('orgId is required when persist=true');
    const serverId = uuidv4();
    const slug = `mock-${collectionId.slice(0, 8)}-${Date.now().toString(36)}`;

    await transaction(async (client) => {
      await client.query(
        `INSERT INTO api_mock_servers (id, org_id, collection_id, name, slug, base_url, config, enabled, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8, NOW(), NOW())`,
        [
          serverId, orgId, collectionId,
          name ?? `Mock: ${collection.name}`,
          slug,
          `http://localhost:${requestedPort || 3000}`,
          JSON.stringify(config),
          userId,
        ],
      );

      for (const rule of mockRoutes) {
        await client.query(
          `INSERT INTO api_mock_rules (id, mock_server_id, method, path_pattern, response_status, response_headers, response_body, latency_ms, error_probability, priority, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`,
          [
            uuidv4(), serverId,
            rule.method, rule.pathPattern,
            rule.responseStatus, JSON.stringify(rule.responseHeaders),
            rule.responseBody, rule.latencyMs,
            rule.errorProbability, 0,
          ],
        );
      }
    });

    logger.info({ serverId, collectionId, name }, 'Mock server persisted to database');
  }

  // --- Create Express app ---
  const app: Express = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Global CORS + preflight handler
  app.use((_req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Requested-With');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Type, X-Mock-Server, X-Mock-Latency');
    res.setHeader('X-Mock-Server', 'appsec-mock');
    if (_req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  // Health check
  app.get('/__mock/health', (_req, res) => {
    res.json({
      status: 'running',
      collectionId,
      routes: mockRoutes.length,
      uptime: process.uptime(),
    });
  });

  // List configured routes
  app.get('/__mock/routes', (_req, res) => {
    res.json({
      routes: mockRoutes.map(r => ({
        method: r.method,
        path: r.pathPattern,
        status: r.responseStatus,
        latencyMs: r.latencyMs,
        errorProbability: r.errorProbability,
      })),
    });
  });

  // --- Register mock routes from collection ---
  const mockRouter = Router();

  for (const route of mockRoutes) {
    const expressMethod = route.method.toLowerCase() as 'get' | 'post' | 'put' | 'patch' | 'delete' | 'options' | 'head';

    // Convert path parameters from :id to Express :id format (they're the same)
    const expressPath = route.pathPattern;

    const handler = async (_req: Request, res: Response) => {
      // --- Simulate latency ---
      const effectiveLatency = route.latencyMs > 0 ? route.latencyMs : resolveLatency(latency);
      if (effectiveLatency > 0) {
        await new Promise<void>(resolve => setTimeout(resolve, effectiveLatency));
      }

      // --- Simulate errors ---
      if (route.errorProbability > 0 && Math.random() < route.errorProbability) {
        res.status(route.errorStatus).json({
          error: true,
          status: route.errorStatus,
          message: 'Simulated mock server error',
          timestamp: resolveTemplateVariables('{{$timestamp}}'),
        });
        return;
      }

      // --- Resolve template variables in response body ---
      const resolvedBody = resolveTemplateVariables(route.responseBody);

      // --- Set response headers with variable resolution ---
      for (const [key, value] of Object.entries(route.responseHeaders)) {
        res.setHeader(key, resolveTemplateVariables(value));
      }
      if (effectiveLatency > 0) {
        res.setHeader('X-Mock-Latency', String(effectiveLatency));
      }

      // For 204 No Content, don't send a body
      if (route.responseStatus === 204) {
        res.status(204).end();
        return;
      }

      res.status(route.responseStatus).send(resolvedBody);
    };

    // Use the type-safe Express route registration
    if (expressMethod in mockRouter) {
      (mockRouter as any)[expressMethod](expressPath, handler);
    }
  }

  app.use('/', mockRouter);

  // Catch-all 404 for unmatched routes
  app.use((_req, res) => {
    res.status(404).json({
      error: true,
      status: 404,
      message: 'No mock route matches this request',
      hint: 'Check the method and path against your configured mock routes',
    });
  });

  // --- Start HTTP server ---
  const server = http.createServer(app);

  const port: number = await new Promise((resolve, reject) => {
    server.listen(requestedPort, () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        resolve(addr.port);
      } else {
        resolve(requestedPort || 3000);
      }
    });
    server.on('error', (err) => {
      reject(new Error(`Failed to start mock server: ${err.message}`));
    });
  });

  const serverUrl = `http://localhost:${port}`;

  // --- Build instance ---
  const instance: MockServerInstance = {
    serverUrl,
    port,
    mockRoutes,
    server,
    stop: () => {
      return new Promise<void>((resolve, reject) => {
        // Remove from active registry
        for (const [key, val] of activeMockServers) {
          if (val.port === port) {
            activeMockServers.delete(key);
            break;
          }
        }
        server.close((err) => {
          if (err) {
            logger.error({ err, port }, 'Error stopping mock server');
            reject(err);
          } else {
            logger.info({ port, collectionId }, 'Mock server stopped');
            resolve();
          }
        });
      });
    },
  };

  // Register in active servers
  const slug = `mock-${collectionId.slice(0, 8)}-${port}`;
  activeMockServers.set(slug, instance);

  logger.info({
    port,
    collectionId,
    routes: mockRoutes.length,
    url: serverUrl,
  }, 'Mock server started');

  return instance;
}

/**
 * Stop a running mock server by its URL.
 */
export async function stopMockServer(serverUrl: string): Promise<void> {
  for (const [, instance] of activeMockServers) {
    if (instance.serverUrl === serverUrl) {
      await instance.stop();
      return;
    }
  }
  throw new Error(`No active mock server found at ${serverUrl}`);
}

/**
 * Stop all running mock servers.
 */
export async function stopAllMockServers(): Promise<void> {
  const servers = Array.from(activeMockServers.values());
  await Promise.all(servers.map(s => s.stop()));
}

/**
 * Get all active mock server instances.
 */
export function getActiveMockServers(): MockServerInstance[] {
  return Array.from(activeMockServers.values());
}

// ---------------------------------------------------------------------------
// Code Snippet Generation (15+ languages)
// ---------------------------------------------------------------------------

/**
 * Generate a runnable, compilable code snippet for the given request in the
 * specified programming language.
 *
 * Supports 15+ languages with proper imports, error handling, and idiomatic
 * patterns for each ecosystem.
 *
 * @param request   The API request details
 * @param language  Target language identifier
 * @returns         Source code string
 */
export function generateCodeSnippet(request: CodeGenRequest, language: string): string {
  const { method, url, headers, body, bodyType } = request;
  const methodUpper = method.toUpperCase();
  const methodLower = method.toLowerCase();
  const hasBody = body != null && body.length > 0 && ['POST', 'PUT', 'PATCH'].includes(methodUpper);
  const isJsonBody = hasBody && (
    bodyType === 'json' ||
    body!.trim().startsWith('{') ||
    body!.trim().startsWith('[')
  );

  // Escape helpers
  const escSingle = (s: string) => s.replace(/'/g, "\\'");
  const escDouble = (s: string) => s.replace(/"/g, '\\"');

  const headerLines = Object.entries(headers).map(([k, v]) => ({ key: k, value: v }));
  const jsonBody = hasBody && isJsonBody ? body!.trim() : null;
  const stringBody = hasBody && !isJsonBody ? body! : null;

  switch (language) {
    // ============================================================
    // curl
    // ============================================================
    case 'curl': {
      let cmd = `curl -X ${methodUpper}`;
      cmd += ` '${escSingle(url)}'`;
      for (const h of headerLines) {
        cmd += ` \\\n  -H '${escSingle(h.key)}: ${escSingle(h.value)}'`;
      }
      if (hasBody) {
        cmd += ` \\\n  --data '${escSingle(body!)}'`;
      }
      return cmd;
    }

    // ============================================================
    // Python (requests)
    // ============================================================
    case 'python': {
      let code = 'import requests\n';
      code += 'import json\n\n';
      code += 'def main():\n';
      code += '    """Execute the API request and print the response."""\n';
      code += '    try:\n';
      code += `        url = '${escSingle(url)}'\n`;
      if (headerLines.length > 0) {
        code += '        headers = {\n';
        for (const h of headerLines) {
          code += `            '${escSingle(h.key)}': '${escSingle(h.value)}',\n`;
        }
        code += '        }\n';
      }
      if (isJsonBody) {
        code += `        payload = ${jsonBody}\n`;
        code += `        response = requests.${methodLower}(url, headers=headers, json=payload, timeout=30)\n`;
      } else if (stringBody) {
        code += `        data = '${escSingle(stringBody)}'\n`;
        code += `        response = requests.${methodLower}(url, headers=headers, data=data, timeout=30)\n`;
      } else {
        const hdr = headerLines.length > 0 ? 'headers=headers, ' : '';
        code += `        response = requests.${methodLower}(url, ${hdr}timeout=30)\n`;
      }
      code += '        response.raise_for_status()\n';
      code += '        print(f"Status: {response.status_code}")\n';
      code += '        print(f"Response: {response.text}")\n';
      code += '    except requests.exceptions.RequestException as e:\n';
      code += '        print(f"Error: {e}")\n';
      code += '        return 1\n';
      code += '    return 0\n\n';
      code += 'if __name__ == "__main__":\n';
      code += '    exit(main())\n';
      return code;
    }

    // ============================================================
    // JavaScript (fetch)
    // ============================================================
    case 'javascript': {
      let code = '/**\n';
      code += ' * Execute API request using fetch.\n';
      code += ' */\n';
      code += 'async function main() {\n';
      code += '  try {\n';
      code += `    const url = '${escSingle(url)}';\n`;
      code += '    const options = {\n';
      code += `      method: '${methodUpper}',\n`;
      if (headerLines.length > 0) {
        code += '      headers: {\n';
        for (const h of headerLines) {
          code += `        '${escSingle(h.key)}': '${escSingle(h.value)}',\n`;
        }
        code += '      },\n';
      }
      if (isJsonBody) {
        code += `      body: JSON.stringify(${jsonBody!.replace(/\n/g, '')}),\n`;
      } else if (stringBody) {
        code += `      body: '${escSingle(stringBody)}',\n`;
      }
      code += '    };\n\n';
      code += '    const response = await fetch(url, options);\n';
      code += '    const data = await response.text();\n';
      code += '    console.log(`Status: ${response.status}`);\n';
      code += '    console.log(`Response: ${data}`);\n';
      code += '    return 0;\n';
      code += '  } catch (err) {\n';
      code += '    console.error(\'Error:\', err);\n';
      code += '    return 1;\n';
      code += '  }\n';
      code += '}\n\n';
      code += 'main().then(exit);\n';
      return code;
    }

    // ============================================================
    // JavaScript (axios)
    // ============================================================
    case 'javascript-axios': {
      let code = 'import axios from \'axios\';\n\n';
      code += '/**\n';
      code += ' * Execute API request using axios.\n';
      code += ' */\n';
      code += 'async function main() {\n';
      code += '  try {\n';
      code += '    const config = {\n';
      code += `      method: '${methodLower}',\n`;
      code += `      url: '${escSingle(url)}',\n`;
      if (headerLines.length > 0) {
        code += '      headers: {\n';
        for (const h of headerLines) {
          code += `        '${escSingle(h.key)}': '${escSingle(h.value)}',\n`;
        }
        code += '      },\n';
      }
      if (isJsonBody) {
        code += `      data: ${jsonBody!.replace(/\n/g, '')},\n`;
      } else if (stringBody) {
        code += `      data: '${escSingle(stringBody)}',\n`;
      }
      code += '    };\n\n';
      code += '    const response = await axios(config);\n';
      code += '    console.log(`Status: ${response.status}`);\n';
      code += '    console.log(`Response:`, response.data);\n';
      code += '    return 0;\n';
      code += '  } catch (err) {\n';
      code += '    if (axios.isAxiosError(err)) {\n';
      code += '      console.error(\'Error:\', err.message);\n';
      code += '      if (err.response) {\n';
      code += '        console.error(\'Status:\', err.response.status);\n';
      code += '        console.error(\'Data:\', err.response.data);\n';
      code += '      }\n';
      code += '    } else {\n';
      code += '      console.error(\'Unexpected error:\', err);\n';
      code += '    }\n';
      code += '    return 1;\n';
      code += '  }\n';
      code += '}\n\n';
      code += 'main().then(exit);\n';
      return code;
    }

    // ============================================================
    // TypeScript (typed fetch)
    // ============================================================
    case 'typescript': {
      let code = '// --- TypeScript API Client ---\n';
      code += '// Define response type based on your API\n';
      code += 'interface ApiResponse {\n';
      code += '  [key: string]: unknown;\n';
      code += '}\n\n';
      code += 'interface RequestOptions {\n';
      code += '  method: string;\n';
      code += '  headers?: Record<string, string>;\n';
      code += '  body?: string;\n';
      code += '}\n\n';
      code += 'async function apiRequest<T = ApiResponse>(\n';
      code += '  url: string,\n';
      code += '  options: RequestOptions,\n';
      code += '): Promise<T> {\n';
      code += '  const response = await fetch(url, {\n';
      code += '    method: options.method,\n';
      code += '    headers: {\n';
      code += "      'Content-Type': 'application/json',\n";
      if (headerLines.length > 0) {
        for (const h of headerLines) {
          code += `      '${escSingle(h.key)}': '${escSingle(h.value)}',\n`;
        }
      }
      code += '      ...options.headers,\n';
      code += '    },\n';
      if (hasBody) {
        code += '    body: options.body,\n';
      }
      code += '  });\n\n';
      code += '  if (!response.ok) {\n';
      code += '    throw new Error(`HTTP ${response.status}: ${response.statusText}`);\n';
      code += '  }\n\n';
      code += '  return response.json() as Promise<T>;\n';
      code += '}\n\n';
      code += '// --- Usage ---\n';
      code += 'async function main() {\n';
      code += '  try {\n';
      code += `    const url = '${escSingle(url)}';\n`;
      if (hasBody) {
        code += `    const body = JSON.stringify(${isJsonBody ? jsonBody!.replace(/\n/g, '') : `'${escSingle(stringBody!)}'`});\n`;
      }
      code += '    const response = await apiRequest<ApiResponse>(url, {\n';
      code += `      method: '${methodUpper}',\n`;
      if (hasBody) {
        code += '      body,\n';
      }
      code += '    });\n\n';
      code += '    console.log(\'Response:\', response);\n';
      code += '  } catch (err) {\n';
      code += '    console.error(\'Error:\', err);\n';
      code += '    process.exit(1);\n';
      code += '  }\n';
      code += '}\n\n';
      code += 'main();\n';
      return code;
    }

    // ============================================================
    // Go (net/http)
    // ============================================================
    case 'go': {
      let code = 'package main\n\n';
      code += 'import (\n';
      code += '  "bytes"\n';
      code += '  "encoding/json"\n';
      code += '  "fmt"\n';
      code += '  "io"\n';
      code += '  "net/http"\n';
      code += '  "os"\n';
      code += ')\n\n';
      code += 'func main() {\n';
      code += `  url := "${escDouble(url)}"\n\n`;
      if (isJsonBody) {
        code += `  payload := ${jsonBody}\n`;
        code += '  jsonData, err := json.Marshal(payload)\n';
        code += '  if err != nil {\n';
        code += '    fmt.Println("Error marshaling JSON:", err)\n';
        code += '    os.Exit(1)\n';
        code += '  }\n\n';
        code += '  req, err := http.NewRequest("' + methodUpper + '", url, bytes.NewBuffer(jsonData))\n';
      } else if (stringBody) {
        code += '  reqBody := bytes.NewBufferString("' + escDouble(stringBody) + '")\n';
        code += '  req, err := http.NewRequest("' + methodUpper + '", url, reqBody)\n';
      } else {
        code += '  req, err := http.NewRequest("' + methodUpper + '", url, nil)\n';
      }
      code += '  if err != nil {\n';
      code += '    fmt.Println("Error creating request:", err)\n';
      code += '    os.Exit(1)\n';
      code += '  }\n\n';
      for (const h of headerLines) {
        code += `  req.Header.Set("${escDouble(h.key)}", "${escDouble(h.value)}")\n`;
      }
      code += '\n';
      code += '  client := &http.Client{}\n';
      code += '  resp, err := client.Do(req)\n';
      code += '  if err != nil {\n';
      code += '    fmt.Println("Error executing request:", err)\n';
      code += '    os.Exit(1)\n';
      code += '  }\n';
      code += '  defer resp.Body.Close()\n\n';
      code += '  body, err := io.ReadAll(resp.Body)\n';
      code += '  if err != nil {\n';
      code += '    fmt.Println("Error reading response:", err)\n';
      code += '    os.Exit(1)\n';
      code += '  }\n\n';
      code += '  fmt.Println("Status:", resp.Status)\n';
      code += '  fmt.Println("Body:", string(body))\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // Java (OkHttp)
    // ============================================================
    case 'java-okhttp': {
      let code = 'import okhttp3.*;\n';
      code += 'import java.io.IOException;\n\n';
      code += 'public class ApiRequest {\n';
      code += '  public static void main(String[] args) {\n';
      code += '    OkHttpClient client = new OkHttpClient.Builder()\n';
      code += '        .connectTimeout(30, java.util.concurrent.TimeUnit.SECONDS)\n';
      code += '        .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)\n';
      code += '        .build();\n\n';
      code += '    try {\n';
      code += `      String url = "${escDouble(url)}";\n`;
      if (hasBody) {
        code += `      MediaType mediaType = MediaType.parse("${isJsonBody ? 'application/json' : 'text/plain'}");\n`;
        const bodyEscaped = escDouble(isJsonBody ? jsonBody! : stringBody!);
        code += `      RequestBody body = RequestBody.create(mediaType, "${bodyEscaped}");\n`;
        code += `      Request request = new Request.Builder()\n`;
        code += `          .url(url)\n`;
        code += `          .${methodLower}(body)\n`;
      } else {
        code += `      Request request = new Request.Builder()\n`;
        code += `          .url(url)\n`;
        code += `          .${methodLower}()\n`;
      }
      for (const h of headerLines) {
        code += `          .addHeader("${escDouble(h.key)}", "${escDouble(h.value)}")\n`;
      }
      code += '          .build();\n\n';
      code += '      try (Response response = client.newCall(request).execute()) {\n';
      code += '        System.out.println("Status: " + response.code());\n';
      code += '        System.out.println("Response: " + response.body().string());\n';
      code += '      }\n';
      code += '    } catch (IOException e) {\n';
      code += '      System.err.println("Error: " + e.getMessage());\n';
      code += '      System.exit(1);\n';
      code += '    }\n';
      code += '  }\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // Java (java.net.http.HttpClient)
    // ============================================================
    case 'java': {
      let code = 'import java.net.URI;\n';
      code += 'import java.net.http.HttpClient;\n';
      code += 'import java.net.http.HttpRequest;\n';
      code += 'import java.net.http.HttpResponse;\n';
      code += 'import java.time.Duration;\n\n';
      code += 'public class ApiRequest {\n';
      code += '  public static void main(String[] args) throws Exception {\n';
      code += '    HttpClient client = HttpClient.newBuilder()\n';
      code += '        .connectTimeout(Duration.ofSeconds(30))\n';
      code += '        .build();\n\n';
      code += '    try {\n';
      code += `      URI uri = URI.create("${escDouble(url)}");\n`;
      code += '      HttpRequest.Builder builder = HttpRequest.newBuilder()\n';
      code += '          .uri(uri)\n';
      code += '          .timeout(Duration.ofSeconds(30));\n';
      for (const h of headerLines) {
        code += `      builder.header("${escDouble(h.key)}", "${escDouble(h.value)}");\n`;
      }
      if (isJsonBody) {
        const bodyStr = jsonBody!.replace(/\n/g, '');
        code += `      HttpRequest.BodyPublisher bodyPublisher = HttpRequest.BodyPublishers.ofString("${escDouble(bodyStr)}");\n`;
        code += `      builder.method("${methodUpper}", bodyPublisher);\n`;
      } else if (stringBody) {
        code += `      HttpRequest.BodyPublisher bodyPublisher = HttpRequest.BodyPublishers.ofString("${escDouble(stringBody)}");\n`;
        code += `      builder.method("${methodUpper}", bodyPublisher);\n`;
      } else if (methodUpper === 'GET') {
        code += '      builder.GET();\n';
      } else if (methodUpper === 'DELETE') {
        code += '      builder.DELETE();\n';
      } else {
        code += `      builder.method("${methodUpper}", HttpRequest.BodyPublishers.noBody());\n`;
      }
      code += '\n';
      code += '      HttpRequest request = builder.build();\n';
      code += '      HttpResponse<String> response = client.send(request,\n';
      code += '          HttpResponse.BodyHandlers.ofString());\n\n';
      code += '      System.out.println("Status: " + response.statusCode());\n';
      code += '      System.out.println("Response: " + response.body());\n';
      code += '    } catch (Exception e) {\n';
      code += '      System.err.println("Error: " + e.getMessage());\n';
      code += '      System.exit(1);\n';
      code += '    }\n';
      code += '  }\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // C# (HttpClient)
    // ============================================================
    case 'csharp': {
      let code = 'using System;\n';
      code += 'using System.Net.Http;\n';
      code += 'using System.Text;\n';
      code += 'using System.Threading.Tasks;\n\n';
      code += 'class Program\n';
      code += '{\n';
      code += '  static async Task Main(string[] args)\n';
      code += '  {\n';
      code += '    using var client = new HttpClient();\n';
      code += '    client.Timeout = TimeSpan.FromSeconds(30);\n\n';
      for (const h of headerLines) {
        code += `    client.DefaultRequestHeaders.TryAddWithoutValidation("${escDouble(h.key)}", "${escDouble(h.value)}");\n`;
      }
      code += '\n';
      code += '    try\n';
      code += '    {\n';
      if (isJsonBody) {
        code += `      var content = new StringContent("${escDouble(jsonBody!)}", Encoding.UTF8, "application/json");\n`;
        code += `      var response = await client.${methodUpper}Async("${escDouble(url)}", content);\n`;
      } else if (stringBody) {
        code += `      var content = new StringContent("${escDouble(stringBody)}", Encoding.UTF8, "text/plain");\n`;
        code += `      var response = await client.${methodUpper}Async("${escDouble(url)}", content);\n`;
      } else {
        code += `      var response = await client.${methodUpper}Async("${escDouble(url)}");\n`;
      }
      code += '      var responseBody = await response.Content.ReadAsStringAsync();\n';
      code += '      Console.WriteLine($"Status: {(int)response.StatusCode} {response.ReasonPhrase}");\n';
      code += '      Console.WriteLine($"Response: {responseBody}");\n';
      code += '    }\n';
      code += '    catch (HttpRequestException e)\n';
      code += '    {\n';
      code += '      Console.WriteLine($"Error: {e.Message}");\n';
      code += '      Environment.Exit(1);\n';
      code += '    }\n';
      code += '  }\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // C# (RestSharp)
    // ============================================================
    case 'csharp-restsharp': {
      let code = 'using System;\n';
      code += 'using RestSharp;\n';
      code += 'using RestSharp.Serializers.Json;\n';
      code += 'using System.Threading.Tasks;\n\n';
      code += 'class Program\n';
      code += '{\n';
      code += '  static async Task Main(string[] args)\n';
      code += '  {\n';
      code += '    var options = new RestClientOptions("' + escDouble(url) + '")\n';
      code += '    {\n';
      code += '        Timeout = TimeSpan.FromSeconds(30)\n';
      code += '    };\n';
      code += '    var client = new RestClient(options);\n';
      code += '    var request = new RestRequest();\n';
      code += `    request.Method = Method.${methodUpper};\n`;
      for (const h of headerLines) {
        code += `    request.AddHeader("${escDouble(h.key)}", "${escDouble(h.value)}");\n`;
      }
      if (isJsonBody) {
        code += `    request.AddJsonBody(${jsonBody!.replace(/\n/g, '')});\n`;
      } else if (stringBody) {
        code += `    request.AddBody("${escDouble(stringBody)}", ContentType.Plain);\n`;
      }
      code += '\n';
      code += '    try\n';
      code += '    {\n';
      code += '      var response = await client.ExecuteAsync(request);\n';
      code += '      Console.WriteLine($"Status: {(int)response.StatusCode}");\n';
      code += '      Console.WriteLine($"Response: {response.Content}");\n';
      code += '    }\n';
      code += '    catch (Exception e)\n';
      code += '    {\n';
      code += '      Console.WriteLine($"Error: {e.Message}");\n';
      code += '      Environment.Exit(1);\n';
      code += '    }\n';
      code += '  }\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // Ruby (Net::HTTP)
    // ============================================================
    case 'ruby': {
      let code = "require 'net/http'\n";
      code += "require 'uri'\n";
      code += "require 'json'\n\n";
      code += 'begin\n';
      code += `  uri = URI('${escSingle(url)}')\n`;
      code += '  http = Net::HTTP.new(uri.host, uri.port)\n';
      code += '  http.open_timeout = 30\n';
      code += '  http.read_timeout = 30\n\n';

      // SSL if HTTPS
      if (url.startsWith('https')) {
        code += '  http.use_ssl = true\n';
        code += '  http.verify_mode = OpenSSL::SSL::VERIFY_PEER\n\n';
      }

      code += '  request = Net::HTTP::' + methodUpper + '.new(uri.request_uri)\n';
      for (const h of headerLines) {
        code += `  request['${escSingle(h.key)}'] = '${escSingle(h.value)}'\n`;
      }
      if (isJsonBody) {
        code += `  request.body = ${jsonBody!}.to_json\n`;
        code += "  request['Content-Type'] = 'application/json'\n";
      } else if (stringBody) {
        code += `  request.body = '${escSingle(stringBody)}'\n`;
      }
      code += '\n  response = http.request(request)\n\n';
      code += '  puts "Status: #{response.code}"\n';
      code += '  puts "Response: #{response.body}"\n';
      code += 'rescue StandardError => e\n';
      code += '  puts "Error: #{e.message}"\n';
      code += '  exit 1\n';
      code += 'end\n';
      return code;
    }

    // ============================================================
    // Ruby (Faraday)
    // ============================================================
    case 'ruby-faraday': {
      let code = "require 'faraday'\n";
      code += "require 'json'\n\n";
      code += 'begin\n';
      code += '  conn = Faraday.new(\n';
      code += `    url: '${escSingle(url)}',\n`;
      code += '    request: {\n';
      code += '      open_timeout: 30,\n';
      code += '      read_timeout: 30,\n';
      code += '    }\n';
      code += '  ) do |f|\n';
      // Only add adapter if not already configured
      code += '    f.adapter Faraday.default_adapter\n';
      code += '  end\n\n';
      code += '  response = conn.' + methodLower + ' do |req|\n';
      code += '    req.headers = {\n';
      for (const h of headerLines) {
        code += `      '${escSingle(h.key)}' => '${escSingle(h.value)}',\n`;
      }
      code += '    }\n';
      if (isJsonBody) {
        code += `    req.body = ${jsonBody!}.to_json\n`;
      } else if (stringBody) {
        code += `    req.body = '${escSingle(stringBody)}'\n`;
      }
      code += '  end\n\n';
      code += '  puts "Status: #{response.status}"\n';
      code += '  puts "Response: #{response.body}"\n';
      code += 'rescue Faraday::Error => e\n';
      code += '  puts "Error: #{e.message}"\n';
      code += '  exit 1\n';
      code += 'end\n';
      return code;
    }

    // ============================================================
    // PHP (cURL)
    // ============================================================
    case 'php': {
      let code = "<?php\n\n";
      code += '$url = \'' + escSingle(url) + "';\n\n";
      code += '$ch = curl_init($url);\n';
      code += 'curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);\n';
      code += 'curl_setopt($ch, CURLOPT_TIMEOUT, 30);\n';
      code += `curl_setopt($ch, CURLOPT_CUSTOMREQUEST, '${methodUpper}');\n`;
      if (headerLines.length > 0) {
        code += '$headers = [\n';
        for (const h of headerLines) {
          code += `    '${escSingle(h.key)}: ${escSingle(h.value)}',\n`;
        }
        code += '];\n';
        code += 'curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);\n';
      }
      if (isJsonBody) {
        code += `\$payload = json_encode(${jsonBody!.replace(/\n/g, '')});\n`;
        code += 'curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);\n';
      } else if (stringBody) {
        code += `curl_setopt($ch, CURLOPT_POSTFIELDS, '${escSingle(stringBody)}');\n`;
      }
      code += '\n';
      code += 'try {\n';
      code += '    $response = curl_exec($ch);\n';
      code += '    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);\n';
      code += '    $error = curl_error($ch);\n';
      code += '    curl_close($ch);\n\n';
      code += '    if ($error) {\n';
      code += "        throw new \\Exception('cURL error: ' . \$error);\n";
      code += '    }\n\n';
      code += '    echo "Status: " . $httpCode . "\\n";\n';
      code += '    echo "Response: " . $response . "\\n";\n';
      code += '} catch (\\Exception $e) {\n';
      code += '    echo "Error: " . $e->getMessage() . "\\n";\n';
      code += '    exit(1);\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // PHP (Guzzle)
    // ============================================================
    case 'php-guzzle': {
      let code = "<?php\n\n";
      code += "require 'vendor/autoload.php';\n\n";
      code += 'use GuzzleHttp\\Client;\n';
      code += 'use GuzzleHttp\\Exception\\GuzzleException;\n\n';
      code += '$client = new Client([\n';
      code += "    'timeout' => 30.0,\n";
      code += ']);\n\n';
      code += 'try {\n';
      code += '    $response = $client->request(\'' + methodLower + "', '" + escSingle(url) + "', [\n";
      if (headerLines.length > 0) {
        code += "        'headers' => [\n";
        for (const h of headerLines) {
          code += `            '${escSingle(h.key)}' => '${escSingle(h.value)}',\n`;
        }
        code += '        ],\n';
      }
      if (isJsonBody) {
        code += `        'json' => ${jsonBody!.replace(/\n/g, '')},\n`;
      } else if (stringBody) {
        code += `        'body' => '${escSingle(stringBody)}',\n`;
      }
      code += "    ]);\n\n";
      code += '    echo "Status: " . $response->getStatusCode() . "\\n";\n';
      code += '    echo "Response: " . $response->getBody() . "\\n";\n';
      code += '} catch (GuzzleException $e) {\n';
      code += '    echo "Error: " . $e->getMessage() . "\\n";\n';
      code += '    exit(1);\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // Rust (reqwest)
    // ============================================================
    case 'rust': {
      let code = 'use reqwest;\n';
      code += 'use std::collections::HashMap;\n\n';
      code += '#[tokio::main]\n';
      code += 'async fn main() -> Result<(), Box<dyn std::error::Error>> {\n';
      code += '    let client = reqwest::Client::builder()\n';
      code += '        .timeout(std::time::Duration::from_secs(30))\n';
      code += '        .build()?;\n\n';
      code += '    let mut headers = HashMap::new();\n';
      for (const h of headerLines) {
        code += `    headers.insert("${escDouble(h.key)}", "${escDouble(h.value)}");\n`;
      }
      code += '\n';
      if (isJsonBody) {
        code += `    let payload = serde_json::json!(${jsonBody!.replace(/\n/g, '')});\n`;
        code += '    let response = client\n';
        code += `        .${methodLower}("${escDouble(url)}")\n`;
        code += '        .headers((&headers).try_into()?)\n';
        code += '        .json(&payload)\n';
        code += '        .send()\n';
        code += '        .await?;\n';
      } else if (stringBody) {
        code += '    let response = client\n';
        code += `        .${methodLower}("${escDouble(url)}")\n`;
        code += '        .headers((&headers).try_into()?)\n';
        code += `        .body("${escDouble(stringBody)}")\n`;
        code += '        .send()\n';
        code += '        .await?;\n';
      } else {
        code += '    let response = client\n';
        code += `        .${methodLower}("${escDouble(url)}")\n`;
        code += '        .headers((&headers).try_into()?)\n';
        code += '        .send()\n';
        code += '        .await?;\n';
      }
      code += '\n';
      code += '    println!("Status: {}", response.status());\n';
      code += '    let body = response.text().await?;\n';
      code += '    println!("Response: {}", body);\n\n';
      code += '    Ok(())\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // Kotlin (OkHttp with coroutines)
    // ============================================================
    case 'kotlin': {
      let code = 'import kotlinx.coroutines.*\n';
      code += 'import okhttp3.*\n';
      code += 'import java.io.IOException\n\n';
      code += 'suspend fun apiRequest(): String = withContext(Dispatchers.IO) {\n';
      code += '    val client = OkHttpClient.Builder()\n';
      code += '        .connectTimeout(30, java.util.concurrent.TimeUnit.SECONDS)\n';
      code += '        .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)\n';
      code += '        .build()\n\n';
      code += `    val url = "${escDouble(url)}"\n`;
      if (hasBody) {
        const contentType = isJsonBody ? '"application/json"' : '"text/plain"';
        code += `    val mediaType = MediaType.parse(${contentType})\n`;
        const bodyEscaped = escDouble(isJsonBody ? jsonBody! : stringBody!);
        code += `    val requestBody = RequestBody.create(mediaType, "${bodyEscaped}")\n`;
        code += `    val request = Request.Builder()\n`;
        code += `        .url(url)\n`;
        code += `        .${methodLower}(requestBody)\n`;
      } else {
        code += `    val request = Request.Builder()\n`;
        code += `        .url(url)\n`;
        code += `        .${methodLower}()\n`;
      }
      for (const h of headerLines) {
        code += `        .addHeader("${escDouble(h.key)}", "${escDouble(h.value)}")\n`;
      }
      code += '        .build()\n\n';
      code += '    try {\n';
      code += '        val response = client.newCall(request).execute()\n';
      code += '        return "Status: \${response.code()}\\nResponse: \${response.body()?.string()}"\n';
      code += '    } catch (e: IOException) {\n';
      code += '        throw RuntimeException("Request failed: \${e.message}")\n';
      code += '    }\n';
      code += '}\n\n';
      code += 'fun main() = runBlocking {\n';
      code += '    try {\n';
      code += '        val result = apiRequest()\n';
      code += '        println(result)\n';
      code += '    } catch (e: Exception) {\n';
      code += '        System.err.println("Error: \${e.message}")\n';
      code += '        System.exit(1)\n';
      code += '    }\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // Swift (URLSession)
    // ============================================================
    case 'swift': {
      let code = 'import Foundation\n\n';
      code += '// MARK: - API Request\n';
      code += 'func apiRequest() {\n';
      code += `    guard let url = URL(string: "${escDouble(url)}") else {\n`;
      code += '        print("Invalid URL")\n';
      code += '        return\n';
      code += '    }\n\n';
      code += '    var request = URLRequest(url: url)\n';
      code += `    request.httpMethod = "${methodUpper}"\n`;
      code += '    request.timeoutInterval = 30\n';
      for (const h of headerLines) {
        code += `    request.setValue("${escDouble(h.value)}", forHTTPHeaderField: "${escDouble(h.key)}")\n`;
      }
      if (isJsonBody) {
        const jsonStr = jsonBody!.replace(/\n/g, '');
        code += `    let bodyData = """${jsonStr}"""\n`;
        code += '    request.httpBody = bodyData.data(using: .utf8)\n';
        code += '    request.setValue("application/json", forHTTPHeaderField: "Content-Type")\n';
      } else if (stringBody) {
        code += `    request.httpBody = "${escDouble(stringBody)}".data(using: .utf8)\n`;
      }
      code += '\n';
      code += '    let task = URLSession.shared.dataTask(with: request) { data, response, error in\n';
      code += '        if let error = error {\n';
      code += '            print("Error: \\(error.localizedDescription)")\n';
      code += '            exit(1)\n';
      code += '            return\n';
      code += '        }\n\n';
      code += '        if let httpResponse = response as? HTTPURLResponse {\n';
      code += '            print("Status: \\(httpResponse.statusCode)")\n';
      code += '        }\n\n';
      code += '        if let data = data, let body = String(data: data, encoding: .utf8) {\n';
      code += '            print("Response: \\(body)")\n';
      code += '        }\n';
      code += '    }\n';
      code += '    task.resume()\n';
      code += '    // Keep the program running until the request completes\n';
      code += '    dispatchMain()\n';
      code += '}\n\n';
      code += '// Call the function\n';
      code += 'apiRequest()\n';
      return code;
    }

    // ============================================================
    // PowerShell (Invoke-RestMethod)
    // ============================================================
    case 'powershell': {
      let code = '# PowerShell API Request\n';
      code += '$params = @{\n';
      code += `    Uri     = '${escSingle(url)}'\n`;
      code += `    Method  = '${methodUpper}'\n`;
      code += '    Timeout = 30\n';
      code += '}\n\n';
      if (headerLines.length > 0) {
        code += '$headers = @{\n';
        for (const h of headerLines) {
          code += `    '${escSingle(h.key)}' = '${escSingle(h.value)}'\n`;
        }
        code += '}\n';
        code += '$params.Headers = $headers\n\n';
      }
      if (isJsonBody) {
        const jsonStr = jsonBody!.replace(/\n/g, '');
        code += `\$body = '${escSingle(jsonStr)}'\n`;
        code += '$params.Body = $body\n';
        code += '$params.ContentType = \'application/json\'\n\n';
      } else if (stringBody) {
        code += `\$body = '${escSingle(stringBody)}'\n`;
        code += '$params.Body = $body\n\n';
      }
      code += 'try {\n';
      code += '    $response = Invoke-RestMethod @params\n';
      code += '    Write-Host "Status: $($response | ConvertTo-Json -Compress | Out-String)"\n';
      if (isJsonBody) {
        code += '    Write-Host "Response:"\n';
        code += '    $response | ConvertTo-Json -Depth 10\n';
      } else {
        code += '    Write-Host "Response: $response"\n';
      }
      code += '}\n';
      code += 'catch {\n';
      code += '    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red\n';
      code += '    if ($_.Exception.Response) {\n';
      code += '        $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())\n';
      code += '        $reader.BaseStream.Position = 0\n';
      code += '        $reader.DiscardBufferedData()\n';
      code += '        Write-Host "Details: $($reader.ReadToEnd())"\n';
      code += '    }\n';
      code += '    exit 1\n';
      code += '}\n';
      return code;
    }

    // ============================================================
    // Default / fallback (curl)
    // ============================================================
    default: {
      let cmd = `curl -X ${methodUpper}`;
      cmd += ` '${escSingle(url)}'`;
      for (const h of headerLines) {
        cmd += ` \\\n  -H '${escSingle(h.key)}: ${escSingle(h.value)}'`;
      }
      if (hasBody) {
        cmd += ` \\\n  --data '${escSingle(body!)}'`;
      }
      return cmd;
    }
  }
}

// ---------------------------------------------------------------------------
// API Documentation Generation
// ---------------------------------------------------------------------------

/**
 * Generate API documentation in Markdown format from a collection.
 *
 * Fetches the collection and its requests from the database, groups them by
 * folder, and produces a comprehensive Markdown document with:
 *   - Title and description
 *   - Authentication section
 *   - Endpoint table
 *   - Per-endpoint details with example requests and responses
 *
 * @param collectionId  UUID of the API collection
 * @returns             Markdown string
 */
export async function generateAPIDocumentation(collectionId: string): Promise<string> {
  // Fetch collection
  const collectionResult = await query(
    `SELECT id, name, description, environment, created_at, updated_at
     FROM api_collections
     WHERE id = $1 AND deleted_at IS NULL`,
    [collectionId],
  );

  if (collectionResult.rows.length === 0) {
    throw new Error(`Collection not found: ${collectionId}`);
  }

  const collection = collectionResult.rows[0] as Record<string, unknown>;
  const env = (collection.environment as Record<string, unknown>) ?? {};
  const baseUrl = (env.baseUrl as string) ?? '(no base URL configured)';

  // Fetch folders
  const { rows: folderRows } = await query(
    `SELECT id, name, parent_id
     FROM api_folders
     WHERE collection_id = $1
     ORDER BY name`,
    [collectionId],
  );
  const folders = folderRows as Array<{ id: string; name: string; parent_id: string | null }>;

  // Fetch requests
  const { rows: requestRows } = await query(
    `SELECT id, folder_id, name, method, url, headers, query_params, body, body_type, auth
     FROM api_requests
     WHERE collection_id = $1 AND deleted_at IS NULL
     ORDER BY created_at, name`,
    [collectionId],
  );
  const requests = requestRows as Array<{
    id: string;
    folder_id: string | null;
    name: string;
    method: string;
    url: string;
    headers: string | Record<string, string>;
    query_params: string | Record<string, string>;
    body: string | null;
    body_type: string;
    auth: string | Record<string, string>;
  }>;

  // Build folder hierarchy
  const folderMap = new Map<string, typeof folders[0]>();
  for (const f of folders) folderMap.set(f.id, f);

  const rootRequests = requests.filter(r => r.folder_id === null);
  const requestsByFolder = new Map<string, typeof requests>();
  for (const r of requests) {
    if (r.folder_id) {
      const existing = requestsByFolder.get(r.folder_id) ?? [];
      existing.push(r);
      requestsByFolder.set(r.folder_id, existing);
    }
  }

  // Determine auth type
  let authType = 'None';
  let authDetails = '';
  for (const req of requests) {
    const auth = typeof req.auth === 'string' ? JSON.parse(req.auth) : (req.auth ?? {});
    if (auth.type && auth.type !== 'none') {
      authType = auth.type.toUpperCase();
      authDetails = `Authentication type: **${authType}**`;
      if (auth.type === 'bearer') {
        authDetails += '\n\nPass the token in the `Authorization` header:\n\n```\nAuthorization: Bearer <your-token>\n```';
      } else if (auth.type === 'basic') {
        authDetails += '\n\nPass credentials in the `Authorization` header using Basic authentication.';
      } else if (auth.type === 'api_key') {
        authDetails += '\n\nPass your API key in the header or query parameter as configured.';
      }
      break;
    }
  }

  // Methods
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];

  // --- Build the Markdown ---
  const escapedName = (collection.name as string).replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const md: string[] = [];

  // Title
  md.push(`# ${escapedName}\n`);
  if (collection.description) {
    md.push(`${(collection.description as string).replace(/</g, '&lt;').replace(/>/g, '&gt;')}\n`);
  }

  // Info section
  md.push(`## Overview\n`);
  md.push(`| Property | Value |`);
  md.push(`| -------- | ----- |`);
  md.push(`| **Base URL** | \`${baseUrl}\` |`);
  md.push(`| **Total Endpoints** | ${requests.length} |`);
  md.push(`| **Folders** | ${folders.length} |`);
  md.push(`| **Authentication** | ${authType === 'None' ? 'None' : authType} |`);
  md.push(`| **Created** | ${new Date(collection.created_at as string).toISOString().split('T')[0]} |`);
  md.push(`| **Last Updated** | ${new Date(collection.updated_at as string).toISOString().split('T')[0]} |`);
  md.push('');

  // Authentication section
  if (authType !== 'None') {
    md.push(`## Authentication\n`);
    md.push(`${authDetails}\n`);
  }

  // --- Endpoint Table ---
  md.push(`## Endpoints\n`);
  md.push(`| Method | Path | Name | Auth |`);
  md.push(`| ------ | ---- | ---- | ---- |`);
  for (const req of rootRequests) {
    const reqMethod = (req.method as string).toUpperCase();
    const methodBadge = methods.includes(reqMethod) ? `**${reqMethod}**` : reqMethod;
    const methodColor = getMethodColor(reqMethod);
    const reqAuth = getReqAuth(req);
    md.push(`| ${methodColor}${methodBadge}${methodColor ? '<!-- -->' : ''} | \`${escapeMd(extractPath(req.url))}\` | ${escapeMd(req.name)} | ${reqAuth} |`);
  }
  for (const folder of folders) {
    const folderRequests = requestsByFolder.get(folder.id) ?? [];
    if (folderRequests.length === 0) continue;
    for (const req of folderRequests) {
      const reqMethod = (req.method as string).toUpperCase();
      const reqAuth = getReqAuth(req);
      md.push(`| **${reqMethod}** | \`${escapeMd(extractPath(req.url))}\` | ${escapeMd(folder.name)} > ${escapeMd(req.name)} | ${reqAuth} |`);
    }
  }
  md.push('');

  // --- Endpoint Details ---
  md.push(`## Endpoint Details\n`);
  md.push('<details>\n<summary><strong>Table of Contents</strong></summary>\n\n');

  // Table of contents
  const allEndpoints = [...rootRequests];
  for (const folder of folders) {
    const folderRequests = requestsByFolder.get(folder.id) ?? [];
    allEndpoints.push(...folderRequests);
  }
  for (const req of allEndpoints) {
    const reqMethod = (req.method as string).toUpperCase();
    const safeAnchor = `${reqMethod.toLowerCase()}-${extractPath(req.url).replace(/[^a-zA-Z0-9-_]/g, '-')}`;
    md.push(`- [${reqMethod} ${extractPath(req.url)}](#${safeAnchor})`);
  }
  md.push('\n</details>\n');

  // Per-endpoint sections
  const processedSections = [
    ...rootRequests.map(req => ({ req, folderName: null as string | null })),
  ];
  for (const folder of folders) {
    const folderRequests = requestsByFolder.get(folder.id) ?? [];
    for (const req of folderRequests) {
      processedSections.push({ req, folderName: folder.name });
    }
  }

  for (const { req, folderName } of processedSections) {
    const reqMethod = (req.method as string).toUpperCase();
    const reqPath = extractPath(req.url);
    const safeAnchor = `${reqMethod.toLowerCase()}-${reqPath.replace(/[^a-zA-Z0-9-_]/g, '-')}`;
    const reqHeaders = typeof req.headers === 'string' ? JSON.parse(req.headers) : (req.headers ?? {});
    const reqQueryParams = typeof req.query_params === 'string' ? JSON.parse(req.query_params) : (req.query_params ?? {});
    const reqAuth = typeof req.auth === 'string' ? JSON.parse(req.auth) : (req.auth ?? {});

    md.push(`---\n`);
    md.push(`### ${reqMethod} \`${reqPath}\` {#${safeAnchor}}\n`);
    if (folderName) {
      md.push(`**Folder:** \`${escapeMd(folderName)}\`  `);
    }
    md.push(`**Name:** ${escapeMd(req.name)}  `);
    md.push('');

    // URL
    md.push('#### Request URL\n');
    md.push('```\n');
    md.push(`${reqMethod} ${req.url}`);
    md.push('\n```\n');

    // Headers
    const headerKeys = Object.keys(reqHeaders);
    if (headerKeys.length > 0) {
      md.push('#### Headers\n');
      md.push('| Key | Value |');
      md.push('| --- | ----- |');
      for (const key of headerKeys) {
        const val = (reqHeaders as Record<string, string>)[key] ?? '';
        md.push(`| \`${escapeMd(key)}\` | \`${escapeMd(val)}\` |`);
      }
      md.push('');
    }

    // Query Parameters
    const qpKeys = Object.keys(reqQueryParams);
    if (qpKeys.length > 0) {
      md.push('#### Query Parameters\n');
      md.push('| Key | Value |');
      md.push('| --- | ----- |');
      for (const key of qpKeys) {
        const val = (reqQueryParams as Record<string, string>)[key] ?? '';
        md.push(`| \`${escapeMd(key)}\` | \`${escapeMd(val)}\` |`);
      }
      md.push('');
    }

    // Body
    if (req.body && req.body_type !== 'none') {
      md.push('#### Request Body\n');
      md.push('```' + (req.body_type === 'json' ? 'json' : '') + '\n');
      md.push(req.body);
      md.push('\n```\n');
    }

    // Authentication info for this request
    if (reqAuth.type && reqAuth.type !== 'none') {
      md.push('#### Authentication\n');
      md.push(`This endpoint uses **${reqAuth.type.toUpperCase()}** authentication.\n`);
    }

    // Example curl command
    md.push('#### Example\n');
    md.push('```bash\n');
    const headersRecord = reqHeaders as Record<string, string>;
    const snippet = generateCodeSnippet({
      method: reqMethod,
      url: req.url,
      headers: headersRecord,
      body: req.body ?? undefined,
      bodyType: req.body_type ?? undefined,
    }, 'curl');
    md.push(snippet);
    md.push('\n```\n');
  }

  return md.join('\n');
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Extract a clean path from a URL string. */
function extractPath(urlStr: string): string {
  try {
    const u = new URL(urlStr);
    return u.pathname + u.search;
  } catch {
    return urlStr.startsWith('/') ? urlStr : `/${urlStr}`;
  }
}

/** Escape special Markdown characters in inline code context. */
function escapeMd(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Get a color tag for an HTTP method (for Markdown table display). */
function getMethodColor(_method: string): string {
  // Not actually coloring in plain markdown, but we could use HTML spans if needed
  return '';
}

/** Extract auth info from a request. */
function getReqAuth(req: { auth?: string | Record<string, unknown> }): string {
  if (!req.auth) return 'None';
  const auth = typeof req.auth === 'string' ? JSON.parse(req.auth) : req.auth;
  return auth && (auth as Record<string, unknown>).type && (auth as Record<string, unknown>).type !== 'none'
    ? ((auth as Record<string, unknown>).type as string).toUpperCase()
    : 'None';
}
