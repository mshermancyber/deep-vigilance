import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import https from 'https';
import http from 'http';
import dns from 'dns';
import net from 'net';
import { query } from '../../core/db/pool.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { validateBody, validateQuery } from '../../middleware/validate.js';
import { AppError } from '../../core/errors/handler.js';
import { logger } from '../../core/logging/logger.js';

function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
  }
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    if (normalized === '::1' || normalized === '::' || normalized.startsWith('fc') ||
        normalized.startsWith('fd') || normalized.startsWith('fe80') ||
        normalized.startsWith('ff')) return true;
    if (normalized.startsWith('::ffff:')) {
      return isPrivateIP(normalized.slice(7));
    }
  }
  return false;
}

async function validateTargetUrl(urlStr: string): Promise<void> {
  const parsed = new URL(urlStr);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw AppError.badRequest('Only HTTP and HTTPS protocols are allowed');
  }
  const hostname = parsed.hostname;
  if (net.isIP(hostname)) {
    if (isPrivateIP(hostname)) {
      throw AppError.badRequest('Requests to private/internal IP addresses are not allowed');
    }
  } else {
    const addresses = await dns.promises.resolve4(hostname).catch(() => []);
    const addresses6 = await dns.promises.resolve6(hostname).catch(() => []);
    const allAddresses = [...addresses, ...addresses6];
    if (allAddresses.length === 0) {
      throw AppError.badRequest('Could not resolve hostname');
    }
    for (const addr of allAddresses) {
      if (isPrivateIP(addr)) {
        throw AppError.badRequest('Requests to private/internal IP addresses are not allowed');
      }
    }
  }
}

interface ParsedEndpoint {
  name: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  queryParams?: Record<string, string>;
  body?: string;
  bodyType?: string;
  auth?: Record<string, unknown>;
}

function parseImportData(format: string, data: string): ParsedEndpoint[] {
  try {
    if (format === 'openapi' || format === 'swagger') return parseOpenAPI(data);
    if (format === 'postman') return parsePostman(data);
    if (format === 'curl') return parseCurl(data);
    if (format === 'graphql') return parseGraphQL(data);
  } catch (e) {
    logger.warn({ format, err: e }, 'Failed to parse import data, collection created without requests');
  }
  return [];
}

function parseOpenAPI(data: string): ParsedEndpoint[] {
  const spec = JSON.parse(data);
  const endpoints: ParsedEndpoint[] = [];
  const baseUrl = spec.servers?.[0]?.url || '';
  const paths = spec.paths || {};

  for (const [path, methods] of Object.entries(paths)) {
    const methodsObj = methods as Record<string, unknown>;
    for (const method of ['get', 'post', 'put', 'patch', 'delete', 'options', 'head']) {
      const op = methodsObj[method] as Record<string, unknown> | undefined;
      if (!op) continue;
      const name = (op.summary as string) || (op.operationId as string) || `${method.toUpperCase()} ${path}`;
      const url = `${baseUrl}${path}`;

      const headers: Record<string, string> = { 'Accept': 'application/json' };
      if (['post', 'put', 'patch'].includes(method)) headers['Content-Type'] = 'application/json';

      let body: string | undefined;
      let bodyType = 'none';
      const requestBody = op.requestBody as Record<string, unknown> | undefined;
      if (requestBody) {
        const content = requestBody.content as Record<string, unknown> | undefined;
        if (content) {
          const jsonContent = content['application/json'] as Record<string, unknown> | undefined;
          if (jsonContent?.schema) {
            body = JSON.stringify(generateExampleFromSchema(jsonContent.schema as Record<string, unknown>));
            bodyType = 'json';
          }
        }
      }

      const queryParams: Record<string, string> = {};
      const parameters = (op.parameters || []) as Array<Record<string, unknown>>;
      for (const p of parameters) {
        if (p.in === 'query') queryParams[p.name as string] = (p.example as string) || '';
        if (p.in === 'header') headers[p.name as string] = (p.example as string) || '';
      }

      endpoints.push({ name, method: method.toUpperCase(), url, headers, queryParams, body, bodyType });
    }
  }
  return endpoints;
}

function generateExampleFromSchema(schema: Record<string, unknown>): unknown {
  if (!schema) return {};
  if (schema.example !== undefined) return schema.example;
  const type = schema.type as string;
  if (type === 'string') return schema.enum ? (schema.enum as string[])[0] : 'string';
  if (type === 'number' || type === 'integer') return 0;
  if (type === 'boolean') return false;
  if (type === 'array') {
    const items = schema.items as Record<string, unknown> | undefined;
    return items ? [generateExampleFromSchema(items)] : [];
  }
  if (type === 'object' || schema.properties) {
    const result: Record<string, unknown> = {};
    const props = (schema.properties || {}) as Record<string, Record<string, unknown>>;
    for (const [key, propSchema] of Object.entries(props)) {
      result[key] = generateExampleFromSchema(propSchema);
    }
    return result;
  }
  return {};
}

function parsePostman(data: string): ParsedEndpoint[] {
  const collection = JSON.parse(data);
  const endpoints: ParsedEndpoint[] = [];

  function extractItems(items: Array<Record<string, unknown>>) {
    for (const item of items) {
      if (item.item) { extractItems(item.item as Array<Record<string, unknown>>); continue; }
      const req = item.request as Record<string, unknown> | undefined;
      if (!req) continue;

      const method = (req.method as string || 'GET').toUpperCase();
      let url = '';
      if (typeof req.url === 'string') { url = req.url; }
      else if (req.url && typeof req.url === 'object') {
        const urlObj = req.url as Record<string, unknown>;
        url = (urlObj.raw as string) || '';
      }

      const headers: Record<string, string> = {};
      const headerArr = (req.header || []) as Array<Record<string, string>>;
      for (const h of headerArr) { if (h.key && h.value) headers[h.key] = h.value; }

      let body: string | undefined;
      let bodyType = 'none';
      const bodyObj = req.body as Record<string, unknown> | undefined;
      if (bodyObj) {
        const mode = bodyObj.mode as string;
        if (mode === 'raw') { body = bodyObj.raw as string; bodyType = 'json'; }
        else if (mode === 'urlencoded') { bodyType = 'form-urlencoded'; }
        else if (mode === 'formdata') { bodyType = 'form-data'; }
      }

      endpoints.push({ name: (item.name as string) || `${method} ${url}`, method, url, headers, body, bodyType });
    }
  }

  const items = collection.item || collection.items || [];
  extractItems(items);
  return endpoints;
}

function parseCurl(data: string): ParsedEndpoint[] {
  const endpoints: ParsedEndpoint[] = [];
  const commands = data.split(/\n(?=curl\s)/);

  for (const cmd of commands) {
    const trimmed = cmd.trim();
    if (!trimmed.startsWith('curl')) continue;

    let method = 'GET';
    const methodMatch = trimmed.match(/-X\s+['"]?(\w+)['"]?/);
    if (methodMatch) method = methodMatch[1]!.toUpperCase();

    const urlMatch = trimmed.match(/(?:curl\s+|['"])?(https?:\/\/[^\s'"]+)/);
    if (!urlMatch) continue;
    const url = urlMatch[1]!;

    const headers: Record<string, string> = {};
    const headerMatches = trimmed.matchAll(/-H\s+['"]([^'"]+)['"]/g);
    for (const m of headerMatches) {
      const [key, ...valParts] = m[1]!.split(':');
      if (key) headers[key.trim()] = valParts.join(':').trim();
    }

    let body: string | undefined;
    let bodyType = 'none';
    const dataMatch = trimmed.match(/(?:-d|--data(?:-raw)?)\s+['"]({[\s\S]*?})['"]/);
    if (dataMatch) { body = dataMatch[1]; bodyType = 'json'; }
    if (!dataMatch) {
      const dataMatch2 = trimmed.match(/(?:-d|--data(?:-raw)?)\s+'([^']+)'/);
      if (dataMatch2) { body = dataMatch2[1]; bodyType = 'raw'; }
    }

    if (body && method === 'GET') method = 'POST';

    const name = `${method} ${new URL(url).pathname}`;
    endpoints.push({ name, method, url, headers, body, bodyType });
  }
  return endpoints;
}

function parseGraphQL(data: string): ParsedEndpoint[] {
  const spec = JSON.parse(data);
  const endpoint = spec.endpoint || spec.url || '';
  const queries = spec.queries || spec.operations || [];
  const endpoints: ParsedEndpoint[] = [];

  if (Array.isArray(queries)) {
    for (const q of queries) {
      const name = (q as Record<string, string>).name || 'GraphQL Query';
      const queryStr = (q as Record<string, string>).query || '';
      endpoints.push({
        name, method: 'POST', url: endpoint,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: queryStr, variables: (q as Record<string, unknown>).variables || {} }),
        bodyType: 'graphql',
      });
    }
  } else if (typeof spec.query === 'string') {
    endpoints.push({
      name: 'GraphQL Query', method: 'POST', url: endpoint,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: spec.query, variables: spec.variables || {} }),
      bodyType: 'graphql',
    });
  }
  return endpoints;
}

export const apiClientRouter = Router();

apiClientRouter.get('/collections',
  requirePermission(Permission.API_CLIENT_USE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT c.*, (SELECT COUNT(*) FROM api_requests r WHERE r.collection_id = c.id) as request_count
         FROM api_collections c
         WHERE c.org_id = $1 AND c.deleted_at IS NULL
         ORDER BY c.updated_at DESC`,
        [req.orgId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

apiClientRouter.post('/collections',
  requirePermission(Permission.API_CLIENT_MANAGE),
  validateBody(z.object({
    name: z.string().min(1).max(200),
    description: z.string().max(1000).optional(),
    projectId: z.string().uuid().optional(),
    folders: z.array(z.object({
      name: z.string().min(1).max(200),
      parentId: z.string().uuid().optional(),
    })).optional(),
    environment: z.object({
      variables: z.record(z.string()).optional(),
      baseUrl: z.string().url().optional(),
    }).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const collectionId = uuidv4();
      const { name, description, projectId, folders, environment } = req.body;

      await query(
        `INSERT INTO api_collections (id, org_id, project_id, name, description, environment, created_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW(),NOW())`,
        [collectionId, req.orgId, projectId, name, description, JSON.stringify(environment || {}), req.userId],
      );

      if (folders?.length) {
        for (const folder of folders) {
          await query(
            `INSERT INTO api_folders (id, collection_id, name, parent_id, created_at, updated_at)
             VALUES ($1,$2,$3,$4,NOW(),NOW())`,
            [uuidv4(), collectionId, folder.name, folder.parentId],
          );
        }
      }

      logger.info({ collectionId, name }, 'API collection created');
      res.status(201).json({ id: collectionId, name });
    } catch (err) { next(err); }
  },
);

apiClientRouter.get('/collections/:id',
  requirePermission(Permission.API_CLIENT_USE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const collectionResult = await query(
        'SELECT * FROM api_collections WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL',
        [req.params.id, req.orgId],
      );
      if (collectionResult.rows.length === 0) throw AppError.notFound('Collection not found');

      const foldersResult = await query(
        'SELECT * FROM api_folders WHERE collection_id = $1 ORDER BY name',
        [req.params.id],
      );

      const requestsResult = await query(
        'SELECT * FROM api_requests WHERE collection_id = $1 AND deleted_at IS NULL ORDER BY updated_at DESC',
        [req.params.id],
      );

      res.json({
        ...collectionResult.rows[0],
        folders: foldersResult.rows,
        requests: requestsResult.rows,
      });
    } catch (err) { next(err); }
  },
);

apiClientRouter.post('/requests',
  requirePermission(Permission.API_CLIENT_USE),
  validateBody(z.object({
    name: z.string().min(1).max(200),
    collectionId: z.string().uuid(),
    folderId: z.string().uuid().optional(),
    method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']),
    url: z.string().min(1).max(2000),
    headers: z.record(z.string()).optional().default({}),
    queryParams: z.record(z.string()).optional().default({}),
    body: z.union([z.string(), z.object({}).passthrough()]).optional(),
    bodyType: z.enum(['none', 'json', 'xml', 'form-data', 'form-urlencoded', 'raw', 'binary', 'graphql']).optional().default('none'),
    auth: z.object({
      type: z.enum(['none', 'bearer', 'jwt', 'basic', 'digest', 'oauth', 'api_key', 'mtls']),
      credentials: z.object({}).passthrough().optional(),
    }).optional(),
    preRequestScript: z.string().max(5000).optional(),
    postScript: z.string().max(5000).optional(),
    assertions: z.array(z.object({
      type: z.enum(['status', 'header', 'body', 'json_path', 'response_time', 'schema']),
      operator: z.enum(['equals', 'contains', 'exists', 'not_exists', 'regex', 'gt', 'lt', 'gte', 'lte']),
      target: z.string().optional(),
      value: z.string().optional(),
    })).optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const requestId = uuidv4();
      const { name, collectionId, folderId, method, url, headers, queryParams,
        body, bodyType, auth, preRequestScript, postScript, assertions } = req.body;

      // Tenant isolation: the collection must belong to the caller's org, and the
      // folder (if any) must belong to that collection.
      const collCheck = await query('SELECT id FROM api_collections WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL', [collectionId, req.orgId]);
      if (collCheck.rows.length === 0) throw AppError.notFound('Collection not found');
      if (folderId) {
        const folderCheck = await query('SELECT id FROM api_folders WHERE id = $1 AND collection_id = $2', [folderId, collectionId]);
        if (folderCheck.rows.length === 0) throw AppError.notFound('Folder not found');
      }

      await query(
        `INSERT INTO api_requests (id, org_id, collection_id, folder_id, name, method, url, headers,
          query_params, body, body_type, auth, pre_request_script, post_script, assertions, created_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW(),NOW())`,
        [requestId, req.orgId, collectionId, folderId, name, method, url,
          JSON.stringify(headers), JSON.stringify(queryParams),
          typeof body === 'string' ? body : JSON.stringify(body),
          bodyType, JSON.stringify(auth || {}),
          preRequestScript, postScript, JSON.stringify(assertions || []), req.userId],
      );

      res.status(201).json({ id: requestId, name, method, url });
    } catch (err) { next(err); }
  },
);

apiClientRouter.post('/requests/:id/execute',
  requirePermission(Permission.API_CLIENT_USE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'SELECT * FROM api_requests WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL',
        [req.params.id, req.orgId],
      );
      if (result.rows.length === 0) throw AppError.notFound('Request not found');

      const apiReq = result.rows[0] as Record<string, unknown>;
      const startTime = Date.now();

      await validateTargetUrl(apiReq.url as string);

      const url = new URL(apiReq.url as string);
      const headers: Record<string, string> = typeof apiReq.headers === 'string' ? JSON.parse(apiReq.headers) : (apiReq.headers || {});

      const options: https.RequestOptions = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: apiReq.method as string,
        headers,
        timeout: 30000,
      };

      const transport = url.protocol === 'https:' ? https : http;

      const response = await new Promise<{ status: number; headers: Record<string,string>; body: string; timing: number }>((resolve, reject) => {
        const hreq = transport.request(options, (hres) => {
          let data = '';
          hres.on('data', chunk => data += chunk);
          hres.on('end', () => {
            resolve({
              status: hres.statusCode || 0,
              headers: hres.headers as Record<string, string>,
              body: data,
              timing: Date.now() - startTime,
            });
          });
        });
        hreq.on('error', reject);
        hreq.on('timeout', () => { hreq.destroy(); reject(new Error('Request timeout')); });

        if (apiReq.body && ['POST', 'PUT', 'PATCH'].includes(apiReq.method as string)) {
          hreq.write(typeof apiReq.body === 'string' ? apiReq.body : JSON.stringify(apiReq.body));
        }
        hreq.end();
      });

      await query(
        `INSERT INTO api_request_history (id, request_id, user_id, response_status, response_headers, response_body, timing_ms, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [uuidv4(), req.params.id, req.userId, response.status,
          JSON.stringify(response.headers), response.body.slice(0, 100000), response.timing],
      );

      res.json({
        status: response.status,
        headers: response.headers,
        body: response.body.slice(0, 500000),
        timing: response.timing,
        size: Buffer.byteLength(response.body),
      });
    } catch (err) { next(err); }
  },
);

apiClientRouter.get('/history',
  requirePermission(Permission.API_CLIENT_USE),
  validateQuery(z.object({
    limit: z.string().transform(Number).pipe(z.number().min(1).max(100)).optional().default('20'),
    requestId: z.string().uuid().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { limit, requestId } = req.query as any;
      const conditions = ['h.user_id = $1'];
      const params: unknown[] = [req.userId];
      if (requestId) { conditions.push('h.request_id = $2'); params.push(requestId); }

      const result = await query(
        `SELECT h.id, h.request_id, r.name as request_name, r.method, r.url,
                h.response_status, h.timing_ms, h.created_at
         FROM api_request_history h
         JOIN api_requests r ON h.request_id = r.id
         WHERE ${conditions.join(' AND ')}
         ORDER BY h.created_at DESC
         LIMIT $${params.length + 1}`,
        [...params, Number(limit)],
      );

      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

apiClientRouter.post('/import',
  requirePermission(Permission.API_CLIENT_MANAGE),
  validateBody(z.object({
    format: z.enum(['openapi', 'swagger', 'postman', 'graphql', 'curl']),
    data: z.string(),
    collectionName: z.string().min(1).max(200),
    projectId: z.string().uuid().optional(),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const collectionId = uuidv4();
      const { format, data, collectionName, projectId } = req.body;

      await query(
        `INSERT INTO api_collections (id, org_id, project_id, name, description, import_format, import_data, created_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),NOW())`,
        [collectionId, req.orgId, projectId, collectionName, `Imported from ${format}`, format, data, req.userId],
      );

      const parsed = parseImportData(format, data);
      for (const ep of parsed) {
        await query(
          `INSERT INTO api_requests (id, org_id, collection_id, name, method, url, headers, query_params, body, body_type, auth, created_by, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),NOW())`,
          [uuidv4(), req.orgId, collectionId, ep.name, ep.method, ep.url,
            JSON.stringify(ep.headers), JSON.stringify(ep.queryParams || {}),
            ep.body || null, ep.bodyType || 'none', JSON.stringify(ep.auth || {}), req.userId],
        );
      }

      logger.info({ collectionId, format, endpointsParsed: parsed.length }, 'API collection imported and parsed');
      res.status(201).json({
        id: collectionId,
        name: collectionName,
        requestCount: parsed.length,
        message: `Imported ${parsed.length} requests from ${format}.`,
      });
    } catch (err) { next(err); }
  },
);

apiClientRouter.get('/export/:collectionId',
  requirePermission(Permission.API_CLIENT_USE),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const collectionResult = await query(
        'SELECT * FROM api_collections WHERE id = $1 AND org_id = $2',
        [req.params.collectionId, req.orgId],
      );
      if (collectionResult.rows.length === 0) throw AppError.notFound('Collection not found');

      const requestsResult = await query(
        'SELECT * FROM api_requests WHERE collection_id = $1 AND deleted_at IS NULL',
        [req.params.collectionId],
      );

      const collection = collectionResult.rows[0] as Record<string, unknown>;
      const exportData = {
        info: { name: collection.name, description: collection.description },
        item: requestsResult.rows.map((r: Record<string, unknown>) => ({
          name: r.name,
          request: {
            method: r.method,
            url: r.url,
            header: typeof r.headers === 'string' ? JSON.parse(r.headers) : r.headers,
            body: r.body_type !== 'none' ? r.body : undefined,
          },
        })),
      };

      const format = req.query.format as string || 'json';
      if (format === 'curl') {
        const shellEscape = (s: string) => "'" + String(s).replace(/'/g, "'\\''") + "'";
        const curls = requestsResult.rows.map((r: Record<string, unknown>) => {
          const headers = typeof r.headers === 'string' ? JSON.parse(r.headers) : (r.headers || {});
          const headerStr = Object.entries(headers).map(([k, v]) => `-H ${shellEscape(k + ': ' + v)}`).join(' ');
          return `curl -X ${shellEscape(String(r.method))} ${headerStr} ${shellEscape(String(r.url))}`;
        }).join('\n\n');
        res.setHeader('Content-Type', 'text/plain');
        res.send(curls);
        return;
      }

      res.json(exportData);
    } catch (err) { next(err); }
  },
);
