import { v4 as uuidv4 } from 'uuid';
import crypto from 'node:crypto';
import * as http from 'node:http';
import * as https from 'node:https';
import { logger } from '../../core/logging/logger.js';
import { getRedis } from '../../core/redis/client.js';
import { query } from '../../core/db/pool.js';
import { decrypt } from '../../core/encryption/cipher.js';

// ============================================================================
// Types & Enums
// ============================================================================

export enum WebhookEventType {
  SCAN_STARTED = 'scan.started',
  SCAN_COMPLETED = 'scan.completed',
  SCAN_FAILED = 'scan.failed',
  FINDING_CREATED = 'finding.created',
  FINDING_CRITICAL = 'finding.critical',
  REPORT_GENERATED = 'report.generated',
  USER_INVITED = 'user.invited',
  INTEGRATION_TEST = 'integration.test',
}

export interface Webhook {
  id: string;
  orgId: string;
  name: string;
  url: string;
  events: WebhookEventType[];
  secret?: string;
  headers?: Record<string, string>;
  enabled: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface WebhookPayload {
  eventType: string;
  timestamp: string;
  orgId: string;
  data: unknown;
}

export interface WebhookDispatchConfig {
  timeoutMs: number;
}

export interface DispatchResult {
  webhookId: string;
  webhookName: string;
  statusCode: number | null;
  responseBody: string;
  duration: number;
  success: boolean;
  attempts: number;
  error?: string;
}

export interface DispatchSummary {
  total: number;
  succeeded: number;
  failed: number;
  results: DispatchResult[];
}

export interface DeadLetterEntry {
  id: string;
  webhookId: string;
  orgId: string;
  eventType: string;
  payload: unknown;
  error: string;
  attempts: number;
  createdAt: string;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_RETRIES = 3;
const RETRY_DELAYS_MS: readonly number[] = [1_000, 4_000, 16_000];
const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_SECONDS = 1;
const SIGNATURE_HEADER = 'X-AppSec-Signature';
const SECRET_SCHEME = 'sha256:';

const DISPATCH_EVENT_LOG_BASE = {
  module: 'webhook-service',
  protocol: 'webhook',
};

// ============================================================================
// HMAC Signature Helpers
// ============================================================================

function signPayload(payload: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
}

function extractSecret(secretHash: string | null | undefined): string | undefined {
  if (!secretHash) return undefined;
  try {
    return decrypt(secretHash);
  } catch {
    if (secretHash.startsWith(SECRET_SCHEME)) {
      return secretHash.slice(SECRET_SCHEME.length);
    }
    return secretHash;
  }
}

// ============================================================================
// Rate Limiter (Redis-backed sliding window)
// ============================================================================

async function checkRateLimit(orgId: string): Promise<boolean> {
  const redis = getRedis();
  const key = `webhook:ratelimit:${orgId}`;
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW_SECONDS * 1000;

  try {
    const multi = redis.multi();
    multi.zremrangebyscore(key, 0, windowStart);
    multi.zadd(key, now, `${now}:${uuidv4()}`);
    multi.zcard(key);
    multi.expire(key, 10);
    const results = await multi.exec();

    // results[2] is the zcard result: [error, count]
    const count = (results?.[2]?.[1] as number | undefined) ?? 0;
    return count <= RATE_LIMIT_MAX;
  } catch (err) {
    logger.error({ err, orgId, ...DISPATCH_EVENT_LOG_BASE }, 'Rate limit check failed, allowing request');
    return true; // Fail open
  }
}

// ============================================================================
// HTTP POST Dispatch
// ============================================================================

interface HttpResponse {
  statusCode: number | null;
  responseBody: string;
  duration: number;
}

function httpPost(
  url: string,
  payload: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<HttpResponse> {
  const urlObj = new URL(url);
  const isHttps = urlObj.protocol === 'https:';
  const mod = isHttps ? https : http;
  const port = urlObj.port ? parseInt(urlObj.port, 10) : isHttps ? 443 : 80;

  return new Promise<HttpResponse>((resolve) => {
    const start = Date.now();

    const options: http.RequestOptions = {
      hostname: urlObj.hostname,
      port,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload, 'utf8'),
        'User-Agent': 'AppSec-Webhook/1.0',
        ...headers,
      },
      timeout: timeoutMs,
    };

    const req = mod.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const duration = Date.now() - start;
        resolve({
          statusCode: res.statusCode ?? null,
          responseBody: Buffer.concat(chunks).toString('utf8'),
          duration,
        });
      });
      res.on('error', () => {
        const duration = Date.now() - start;
        resolve({ statusCode: null, responseBody: 'Response stream error', duration });
      });
    });

    req.on('error', (err: Error) => {
      const duration = Date.now() - start;
      resolve({ statusCode: null, responseBody: err.message, duration });
    });

    req.on('timeout', () => {
      req.destroy();
      const duration = Date.now() - start;
      resolve({ statusCode: null, responseBody: 'Request timed out', duration });
    });

    req.write(payload);
    req.end();
  });
}

// ============================================================================
// Dead Letter Queue
// ============================================================================

async function addToDeadLetterQueue(
  webhook: Webhook,
  eventType: string,
  payload: unknown,
  error: string,
  attempts: number,
): Promise<void> {
  try {
    const dqId = uuidv4();
    await query(
      `INSERT INTO webhook_dead_letters (id, webhook_id, org_id, event_type, payload, error, attempts, created_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, NOW())`,
      [dqId, webhook.id, webhook.orgId, eventType, JSON.stringify(payload), error, attempts],
    );

    logger.warn({
      webhookId: webhook.id,
      webhookName: webhook.name,
      orgId: webhook.orgId,
      eventType,
      deadLetterId: dqId,
      attempts,
      ...DISPATCH_EVENT_LOG_BASE,
    }, 'Webhook moved to dead letter queue after max retries');
  } catch (err) {
    logger.error(
      { err, webhookId: webhook.id, orgId: webhook.orgId, ...DISPATCH_EVENT_LOG_BASE },
      'Failed to persist dead letter entry',
    );
  }
}

// ============================================================================
// Retry Decision
// ============================================================================

function shouldRetry(statusCode: number | null, attempt: number): boolean {
  if (attempt >= MAX_RETRIES) return false;
  // Network errors (null statusCode) should be retried
  if (statusCode === null) return true;
  // 5xx server errors should be retried
  if (statusCode >= 500) return true;
  // 4xx client errors should NOT be retried
  return false;
}

// ============================================================================
// dispatchWebhook — Send a single webhook with retry + backoff
// ============================================================================

export async function dispatchWebhook(
  webhook: Webhook,
  event: WebhookPayload,
  config?: Partial<WebhookDispatchConfig>,
): Promise<DispatchResult> {
  const timeoutMs = config?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const overallStart = Date.now();

  const payloadStr = JSON.stringify(event);
  const secret = webhook.secret;
  const signature = secret ? signPayload(payloadStr, secret) : undefined;

  const customHeaders: Record<string, string> = { ...webhook.headers };
  if (signature) {
    customHeaders[SIGNATURE_HEADER] = signature;
  }

  let lastResponse: HttpResponse = { statusCode: null, responseBody: '', duration: 0 };
  let attempts = 0;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    attempts++;

    const response = await httpPost(webhook.url, payloadStr, customHeaders, timeoutMs);
    lastResponse = response;

    logger.info({
      webhookId: webhook.id,
      webhookName: webhook.name,
      orgId: webhook.orgId,
      eventType: event.eventType,
      attempt: attempt + 1,
      totalAttempts: MAX_RETRIES + 1,
      statusCode: response.statusCode,
      duration: response.duration,
      ...DISPATCH_EVENT_LOG_BASE,
    }, 'Webhook dispatch attempt completed');

    if (response.statusCode !== null && response.statusCode >= 200 && response.statusCode < 300) {
      // Success — no retry needed
      return {
        webhookId: webhook.id,
        webhookName: webhook.name,
        statusCode: response.statusCode,
        responseBody: response.responseBody,
        duration: Date.now() - overallStart,
        success: true,
        attempts,
      };
    }

    if (!shouldRetry(response.statusCode, attempt)) {
      break;
    }

    const delay = RETRY_DELAYS_MS[attempt] ?? RETRY_DELAYS_MS[RETRY_DELAYS_MS.length - 1] ?? 1000;

    logger.warn({
      webhookId: webhook.id,
      webhookName: webhook.name,
      orgId: webhook.orgId,
      eventType: event.eventType,
      attempt: attempt + 1,
      statusCode: response.statusCode,
      nextRetryDelayMs: delay,
      ...DISPATCH_EVENT_LOG_BASE,
    }, 'Retrying webhook dispatch');

    await sleep(delay);
  }

  // All retries exhausted — move to dead letter queue
  const errorBody = lastResponse.responseBody.slice(0, 1_000);
  const errorMsg = lastResponse.statusCode !== null
    ? `HTTP ${lastResponse.statusCode}: ${errorBody}`
    : (errorBody || 'Unknown dispatch error');

  await addToDeadLetterQueue(webhook, event.eventType, event.data, errorMsg, attempts);

  return {
    webhookId: webhook.id,
    webhookName: webhook.name,
    statusCode: lastResponse.statusCode,
    responseBody: lastResponse.responseBody,
    duration: Date.now() - overallStart,
    success: false,
    attempts,
    error: errorMsg,
  };
}

// ============================================================================
// dispatchEvent — Find matching webhooks and dispatch in parallel
// ============================================================================

export async function dispatchEvent(
  eventType: string,
  data: unknown,
  orgId: string,
): Promise<DispatchSummary> {
  const eventTimestamp = new Date().toISOString();
  const payload: WebhookPayload = {
    eventType,
    timestamp: eventTimestamp,
    orgId,
    data,
  };

  logger.info({
    orgId,
    eventType,
    ...DISPATCH_EVENT_LOG_BASE,
  }, 'Dispatching webhook event');

  // Query all enabled, non-deleted webhooks for this org subscribed to the event
  const dbResult = await query<{
    id: string;
    org_id: string;
    name: string;
    url: string;
    events: string[];
    secret_hash: string | null;
    headers: Record<string, string>;
    enabled: boolean;
    created_at: string;
    updated_at: string;
  }>(
    `SELECT id, org_id, name, url, events, secret_hash, headers, enabled, created_at, updated_at
     FROM webhooks
     WHERE org_id = $1
       AND enabled = true
       AND deleted_at IS NULL
       AND events ? $2`,
    [orgId, eventType],
  );

  const webhooks: Webhook[] = dbResult.rows.map((row) => ({
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    url: row.url,
    events: row.events as WebhookEventType[],
    secret: extractSecret(row.secret_hash),
    headers: row.headers ?? {},
    enabled: row.enabled,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));

  if (webhooks.length === 0) {
    logger.info({
      orgId,
      eventType,
      matchedWebhooks: 0,
      ...DISPATCH_EVENT_LOG_BASE,
    }, 'No webhooks matched for event');
    return { total: 0, succeeded: 0, failed: 0, results: [] };
  }

  // Rate limit check per org
  const allowed = await checkRateLimit(orgId);
  if (!allowed) {
    logger.warn({
      orgId,
      eventType,
      webhookCount: webhooks.length,
      ...DISPATCH_EVENT_LOG_BASE,
    }, 'Webhook rate limit exceeded for org — all dispatches rejected');

    const rateLimitedResults: DispatchResult[] = webhooks.map((wh) => ({
      webhookId: wh.id,
      webhookName: wh.name,
      statusCode: null,
      responseBody: '',
      duration: 0,
      success: false,
      attempts: 0,
      error: 'Org webhook rate limit exceeded (max 10/s)',
    }));

    return {
      total: webhooks.length,
      succeeded: 0,
      failed: webhooks.length,
      results: rateLimitedResults,
    };
  }

  // Dispatch to all matching webhooks in parallel
  const dispatchPromises = webhooks.map((wh) => dispatchWebhook(wh, payload));
  const results = await Promise.all(dispatchPromises);

  const succeeded = results.filter((r) => r.success).length;
  const failed = results.filter((r) => !r.success).length;

  logger.info({
    orgId,
    eventType,
    total: results.length,
    succeeded,
    failed,
    ...DISPATCH_EVENT_LOG_BASE,
  }, 'Webhook event dispatch completed');

  return { total: results.length, succeeded, failed, results };
}

// ============================================================================
// testWebhook — Send a test ping to verify connectivity
// ============================================================================

export async function testWebhook(webhook: Webhook): Promise<DispatchResult> {
  const testPayload: WebhookPayload = {
    eventType: WebhookEventType.INTEGRATION_TEST,
    timestamp: new Date().toISOString(),
    orgId: webhook.orgId,
    data: {
      message: 'This is a connectivity test from AppSec Platform',
      webhookId: webhook.id,
      webhookName: webhook.name,
      test: true,
    },
  };

  logger.info({
    webhookId: webhook.id,
    webhookName: webhook.name,
    orgId: webhook.orgId,
    ...DISPATCH_EVENT_LOG_BASE,
  }, 'Sending webhook test ping');

  return dispatchWebhook(webhook, testPayload, { timeoutMs: 15_000 });
}

// ============================================================================
// verifySignature — Validate HMAC on incoming webhook payloads
// ============================================================================

/**
 * Verify an HMAC-SHA256 signature using timing-safe comparison.
 *
 * @param payload - Raw request body (string).
 * @param signature - Value of the X-AppSec-Signature header.
 * @param secret - The shared webhook secret.
 * @returns `true` if the signature is valid.
 */
export function verifySignature(
  payload: string,
  signature: string,
  secret: string,
): boolean {
  if (!payload || !signature || !secret) {
    logger.warn({ ...DISPATCH_EVENT_LOG_BASE }, 'verifySignature called with empty arguments');
    return false;
  }

  const expected = signPayload(payload, secret);
  const expectedBuf = Buffer.from(expected, 'utf8');
  const actualBuf = Buffer.from(signature, 'utf8');

  if (expectedBuf.length !== actualBuf.length) {
    const paddedActual = Buffer.alloc(expectedBuf.length);
    actualBuf.copy(paddedActual, 0, 0, Math.min(actualBuf.length, expectedBuf.length));
    return crypto.timingSafeEqual(expectedBuf, paddedActual) && expectedBuf.length === actualBuf.length;
  }

  return crypto.timingSafeEqual(expectedBuf, actualBuf);
}

// ============================================================================
// Helpers
// ============================================================================

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
