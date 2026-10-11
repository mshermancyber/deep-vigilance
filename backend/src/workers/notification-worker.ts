// ---------------------------------------------------------------------------
// Notification Worker — dispatches notifications to Slack, Teams, Discord,
// email (via SMTP service), and generic webhooks with HMAC signing.
//
// Reads notification records from the database, formats the payload per
// platform spec, sends via HTTP(S), updates status, and supports retry with
// exponential backoff + global rate limiting (10/s across all channels).
// ---------------------------------------------------------------------------

import { Worker, Job } from 'bullmq';
import crypto from 'node:crypto';
import * as http from 'node:http';
import * as https from 'node:https';
import * as dns from 'node:dns';
import * as net from 'node:net';
import { URL } from 'node:url';
import { getConfig } from '../config/index.js';
import { logger } from '../core/logging/logger.js';
import { query } from '../core/db/pool.js';
import { createRedisClient, closeRedis } from '../core/redis/client.js';

// ============================================================================
// Types
// ============================================================================

export type NotificationChannel = 'email' | 'slack' | 'teams' | 'discord' | 'webhook';

/**
 * Severity levels used to colour-code messages across all channels.
 */
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Interface for a channel integration configuration stored in the
 * `integrations` table (decrypted at job-enqueue time or looked up here).
 */
export interface IntegrationConfig {
  id: string;
  orgId: string;
  type: NotificationChannel;
  name: string;
  enabled: boolean;
  config: {
    url?: string;
    webhookUrl?: string;
    secret?: string;
    channel?: string;
    username?: string;
    iconEmoji?: string;
    avatarUrl?: string;
    headers?: Record<string, string>;
    [key: string]: unknown;
  };
}

/**
 * Shape of the data payload that arrives on the BullMQ 'notification' queue.
 */
export interface NotificationJobData {
  /** PK of the notifications row (used to update status). */
  notificationId: string;
  organizationId: string;
  /** Which integration id from the integrations table to use. */
  integrationId: string;
  /** Optional override — if absent the worker reads the integration row. */
  integrationConfig?: IntegrationConfig;

  // --- Content ---
  title: string;
  body: string;
  severity: SeverityLevel;

  // --- Channel-specific overrides ---
  emailOverrides?: {
    to: string | string[];
    cc?: string | string[];
    bcc?: string | string[];
    htmlBody?: string;
    textBody?: string;
  };
  channelOverrides?: Record<string, unknown>;

  // --- Metadata stored for context ---
  projectId?: string;
  scanId?: string;
  findingId?: string;
  reportId?: string;
  sourceUrl?: string;
  metadata?: Record<string, unknown>;
}

export interface DispatchResult {
  success: boolean;
  statusCode: number | null;
  responseBody: string;
  durationMs: number;
  attempts: number;
  error?: string;
}

// ============================================================================
// Constants
// ============================================================================

const MAX_RETRIES = 3;
const RETRY_DELAYS_MS: readonly number[] = [1_000, 2_000, 4_000];
const HTTP_TIMEOUT_MS = 15_000;
const SIGNATURE_HEADER = 'X-AppSec-Signature';
const USER_AGENT = 'AppSec-NotificationWorker/1.0';

/** Colour mapping for severity levels (hex, without #). */
export const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  critical: 'dc2626',
  high: 'ea580c',
  medium: 'ca8a04',
  low: '2563eb',
  info: '6b7280',
};

/** Numeric colour mapping for Discord embeds (decimal). */
export const SEVERITY_DISCORD_COLORS: Record<SeverityLevel, number> = {
  critical: 0xdc2626,
  high: 0xea580c,
  medium: 0xca8a04,
  low: 0x2563eb,
  info: 0x6b7280,
};

// ============================================================================
// Rate Limiter — token bucket, 10 notifications / second globally
// ============================================================================

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

const bucket: TokenBucket = {
  tokens: 10,
  lastRefill: Date.now(),
};

const BUCKET_MAX = 10;
const BUCKET_REFILL_INTERVAL_MS = 100; // refill every 100 ms
const BUCKET_REFILL_AMOUNT = 1;        // 1 token per 100 ms => 10/sec

function refillBucket(): void {
  const now = Date.now();
  const elapsed = now - bucket.lastRefill;
  if (elapsed >= BUCKET_REFILL_INTERVAL_MS) {
    const newTokens = Math.floor(elapsed / BUCKET_REFILL_INTERVAL_MS) * BUCKET_REFILL_AMOUNT;
    bucket.tokens = Math.min(BUCKET_MAX, bucket.tokens + newTokens);
    bucket.lastRefill = now - (elapsed % BUCKET_REFILL_INTERVAL_MS);
  }
}

function consumeToken(): boolean {
  refillBucket();
  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return true;
  }
  return false;
}

async function waitForToken(timeoutMs: number = 30_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (consumeToken()) return true;
    await sleep(50);
  }
  return false;
}

// ============================================================================
// Shared HTTP POST helper (mirrors webhook-service.ts pattern)
// ============================================================================

interface HttpResponse {
  statusCode: number | null;
  body: string;
  durationMs: number;
}

function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0]! >= 224) return true;
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

async function validateWebhookUrl(rawUrl: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Invalid webhook URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Webhook URL must use http or https');
  }
  const host = parsed.hostname;
  if (net.isIP(host)) {
    if (isPrivateIP(host)) throw new Error('Webhook URL resolves to a private address');
    return;
  }
  const { address } = await dns.promises.lookup(host);
  const all = await dns.promises.lookup(host, { all: true });
  for (const a of all) {
    if (isPrivateIP(a.address)) throw new Error('Webhook URL resolves to a private address');
  }
  if (isPrivateIP(address)) throw new Error('Webhook URL resolves to a private address');
}

function httpPost(
  url: string,
  payload: string,
  headers: Record<string, string>,
  timeoutMs: number = HTTP_TIMEOUT_MS,
): Promise<HttpResponse> {
  const urlObj = new URL(url);
  const isHttps = urlObj.protocol === 'https:';
  const mod = isHttps ? https : http;
  const port = urlObj.port ? parseInt(urlObj.port, 10) : isHttps ? 443 : 80;

  return new Promise<HttpResponse>((resolve) => {
    const start = Date.now();

    validateWebhookUrl(url).then(() => {

    const options: http.RequestOptions = {
      hostname: urlObj.hostname,
      port,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload, 'utf8'),
        'User-Agent': USER_AGENT,
        ...headers,
      },
      timeout: timeoutMs,
    };

    const req = mod.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const durationMs = Date.now() - start;
        resolve({
          statusCode: res.statusCode ?? null,
          body: Buffer.concat(chunks).toString('utf8'),
          durationMs,
        });
      });
      res.on('error', () => {
        const durationMs = Date.now() - start;
        resolve({ statusCode: null, body: 'Response stream error', durationMs });
      });
    });

    req.on('error', (err: Error) => {
      const durationMs = Date.now() - start;
      resolve({ statusCode: null, body: err.message, durationMs });
    });

    req.on('timeout', () => {
      req.destroy();
      const durationMs = Date.now() - start;
      resolve({ statusCode: null, body: 'Request timed out', durationMs });
    });

    req.write(payload);
    req.end();
    }).catch((err: Error) => {
      const durationMs = Date.now() - start;
      resolve({ statusCode: null, body: `Blocked: ${err.message}`, durationMs });
    });
  });
}

// ============================================================================
// HMAC Signature (matches webhook-service.ts)
// ============================================================================

function signPayload(payload: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
}

// ============================================================================
// Platform-specific formatters
// ============================================================================

// ---------------------------------------------------------------------------
// Slack Block Kit formatter
// ---------------------------------------------------------------------------

export interface SlackMessage {
  text?: string;
  channel?: string;
  username?: string;
  icon_emoji?: string;
  attachments?: SlackAttachment[];
  blocks?: Record<string, unknown>[];
}

export interface SlackAttachment {
  color?: string;
  pretext?: string;
  author_name?: string;
  author_link?: string;
  author_icon?: string;
  title?: string;
  title_link?: string;
  text?: string;
  fields?: SlackField[];
  image_url?: string;
  thumb_url?: string;
  footer?: string;
  footer_icon?: string;
  ts?: number;
  mrkdwn_in?: string[];
}

export interface SlackField {
  title: string;
  value: string;
  short?: boolean;
}

function formatSlack(
  title: string,
  body: string,
  severity: SeverityLevel,
  config: IntegrationConfig['config'],
  metadata?: Record<string, unknown>,
): SlackMessage {
  const color = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);

  const fields: SlackField[] = [
    { title: 'Severity', value: severityLabel, short: true },
  ];

  if (metadata?.projectName) {
    fields.push({ title: 'Project', value: String(metadata.projectName), short: true });
  }
  if (metadata?.scanId) {
    fields.push({ title: 'Scan ID', value: `\`${String(metadata.scanId)}\``, short: true });
  }
  if (metadata?.findingId) {
    fields.push({ title: 'Finding ID', value: `\`${String(metadata.findingId)}\``, short: true });
  }
  if (metadata?.sourceUrl) {
    fields.push({
      title: 'Link',
      value: `<${String(metadata.sourceUrl)}|View in Dashboard>`,
      short: false,
    });
  }

  const attachment: SlackAttachment = {
    color: `#${color}`,
    pretext: severity === 'critical' || severity === 'high'
      ? `:warning: *${severityLabel} Alert*`
      : `:information_source: *${severityLabel} Notification*`,
    title,
    title_link: metadata?.sourceUrl ? String(metadata.sourceUrl) : undefined,
    text: body.length > 3000 ? `${body.slice(0, 2997)}...` : body,
    fields,
    footer: 'AppSec Platform',
    footer_icon: 'https://deep-vigilance.local/favicon.ico',
    ts: Math.floor(Date.now() / 1000),
    mrkdwn_in: ['pretext', 'text', 'fields', 'title'],
  };

  return {
    text: `[${severityLabel}] ${title}`,
    channel: config.channel as string | undefined,
    username: (config.username as string) || 'AppSec Bot',
    icon_emoji: (config.iconEmoji as string) || (severity === 'critical' || severity === 'high' ? ':warning:' : ':bell:'),
    attachments: [attachment],
  };
}

// ---------------------------------------------------------------------------
// Teams Adaptive Card formatter
// ---------------------------------------------------------------------------

export interface TeamsMessage {
  type: 'message';
  attachments: TeamsAttachment[];
}

export interface TeamsAttachment {
  contentType: 'application/vnd.microsoft.card.adaptive';
  content: TeamsAdaptiveCard;
}

export interface TeamsAdaptiveCard {
  $schema: 'http://adaptivecards.io/schemas/adaptive-card.json';
  type: 'AdaptiveCard';
  version: '1.5';
  summary?: string;
  themeColor?: string;
  msteams?: {
    entities?: Record<string, unknown>[];
  };
  body: TeamsElement[];
  actions?: TeamsAction[];
}

export type TeamsElement =
  | TeamsTextBlock
  | TeamsFactSet
  | TeamsColumnSet
  | TeamsContainer
  | TeamsImage;

export interface TeamsTextBlock {
  type: 'TextBlock';
  text: string;
  weight?: 'default' | 'lighter' | 'bolder';
  size?: 'small' | 'default' | 'medium' | 'large' | 'extraLarge';
  color?: 'default' | 'dark' | 'light' | 'accent' | 'good' | 'warning' | 'attention';
  wrap?: boolean;
  spacing?: 'none' | 'small' | 'default' | 'medium' | 'large' | 'padding';
  isSubtle?: boolean;
}

export interface TeamsFactSet {
  type: 'FactSet';
  facts: TeamsFact[];
  spacing?: 'none' | 'small' | 'default' | 'medium' | 'large' | 'padding';
}

export interface TeamsFact {
  title: string;
  value: string;
}

export interface TeamsColumnSet {
  type: 'ColumnSet';
  columns: TeamsColumn[];
}

export interface TeamsColumn {
  type: 'Column';
  width: string;
  items: TeamsElement[];
}

export interface TeamsContainer {
  type: 'Container';
  items: TeamsElement[];
  style?: 'default' | 'emphasis' | 'good' | 'attention' | 'warning' | 'accent';
  bleed?: boolean;
}

export interface TeamsImage {
  type: 'Image';
  url: string;
  altText?: string;
  size?: 'small' | 'medium' | 'large' | 'auto' | 'stretch';
}

export interface TeamsAction {
  type: 'Action.OpenUrl';
  title: string;
  url: string;
}

function formatTeams(
  title: string,
  body: string,
  severity: SeverityLevel,
  _config: IntegrationConfig['config'],
  metadata?: Record<string, unknown>,
): TeamsMessage {
  const themeColor = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);

  const cardColor: TeamsTextBlock['color'] =
    severity === 'critical' ? 'attention'
    : severity === 'high' ? 'warning'
    : severity === 'medium' ? 'warning'
    : severity === 'low' ? 'accent'
    : 'default';

  const bodyElements: TeamsElement[] = [];

  // Header
  bodyElements.push({
    type: 'TextBlock',
    text: severity === 'critical' || severity === 'high'
      ? `&#x26A0; ${severityLabel} Alert`
      : `&#x2139; ${severityLabel} Notification`,
    weight: 'bolder',
    size: 'medium',
    color: cardColor,
    spacing: 'none',
  });

  bodyElements.push({
    type: 'TextBlock',
    text: title,
    weight: 'bolder',
    size: 'large',
    wrap: true,
    spacing: 'small',
  });

  // Severity badge
  bodyElements.push({
    type: 'TextBlock',
    text: `**Severity:** ${severityLabel}`,
    size: 'default',
    color: cardColor,
    spacing: 'small',
    isSubtle: true,
  });

  bodyElements.push({
    type: 'TextBlock',
    text: body.length > 500 ? `${body.slice(0, 497)}...` : body,
    wrap: true,
    spacing: 'default',
  });

  // Facts section
  const facts: TeamsFact[] = [];

  if (metadata?.projectName) {
    facts.push({ title: 'Project', value: String(metadata.projectName) });
  }
  if (metadata?.scanId) {
    facts.push({ title: 'Scan ID', value: String(metadata.scanId) });
  }
  if (metadata?.findingId) {
    facts.push({ title: 'Finding ID', value: String(metadata.findingId) });
  }
  if (metadata?.reportId) {
    facts.push({ title: 'Report ID', value: String(metadata.reportId) });
  }
  if (metadata?.timestamp) {
    facts.push({ title: 'Timestamp', value: String(metadata.timestamp) });
  }

  if (facts.length > 0) {
    bodyElements.push({
      type: 'FactSet',
      facts,
      spacing: 'default',
    });
  }

  // Conditional style container for high/critical severity
  if (severity === 'critical' || severity === 'high') {
    bodyElements.push({
      type: 'Container',
      style: severity === 'critical' ? 'attention' : 'warning',
      bleed: true,
      items: [
        {
          type: 'TextBlock',
          text: severity === 'critical'
            ? 'This finding requires immediate attention.'
            : 'This finding should be reviewed promptly.',
          wrap: true,
          size: 'default',
        },
      ],
    });
  }

  const actions: TeamsAction[] = [];
  if (metadata?.sourceUrl) {
    actions.push({
      type: 'Action.OpenUrl',
      title: severity === 'critical' || severity === 'high'
        ? 'View & Remediate in Dashboard'
        : 'View in Dashboard',
      url: String(metadata.sourceUrl),
    });
  }

  return {
    type: 'message',
    attachments: [
      {
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard',
          version: '1.5',
          summary: `[${severityLabel}] ${title}`,
          themeColor: `#${themeColor}`,
          body: bodyElements,
          actions: actions.length > 0 ? actions : undefined,
        },
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// Discord embed formatter
// ---------------------------------------------------------------------------

export interface DiscordMessage {
  content?: string;
  username?: string;
  avatar_url?: string;
  tts?: boolean;
  embeds?: DiscordEmbed[];
}

export interface DiscordEmbed {
  title?: string;
  description?: string;
  url?: string;
  color?: number;
  timestamp?: string;
  footer?: DiscordEmbedFooter;
  image?: DiscordEmbedImage;
  thumbnail?: DiscordEmbedThumbnail;
  author?: DiscordEmbedAuthor;
  fields?: DiscordEmbedField[];
}

export interface DiscordEmbedFooter {
  text: string;
  icon_url?: string;
}

export interface DiscordEmbedImage {
  url: string;
}

export interface DiscordEmbedThumbnail {
  url: string;
}

export interface DiscordEmbedAuthor {
  name: string;
  url?: string;
  icon_url?: string;
}

export interface DiscordEmbedField {
  name: string;
  value: string;
  inline?: boolean;
}

function formatDiscord(
  title: string,
  body: string,
  severity: SeverityLevel,
  config: IntegrationConfig['config'],
  metadata?: Record<string, unknown>,
): DiscordMessage {
  const color = SEVERITY_DISCORD_COLORS[severity] ?? SEVERITY_DISCORD_COLORS.info;
  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);

  const fields: DiscordEmbedField[] = [
    { name: 'Severity', value: severityLabel, inline: true },
  ];

  if (metadata?.projectName) {
    fields.push({ name: 'Project', value: String(metadata.projectName), inline: true });
  }
  if (metadata?.scanId) {
    fields.push({ name: 'Scan ID', value: `\`${String(metadata.scanId)}\``, inline: false });
  }
  if (metadata?.findingId) {
    fields.push({ name: 'Finding ID', value: `\`${String(metadata.findingId)}\``, inline: false });
  }
  if (metadata?.reportId) {
    fields.push({ name: 'Report ID', value: `\`${String(metadata.reportId)}\``, inline: false });
  }

  const embed: DiscordEmbed = {
    title,
    description: body.length > 4096 ? `${body.slice(0, 4093)}...` : body,
    url: metadata?.sourceUrl ? String(metadata.sourceUrl) : undefined,
    color,
    timestamp: new Date().toISOString(),
    footer: {
      text: 'AppSec Platform',
    },
    fields,
    author: {
      name: `${severityLabel} Alert`,
      icon_url: severity === 'critical' || severity === 'high'
        ? 'https://deep-vigilance.local/icons/warning.png'
        : 'https://deep-vigilance.local/icons/info.png',
    },
  };

  return {
    content: severity === 'critical' ? '@everyone **Critical Alert**' : undefined,
    username: (config.username as string) || 'AppSec Bot',
    avatar_url: (config.avatarUrl as string) || undefined,
    embeds: [embed],
  };
}

// ---------------------------------------------------------------------------
// Generic Webhook formatter — wraps the payload with HMAC signature
// ---------------------------------------------------------------------------

export interface WebhookPayload {
  event: string;
  timestamp: string;
  notificationId: string;
  organizationId: string;
  severity: SeverityLevel;
  title: string;
  body: string;
  projectId?: string;
  scanId?: string;
  findingId?: string;
  reportId?: string;
  sourceUrl?: string;
  metadata?: Record<string, unknown>;
}

function formatWebhook(
  title: string,
  body: string,
  severity: SeverityLevel,
  jobData: NotificationJobData,
): { payload: string; signature?: string } {
  const webhookPayload: WebhookPayload = {
    event: 'notification.dispatch',
    timestamp: new Date().toISOString(),
    notificationId: jobData.notificationId,
    organizationId: jobData.organizationId,
    severity,
    title,
    body,
    projectId: jobData.projectId,
    scanId: jobData.scanId,
    findingId: jobData.findingId,
    reportId: jobData.reportId,
    sourceUrl: jobData.sourceUrl,
    metadata: jobData.metadata,
  };

  const payloadStr = JSON.stringify(webhookPayload);
  return { payload: payloadStr };
}

// ============================================================================
// Channel Dispatch Functions
// ============================================================================

async function dispatchEmail(
  jobData: NotificationJobData,
  integration: IntegrationConfig,
): Promise<DispatchResult> {
  // Dynamic import to avoid pulling in nodemailer when not needed
  const { sendEmail } = await import('../services/notification/smtp-service.js');

  const to = jobData.emailOverrides?.to
    ?? (integration.config.emailTo as string | string[] | undefined)
    ?? [];

  const htmlBody = jobData.emailOverrides?.htmlBody
    ?? `<html><body><h2>${escapeHtml(jobData.title)}</h2><p>${escapeHtml(jobData.body).replace(/\n/g, '<br>')}</p></body></html>`;

  const textBody = jobData.emailOverrides?.textBody ?? jobData.body;

  try {
    const result = await sendEmail({
      to: Array.isArray(to) ? to : [to],
      cc: jobData.emailOverrides?.cc
        ? (Array.isArray(jobData.emailOverrides.cc) ? jobData.emailOverrides.cc : [jobData.emailOverrides.cc])
        : undefined,
      bcc: jobData.emailOverrides?.bcc
        ? (Array.isArray(jobData.emailOverrides.bcc) ? jobData.emailOverrides.bcc : [jobData.emailOverrides.bcc])
        : undefined,
      subject: `[${jobData.severity.toUpperCase()}] ${jobData.title}`,
      html: htmlBody,
      text: textBody,
      headers: {
        'X-AppSec-Notification-ID': jobData.notificationId,
        'X-AppSec-Severity': jobData.severity,
        'X-AppSec-Entity': integration.name,
        Priority: jobData.severity === 'critical' || jobData.severity === 'high' ? 'urgent' : 'normal',
      },
    });

    const success = result.rejected.length === 0;
    return {
      success,
      statusCode: success ? 200 : 550,
      responseBody: result.messageId,
      durationMs: 0,
      attempts: 1,
      error: success ? undefined : `Rejected recipients: ${result.rejected.join(', ')}`,
    };
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    return {
      success: false,
      statusCode: null,
      responseBody: error.message,
      durationMs: 0,
      attempts: 1,
      error: error.message,
    };
  }
}

async function dispatchSlack(
  jobData: NotificationJobData,
  integration: IntegrationConfig,
): Promise<DispatchResult> {
  const webhookUrl = integration.config.webhookUrl as string | undefined
    ?? integration.config.url as string | undefined;

  if (!webhookUrl) {
    return { success: false, statusCode: null, responseBody: 'No webhook URL configured', durationMs: 0, attempts: 0, error: 'Missing webhook URL' };
  }

  const message = formatSlack(
    jobData.title,
    jobData.body,
    jobData.severity,
    integration.config,
    {
      projectName: jobData.metadata?.projectName,
      scanId: jobData.scanId,
      findingId: jobData.findingId,
      sourceUrl: jobData.sourceUrl,
    },
  );

  const payload = JSON.stringify(message);
  const response = await httpPost(webhookUrl, payload, {}, HTTP_TIMEOUT_MS);

  // Slack returns 200 OK on success
  const success = response.statusCode !== null && response.statusCode >= 200 && response.statusCode < 300;

  return {
    success,
    statusCode: response.statusCode,
    responseBody: response.body,
    durationMs: response.durationMs,
    attempts: 1,
    error: success ? undefined : `HTTP ${response.statusCode}: ${response.body.slice(0, 500)}`,
  };
}

async function dispatchTeams(
  jobData: NotificationJobData,
  integration: IntegrationConfig,
): Promise<DispatchResult> {
  const webhookUrl = integration.config.webhookUrl as string | undefined
    ?? integration.config.url as string | undefined;

  if (!webhookUrl) {
    return { success: false, statusCode: null, responseBody: 'No webhook URL configured', durationMs: 0, attempts: 0, error: 'Missing webhook URL' };
  }

  const message = formatTeams(
    jobData.title,
    jobData.body,
    jobData.severity,
    integration.config,
    {
      projectName: jobData.metadata?.projectName,
      scanId: jobData.scanId,
      findingId: jobData.findingId,
      reportId: jobData.reportId,
      sourceUrl: jobData.sourceUrl,
      timestamp: new Date().toISOString(),
    },
  );

  const payload = JSON.stringify(message);
  const response = await httpPost(webhookUrl, payload, {}, HTTP_TIMEOUT_MS);

  // Teams returns 1 or 2-digit status codes on success sometimes; accept 2xx
  const success = response.statusCode !== null && response.statusCode >= 200 && response.statusCode < 300;

  return {
    success,
    statusCode: response.statusCode,
    responseBody: response.body,
    durationMs: response.durationMs,
    attempts: 1,
    error: success ? undefined : `HTTP ${response.statusCode}: ${response.body.slice(0, 500)}`,
  };
}

async function dispatchDiscord(
  jobData: NotificationJobData,
  integration: IntegrationConfig,
): Promise<DispatchResult> {
  const webhookUrl = integration.config.webhookUrl as string | undefined
    ?? integration.config.url as string | undefined;

  if (!webhookUrl) {
    return { success: false, statusCode: null, responseBody: 'No webhook URL configured', durationMs: 0, attempts: 0, error: 'Missing webhook URL' };
  }

  const message = formatDiscord(
    jobData.title,
    jobData.body,
    jobData.severity,
    integration.config,
    {
      projectName: jobData.metadata?.projectName,
      scanId: jobData.scanId,
      findingId: jobData.findingId,
      reportId: jobData.reportId,
      sourceUrl: jobData.sourceUrl,
    },
  );

  const payload = JSON.stringify(message);
  const response = await httpPost(webhookUrl, payload, {}, HTTP_TIMEOUT_MS);

  // Discord returns 204 No Content on success
  const success = response.statusCode !== null && response.statusCode >= 200 && response.statusCode < 300;

  return {
    success,
    statusCode: response.statusCode,
    responseBody: response.body,
    durationMs: response.durationMs,
    attempts: 1,
    error: success ? undefined : `HTTP ${response.statusCode}: ${response.body.slice(0, 500)}`,
  };
}

async function dispatchWebhookChannel(
  jobData: NotificationJobData,
  integration: IntegrationConfig,
): Promise<DispatchResult> {
  const url = integration.config.url as string | undefined
    ?? integration.config.webhookUrl as string | undefined;

  if (!url) {
    return { success: false, statusCode: null, responseBody: 'No URL configured', durationMs: 0, attempts: 0, error: 'Missing webhook URL' };
  }

  const { payload } = formatWebhook(jobData.title, jobData.body, jobData.severity, jobData);

  const secret = integration.config.secret as string | undefined;
  const signature = secret ? signPayload(payload, secret) : undefined;

  const customHeaders: Record<string, string> = {
    ...(integration.config.headers as Record<string, string> | undefined),
  };

  if (signature) {
    customHeaders[SIGNATURE_HEADER] = signature;
  }

  const response = await httpPost(url, payload, customHeaders, HTTP_TIMEOUT_MS);

  const success = response.statusCode !== null && response.statusCode >= 200 && response.statusCode < 300;

  return {
    success,
    statusCode: response.statusCode,
    responseBody: response.body,
    durationMs: response.durationMs,
    attempts: 1,
    error: success ? undefined : `HTTP ${response.statusCode}: ${response.body.slice(0, 500)}`,
  };
}

// ============================================================================
// Retry wrapper — internal retry loop for transient HTTP failures
// ============================================================================

async function dispatchWithRetry(
  dispatchFn: () => Promise<DispatchResult>,
  channel: NotificationChannel,
  notificationId: string,
): Promise<DispatchResult> {
  let lastResult: DispatchResult | null = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    // Wait for global rate limit token
    const gotToken = await waitForToken();
    if (!gotToken) {
      logger.warn(
        { notificationId, channel, attempt: attempt + 1 },
        'Rate limit deadline exceeded — proceeding anyway',
      );
    }

    lastResult = await dispatchFn();
    lastResult.attempts = attempt + 1;

    logger.info(
      {
        notificationId,
        channel,
        attempt: attempt + 1,
        maxAttempts: MAX_RETRIES + 1,
        success: lastResult.success,
        statusCode: lastResult.statusCode,
        durationMs: lastResult.durationMs,
      },
      `Notification dispatch attempt ${attempt + 1} completed`,
    );

    if (lastResult.success) {
      return lastResult;
    }

    // Decide whether to retry
    if (attempt < MAX_RETRIES && shouldRetry(lastResult.statusCode)) {
      const delay = RETRY_DELAYS_MS[attempt] ?? RETRY_DELAYS_MS[RETRY_DELAYS_MS.length - 1] ?? 1000;
      logger.warn(
        {
          notificationId,
          channel,
          attempt: attempt + 1,
          nextRetryDelayMs: delay,
          statusCode: lastResult.statusCode,
          error: lastResult.error,
        },
        'Notification dispatch failed — retrying with backoff',
      );
      await sleep(delay);
    } else {
      break;
    }
  }

  // All retries exhausted
  return lastResult ?? {
    success: false,
    statusCode: null,
    responseBody: 'No dispatch attempted',
    durationMs: 0,
    attempts: 0,
    error: 'Unknown error',
  };
}

function shouldRetry(statusCode: number | null): boolean {
  // Network errors (null) should be retried
  if (statusCode === null) return true;
  // 5xx server errors should be retried
  if (statusCode >= 500) return true;
  // 429 rate limiting should be retried
  if (statusCode === 429) return true;
  // 4xx client errors should NOT be retried (except 429)
  if (statusCode >= 400) return false;
  // 2xx / 3xx are success — already handled above
  return false;
}

// ============================================================================
// Integration loader from database
// ============================================================================

async function loadIntegration(integrationId: string, orgId: string): Promise<IntegrationConfig | null> {
  try {
    const result = await query<{
      id: string;
      org_id: string;
      type: string;
      name: string;
      enabled: boolean;
      config: Record<string, unknown>;
    }>(
      `SELECT id, org_id, type, name, enabled, config
       FROM integrations
       WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
       LIMIT 1`,
      [integrationId, orgId],
    );

    if (result.rows.length === 0) {
      logger.warn({ integrationId, orgId }, 'Integration not found or deleted');
      return null;
    }

    const row = result.rows[0]!;
    return {
      id: row.id,
      orgId: row.org_id,
      type: row.type as NotificationChannel,
      name: row.name,
      enabled: row.enabled,
      config: typeof row.config === 'string' ? JSON.parse(row.config) : row.config,
    };
  } catch (err) {
    logger.error({ err, integrationId, orgId }, 'Failed to load integration');
    return null;
  }
}

// ============================================================================
// Database helpers — update notification status
// ============================================================================

async function updateNotificationStatus(
  notificationId: string,
  status: 'sent' | 'failed',
  result: DispatchResult,
): Promise<void> {
  try {
    if (status === 'sent') {
      await query(
        `UPDATE notifications
         SET status = 'sent', sent_at = NOW(), updated_at = NOW(),
             response_status = $2, response_body = $3, delivery_attempts = $4
         WHERE id = $1`,
        [notificationId, result.statusCode, result.responseBody.slice(0, 2000), result.attempts],
      );
    } else {
      await query(
        `UPDATE notifications
         SET status = 'failed', updated_at = NOW(),
             error_message = $2, response_status = $3, response_body = $4, delivery_attempts = $5
         WHERE id = $1`,
        [notificationId, result.error ?? 'Unknown error', result.statusCode, result.responseBody.slice(0, 2000), result.attempts],
      );
    }
  } catch (err) {
    logger.error({ err, notificationId, status }, 'Failed to update notification status in database');
  }
}

// ============================================================================
// Main Job Processor
// ============================================================================

/**
 * Maps from the integration type to the dispatch function.
 */
const channelDispatchers: Record<NotificationChannel, (
  jobData: NotificationJobData,
  integration: IntegrationConfig,
) => Promise<DispatchResult>> = {
  email: dispatchEmail,
  slack: dispatchSlack,
  teams: dispatchTeams,
  discord: dispatchDiscord,
  webhook: dispatchWebhookChannel,
};

async function processNotification(job: Job<NotificationJobData>): Promise<DispatchResult> {
  const jobData = job.data;
  const { notificationId, organizationId, integrationId, title, severity } = jobData;

  logger.info(
    {
      jobId: job.id,
      notificationId,
      organizationId,
      integrationId,
      channel: jobData.integrationConfig?.type ?? 'unknown',
      severity,
      title: title.slice(0, 100),
    },
    'Processing notification dispatch',
  );

  await job.updateProgress(10);

  // 1. Resolve integration config
  let integration = jobData.integrationConfig ?? null;
  if (!integration) {
    integration = await loadIntegration(integrationId, organizationId);
  }

  if (!integration) {
    const errorMsg = `Integration ${integrationId} not found or not available`;
    logger.error({ notificationId, integrationId, organizationId }, errorMsg);
    await job.updateProgress(100);
    // Mark as failed in DB even though we won't retry
    await updateNotificationStatus(notificationId, 'failed', {
      success: false,
      statusCode: null,
      responseBody: '',
      durationMs: 0,
      attempts: 1,
      error: errorMsg,
    });
    throw new Error(errorMsg);
  }

  if (!integration.enabled) {
    const errorMsg = `Integration ${integrationId} is disabled`;
    logger.warn({ notificationId, integrationId }, errorMsg);
    await updateNotificationStatus(notificationId, 'failed', {
      success: false,
      statusCode: null,
      responseBody: '',
      durationMs: 0,
      attempts: 1,
      error: errorMsg,
    });
    throw new Error(errorMsg);
  }

  await job.updateProgress(30);

  // 2. Validate channel type is supported
  const channel = integration.type;
  const dispatcher = channelDispatchers[channel];

  if (!dispatcher) {
    const errorMsg = `Unsupported notification channel: ${channel}`;
    logger.error({ notificationId, channel }, errorMsg);
    await updateNotificationStatus(notificationId, 'failed', {
      success: false,
      statusCode: null,
      responseBody: '',
      durationMs: 0,
      attempts: 1,
      error: errorMsg,
    });
    throw new Error(errorMsg);
  }

  await job.updateProgress(50);

  // 3. Dispatch with retry
  const result = await dispatchWithRetry(
    () => dispatcher(jobData, integration),
    channel,
    notificationId,
  );

  await job.updateProgress(90);

  // 4. Update notification status in database
  await updateNotificationStatus(
    notificationId,
    result.success ? 'sent' : 'failed',
    result,
  );

  await job.updateProgress(100);

  if (result.success) {
    logger.info(
      {
        notificationId,
        channel,
        statusCode: result.statusCode,
        durationMs: result.durationMs,
        attempts: result.attempts,
      },
      'Notification dispatched successfully',
    );
  } else {
    logger.error(
      {
        notificationId,
        channel,
        statusCode: result.statusCode,
        durationMs: result.durationMs,
        attempts: result.attempts,
        error: result.error,
      },
      'Notification dispatch failed after all retries',
    );
  }

  return result;
}

// ============================================================================
// Worker Bootstrap
// ============================================================================

const config = getConfig();

const connection = {
  host: config.REDIS_HOST,
  port: config.REDIS_PORT,
  password: config.REDIS_PASSWORD,
};

let worker: Worker<NotificationJobData, DispatchResult> | null = null;

export function createNotificationWorker(): Worker<NotificationJobData, DispatchResult> {
  if (worker) return worker;

  createRedisClient();

  worker = new Worker<NotificationJobData, DispatchResult>('notification', processNotification, {
    connection,
    concurrency: 8,
    limiter: {
      max: 10,
      duration: 1000, // 10 jobs per second per worker (complemented by in-memory token bucket)
    },
    // Retry is handled internally by dispatchWithRetry (3 retries, exponential backoff).
    // Job-level attempts/backoff are set on the Queue's defaultJobOptions when enqueuing.
  });

  // --- Event handlers ---

  worker.on('completed', (job) => {
    logger.info(
      {
        jobId: job?.id,
        notificationId: job?.data?.notificationId,
        channel: job?.data?.integrationConfig?.type,
      },
      'Notification job completed',
    );
  });

  worker.on('failed', (job, err) => {
    logger.error(
      {
        jobId: job?.id,
        notificationId: job?.data?.notificationId,
        channel: job?.data?.integrationConfig?.type,
        err: err.message,
        stack: err.stack?.slice(0, 500),
      },
      'Notification job failed after all attempts',
    );
  });

  worker.on('error', (err) => {
    logger.error({ err }, 'Notification worker error');
  });

  worker.on('active', (job) => {
    logger.debug(
      {
        jobId: job?.id,
        notificationId: job?.data?.notificationId,
      },
      'Notification job activated',
    );
  });

  logger.info({
    concurrency: 8,
    rateLimit: '10/sec',
    retryAttempts: 4,
    retryBackoff: 'exponential (2s base)',
  }, 'Notification worker created');

  return worker;
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

let shuttingDown = false;

export async function shutdownWorker(): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;

  logger.info('Shutting down notification worker...');

  if (worker) {
    // Close worker — waits for active jobs to finish (within a timeout)
    await worker.close(true); // force=true kills running jobs gracefully
    worker = null;
    logger.info('Notification worker closed');
  }

  await closeRedis();
  logger.info('Notification worker shutdown complete');
}

// ---------------------------------------------------------------------------
// Auto-start when run directly (node dist/workers/notification-worker.js)
// ---------------------------------------------------------------------------

const isMainModule = process.argv[1]?.endsWith('notification-worker.js')
  || process.argv[1]?.endsWith('notification-worker.ts');

if (isMainModule) {
  createNotificationWorker();

  // Handle graceful shutdown
  process.on('SIGTERM', async () => {
    logger.info('Received SIGTERM — shutting down notification worker');
    await shutdownWorker();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    logger.info('Received SIGINT — shutting down notification worker');
    await shutdownWorker();
    process.exit(0);
  });

  process.on('unhandledRejection', (reason) => {
    logger.error({ err: reason }, 'Unhandled rejection in notification worker');
  });

  process.on('uncaughtException', (err) => {
    logger.error({ err: err.message, stack: err.stack }, 'Uncaught exception in notification worker');
    shutdownWorker().finally(() => process.exit(1));
  });

  logger.info('Notification worker started in standalone mode');
}

// ============================================================================
// Helpers
// ============================================================================

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
