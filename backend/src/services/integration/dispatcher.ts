// ---------------------------------------------------------------------------
// Integration Notification Dispatcher
//
// Routes security events to all configured channels: Slack, Teams, Discord,
// email (SMTP), and generic webhooks.  Each platform receives properly
// formatted messages (Block Kit, Adaptive Card, rich embed, HTML email).
//
// Main entry points:
//   dispatchFindingAlert(finding, orgId)  — alert on a single finding
//   dispatchScanComplete(scanId, orgId)   — scan-completed notification
//   dispatchDigest(orgId, period)         — periodic digest (daily/weekly/monthly)
// ---------------------------------------------------------------------------

import * as http from 'node:http';
import * as https from 'node:https';
import * as crypto from 'node:crypto';
import { query } from '../../core/db/pool.js';
import { logger } from '../../core/logging/logger.js';
import { decrypt } from '../../core/encryption/cipher.js';
import { getConfig } from '../../config/index.js';
import { sendEmail } from '../notification/smtp-service.js';

// ============================================================================
// Types & Interfaces
// ============================================================================

export type IntegrationType = 'slack' | 'teams' | 'discord' | 'smtp' | 'webhook';
export type DigestPeriod = 'daily' | 'weekly' | 'monthly';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Severity-ordered list (most severe first). */
export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'] as const;

/**
 * Finding alert payload — the shape passed by the caller or fetched from DB.
 * Maps to the `findings` table columns.
 */
export interface FindingAlert {
  id: string;
  orgId: string;
  projectId: string;
  projectName?: string;
  scanId?: string;
  title: string;
  description?: string;
  severity: Severity;
  severityRank?: number;
  status?: string;
  confidence?: string;
  filePath?: string;
  lineNumber?: number;
  lineRange?: string;
  codeSnippet?: string;
  ruleId?: string;
  ruleName?: string;
  cweId?: string;
  cveId?: string;
  owaspCategory?: string;
  cvssScore?: number;
  cvssVector?: string;
  epssScore?: number;
  kevMatch?: boolean;
  recommendation?: string;
  referencesData?: unknown[];
  assignedTo?: string;
  assignedToName?: string;
  createdAt?: string;
  dashboardUrl?: string;
  endpoint?: string;
  httpMethod?: string;
}

/** Minimal finding row used for digest grouping. */
export interface DigestFinding {
  id: string;
  title: string;
  severity: Severity;
  severityRank?: number;
  cvssScore?: number;
  cweId?: string;
  filePath?: string;
  lineNumber?: number;
  projectId: string;
  projectName: string;
  createdAt?: string;
  dashboardUrl?: string;
}

/** A digest group by project + severity. */
export interface DigestGroup {
  projectId: string;
  projectName: string;
  severity: Severity;
  findings: DigestFinding[];
  count: number;
}

/** Per-channel dispatch outcome. */
export interface DispatchChannelResult {
  channel: string;
  integrationId: string;
  integrationName: string;
  success: boolean;
  statusCode: number | null;
  error?: string;
  durationMs: number;
}

/** Aggregate dispatch summary. */
export interface DispatchSummary {
  total: number;
  succeeded: number;
  failed: number;
  results: DispatchChannelResult[];
}

/** Integration row from the `integrations` table. */
interface IntegrationRow {
  id: string;
  org_id: string;
  type: IntegrationType;
  name: string;
  enabled: boolean;
  config: Record<string, unknown>;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

/** Decrypted, ready-to-use integration configuration. */
interface IntegrationChannel {
  integrationId: string;
  integrationName: string;
  type: IntegrationType;
  config: Record<string, unknown>;
  events: string[];
}

// ============================================================================
// Constants
// ============================================================================

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
  info: '#6b7280',
};

const DISCORD_EMBED_COLORS: Record<Severity, number> = {
  critical: 0xff0000,
  high: 0xffa500,
  medium: 0xffff00,
  low: 0x2563eb,
  info: 0x6b7280,
};

const SEVERITY_BG_COLORS: Record<Severity, string> = {
  critical: '#fef2f2',
  high: '#fff7ed',
  medium: '#fefce8',
  low: '#eff6ff',
  info: '#f9fafb',
};

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

const DEFAULT_TIMEOUT_MS = 10_000;
const SENSITIVE_CONFIG_FIELDS = new Set(['token', 'secret', 'apiKey', 'password']);

// ============================================================================
// Low-level helpers
// ============================================================================

/**
 * Decrypt a config value if it was stored as encrypted, otherwise return as-is.
 */
function decryptConfigField(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return decrypt(value);
  } catch {
    // Value wasn't encrypted — return raw
    return value;
  }
}

/**
 * Recursively decrypt sensitive fields in an integration config object.
 * Fields named 'token', 'secret', 'apiKey', 'password' may be encrypted.
 */
function decryptIntegrationConfig(config: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(config)) {
    if (SENSITIVE_CONFIG_FIELDS.has(key) && typeof value === 'string') {
      out[key] = decryptConfigField(value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

/**
 * Return an ISO timestamp string N days/weeks/months ago.
 */
function periodStartDate(period: DigestPeriod): string {
  const now = new Date();
  switch (period) {
    case 'daily':
      now.setDate(now.getDate() - 1);
      break;
    case 'weekly':
      now.setDate(now.getDate() - 7);
      break;
    case 'monthly':
      now.setMonth(now.getMonth() - 1);
      break;
  }
  return now.toISOString();
}

/**
 * Friendly label for the period, e.g. "Past 24 Hours", "Past 7 Days".
 */
function periodLabel(period: DigestPeriod): string {
  switch (period) {
    case 'daily':
      return 'Past 24 Hours';
    case 'weekly':
      return 'Past 7 Days';
    case 'monthly':
      return 'Past 30 Days';
  }
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================================================
// HTTP POST (mirrors the pattern from webhook-service.ts)
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
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
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
        'User-Agent': 'AppSec-Integration-Dispatcher/1.0',
        ...headers,
      },
      timeout: timeoutMs,
    };

    const req = mod.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode ?? null,
          responseBody: Buffer.concat(chunks).toString('utf8'),
          duration: Date.now() - start,
        });
      });
      res.on('error', () => {
        resolve({ statusCode: null, responseBody: 'Response stream error', duration: Date.now() - start });
      });
    });

    req.on('error', (err: Error) => {
      resolve({ statusCode: null, responseBody: err.message, duration: Date.now() - start });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({ statusCode: null, responseBody: 'Request timed out', duration: Date.now() - start });
    });

    req.write(payload);
    req.end();
  });
}

// ============================================================================
// Database queries
// ============================================================================

/**
 * Fetch all enabled notification-channel integrations for an org.
 * Only returns types that can receive alerts (slack, teams, discord, smtp, webhook).
 */
async function fetchIntegrations(orgId: string): Promise<IntegrationChannel[]> {
  const types: IntegrationType[] = ['slack', 'teams', 'discord', 'smtp', 'webhook'];
  const result = await query<IntegrationRow>(
    `SELECT id, org_id, type, name, enabled, config, created_by, created_at, updated_at
     FROM integrations
     WHERE org_id = $1
       AND enabled = true
       AND deleted_at IS NULL
       AND type = ANY($2::text[])
     ORDER BY type, name`,
    [orgId, types],
  );

  return result.rows.map((row) => {
    const rawConfig =
      typeof row.config === 'string' ? JSON.parse(row.config) : (row.config ?? {});
    const config = decryptIntegrationConfig(rawConfig as Record<string, unknown>);
    const events: string[] = Array.isArray(config.events) ? (config.events as string[]) : [];
    return {
      integrationId: row.id,
      integrationName: row.name,
      type: row.type,
      config,
      events,
    };
  });
}

/**
 * Fetch scan details and severity breakdown from the `scans` and `findings` tables.
 */
async function fetchScanSummary(scanId: string, orgId: string): Promise<{
  scan: Record<string, unknown>;
  counts: Record<Severity, number>;
  totalFindings: number;
} | null> {
  const scanResult = await query<Record<string, unknown>>(
    `SELECT s.*, p.name AS project_name
     FROM scans s
     JOIN projects p ON s.project_id = p.id
     WHERE s.id = $1 AND s.org_id = $2`,
    [scanId, orgId],
  );
  if (scanResult.rows.length === 0) return null;
  const scan = scanResult.rows[0] as Record<string, unknown>;

  // Count findings per severity for this scan
  const countResult = await query<{ severity: string; count: string }>(
    `SELECT severity, COUNT(*)::text AS count
     FROM findings
     WHERE scan_id = $1 AND org_id = $2
     GROUP BY severity
     ORDER BY severity`,
    [scanId, orgId],
  );

  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let totalFindings = 0;
  for (const row of countResult.rows) {
    const sev = row.severity as Severity;
    const n = parseInt(row.count, 10);
    if (SEVERITY_ORDER.includes(sev)) {
      counts[sev] = n;
    }
    totalFindings += n;
  }

  return { scan, counts, totalFindings };
}

/**
 * Fetch digest findings for an org within a given time period, grouped by project.
 */
async function fetchDigestData(orgId: string, period: DigestPeriod): Promise<{
  groups: DigestGroup[];
  totalFindings: number;
  periodStart: string;
  periodEnd: string;
}> {
  const startIso = periodStartDate(period);
  const endIso = new Date().toISOString();

  const result = await query<Record<string, unknown>>(
    `SELECT f.id, f.title, f.severity, f.severity_rank, f.cvss_score,
            f.cwe_id, f.file_path, f.line_number, f.project_id,
            f.created_at, p.name AS project_name
     FROM findings f
     JOIN projects p ON f.project_id = p.id
     WHERE f.org_id = $1
       AND f.created_at >= $2
       AND f.status NOT IN ('closed', 'false_positive', 'wont_fix')
     ORDER BY f.severity_rank ASC, f.created_at DESC`,
    [orgId, startIso],
  );

  const findings: DigestFinding[] = result.rows.map((row) => ({
    id: row.id as string,
    title: row.title as string,
    severity: (row.severity as Severity) ?? 'info',
    severityRank: row.severity_rank != null ? Number(row.severity_rank) : undefined,
    cvssScore: row.cvss_score != null ? Number(row.cvss_score) : undefined,
    cweId: row.cwe_id as string | undefined,
    filePath: row.file_path as string | undefined,
    lineNumber: row.line_number != null ? Number(row.line_number) : undefined,
    projectId: row.project_id as string,
    projectName: row.project_name as string,
    createdAt: row.created_at as string | undefined,
    dashboardUrl: dashboardFindingUrl(orgId, row.project_id as string, row.id as string),
  }));

  // Group by severity then project
  const seen = new Map<string, DigestGroup>();
  for (const f of findings) {
    const key = `${f.projectId}::${f.severity}`;
    let group = seen.get(key);
    if (!group) {
      group = {
        projectId: f.projectId,
        projectName: f.projectName,
        severity: f.severity,
        findings: [],
        count: 0,
      };
      seen.set(key, group);
    }
    group.findings.push(f);
    group.count++;
  }

  // Sort groups: by severity rank, then project name
  const groups = Array.from(seen.values()).sort((a, b) => {
    const rankA = SEVERITY_ORDER.indexOf(a.severity);
    const rankB = SEVERITY_ORDER.indexOf(b.severity);
    if (rankA !== rankB) return rankA - rankB;
    return a.projectName.localeCompare(b.projectName);
  });

  return {
    groups,
    totalFindings: findings.length,
    periodStart: startIso,
    periodEnd: endIso,
  };
}

// ============================================================================
// Dashboard URL builder
// ============================================================================

function dashboardFindingUrl(orgId: string, projectId: string, findingId: string): string {
  const config = getConfig();
  const baseUrl = config.SCANNER_API_URL.replace(/\/+$/, '');
  return `${baseUrl}/dashboard/projects/${projectId}/findings/${findingId}?orgId=${orgId}`;
}

function dashboardProjectUrl(_orgId: string, projectId: string): string {
  const config = getConfig();
  const baseUrl = config.SCANNER_API_URL.replace(/\/+$/, '');
  return `${baseUrl}/dashboard/projects/${projectId}`;
}

function dashboardScanUrl(orgId: string, scanId: string): string {
  const config = getConfig();
  const baseUrl = config.SCANNER_API_URL.replace(/\/+$/, '');
  return `${baseUrl}/dashboard/scans/${scanId}?orgId=${orgId}`;
}

// ============================================================================
// Platform-specific severity badge / color helpers
// ============================================================================

function severityBadgeHtml(severity: Severity): string {
  const color = SEVERITY_COLORS[severity] || '#6b7280';
  const bg = SEVERITY_BG_COLORS[severity] || '#f9fafb';
  const label = SEVERITY_LABELS[severity] || severity;
  return `<span style="display:inline-block;padding:4px 12px;border-radius:12px;background-color:${bg};color:${color};font-weight:600;font-size:13px;border:1px solid ${color};">${escapeHtml(label)}</span>`;
}

function slackSeverityText(severity: Severity): string {
  const labels: Record<Severity, string> = {
    critical: ':red_circle: Critical',
    high: ':orange_circle: High',
    medium: ':large_yellow_circle: Medium',
    low: ':large_blue_circle: Low',
    info: ':information_source: Info',
  };
  return labels[severity] || severity;
}

// ============================================================================
// Slack Format — Block Kit
// ============================================================================

export function formatSlackMessage(finding: FindingAlert): Record<string, unknown> {
  const severityEmoji = slackSeverityText(finding.severity);
  const color = SEVERITY_COLORS[finding.severity] || '#6b7280';

  const blocks: Record<string, unknown>[] = [];

  // Header
  blocks.push({
    type: 'header',
    text: {
      type: 'plain_text',
      text: `[${SEVERITY_LABELS[finding.severity].toUpperCase()}] ${finding.title}`,
      emoji: true,
    },
  });

  // Divider
  blocks.push({ type: 'divider' });

  // Severity + Project section
  const fields: Record<string, unknown>[] = [
    { type: 'mrkdwn', text: `*Severity:*\n${severityEmoji}` },
    { type: 'mrkdwn', text: `*Project:*\n${escapeHtml(finding.projectName || 'Unknown')}` },
  ];

  if (finding.cweId) {
    fields.push({ type: 'mrkdwn', text: `*CWE:*\n${escapeHtml(finding.cweId)}` });
  }
  if (finding.cvssScore !== undefined && finding.cvssScore !== null) {
    let cvssIcon = '';
    if (finding.cvssScore >= 9.0) cvssIcon = ':red_circle:';
    else if (finding.cvssScore >= 7.0) cvssIcon = ':orange_circle:';
    else if (finding.cvssScore >= 4.0) cvssIcon = ':large_yellow_circle:';
    else cvssIcon = ':large_blue_circle:';
    fields.push({ type: 'mrkdwn', text: `*CVSS:*\n${cvssIcon} ${finding.cvssScore.toFixed(1)} / 10.0` });
  }
  if (finding.owaspCategory) {
    fields.push({ type: 'mrkdwn', text: `*OWASP:*\n${escapeHtml(finding.owaspCategory)}` });
  }

  blocks.push({ type: 'section', fields });

  // File location
  if (finding.filePath) {
    const location = `\`${escapeHtml(finding.filePath)}${finding.lineNumber ? `:${finding.lineNumber}` : ''}\``;
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*Location:*\n${location}` } });
  }

  // Description
  if (finding.description) {
    const desc = finding.description.length > 500
      ? finding.description.slice(0, 500) + '...'
      : finding.description;
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*Description:*\n${escapeHtml(desc)}` } });
  }

  // Rule
  if (finding.ruleName) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*Rule:* ${escapeHtml(finding.ruleName)}` } });
  }

  // Recommendation
  if (finding.recommendation) {
    const rec =
      finding.recommendation.length > 500
        ? finding.recommendation.slice(0, 500) + '...'
        : finding.recommendation;
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*Recommendation:*\n${escapeHtml(rec)}` } });
  }

  // Divider before actions
  blocks.push({ type: 'divider' });

  // Action buttons
  const actions: Record<string, unknown>[] = [];
  const dashboardUrl = finding.dashboardUrl || dashboardFindingUrl(finding.orgId, finding.projectId, finding.id);
  actions.push({
    type: 'button',
    text: { type: 'plain_text', text: 'View in Dashboard', emoji: true },
    url: dashboardUrl,
    style: 'primary',
  });
  actions.push({
    type: 'button',
    text: { type: 'plain_text', text: 'Acknowledge', emoji: true },
    value: `ack:${finding.id}`,
  });

  blocks.push({
    type: 'actions',
    elements: actions,
  });

  // Context footer
  blocks.push({
    type: 'context',
    elements: [
      {
        type: 'mrkdwn',
        text: `:zap: AppSec Platform · Finding ID: \`${finding.id.slice(0, 8)}\` · ${new Date().toISOString()}`,
      },
    ],
  });

  return {
    text: `[${SEVERITY_LABELS[finding.severity].toUpperCase()}] ${finding.title}`, // fallback
    attachments: [
      {
        color,
        blocks,
      },
    ],
  };
}

// ============================================================================
// Teams Format — Adaptive Card
// ============================================================================

export function formatTeamsMessage(finding: FindingAlert): Record<string, unknown> {
  const dashboardUrl = finding.dashboardUrl || dashboardFindingUrl(finding.orgId, finding.projectId, finding.id);

  const body: Record<string, unknown>[] = [
    // Severity header with color accent
    {
      type: 'ColumnSet',
      columns: [
        {
          type: 'Column',
          width: '6px',
          items: [
            {
              type: 'TextBlock',
              text: ' ',
              color: finding.severity === 'critical' ? 'attention' : finding.severity === 'high' ? 'warning' : 'default',
              height: 'stretch',
            },
          ],
        },
        {
          type: 'Column',
          width: 'stretch',
          items: [
            {
              type: 'TextBlock',
              text: `[${SEVERITY_LABELS[finding.severity]}] ${finding.title}`,
              weight: 'bolder',
              size: 'large',
              wrap: true,
              spacing: 'none',
            },
            {
              type: 'TextBlock',
              text: finding.projectName || 'Unknown Project',
              isSubtle: true,
              wrap: true,
              spacing: 'none',
            },
          ],
        },
      ],
    },
    { type: 'FactSet', facts: [] as Record<string, unknown>[] },
  ];

  // Build facts
  const factSet = body[1] as { type: string; facts: Record<string, unknown>[] };
  factSet.facts = [
    { title: 'Severity', value: SEVERITY_LABELS[finding.severity] },
    { title: 'Project', value: finding.projectName || 'Unknown' },
  ];

  if (finding.cweId) {
    factSet.facts.push({ title: 'CWE', value: finding.cweId });
  }
  if (finding.cvssScore !== undefined && finding.cvssScore !== null) {
    factSet.facts.push({ title: 'CVSS Score', value: `${finding.cvssScore.toFixed(1)} / 10.0` });
  }
  if (finding.cvssVector) {
    factSet.facts.push({ title: 'CVSS Vector', value: finding.cvssVector });
  }
  if (finding.owaspCategory) {
    factSet.facts.push({ title: 'OWASP Category', value: finding.owaspCategory });
  }
  if (finding.ruleName) {
    factSet.facts.push({ title: 'Rule', value: finding.ruleName });
  }
  if (finding.filePath) {
    const location = `${finding.filePath}${finding.lineNumber ? `:${finding.lineNumber}` : ''}`;
    factSet.facts.push({ title: 'File', value: location });
  }
  if (finding.endpoint) {
    factSet.facts.push({ title: 'Endpoint', value: finding.endpoint });
  }
  if (finding.httpMethod) {
    factSet.facts.push({ title: 'Method', value: finding.httpMethod });
  }
  if (finding.status) {
    factSet.facts.push({ title: 'Status', value: finding.status });
  }

  // Description
  if (finding.description) {
    body.push({
      type: 'TextBlock',
      text: finding.description,
      wrap: true,
      spacing: 'medium',
    });
  }

  // Code snippet (truncated)
  if (finding.codeSnippet) {
    const snippet = finding.codeSnippet.length > 1000
      ? finding.codeSnippet.slice(0, 1000) + '...'
      : finding.codeSnippet;
    body.push({
      type: 'CodeBlock',
      codeSnippet: snippet,
      language: 'plaintext',
      spacing: 'medium',
    });
  }

  // Recommendation
  if (finding.recommendation) {
    body.push({
      type: 'TextBlock',
      text: `**Recommendation:** ${finding.recommendation}`,
      wrap: true,
      spacing: 'medium',
    });
  }

  // References
  if (finding.referencesData && finding.referencesData.length > 0) {
    const refLinks = (finding.referencesData as Array<{ url?: string; title?: string }>)
      .slice(0, 5)
      .map((r) => r.url || r.title || '')
      .filter(Boolean)
      .join('\n');
    if (refLinks) {
      body.push({
        type: 'TextBlock',
        text: `**References:**\n${refLinks}`,
        wrap: true,
        isSubtle: true,
        spacing: 'medium',
      });
    }
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
          msteams: {
            width: 'Full',
          },
          body,
          actions: [
            {
              type: 'Action.OpenUrl',
              title: 'View in Dashboard',
              url: dashboardUrl,
            },
          ],
        },
      },
    ],
  };
}

// ============================================================================
// Discord Format — Rich Embed
// ============================================================================

export function formatDiscordMessage(finding: FindingAlert): Record<string, unknown> {
  const color = DISCORD_EMBED_COLORS[finding.severity] || 0x6b7280;
  const dashboardUrl = finding.dashboardUrl || dashboardFindingUrl(finding.orgId, finding.projectId, finding.id);

  const fields: Record<string, unknown>[] = [];

  fields.push({
    name: 'Severity',
    value: SEVERITY_LABELS[finding.severity],
    inline: true,
  });
  fields.push({
    name: 'Project',
    value: finding.projectName || 'Unknown',
    inline: true,
  });

  if (finding.cweId) {
    fields.push({ name: 'CWE', value: finding.cweId, inline: true });
  }
  if (finding.cvssScore !== undefined && finding.cvssScore !== null) {
    fields.push({ name: 'CVSS Score', value: `${finding.cvssScore.toFixed(1)} / 10.0`, inline: true });
  }
  if (finding.owaspCategory) {
    fields.push({ name: 'OWASP', value: finding.owaspCategory, inline: true });
  }

  // File location as a separate field
  if (finding.filePath) {
    const location = `${finding.filePath}${finding.lineNumber ? `:${finding.lineNumber}` : ''}`;
    fields.push({
      name: 'File Location',
      value: location.length > 100 ? location.slice(0, 100) + '...' : location,
    });
  }

  if (finding.ruleName) {
    fields.push({
      name: 'Rule',
      value: finding.ruleName,
      inline: true,
    });
  }

  if (finding.status) {
    fields.push({
      name: 'Status',
      value: finding.status,
      inline: true,
    });
  }

  const embed: Record<string, unknown> = {
    title: finding.title,
    color,
    fields,
    timestamp: finding.createdAt || new Date().toISOString(),
    footer: {
      text: 'AppSec Platform',
      icon_url: undefined as string | undefined,
    },
    url: dashboardUrl,
  };

  if (finding.description) {
    embed.description = finding.description.length > 2048
      ? finding.description.slice(0, 2048) + '...'
      : finding.description;
  }

  // Add a separate recommendation field
  if (finding.recommendation) {
    (embed.fields as Record<string, unknown>[]).push({
      name: 'Recommendation',
      value: finding.recommendation.length > 1024
        ? finding.recommendation.slice(0, 1024) + '...'
        : finding.recommendation,
    });
  }

  return {
    embeds: [embed],
    username: 'AppSec Security Scanner',
    avatar_url: undefined as string | undefined,
  };
}

// ============================================================================
// Email Format — Full HTML
// ============================================================================

export function formatEmailMessage(finding: FindingAlert): string {
  const severity = finding.severity || 'info';
  const dashboardUrl = finding.dashboardUrl || dashboardFindingUrl(finding.orgId, finding.projectId, finding.id);

  const styles = `
    body { margin: 0; padding: 0; background-color: #f4f5f7; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }
    .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .header { padding: 24px 32px; }
    .header.critical { background: linear-gradient(135deg, #dc2626, #b91c1c); }
    .header.high { background: linear-gradient(135deg, #ea580c, #c2410c); }
    .header.medium { background: linear-gradient(135deg, #ca8a04, #a16207); }
    .header.low { background: linear-gradient(135deg, #2563eb, #1d4ed8); }
    .header.info { background: linear-gradient(135deg, #6b7280, #4b5563); }
    .header h1 { margin: 0; color: #ffffff; font-size: 22px; font-weight: 700; }
    .header p { margin: 4px 0 0; color: rgba(255,255,255,0.85); font-size: 14px; }
    .body { padding: 32px; }
    .section { margin-bottom: 24px; }
    .section-title { font-size: 14px; font-weight: 600; color: #374151; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
    .field-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f3f4f6; }
    .field-label { font-size: 14px; color: #6b7280; }
    .field-value { font-size: 14px; color: #111827; font-weight: 500; }
    .description { font-size: 14px; color: #374151; line-height: 1.6; background-color: #f9fafb; padding: 12px 16px; border-radius: 6px; border-left: 4px solid #6366f1; margin: 8px 0; }
    .remediation { font-size: 14px; color: #374151; line-height: 1.6; background-color: #f0fdf4; padding: 12px 16px; border-radius: 6px; border-left: 4px solid #22c55e; margin: 8px 0; }
    .code-block { font-size: 13px; color: #1e293b; line-height: 1.5; background-color: #f1f5f9; padding: 12px 16px; border-radius: 6px; font-family: 'SF Mono', 'Fira Code', monospace; white-space: pre-wrap; overflow-x: auto; border: 1px solid #e2e8f0; margin: 8px 0; }
    .btn { display: inline-block; padding: 12px 24px; background-color: #6366f1; color: #ffffff !important; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 14px; margin-top: 8px; }
    .btn:hover { background-color: #4f46f5; }
    .footer { padding: 24px 32px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af; text-align: center; }
    .footer a { color: #6366f1; }
  `.trim();

  const headerContent = `
    <h1>Security Finding: ${escapeHtml(finding.title)}</h1>
    <p>${severityBadgeHtml(severity)} &mdash; ${escapeHtml(finding.projectName || 'Unknown Project')}</p>
  `;

  const cweHtml = finding.cweId
    ? `<div class="field-row"><span class="field-label">CWE</span><span class="field-value">${escapeHtml(finding.cweId)}</span></div>`
    : '';
  const cveHtml = finding.cveId
    ? `<div class="field-row"><span class="field-label">CVE</span><span class="field-value">${escapeHtml(finding.cveId)}</span></div>`
    : '';
  const cvssHtml =
    finding.cvssScore !== undefined && finding.cvssScore !== null
      ? `<div class="field-row"><span class="field-label">CVSS Score</span><span class="field-value">${finding.cvssScore.toFixed(1)} / 10.0</span></div>`
      : '';
  const cvssVectorHtml = finding.cvssVector
    ? `<div class="field-row"><span class="field-label">CVSS Vector</span><span class="field-value" style="font-family:monospace;font-size:12px;">${escapeHtml(finding.cvssVector)}</span></div>`
    : '';
  const fileHtml = finding.filePath
    ? `<div class="field-row"><span class="field-label">File</span><span class="field-value" style="font-family:monospace;font-size:13px;">${escapeHtml(finding.filePath)}${finding.lineNumber ? `:${finding.lineNumber}` : ''}</span></div>`
    : '';
  const endpointHtml = finding.endpoint
    ? `<div class="field-row"><span class="field-label">Endpoint</span><span class="field-value" style="font-family:monospace;font-size:13px;">${escapeHtml(finding.httpMethod ? `${finding.httpMethod} ` : '')}${escapeHtml(finding.endpoint)}</span></div>`
    : '';
  const owaspHtml = finding.owaspCategory
    ? `<div class="field-row"><span class="field-label">OWASP</span><span class="field-value">${escapeHtml(finding.owaspCategory)}</span></div>`
    : '';
  const ruleHtml = finding.ruleName
    ? `<div class="field-row"><span class="field-label">Rule</span><span class="field-value">${escapeHtml(finding.ruleName)}</span></div>`
    : '';
  const statusHtml = finding.status
    ? `<div class="field-row"><span class="field-label">Status</span><span class="field-value">${escapeHtml(finding.status.replace(/_/g, ' '))}</span></div>`
    : '';

  const descriptionHtml = finding.description
    ? `<div class="section"><div class="section-title">Description</div><div class="description">${escapeHtml(finding.description)}</div></div>`
    : '';

  const codeHtml = finding.codeSnippet
    ? `<div class="section"><div class="section-title">Code Location</div><div class="code-block">${escapeHtml(finding.codeSnippet)}</div></div>`
    : '';

  const remediationHtml = finding.recommendation
    ? `<div class="section"><div class="section-title">Remediation Recommendation</div><div class="remediation">${escapeHtml(finding.recommendation)}</div></div>`
    : '';

  const referencesHtml =
    finding.referencesData && finding.referencesData.length > 0
      ? `<div class="section"><div class="section-title">References</div>
         ${(finding.referencesData as Array<{ url?: string; title?: string }>)
           .slice(0, 5)
           .map((ref) => {
             const link = ref.url || '#';
             const text = ref.title || ref.url || 'Reference';
             return `<div style="font-size:13px;padding:2px 0;"><a href="${escapeHtml(link)}" style="color:#6366f1;">${escapeHtml(text)}</a></div>`;
           })
           .join('')}
         </div>`
      : '';

  const bodyContent = `
    <div class="section">
      <div class="section-title">Finding Details</div>
      <div class="field-row"><span class="field-label">Severity</span><span class="field-value">${severityBadgeHtml(severity)}</span></div>
      <div class="field-row"><span class="field-label">Project</span><span class="field-value">${escapeHtml(finding.projectName || 'Unknown')}</span></div>
      ${cweHtml}
      ${cveHtml}
      ${cvssHtml}
      ${cvssVectorHtml}
      ${owaspHtml}
      ${ruleHtml}
      ${fileHtml}
      ${endpointHtml}
      ${statusHtml}
    </div>
    ${descriptionHtml}
    ${codeHtml}
    ${remediationHtml}
    ${referencesHtml}
    <div style="text-align:center;margin-top:24px;">
      <a href="${escapeHtml(dashboardUrl)}" class="btn">View in Dashboard</a>
    </div>
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>${styles}</style>
</head>
<body>
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:24px 0;">
    <tr>
      <td align="center">
        <div class="container">
          <div class="header ${severity}">
            ${headerContent}
          </div>
          <div class="body">
            ${bodyContent}
          </div>
          <div class="footer">
            <p>AppSec Platform &mdash; Automated Security Scanning</p>
            <p style="margin-top:4px;">
              <a href="[unsubscribe_url]">Unsubscribe</a> &middot;
              <a href="[preferences_url]">Notification Preferences</a>
            </p>
          </div>
        </div>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ============================================================================
// Email format for digest
// ============================================================================

function formatDigestEmailHtml(
  _orgId: string,
  groups: DigestGroup[],
  totalFindings: number,
  periodStart: string,
  periodEnd: string,
  period: DigestPeriod,
): string {
  const periodLabelStr = periodLabel(period);
  const startDate = new Date(periodStart).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  const endDate = new Date(periodEnd).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

  const styles = `
    body { margin:0; padding:0; background-color:#f4f5f7; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif; }
    .container { max-width:600px; margin:0 auto; background-color:#ffffff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.1); }
    .header { padding:24px 32px; background:linear-gradient(135deg,#6366f1,#4f46e5); }
    .header h1 { margin:0; color:#ffffff; font-size:22px; font-weight:700; }
    .header p { margin:4px 0 0; color:rgba(255,255,255,0.85); font-size:14px; }
    .body { padding:32px; }
    .section { margin-bottom:24px; }
    .section-title { font-size:14px; font-weight:600; color:#374151; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:8px; }
    .group-title { font-size:15px; font-weight:700; color:#111827; margin:16px 0 8px; padding-bottom:4px; border-bottom:2px solid #e5e7eb; }
    .finding-item { padding:10px 12px; margin:4px 0; background:#f9fafb; border-radius:6px; border-left:4px solid #6366f1; }
    .finding-title { font-size:14px; font-weight:600; color:#111827; }
    .finding-meta { font-size:12px; color:#6b7280; margin-top:2px; }
    .badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; color:#fff; }
    .badge.critical { background:#dc2626; }
    .badge.high { background:#ea580c; }
    .badge.medium { background:#ca8a04; }
    .badge.low { background:#2563eb; }
    .badge.info { background:#6b7280; }
    .summary-row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #f3f4f6; }
    .summary-label { font-size:14px; color:#6b7280; }
    .summary-value { font-size:18px; font-weight:700; color:#111827; }
    .footer { padding:24px 32px; background-color:#f9fafb; border-top:1px solid #e5e7eb; font-size:12px; color:#9ca3af; text-align:center; }
    .footer a { color:#6366f1; }
  `.trim();

  // Summary section
  const severityCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const g of groups) {
    severityCounts[g.severity] += g.count;
  }

  const summaryBars = SEVERITY_ORDER
    .filter((s) => severityCounts[s] > 0)
    .map((s) => {
      const color = SEVERITY_COLORS[s];
      return `<div class="summary-row">
        <span class="summary-label"><span class="badge ${s}">${SEVERITY_LABELS[s]}</span></span>
        <span class="summary-value" style="color:${color};">${severityCounts[s]}</span>
      </div>`;
    })
    .join('');

  // Group sections
  const groupsHtml = groups
    .map((g) => {
      const items = g.findings
        .slice(0, 20)
        .map((f) => {
          const loc = f.filePath
            ? ` &middot; <code style="font-size:11px;color:#6b7280;">${escapeHtml(f.filePath)}${f.lineNumber ? `:${f.lineNumber}` : ''}</code>`
            : '';
          const cvss = f.cvssScore !== undefined && f.cvssScore !== null
            ? ` &middot; CVSS ${f.cvssScore.toFixed(1)}`
            : '';
          return `<div class="finding-item" style="border-left-color:${SEVERITY_COLORS[g.severity]}">
            <div class="finding-title">
              <a href="${f.dashboardUrl || '#'}" style="color:#6366f1;text-decoration:none;">${escapeHtml(f.title)}</a>
            </div>
            <div class="finding-meta">${escapeHtml(f.projectName)}${loc}${cvss}</div>
          </div>`;
        })
        .join('');

      const overflow = g.count > 20
        ? `<p style="font-size:13px;color:#6b7280;margin:4px 0;">... and ${g.count - 20} more findings</p>`
        : '';

      const badgeColor = SEVERITY_COLORS[g.severity];
      return `<div class="group-title" style="border-bottom-color:${badgeColor};">
        <span class="badge ${g.severity}" style="margin-right:8px;">${SEVERITY_LABELS[g.severity]}</span>
        ${escapeHtml(g.projectName)} (${g.count})
      </div>
      ${items}
      ${overflow}`;
    })
    .join('');

  const bodyContent = `
    <div class="section">
      <div class="section-title">Summary</div>
      <div class="summary-row">
        <span class="summary-label">Period</span>
        <span class="summary-value" style="font-size:14px;font-weight:500;">${escapeHtml(startDate)} &ndash; ${escapeHtml(endDate)}</span>
      </div>
      <div class="summary-row">
        <span class="summary-label">Total Open Findings</span>
        <span class="summary-value" style="font-size:22px;">${totalFindings}</span>
      </div>
      ${summaryBars}
    </div>
    ${groupsHtml}
    <div style="text-align:center;margin-top:24px;padding-top:16px;border-top:1px solid #e5e7eb;">
      <p style="font-size:13px;color:#6b7280;">
        This is an automated ${period} digest from AppSec Platform.
        <a href="[preferences_url]" style="color:#6366f1;">Manage notifications</a>
      </p>
    </div>
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>${styles}</style>
</head>
<body>
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:24px 0;">
    <tr>
      <td align="center">
        <div class="container">
          <div class="header">
            <h1>Security Digest</h1>
            <p>${escapeHtml(periodLabelStr)} &middot; ${escapeHtml(startDate)} &ndash; ${escapeHtml(endDate)}</p>
          </div>
          <div class="body">
            ${bodyContent}
          </div>
          <div class="footer">
            <p>AppSec Platform &mdash; Automated Security Scanning</p>
            <p style="margin-top:4px;">
              <a href="[unsubscribe_url]">Unsubscribe</a> &middot;
              <a href="[preferences_url]">Notification Preferences</a>
            </p>
          </div>
        </div>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ============================================================================
// Integration dispatch — individual channel send
// ============================================================================

/**
 * Send a finding alert to a single configured integration channel.
 */
async function sendToChannel(
  channel: IntegrationChannel,
  finding: FindingAlert,
): Promise<DispatchChannelResult> {
  const start = Date.now();
  const baseResult: Omit<DispatchChannelResult, 'success' | 'statusCode' | 'error' | 'durationMs'> = {
    channel: channel.type,
    integrationId: channel.integrationId,
    integrationName: channel.integrationName,
  };

  try {
    switch (channel.type) {
      case 'slack': {
        const webhookUrl = channel.config.webhookUrl as string | undefined;
        if (!webhookUrl) throw new Error('Slack integration missing webhookUrl');
        const payload = JSON.stringify(formatSlackMessage(finding));
        const resp = await httpPost(webhookUrl, payload, {}, DEFAULT_TIMEOUT_MS);
        return {
          ...baseResult,
          success: resp.statusCode !== null && resp.statusCode >= 200 && resp.statusCode < 300,
          statusCode: resp.statusCode,
          error: resp.statusCode !== null && resp.statusCode >= 300 ? resp.responseBody.slice(0, 500) : undefined,
          durationMs: Date.now() - start,
        };
      }

      case 'teams': {
        const webhookUrl = channel.config.webhookUrl as string | undefined;
        if (!webhookUrl) throw new Error('Teams integration missing webhookUrl');
        const payload = JSON.stringify(formatTeamsMessage(finding));
        const resp = await httpPost(webhookUrl, payload, {}, DEFAULT_TIMEOUT_MS);
        return {
          ...baseResult,
          success: resp.statusCode !== null && resp.statusCode >= 200 && resp.statusCode < 300,
          statusCode: resp.statusCode,
          error: resp.statusCode !== null && resp.statusCode >= 300 ? resp.responseBody.slice(0, 500) : undefined,
          durationMs: Date.now() - start,
        };
      }

      case 'discord': {
        const webhookUrl = channel.config.webhookUrl as string | undefined;
        if (!webhookUrl) throw new Error('Discord integration missing webhookUrl');
        const payload = JSON.stringify(formatDiscordMessage(finding));
        const resp = await httpPost(webhookUrl, payload, {}, DEFAULT_TIMEOUT_MS);
        return {
          ...baseResult,
          success: resp.statusCode !== null && resp.statusCode >= 200 && resp.statusCode < 300,
          statusCode: resp.statusCode,
          error: resp.statusCode !== null && resp.statusCode >= 300 ? resp.responseBody.slice(0, 500) : undefined,
          durationMs: Date.now() - start,
        };
      }

      case 'smtp': {
        // Find recipients from the integration config or fall back to all org users
        const recipients = channel.config.recipients as string[] | string | undefined;
        let to: string[];
        if (Array.isArray(recipients) && recipients.length > 0) {
          to = recipients;
        } else if (typeof recipients === 'string' && recipients.trim()) {
          to = recipients.split(/[,\s;]+/).filter(Boolean);
        } else {
          // Fall back to querying all users in the org
          const usersResult = await query<{ email: string }>(
            `SELECT email FROM users WHERE org_id = $1 AND deleted_at IS NULL AND disabled = false`,
            [finding.orgId],
          );
          to = usersResult.rows.map((r) => r.email);
        }

        if (to.length === 0) {
          throw new Error('No email recipients configured or found for org');
        }

        const html = formatEmailMessage(finding);
        const subject = `[${SEVERITY_LABELS[finding.severity]}] Security Finding: ${finding.title}`;

        const emailResult = await sendEmail({
          to,
          subject,
          html,
          text: `[${SEVERITY_LABELS[finding.severity].toUpperCase()}] ${finding.title}\nProject: ${finding.projectName || 'Unknown'}\n${finding.filePath ? `File: ${finding.filePath}${finding.lineNumber ? `:${finding.lineNumber}` : ''}\n` : ''}\n${finding.description || ''}\n\nRemediation: ${finding.recommendation || 'Not provided'}\n\nDashboard: ${finding.dashboardUrl || dashboardFindingUrl(finding.orgId, finding.projectId, finding.id)}`,
          headers: {
            'X-AppSec-Finding-ID': finding.id,
            'X-AppSec-Severity': finding.severity,
            'X-AppSec-Entity': 'security-alert',
            Priority: finding.severity === 'critical' || finding.severity === 'high' ? 'urgent' : 'normal',
          },
        });

        return {
          ...baseResult,
          success: emailResult.accepted.length > 0,
          statusCode: emailResult.accepted.length > 0 ? 200 : null,
          error: emailResult.rejected.length > 0 ? `Recipients rejected: ${emailResult.rejected.join(', ')}` : undefined,
          durationMs: Date.now() - start,
        };
      }

      case 'webhook': {
        const url = channel.config.url as string | undefined;
        if (!url) throw new Error('Webhook integration missing url');

        // Build a generic webhook payload similar to the webhook-service envelope
        const payload = JSON.stringify({
          eventType: 'finding.alert',
          timestamp: new Date().toISOString(),
          orgId: finding.orgId,
          data: {
            finding: {
              id: finding.id,
              title: finding.title,
              severity: finding.severity,
              severityRank: finding.severityRank,
              cweId: finding.cweId,
              cveId: finding.cveId,
              cvssScore: finding.cvssScore,
              cvssVector: finding.cvssVector,
              filePath: finding.filePath,
              lineNumber: finding.lineNumber,
              description: finding.description,
              recommendation: finding.recommendation,
              projectId: finding.projectId,
              projectName: finding.projectName,
              dashboardUrl: finding.dashboardUrl || dashboardFindingUrl(finding.orgId, finding.projectId, finding.id),
            },
          },
        });

        // Build custom headers
        const customHeaders: Record<string, string> = {};
        const configHeaders = channel.config.headers as Record<string, string> | undefined;
        if (configHeaders) {
          Object.assign(customHeaders, configHeaders);
        }

        // Add HMAC signature if secret is configured
        const secret = channel.config.secret as string | undefined;
        if (secret) {
          const sig = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
          customHeaders['X-AppSec-Signature'] = sig;
        }

        const resp = await httpPost(url, payload, customHeaders, DEFAULT_TIMEOUT_MS);
        return {
          ...baseResult,
          success: resp.statusCode !== null && resp.statusCode >= 200 && resp.statusCode < 300,
          statusCode: resp.statusCode,
          error: resp.statusCode !== null && resp.statusCode >= 300 ? resp.responseBody.slice(0, 500) : undefined,
          durationMs: Date.now() - start,
        };
      }

      default:
        throw new Error(`Unsupported integration type: ${channel.type}`);
    }
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    logger.error(
      { err, integrationId: channel.integrationId, integrationName: channel.integrationName, type: channel.type },
      'Integration dispatch failed',
    );
    return {
      ...baseResult,
      success: false,
      statusCode: null,
      error: errorMsg,
      durationMs: Date.now() - start,
    };
  }
}

// ============================================================================
// Finding digest HTML -> plain-text conversion (helper for email fallback)
// ============================================================================

function digestToPlainText(
  groups: DigestGroup[],
  totalFindings: number,
  periodStart: string,
  periodEnd: string,
  period: DigestPeriod,
): string {
  const lines: string[] = [
    `SECURITY DIGEST — ${periodLabel(period).toUpperCase()}`,
    `${new Date(periodStart).toLocaleDateString()} — ${new Date(periodEnd).toLocaleDateString()}`,
    '',
    `Total Open Findings: ${totalFindings}`,
    '',
  ];

  const severityCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const g of groups) {
    severityCounts[g.severity] += g.count;
  }
  for (const sev of SEVERITY_ORDER) {
    if (severityCounts[sev] > 0) {
      lines.push(`${SEVERITY_LABELS[sev].toUpperCase()}: ${severityCounts[sev]}`);
    }
  }
  lines.push('');

  for (const g of groups) {
    lines.push(`${SEVERITY_LABELS[g.severity].toUpperCase()} — ${g.projectName} (${g.count})`);
    for (const f of g.findings.slice(0, 20)) {
      const loc = f.filePath ? ` (${f.filePath}${f.lineNumber ? `:${f.lineNumber}` : ''})` : '';
      const cvss = f.cvssScore !== undefined && f.cvssScore !== null ? ` [CVSS: ${f.cvssScore.toFixed(1)}]` : '';
      lines.push(`  - ${f.title}${cvss}${loc}`);
    }
    if (g.count > 20) {
      lines.push(`  ... and ${g.count - 20} more`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ============================================================================
// Public API — dispatchFindingAlert
// ============================================================================

/**
 * Dispatch a finding alert to all enabled notification integrations for an org.
 *
 * Queries the `integrations` table for channels of type slack / teams / discord /
 * smtp / webhook, formats the finding per each platform's documented message
 * format, and dispatches to all in parallel.
 *
 * @param finding - The finding alert payload (from the caller or fetched from DB).
 * @param orgId   - The organisation whose integrations to use.
 * @returns Aggregate dispatch results across all channels.
 */
export async function dispatchFindingAlert(
  finding: FindingAlert,
  orgId: string,
): Promise<DispatchSummary> {
  logger.info(
    { findingId: finding.id, orgId, severity: finding.severity },
    'Dispatching finding alert',
  );

  const channels = await fetchIntegrations(orgId);

  // Filter channels by event subscription:
  // - 'finding.critical' matches critical/high findings
  // - 'finding.created' matches all
  // If no events are configured on the integration, dispatch all findings.
  const shouldSend = (ch: IntegrationChannel): boolean => {
    if (ch.events.length === 0) return true; // no filter — send all
    if (ch.events.includes('finding.created')) return true;
    if (ch.events.includes('finding.critical') && (finding.severity === 'critical' || finding.severity === 'high')) return true;
    return false;
  };

  const eligible = channels.filter(shouldSend);

  if (eligible.length === 0) {
    logger.info({ orgId, findingId: finding.id }, 'No integrations matched for finding alert');
    return { total: 0, succeeded: 0, failed: 0, results: [] };
  }

  // Dispatch to all channels in parallel
  const results = await Promise.all(
    eligible.map((ch) => sendToChannel(ch, finding)),
  );

  const succeeded = results.filter((r) => r.success).length;
  const failed = results.filter((r) => !r.success).length;

  logger.info(
    { orgId, findingId: finding.id, total: results.length, succeeded, failed },
    'Finding alert dispatch completed',
  );

  return { total: results.length, succeeded, failed, results };
}

// ============================================================================
// Public API — dispatchScanComplete
// ============================================================================

/**
 * Dispatch a scan-completion notification with finding counts by severity.
 *
 * Fetches scan details from the `scans` table (joined with `projects`) and
 * severity counts from `findings`.  Sends a formatted notification to all
 * enabled notification integrations.
 *
 * @param scanId - The ID of the completed scan.
 * @param orgId  - The organisation whose integrations to use.
 * @returns Aggregate dispatch results.
 */
export async function dispatchScanComplete(
  scanId: string,
  orgId: string,
): Promise<DispatchSummary> {
  logger.info({ scanId, orgId }, 'Dispatching scan complete notification');

  const summary = await fetchScanSummary(scanId, orgId);
  if (!summary) {
    logger.warn({ scanId, orgId }, 'Scan not found for dispatchScanComplete');
    return { total: 0, succeeded: 0, failed: 0, results: [] };
  }

  const { scan, counts, totalFindings } = summary;
  const channels = await fetchIntegrations(orgId);

  // Filter channels subscribing to 'scan.completed' — or send to all if no events configured
  const eligible = channels.filter((ch) => {
    if (ch.events.length === 0) return true;
    return ch.events.includes('scan.completed');
  });

  if (eligible.length === 0) {
    logger.info({ orgId, scanId }, 'No integrations matched for scan completed');
    return { total: 0, succeeded: 0, failed: 0, results: [] };
  }

  // Build a finding alert-like shape to reuse formatting functions
  const scanFinding: FindingAlert = {
    id: scanId,
    orgId,
    projectId: scan.project_id as string,
    projectName: scan.project_name as string | undefined,
    scanId,
    title: `Scan Complete: ${(scan.name as string) || 'Scan'}`,
    description: `Scan completed with ${totalFindings} finding${totalFindings === 1 ? '' : 's'}.\n`
      + `Critical: ${counts.critical}, High: ${counts.high}, Medium: ${counts.medium}, Low: ${counts.low}.`,
    severity: counts.critical > 0 ? 'critical' : counts.high > 0 ? 'high' : counts.medium > 0 ? 'medium' : 'info',
    severityRank: counts.critical > 0 ? 1 : counts.high > 0 ? 2 : counts.medium > 0 ? 3 : 5,
    status: 'resolved',
    filePath: undefined,
    recommendation: `Review the ${totalFindings} finding${totalFindings === 1 ? '' : 's'} in the dashboard for details.`,
    dashboardUrl: dashboardScanUrl(orgId, scanId),
    createdAt: scan.completed_at as string | undefined,
  };

  // Enrich description with severity counts
  if (totalFindings > 0) {
    const countLines = SEVERITY_ORDER
      .filter((s) => counts[s] > 0)
      .map((s) => `  ${SEVERITY_LABELS[s]}: ${counts[s]}`)
      .join('\n');
    scanFinding.description = `Scan completed with ${totalFindings} finding${totalFindings === 1 ? '' : 's'}:\n${countLines}`;
  }

  const results = await Promise.all(
    eligible.map((ch) => sendToChannel(ch, scanFinding)),
  );

  const succeeded = results.filter((r) => r.success).length;
  const failed = results.filter((r) => !r.success).length;

  logger.info(
    { scanId, orgId, totalFindings, total: results.length, succeeded, failed },
    'Scan complete dispatch completed',
  );

  return { total: results.length, succeeded, failed, results };
}

// ============================================================================
// Public API — dispatchDigest
// ============================================================================

/**
 * Generate a digest of all findings from a past period, grouped by severity
 * and project, and send the consolidated digest to all enabled notification
 * channels.
 *
 * @param orgId  - The organisation whose data and integrations to use.
 * @param period - One of 'daily', 'weekly', or 'monthly'.
 * @returns Aggregate dispatch results.
 */
export async function dispatchDigest(
  orgId: string,
  period: DigestPeriod,
): Promise<DispatchSummary> {
  logger.info({ orgId, period }, 'Dispatching digest');

  const digestData = await fetchDigestData(orgId, period);

  if (digestData.groups.length === 0) {
    logger.info({ orgId, period }, 'No findings in digest period — nothing to dispatch');
    return { total: 0, succeeded: 0, failed: 0, results: [] };
  }

  const channels = await fetchIntegrations(orgId);

  // Filter channels subscribing to 'digest' event — or send to all if no events
  const eligible = channels.filter((ch) => {
    if (ch.events.length === 0) return true;
    return ch.events.includes('digest');
  });

  if (eligible.length === 0) {
    logger.info({ orgId, period }, 'No integrations matched for digest');
    return { total: 0, succeeded: 0, failed: 0, results: [] };
  }

  // Build a top-severity finding for the title
  const topFinding: DigestFinding | undefined = digestData.groups[0]?.findings[0];

  // Dispatch to each channel in parallel
  const results = await Promise.all(
    eligible.map(async (ch) => {
      const start = Date.now();
      const baseResult: Omit<DispatchChannelResult, 'success' | 'statusCode' | 'error' | 'durationMs'> = {
        channel: ch.type,
        integrationId: ch.integrationId,
        integrationName: ch.integrationName,
      };

      try {
        switch (ch.type) {
          case 'slack':
          case 'teams':
          case 'discord': {
            // Format a summary finding alert and send
            const digestFinding: FindingAlert = {
              id: `digest-${period}-${orgId}`,
              orgId,
              projectId: digestData.groups[0]?.projectId || orgId,
              projectName: 'All Projects (Digest)',
              title: `Security Digest — ${periodLabel(period)}`,
              description: `Found ${digestData.totalFindings} open finding${digestData.totalFindings === 1 ? '' : 's'} in the ${periodLabel(period).toLowerCase()}.\n\n`
                + digestData.groups
                    .map((g) => `${SEVERITY_LABELS[g.severity]} — ${g.projectName}: ${g.count}`)
                    .join('\n'),
              severity: topFinding?.severity || 'info',
              severityRank: SEVERITY_ORDER.indexOf(topFinding?.severity || 'info'),
              dashboardUrl: dashboardProjectUrl(orgId, digestData.groups[0]?.projectId || orgId),
              createdAt: digestData.periodEnd,
            };

            let payload: string;
            let webhookUrl: string | undefined;

            switch (ch.type) {
              case 'slack':
                webhookUrl = ch.config.webhookUrl as string | undefined;
                if (!webhookUrl) throw new Error('Slack integration missing webhookUrl');
                payload = JSON.stringify(formatSlackMessage(digestFinding));
                break;
              case 'teams':
                webhookUrl = ch.config.webhookUrl as string | undefined;
                if (!webhookUrl) throw new Error('Teams integration missing webhookUrl');
                payload = JSON.stringify(formatTeamsMessage(digestFinding));
                break;
              case 'discord':
                webhookUrl = ch.config.webhookUrl as string | undefined;
                if (!webhookUrl) throw new Error('Discord integration missing webhookUrl');
                payload = JSON.stringify(formatDiscordMessage(digestFinding));
                break;
              default:
                throw new Error(`Unreachable: ${ch.type}`);
            }

            const resp = await httpPost(webhookUrl!, payload, {}, DEFAULT_TIMEOUT_MS);
            return {
              ...baseResult,
              success: resp.statusCode !== null && resp.statusCode >= 200 && resp.statusCode < 300,
              statusCode: resp.statusCode,
              error: resp.statusCode !== null && resp.statusCode >= 300 ? resp.responseBody.slice(0, 500) : undefined,
              durationMs: Date.now() - start,
            };
          }

          case 'smtp': {
            // Build recipients
            const recipients = ch.config.recipients as string[] | string | undefined;
            let to: string[];
            if (Array.isArray(recipients) && recipients.length > 0) {
              to = recipients;
            } else if (typeof recipients === 'string' && recipients.trim()) {
              to = recipients.split(/[,\s;]+/).filter(Boolean);
            } else {
              const usersResult = await query<{ email: string }>(
                `SELECT email FROM users WHERE org_id = $1 AND deleted_at IS NULL AND disabled = false`,
                [orgId],
              );
              to = usersResult.rows.map((r) => r.email);
            }

            if (to.length === 0) throw new Error('No email recipients configured for digest');

            const html = formatDigestEmailHtml(
              orgId,
              digestData.groups,
              digestData.totalFindings,
              digestData.periodStart,
              digestData.periodEnd,
              period,
            );
            const text = digestToPlainText(
              digestData.groups,
              digestData.totalFindings,
              digestData.periodStart,
              digestData.periodEnd,
              period,
            );

            const periodLabelStr = periodLabel(period);
            const emailResult = await sendEmail({
              to,
              subject: `Security Digest — ${periodLabelStr} (${digestData.totalFindings} findings)`,
              html,
              text,
              headers: {
                'X-AppSec-Entity': 'digest',
                'X-AppSec-Period': period,
                'Precedence': 'bulk',
                'List-Id': `<digest.${orgId}.appsec>`,
              },
            });

            return {
              ...baseResult,
              success: emailResult.accepted.length > 0,
              statusCode: emailResult.accepted.length > 0 ? 200 : null,
              error: emailResult.rejected.length > 0 ? `Recipients rejected: ${emailResult.rejected.join(', ')}` : undefined,
              durationMs: Date.now() - start,
            };
          }

          case 'webhook': {
            const url = ch.config.url as string | undefined;
            if (!url) throw new Error('Webhook integration missing url');

            const payload = JSON.stringify({
              eventType: 'digest',
              timestamp: new Date().toISOString(),
              orgId,
              period,
              data: {
                periodStart: digestData.periodStart,
                periodEnd: digestData.periodEnd,
                totalFindings: digestData.totalFindings,
                groups: digestData.groups.map((g) => ({
                  projectId: g.projectId,
                  projectName: g.projectName,
                  severity: g.severity,
                  count: g.count,
                })),
              },
            });

            const customHeaders: Record<string, string> = {};
            const configHeaders = ch.config.headers as Record<string, string> | undefined;
            if (configHeaders) Object.assign(customHeaders, configHeaders);

            const secret = ch.config.secret as string | undefined;
            if (secret) {
              const sig = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
              customHeaders['X-AppSec-Signature'] = sig;
            }

            const resp = await httpPost(url, payload, customHeaders, DEFAULT_TIMEOUT_MS);
            return {
              ...baseResult,
              success: resp.statusCode !== null && resp.statusCode >= 200 && resp.statusCode < 300,
              statusCode: resp.statusCode,
              error: resp.statusCode !== null && resp.statusCode >= 300 ? resp.responseBody.slice(0, 500) : undefined,
              durationMs: Date.now() - start,
            };
          }

          default:
            throw new Error(`Unsupported integration type: ${ch.type}`);
        }
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        logger.error(
          { err, integrationId: ch.integrationId, type: ch.type },
          'Digest dispatch failed per channel',
        );
        return {
          ...baseResult,
          success: false,
          statusCode: null,
          error: errorMsg,
          durationMs: Date.now() - start,
        };
      }
    }),
  );

  const succeeded = results.filter((r) => r.success).length;
  const failed = results.filter((r) => !r.success).length;

  logger.info(
    { orgId, period, totalFindings: digestData.totalFindings, total: results.length, succeeded, failed },
    'Digest dispatch completed',
  );

  return { total: results.length, succeeded, failed, results };
}
