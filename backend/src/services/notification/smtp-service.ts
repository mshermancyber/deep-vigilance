// Real nodemailer-based SMTP integration for AppSec Platform notifications
import nodemailer from 'nodemailer';
import type { SentMessageInfo, Transporter } from 'nodemailer';
import type Mail from 'nodemailer/lib/mailer';
import { getConfig } from '../../config/index.js';
import { logger } from '../../core/logging/logger.js';
import { getRedis } from '../../core/redis/client.js';

// ---------------------------------------------------------------------------
// Exported Interfaces
// ---------------------------------------------------------------------------

export interface EmailAttachment {
  filename: string;
  content?: Buffer | string;
  path?: string;
  contentType?: string;
  cid?: string;
}

export interface EmailOptions {
  to: string | string[];
  cc?: string | string[];
  bcc?: string | string[];
  subject: string;
  html?: string;
  text?: string;
  attachments?: EmailAttachment[];
  replyTo?: string;
  priority?: 'low' | 'normal' | 'high';
  headers?: Record<string, string>;
}

export interface SendEmailResult {
  messageId: string;
  accepted: string[];
  rejected: string[];
}

export interface SecurityAlertFinding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe?: string;
  cvssScore?: number;
  file?: string;
  line?: number;
  description?: string;
  remediation?: string;
  projectName?: string;
  projectId?: string;
  dashboardUrl?: string;
}

export interface ReportNotification {
  reportId: string;
  reportName: string;
  projectName: string;
  format: string;
  downloadUrl: string;
  generatedAt: Date;
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface DigestEmail {
  recipient: string;
  recipientName?: string;
  projectName: string;
  periodStart: Date;
  periodEnd: Date;
  findings: SecurityAlertFinding[];
  totalOpenFindings: number;
}

// ---------------------------------------------------------------------------
// SMTP Transport
// ---------------------------------------------------------------------------

let transport: Transporter<SentMessageInfo> | null = null;

function getSmtpConfig() {
  const config = getConfig();
  return {
    host: config.SMTP_HOST,
    port: config.SMTP_PORT,
    user: config.SMTP_USER,
    pass: config.SMTP_PASS,
    from: config.SMTP_FROM,
  };
}

export function createTransport(): Transporter<SentMessageInfo> {
  if (transport) return transport;

  const smtp = getSmtpConfig();
  const useAuth = smtp.user.length > 0 && smtp.pass.length > 0;

  transport = nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.port === 465,
    auth: useAuth
      ? {
          user: smtp.user,
          pass: smtp.pass,
        }
      : undefined,
    tls: {
      rejectUnauthorized: process.env.NODE_ENV === 'production',
    },
    // Timeouts
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 30_000,
  });

  logger.info(
    {
      host: smtp.host,
      port: smtp.port,
      auth: useAuth,
      secure: smtp.port === 465,
    },
    'SMTP transport created'
  );

  return transport;
}

export function closeTransport(): void {
  if (transport) {
    transport.close();
    transport = null;
    logger.info('SMTP transport closed');
  }
}

/**
 * Verify SMTP connection is working. Useful at startup.
 */
export async function verifyConnection(): Promise<boolean> {
  try {
    const tr = createTransport();
    const success = await tr.verify();
    logger.info('SMTP connection verified successfully');
    return success;
  } catch (err) {
    logger.error({ err }, 'SMTP connection verification failed');
    return false;
  }
}

// ---------------------------------------------------------------------------
// Rate Limiter — track sends per minute
// ---------------------------------------------------------------------------

interface RateLimitEntry {
  windowStart: number; // epoch ms
  count: number;
}

interface QueuedEmail {
  options: EmailOptions;
  resolve: (result: SendEmailResult) => void;
  reject: (err: Error) => void;
  retriesLeft: number;
}

const rateLimitState: RateLimitEntry = {
  windowStart: Date.now(),
  count: 0,
};

const emailQueue: QueuedEmail[] = [];
let isProcessingQueue = false;

const MAX_EMAILS_PER_MINUTE = 60; // configurable via env
const RATE_LIMIT_WINDOW_MS = 60_000;

const RATE_LIMIT_KEY = 'smtp:ratelimit';

function windowKey(): string {
  return `${RATE_LIMIT_KEY}:${Math.floor(Date.now() / RATE_LIMIT_WINDOW_MS)}`;
}

/**
 * Redis-backed fixed-window check so the send rate is enforced across ALL
 * replicas, not per-process. Fails open if Redis is unavailable — this is a
 * politeness throttle, not a security control.
 */
async function isRateLimited(): Promise<boolean> {
  try {
    const v = await getRedis().get(windowKey());
    return v ? parseInt(v, 10) >= MAX_EMAILS_PER_MINUTE : false;
  } catch {
    return false;
  }
}

/** Atomically consume one send slot in the shared (Redis) current window. */
async function incrementRateCounter(): Promise<void> {
  // Local mirror kept only for getQueueStats(); Redis is authoritative.
  const now = Date.now();
  if (now - rateLimitState.windowStart >= RATE_LIMIT_WINDOW_MS) {
    rateLimitState.windowStart = now;
    rateLimitState.count = 0;
  }
  rateLimitState.count++;
  try {
    const redis = getRedis();
    const key = windowKey();
    const n = await redis.incr(key);
    if (n === 1) await redis.pexpire(key, RATE_LIMIT_WINDOW_MS);
  } catch {
    /* local mirror already updated */
  }
}

// ---------------------------------------------------------------------------
// Core sendEmail with retry + backoff
// ---------------------------------------------------------------------------

const MAX_RETRIES = 3;

/**
 * Sleep helper for exponential backoff (seconds).
 */
function sleep(seconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

async function processQueue(): Promise<void> {
  if (isProcessingQueue) return;
  isProcessingQueue = true;

  while (emailQueue.length > 0) {
    if (await isRateLimited()) {
      // Wait for the next fixed window to open
      const waitMs = RATE_LIMIT_WINDOW_MS - (Date.now() % RATE_LIMIT_WINDOW_MS);
      if (waitMs > 0) {
        logger.debug({ waitMs }, 'Rate limited — waiting before sending next email');
        await sleep(waitMs / 1000);
      }
      continue;
    }

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const item = emailQueue.shift()!;
    await incrementRateCounter();

    try {
      const result = await attemptSend(item.options, item.retriesLeft);
      item.resolve(result);
    } catch (err) {
      item.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }

  isProcessingQueue = false;
}

async function attemptSend(
  options: EmailOptions,
  retriesLeft: number
): Promise<SendEmailResult> {
  const smtp = getSmtpConfig();

  try {
    const tr = createTransport();
    const to = Array.isArray(options.to) ? options.to.join(', ') : options.to;
    const cc = options.cc
      ? Array.isArray(options.cc)
        ? options.cc.join(', ')
        : options.cc
      : undefined;
    const bcc = options.bcc
      ? Array.isArray(options.bcc)
        ? options.bcc.join(', ')
        : options.bcc
      : undefined;

    // Map attachments to nodemailer's expected shape
    const attachments = options.attachments?.map((a) => ({
      filename: a.filename,
      content: a.content,
      path: a.path,
      contentType: a.contentType,
      cid: a.cid,
    }));

    // Strip HTML of any scripts to prevent injection in email
    const safeHtml = options.html
      ? options.html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      : undefined;

    const info = await tr.sendMail({
      from: smtp.from,
      to,
      cc,
      bcc,
      subject: options.subject,
      html: safeHtml,
      text: options.text,
      attachments: attachments as Mail.Attachment[],
      replyTo: options.replyTo,
      priority: options.priority,
      headers: options.headers,
    });

    const result: SendEmailResult = {
      messageId: info.messageId || 'unknown',
      accepted: Array.isArray(info.accepted) ? info.accepted.map(String) : [],
      rejected: Array.isArray(info.rejected) ? info.rejected.map(String) : [],
    };

    logger.info(
      {
        to,
        subject: options.subject,
        messageId: result.messageId,
        acceptedCount: result.accepted.length,
        rejectedCount: result.rejected.length,
      },
      'Email sent successfully'
    );

    if (result.rejected.length > 0) {
      logger.warn(
        { rejected: result.rejected },
        'Some recipients were rejected'
      );
    }

    return result;
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));

    if (retriesLeft > 0) {
      const backoffSeconds = Math.pow(2, MAX_RETRIES - retriesLeft);
      logger.warn(
        {
          err: error.message,
          retriesLeft: retriesLeft - 1,
          backoffSeconds,
          subject: options.subject,
        },
        'Email send failed — retrying with exponential backoff'
      );
      await sleep(backoffSeconds);
      return attemptSend(options, retriesLeft - 1);
    }

    logger.error(
      {
        err: error.message,
        subject: options.subject,
        to: options.to,
      },
      'Email send failed — all retries exhausted'
    );

    throw error;
  }
}

/**
 * Send an email with rate limiting, queuing, and retry logic.
 */
export async function sendEmail(options: EmailOptions): Promise<SendEmailResult> {
  // Validate
  if (!options.to || (Array.isArray(options.to) && options.to.length === 0)) {
    throw new Error('sendEmail: at least one "to" recipient is required');
  }
  if (!options.subject) {
    throw new Error('sendEmail: "subject" is required');
  }
  if (!options.html && !options.text) {
    throw new Error('sendEmail: at least one of "html" or "text" body is required');
  }

  logger.debug(
    {
      to: options.to,
      cc: options.cc,
      bcc: options.bcc ? '(redacted)' : undefined,
      subject: options.subject,
      hasHtml: !!options.html,
      hasText: !!options.text,
      attachmentsCount: options.attachments?.length ?? 0,
    },
    'Queueing email for send'
  );

  // If not rate limited, send immediately; otherwise queue
  if (!(await isRateLimited())) {
    await incrementRateCounter();
    return attemptSend(options, MAX_RETRIES);
  }

  return new Promise<SendEmailResult>((resolve, reject) => {
    emailQueue.push({
      options,
      resolve,
      reject,
      retriesLeft: MAX_RETRIES,
    });
    logger.info(
      { queueLength: emailQueue.length },
      'Email rate limited — added to queue'
    );
    // Trigger queue processing (non-blocking)
    processQueue().catch((err) => {
      logger.error({ err }, 'Email queue processor encountered an error');
    });
  });
}

// ---------------------------------------------------------------------------
// sendSecurityAlert  — professional HTML email for a security finding
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
  info: '#6b7280',
};

const SEVERITY_BG_COLORS: Record<string, string> = {
  critical: '#fef2f2',
  high: '#fff7ed',
  medium: '#fefce8',
  low: '#eff6ff',
  info: '#f9fafb',
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function buildSeverityBadge(severity: string): string {
  const color = SEVERITY_COLORS[severity] || '#6b7280';
  const bg = SEVERITY_BG_COLORS[severity] || '#f9fafb';
  const label = severity.charAt(0).toUpperCase() + severity.slice(1);
  return `<span style="display:inline-block;padding:4px 12px;border-radius:12px;background-color:${bg};color:${color};font-weight:600;font-size:13px;border:1px solid ${color};">${escapeHtml(label)}</span>`;
}

const EMAIL_STYLES = `
  body { margin: 0; padding: 0; background-color: #f4f5f7; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }
  .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .header { padding: 24px 32px; }
  .header.critical { background: linear-gradient(135deg, #dc2626, #b91c1c); }
  .header.high { background: linear-gradient(135deg, #ea580c, #c2410c); }
  .header.medium { background: linear-gradient(135deg, #ca8a04, #a16207); }
  .header.low { background: linear-gradient(135deg, #2563eb, #1d4ed8); }
  .header.info { background: linear-gradient(135deg, #6b7280, #4b5563); }
  .header.default { background: linear-gradient(135deg, #6366f1, #4f46e5); }
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
  .btn { display: inline-block; padding: 12px 24px; background-color: #6366f1; color: #ffffff !important; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 14px; margin-top: 8px; }
  .btn:hover { background-color: #4f46f5; }
  .footer { padding: 24px 32px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af; text-align: center; }
  .footer a { color: #6366f1; }
`.trim();

function wrapEmailHtml(
  headerContent: string,
  bodyContent: string,
  headerClass: string = 'default'
): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>${EMAIL_STYLES}</style>
</head>
<body>
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:24px 0;">
    <tr>
      <td align="center">
        <div class="container">
          <div class="header ${headerClass}">
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

export async function sendSecurityAlert(
  finding: SecurityAlertFinding
): Promise<SendEmailResult> {
  const severity = finding.severity || 'info';
  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);

  const headerContent = `
    <h1>Security Finding: ${escapeHtml(finding.title)}</h1>
    <p>${buildSeverityBadge(severity)} &mdash; ${escapeHtml(finding.projectName || 'Unknown Project')}</p>
  `;

  const cweHtml = finding.cwe
    ? `<div class="field-row"><span class="field-label">CWE</span><span class="field-value">${escapeHtml(finding.cwe)}</span></div>`
    : '';
  const cvssHtml =
    finding.cvssScore !== undefined
      ? `<div class="field-row"><span class="field-label">CVSS Score</span><span class="field-value">${finding.cvssScore.toFixed(1)} / 10.0</span></div>`
      : '';
  const fileHtml = finding.file
    ? `<div class="field-row"><span class="field-label">File</span><span class="field-value" style="font-family:monospace;font-size:13px;">${escapeHtml(finding.file)}${finding.line ? `:${finding.line}` : ''}</span></div>`
    : '';

  const descriptionHtml = finding.description
    ? `<div class="section"><div class="section-title">Description</div><div class="description">${escapeHtml(finding.description)}</div></div>`
    : '';

  const remediationHtml = finding.remediation
    ? `<div class="section"><div class="section-title">Remediation Recommendation</div><div class="remediation">${escapeHtml(finding.remediation)}</div></div>`
    : '';

  const dashboardLink = finding.dashboardUrl
    ? `<a href="${escapeHtml(finding.dashboardUrl)}" class="btn">View in Dashboard</a>`
    : '';

  const bodyContent = `
    <div class="section">
      <div class="section-title">Finding Details</div>
      <div class="field-row"><span class="field-label">Severity</span><span class="field-value">${buildSeverityBadge(severity)}</span></div>
      ${cweHtml}
      ${cvssHtml}
      ${fileHtml}
    </div>
    ${descriptionHtml}
    ${remediationHtml}
    ${dashboardLink ? `<div style="text-align:center;margin-top:16px;">${dashboardLink}</div>` : ''}
  `;

  const html = wrapEmailHtml(headerContent, bodyContent, severity);

  // Plain text fallback
  const textParts =
    [
      `[${severityLabel.toUpperCase()}] ${finding.title}`,
      `Project: ${finding.projectName || 'Unknown'}`,
      finding.cwe ? `CWE: ${finding.cwe}` : '',
      finding.cvssScore !== undefined ? `CVSS: ${finding.cvssScore.toFixed(1)}` : '',
      finding.file ? `File: ${finding.file}${finding.line ? `:${finding.line}` : ''}` : '',
      '',
      finding.description || '',
      '',
      `Remediation: ${finding.remediation || 'Not provided'}`,
      '',
      finding.dashboardUrl ? `Dashboard: ${finding.dashboardUrl}` : '',
    ]
      .filter(Boolean)
      .join('\n');

  const subject = `[${severityLabel}] Security Finding: ${finding.title}`;

  return sendEmail({
    to: [], // Caller must set recipient(s)
    subject,
    html,
    text: textParts,
    headers: {
      'X-AppSec-Finding-ID': finding.id,
      'X-AppSec-Severity': severity,
      'X-AppSec-Entity': 'security-alert',
      Priority: severity === 'critical' || severity === 'high' ? 'urgent' : 'normal',
      Importance: severity === 'critical' || severity === 'high' ? 'high' : 'normal',
    },
  });
}

// ---------------------------------------------------------------------------
// sendReportNotification  — report ready with download link
// ---------------------------------------------------------------------------

export async function sendReportNotification(
  report: ReportNotification
): Promise<SendEmailResult> {
  const headerContent = `
    <h1>Report Ready: ${escapeHtml(report.reportName)}</h1>
    <p>${escapeHtml(report.projectName)} &middot; ${report.format.toUpperCase()}</p>
  `;

  const generatedDate = report.generatedAt.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  const summaryRows = Object.entries({
    critical: report.summary.critical,
    high: report.summary.high,
    medium: report.summary.medium,
    low: report.summary.low,
  })
    .filter(([, count]) => count > 0)
    .map(
      ([sev, count]) =>
        `<div class="field-row"><span class="field-label">${sev.charAt(0).toUpperCase() + sev.slice(1)}</span><span class="field-value" style="color:${SEVERITY_COLORS[sev] || '#6b7280'};">${count}</span></div>`
    )
    .join('');

  const bodyContent = `
    <div class="section">
      <div class="section-title">Report Summary</div>
      <div class="field-row"><span class="field-label">Report Name</span><span class="field-value">${escapeHtml(report.reportName)}</span></div>
      <div class="field-row"><span class="field-label">Project</span><span class="field-value">${escapeHtml(report.projectName)}</span></div>
      <div class="field-row"><span class="field-label">Format</span><span class="field-value">${report.format.toUpperCase()}</span></div>
      <div class="field-row"><span class="field-label">Generated</span><span class="field-value">${escapeHtml(generatedDate)}</span></div>
      <div class="field-row"><span class="field-label">Total Findings</span><span class="field-value">${report.summary.totalFindings}</span></div>
      ${summaryRows}
    </div>
    <div style="text-align:center;margin-top:24px;">
      <a href="${escapeHtml(report.downloadUrl)}" class="btn">Download ${report.format.toUpperCase()} Report</a>
    </div>
    <p style="font-size:13px;color:#6b7280;text-align:center;margin-top:8px;">
      The download link will expire in 7 days.
    </p>
  `;

  const html = wrapEmailHtml(headerContent, bodyContent, 'default');

  const textParts: string[] = [
    `Report Ready: ${report.reportName}`,
    `Project: ${report.projectName}`,
    `Format: ${report.format.toUpperCase()}`,
    `Generated: ${generatedDate}`,
    `Total Findings: ${report.summary.totalFindings}`,
    `Critical: ${report.summary.critical}`,
    `High: ${report.summary.high}`,
    `Medium: ${report.summary.medium}`,
    `Low: ${report.summary.low}`,
    '',
    `Download: ${report.downloadUrl}`,
  ];

  const subject = `Report Ready: ${report.reportName} (${report.format.toUpperCase()})`;

  return sendEmail({
    to: [], // Caller must set recipient(s)
    subject,
    html,
    text: textParts.join('\n'),
    headers: {
      'X-AppSec-Report-ID': report.reportId,
      'X-AppSec-Entity': 'report-notification',
    },
  });
}

// ---------------------------------------------------------------------------
// sendDigest  — weekly digest of open findings grouped by severity
// ---------------------------------------------------------------------------

export async function sendDigest(
  digest: DigestEmail
): Promise<SendEmailResult> {
  const periodStartStr = digest.periodStart.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
  const periodEndStr = digest.periodEnd.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });

  // Group findings by severity (maintaining a severity order)
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const grouped: Record<string, SecurityAlertFinding[]> = {};
  for (const sev of severityOrder) {
    grouped[sev] = [];
  }
  for (const f of digest.findings) {
    const sev = f.severity || 'info';
    if (!grouped[sev]) grouped[sev] = [];
    grouped[sev]!.push(f);
  }

  const headerContent = `
    <h1>Weekly Security Digest</h1>
    <p>${escapeHtml(digest.projectName)} &middot; ${escapeHtml(periodStartStr)} &ndash; ${escapeHtml(periodEndStr)}</p>
  `;

  // Summary bar
  const summaryBars = severityOrder
    .filter((sev) => (grouped[sev]?.length ?? 0) > 0)
    .map((sev) => {
      const count = grouped[sev]?.length ?? 0;
      const color = SEVERITY_COLORS[sev] || '#6b7280';
      return `
        <div class="field-row">
          <span class="field-label">${buildSeverityBadge(sev)}</span>
          <span class="field-value" style="font-size:18px;font-weight:700;color:${color};">${count}</span>
        </div>`;
    })
    .join('');

  // Finding lists per severity
  const findingLists = severityOrder
    .filter((sev) => (grouped[sev]?.length ?? 0) > 0)
    .map((sev) => {
      const items = (grouped[sev] ?? [])
        .slice(0, 20) // cap per group to avoid massive emails
        .map((f) => {
          const location = f.file
            ? ` &middot; <code style="font-size:12px;background:#f3f4f6;padding:2px 6px;border-radius:3px;">${escapeHtml(f.file)}${f.line ? `:${f.line}` : ''}</code>`
            : '';
          const cvssTag =
            f.cvssScore !== undefined
              ? ` &middot; <span style="font-size:12px;color:#6b7280;">CVSS ${f.cvssScore.toFixed(1)}</span>`
              : '';
          return `<tr>
            <td style="padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:14px;">
              <a href="${escapeHtml(f.dashboardUrl || '#')}" style="color:#6366f1;text-decoration:none;font-weight:500;">${escapeHtml(f.title)}</a>
              ${location}${cvssTag}
            </td>
          </tr>`;
        })
        .join('');

      const totalInGroup = grouped[sev]?.length ?? 0;
      const overflow =
        totalInGroup > 20
          ? `<tr><td style="padding:4px 0;font-size:13px;color:#6b7280;">... and ${totalInGroup - 20} more ${sev} finding${totalInGroup - 20 === 1 ? '' : 's'}</td></tr>`
          : '';

      return `
        <div class="section">
          <div class="section-title">${sev.charAt(0).toUpperCase() + sev.slice(1)} (${totalInGroup})</div>
          <table width="100%" cellpadding="0" cellspacing="0">
            ${items}
            ${overflow}
          </table>
        </div>`;
    })
    .join('');

  const bodyContent = `
    <div class="section">
      <div class="section-title">Summary</div>
      <div class="field-row"><span class="field-label">Reporting Period</span><span class="field-value">${escapeHtml(periodStartStr)} &ndash; ${escapeHtml(periodEndStr)}</span></div>
      <div class="field-row"><span class="field-label">Open Findings</span><span class="field-value" style="font-size:18px;font-weight:700;">${digest.totalOpenFindings}</span></div>
      ${summaryBars}
    </div>
    ${findingLists}
    <div style="text-align:center;margin-top:24px;padding-top:16px;border-top:1px solid #e5e7eb;">
      <p style="font-size:13px;color:#6b7280;">
        This is an automated weekly digest from AppSec Platform.
        <a href="[preferences_url]" style="color:#6366f1;">Manage notifications</a>
      </p>
    </div>
  `;

  const html = wrapEmailHtml(headerContent, bodyContent, 'default');

  // Plain text version
  const textLines: string[] = [
    `WEEKLY SECURITY DIGEST`,
    `${digest.projectName}`,
    `${periodStartStr} - ${periodEndStr}`,
    '',
    `Total Open Findings: ${digest.totalOpenFindings}`,
    '',
  ];

  for (const sev of severityOrder) {
    const items = grouped[sev];
    if (!items || items.length === 0) continue;
    textLines.push(`${sev.toUpperCase()}: ${items.length}`);
    for (const f of items.slice(0, 20)) {
      const loc = f.file ? ` (${f.file}${f.line ? `:${f.line}` : ''})` : '';
      const cvss = f.cvssScore !== undefined ? ` [CVSS: ${f.cvssScore.toFixed(1)}]` : '';
      textLines.push(`  - ${f.title}${cvss}${loc}`);
    }
    if (items.length > 20) {
      textLines.push(`  ... and ${items.length - 20} more`);
    }
    textLines.push('');
  }

  const subject = `Weekly Security Digest — ${escapeHtml(digest.projectName)} (${escapeHtml(periodStartStr)} – ${escapeHtml(periodEndStr)})`;

  return sendEmail({
    to: [digest.recipient],
    subject,
    html,
    text: textLines.join('\n'),
    headers: {
      'X-AppSec-Entity': 'weekly-digest',
      'X-AppSec-Project': digest.projectName,
      'X-AppSec-Period-Start': digest.periodStart.toISOString(),
      'X-AppSec-Period-End': digest.periodEnd.toISOString(),
      'Precedence': 'bulk',
      'List-Id': `<weekly-digest.${digest.projectName.replace(/\s+/g, '-').toLowerCase()}.appsec>`,
    },
  });
}

// ---------------------------------------------------------------------------
// Utility: Get queue stats (useful for health checks / monitoring)
// ---------------------------------------------------------------------------

export function getQueueStats(): {
  queuedCount: number;
  currentWindowCount: number;
  windowResetMs: number;
} {
  const now = Date.now();
  const windowResetMs = Math.max(
    0,
    rateLimitState.windowStart + RATE_LIMIT_WINDOW_MS - now
  );
  return {
    queuedCount: emailQueue.length,
    currentWindowCount: rateLimitState.count,
    windowResetMs,
  };
}
