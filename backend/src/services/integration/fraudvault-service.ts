import fs from 'fs';
import path from 'path';
import { logger } from '../../core/logging/logger.js';

// Optional integration: set FRAUDVAULT_URL + credentials in .env to enable binary/malware
// submission. Left empty the feature self-disables (isFraudVaultConfigured() -> false).
const FRAUDVAULT_URL = process.env.FRAUDVAULT_URL || '';
const FRAUDVAULT_EMAIL = process.env.FRAUDVAULT_EMAIL || '';
const FRAUDVAULT_PASSWORD = process.env.FRAUDVAULT_PASSWORD || '';

let cachedToken: string | null = null;
let tokenExpiry = 0;

async function fvFetch(path: string, opts: RequestInit = {}): Promise<Response> {
  const url = `${FRAUDVAULT_URL}/api/v1${path}`;
  return fetch(url, {
    ...opts,
    headers: { ...opts.headers as Record<string, string> },
    // Self-hosted FraudVault instances commonly use a self-signed cert.
    ...(process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ? {} : {}),
  });
}

async function getToken(): Promise<string | null> {
  if (cachedToken && Date.now() < tokenExpiry) return cachedToken;
  if (!FRAUDVAULT_EMAIL || !FRAUDVAULT_PASSWORD) {
    logger.warn('FraudVault credentials not configured (FRAUDVAULT_EMAIL / FRAUDVAULT_PASSWORD)');
    return null;
  }
  try {
    const res = await fvFetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: FRAUDVAULT_EMAIL, password: FRAUDVAULT_PASSWORD }),
    });
    if (!res.ok) {
      logger.error({ status: res.status }, 'FraudVault auth failed');
      return null;
    }
    const data = await res.json() as { data?: { token?: string; refreshToken?: string } };
    cachedToken = data?.data?.token || null;
    // FraudVault JWT_EXPIRY defaults to 15m — refresh after 10m
    tokenExpiry = Date.now() + 10 * 60 * 1000;
    return cachedToken;
  } catch (err) {
    logger.error({ err }, 'FraudVault auth error');
    return null;
  }
}

export interface FraudVaultSubmission {
  id: string;
  status: string;
  filename?: string;
  threatLevel?: string;
}

export async function submitFileToFraudVault(
  filePath: string,
  tags?: string[],
): Promise<FraudVaultSubmission | null> {
  const token = await getToken();
  if (!token) return null;

  try {
    const filename = path.basename(filePath);
    const fileBuffer = fs.readFileSync(filePath);
    const blob = new Blob([fileBuffer]);

    const form = new FormData();
    form.append('file', blob, filename);
    form.append('type', 'file');
    if (tags?.length) {
      for (const t of tags) form.append('tags', t);
    }

    const res = await fvFetch('/submissions/upload', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: form,
    });

    if (!res.ok) {
      const text = await res.text();
      logger.error({ status: res.status, body: text }, 'FraudVault file submission failed');
      return null;
    }

    const data = await res.json() as { data?: FraudVaultSubmission };
    logger.info({ submissionId: data?.data?.id, filename }, 'Submitted to FraudVault');
    return data?.data || null;
  } catch (err) {
    logger.error({ err, filePath }, 'FraudVault file submission error');
    return null;
  }
}

export async function submitUrlToFraudVault(
  url: string,
): Promise<FraudVaultSubmission | null> {
  const token = await getToken();
  if (!token) return null;

  try {
    const res = await fvFetch('/submissions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ type: 'url', url }),
    });

    if (!res.ok) {
      const text = await res.text();
      logger.error({ status: res.status, body: text }, 'FraudVault URL submission failed');
      return null;
    }

    const data = await res.json() as { data?: FraudVaultSubmission };
    logger.info({ submissionId: data?.data?.id, url }, 'URL submitted to FraudVault');
    return data?.data || null;
  } catch (err) {
    logger.error({ err, url }, 'FraudVault URL submission error');
    return null;
  }
}

export async function getFraudVaultSubmission(submissionId: string): Promise<Record<string, unknown> | null> {
  const token = await getToken();
  if (!token) return null;

  try {
    const res = await fvFetch(`/submissions/${submissionId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const data = await res.json() as { data?: Record<string, unknown> };
    return data?.data || null;
  } catch {
    return null;
  }
}

export async function getFraudVaultReport(submissionId: string): Promise<Record<string, unknown> | null> {
  const token = await getToken();
  if (!token) return null;

  try {
    const res = await fvFetch(`/analysis/submissions/${submissionId}/report`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const data = await res.json() as { data?: Record<string, unknown> };
    return data?.data || null;
  } catch {
    return null;
  }
}

export async function listFraudVaultSubmissions(
  opts: { page?: number; pageSize?: number; status?: string; threatLevel?: string } = {},
): Promise<{ items: FraudVaultSubmission[]; total: number } | null> {
  const token = await getToken();
  if (!token) return null;

  try {
    const params = new URLSearchParams();
    if (opts.page) params.set('page', String(opts.page));
    if (opts.pageSize) params.set('pageSize', String(opts.pageSize));
    if (opts.status) params.set('status', opts.status);
    if (opts.threatLevel) params.set('threatLevel', opts.threatLevel);

    const res = await fvFetch(`/submissions?${params}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const data = await res.json() as { data?: { items: FraudVaultSubmission[]; total: number } };
    return data?.data || null;
  } catch {
    return null;
  }
}

export async function getFraudVaultAnalysisJobs(
  submissionId: string,
): Promise<Array<Record<string, unknown>> | null> {
  const token = await getToken();
  if (!token) return null;

  try {
    const res = await fvFetch(`/analysis/submissions/${submissionId}/jobs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const data = await res.json() as { data?: Array<Record<string, unknown>> };
    return data?.data || null;
  } catch {
    return null;
  }
}

export async function getFraudVaultDetectionResults(
  submissionId: string,
): Promise<Record<string, unknown> | null> {
  const token = await getToken();
  if (!token) return null;

  try {
    const res = await fvFetch(`/analysis/${submissionId}/detection-results`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const data = await res.json() as { data?: Record<string, unknown> };
    return data?.data || null;
  } catch {
    return null;
  }
}

export async function searchFraudVault(
  query: string,
  field: string = 'all',
): Promise<Array<Record<string, unknown>> | null> {
  const token = await getToken();
  if (!token) return null;

  try {
    const params = new URLSearchParams({ q: query, field });
    const res = await fvFetch(`/search?${params}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const data = await res.json() as { data?: Array<Record<string, unknown>> };
    return data?.data || null;
  } catch {
    return null;
  }
}

export async function getFraudVaultDashboard(): Promise<Record<string, unknown> | null> {
  const token = await getToken();
  if (!token) return null;

  try {
    const res = await fvFetch('/dashboard/stats', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const data = await res.json() as { data?: Record<string, unknown> };
    return data?.data || null;
  } catch {
    return null;
  }
}

export function isFraudVaultConfigured(): boolean {
  return !!(FRAUDVAULT_URL && FRAUDVAULT_EMAIL && FRAUDVAULT_PASSWORD);
}
