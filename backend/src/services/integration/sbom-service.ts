import { logger } from '../../core/logging/logger.js';

// Optional integration: set SBOM_VISUALIZER_URL in .env to enable the dependency-graph
// view. Left empty the feature self-disables (isSbomVisualizerConfigured() -> false).
const SBOM_VIZ_URL = process.env.SBOM_VISUALIZER_URL || '';
const SBOM_VIZ_TOKEN = process.env.SBOM_VISUALIZER_TOKEN || '';

async function sbomFetch(path: string, opts: RequestInit = {}): Promise<Response> {
  const url = `${SBOM_VIZ_URL}/api${path}`;
  const headers: Record<string, string> = { ...(opts.headers as Record<string, string>) };
  if (SBOM_VIZ_TOKEN) {
    headers['Authorization'] = `Bearer ${SBOM_VIZ_TOKEN}`;
  }
  return fetch(url, { ...opts, headers });
}

export interface SbomComponent {
  name: string;
  version: string;
  type: string;
  purl?: string;
  cpe?: string;
  licenses?: string[];
  language?: string;
  depth?: string;
}

export interface ParsedSbom {
  id: string;
  format: string;
  formatVersion?: string;
  name: string;
  version?: string;
  timestamp?: string;
  components: SbomComponent[];
  dependencies?: Array<{ ref: string; deps: string[] }>;
}

export interface ScanFinding {
  componentIndex: number;
  vulns: Array<{
    id: string;
    cveId?: string;
    description?: string;
    cvss?: { score: number; severity: string; version?: string; vector?: string };
    cwes?: string[];
    fixed?: string[];
    kev?: boolean;
    epss?: { score: number; percentile: number };
    published?: string;
  }>;
}

export interface ScanSummary {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  NONE: number;
  UNKNOWN: number;
  total: number;
  scanned: number;
  affected: number;
}

export interface ScanResult {
  findings: ScanFinding[];
  summary: ScanSummary;
  errors?: string[];
  scanId?: string;
}

export interface AssessmentResult {
  verdict: { status: string; reasons: string[]; policy: string };
  risk: { score: number; grade: string; pct: number };
  summary: ScanSummary;
  remediation?: Array<{
    componentIndex: number;
    name: string;
    currentVersion: string;
    target: string;
    cvesResolved: number;
    kevCount: number;
  }>;
  noFix?: Array<{ componentIndex: number; name: string; vulnCount: number }>;
  topCwes?: Array<{ id: string; name: string; count: number }>;
  kevCount?: number;
  maliciousCount?: number;
}

export interface AnalyzeResult {
  sbom: { id: string; format: string; name: string; version?: string };
  findings: ScanFinding[];
  summary: ScanSummary;
  errors?: string[];
  scanId?: string;
  assessment: AssessmentResult;
}

export async function sbomHealth(): Promise<{ status: string; version: string } | null> {
  try {
    const res = await sbomFetch('/health');
    if (!res.ok) return null;
    return await res.json() as { status: string; version: string };
  } catch {
    return null;
  }
}

export async function parseSbom(raw: object): Promise<{ sbom: ParsedSbom } | null> {
  try {
    const res = await sbomFetch('/parse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw }),
    });
    if (!res.ok) {
      const text = await res.text();
      logger.error({ status: res.status, body: text }, 'SBOM parse failed');
      return null;
    }
    return await res.json() as { sbom: ParsedSbom };
  } catch (err) {
    logger.error({ err }, 'SBOM parse error');
    return null;
  }
}

export async function parseSbomFromUrl(url: string): Promise<{ sbom: ParsedSbom } | null> {
  try {
    const res = await sbomFetch('/parse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) {
      const text = await res.text();
      logger.error({ status: res.status, body: text }, 'SBOM parse from URL failed');
      return null;
    }
    return await res.json() as { sbom: ParsedSbom };
  } catch (err) {
    logger.error({ err }, 'SBOM parse from URL error');
    return null;
  }
}

export async function scanSbom(
  sbom: ParsedSbom,
  options?: { kev?: boolean; epss?: boolean },
): Promise<ScanResult | null> {
  try {
    const res = await sbomFetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sbom,
        options: { kev: true, epss: true, ...options },
      }),
    });
    if (!res.ok) {
      const text = await res.text();
      logger.error({ status: res.status, body: text }, 'SBOM scan failed');
      return null;
    }
    return await res.json() as ScanResult;
  } catch (err) {
    logger.error({ err }, 'SBOM scan error');
    return null;
  }
}

export async function assessSbom(
  sbom: ParsedSbom,
  findings: ScanFinding[],
  summary: ScanSummary,
  policy?: string,
): Promise<{ assessment: AssessmentResult } | null> {
  try {
    const res = await sbomFetch('/assess', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sbom,
        findings,
        summary,
        policy: policy || 'standard',
      }),
    });
    if (!res.ok) {
      const text = await res.text();
      logger.error({ status: res.status, body: text }, 'SBOM assess failed');
      return null;
    }
    return await res.json() as { assessment: AssessmentResult };
  } catch (err) {
    logger.error({ err }, 'SBOM assess error');
    return null;
  }
}

export async function analyzeSbom(raw: object): Promise<AnalyzeResult | null> {
  try {
    const res = await sbomFetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw }),
    });
    if (!res.ok) {
      const text = await res.text();
      logger.error({ status: res.status, body: text }, 'SBOM analyze failed');
      return null;
    }
    return await res.json() as AnalyzeResult;
  } catch (err) {
    logger.error({ err }, 'SBOM analyze error');
    return null;
  }
}

export async function getSbomGraphHtml(raw: object): Promise<string | null> {
  try {
    const res = await sbomFetch('/graph/html', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw }),
    });
    if (!res.ok) return null;
    return await res.text();
  } catch (err) {
    logger.error({ err }, 'SBOM graph HTML error');
    return null;
  }
}

export async function getSbomReport(
  sbom: ParsedSbom,
  findings: ScanFinding[],
  summary: ScanSummary,
  assessment?: AssessmentResult | null,
): Promise<string | null> {
  try {
    const res = await sbomFetch('/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sbom, findings, summary, assessment: assessment || null }),
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

export async function exportSarif(
  sbom: ParsedSbom,
  findings: ScanFinding[],
): Promise<Record<string, unknown> | null> {
  try {
    const res = await sbomFetch('/export/sarif', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sbom, findings }),
    });
    if (!res.ok) return null;
    return await res.json() as Record<string, unknown>;
  } catch {
    return null;
  }
}

export async function getSbomSources(): Promise<Array<Record<string, unknown>> | null> {
  try {
    const res = await sbomFetch('/sources');
    if (!res.ok) return null;
    const data = await res.json() as { sources: Array<Record<string, unknown>> };
    return data.sources;
  } catch {
    return null;
  }
}

export async function listSbomScans(): Promise<Array<Record<string, unknown>> | null> {
  try {
    const res = await sbomFetch('/scans');
    if (!res.ok) return null;
    const data = await res.json() as { scans: Array<Record<string, unknown>> };
    return data.scans;
  } catch {
    return null;
  }
}

export async function getSbomScan(scanId: string): Promise<Record<string, unknown> | null> {
  try {
    const res = await sbomFetch(`/scans/${scanId}`);
    if (!res.ok) return null;
    return await res.json() as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function isSbomVisualizerConfigured(): boolean {
  return !!SBOM_VIZ_URL;
}
