// ============================================================
// Shared Types — Application Security Platform
// ============================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanType = 'sast' | 'dast' | 'api' | 'sca' | 'full';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'paused';
export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'closed' | 'false_positive' | 'wont_fix';
export type FindingType = 'sast' | 'dast' | 'api' | 'sca' | 'manual';
export type ReportFormat = 'pdf' | 'html' | 'json' | 'csv' | 'markdown';
export type ReportTemplate = 'executive' | 'developer' | 'compliance' | 'owasp' | 'api' | 'sast' | 'dast' | 'summary';
export type IntegrationType = 'github' | 'gitlab' | 'bitbucket' | 'jira' | 'slack' | 'teams' | 'discord' | 'webhook' | 'smtp' | 'siem';
export type AuthType = 'none' | 'basic' | 'bearer' | 'jwt' | 'oauth' | 'api_key' | 'mtls' | 'digest';
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';

export const SEVERITY_RANK: Record<Severity, number> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
export const SEVERITY_COLORS: Record<Severity, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6' };

export interface User {
  id: string; email: string; name: string; role: string; orgId: string; orgName: string; permissions: string[];
  mfaEnabled?: boolean; disabled?: boolean; lastLogin?: string; createdAt?: string;
}

export interface Organization {
  id: string; name: string; settings?: Record<string, unknown>; createdAt: string; updatedAt: string;
}

export interface Project {
  id: string; orgId: string; name: string; description?: string; ownerId?: string; repository?: string;
  targetUrl?: string; apiBaseUrl?: string; authType?: AuthType; tags?: string[];
  riskScore?: number; scanCount?: number; criticalCount?: number; highCount?: number;
  createdAt: string; updatedAt: string;
}

export interface Scan {
  id: string; orgId: string; projectId: string; scanType: ScanType; name: string; status: ScanStatus;
  options?: Record<string, unknown>; findingsCount?: number; errorMessage?: string;
  startedBy?: string; startedAt?: string; completedAt?: string; createdAt: string;
}

export interface Finding {
  id: string; orgId: string; projectId: string; scanId: string; type: FindingType;
  title: string; description?: string; severity: Severity; severityRank: number; status: FindingStatus;
  filePath?: string; lineNumber?: number; codeSnippet?: string; endpoint?: string;
  ruleId?: string; ruleName?: string; cweId?: string; cveId?: string;
  owaspCategory?: string; cvssScore?: number; cvssVector?: string; epssScore?: number;
  recommendation?: string; references?: string[]; assignedTo?: string;
  createdAt: string; updatedAt: string;
}

export interface Report {
  id: string; orgId: string; projectId: string; name: string; templateType: ReportTemplate;
  format: ReportFormat; status: 'queued' | 'generating' | 'completed' | 'failed';
  filters?: Record<string, unknown>; fileSize?: number; generatedBy?: string; createdAt: string;
}

export interface DashboardSummary {
  findings: { openFindings: number; critical: number; high: number; medium: number; low: number; avgCvss: number };
  projects: { total: number; active: number; updatedThisWeek: number };
  scans: { total: number; running: number; queued: number; completed: number; last24h: number };
  recentScans: Scan[];
  topVulnerableApps: Array<{ id: string; name: string; openFindings: number; critical: number; high: number }>;
}
