// ============================================================
// Compliance Service
// Backend service that generates compliance reports by fetching
// findings and running them through framework mappers.
//
// Re-exports the SOC2/HIPAA mapper types and functions from
// the scanner module, and wraps the core compliance mapper
// functions for use from the API layer.
// ============================================================

// ---------------------------------------------------------------------------
// Types (mirrored from scanners for backend use)
// ---------------------------------------------------------------------------

export type ComplianceFramework = 'owasp-asvs' | 'cwe-top25' | 'pci-dss';
export type ExtendedComplianceFramework = 'soc2' | 'hipaa';
export type AllFrameworks = ComplianceFramework | ExtendedComplianceFramework;

/** Minimum finding shape required by compliance functions */
export interface FindingStub {
  id: string;
  cweId: string;
  title?: string;
  severity?: string;
  severityRank?: number;
  ruleId?: string;
  filePath?: string;
  lineNumber?: number;
  [key: string]: unknown;
}

export interface ComplianceReport {
  framework: ComplianceFramework;
  frameworkName: string;
  generatedAt: string;
  overallCoveragePercent: number;
  passedCount: number;
  failedCount: number;
  notTestedCount: number;
  totalRequirements: number;
  executiveSummary: string;
  requirements: Array<{
    requirementId: string;
    title: string;
    description: string;
    status: 'passed' | 'failed' | 'not-tested';
    findingCount: number;
  }>;
  gapAnalysis: GapItem[];
}

export interface GapItem {
  requirementId: string;
  title: string;
  gapType: 'no-automated-coverage' | 'partial-coverage' | 'no-findings';
  recommendation: string;
}

// ---------------------------------------------------------------------------
// SOC2 Types
// ---------------------------------------------------------------------------

export interface SOC2Criterion {
  criterionId: string;
  title: string;
  description: string;
  cweIds: string[];
}

export interface SOC2CriterionResult {
  criterionId: string;
  title: string;
  description: string;
  status: 'pass' | 'fail' | 'partial';
  matchingFindingsCount: number;
  cweIds: string[];
  matchedCweIds: string[];
  remediationGuidance: string;
}

export interface SOC2MappingResult {
  framework: 'SOC2 Type II';
  generatedAt: string;
  overallStatus: 'pass' | 'fail' | 'partial';
  criteria: SOC2CriterionResult[];
  passCount: number;
  failCount: number;
  partialCount: number;
  totalCriteria: number;
  executiveSummary: string;
}

// ---------------------------------------------------------------------------
// HIPAA Types
// ---------------------------------------------------------------------------

export interface HIPAARequirement {
  requirementId: string;
  title: string;
  description: string;
  cweIds: string[];
}

export interface HIPAARequirementResult {
  requirementId: string;
  title: string;
  description: string;
  status: 'pass' | 'fail' | 'partial';
  matchingFindingsCount: number;
  cweIds: string[];
  matchedCweIds: string[];
  remediationGuidance: string;
}

export interface HIPAAMappingResult {
  framework: 'HIPAA Security Rule';
  generatedAt: string;
  overallStatus: 'pass' | 'fail' | 'partial';
  requirements: HIPAARequirementResult[];
  passCount: number;
  failCount: number;
  partialCount: number;
  totalRequirements: number;
  executiveSummary: string;
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/**
 * Normalize a CWE ID string to "CWE-NNNN" format.
 */
function normalizeCweId(raw: string): string {
  if (!raw) return '';
  const cleaned = raw.trim();
  if (/^\d+$/.test(cleaned)) return `CWE-${cleaned}`;
  const upper = cleaned.toUpperCase();
  if (/^CWE-\d+$/.test(upper)) return upper;
  const match = cleaned.match(/(\d+)/);
  return match ? `CWE-${match[1]}` : cleaned;
}

/**
 * Group findings by their normalized CWE ID.
 */
function groupFindingsByCwe(findings: FindingStub[]): Map<string, FindingStub[]> {
  const map = new Map<string, FindingStub[]>();
  for (const finding of findings) {
    if (!finding.cweId) continue;
    const normalized = normalizeCweId(finding.cweId);
    if (!normalized) continue;
    const existing = map.get(normalized) ?? [];
    existing.push(finding);
    map.set(normalized, existing);
  }
  return map;
}

// ---------------------------------------------------------------------------
// SOC2 Mapping Tables
// ---------------------------------------------------------------------------

const SOC2_MAPPING: SOC2Criterion[] = [
  {
    criterionId: 'CC6.1',
    title: 'Logical Access Security',
    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.',
    cweIds: ['CWE-798', 'CWE-522', 'CWE-521', 'CWE-307'],
  },
  {
    criterionId: 'CC6.3',
    title: 'Unauthorized Access Prevention',
    description: 'The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles and responsibilities.',
    cweIds: ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-94', 'CWE-918'],
  },
  {
    criterionId: 'CC6.6',
    title: 'External Threats',
    description: 'The entity implements logical access security measures to protect against threats from sources outside its system boundaries.',
    cweIds: ['CWE-79', 'CWE-89', 'CWE-352', 'CWE-22'],
  },
  {
    criterionId: 'CC6.7',
    title: 'Transmitted Data Protection',
    description: 'The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.',
    cweIds: ['CWE-319', 'CWE-326', 'CWE-327'],
  },
  {
    criterionId: 'CC6.8',
    title: 'Unauthorized Software Prevention',
    description: 'The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.',
    cweIds: ['CWE-502', 'CWE-94', 'CWE-829'],
  },
  {
    criterionId: 'CC7.1',
    title: 'Monitoring',
    description: 'To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.',
    cweIds: ['CWE-778', 'CWE-532', 'CWE-209'],
  },
  {
    criterionId: 'CC7.2',
    title: 'Anomaly Detection',
    description: 'The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors.',
    cweIds: ['CWE-307', 'CWE-770'],
  },
  {
    criterionId: 'CC8.1',
    title: 'Change Management',
    description: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.',
    cweIds: ['CWE-489', 'CWE-1004'],
  },
];

const SOC2_REMEDIATION: Record<string, string> = {
  'CC6.1': 'Implement strong credential management: remove hardcoded credentials (CWE-798), enforce password hashing best practices (CWE-522), require minimum password complexity (CWE-521), and add brute-force protection with account lockout (CWE-307).',
  'CC6.3': 'Prevent injection-based unauthorized access: parameterize SQL queries (CWE-89), apply contextual output encoding (CWE-79), sanitize OS command inputs (CWE-78), prevent code injection via eval/Function (CWE-94), and validate server-side request URLs (CWE-918).',
  'CC6.6': 'Harden external-facing attack surface: apply XSS output encoding (CWE-79), parameterize queries (CWE-89), implement anti-CSRF tokens (CWE-352), and normalize file paths to prevent traversal (CWE-22).',
  'CC6.7': 'Enforce TLS for all data in transit (CWE-319), use approved key lengths (CWE-326), and replace weak or deprecated cryptographic algorithms (CWE-327).',
  'CC6.8': 'Prevent malicious code execution: disable unsafe deserialization (CWE-502), block dynamic code injection (CWE-94), and restrict inclusion of untrusted external resources (CWE-829).',
  'CC7.1': 'Enable comprehensive logging (CWE-778), prevent sensitive data from appearing in logs (CWE-532), and ensure error messages do not expose internal details (CWE-209).',
  'CC7.2': 'Implement rate limiting and anomaly detection: add brute-force detection with account lockout (CWE-307) and enforce resource consumption limits (CWE-770).',
  'CC8.1': 'Enforce change management controls: remove debug code and leftover test artifacts from production (CWE-489) and set HttpOnly on sensitive cookies to limit client-side exposure (CWE-1004).',
};

// ---------------------------------------------------------------------------
// HIPAA Mapping Tables
// ---------------------------------------------------------------------------

const HIPAA_MAPPING: HIPAARequirement[] = [
  {
    requirementId: '164.312(a)(1)',
    title: 'Access Control',
    description: 'Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to authorized persons or software programs.',
    cweIds: ['CWE-798', 'CWE-522', 'CWE-862', 'CWE-863'],
  },
  {
    requirementId: '164.312(a)(2)(iv)',
    title: 'Encryption and Decryption',
    description: 'Implement a mechanism to encrypt and decrypt electronic protected health information.',
    cweIds: ['CWE-326', 'CWE-327', 'CWE-311'],
  },
  {
    requirementId: '164.312(b)',
    title: 'Audit Controls',
    description: 'Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information.',
    cweIds: ['CWE-778', 'CWE-532', 'CWE-209'],
  },
  {
    requirementId: '164.312(c)(1)',
    title: 'Integrity',
    description: 'Implement policies and procedures to protect electronic protected health information from improper alteration or destruction.',
    cweIds: ['CWE-345', 'CWE-354', 'CWE-347'],
  },
  {
    requirementId: '164.312(d)',
    title: 'Person or Entity Authentication',
    description: 'Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed.',
    cweIds: ['CWE-287', 'CWE-307', 'CWE-521', 'CWE-613'],
  },
  {
    requirementId: '164.312(e)(1)',
    title: 'Transmission Security',
    description: 'Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network.',
    cweIds: ['CWE-319', 'CWE-295', 'CWE-297'],
  },
];

const HIPAA_REMEDIATION: Record<string, string> = {
  '164.312(a)(1)': 'Enforce access controls for ePHI systems: remove hardcoded credentials (CWE-798), store credentials with strong hashing (CWE-522), implement authorization checks at every tier (CWE-862), and validate role-based access on each request (CWE-863).',
  '164.312(a)(2)(iv)': 'Encrypt ePHI at rest and ensure adequate key strength (CWE-326), use only approved cryptographic algorithms such as AES-256-GCM (CWE-327), and encrypt all sensitive data fields in storage (CWE-311).',
  '164.312(b)': 'Implement comprehensive audit logging (CWE-778), prevent sensitive health data from appearing in log files (CWE-532), and ensure error messages do not expose ePHI or internal system details (CWE-209).',
  '164.312(c)(1)': 'Protect ePHI integrity: validate data authenticity with verification checks (CWE-345), enforce integrity checks on transmitted data (CWE-354), and verify cryptographic signatures on tokens and messages (CWE-347).',
  '164.312(d)': 'Strengthen authentication for ePHI access: validate authentication mechanisms properly (CWE-287), implement brute-force protection with account lockout (CWE-307), enforce password complexity requirements (CWE-521), and set appropriate session timeouts (CWE-613).',
  '164.312(e)(1)': 'Protect ePHI in transit: enforce TLS for all transmissions (CWE-319), validate server certificates properly (CWE-295), and verify certificate hostname matching (CWE-297).',
};

// ---------------------------------------------------------------------------
// OWASP ASVS / CWE Top 25 / PCI DSS Mapping Tables
// ---------------------------------------------------------------------------

// Simplified ASVS mapping: CWE → ASVS section
const ASVS_MAPPING: Array<{ cweId: string; section: string; title: string; description: string }> = [
  { cweId: 'CWE-798', section: 'V2.10.4', title: 'Hardcoded Credentials', description: 'Verify that there are no hardcoded credentials, API keys, or secrets in source code.' },
  { cweId: 'CWE-521', section: 'V2.2.1', title: 'Password Strength Requirements', description: 'Verify that password minimum length and complexity requirements are enforced.' },
  { cweId: 'CWE-614', section: 'V3.4.2', title: 'Cookie Secure Flag', description: 'Verify that the Secure attribute is set for all cookies containing sensitive data.' },
  { cweId: 'CWE-1004', section: 'V3.4.3', title: 'Cookie HttpOnly Flag', description: 'Verify that the HttpOnly attribute is set for all cookies containing sensitive data.' },
  { cweId: 'CWE-539', section: 'V3.1.1', title: 'Session Expiration', description: 'Verify that the application expires sessions after a defined period of inactivity.' },
  { cweId: 'CWE-613', section: 'V3.1.2', title: 'Absolute Session Timeout', description: 'Verify that sessions are invalidated after a defined absolute timeout period.' },
  { cweId: 'CWE-862', section: 'V4.1.1', title: 'Authorization Enforcement', description: 'Verify that the application enforces access controls at every tier.' },
  { cweId: 'CWE-639', section: 'V4.1.2', title: 'Object-Level Authorization', description: 'Verify IDOR prevention per object.' },
  { cweId: 'CWE-352', section: 'V4.2.2', title: 'CSRF Protection', description: 'Verify CSRF protection for state-changing operations.' },
  { cweId: 'CWE-89', section: 'V5.1.4', title: 'SQL Parameterization', description: 'Verify that SQL queries are parameterized.' },
  { cweId: 'CWE-79', section: 'V5.3.3', title: 'Contextual Output Encoding', description: 'Verify contextual output encoding for XSS prevention.' },
  { cweId: 'CWE-78', section: 'V5.2.4', title: 'OS Command Injection Prevention', description: 'Verify that OS commands are constructed safely.' },
  { cweId: 'CWE-22', section: 'V5.2.6', title: 'Path Traversal Prevention', description: 'Verify that file paths are constructed safely.' },
  { cweId: 'CWE-918', section: 'V5.2.6', title: 'SSRF Prevention', description: 'Verify URL validation for server-side requests.' },
  { cweId: 'CWE-502', section: 'V5.5.3', title: 'Safe Deserialization', description: 'Verify safe deserialization practices.' },
  { cweId: 'CWE-327', section: 'V6.2.3', title: 'Weak Algorithm Detection', description: 'Verify only approved cryptographic algorithms are used.' },
  { cweId: 'CWE-326', section: 'V6.2.2', title: 'Key Strength', description: 'Verify encryption keys meet minimum strength requirements.' },
  { cweId: 'CWE-209', section: 'V7.1.1', title: 'Safe Error Handling', description: 'Verify generic error messages are returned to users.' },
  { cweId: 'CWE-532', section: 'V7.4.2', title: 'Sensitive Information in Logs', description: 'Verify no sensitive data in logs.' },
  { cweId: 'CWE-489', section: 'V7.4.3', title: 'Debug Output in Production', description: 'Verify no debug output in production.' },
  { cweId: 'CWE-200', section: 'V7.4.1', title: 'Information Leakage', description: 'Verify no sensitive info leakage.' },
  { cweId: 'CWE-319', section: 'V14.4.1', title: 'HTTPS Enforcement', description: 'Verify HTTPS enforcement for sensitive data.' },
  { cweId: 'CWE-94', section: 'V5.2.2', title: 'Code Injection Prevention', description: 'Verify code injection prevention.' },
  { cweId: 'CWE-611', section: 'V5.5.2', title: 'XML Processing Security', description: 'Verify XML parser security configuration.' },
  { cweId: 'CWE-601', section: 'V5.2.7', title: 'Open Redirect Prevention', description: 'Verify open redirect prevention.' },
  { cweId: 'CWE-347', section: 'V6.3.1', title: 'JWT Token Validation', description: 'Verify JWT tokens are properly validated.' },
  { cweId: 'CWE-434', section: 'V12.2.1', title: 'File Upload Validation', description: 'Verify secure file upload handling.' },
  { cweId: 'CWE-285', section: 'V4.3.1', title: 'Administrative Authorization', description: 'Verify administrative interfaces use appropriate authorization.' },
];

const CWE_TOP_25_2024: Array<{ rank: number; cweId: string; name: string; score: number }> = [
  { rank: 1,  cweId: 'CWE-787', name: 'Out-of-bounds Write',                                 score: 64.29 },
  { rank: 2,  cweId: 'CWE-79',  name: 'Cross-site Scripting (XSS)',                         score: 47.53 },
  { rank: 3,  cweId: 'CWE-89',  name: 'SQL Injection',                                      score: 33.97 },
  { rank: 4,  cweId: 'CWE-416', name: 'Use After Free',                                     score: 16.86 },
  { rank: 5,  cweId: 'CWE-352', name: 'Cross-Site Request Forgery (CSRF)',                  score: 15.70 },
  { rank: 6,  cweId: 'CWE-78',  name: 'OS Command Injection',                               score: 15.32 },
  { rank: 7,  cweId: 'CWE-862', name: 'Missing Authorization',                              score: 15.18 },
  { rank: 8,  cweId: 'CWE-22',  name: 'Path Traversal',                                     score: 14.36 },
  { rank: 9,  cweId: 'CWE-125', name: 'Out-of-bounds Read',                                  score: 14.02 },
  { rank: 10, cweId: 'CWE-119', name: 'Buffer Overflow',                                    score: 13.58 },
  { rank: 11, cweId: 'CWE-287', name: 'Improper Authentication',                            score: 12.72 },
  { rank: 12, cweId: 'CWE-476', name: 'NULL Pointer Dereference',                           score: 12.18 },
  { rank: 13, cweId: 'CWE-798', name: 'Use of Hard-coded Credentials',                     score: 11.07 },
  { rank: 14, cweId: 'CWE-200', name: 'Exposure of Sensitive Information',                  score: 10.49 },
  { rank: 15, cweId: 'CWE-77',  name: 'Command Injection',                                  score: 10.26 },
  { rank: 16, cweId: 'CWE-306', name: 'Missing Authentication for Critical Function',        score:  9.73 },
  { rank: 17, cweId: 'CWE-502', name: 'Deserialization of Untrusted Data',                  score:  8.53 },
  { rank: 18, cweId: 'CWE-269', name: 'Improper Privilege Management',                      score:  8.40 },
  { rank: 19, cweId: 'CWE-400', name: 'Uncontrolled Resource Consumption',                   score:  8.37 },
  { rank: 20, cweId: 'CWE-190', name: 'Integer Overflow or Wraparound',                      score:  7.76 },
  { rank: 21, cweId: 'CWE-732', name: 'Incorrect Permission Assignment',                    score:  7.62 },
  { rank: 22, cweId: 'CWE-611', name: 'XML External Entity (XXE)',                          score:  7.34 },
  { rank: 23, cweId: 'CWE-918', name: 'Server-Side Request Forgery (SSRF)',                  score:  6.95 },
  { rank: 24, cweId: 'CWE-276', name: 'Incorrect Default Permissions',                       score:  6.88 },
  { rank: 25, cweId: 'CWE-434', name: 'Unrestricted Upload of Dangerous File Type',          score:  6.66 },
];

const SAST_COVERED_CWES = new Set([
  'CWE-89', 'CWE-79', 'CWE-78', 'CWE-798', 'CWE-327', 'CWE-22', 'CWE-918',
  'CWE-502', 'CWE-611', 'CWE-1321', 'CWE-601', 'CWE-347', 'CWE-1333',
  'CWE-489', 'CWE-676', 'CWE-862', 'CWE-639', 'CWE-352', 'CWE-200',
  'CWE-532', 'CWE-614', 'CWE-1004', 'CWE-521', 'CWE-917', 'CWE-94',
  'CWE-643', 'CWE-330', 'CWE-338', 'CWE-326', 'CWE-209', 'CWE-434',
  'CWE-319', 'CWE-759', 'CWE-23', 'CWE-285', 'CWE-539', 'CWE-613',
  'CWE-77', 'CWE-416', 'CWE-125', 'CWE-119', 'CWE-287', 'CWE-476',
  'CWE-306', 'CWE-269', 'CWE-400', 'CWE-190', 'CWE-732', 'CWE-276',
]);

const PCI_DSS_MAPPING: Array<{
  cweId: string;
  requirementId: string;
  subRequirementId: string;
  title: string;
  description: string;
}> = [
  { cweId: 'CWE-89', requirementId: '6.2.4', subRequirementId: '6.2.4.1', title: 'SQL Injection Prevention', description: 'Parameterized queries and prepared statements to prevent SQL injection.' },
  { cweId: 'CWE-79', requirementId: '6.2.4', subRequirementId: '6.2.4.2', title: 'XSS Prevention', description: 'Contextual output encoding and CSP to prevent XSS.' },
  { cweId: 'CWE-78', requirementId: '6.2.4', subRequirementId: '6.2.4.3', title: 'Command Injection Prevention', description: 'Safe construction of OS commands.' },
  { cweId: 'CWE-22', requirementId: '6.2.4', subRequirementId: '6.2.4.4', title: 'Path Traversal Prevention', description: 'Path normalization and allowlists.' },
  { cweId: 'CWE-918', requirementId: '6.2.4', subRequirementId: '6.2.4.5', title: 'SSRF Prevention', description: 'URL validation and allowlists.' },
  { cweId: 'CWE-502', requirementId: '6.2.4', subRequirementId: '6.2.4.6', title: 'Safe Deserialization', description: 'Avoiding deserialization of untrusted data.' },
  { cweId: 'CWE-798', requirementId: '6.2.4', subRequirementId: '6.2.4.7', title: 'Secrets Management', description: 'Avoiding hardcoded credentials.' },
  { cweId: 'CWE-327', requirementId: '6.2.4', subRequirementId: '6.2.4.8', title: 'Cryptographic Practices', description: 'Using only approved cryptographic algorithms.' },
  { cweId: 'CWE-862', requirementId: '6.2.4', subRequirementId: '6.2.4.9', title: 'Access Control Enforcement', description: 'Proper authorization checks at every tier.' },
  { cweId: 'CWE-89', requirementId: '6.3.2', subRequirementId: '6.3.2.1', title: 'SQL Injection Patching', description: 'SQL Injection must be remediated as critical.' },
  { cweId: 'CWE-78', requirementId: '6.3.2', subRequirementId: '6.3.2.2', title: 'Command Injection Patching', description: 'Command Injection must be remediated.' },
  { cweId: 'CWE-798', requirementId: '6.3.2', subRequirementId: '6.3.2.3', title: 'Hardcoded Credential Remediation', description: 'Hardcoded credentials must be remediated.' },
  { cweId: 'CWE-502', requirementId: '6.3.2', subRequirementId: '6.3.2.4', title: 'Deserialization Remediation', description: 'Insecure deserialization must be remediated.' },
  { cweId: 'CWE-79', requirementId: '11.3.1', subRequirementId: '11.3.1.1', title: 'XSS in Vulnerability Scans', description: 'Detect XSS in vulnerability scans.' },
  { cweId: 'CWE-89', requirementId: '11.3.1', subRequirementId: '11.3.1.2', title: 'SQL Injection in Vulnerability Scans', description: 'Detect SQL injection in scans.' },
  { cweId: 'CWE-918', requirementId: '11.3.1', subRequirementId: '11.3.1.3', title: 'SSRF in Vulnerability Scans', description: 'Detect SSRF in scans.' },
  { cweId: 'CWE-22', requirementId: '11.3.1', subRequirementId: '11.3.1.4', title: 'Path Traversal in Vulnerability Scans', description: 'Detect path traversal in scans.' },
];

const PCI_DSS_REQ_TITLES: Record<string, string> = {
  '6.2.4': 'Software Engineering Techniques',
  '6.3.2': 'Security Vulnerabilities Addressed',
  '11.3.1': 'External and Internal Vulnerability Scans',
};

const PCI_DSS_REQ_DESCRIPTIONS: Record<string, string> = {
  '6.2.4': 'Software development personnel must be trained in secure coding techniques.',
  '6.3.2': 'Security vulnerabilities must be evaluated and addressed based on risk ranking.',
  '11.3.1': 'External and internal vulnerability scans must be performed regularly.',
};

// ---------------------------------------------------------------------------
// Core Compliance Report Generator
// ---------------------------------------------------------------------------

/**
 * Generate a compliance report for a core framework (OWASP ASVS, CWE Top 25, PCI DSS).
 */
export function generateCoreComplianceReport(
  findings: FindingStub[],
  framework: ComplianceFramework,
): ComplianceReport {
  switch (framework) {
    case 'owasp-asvs':
      return generateASVSReport(findings);
    case 'cwe-top25':
      return generateCweTop25Report(findings);
    case 'pci-dss':
      return generatePciDssReport(findings);
    default: {
      const _exhaustive: never = framework;
      throw new Error(`Unknown framework: ${_exhaustive}`);
    }
  }
}

function generateASVSReport(findings: FindingStub[]): ComplianceReport {
  const cweGroups = groupFindingsByCwe(findings);
  const sectionResults = new Map<string, { title: string; description: string; status: 'passed' | 'failed' | 'not-tested'; findingCount: number }>();

  // Initialize all sections as not-tested
  for (const entry of ASVS_MAPPING) {
    if (!sectionResults.has(entry.section)) {
      sectionResults.set(entry.section, {
        title: entry.title,
        description: `${entry.section} - ${entry.title}`,
        status: 'not-tested',
        findingCount: 0,
      });
    }
  }

  // Mark sections with findings as failed
  for (const entry of ASVS_MAPPING) {
    const matched = cweGroups.get(entry.cweId);
    if (matched && matched.length > 0) {
      const existing = sectionResults.get(entry.section)!;
      existing.status = 'failed';
      existing.findingCount += matched.length;
    }
  }

  const requirements = Array.from(sectionResults.entries()).map(([section, data]) => ({
    requirementId: section,
    title: data.title,
    description: data.description,
    status: data.status,
    findingCount: data.findingCount,
  }));

  const passedCount = 0;
  const failedCount = requirements.filter(r => r.status === 'failed').length;
  const notTestedCount = requirements.filter(r => r.status === 'not-tested').length;
  const totalRequirements = requirements.length;
  const coveragePercent = totalRequirements > 0
    ? Math.round(((passedCount + failedCount) / totalRequirements) * 100)
    : 0;

  const gapAnalysis = requirements
    .filter(r => r.status === 'not-tested')
    .map(r => ({
      requirementId: r.requirementId,
      title: r.title,
      gapType: 'no-findings' as const,
      recommendation: `ASVS ${r.requirementId} (${r.title}) has no findings. Consider manual verification or additional rules.`,
    }));

  return {
    framework: 'owasp-asvs',
    frameworkName: 'OWASP ASVS v4.0',
    generatedAt: new Date().toISOString(),
    overallCoveragePercent: coveragePercent,
    passedCount,
    failedCount,
    notTestedCount,
    totalRequirements,
    executiveSummary: buildExecutiveSummary('OWASP ASVS v4.0', coveragePercent, passedCount, failedCount, notTestedCount, totalRequirements),
    requirements,
    gapAnalysis,
  };
}

function generateCweTop25Report(findings: FindingStub[]): ComplianceReport {
  const cweGroups = groupFindingsByCwe(findings);

  const requirements = CWE_TOP_25_2024.map(entry => {
    const matched = cweGroups.get(entry.cweId) ?? [];
    const isCovered = SAST_COVERED_CWES.has(entry.cweId);
    const status: 'passed' | 'failed' | 'not-tested' =
      matched.length > 0 ? 'failed' : (isCovered ? 'passed' : 'not-tested');

    return {
      requirementId: entry.cweId,
      title: `#${entry.rank} ${entry.name} (Score: ${entry.score})`,
      description: `CWE Top 25 (2024) Rank ${entry.rank}: ${entry.name}`,
      status,
      findingCount: matched.length,
    };
  });

  const passedCount = 0;
  const failedCount = requirements.filter(r => r.status === 'failed').length;
  const notTestedCount = requirements.filter(r => r.status === 'not-tested').length;
  const totalRequirements = requirements.length;
  const coveragePercent = totalRequirements > 0
    ? Math.round(((passedCount + failedCount) / totalRequirements) * 100)
    : 0;

  const gapAnalysis = requirements
    .filter(r => r.status === 'not-tested')
    .map(r => ({
      requirementId: r.requirementId,
      title: r.title,
      gapType: 'no-automated-coverage' as const,
      recommendation: `CWE Top 25 entry ${r.title} requires manual review — no automated SAST rule exists.`,
    }));

  return {
    framework: 'cwe-top25',
    frameworkName: 'CWE Top 25 Most Dangerous (2024)',
    generatedAt: new Date().toISOString(),
    overallCoveragePercent: coveragePercent,
    passedCount,
    failedCount,
    notTestedCount,
    totalRequirements,
    executiveSummary: buildExecutiveSummary('CWE Top 25 (2024)', coveragePercent, passedCount, failedCount, notTestedCount, totalRequirements),
    requirements,
    gapAnalysis,
  };
}

function generatePciDssReport(findings: FindingStub[]): ComplianceReport {
  const cweGroups = groupFindingsByCwe(findings);

  // Group by requirement ID
  const reqMap = new Map<string, { title: string; description: string; subResults: Array<{ status: 'passed' | 'failed' | 'not-tested'; findingCount: number }> }>();

  for (const entry of PCI_DSS_MAPPING) {
    if (!reqMap.has(entry.requirementId)) {
      reqMap.set(entry.requirementId, {
        title: PCI_DSS_REQ_TITLES[entry.requirementId] ?? `PCI DSS ${entry.requirementId}`,
        description: PCI_DSS_REQ_DESCRIPTIONS[entry.requirementId] ?? '',
        subResults: [],
      });
    }
    const matched = cweGroups.get(entry.cweId) ?? [];
    reqMap.get(entry.requirementId)!.subResults.push({
      status: matched.length > 0 ? 'failed' : 'not-tested',
      findingCount: matched.length,
    });
  }

  const requirements = Array.from(reqMap.entries()).map(([reqId, data]) => {
    const hasFailed = data.subResults.some(s => s.status === 'failed');
    const totalFindings = data.subResults.reduce((sum, s) => sum + s.findingCount, 0);
    return {
      requirementId: reqId,
      title: data.title,
      description: data.description,
      status: hasFailed ? 'failed' as const : 'not-tested' as const,
      findingCount: totalFindings,
    };
  });

  const passedCount = 0;
  const failedCount = requirements.filter(r => r.status === 'failed').length;
  const notTestedCount = requirements.filter(r => r.status === 'not-tested').length;
  const totalRequirements = requirements.length;
  const coveragePercent = totalRequirements > 0
    ? Math.round(((totalRequirements - notTestedCount) / totalRequirements) * 100)
    : 0;

  const gapAnalysis = requirements
    .filter(r => r.status === 'not-tested')
    .map(r => ({
      requirementId: r.requirementId,
      title: r.title,
      gapType: 'partial-coverage' as const,
      recommendation: `PCI DSS ${r.requirementId} (${r.title}) has no findings mapped. Review if SAST rules cover the sub-requirements.`,
    }));

  return {
    framework: 'pci-dss',
    frameworkName: 'PCI DSS v4.0',
    generatedAt: new Date().toISOString(),
    overallCoveragePercent: coveragePercent,
    passedCount,
    failedCount,
    notTestedCount,
    totalRequirements,
    executiveSummary: buildExecutiveSummary('PCI DSS v4.0', coveragePercent, passedCount, failedCount, notTestedCount, totalRequirements),
    requirements,
    gapAnalysis,
  };
}

// ---------------------------------------------------------------------------
// SOC2 Mapper
// ---------------------------------------------------------------------------

/**
 * Map security findings to SOC2 Type II Trust Service Criteria.
 */
export function mapToSOC2(findings: FindingStub[]): SOC2MappingResult {
  const cweGroups = groupFindingsByCwe(findings);

  const criteria: SOC2CriterionResult[] = SOC2_MAPPING.map((criterion) => {
    let totalFindings = 0;
    const matchedCweIds: string[] = [];

    for (const cweId of criterion.cweIds) {
      const normalized = normalizeCweId(cweId);
      const matched = cweGroups.get(normalized);
      if (matched && matched.length > 0) {
        totalFindings += matched.length;
        matchedCweIds.push(normalized);
      }
    }

    let status: 'pass' | 'fail' | 'partial';
    if (totalFindings === 0) {
      status = 'pass';
    } else if (matchedCweIds.length === criterion.cweIds.length) {
      status = 'fail';
    } else {
      status = 'partial';
    }

    return {
      criterionId: criterion.criterionId,
      title: criterion.title,
      description: criterion.description,
      status,
      matchingFindingsCount: totalFindings,
      cweIds: criterion.cweIds,
      matchedCweIds,
      remediationGuidance: SOC2_REMEDIATION[criterion.criterionId] ?? '',
    };
  });

  const passCount = criteria.filter(c => c.status === 'pass').length;
  const failCount = criteria.filter(c => c.status === 'fail').length;
  const partialCount = criteria.filter(c => c.status === 'partial').length;
  const totalCriteria = criteria.length;

  const overallStatus: 'pass' | 'fail' | 'partial' =
    failCount > 0 ? 'fail' : (partialCount > 0 ? 'partial' : 'pass');

  let posture: string;
  if (overallStatus === 'pass') {
    posture = 'Strong compliance posture against SOC2 Type II Trust Service Criteria.';
  } else if (overallStatus === 'partial') {
    posture = 'Partial compliance with SOC2 Type II Trust Service Criteria. Some criteria have security findings that require remediation.';
  } else {
    posture = 'Compliance gaps detected against SOC2 Type II Trust Service Criteria. Multiple criteria have security findings requiring immediate attention.';
  }

  const breakdown = `Of ${totalCriteria} criteria evaluated: ${passCount} passed, ${failCount} failed, ${partialCount} partially met.`;
  let action = '';
  if (failCount > 0) action = ' Prioritize remediation of failed criteria to achieve SOC2 readiness.';
  else if (partialCount > 0) action = ' Address partial findings to strengthen compliance posture.';
  else action = ' No automated findings detected. Continue periodic review and manual verification.';

  return {
    framework: 'SOC2 Type II',
    generatedAt: new Date().toISOString(),
    overallStatus,
    criteria,
    passCount,
    failCount,
    partialCount,
    totalCriteria,
    executiveSummary: `${posture} ${breakdown}${action}`,
  };
}

// ---------------------------------------------------------------------------
// HIPAA Mapper
// ---------------------------------------------------------------------------

/**
 * Map security findings to HIPAA Security Rule requirements.
 */
export function mapToHIPAA(findings: FindingStub[]): HIPAAMappingResult {
  const cweGroups = groupFindingsByCwe(findings);

  const requirements: HIPAARequirementResult[] = HIPAA_MAPPING.map((requirement) => {
    let totalFindings = 0;
    const matchedCweIds: string[] = [];

    for (const cweId of requirement.cweIds) {
      const normalized = normalizeCweId(cweId);
      const matched = cweGroups.get(normalized);
      if (matched && matched.length > 0) {
        totalFindings += matched.length;
        matchedCweIds.push(normalized);
      }
    }

    let status: 'pass' | 'fail' | 'partial';
    if (totalFindings === 0) {
      status = 'pass';
    } else if (matchedCweIds.length === requirement.cweIds.length) {
      status = 'fail';
    } else {
      status = 'partial';
    }

    return {
      requirementId: requirement.requirementId,
      title: requirement.title,
      description: requirement.description,
      status,
      matchingFindingsCount: totalFindings,
      cweIds: requirement.cweIds,
      matchedCweIds,
      remediationGuidance: HIPAA_REMEDIATION[requirement.requirementId] ?? '',
    };
  });

  const passCount = requirements.filter(r => r.status === 'pass').length;
  const failCount = requirements.filter(r => r.status === 'fail').length;
  const partialCount = requirements.filter(r => r.status === 'partial').length;
  const totalRequirements = requirements.length;

  const overallStatus: 'pass' | 'fail' | 'partial' =
    failCount > 0 ? 'fail' : (partialCount > 0 ? 'partial' : 'pass');

  let posture: string;
  if (overallStatus === 'pass') {
    posture = 'Strong compliance posture against HIPAA Security Rule technical safeguards.';
  } else if (overallStatus === 'partial') {
    posture = 'Partial compliance with HIPAA Security Rule technical safeguards. Some requirements have security findings that may impact ePHI protection.';
  } else {
    posture = 'Compliance gaps detected against HIPAA Security Rule technical safeguards. Multiple requirements have findings that must be remediated to protect ePHI.';
  }

  const breakdown = `Of ${totalRequirements} requirements evaluated: ${passCount} passed, ${failCount} failed, ${partialCount} partially met.`;
  let action = '';
  if (failCount > 0) action = ' Immediate remediation required for failed requirements to maintain HIPAA compliance and protect electronic protected health information (ePHI).';
  else if (partialCount > 0) action = ' Address partial findings to strengthen ePHI protection and ensure full HIPAA compliance.';
  else action = ' No automated findings detected. Continue periodic risk assessments and manual verification of safeguards.';

  return {
    framework: 'HIPAA Security Rule',
    generatedAt: new Date().toISOString(),
    overallStatus,
    requirements,
    passCount,
    failCount,
    partialCount,
    totalRequirements,
    executiveSummary: `${posture} ${breakdown}${action}`,
  };
}

// ---------------------------------------------------------------------------
// Generate All Reports
// ---------------------------------------------------------------------------

/**
 * Generate compliance reports for all supported core frameworks.
 */
export function generateAllCoreComplianceReports(findings: FindingStub[]): Record<ComplianceFramework, ComplianceReport> {
  return {
    'owasp-asvs': generateCoreComplianceReport(findings, 'owasp-asvs'),
    'cwe-top25': generateCoreComplianceReport(findings, 'cwe-top25'),
    'pci-dss': generateCoreComplianceReport(findings, 'pci-dss'),
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildExecutiveSummary(
  label: string,
  coveragePercent: number,
  passedCount: number,
  failedCount: number,
  notTestedCount: number,
  totalRequirements: number,
): string {
  const hasFailures = failedCount > 0;

  let summary: string;
  if (coveragePercent >= 80 && !hasFailures) {
    summary = `Strong compliance posture against ${label}.`;
  } else if (coveragePercent >= 50) {
    summary = `Moderate compliance coverage against ${label} with gaps requiring attention.`;
  } else {
    summary = `Limited compliance coverage against ${label}. Significant automation gaps exist.`;
  }

  let failureDetail = '';
  if (hasFailures) {
    failureDetail = ` ${failedCount} requirement(s) have failed findings that must be remediated.`;
  }

  let gapDetail = '';
  if (notTestedCount > 0) {
    gapDetail = ` ${notTestedCount} requirement(s) could not be tested automatically and ${notTestedCount > 1 ? 'require' : 'requires'} manual review.`;
  }

  return [
    summary,
    `Of ${totalRequirements} total requirements: ${passedCount} passed, ${failedCount} failed, ${notTestedCount} not tested.`,
    `Automated coverage: ${coveragePercent}%.`,
    failureDetail,
    gapDetail,
    hasFailures
      ? 'Critical remediation needed for failed requirements to achieve compliance.'
      : 'No automated findings detected for covered requirements. Continue manual verification for non-automated areas.',
  ].filter(Boolean).join(' ');
}
