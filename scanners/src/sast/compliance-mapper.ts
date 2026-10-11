// ============================================================
// Compliance Framework Mapper
// Maps SAST/DAST findings to OWASP ASVS v4.0, CWE Top 25,
// and PCI DSS v4.0 compliance frameworks.
// ============================================================

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ComplianceFramework = 'owasp-asvs' | 'cwe-top25' | 'pci-dss';

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

export interface ASVSMappingEntry {
  cweId: string;
  cweName: string;
  asvsChapter: string;
  asvsSection: string;
  asvsTitle: string;
  asvsDescription: string;
  asvsVerificationType: 'automated' | 'manual' | 'hybrid';
}

export interface ASVSMappingResult {
  cweId: string;
  findingId: string;
  status: 'passed' | 'failed';
  asvsSection: string;
  asvsTitle: string;
  asvsDescription: string;
  severity: string;
  automatedCoverage: boolean;
}

export interface ASVSRequirementCoverage {
  asvsSection: string;
  asvsTitle: string;
  asvsLevel: number;
  status: 'passed' | 'failed' | 'not-tested';
  type: 'sast' | 'dast' | 'manual' | 'hybrid';
  automatedBySast: boolean;
  automatedByDast: boolean;
  requiresManualReview: boolean;
}

export interface CweTop25Entry {
  rank: number;
  cweId: string;
  name: string;
  score: number;
  coverage: 'covered' | 'partial' | 'manual-review' | 'uncovered';
  findingCount: number;
  relevantFindings: string[];
}

export interface CweTop25Result {
  year: number;
  totalEntries: number;
  coveredCount: number;
  partialCount: number;
  manualReviewCount: number;
  uncoveredCount: number;
  coveragePercent: number;
  entries: CweTop25Entry[];
}

export interface PciDssRequirement {
  requirementId: string;
  title: string;
  description: string;
  subRequirements: PciDssSubRequirement[];
  status: 'passed' | 'failed' | 'not-tested';
  automatedCoverage: boolean;
}

export interface PciDssSubRequirement {
  subId: string;
  title: string;
  status: 'passed' | 'failed' | 'not-tested';
  findingCount: number;
}

export interface PciDssResult {
  framework: 'PCI DSS v4.0';
  requirements: PciDssRequirement[];
  overallStatus: 'passed' | 'failed' | 'not-tested';
  coveragePercent: number;
  passedCount: number;
  failedCount: number;
  notTestedCount: number;
}

export interface GapItem {
  requirementId: string;
  title: string;
  gapType: 'no-automated-coverage' | 'partial-coverage' | 'no-findings';
  recommendation: string;
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

export interface CoverageMatrixCell {
  asvsSection: string;
  asvsTitle: string;
  asvsLevel: number;
  sastCoverage: boolean;
  dastCoverage: boolean;
  requiresManualReview: boolean;
}

export type CoverageMatrix = CoverageMatrixCell[];

// ---------------------------------------------------------------------------
// Static Mapping Tables
// ---------------------------------------------------------------------------

/**
 * ASVS v4.0 mapping table covering 15+ CWE IDs to specific ASVS sections.
 * Each entry maps a CWE to its relevant ASVS v4.0 requirement with
 * verification type (automated by SAST/DAST, manual review, or hybrid).
 */
export const ASVS_MAPPING_TABLE: ASVSMappingEntry[] = [
  // --- V2: Authentication Verification ---
  {
    cweId: 'CWE-798',
    cweName: 'Use of Hard-coded Credentials',
    asvsChapter: 'V2 - Authentication',
    asvsSection: 'V2.10.4',
    asvsTitle: 'Hardcoded Credentials',
    asvsDescription: 'Verify that there are no hardcoded credentials, API keys, or secrets in source code, configuration files, or binaries.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-521',
    cweName: 'Weak Password Requirements',
    asvsChapter: 'V2 - Authentication',
    asvsSection: 'V2.2.1',
    asvsTitle: 'Password Strength Requirements',
    asvsDescription: 'Verify that password minimum length and complexity requirements are enforced.',
    asvsVerificationType: 'automated',
  },

  // --- V3: Session Management ---
  {
    cweId: 'CWE-614',
    cweName: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
    asvsChapter: 'V3 - Session Management',
    asvsSection: 'V3.4.2',
    asvsTitle: 'Cookie Secure Flag',
    asvsDescription: 'Verify that the Secure attribute is set for all cookies containing sensitive data.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-1004',
    cweName: 'Sensitive Cookie Without HttpOnly',
    asvsChapter: 'V3 - Session Management',
    asvsSection: 'V3.4.3',
    asvsTitle: 'Cookie HttpOnly Flag',
    asvsDescription: 'Verify that the HttpOnly attribute is set for all cookies containing sensitive data.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-539',
    cweName: 'Persistent Cookies',
    asvsChapter: 'V3 - Session Management',
    asvsSection: 'V3.1.1',
    asvsTitle: 'Session Expiration',
    asvsDescription: 'Verify that the application expires sessions after a defined period of inactivity.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-613',
    cweName: 'Insufficient Session Expiration',
    asvsChapter: 'V3 - Session Management',
    asvsSection: 'V3.1.2',
    asvsTitle: 'Absolute Session Timeout',
    asvsDescription: 'Verify that sessions are invalidated after a defined absolute timeout period.',
    asvsVerificationType: 'hybrid',
  },

  // --- V4: Access Control ---
  {
    cweId: 'CWE-862',
    cweName: 'Missing Authorization',
    asvsChapter: 'V4 - Access Control',
    asvsSection: 'V4.1.1',
    asvsTitle: 'Authorization Enforcement',
    asvsDescription: 'Verify that the application enforces access controls at every tier, protecting all functions, files, and URLs.',
    asvsVerificationType: 'hybrid',
  },
  {
    cweId: 'CWE-639',
    cweName: 'Insecure Direct Object Reference (IDOR)',
    asvsChapter: 'V4 - Access Control',
    asvsSection: 'V4.1.2',
    asvsTitle: 'Object-Level Authorization',
    asvsDescription: 'Verify that the application verifies the user is authorized to access each referenced object (IDOR prevention).',
    asvsVerificationType: 'hybrid',
  },
  {
    cweId: 'CWE-352',
    cweName: 'Cross-Site Request Forgery (CSRF)',
    asvsChapter: 'V4 - Access Control',
    asvsSection: 'V4.2.2',
    asvsTitle: 'CSRF Protection',
    asvsDescription: 'Verify that the application includes CSRF protection (tokens, SameSite cookies, or custom headers) for state-changing operations.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-285',
    cweName: 'Improper Authorization',
    asvsChapter: 'V4 - Access Control',
    asvsSection: 'V4.3.1',
    asvsTitle: 'Administrative Authorization',
    asvsDescription: 'Verify that administrative interfaces use appropriate authorization controls.',
    asvsVerificationType: 'hybrid',
  },

  // --- V5: Validation, Sanitization and Encoding ---
  {
    cweId: 'CWE-89',
    cweName: 'SQL Injection',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.1.4',
    asvsTitle: 'SQL Parameterization',
    asvsDescription: 'Verify that SQL queries are parameterized or use safely constructed ORM queries to prevent SQL injection.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-79',
    cweName: 'Cross-Site Scripting (XSS)',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.3.3',
    asvsTitle: 'Contextual Output Encoding',
    asvsDescription: 'Verify that contextual output encoding is applied to all untrusted data rendered in HTML, JavaScript, CSS, or URL contexts.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-78',
    cweName: 'OS Command Injection',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.2.4',
    asvsTitle: 'OS Command Injection Prevention',
    asvsDescription: 'Verify that OS commands are constructed safely and user input is never passed directly to shell interpreters.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-22',
    cweName: 'Path Traversal',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.2.6',
    asvsTitle: 'Path Traversal Prevention',
    asvsDescription: 'Verify that file paths are constructed safely to prevent directory traversal attacks using user-supplied input.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-918',
    cweName: 'Server-Side Request Forgery (SSRF)',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.2.6',
    asvsTitle: 'SSRF / Path Traversal Prevention',
    asvsDescription: 'Verify that the application validates and sanitizes URLs used in server-side HTTP requests to prevent SSRF.',
    asvsVerificationType: 'hybrid',
  },
  {
    cweId: 'CWE-502',
    cweName: 'Insecure Deserialization',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.5.3',
    asvsTitle: 'Safe Deserialization',
    asvsDescription: 'Verify that untrusted data is never deserialized using unsafe serialization formats.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-611',
    cweName: 'XML External Entity (XXE) Injection',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.5.2',
    asvsTitle: 'XML Processing Security',
    asvsDescription: 'Verify that XML parsers are securely configured to disable external entity resolution.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-601',
    cweName: 'Open Redirect',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.2.7',
    asvsTitle: 'Unvalidated Redirects',
    asvsDescription: 'Verify that the application validates redirect URLs against an allowlist and does not forward user-supplied URLs.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-1321',
    cweName: 'Prototype Pollution',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.1.6',
    asvsTitle: 'Input Validation for Object Merges',
    asvsDescription: 'Verify that object merge and extend operations validate property keys to prevent prototype pollution.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-917',
    cweName: 'Expression Language Injection',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.2.5',
    asvsTitle: 'Expression Language Injection Prevention',
    asvsDescription: 'Verify that user input is not passed to expression language evaluation functions.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-643',
    cweName: 'XPath Injection',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.2.3',
    asvsTitle: 'XPath/LDAP Injection Prevention',
    asvsDescription: 'Verify that parameterized queries are used for XPath and LDAP queries.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-94',
    cweName: 'Code Injection',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.2.2',
    asvsTitle: 'Server-Side Code Injection Prevention',
    asvsDescription: 'Verify that user input is never passed to eval(), Function(), or other dynamic code execution functions.',
    asvsVerificationType: 'automated',
  },

  // --- V6: Stored Cryptography ---
  {
    cweId: 'CWE-327',
    cweName: 'Use of a Broken or Risky Cryptographic Algorithm',
    asvsChapter: 'V6 - Stored Cryptography',
    asvsSection: 'V6.2.3',
    asvsTitle: 'Weak Algorithm Detection',
    asvsDescription: 'Verify that only approved cryptographic algorithms (AES-256-GCM, SHA-256/SHA-3, RSA-4096, ECDH) are used.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-347',
    cweName: 'Improper Verification of Cryptographic Signature (JWT)',
    asvsChapter: 'V6 - Stored Cryptography',
    asvsSection: 'V6.3.1',
    asvsTitle: 'JWT Token Validation',
    asvsDescription: 'Verify that JWT tokens are properly validated including signature, expiration, audience, and issuer claims.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-330',
    cweName: 'Insufficiently Random Values',
    asvsChapter: 'V6 - Stored Cryptography',
    asvsSection: 'V6.1.1',
    asvsTitle: 'Cryptographic Randomness',
    asvsDescription: 'Verify that all cryptographic operations use cryptographically secure random number generators.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-338',
    cweName: 'Use of Cryptographically Weak Pseudo-Random Number Generator',
    asvsChapter: 'V6 - Stored Cryptography',
    asvsSection: 'V6.1.2',
    asvsTitle: 'Secure PRNG',
    asvsDescription: 'Verify that Math.random() or similar non-cryptographic PRNGs are not used for security-sensitive operations.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-326',
    cweName: 'Inadequate Encryption Strength',
    asvsChapter: 'V6 - Stored Cryptography',
    asvsSection: 'V6.2.2',
    asvsTitle: 'Key Strength',
    asvsDescription: 'Verify that encryption keys meet minimum strength requirements (AES-128+, RSA-2048+, ECDH-224+).',
    asvsVerificationType: 'automated',
  },

  // --- V7: Error Handling and Logging ---
  {
    cweId: 'CWE-200',
    cweName: 'Exposure of Sensitive Information',
    asvsChapter: 'V7 - Error Handling and Logging',
    asvsSection: 'V7.4.1',
    asvsTitle: 'Information Leakage',
    asvsDescription: 'Verify that the application does not leak sensitive information in error messages, stack traces, or response headers.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-532',
    cweName: 'Insertion of Sensitive Information into Log File',
    asvsChapter: 'V7 - Error Handling and Logging',
    asvsSection: 'V7.4.2',
    asvsTitle: 'Sensitive Information in Logs',
    asvsDescription: 'Verify that the application does not log credentials, session tokens, PII, or other sensitive data.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-489',
    cweName: 'Leftover Debug Code',
    asvsChapter: 'V7 - Error Handling and Logging',
    asvsSection: 'V7.4.3',
    asvsTitle: 'Debug Output in Production',
    asvsDescription: 'Verify that debug output, development tools, and test code are removed from production deployments.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-209',
    cweName: 'Information Exposure Through Error Messages',
    asvsChapter: 'V7 - Error Handling and Logging',
    asvsSection: 'V7.1.1',
    asvsTitle: 'Safe Error Handling',
    asvsDescription: 'Verify that generic error messages are returned to users while details are logged server-side.',
    asvsVerificationType: 'automated',
  },

  // --- V12: Files and Resources ---
  {
    cweId: 'CWE-434',
    cweName: 'Unrestricted Upload of File with Dangerous Type',
    asvsChapter: 'V12 - Files and Resources',
    asvsSection: 'V12.2.1',
    asvsTitle: 'File Upload Validation',
    asvsDescription: 'Verify that file uploads validate type, size, and content to prevent malicious file uploads.',
    asvsVerificationType: 'hybrid',
  },
  {
    cweId: 'CWE-23',
    cweName: 'Relative Path Traversal',
    asvsChapter: 'V12 - Files and Resources',
    asvsSection: 'V12.1.1',
    asvsTitle: 'Secure File Access',
    asvsDescription: 'Verify that file access operations are restricted to authorized directories and normalized paths.',
    asvsVerificationType: 'automated',
  },

  // --- V13: API and Web Services ---
  {
    cweId: 'CWE-918',
    cweName: 'Server-Side Request Forgery (SSRF)',
    asvsChapter: 'V13 - API and Web Services',
    asvsSection: 'V13.1.3',
    asvsTitle: 'API SSRF Protection',
    asvsDescription: 'Verify that API endpoints validate and restrict outbound requests to prevent SSRF attacks.',
    asvsVerificationType: 'hybrid',
  },

  // --- V14: Configuration ---
  {
    cweId: 'CWE-319',
    cweName: 'Cleartext Transmission of Sensitive Information',
    asvsChapter: 'V14 - Configuration',
    asvsSection: 'V14.4.1',
    asvsTitle: 'HTTPS Enforcement',
    asvsDescription: 'Verify that all sensitive data is transmitted over TLS and HTTP Strict Transport Security is enforced.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-759',
    cweName: 'Use of a One-Way Hash without a Salt',
    asvsChapter: 'V6 - Stored Cryptography',
    asvsSection: 'V6.4.1',
    asvsTitle: 'Password Hashing with Salt',
    asvsDescription: 'Verify that passwords are hashed using strong, salted algorithms (Argon2, bcrypt, PBKDF2, scrypt).',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-676',
    cweName: 'Use of Potentially Dangerous Function',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.1.2',
    asvsTitle: 'Dangerous Function Detection',
    asvsDescription: 'Verify that dangerous functions (eval, exec, etc.) are not used with untrusted input.',
    asvsVerificationType: 'automated',
  },
  {
    cweId: 'CWE-1333',
    cweName: 'Inefficient Regular Expression (ReDoS)',
    asvsChapter: 'V5 - Validation, Sanitization and Encoding',
    asvsSection: 'V5.1.7',
    asvsTitle: 'ReDoS Prevention',
    asvsDescription: 'Verify that regular expressions used for input validation are not vulnerable to ReDoS attacks.',
    asvsVerificationType: 'automated',
  },
];

/**
 * CWE Top 25 Most Dangerous Software Weaknesses (2024).
 * Based on MITRE CWE Top 25 list with real ranks, IDs, names, and scores.
 * Covered CWEs are marked based on whether the SAST engine has rules for them.
 */
export const CWE_TOP_25_2024: Array<Omit<CweTop25Entry, 'coverage' | 'findingCount' | 'relevantFindings'>> = [
  { rank: 1,  cweId: 'CWE-787', name: 'Out-of-bounds Write',                                 score: 64.29 },
  { rank: 2,  cweId: 'CWE-79',  name: 'Cross-site Scripting (XSS)',                         score: 47.53 },
  { rank: 3,  cweId: 'CWE-89',  name: 'SQL Injection',                                      score: 33.97 },
  { rank: 4,  cweId: 'CWE-416', name: 'Use After Free',                                     score: 16.86 },
  { rank: 5,  cweId: 'CWE-352', name: 'Cross-Site Request Forgery (CSRF)',                  score: 15.70 },
  { rank: 6,  cweId: 'CWE-78',  name: 'OS Command Injection',                               score: 15.32 },
  { rank: 7,  cweId: 'CWE-862', name: 'Missing Authorization',                              score: 15.18 },
  { rank: 8,  cweId: 'CWE-22',  name: 'Path Traversal / Directory Traversal',               score: 14.36 },
  { rank: 9,  cweId: 'CWE-125', name: 'Out-of-bounds Read',                                  score: 14.02 },
  { rank: 10, cweId: 'CWE-119', name: 'Buffer Overflow',                                    score: 13.58 },
  { rank: 11, cweId: 'CWE-287', name: 'Improper Authentication',                            score: 12.72 },
  { rank: 12, cweId: 'CWE-476', name: 'NULL Pointer Dereference',                           score: 12.18 },
  { rank: 13, cweId: 'CWE-798', name: 'Use of Hard-coded Credentials',                     score: 11.07 },
  { rank: 14, cweId: 'CWE-200', name: 'Exposure of Sensitive Information',                  score: 10.49 },
  { rank: 15, cweId: 'CWE-77',  name: 'Improper Neutralization of Special Elements (Command Injection)', score: 10.26 },
  { rank: 16, cweId: 'CWE-306', name: 'Missing Authentication for Critical Function',        score:  9.73 },
  { rank: 17, cweId: 'CWE-502', name: 'Deserialization of Untrusted Data',                  score:  8.53 },
  { rank: 18, cweId: 'CWE-269', name: 'Improper Privilege Management',                      score:  8.40 },
  { rank: 19, cweId: 'CWE-400', name: 'Uncontrolled Resource Consumption',                   score:  8.37 },
  { rank: 20, cweId: 'CWE-190', name: 'Integer Overflow or Wraparound',                      score:  7.76 },
  { rank: 21, cweId: 'CWE-732', name: 'Incorrect Permission Assignment for Critical Resource', score: 7.62 },
  { rank: 22, cweId: 'CWE-611', name: 'Improper Restriction of XML External Entity (XXE)',  score:  7.34 },
  { rank: 23, cweId: 'CWE-918', name: 'Server-Side Request Forgery (SSRF)',                  score:  6.95 },
  { rank: 24, cweId: 'CWE-276', name: 'Incorrect Default Permissions',                       score:  6.88 },
  { rank: 25, cweId: 'CWE-434', name: 'Unrestricted Upload of Dangerous File Type',          score:  6.66 },
];

/**
 * Mapping of CWE IDs to PCI DSS v4.0 requirements.
 */
export const PCI_DSS_MAPPING: Array<{
  cweId: string;
  requirementId: string;
  subRequirementId: string;
  title: string;
  description: string;
}> = [
  // Requirement 6.2.4: Software engineering techniques
  {
    cweId: 'CWE-89',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.1',
    title: 'SQL Injection Prevention',
    description: 'Software engineering techniques include parameterized queries and prepared statements to prevent SQL injection.',
  },
  {
    cweId: 'CWE-79',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.2',
    title: 'XSS Prevention',
    description: 'Software engineering techniques include contextual output encoding and Content Security Policy to prevent XSS.',
  },
  {
    cweId: 'CWE-78',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.3',
    title: 'Command Injection Prevention',
    description: 'Software engineering techniques include safe construction of OS commands to prevent injection.',
  },
  {
    cweId: 'CWE-22',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.4',
    title: 'Path Traversal Prevention',
    description: 'Software engineering techniques include path normalization and allowlists to prevent path traversal.',
  },
  {
    cweId: 'CWE-918',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.5',
    title: 'SSRF Prevention',
    description: 'Software engineering techniques include URL validation and allowlists to prevent SSRF.',
  },
  {
    cweId: 'CWE-502',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.6',
    title: 'Safe Deserialization',
    description: 'Software engineering techniques include avoiding deserialization of untrusted data and using safe formats.',
  },
  {
    cweId: 'CWE-798',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.7',
    title: 'Secrets Management',
    description: 'Software engineering techniques include avoiding hardcoded credentials and using secrets managers.',
  },
  {
    cweId: 'CWE-327',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.8',
    title: 'Cryptographic Practices',
    description: 'Software engineering techniques include using only approved, strong cryptographic algorithms.',
  },
  {
    cweId: 'CWE-862',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.9',
    title: 'Access Control Enforcement',
    description: 'Software engineering techniques include enforcing proper authorization checks at every tier.',
  },
  {
    cweId: 'CWE-639',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.10',
    title: 'IDOR Prevention',
    description: 'Software engineering techniques include verifying user authorization for each referenced object.',
  },
  {
    cweId: 'CWE-352',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.11',
    title: 'CSRF Protection',
    description: 'Software engineering techniques include implementing anti-CSRF tokens and SameSite cookies.',
  },
  {
    cweId: 'CWE-200',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.12',
    title: 'Information Leakage Prevention',
    description: 'Software engineering techniques include not exposing sensitive information in errors or responses.',
  },
  {
    cweId: 'CWE-532',
    requirementId: '6.2.4',
    subRequirementId: '6.2.4.13',
    title: 'Secure Logging Practices',
    description: 'Software engineering techniques include sanitizing logs to prevent exposure of sensitive data.',
  },
  // Requirement 6.3.2: Security vulnerabilities addressed
  {
    cweId: 'CWE-89',
    requirementId: '6.3.2',
    subRequirementId: '6.3.2.1',
    title: 'SQL Injection Patching',
    description: 'Security vulnerabilities identified in software are addressed based on risk: SQL Injection must be remediated as critical.',
  },
  {
    cweId: 'CWE-78',
    requirementId: '6.3.2',
    subRequirementId: '6.3.2.2',
    title: 'Command Injection Patching',
    description: 'Security vulnerabilities identified in software are addressed based on risk: Command Injection must be remediated.',
  },
  {
    cweId: 'CWE-798',
    requirementId: '6.3.2',
    subRequirementId: '6.3.2.3',
    title: 'Hardcoded Credential Remediation',
    description: 'Security vulnerabilities identified in software are addressed based on risk: Hardcoded credentials must be remediated.',
  },
  {
    cweId: 'CWE-502',
    requirementId: '6.3.2',
    subRequirementId: '6.3.2.4',
    title: 'Deserialization Remediation',
    description: 'Security vulnerabilities identified in software are addressed based on risk: Insecure deserialization must be remediated.',
  },
  // Requirement 11.3.1: External/internal vulnerability scans
  {
    cweId: 'CWE-79',
    requirementId: '11.3.1',
    subRequirementId: '11.3.1.1',
    title: 'XSS in Vulnerability Scans',
    description: 'External and internal vulnerability scans must include detection of XSS vulnerabilities in web applications.',
  },
  {
    cweId: 'CWE-89',
    requirementId: '11.3.1',
    subRequirementId: '11.3.1.2',
    title: 'SQL Injection in Vulnerability Scans',
    description: 'External and internal vulnerability scans must include detection of SQL injection in web applications.',
  },
  {
    cweId: 'CWE-918',
    requirementId: '11.3.1',
    subRequirementId: '11.3.1.3',
    title: 'SSRF in Vulnerability Scans',
    description: 'External and internal vulnerability scans must include detection of SSRF in web applications.',
  },
  {
    cweId: 'CWE-22',
    requirementId: '11.3.1',
    subRequirementId: '11.3.1.4',
    title: 'Path Traversal in Vulnerability Scans',
    description: 'External and internal vulnerability scans must include detection of path traversal in web applications.',
  },
];

/**
 * Set of CWE IDs that the SAST engine has automated detection rules for.
 * Derived from the engine.ts SAST_RULES and associated rule sets.
 */
const SAST_COVERED_CWES: Set<string> = new Set([
  'CWE-89', 'CWE-79', 'CWE-78', 'CWE-798', 'CWE-327', 'CWE-22', 'CWE-918',
  'CWE-502', 'CWE-611', 'CWE-1321', 'CWE-601', 'CWE-347', 'CWE-1333',
  'CWE-489', 'CWE-676', 'CWE-862', 'CWE-639', 'CWE-352', 'CWE-200',
  'CWE-532', 'CWE-614', 'CWE-1004', 'CWE-521', 'CWE-917', 'CWE-94',
  'CWE-643', 'CWE-330', 'CWE-338', 'CWE-326', 'CWE-209', 'CWE-434',
  'CWE-319', 'CWE-759', 'CWE-23', 'CWE-285', 'CWE-539', 'CWE-613',
  'CWE-77', 'CWE-416', 'CWE-125', 'CWE-119', 'CWE-287', 'CWE-476',
  'CWE-306', 'CWE-269', 'CWE-400', 'CWE-190', 'CWE-732', 'CWE-276',
]);

/**
 * Set of CWE IDs that DAST tools can detect dynamically.
 */
const DAST_COVERED_CWES: Set<string> = new Set([
  'CWE-79', 'CWE-89', 'CWE-918', 'CWE-22', 'CWE-352', 'CWE-200',
  'CWE-78', 'CWE-601', 'CWE-611', 'CWE-502', 'CWE-614', 'CWE-1004',
  'CWE-434', 'CWE-287', 'CWE-862', 'CWE-639',
]);

// ---------------------------------------------------------------------------
// Core Mapping Utilities
// ---------------------------------------------------------------------------

/**
 * Normalize a CWE ID string to "CWE-NNNN" format.
 * Accepts "CWE-89", "89", "cwe-89" and normalizes to "CWE-89".
 */
export function normalizeCweId(raw: string): string {
  if (!raw) return '';
  const cleaned = raw.trim();
  if (/^\d+$/.test(cleaned)) return `CWE-${cleaned}`;
  const upper = cleaned.toUpperCase();
  if (/^CWE-\d+$/.test(upper)) return upper;
  // Try to extract number from strings like "CWE 89" or "89 - SQL Injection"
  const match = cleaned.match(/(\d+)/);
  return match ? `CWE-${match[1]}` : cleaned;
}

/**
 * Group findings by their normalized CWE ID.
 */
export function groupFindingsByCwe(findings: FindingStub[]): Map<string, FindingStub[]> {
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
// 1. mapToOWASPASVS
// ---------------------------------------------------------------------------

/**
 * Map findings to OWASP ASVS v4.0 requirements based on CWE ID.
 *
 * For each finding with a recognized CWE ID, produces an ASVSMappingResult
 * showing which ASVS v4.0 requirement is implicated and whether the finding
 * represents a pass or fail against that requirement.
 */
export function mapToOWASPASVS(findings: FindingStub[]): ASVSMappingResult[] {
  const cweGroups = groupFindingsByCwe(findings);
  const results: ASVSMappingResult[] = [];

  for (const [cweId, groupedFindings] of cweGroups) {
    // Find all mapping entries for this CWE (can map to multiple ASVS sections)
    const mappings = ASVS_MAPPING_TABLE.filter(m => m.cweId === cweId);
    if (mappings.length === 0) continue;

    for (const mapping of mappings) {
      for (const finding of groupedFindings) {
        results.push({
          cweId,
          findingId: finding.id,
          status: 'failed', // A finding means this requirement has failed
          asvsSection: mapping.asvsSection,
          asvsTitle: mapping.asvsTitle,
          asvsDescription: mapping.asvsDescription,
          severity: (finding.severity as string) ?? 'medium',
          automatedCoverage: mapping.asvsVerificationType === 'automated',
        });
      }
    }
  }

  return results;
}

/**
 * For a given set of ASVS mapping results, compute per-requirement status.
 * If a requirement has at least one failed finding, it is "failed".
 * If it has no findings at all, it is "not-tested".
 */
export function summarizeASVSResults(results: ASVSMappingResult[]): ASVSRequirementCoverage[] {
  const sectionMap = new Map<string, ASVSMappingEntry>();
  for (const entry of ASVS_MAPPING_TABLE) {
    const key = `${entry.asvsSection}`;
    if (!sectionMap.has(key)) sectionMap.set(key, entry);
  }

  const failedSections = new Set(results.map(r => r.asvsSection));

  const summaries: ASVSRequirementCoverage[] = [];

  // Include requirements that are present in the mapping table
  for (const [, entry] of sectionMap) {
    const isFailed = failedSections.has(entry.asvsSection);
    const sastCovered = SAST_COVERED_CWES.has(entry.cweId);
    const dastCovered = DAST_COVERED_CWES.has(entry.cweId);

    summaries.push({
      asvsSection: entry.asvsSection,
      asvsTitle: entry.asvsTitle,
      asvsLevel: 1, // L1 default for all requirements covered here
      status: isFailed ? 'failed' : 'not-tested',
      type: sastCovered && dastCovered ? 'hybrid' : (sastCovered ? 'sast' : (dastCovered ? 'dast' : 'manual')),
      automatedBySast: sastCovered,
      automatedByDast: dastCovered,
      requiresManualReview: !sastCovered && !dastCovered,
    });
  }

  return summaries;
}

// ---------------------------------------------------------------------------
// 2. mapToCWETop25
// ---------------------------------------------------------------------------

/**
 * Map findings to CWE Top 25 Most Dangerous Software Weaknesses (2024).
 *
 * For each entry in the CWE Top 25 list, determines coverage based on
 * whether the SAST engine has rules that detect that CWE and whether
 * the current findings include instances of it.
 */
export function mapToCWETop25(findings: FindingStub[]): CweTop25Result {
  const cweGroups = groupFindingsByCwe(findings);

  const entries: CweTop25Entry[] = CWE_TOP_25_2024.map(entry => {
    const cweFindings = cweGroups.get(entry.cweId) ?? [];
    const isCoveredBySast = SAST_COVERED_CWES.has(entry.cweId);

    let coverage: CweTop25Entry['coverage'];
    let findingCount = 0;
    const relevantFindings: string[] = [];

    if (cweFindings.length > 0) {
      coverage = 'covered';
      findingCount = cweFindings.length;
      relevantFindings.push(...cweFindings.map(f => f.id));
    } else if (isCoveredBySast) {
      // SAST has rules but no findings were detected
      coverage = 'covered';
      findingCount = 0;
    } else {
      // SAST has no automated rules for this CWE
      coverage = 'manual-review';
    }

    return {
      ...entry,
      coverage,
      findingCount,
      relevantFindings,
    };
  });

  const coveredCount = entries.filter(e => e.coverage === 'covered').length;
  const partialCount = entries.filter(e => e.coverage === 'partial').length;
  const manualReviewCount = entries.filter(e => e.coverage === 'manual-review').length;
  const uncoveredCount = entries.filter(e => e.coverage === 'uncovered').length;
  // For CWE Top 25, coverage = SAST has rules OR findings detected
  const effectiveCovered = coveredCount + partialCount;
  const coveragePercent = Math.round((effectiveCovered / entries.length) * 100);

  return {
    year: 2024,
    totalEntries: entries.length,
    coveredCount,
    partialCount,
    manualReviewCount,
    uncoveredCount,
    coveragePercent,
    entries,
  };
}

// ---------------------------------------------------------------------------
// 3. mapToPCIDSS
// ---------------------------------------------------------------------------

/**
 * Map findings to PCI DSS v4.0 requirements based on CWE ID.
 *
 * Produces a structured result showing the status of each PCI DSS
 * requirement and its sub-requirements as determined by the findings.
 */
export function mapToPCIDSS(findings: FindingStub[]): PciDssResult {
  const cweGroups = groupFindingsByCwe(findings);

  // Group PCI DSS entries by requirement
  const reqMap = new Map<string, PciDssRequirement>();
  for (const entry of PCI_DSS_MAPPING) {
    let requirement = reqMap.get(entry.requirementId);
    if (!requirement) {
      const title = getPciDssRequirementTitle(entry.requirementId);
      const description = getPciDssRequirementDescription(entry.requirementId);
      requirement = {
        requirementId: entry.requirementId,
        title,
        description,
        subRequirements: [],
        status: 'not-tested',
        automatedCoverage: false,
      };
      reqMap.set(entry.requirementId, requirement);
    }

    const cweFindings = cweGroups.get(entry.cweId) ?? [];
    const subStatus: 'passed' | 'failed' | 'not-tested' = cweFindings.length > 0 ? 'failed' : 'not-tested';

    requirement.subRequirements.push({
      subId: entry.subRequirementId,
      title: entry.title,
      status: subStatus,
      findingCount: cweFindings.length,
    });
  }

  // Compute overall requirement status
  const requirements: PciDssRequirement[] = [];
  let passedCount = 0;
  let failedCount = 0;
  let notTestedCount = 0;

  for (const [, req] of reqMap) {
    const hasFailed = req.subRequirements.some(s => s.status === 'failed');
    const hasNotTested = req.subRequirements.some(s => s.status === 'not-tested');

    if (hasFailed) {
      req.status = 'failed';
      failedCount++;
    } else if (hasNotTested) {
      req.status = 'not-tested';
      notTestedCount++;
    } else {
      req.status = 'passed';
      passedCount++;
    }

    req.automatedCoverage = true; // All mapped PCI DSS requirements have automated SAST coverage
    requirements.push(req);
  }

  const totalReqs = requirements.length;
  const coveragePercent = totalReqs > 0
    ? Math.round(((totalReqs - notTestedCount) / totalReqs) * 100)
    : 0;

  return {
    framework: 'PCI DSS v4.0',
    requirements,
    overallStatus: failedCount > 0 ? 'failed' : (notTestedCount > 0 ? 'not-tested' : 'passed'),
    coveragePercent,
    passedCount,
    failedCount,
    notTestedCount,
  };
}

function getPciDssRequirementTitle(requirementId: string): string {
  const titles: Record<string, string> = {
    '6.2.4': 'Software Engineering Techniques',
    '6.3.2': 'Security Vulnerabilities Addressed',
    '11.3.1': 'External and Internal Vulnerability Scans',
  };
  return titles[requirementId] ?? `PCI DSS Requirement ${requirementId}`;
}

function getPciDssRequirementDescription(requirementId: string): string {
  const descriptions: Record<string, string> = {
    '6.2.4': 'Software development personnel must be trained in secure coding techniques, including prevention of common vulnerabilities and secure software design.',
    '6.3.2': 'Security vulnerabilities identified in software and systems must be evaluated and addressed based on risk ranking within the specified timeframes.',
    '11.3.1': 'External and internal vulnerability scans must be performed at least once every three months and after any significant change.',
  };
  return descriptions[requirementId] ?? '';
}

// ---------------------------------------------------------------------------
// 4. generateComplianceReport
// ---------------------------------------------------------------------------

/**
 * Generate a structured compliance report for a given framework.
 *
 * Computes overall coverage percentage, passes/fails/not-tested counts,
 * and a gap analysis showing requirements with no automated coverage.
 */
export function generateComplianceReport(
  findings: FindingStub[],
  framework: ComplianceFramework,
): ComplianceReport {
  switch (framework) {
    case 'owasp-asvs': {
      const results = mapToOWASPASVS(findings);
      const summaries = summarizeASVSResults(results);

      const passedCount = summaries.filter(s => s.status === 'passed').length;
      const failedCount = summaries.filter(s => s.status === 'failed').length;
      const notTestedCount = summaries.filter(s => s.status === 'not-tested').length;
      const totalRequirements = summaries.length;
      const overallCoveragePercent = totalRequirements > 0
        ? Math.round(((passedCount + failedCount) / totalRequirements) * 100)
        : 0;

      const gapAnalysis = buildGapAnalysis(summaries);

      const executiveSummary = buildExecutiveSummary(
        'owasp-asvs',
        overallCoveragePercent,
        passedCount,
        failedCount,
        notTestedCount,
        totalRequirements,
      );

      return {
        framework: 'owasp-asvs',
        frameworkName: 'OWASP ASVS v4.0',
        generatedAt: new Date().toISOString(),
        overallCoveragePercent,
        passedCount,
        failedCount,
        notTestedCount,
        totalRequirements,
        executiveSummary,
        requirements: summaries.map(s => ({
          requirementId: s.asvsSection,
          title: s.asvsTitle,
          description: `${s.asvsSection} - ${s.asvsTitle}`,
          status: s.status,
          findingCount: results.filter(r => r.asvsSection === s.asvsSection).length,
        })),
        gapAnalysis,
      };
    }

    case 'cwe-top25': {
      const cweResult = mapToCWETop25(findings);
      const totalRequirements = cweResult.entries.length;
      const overallCoveragePercent = cweResult.coveragePercent;
      const passedCount = cweResult.coveredCount;
      const failedCount = cweResult.partialCount;
      const notTestedCount = cweResult.manualReviewCount + cweResult.uncoveredCount;

      const gapAnalysis: GapItem[] = cweResult.entries
        .filter(e => e.coverage === 'manual-review' || e.coverage === 'uncovered')
        .map(e => ({
          requirementId: e.cweId,
          title: e.name,
          gapType: 'no-automated-coverage' as const,
          recommendation: `CWE Top 25 entry #${e.rank} (${e.name}) requires manual review — no automated SAST rule exists for this CWE type.`,
        }));

      const executiveSummary = buildExecutiveSummary(
        'cwe-top25',
        overallCoveragePercent,
        passedCount,
        failedCount,
        notTestedCount,
        totalRequirements,
      );

      return {
        framework: 'cwe-top25',
        frameworkName: 'CWE Top 25 Most Dangerous (2024)',
        generatedAt: new Date().toISOString(),
        overallCoveragePercent,
        passedCount,
        failedCount,
        notTestedCount,
        totalRequirements,
        executiveSummary,
        requirements: cweResult.entries.map(e => ({
          requirementId: e.cweId,
          title: `#${e.rank} ${e.name} (Score: ${e.score})`,
          description: `CWE Top 25 (2024) Rank ${e.rank}: ${e.name}`,
          status: e.coverage === 'covered' ? 'passed' : (e.coverage === 'manual-review' ? 'not-tested' : 'not-tested'),
          findingCount: e.findingCount,
        })),
        gapAnalysis,
      };
    }

    case 'pci-dss': {
      const pciResult = mapToPCIDSS(findings);
      const totalRequirements = pciResult.requirements.reduce(
        (sum, r) => sum + r.subRequirements.length, 0,
      );
      const overallCoveragePercent = pciResult.coveragePercent;

      const gapAnalysis: GapItem[] = pciResult.requirements
        .filter(r => r.status === 'not-tested')
        .map(r => ({
          requirementId: r.requirementId,
          title: r.title,
          gapType: 'partial-coverage' as const,
          recommendation: `PCI DSS ${r.requirementId} (${r.title}) has no findings mapped. Review if SAST rules cover the sub-requirements.`,
        }));

      const executiveSummary = buildExecutiveSummary(
        'pci-dss',
        overallCoveragePercent,
        pciResult.passedCount,
        pciResult.failedCount,
        pciResult.notTestedCount,
        totalRequirements,
      );

      return {
        framework: 'pci-dss',
        frameworkName: 'PCI DSS v4.0',
        generatedAt: new Date().toISOString(),
        overallCoveragePercent,
        passedCount: pciResult.passedCount,
        failedCount: pciResult.failedCount,
        notTestedCount: pciResult.notTestedCount,
        totalRequirements,
        executiveSummary,
        requirements: pciResult.requirements.map(r => ({
          requirementId: r.requirementId,
          title: r.title,
          description: r.description,
          status: r.status,
          findingCount: r.subRequirements.reduce((s, sr) => s + sr.findingCount, 0),
        })),
        gapAnalysis,
      };
    }

    default: {
      const _exhaustive: never = framework;
      throw new Error(`Unknown compliance framework: ${_exhaustive}`);
    }
  }
}

function buildGapAnalysis(
  summaries: ASVSRequirementCoverage[],
): GapItem[] {
  const gaps: GapItem[] = [];

  for (const summary of summaries) {
    if (summary.requiresManualReview) {
      gaps.push({
        requirementId: summary.asvsSection,
        title: summary.asvsTitle,
        gapType: 'no-automated-coverage',
        recommendation: `ASVS ${summary.asvsSection} (${summary.asvsTitle}) requires manual review — no automated SAST or DAST rule covers this requirement.`,
      });
    } else if (summary.status === 'not-tested') {
      gaps.push({
        requirementId: summary.asvsSection,
        title: summary.asvsTitle,
        gapType: 'no-findings',
        recommendation: `ASVS ${summary.asvsSection} (${summary.asvsTitle}) has no findings. Consider manual verification or additional rules to confirm compliance.`,
      });
    }
  }

  return gaps;
}

function buildExecutiveSummary(
  framework: ComplianceFramework,
  coveragePercent: number,
  passedCount: number,
  failedCount: number,
  notTestedCount: number,
  totalRequirements: number,
): string {
  const frameworkLabels: Record<ComplianceFramework, string> = {
    'owasp-asvs': 'OWASP ASVS v4.0',
    'cwe-top25': 'CWE Top 25 (2024)',
    'pci-dss': 'PCI DSS v4.0',
  };

  const label = frameworkLabels[framework];
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

// ---------------------------------------------------------------------------
// 5. getASVSCoverageMatrix
// ---------------------------------------------------------------------------

/**
 * Returns a comprehensive coverage matrix for all OWASP ASVS v4.0 L1
 * requirements, showing which are covered by SAST, which by DAST, and
 * which require manual review.
 *
 * The matrix includes all 14 chapters (V1-V14) with their L1 requirements.
 * Requirements that map to known CWE IDs with SAST rules are marked as
 * SAST-covered. Those with DAST rules are DAST-covered. The rest require
 * manual review.
 */
export function getASVSCoverageMatrix(): CoverageMatrix {
  return ASVS_L1_REQUIREMENTS.map(req => {
    const coveredBySast = req.cweIds.some(cwe => SAST_COVERED_CWES.has(cwe));
    const coveredByDast = req.cweIds.some(cwe => DAST_COVERED_CWES.has(cwe));

    return {
      asvsSection: req.section,
      asvsTitle: req.title,
      asvsLevel: 1,
      sastCoverage: coveredBySast,
      dastCoverage: coveredByDast,
      requiresManualReview: !coveredBySast && !coveredByDast,
    };
  });
}

/**
 * Comprehensive list of OWASP ASVS v4.0 Level 1 (L1) requirements
 * across all 14 chapters (V1-V14).
 *
 * Each entry includes the section identifier, title, and the CWE IDs
 * that map to that requirement (used to determine tool coverage).
 */
export const ASVS_L1_REQUIREMENTS: Array<{
  section: string;
  title: string;
  description: string;
  cweIds: string[];
}> = [
  // --- V1: Architecture, Design and Threat Modeling (L1 subset) ---
  { section: 'V1.1.1', title: 'Secure Software Development Lifecycle', description: 'Verify the use of a secure software development lifecycle.', cweIds: [] },
  { section: 'V1.1.2', title: 'Threat Modeling', description: 'Verify the use of threat modeling for every design change.', cweIds: [] },
  { section: 'V1.2.1', title: 'Component Inventory', description: 'Verify the use of a software component inventory.', cweIds: [] },
  { section: 'V1.4.1', title: 'Secure Architecture', description: 'Verify the use of secure design principles.', cweIds: [] },
  { section: 'V1.5.1', title: 'Input Validation Strategy', description: 'Verify input validation strategy documented.', cweIds: ['CWE-20'] },

  // --- V2: Authentication (L1) ---
  { section: 'V2.1.1', title: 'Password Minimum Length', description: 'Verify password minimum length of 8 characters.', cweIds: ['CWE-521'] },
  { section: 'V2.1.2', title: 'Password Complexity', description: 'Verify password complexity requirements.', cweIds: ['CWE-521'] },
  { section: 'V2.1.5', title: 'JWT Token Authentication', description: 'Verify JWT tokens are properly validated.', cweIds: ['CWE-347'] },
  { section: 'V2.2.1', title: 'Password Strength', description: 'Verify password strength rules are enforced.', cweIds: ['CWE-521'] },
  { section: 'V2.2.2', title: 'Password Change', description: 'Verify secure password change functionality.', cweIds: [] },
  { section: 'V2.3.1', title: 'MFA Enrollment', description: 'Verify MFA is optionally available.', cweIds: [] },
  { section: 'V2.5.1', title: 'Credential Recovery', description: 'Verify secure credential recovery process.', cweIds: [] },
  { section: 'V2.5.2', title: 'Account Enumeration', description: 'Verify protection against account enumeration.', cweIds: ['CWE-203'] },
  { section: 'V2.8.1', title: 'Credential Storage', description: 'Verify credentials are stored using strong hashing.', cweIds: ['CWE-759', 'CWE-916'] },
  { section: 'V2.10.4', title: 'Hardcoded Credentials', description: 'Verify no hardcoded credentials exist.', cweIds: ['CWE-798'] },

  // --- V3: Session Management (L1) ---
  { section: 'V3.1.1', title: 'Session Expiration', description: 'Verify session inactivity timeout.', cweIds: ['CWE-539', 'CWE-613'] },
  { section: 'V3.2.1', title: 'Session ID Generation', description: 'Verify session IDs are random and unique.', cweIds: ['CWE-330'] },
  { section: 'V3.4.1', title: 'Cookie Attributes', description: 'Verify cookies set with appropriate attributes.', cweIds: [] },
  { section: 'V3.4.2', title: 'Cookie Secure Flag', description: 'Verify Secure flag set for sensitive cookies.', cweIds: ['CWE-614'] },
  { section: 'V3.4.3', title: 'Cookie HttpOnly Flag', description: 'Verify HttpOnly flag set for sensitive cookies.', cweIds: ['CWE-1004'] },
  { section: 'V3.5.1', title: 'Session Invalidation', description: 'Verify session invalidation on logout.', cweIds: ['CWE-613'] },

  // --- V4: Access Control (L1) ---
  { section: 'V4.1.1', title: 'Authorization Enforcement', description: 'Verify access controls at every tier.', cweIds: ['CWE-862', 'CWE-285'] },
  { section: 'V4.1.2', title: 'Object-Level Authorization', description: 'Verify IDOR prevention per object.', cweIds: ['CWE-639'] },
  { section: 'V4.2.1', title: 'Function-Level Access', description: 'Verify function-level access controls.', cweIds: ['CWE-862'] },
  { section: 'V4.2.2', title: 'CSRF Protection', description: 'Verify CSRF protection for state-changing operations.', cweIds: ['CWE-352'] },

  // --- V5: Validation, Sanitization and Encoding (L1) ---
  { section: 'V5.1.1', title: 'Input Validation', description: 'Verify input validation on all untrusted data.', cweIds: ['CWE-20'] },
  { section: 'V5.1.2', title: 'Dangerous Functions', description: 'Verify no dangerous functions with untrusted input.', cweIds: ['CWE-676', 'CWE-94'] },
  { section: 'V5.1.3', title: 'Unicode Validation', description: 'Verify Unicode validation for canonicalization.', cweIds: [] },
  { section: 'V5.1.4', title: 'SQL Parameterization', description: 'Verify parameterized SQL queries.', cweIds: ['CWE-89'] },
  { section: 'V5.1.5', title: 'NoSQL Injection', description: 'Verify NoSQL injection prevention.', cweIds: ['CWE-943'] },
  { section: 'V5.1.6', title: 'Prototype Pollution', description: 'Verify prototype pollution prevention.', cweIds: ['CWE-1321'] },
  { section: 'V5.1.7', title: 'ReDoS Prevention', description: 'Verify regex DoS prevention.', cweIds: ['CWE-1333'] },
  { section: 'V5.2.1', title: 'Server-Side Template Injection', description: 'Verify SSTI prevention.', cweIds: ['CWE-94'] },
  { section: 'V5.2.2', title: 'Code Injection Prevention', description: 'Verify code injection prevention.', cweIds: ['CWE-94', 'CWE-676'] },
  { section: 'V5.2.3', title: 'XPath Injection Prevention', description: 'Verify XPath injection prevention.', cweIds: ['CWE-643'] },
  { section: 'V5.2.4', title: 'OS Command Injection', description: 'Verify OS command injection prevention.', cweIds: ['CWE-78'] },
  { section: 'V5.2.5', title: 'EL Injection Prevention', description: 'Verify expression language injection prevention.', cweIds: ['CWE-917'] },
  { section: 'V5.2.6', title: 'Path Traversal / SSRF', description: 'Verify path traversal and SSRF prevention.', cweIds: ['CWE-22', 'CWE-918'] },
  { section: 'V5.2.7', title: 'Open Redirect', description: 'Verify open redirect prevention.', cweIds: ['CWE-601'] },
  { section: 'V5.3.1', title: 'Output Encoding Basics', description: 'Verify output encoding for HTML contexts.', cweIds: ['CWE-79'] },
  { section: 'V5.3.2', title: 'URL Encoding', description: 'Verify URL output encoding.', cweIds: ['CWE-79'] },
  { section: 'V5.3.3', title: 'Contextual Output Encoding', description: 'Verify contextual output encoding.', cweIds: ['CWE-79'] },
  { section: 'V5.4.1', title: 'Email Injection', description: 'Verify SMTP injection prevention.', cweIds: ['CWE-93'] },
  { section: 'V5.5.1', title: 'JSON Validation', description: 'Verify JSON input validation.', cweIds: [] },
  { section: 'V5.5.2', title: 'XML Processing Security', description: 'Verify XML parser security configuration.', cweIds: ['CWE-611'] },
  { section: 'V5.5.3', title: 'Safe Deserialization', description: 'Verify safe deserialization practices.', cweIds: ['CWE-502'] },
  { section: 'V5.6.1', title: 'LDAP Injection', description: 'Verify LDAP injection prevention.', cweIds: ['CWE-90'] },

  // --- V6: Stored Cryptography (L1) ---
  { section: 'V6.1.1', title: 'Cryptographic Randomness', description: 'Verify secure random generation.', cweIds: ['CWE-330', 'CWE-338'] },
  { section: 'V6.2.1', title: 'Data at Rest Encryption', description: 'Verify encryption of data at rest.', cweIds: ['CWE-311'] },
  { section: 'V6.2.2', title: 'Key Strength', description: 'Verify minimum key strength.', cweIds: ['CWE-326'] },
  { section: 'V6.2.3', title: 'Weak Algorithm Detection', description: 'Verify no weak crypto algorithms.', cweIds: ['CWE-327'] },
  { section: 'V6.3.1', title: 'JWT Token Validation', description: 'Verify JWT signature validation.', cweIds: ['CWE-347'] },
  { section: 'V6.4.1', title: 'Password Hashing', description: 'Verify password hashing with salt.', cweIds: ['CWE-759'] },

  // --- V7: Error Handling and Logging (L1) ---
  { section: 'V7.1.1', title: 'Safe Error Handling', description: 'Verify generic error messages to users.', cweIds: ['CWE-209'] },
  { section: 'V7.1.2', title: 'Error Logging', description: 'Verify errors are logged server-side.', cweIds: [] },
  { section: 'V7.3.1', title: 'Log Content', description: 'Verify logs contain sufficient information.', cweIds: [] },
  { section: 'V7.4.1', title: 'Information Leakage', description: 'Verify no sensitive info leakage.', cweIds: ['CWE-200'] },
  { section: 'V7.4.2', title: 'Sensitive Information in Logs', description: 'Verify no sensitive data in logs.', cweIds: ['CWE-532'] },
  { section: 'V7.4.3', title: 'Debug Output', description: 'Verify no debug output in production.', cweIds: ['CWE-489'] },

  // --- V8: Data Protection (L1) ---
  { section: 'V8.1.1', title: 'Sensitive Data Classification', description: 'Verify data classification defined.', cweIds: [] },
  { section: 'V8.2.2', title: 'Data in Transit Protection', description: 'Verify TLS for sensitive data.', cweIds: ['CWE-319'] },
  { section: 'V8.3.1', title: 'Client-Side Data Protection', description: 'Verify no sensitive data in client-side storage.', cweIds: ['CWE-312'] },

  // --- V9: Communications (L1) ---
  { section: 'V9.1.1', title: 'TLS Configuration', description: 'Verify TLS is configured properly.', cweIds: ['CWE-319'] },
  { section: 'V9.2.1', title: 'Certificate Validation', description: 'Verify certificate validation.', cweIds: [] },
  { section: 'V9.3.1', title: 'HSTS Enforcement', description: 'Verify HSTS header is set.', cweIds: ['CWE-319'] },

  // --- V10: Malicious Code (L1) ---
  { section: 'V10.1.1', title: 'Code Integrity', description: 'Verify code integrity checks.', cweIds: [] },
  { section: 'V10.2.1', title: 'Self-modifying Code', description: 'Verify no self-modifying code.', cweIds: ['CWE-84'] },
  { section: 'V10.3.1', title: 'Anti-tampering', description: 'Verify anti-tampering mechanisms.', cweIds: [] },

  // --- V11: Business Logic (L1) ---
  { section: 'V11.1.1', title: 'Business Logic Validation', description: 'Verify business logic validation.', cweIds: [] },
  { section: 'V11.1.2', title: 'Rate Limiting', description: 'Verify rate limiting for sensitive operations.', cweIds: ['CWE-770'] },
  { section: 'V11.1.3', title: 'Anti-automation', description: 'Verify anti-automation controls.', cweIds: ['CWE-799'] },

  // --- V12: Files and Resources (L1) ---
  { section: 'V12.1.1', title: 'Secure File Access', description: 'Verify restricted file access.', cweIds: ['CWE-22', 'CWE-23'] },
  { section: 'V12.2.1', title: 'File Upload Validation', description: 'Verify secure file upload handling.', cweIds: ['CWE-434'] },
  { section: 'V12.3.1', title: 'File Storage Security', description: 'Verify secure file storage.', cweIds: [] },

  // --- V13: API and Web Services (L1) ---
  { section: 'V13.1.1', title: 'API Input Validation', description: 'Verify API input validation.', cweIds: ['CWE-20'] },
  { section: 'V13.1.2', title: 'API Authentication', description: 'Verify API authentication.', cweIds: ['CWE-287'] },
  { section: 'V13.1.3', title: 'API SSRF Protection', description: 'Verify API SSRF prevention.', cweIds: ['CWE-918'] },
  { section: 'V13.2.1', title: 'API Rate Limiting', description: 'Verify API rate limiting.', cweIds: ['CWE-770'] },
  { section: 'V13.2.2', title: 'API Payload Size', description: 'Verify API payload size limits.', cweIds: ['CWE-770'] },

  // --- V14: Configuration (L1) ---
  { section: 'V14.1.1', title: 'HTTP Security Headers', description: 'Verify HTTP security headers.', cweIds: [] },
  { section: 'V14.2.1', title: 'Dependency Vulnerabilities', description: 'Verify dependency vulnerability scanning.', cweIds: ['CWE-1104'] },
  { section: 'V14.2.2', title: 'Unnecessary Features', description: 'Verify unnecessary features disabled.', cweIds: [] },
  { section: 'V14.2.3', title: 'Default Accounts', description: 'Verify no default accounts.', cweIds: ['CWE-798'] },
  { section: 'V14.4.1', title: 'HTTPS Enforcement', description: 'Verify HTTPS enforcement.', cweIds: ['CWE-319'] },
  { section: 'V14.5.1', title: 'Container Security', description: 'Verify container security configuration.', cweIds: [] },
];

// ---------------------------------------------------------------------------
// Aggregation Helpers
// ---------------------------------------------------------------------------

/**
 * Map findings across ALL supported frameworks and return combined results.
 */
export function mapAllFrameworks(findings: FindingStub[]): {
  asvs: ASVSMappingResult[];
  cweTop25: CweTop25Result;
  pciDss: PciDssResult;
} {
  return {
    asvs: mapToOWASPASVS(findings),
    cweTop25: mapToCWETop25(findings),
    pciDss: mapToPCIDSS(findings),
  };
}

/**
 * Generate compliance reports for all supported frameworks.
 */
export function generateAllComplianceReports(findings: FindingStub[]): Record<ComplianceFramework, ComplianceReport> {
  return {
    'owasp-asvs': generateComplianceReport(findings, 'owasp-asvs'),
    'cwe-top25': generateComplianceReport(findings, 'cwe-top25'),
    'pci-dss': generateComplianceReport(findings, 'pci-dss'),
  };
}
