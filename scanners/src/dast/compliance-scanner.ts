// M6g: Compliance Scanner
// Maps DAST findings to compliance frameworks:
//   - PCI DSS v4.0 Requirement 11.3.1
//   - OWASP ASVS v4.0 (Level 1 automated checks for V1-V14)
//   - NIST SP 800-53 Rev 5 control mappings

import { logger } from '../utils/logger.js';

// ===================== Types =====================

export interface DastFinding {
  cweId?: string;
  severity: string;
  severityRank?: number;
  title?: string;
  description?: string;
  attackName?: string;
  attackId?: string;
  ruleId?: string;
  endpoint?: string;
  target?: string;
  evidence?: string;
  owaspCategory?: string;
  cvssScore?: number;
  parameter?: string;
  payload?: string;
}

export interface ComplianceRequirement {
  id: string;
  framework: string;
  frameworkVersion: string;
  title: string;
  description: string;
  category: string;
  passed: boolean;
  status: 'passed' | 'failed' | 'not_applicable' | 'manual_review';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cweMappings: string[];
  matchedFindings: Array<{
    finding: string;
    severity: string;
    endpoint?: string;
  }>;
  recommendation: string;
  references: string[];
}

export interface ComplianceResult {
  framework: string;
  frameworkVersion: string;
  overallPassed: boolean;
  score: number;
  totalRequirements: number;
  passedRequirements: number;
  failedRequirements: number;
  notApplicable: number;
  manualReview: number;
  requirements: ComplianceRequirement[];
  scanSummary: {
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    infoFindings: number;
  };
  generatedAt: string;
}

export interface ComplianceScorecard {
  overallComplianceScore: number;
  frameworkScores: Array<{
    framework: string;
    version: string;
    score: number;
    passed: boolean;
    passedReqs: number;
    totalReqs: number;
  }>;
  totalFindings: number;
  coveredRequirements: number;
}

// ===================== Framework Requirement Definitions =====================

interface FrameworkControl {
  id: string;
  framework: string;
  version: string;
  title: string;
  description: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cweMappings: string[];
  severityTriggers: string[];
  recommendation: string;
  references: string[];
}

// ---- PCI DSS v4.0 Requirements relevant to DAST ----

const PCI_DSS_V4_CONTROLS: FrameworkControl[] = [
  {
    id: '4.2.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Strong Cryptography for Cardholder Data in Transit',
    description: 'Strong cryptography and security protocols must be implemented to protect cardholder data during transmission over open, public networks.',
    category: 'Encryption of Cardholder Data',
    severity: 'critical',
    cweMappings: ['CWE-319', 'CWE-326', 'CWE-327'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Enforce TLS 1.2 or higher with strong cipher suites. Disable SSL, TLS 1.0, and TLS 1.1. Implement HSTS with a minimum max-age of 31536000 seconds.',
    references: ['PCI DSS v4.0 Requirement 4.2.1', 'NIST SP 800-52 Rev 2'],
  },
  {
    id: '5.2.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Malware Detection and Prevention',
    description: 'Malicious software (malware) is detected and prevented from causing damage to the cardholder data environment.',
    category: 'Malware Protection',
    severity: 'high',
    cweMappings: ['CWE-79', 'CWE-89', 'CWE-94', 'CWE-78'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Deploy WAF rules to block injection attacks. Ensure antivirus/anti-malware solutions are active and updated on all systems in the CDE.',
    references: ['PCI DSS v4.0 Requirement 5.2.1', 'NIST SP 800-83 Rev 1'],
  },
  {
    id: '6.2.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Secure Custom Software Development',
    description: 'Custom software is developed securely, addressing common vulnerabilities such as injection, broken authentication, and XSS.',
    category: 'Secure Coding',
    severity: 'high',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-434'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Implement secure coding practices per OWASP guidelines. Use parameterized queries for SQL. Validate and sanitize all input. Perform code reviews.',
    references: ['PCI DSS v4.0 Requirement 6.2.1', 'OWASP ASVS', 'NIST SP 800-53 SA-11'],
  },
  {
    id: '6.2.2',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Application Security Review',
    description: 'Custom software is reviewed for vulnerabilities using automated tools and manual analysis at least annually.',
    category: 'Vulnerability Management',
    severity: 'high',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-611', 'CWE-200'],
    severityTriggers: ['critical', 'high', 'medium'],
    recommendation: 'Perform automated DAST and SAST scans at least annually and after significant changes. Use a combination of automated tools and manual penetration testing.',
    references: ['PCI DSS v4.0 Requirement 6.2.2', 'NIST SP 800-53 SA-11'],
  },
  {
    id: '6.2.3',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Public-Facing Web Application Protections',
    description: 'Public-facing web applications are protected against attacks via automated technical solutions or manual reviews.',
    category: 'Web Application Security',
    severity: 'critical',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-611', 'CWE-798', 'CWE-200'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Deploy a WAF or equivalent technical controls to protect public-facing web applications. Conduct regular vulnerability scans and penetration tests.',
    references: ['PCI DSS v4.0 Requirement 6.2.3', 'NIST SP 800-53 SC-7'],
  },
  {
    id: '6.2.4',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Automated Technical Solution for Web Application Attacks',
    description: 'An automated technical solution detects and prevents web application attacks, including a WAF configured in blocking mode.',
    category: 'Web Application Security',
    severity: 'high',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-434'],
    severityTriggers: ['critical', 'high', 'medium'],
    recommendation: 'Configure WAF in blocking (not monitoring-only) mode. Regularly review WAF logs and update rules based on emerging threats.',
    references: ['PCI DSS v4.0 Requirement 6.2.4', 'NIST SP 800-53 SI-3'],
  },
  {
    id: '6.3.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Security Vulnerability Identification and Remediation',
    description: 'Security vulnerabilities are identified through manual or automated processes, prioritized based on risk, and remediated according to PCI DSS timelines.',
    category: 'Vulnerability Management',
    severity: 'critical',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-611', 'CWE-200', 'CWE-798'],
    severityTriggers: ['critical', 'high', 'medium', 'low'],
    recommendation: 'Establish a formal vulnerability management program. Prioritize critical and high severity findings for remediation within 30 days.',
    references: ['PCI DSS v4.0 Requirement 6.3.1', 'NIST SP 800-53 RA-5'],
  },
  {
    id: '6.4.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Public-Facing Web Application Attack Protection',
    description: 'Public-facing web applications are protected against known attacks, either via a WAF or through manual code reviews.',
    category: 'Web Application Security',
    severity: 'critical',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Ensure WAF is deployed and actively blocking attacks on all public-facing web applications. Update WAF rules regularly.',
    references: ['PCI DSS v4.0 Requirement 6.4.1'],
  },
  {
    id: '7.2.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Access Control Systems for Cardholder Data',
    description: 'Access control systems are implemented to restrict access to cardholder data based on business need-to-know.',
    category: 'Access Control',
    severity: 'high',
    cweMappings: ['CWE-284', 'CWE-285', 'CWE-287', 'CWE-352', 'CWE-862'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Implement proper authentication and authorization controls. Enforce least privilege. Use role-based access control. Implement CSRF tokens for all state-changing operations.',
    references: ['PCI DSS v4.0 Requirement 7.2.1', 'NIST SP 800-53 AC-2, AC-3, AC-6'],
  },
  {
    id: '8.3.2',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Strong Authentication for Access to CDE',
    description: 'Strong authentication is required for all personnel and systems accessing the cardholder data environment.',
    category: 'Authentication',
    severity: 'critical',
    cweMappings: ['CWE-287', 'CWE-307', 'CWE-521', 'CWE-799'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Implement multi-factor authentication for all access to the CDE. Enforce password complexity. Implement account lockout and rate limiting for login attempts.',
    references: ['PCI DSS v4.0 Requirement 8.3.2', 'NIST SP 800-53 IA-2, IA-5'],
  },
  {
    id: '10.2.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Audit Logs for Security Events',
    description: 'Audit logs capture all security events including access, authentication, and administrative actions.',
    category: 'Logging and Monitoring',
    severity: 'high',
    cweMappings: ['CWE-532', 'CWE-778'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Enable comprehensive audit logging for all critical systems. Never log sensitive authentication data (SAD) or full PAN. Protect logs from tampering.',
    references: ['PCI DSS v4.0 Requirement 10.2.1', 'NIST SP 800-53 AU-2, AU-3'],
  },
  {
    id: '11.3.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'External Vulnerability Scans (Quarterly or After Changes)',
    description: 'External vulnerability scans are performed at least once every three months and after any significant change in the cardholder data environment. Scans must be performed by a PCI SSC Approved Scanning Vendor (ASV).',
    category: 'Vulnerability Scanning',
    severity: 'high',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-200', 'CWE-319'],
    severityTriggers: ['critical', 'high', 'medium'],
    recommendation: 'Engage a qualified ASV to perform quarterly external vulnerability scans. Remediate all critical and high severity findings before rescanning. Maintain scan reports for compliance evidence.',
    references: ['PCI DSS v4.0 Requirement 11.3.1', 'PCI DSS v4.0 Appendix A'],
  },
  {
    id: '11.3.2',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Internal Vulnerability Scans (Quarterly or After Changes)',
    description: 'Internal vulnerability scans are performed at least once every three months and after any significant change.',
    category: 'Vulnerability Scanning',
    severity: 'high',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-200', 'CWE-284', 'CWE-287'],
    severityTriggers: ['critical', 'high', 'medium', 'low'],
    recommendation: 'Conduct quarterly internal vulnerability scans of all systems in the CDE. Use PCI SSC approved scanning tools. Remediate high-risk vulnerabilities according to entity\'s risk ranking.',
    references: ['PCI DSS v4.0 Requirement 11.3.2'],
  },
  {
    id: '11.3.3',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Penetration Testing of CDE Perimeter',
    description: 'Penetration testing methodology covers the entire cardholder data environment perimeter and critical systems at least once every 12 months and after significant infrastructure changes.',
    category: 'Penetration Testing',
    severity: 'high',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-611', 'CWE-319'],
    severityTriggers: ['critical', 'high', 'medium'],
    recommendation: 'Perform annual penetration testing covering the CDE perimeter, segmentation controls, and critical systems. Include both network-layer and application-layer testing. Remediate findings and retest.',
    references: ['PCI DSS v4.0 Requirement 11.3.3', 'NIST SP 800-53 CA-8'],
  },
  {
    id: '11.4.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Intrusion Detection and Prevention',
    description: 'Intrusion detection and/or prevention techniques are used to detect and prevent network intrusions into the cardholder data environment.',
    category: 'Intrusion Detection',
    severity: 'high',
    cweMappings: ['CWE-918', 'CWE-319', 'CWE-200'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Deploy and maintain IDS/IPS solutions. Monitor alerts 24/7. Regularly update signatures and rules.',
    references: ['PCI DSS v4.0 Requirement 11.4.1', 'NIST SP 800-53 SI-4'],
  },
  {
    id: '12.3.1',
    framework: 'PCI DSS',
    version: '4.0',
    title: 'Security Awareness Training',
    description: 'Security awareness training is provided to all personnel, covering the entity\'s security policies and procedures relevant to their role.',
    category: 'Security Policy',
    severity: 'low',
    cweMappings: [],
    severityTriggers: [],
    recommendation: 'Implement ongoing security awareness training programs. Cover phishing, social engineering, secure coding (for developers), and incident reporting procedures.',
    references: ['PCI DSS v4.0 Requirement 12.3.1', 'NIST SP 800-50'],
  },
];

// ---- OWASP ASVS v4.0.3 - Level 1 Automated Requirements ----

const OWASP_ASVS_V4_CONTROLS: FrameworkControl[] = [
  {
    id: 'V1.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Application Component Documentation',
    description: 'Verify that all application components, data flows, and trust boundaries are documented and understood.',
    category: 'Architecture, Design and Threat Modeling',
    severity: 'high',
    cweMappings: ['CWE-200', 'CWE-212'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Maintain application architecture documentation with all components, data flows, and trust boundaries. Update documentation when changes occur.',
    references: ['OWASP ASVS V1.1', 'NIST SP 800-53 SA-3, SA-11'],
  },
  {
    id: 'V2.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Secure Authentication',
    description: 'Verify that authentication is performed securely, including password policies, rate limiting, and credential storage.',
    category: 'Authentication Verification',
    severity: 'critical',
    cweMappings: ['CWE-287', 'CWE-307', 'CWE-521', 'CWE-798', 'CWE-522'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Implement strong password policies (minimum 8 characters, complexity). Use rate limiting on login endpoints. Never store passwords in plaintext; use bcrypt/scrypt/Argon2. Implement MFA.',
    references: ['OWASP ASVS V2.1', 'NIST SP 800-63B'],
  },
  {
    id: 'V2.2',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Credential Storage',
    description: 'Verify that credentials are stored using approved cryptographic hashing algorithms with appropriate work factors.',
    category: 'Authentication Verification',
    severity: 'critical',
    cweMappings: ['CWE-916', 'CWE-522', 'CWE-257'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Use bcrypt (cost factor >= 10), scrypt, or Argon2id for password storage. Never use plaintext, MD5, SHA-1, or unsalted hashes for credential storage.',
    references: ['OWASP ASVS V2.2', 'NIST SP 800-63B'],
  },
  {
    id: 'V2.5',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Credential Recovery Security',
    description: 'Verify that credential recovery mechanisms are secure and do not reveal account enumeration information.',
    category: 'Authentication Verification',
    severity: 'medium',
    cweMappings: ['CWE-640', 'CWE-200'],
    severityTriggers: ['medium'],
    recommendation: 'Use consistent responses for login/forgot-password (e.g., "If account exists, email sent"). Use time-limited tokens for password reset. Invalidate reset tokens after use.',
    references: ['OWASP ASVS V2.5'],
  },
  {
    id: 'V3.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Secure Session Management',
    description: 'Verify that session management is secure, including cookie flags, session timeout, and token handling.',
    category: 'Session Management Verification',
    severity: 'high',
    cweMappings: ['CWE-613', 'CWE-614', 'CWE-384', 'CWE-1004'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Use HttpOnly, Secure, and SameSite=Strict cookie flags. Implement session timeout (15-30 minutes idle). Rotate session tokens after login and privilege changes.',
    references: ['OWASP ASVS V3.1', 'NIST SP 800-63B'],
  },
  {
    id: 'V3.4',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Session Logout',
    description: 'Verify that session tokens are properly invalidated on logout and sessions are terminated on the server side.',
    category: 'Session Management Verification',
    severity: 'medium',
    cweMappings: ['CWE-613', 'CWE-384'],
    severityTriggers: ['medium'],
    recommendation: 'Invalidate server-side sessions on logout. Clear session cookies on the client side. Provide a logout function that is easily accessible from all authenticated pages.',
    references: ['OWASP ASVS V3.4'],
  },
  {
    id: 'V4.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Access Control Enforcement',
    description: 'Verify that access controls are enforced on every request, including API calls, and cannot be bypassed by parameter manipulation.',
    category: 'Access Control Verification',
    severity: 'critical',
    cweMappings: ['CWE-284', 'CWE-285', 'CWE-862', 'CWE-863', 'CWE-639'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Implement server-side authorization checks for every request. Never rely on client-side access controls. Use role-based or attribute-based access control. Implement proper object-level authorization.',
    references: ['OWASP ASVS V4.1', 'NIST SP 800-53 AC-3, AC-6'],
  },
  {
    id: 'V4.2',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Insecure Direct Object References',
    description: 'Verify that direct object references are protected with authorization checks to prevent unauthorized access to data.',
    category: 'Access Control Verification',
    severity: 'high',
    cweMappings: ['CWE-639', 'CWE-862'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Implement indirect object references or verify authorization for every object access. Do not expose database keys or identifiers directly.',
    references: ['OWASP ASVS V4.2'],
  },
  {
    id: 'V5.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Input Validation (Injection Prevention)',
    description: 'Verify that all input is validated and sanitized on the server side, preventing injection attacks (SQL, XSS, command, path traversal, SSRF, XXE).',
    category: 'Input Validation Verification',
    severity: 'critical',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-611', 'CWE-94'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Use parameterized queries for SQL. Encode output contextually for XSS prevention. Validate input against an allowlist. Use secure parsers for XML/JSON. Restrict file system access.',
    references: ['OWASP ASVS V5.1', 'NIST SP 800-53 SI-10'],
  },
  {
    id: 'V5.2',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Anti-Automation Controls',
    description: 'Verify that anti-automation controls are implemented to protect against brute force, credential stuffing, and automated attacks.',
    category: 'Input Validation Verification',
    severity: 'high',
    cweMappings: ['CWE-799', 'CWE-307', 'CWE-770'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Implement CAPTCHA, rate limiting, progressive delays, or other anti-automation controls on login, registration, and form submission endpoints.',
    references: ['OWASP ASVS V5.2'],
  },
  {
    id: 'V5.3',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Content Security and XSS Prevention',
    description: 'Verify that output encoding and content security features prevent XSS and data injection attacks.',
    category: 'Input Validation Verification',
    severity: 'high',
    cweMappings: ['CWE-79', 'CWE-80', 'CWE-1021'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Implement CSP headers (Content-Security-Policy). Use contextual output encoding. Avoid dangerous HTML constructs (innerHTML, document.write). Use framework auto-escaping.',
    references: ['OWASP ASVS V5.3', 'NIST SP 800-53 SI-10'],
  },
  {
    id: 'V5.5',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'File Upload Security',
    description: 'Verify that file upload functionality validates file types by content (not extension), limits file sizes, and stores files securely.',
    category: 'Input Validation Verification',
    severity: 'high',
    cweMappings: ['CWE-434', 'CWE-22', 'CWE-79'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Validate uploaded files by magic bytes, not just extension. Store files outside the web root. Use random file names. Set size limits. Scan uploaded files for malware.',
    references: ['OWASP ASVS V5.5', 'NIST SP 800-53 SI-3'],
  },
  {
    id: 'V6.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Encryption in Transit',
    description: 'Verify that all sensitive data is encrypted in transit using strong TLS protocols and cipher suites.',
    category: 'Stored Cryptography Verification',
    severity: 'critical',
    cweMappings: ['CWE-319', 'CWE-326', 'CWE-327', 'CWE-523'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Enforce TLS 1.2 or higher. Disable SSL and TLS 1.0/1.1. Use strong cipher suites (e.g., ECDHE with AES-GCM). Implement HSTS with max-age=31536000.',
    references: ['OWASP ASVS V6.1', 'NIST SP 800-52 Rev 2'],
  },
  {
    id: 'V7.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Secure Error Handling',
    description: 'Verify that error handling does not reveal sensitive information, including stack traces, database errors, or internal paths.',
    category: 'Error Handling and Logging Verification',
    severity: 'medium',
    cweMappings: ['CWE-209', 'CWE-210', 'CWE-211'],
    severityTriggers: ['medium', 'low'],
    recommendation: 'Return generic error messages to end users. Log detailed error information server-side. Configure custom error pages and disable debug mode in production.',
    references: ['OWASP ASVS V7.1', 'NIST SP 800-53 SI-11'],
  },
  {
    id: 'V7.3',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Log Content Security',
    description: 'Verify that logs are secured and do not contain sensitive information such as credentials, session tokens, or personal data.',
    category: 'Error Handling and Logging Verification',
    severity: 'medium',
    cweMappings: ['CWE-532', 'CWE-200'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Never log credentials, session tokens, PAN, or other sensitive data. Implement log sanitization. Protect log files from unauthorized access.',
    references: ['OWASP ASVS V7.3', 'NIST SP 800-53 AU-9'],
  },
  {
    id: 'V8.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Data Protection Controls',
    description: 'Verify that sensitive data is protected in transit and at rest, with proper classification and handling procedures.',
    category: 'Data Protection Verification',
    severity: 'high',
    cweMappings: ['CWE-200', 'CWE-212', 'CWE-359', 'CWE-312'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Minimize data exposure in responses. Implement data classification. Mask or truncate sensitive data. Use encryption for data at rest.',
    references: ['OWASP ASVS V8.1', 'NIST SP 800-53 SC-8, SC-28'],
  },
  {
    id: 'V9.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'TLS Configuration',
    description: 'Verify that TLS is properly configured, with correct certificate validation and no insecure protocol fallback.',
    category: 'Communications Verification',
    severity: 'critical',
    cweMappings: ['CWE-319', 'CWE-326', 'CWE-327', 'CWE-295'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Use valid TLS certificates from trusted CAs. Enforce TLS 1.2+ only. Disable TLS compression and renegotiation. Configure HSTS. Use strong cipher suites prioritizing forward secrecy.',
    references: ['OWASP ASVS V9.1', 'NIST SP 800-52 Rev 2'],
  },
  {
    id: 'V12.3',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'HTTP Security Headers',
    description: 'Verify that HTTP security headers are correctly configured for all responses.',
    category: 'File and Resources Verification',
    severity: 'medium',
    cweMappings: ['CWE-523', 'CWE-1021', 'CWE-693'],
    severityTriggers: ['medium', 'low'],
    recommendation: 'Configure all security headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-* headers.',
    references: ['OWASP ASVS V12.3', 'OWASP Secure Headers Project'],
  },
  {
    id: 'V12.5',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'CORS Configuration',
    description: 'Verify that CORS headers are properly configured and do not allow wildcard origins with credentials.',
    category: 'File and Resources Verification',
    severity: 'medium',
    cweMappings: ['CWE-942', 'CWE-346'],
    severityTriggers: ['medium', 'high'],
    recommendation: 'Restrict Access-Control-Allow-Origin to specific trusted origins. Never use wildcard (*) with Access-Control-Allow-Credentials: true. Validate Origin header on the server.',
    references: ['OWASP ASVS V12.5'],
  },
  {
    id: 'V13.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'API Security',
    description: 'Verify that all API endpoints are authenticated, authorized, and protected against common attacks.',
    category: 'API and Web Service Verification',
    severity: 'critical',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-200', 'CWE-918', 'CWE-942', 'CWE-287'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Authenticate all API endpoints. Implement proper authorization checks. Validate and sanitize all inputs. Use rate limiting. Enable TLS. Restrict CORS.',
    references: ['OWASP ASVS V13.1', 'OWASP API Security Top 10'],
  },
  {
    id: 'V14.1',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Secure Build and Deployment',
    description: 'Verify that build and deployment pipeline is secure, with no debug code, default credentials, or misconfigurations in production.',
    category: 'Configuration Verification',
    severity: 'high',
    cweMappings: ['CWE-215', 'CWE-489', 'CWE-656', 'CWE-798'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Disable debug mode in production. Remove development endpoints. Change default credentials. Use environment-specific configuration files. Automate security checks in CI/CD.',
    references: ['OWASP ASVS V14.1', 'NIST SP 800-53 CM-6, CM-7'],
  },
  {
    id: 'V14.2',
    framework: 'OWASP ASVS',
    version: '4.0.3',
    title: 'Dependency Vulnerability Management',
    description: 'Verify that third-party libraries and dependencies are free from known vulnerabilities.',
    category: 'Configuration Verification',
    severity: 'high',
    cweMappings: ['CWE-1104'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Regularly audit and update third-party dependencies. Use Software Composition Analysis (SCA) tools to identify vulnerable libraries. Subscribe to CVE notifications.',
    references: ['OWASP ASVS V14.2', 'OWASP Dependency-Check', 'NIST SP 800-53 SA-11'],
  },
];

// ---- NIST SP 800-53 Rev 5 Controls relevant to DAST ----

const NIST_SP800_53_CONTROLS: FrameworkControl[] = [
  {
    id: 'AC-2',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Account Management',
    description: 'Manage information system accounts, including creation, modification, disabling, and removal of accounts.',
    category: 'Access Control',
    severity: 'high',
    cweMappings: ['CWE-287', 'CWE-863'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Implement the full account lifecycle management process. Enforce least privilege. Review accounts regularly. Disable inactive accounts promptly.',
    references: ['NIST SP 800-53 AC-2'],
  },
  {
    id: 'AC-3',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Access Enforcement',
    description: 'Enforce approved authorizations for logical access to information and system resources.',
    category: 'Access Control',
    severity: 'critical',
    cweMappings: ['CWE-284', 'CWE-285', 'CWE-862', 'CWE-863'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Implement access control policies and mechanisms on all systems. Use role-based or attribute-based access control. Enforce need-to-know and least privilege principles.',
    references: ['NIST SP 800-53 AC-3'],
  },
  {
    id: 'AC-4',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Information Flow Enforcement',
    description: 'Control the flow of information between interconnected systems based on approved policies.',
    category: 'Access Control',
    severity: 'high',
    cweMappings: ['CWE-79', 'CWE-89', 'CWE-22', 'CWE-918'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Implement information flow control policies. Use firewalls and data loss prevention controls. Validate and sanitize data at system boundaries.',
    references: ['NIST SP 800-53 AC-4'],
  },
  {
    id: 'AC-6',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Least Privilege',
    description: 'Employ the principle of least privilege, allowing only authorized accesses for users (and processes acting on behalf of users).',
    category: 'Access Control',
    severity: 'high',
    cweMappings: ['CWE-269', 'CWE-272', 'CWE-732'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Implement least privilege for all accounts and processes. Use role-based access controls. Review permissions regularly. Use just-in-time access for privileged operations.',
    references: ['NIST SP 800-53 AC-6'],
  },
  {
    id: 'AC-7',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Unsuccessful Logon Attempts',
    description: 'Enforce a limit on consecutive invalid login attempts and implement an account lockout mechanism.',
    category: 'Access Control',
    severity: 'high',
    cweMappings: ['CWE-307'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Implement account lockout after a defined number of failed login attempts (e.g., 5-10 attempts). Set lockout duration or require administrator intervention for unlock.',
    references: ['NIST SP 800-53 AC-7'],
  },
  {
    id: 'AC-17',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Remote Access',
    description: 'Establish and manage remote access sessions using encryption and strong authentication.',
    category: 'Access Control',
    severity: 'high',
    cweMappings: ['CWE-287', 'CWE-319'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Use encryption for all remote access. Implement multi-factor authentication. Monitor and control remote access sessions. Use secure gateways or VPNs.',
    references: ['NIST SP 800-53 AC-17'],
  },
  {
    id: 'AU-2',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Event Logging',
    description: 'Log auditable events including authentication, access, and administrative actions for security monitoring.',
    category: 'Audit and Accountability',
    severity: 'medium',
    cweMappings: ['CWE-778'],
    severityTriggers: ['medium'],
    recommendation: 'Log all security-relevant events: authentication attempts, access control decisions, administrative actions, and system events. Ensure sufficient detail for forensic analysis.',
    references: ['NIST SP 800-53 AU-2, AU-3'],
  },
  {
    id: 'AU-9',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Protection of Audit Information',
    description: 'Protect audit information and logging tools from unauthorized access, modification, and deletion.',
    category: 'Audit and Accountability',
    severity: 'medium',
    cweMappings: ['CWE-200', 'CWE-532'],
    severityTriggers: ['medium', 'low'],
    recommendation: 'Protect audit logs from unauthorized access. Use write-once or append-only storage. Restrict administrative access to logging systems. Enable log integrity monitoring.',
    references: ['NIST SP 800-53 AU-9'],
  },
  {
    id: 'CM-6',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Configuration Settings',
    description: 'Establish and enforce secure configuration settings for information technology products.',
    category: 'Configuration Management',
    severity: 'high',
    cweMappings: ['CWE-523', 'CWE-693', 'CWE-656', 'CWE-489'],
    severityTriggers: ['high', 'medium', 'low'],
    recommendation: 'Establish secure baseline configurations for all systems. Remove default accounts and passwords. Disable unnecessary services and ports. Use automated configuration management tools.',
    references: ['NIST SP 800-53 CM-6'],
  },
  {
    id: 'CM-7',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Least Functionality',
    description: 'Configure systems to provide only essential capabilities and prohibit or restrict non-essential functions.',
    category: 'Configuration Management',
    severity: 'medium',
    cweMappings: ['CWE-215', 'CWE-489'],
    severityTriggers: ['medium', 'low'],
    recommendation: 'Disable unnecessary services, ports, protocols, and functionality. Remove debug tools and test accounts from production. Use application whitelisting where possible.',
    references: ['NIST SP 800-53 CM-7'],
  },
  {
    id: 'IA-2',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Identification and Authentication',
    description: 'Implement unique identification and authentication for organizational users and processes.',
    category: 'Identification and Authentication',
    severity: 'critical',
    cweMappings: ['CWE-287', 'CWE-798', 'CWE-308'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Require unique identification for all users. Implement strong authentication. Use multi-factor authentication for privileged accounts. Never share or reuse credentials.',
    references: ['NIST SP 800-53 IA-2'],
  },
  {
    id: 'IA-5',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Authenticator Management',
    description: 'Manage system authenticators securely, including passwords, tokens, and cryptographic keys.',
    category: 'Identification and Authentication',
    severity: 'high',
    cweMappings: ['CWE-521', 'CWE-522', 'CWE-798'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Enforce password complexity and expiration policies. Store passwords using strong hashing algorithms (bcrypt/scrypt/Argon2). Rotate cryptographic keys regularly. Protect secrets.',
    references: ['NIST SP 800-53 IA-5', 'NIST SP 800-63B'],
  },
  {
    id: 'RA-3',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Risk Assessment',
    description: 'Conduct risk assessments to identify, analyze, and prioritize risks to organizational operations and assets.',
    category: 'Risk Assessment',
    severity: 'high',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-200'],
    severityTriggers: ['critical', 'high', 'medium'],
    recommendation: 'Conduct regular risk assessments considering vulnerability severity and business impact. Document risk decisions. Review and update risk assessments at least annually.',
    references: ['NIST SP 800-53 RA-3'],
  },
  {
    id: 'RA-5',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Vulnerability Scanning',
    description: 'Scan for vulnerabilities in the system and hosted applications, analyze findings, and remediate based on risk assessment.',
    category: 'Risk Assessment',
    severity: 'high',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-200', 'CWE-319'],
    severityTriggers: ['critical', 'high', 'medium', 'low'],
    recommendation: 'Conduct regular vulnerability scans (DAST, SAST, SCA). Use authenticated scanning where possible. Prioritize remediation based on risk. Rescan to verify fixes.',
    references: ['NIST SP 800-53 RA-5'],
  },
  {
    id: 'SA-11',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Developer Security Testing and Evaluation',
    description: 'Perform application security testing including static analysis, dynamic analysis, and penetration testing.',
    category: 'System and Services Acquisition',
    severity: 'high',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-611', 'CWE-918', 'CWE-434'],
    severityTriggers: ['critical', 'high', 'medium'],
    recommendation: 'Integrate security testing into the development lifecycle. Perform SAST, DAST, SCA, and penetration testing. Use SAST tools to find injection flaws. Use DAST to find runtime vulnerabilities.',
    references: ['NIST SP 800-53 SA-11'],
  },
  {
    id: 'SC-7',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Boundary Protection',
    description: 'Monitor and control communications at external and internal system boundaries using firewalls, proxies, and gateways.',
    category: 'System and Communications Protection',
    severity: 'critical',
    cweMappings: ['CWE-319', 'CWE-942', 'CWE-918', 'CWE-200'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Implement network segmentation and boundary protection. Use firewalls, WAF, and proxies. Monitor and control traffic at all boundaries. Restrict unnecessary outbound traffic.',
    references: ['NIST SP 800-53 SC-7'],
  },
  {
    id: 'SC-8',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Transmission Confidentiality and Integrity',
    description: 'Protect the confidentiality and integrity of transmitted information using encryption.',
    category: 'System and Communications Protection',
    severity: 'critical',
    cweMappings: ['CWE-319', 'CWE-327'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Encrypt all data in transit using TLS 1.2+ with strong cipher suites. Disable all insecure protocols (SSL, TLS 1.0/1.1). Implement HSTS. Use Perfect Forward Secrecy ciphers.',
    references: ['NIST SP 800-53 SC-8', 'NIST SP 800-52 Rev 2'],
  },
  {
    id: 'SC-12',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Cryptographic Key Establishment and Management',
    description: 'Establish and manage cryptographic keys using automated mechanisms with supporting documentation.',
    category: 'System and Communications Protection',
    severity: 'high',
    cweMappings: ['CWE-320', 'CWE-321', 'CWE-322', 'CWE-323', 'CWE-326'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Implement secure key management practices. Use hardware security modules (HSMs) or key management services. Rotate keys regularly. Use approved cryptographic algorithms per NIST SP 800-175B.',
    references: ['NIST SP 800-53 SC-12', 'NIST SP 800-56A Rev 3', 'NIST SP 800-57'],
  },
  {
    id: 'SC-28',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Protection of Information at Rest',
    description: 'Protect the confidentiality and integrity of information at rest using encryption and access controls.',
    category: 'System and Communications Protection',
    severity: 'high',
    cweMappings: ['CWE-200', 'CWE-312'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Encrypt sensitive data at rest. Use strong encryption algorithms (AES-256). Implement access controls for data storage. Use file-level or disk-level encryption as appropriate.',
    references: ['NIST SP 800-53 SC-28', 'NIST SP 800-111'],
  },
  {
    id: 'SI-3',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Malicious Code Protection',
    description: 'Implement malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code.',
    category: 'System and Information Integrity',
    severity: 'high',
    cweMappings: ['CWE-434', 'CWE-79', 'CWE-89', 'CWE-94', 'CWE-78'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Deploy and maintain anti-malware solutions on all systems. Use WAF to block malicious requests. Scan uploaded files. Keep signatures and rules up to date.',
    references: ['NIST SP 800-53 SI-3', 'NIST SP 800-83 Rev 1'],
  },
  {
    id: 'SI-4',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'System Monitoring',
    description: 'Monitor the system to detect attacks, unauthorized access, and anomalies in accordance with organizational monitoring strategy.',
    category: 'System and Information Integrity',
    severity: 'high',
    cweMappings: ['CWE-778', 'CWE-200'],
    severityTriggers: ['high', 'medium'],
    recommendation: 'Implement continuous security monitoring. Use SIEM solutions to aggregate and correlate logs. Set up alerts for suspicious activities. Monitor critical security controls.',
    references: ['NIST SP 800-53 SI-4'],
  },
  {
    id: 'SI-10',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Information Input Validation',
    description: 'Validate all input to information systems for correctness, completeness, and security before processing.',
    category: 'System and Information Integrity',
    severity: 'critical',
    cweMappings: ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-918', 'CWE-611', 'CWE-94'],
    severityTriggers: ['critical', 'high'],
    recommendation: 'Validate all input on the server side. Use allowlists for permitted input patterns. Reject malformed input. Sanitize output to prevent injection attacks.',
    references: ['NIST SP 800-53 SI-10'],
  },
  {
    id: 'SI-11',
    framework: 'NIST SP 800-53',
    version: 'Rev 5',
    title: 'Error Handling',
    description: 'Generate and handle error messages that do not contain sensitive or system information.',
    category: 'System and Information Integrity',
    severity: 'medium',
    cweMappings: ['CWE-209', 'CWE-210'],
    severityTriggers: ['medium', 'low'],
    recommendation: 'Return generic error messages to users. Log detailed error information server-side. Configure custom error pages. Disable debugging and stack traces in production.',
    references: ['NIST SP 800-53 SI-11'],
  },
];

// ===================== Core Mapping Logic =====================

/**
 * Map DAST findings to framework requirements based on CWE and severity matching.
 */
function mapFindingsToControls(
  findings: DastFinding[],
  controls: FrameworkControl[]
): ComplianceRequirement[] {
  return controls.map((control) => {
    const matchedFindings: Array<{ finding: string; severity: string; endpoint?: string }> = [];
    const seen = new Set<string>();

    for (const finding of findings) {
      const cweMatch = finding.cweId && control.cweMappings.includes(finding.cweId);
      const severityMatch = control.severityTriggers.includes(finding.severity);

      // Match if CWE matches OR (if no CWE matching necessary, severity matches and CWE list is broad)
      const matches = cweMatch || (control.cweMappings.length > 0 && severityMatch && !finding.cweId);

      if (matches) {
        const findingDesc =
          finding.attackName || finding.title || finding.description || finding.attackId || finding.ruleId || 'Unknown finding';
        const uniqueKey = `${findingDesc}|${finding.severity}|${finding.endpoint || finding.target || ''}`;

        if (!seen.has(uniqueKey)) {
          seen.add(uniqueKey);
          matchedFindings.push({
            finding: findingDesc,
            severity: finding.severity,
            endpoint: finding.endpoint || finding.target,
          });
        }
      }
    }

    const passed = matchedFindings.length === 0;
    let status: ComplianceRequirement['status'] = 'passed';

    if (passed) {
      status = 'passed';
    } else {
      status = 'failed';
    }

    return {
      id: control.id,
      framework: control.framework,
      frameworkVersion: control.version,
      title: control.title,
      description: control.description,
      category: control.category,
      passed,
      status,
      severity: control.severity,
      cweMappings: control.cweMappings,
      matchedFindings,
      recommendation: control.recommendation,
      references: control.references,
    };
  });
}

/**
 * Normalize finding severity to lowercase.
 */
function normalizeFindings(findings: DastFinding[]): DastFinding[] {
  return findings.map((f) => ({
    ...f,
    severity: f.severity?.toLowerCase() || 'info',
  }));
}

// ===================== Public API =====================

/**
 * Run PCI DSS v4.0 compliance scan against DAST findings.
 */
export function runPciDssComplianceScan(findings: DastFinding[]): ComplianceResult {
  logger.info({ findingsCount: findings.length }, 'Running PCI DSS v4.0 compliance scan');

  const normalizedFindings = normalizeFindings(findings);
  const requirements = mapFindingsToControls(normalizedFindings, PCI_DSS_V4_CONTROLS);

  return buildComplianceResult('PCI DSS', '4.0', requirements, normalizedFindings);
}

/**
 * Run OWASP ASVS v4.0 compliance scan against DAST findings.
 */
export function runOwaspAsvsComplianceScan(
  findings: DastFinding[],
  level: 1 | 2 | 3 = 1
): ComplianceResult {
  logger.info({ findingsCount: findings.length, level }, 'Running OWASP ASVS v4.0 compliance scan');

  const normalizedFindings = normalizeFindings(findings);

  let controls = OWASP_ASVS_V4_CONTROLS;

  if (level > 1) {
    // For levels 2 and 3, mark requirements that need manual review
    controls = OWASP_ASVS_V4_CONTROLS.map((c) => ({
      ...c,
      description: `${c.description} [Level ${level} - some checks require manual review]`,
    }));
  }

  const requirements = mapFindingsToControls(normalizedFindings, controls);

  // For ASVS levels 2+, mark requirements that only partially overlap as manual_review
  if (level > 1) {
    for (const req of requirements) {
      // If it has no matching findings but still needs manual verification
      if (req.status === 'passed' && level >= 2) {
        req.status = 'manual_review';
        req.passed = true; // Still counts as passed but needs manual verification
      }
    }
  }

  return buildComplianceResult('OWASP ASVS', '4.0.3', requirements, normalizedFindings);
}

/**
 * Run NIST SP 800-53 Rev 5 compliance scan against DAST findings.
 */
export function runNistSp80053ComplianceScan(findings: DastFinding[]): ComplianceResult {
  logger.info({ findingsCount: findings.length }, 'Running NIST SP 800-53 Rev 5 compliance scan');

  const normalizedFindings = normalizeFindings(findings);
  const requirements = mapFindingsToControls(normalizedFindings, NIST_SP800_53_CONTROLS);

  return buildComplianceResult('NIST SP 800-53', 'Rev 5', requirements, normalizedFindings);
}

/**
 * Run all three compliance scans against the same findings.
 */
export function runAllComplianceScans(
  findings: DastFinding[]
): ComplianceResult[] {
  return [
    runPciDssComplianceScan(findings),
    runOwaspAsvsComplianceScan(findings),
    runNistSp80053ComplianceScan(findings),
  ];
}

/**
 * Build a consolidated compliance scorecard across all frameworks.
 */
export function getComplianceScorecard(
  findings: DastFinding[]
): ComplianceScorecard {
  const results = runAllComplianceScans(findings);

  const frameworkScores = results.map((r) => ({
    framework: r.framework,
    version: r.frameworkVersion,
    score: r.score,
    passed: r.overallPassed,
    passedReqs: r.passedRequirements,
    totalReqs: r.totalRequirements,
  }));

  const overallScore =
    frameworkScores.length > 0
      ? Math.round(
          frameworkScores.reduce((sum, f) => sum + f.score, 0) /
            frameworkScores.length
        )
      : 0;

  const totalRequirements = results.reduce(
    (sum, r) => sum + r.totalRequirements,
    0
  );

  return {
    overallComplianceScore: overallScore,
    frameworkScores,
    totalFindings: findings.length,
    coveredRequirements: totalRequirements,
  };
}

// ===================== Internal Helpers =====================

/**
 * Build a standardized ComplianceResult from mapped requirements.
 */
function buildComplianceResult(
  framework: string,
  frameworkVersion: string,
  requirements: ComplianceRequirement[],
  findings: DastFinding[]
): ComplianceResult {
  const passedRequirements = requirements.filter((r) => r.passed);
  const failedRequirements = requirements.filter((r) => r.status === 'failed');
  const notApplicable = requirements.filter(
    (r) => r.status === 'not_applicable'
  );
  const manualReview = requirements.filter(
    (r) => r.status === 'manual_review'
  );
  const totalRequirements = requirements.length;
  const passedCount = passedRequirements.length;

  const score =
    totalRequirements > 0
      ? Math.round((passedCount / totalRequirements) * 100)
      : 0;

  const severityBreakdown = {
    criticalFindings: findings.filter((f) => f.severity === 'critical').length,
    highFindings: findings.filter((f) => f.severity === 'high').length,
    mediumFindings: findings.filter((f) => f.severity === 'medium').length,
    lowFindings: findings.filter((f) => f.severity === 'low').length,
    infoFindings: findings.filter((f) => f.severity === 'info').length,
  };

  const result: ComplianceResult = {
    framework,
    frameworkVersion,
    overallPassed: failedRequirements.length === 0,
    score,
    totalRequirements,
    passedRequirements: passedCount,
    failedRequirements: failedRequirements.length,
    notApplicable: notApplicable.length,
    manualReview: manualReview.length,
    requirements,
    scanSummary: {
      totalFindings: findings.length,
      ...severityBreakdown,
    },
    generatedAt: new Date().toISOString(),
  };

  logger.info(
    {
      framework: `${framework} ${frameworkVersion}`,
      passed: result.overallPassed,
      score: result.score,
      total: totalRequirements,
      passedRequirements: passedCount,
      failed: failedRequirements.length,
    },
    'Compliance scan completed'
  );

  return result;
}

/**
 * Get a specific control definition by framework and control ID.
 */
export function getControlDefinition(
  framework: 'pci-dss' | 'owasp-asvs' | 'nist-800-53',
  controlId: string
): FrameworkControl | undefined {
  const controls = {
    'pci-dss': PCI_DSS_V4_CONTROLS,
    'owasp-asvs': OWASP_ASVS_V4_CONTROLS,
    'nist-800-53': NIST_SP800_53_CONTROLS,
  };

  return controls[framework]?.find((c) => c.id === controlId);
}

/**
 * Export framework control definitions for inspection.
 */
export const FRAMEWORK_CONTROLS = {
  'PCI DSS v4.0': PCI_DSS_V4_CONTROLS,
  'OWASP ASVS v4.0.3': OWASP_ASVS_V4_CONTROLS,
  'NIST SP 800-53 Rev 5': NIST_SP800_53_CONTROLS,
};

/**
 * Get total counts of controls per framework.
 */
export function getFrameworkStats() {
  return Object.entries(FRAMEWORK_CONTROLS).map(([name, controls]) => ({
    framework: name,
    totalControls: controls.length,
    critical: controls.filter((c) => c.severity === 'critical').length,
    high: controls.filter((c) => c.severity === 'high').length,
    medium: controls.filter((c) => c.severity === 'medium').length,
    low: controls.filter((c) => c.severity === 'low').length,
    categories: [...new Set(controls.map((c) => c.category))],
  }));
}
