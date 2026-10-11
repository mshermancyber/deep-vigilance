// ============================================================
// Extended Compliance Framework Mappings
// Maps SAST/DAST findings to SOC2 Type II Trust Service Criteria
// and HIPAA Security Rule requirements.
// ============================================================

import {
  type FindingStub,
  normalizeCweId,
  groupFindingsByCwe,
} from './compliance-mapper.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ExtendedComplianceFramework = 'soc2' | 'hipaa';

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
// SOC2 Type II Mapping Table
// ---------------------------------------------------------------------------

/**
 * SOC2 Type II Trust Service Criteria mapped to CWE IDs.
 *
 * Covers Logical/Physical Access (CC6.1-CC6.8), System Operations
 * (CC7.1-CC7.5), and Change Management (CC8.1).
 */
export const SOC2_MAPPING: SOC2Criterion[] = [
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

// ---------------------------------------------------------------------------
// SOC2 Remediation Guidance
// ---------------------------------------------------------------------------

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
// HIPAA Security Rule Mapping Table
// ---------------------------------------------------------------------------

/**
 * HIPAA Security Rule (45 CFR Part 164, Subpart C) technical safeguards
 * mapped to CWE IDs.
 *
 * Covers Access Control, Audit Controls, Integrity, Person/Entity
 * Authentication, and Transmission Security.
 */
export const HIPAA_MAPPING: HIPAARequirement[] = [
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

// ---------------------------------------------------------------------------
// HIPAA Remediation Guidance
// ---------------------------------------------------------------------------

const HIPAA_REMEDIATION: Record<string, string> = {
  '164.312(a)(1)': 'Enforce access controls for ePHI systems: remove hardcoded credentials (CWE-798), store credentials with strong hashing (CWE-522), implement authorization checks at every tier (CWE-862), and validate role-based access on each request (CWE-863).',
  '164.312(a)(2)(iv)': 'Encrypt ePHI at rest and ensure adequate key strength (CWE-326), use only approved cryptographic algorithms such as AES-256-GCM (CWE-327), and encrypt all sensitive data fields in storage (CWE-311).',
  '164.312(b)': 'Implement comprehensive audit logging (CWE-778), prevent sensitive health data from appearing in log files (CWE-532), and ensure error messages do not expose ePHI or internal system details (CWE-209).',
  '164.312(c)(1)': 'Protect ePHI integrity: validate data authenticity with verification checks (CWE-345), enforce integrity checks on transmitted data (CWE-354), and verify cryptographic signatures on tokens and messages (CWE-347).',
  '164.312(d)': 'Strengthen authentication for ePHI access: validate authentication mechanisms properly (CWE-287), implement brute-force protection with account lockout (CWE-307), enforce password complexity requirements (CWE-521), and set appropriate session timeouts (CWE-613).',
  '164.312(e)(1)': 'Protect ePHI in transit: enforce TLS for all transmissions (CWE-319), validate server certificates properly (CWE-295), and verify certificate hostname matching (CWE-297).',
};

// ---------------------------------------------------------------------------
// SOC2 Mapper
// ---------------------------------------------------------------------------

/**
 * Map security findings to SOC2 Type II Trust Service Criteria.
 *
 * For each criterion, checks whether any findings match its mapped CWE IDs.
 * A criterion with matching findings is marked 'fail'. A criterion with
 * findings matching some (but not all) mapped CWEs is marked 'partial'.
 * A criterion with no matching findings is marked 'pass'.
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

  const executiveSummary = buildSOC2ExecutiveSummary(
    overallStatus,
    passCount,
    failCount,
    partialCount,
    totalCriteria,
  );

  return {
    framework: 'SOC2 Type II',
    generatedAt: new Date().toISOString(),
    overallStatus,
    criteria,
    passCount,
    failCount,
    partialCount,
    totalCriteria,
    executiveSummary,
  };
}

function buildSOC2ExecutiveSummary(
  overallStatus: 'pass' | 'fail' | 'partial',
  passCount: number,
  failCount: number,
  partialCount: number,
  totalCriteria: number,
): string {
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
  if (failCount > 0) {
    action = ' Prioritize remediation of failed criteria to achieve SOC2 readiness.';
  } else if (partialCount > 0) {
    action = ' Address partial findings to strengthen compliance posture.';
  } else {
    action = ' No automated findings detected. Continue periodic review and manual verification.';
  }

  return `${posture} ${breakdown}${action}`;
}

// ---------------------------------------------------------------------------
// HIPAA Mapper
// ---------------------------------------------------------------------------

/**
 * Map security findings to HIPAA Security Rule requirements.
 *
 * For each requirement, checks whether any findings match its mapped CWE IDs.
 * A requirement with matching findings is marked 'fail'. A requirement with
 * findings matching some (but not all) mapped CWEs is marked 'partial'.
 * A requirement with no matching findings is marked 'pass'.
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

  const executiveSummary = buildHIPAAExecutiveSummary(
    overallStatus,
    passCount,
    failCount,
    partialCount,
    totalRequirements,
  );

  return {
    framework: 'HIPAA Security Rule',
    generatedAt: new Date().toISOString(),
    overallStatus,
    requirements,
    passCount,
    failCount,
    partialCount,
    totalRequirements,
    executiveSummary,
  };
}

function buildHIPAAExecutiveSummary(
  overallStatus: 'pass' | 'fail' | 'partial',
  passCount: number,
  failCount: number,
  partialCount: number,
  totalRequirements: number,
): string {
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
  if (failCount > 0) {
    action = ' Immediate remediation required for failed requirements to maintain HIPAA compliance and protect electronic protected health information (ePHI).';
  } else if (partialCount > 0) {
    action = ' Address partial findings to strengthen ePHI protection and ensure full HIPAA compliance.';
  } else {
    action = ' No automated findings detected. Continue periodic risk assessments and manual verification of safeguards.';
  }

  return `${posture} ${breakdown}${action}`;
}
