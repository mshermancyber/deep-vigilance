/**
 * IaC / Cloud / Container Misconfiguration SAST Rules
 *
 * Covers Terraform, Dockerfile, Kubernetes manifests, and CloudFormation
 * templates.  Every rule targets a specific misconfiguration that can be
 * detected via regex patterns in the raw source.
 */
import { SastRule } from './engine.js';

export const IAC_RULES: SastRule[] = [
  // ═══════════════════════════════════════════════════════════════════════════
  // Terraform (AWS)
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-IAC-TF-INGRESS-001',
    name: 'Terraform: Security Group Ingress CIDR 0.0.0.0/0',
    description:
      'A security group ingress rule opens a port to the entire internet. This exposes the resource to unrestricted inbound traffic and is rarely necessary.',
    severity: 'high',
    cweId: 'CWE-16',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['terraform'],
    patterns: [
      /cidr_blocks\s*=\s*\[/,
    ],
    excludePatterns: [
      // Only flag when 0.0.0.0/0 is actually used
    ],
    recommendation:
      'Restrict CIDR blocks to the minimum required IP ranges (e.g., corporate VPN CIDR, VPC CIDR). Avoid 0.0.0.0/0 in production security groups.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-INGRESS-002',
    name: 'Terraform: Security Group Ingress 0.0.0.0/0 (explicit)',
    description:
      'An ingress rule explicitly contains "0.0.0.0/0" as a CIDR block, meaning the associated port is open to the entire internet.',
    severity: 'high',
    cweId: 'CWE-16',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['terraform'],
    patterns: [
      /["']0\.0\.0\.0\/0["']/,
    ],
    recommendation:
      'Replace 0.0.0.0/0 with specific IP ranges. If global reachability is required, consider a CDN or WAF instead of direct exposure.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-S3-ACL-001',
    name: 'Terraform: S3 Bucket Public ACL',
    description:
      'An S3 bucket is configured with acl = "public-read" or "public-read-write", granting anonymous access to bucket contents.',
    severity: 'high',
    cweId: 'CWE-284',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['terraform'],
    patterns: [
      /acl\s*=\s*["']public-read(?:-write)?["']/,
    ],
    recommendation:
      'Use acl = "private" and implement fine-grained bucket policies or pre-signed URLs for controlled access.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-S3-POLICY-001',
    name: 'Terraform: S3 Bucket Public Policy',
    description:
      'An S3 bucket policy grants access via Effect:Allow to Principal:"*", making the bucket publicly accessible.',
    severity: 'critical',
    cweId: 'CWE-284',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['terraform'],
    patterns: [
      /Effect["']?\s*:\s*["']Allow["']/,
      /Principal["']?\s*:\s*["']\*["']/,
    ],
    recommendation:
      'Restrict the Principal to specific AWS accounts or IAM roles. Never use Principal: "*" with Effect: Allow in S3 bucket policies.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-IMDSV1-001',
    name: 'Terraform: EC2 IMDSv1 Enabled',
    description:
      'The EC2 instance metadata service is not configured to require IMDSv2 (http_tokens = "required"). IMDSv1 is vulnerable to SSRF-based credential theft.',
    severity: 'high',
    cweId: 'CWE-693',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['terraform'],
    patterns: [
      /metadata_options\s*\{/,
    ],
    excludePatterns: [
      /http_tokens\s*=\s*["']required["']/,
    ],
    recommendation:
      'Set metadata_options { http_tokens = "required" } to enforce IMDSv2 on all EC2 instances.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-IAM-ACTION-001',
    name: 'Terraform: IAM Policy Action Wildcard',
    description:
      'An IAM policy uses Action = "*" (wildcard), granting unrestricted access to all AWS API actions for the attached principal.',
    severity: 'high',
    cweId: 'CWE-284',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['terraform'],
    patterns: [
      /Action["']?\s*:\s*["']\*["']/,
    ],
    recommendation:
      'Restrict IAM policy actions to the minimum set required. Replace "*" with a specific list of allowed actions.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-IAM-PRINCIPAL-001',
    name: 'Terraform: IAM AssumeRole with Wildcard Principal',
    description:
      'An IAM trust policy allows AssumeRole from Principal: "*" or a wildcard AWS account, letting any AWS account assume the role.',
    severity: 'critical',
    cweId: 'CWE-284',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['terraform'],
    patterns: [
      /Principal["']?\s*:\s*\{[^}]*["']AWS["']?\s*:\s*["']\*["']/,
      /Principal["']?\s*:\s*["']\*["']/,
    ],
    recommendation:
      'Restrict the trust policy Principal to specific AWS account IDs or IAM roles. Never use "*" as a principal in trust policies.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-EBS-ENCRYPT-001',
    name: 'Terraform: Unencrypted EBS Volume',
    description:
      'An EBS volume is provisioned with encrypted = false (or encryption is omitted), leaving data at rest unprotected.',
    severity: 'medium',
    cweId: 'CWE-311',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['terraform'],
    patterns: [
      /encrypted\s*=\s*false/,
    ],
    recommendation:
      'Set encrypted = true on all EBS volumes. Enable EBS encryption by default in the AWS region.',
    cvssScore: 5.5,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-RDS-ENCRYPT-001',
    name: 'Terraform: Unencrypted RDS Instance',
    description:
      'An RDS database instance has storage_encrypted = false (or encryption is omitted), leaving database files unprotected at rest.',
    severity: 'medium',
    cweId: 'CWE-311',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['terraform'],
    patterns: [
      /storage_encrypted\s*=\s*false/,
    ],
    recommendation:
      'Set storage_encrypted = true on all RDS instances. Use AWS KMS customer-managed keys for compliance.',
    cvssScore: 5.5,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-S3-SSE-001',
    name: 'Terraform: S3 Bucket Without Default Encryption',
    description:
      'An S3 bucket is defined without a server_side_encryption_configuration block, leaving objects stored in plaintext.',
    severity: 'medium',
    cweId: 'CWE-311',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['terraform'],
    patterns: [
      /resource\s+["']aws_s3_bucket["']/,
    ],
    recommendation:
      'Add a server_side_encryption_configuration block with SSE-S3 or SSE-KMS to every S3 bucket resource.',
    cvssScore: 5.5,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-RDS-PUBLIC-001',
    name: 'Terraform: Publicly Accessible RDS',
    description:
      'An RDS instance has publicly_accessible = true, exposing the database directly to the internet.',
    severity: 'high',
    cweId: 'CWE-284',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['terraform'],
    patterns: [
      /publicly_accessible\s*=\s*true/,
    ],
    recommendation:
      'Set publicly_accessible = false. Place RDS instances in private subnets and access them via bastion hosts or AWS Systems Manager.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'iac-terraform',
  },
  {
    id: 'SAST-IAC-TF-SG-EGRESS-001',
    name: 'Terraform: Security Group Egress 0.0.0.0/0 All Ports',
    description:
      'A security group egress rule allows outbound traffic to 0.0.0.0/0 on all ports, which may facilitate data exfiltration.',
    severity: 'medium',
    cweId: 'CWE-16',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['terraform'],
    patterns: [
      /egress\s*\{/,
    ],
    recommendation:
      'Restrict egress rules to specific CIDR ranges and ports required by the application. Avoid 0.0.0.0/0 with protocol = "-1".',
    cvssScore: 4.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',
    category: 'iac-terraform',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Dockerfile
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-IAC-DKR-USER-001',
    name: 'Dockerfile: Container Runs as Root',
    description:
      'The final image does not switch to a non-root user via the USER instruction. The container process will run as UID 0, increasing the impact of a breakout.',
    severity: 'high',
    cweId: 'CWE-250',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['dockerfile'],
    patterns: [
      /^USER\s+root\s*$/i,
    ],
    recommendation:
      'Add "USER 1000" (or another non-zero UID) after installing packages and before CMD/ENTRYPOINT. Create a dedicated app user in the Dockerfile.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
    category: 'iac-docker',
  },
  {
    id: 'SAST-IAC-DKR-ADD-URL-001',
    name: 'Dockerfile: ADD from Remote URL',
    description:
      'The ADD instruction fetches a file from a remote HTTPS URL. This can introduce untrusted content and breaks layer caching for deterministic builds.',
    severity: 'high',
    cweId: 'CWE-494',
    owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
    languages: ['dockerfile'],
    patterns: [
      /^ADD\s+https?:\/\//i,
    ],
    recommendation:
      'Use curl or wget in a RUN instruction with checksum verification, or download the file ahead of time and COPY it into the image.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L',
    category: 'iac-docker',
  },
  {
    id: 'SAST-IAC-DKR-LATEST-001',
    name: 'Dockerfile: Base Image Uses :latest Tag',
    description:
      'A FROM instruction uses the :latest tag (or omits the tag, defaulting to latest). This makes builds non-reproducible and can silently pull breaking changes.',
    severity: 'low',
    cweId: 'CWE-1104',
    owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
    languages: ['dockerfile'],
    patterns: [
      /^FROM\s+\S+:latest\b/i,
    ],
    recommendation:
      'Pin the base image to a specific digest or version tag (e.g., node:20-alpine@sha256:...). Use renovate/dependabot to keep it updated.',
    cvssScore: 3.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N',
    category: 'iac-docker',
  },
  {
    id: 'SAST-IAC-DKR-SECRET-ENV-001',
    name: 'Dockerfile: Secret in ENV Instruction',
    description:
      'An ENV instruction sets a variable whose name suggests it contains a secret (PASSWORD, SECRET, TOKEN, KEY). Secrets in ENV are baked into image layers.',
    severity: 'high',
    cweId: 'CWE-312',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['dockerfile'],
    patterns: [
      /^ENV\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY|CRED)\w*\s*=\s*\S/i,
    ],
    recommendation:
      'Never hardcode secrets in ENV. Use Docker secrets, Kubernetes secrets, or mount secrets at runtime via a volume. Pass secrets through the runtime environment only.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
    category: 'iac-docker',
  },
  {
    id: 'SAST-IAC-DKR-CURL-BASH-001',
    name: 'Dockerfile: curl | sh Pattern',
    description:
      'A RUN instruction pipes curl output directly into a shell interpreter. This executes untrusted remote code without integrity verification.',
    severity: 'high',
    cweId: 'CWE-494',
    owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
    languages: ['dockerfile'],
    patterns: [
      /^RUN\s+.*curl\s+.*\|\s*(?:sh|bash|zsh)\b/i,
      /^RUN\s+.*wget\s+.*\|\s*(?:sh|bash|zsh)\b/i,
    ],
    recommendation:
      'Download the script first, verify its checksum, and then execute it. Better: use the package manager or copy the script into the image with a known-good version.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'iac-docker',
  },
  {
    id: 'SAST-IAC-DKR-USER-MISSING-001',
    name: 'Dockerfile: No USER Instruction Before CMD/ENTRYPOINT',
    description:
      'The Dockerfile has a CMD or ENTRYPOINT but no preceding USER instruction. By default the container runs as root (UID 0).',
    severity: 'high',
    cweId: 'CWE-250',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['dockerfile'],
    patterns: [
      /^(?:CMD|ENTRYPOINT)\s/i,
    ],
    excludePatterns: [
      /USER\s+\d+/,
    ],
    recommendation:
      'Add "USER <non-root-uid>" before CMD/ENTRYPOINT. Create a dedicated user with minimal privileges.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
    category: 'iac-docker',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Kubernetes Manifests
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-IAC-K8S-PRIV-001',
    name: 'Kubernetes: Privileged Container',
    description:
      'A container has securityContext.privileged: true, granting it all Linux capabilities and access to host devices.',
    severity: 'critical',
    cweId: 'CWE-250',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['yaml'],
    patterns: [
      /privileged\s*:\s*true/,
    ],
    excludePatterns: [
      /#\s*(?:nosec|noqa|pragma)/,
    ],
    recommendation:
      'Remove privileged: true. Grant only the specific capabilities needed via capabilities.add in the securityContext.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
    category: 'iac-kubernetes',
  },
  {
    id: 'SAST-IAC-K8S-HOSTNET-001',
    name: 'Kubernetes: hostNetwork Enabled',
    description:
      'A pod spec sets hostNetwork: true, giving the container access to the node network namespace. This bypasses network policies.',
    severity: 'high',
    cweId: 'CWE-668',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['yaml'],
    patterns: [
      /hostNetwork\s*:\s*true/,
    ],
    excludePatterns: [
      /#\s*(?:nosec|noqa|pragma)/,
    ],
    recommendation:
      'Remove hostNetwork: true unless absolutely required (e.g., for CNI plugins). Use Kubernetes Services and Ingress for network access.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
    category: 'iac-kubernetes',
  },
  {
    id: 'SAST-IAC-K8S-HOSTPID-001',
    name: 'Kubernetes: hostPID Enabled',
    description:
      'A pod spec sets hostPID: true, sharing the host process namespace. This allows the container to see and potentially kill host processes.',
    severity: 'high',
    cweId: 'CWE-668',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['yaml'],
    patterns: [
      /hostPID\s*:\s*true/,
    ],
    excludePatterns: [
      /#\s*(?:nosec|noqa|pragma)/,
    ],
    recommendation:
      'Remove hostPID: true. Host process namespace sharing should be avoided in almost all workloads.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N',
    category: 'iac-kubernetes',
  },
  {
    id: 'SAST-IAC-K8S-HOSTIPC-001',
    name: 'Kubernetes: hostIPC Enabled',
    description:
      'A pod spec sets hostIPC: true, sharing the host IPC namespace. This allows the container to communicate with host processes via shared memory.',
    severity: 'high',
    cweId: 'CWE-668',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['yaml'],
    patterns: [
      /hostIPC\s*:\s*true/,
    ],
    excludePatterns: [
      /#\s*(?:nosec|noqa|pragma)/,
    ],
    recommendation:
      'Remove hostIPC: true. Host IPC namespace sharing is almost never needed for application workloads.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N',
    category: 'iac-kubernetes',
  },
  {
    id: 'SAST-IAC-K8S-PRIVESC-001',
    name: 'Kubernetes: Privilege Escalation Allowed',
    description:
      'A container has allowPrivilegeEscalation: true, permitting child processes to gain more privileges than their parent. This is the default when unset.',
    severity: 'high',
    cweId: 'CWE-250',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['yaml'],
    patterns: [
      /allowPrivilegeEscalation\s*:\s*true/,
    ],
    excludePatterns: [
      /#\s*(?:nosec|noqa|pragma)/,
    ],
    recommendation:
      'Set allowPrivilegeEscalation: false in the securityContext to prevent privilege escalation via setuid binaries.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
    category: 'iac-kubernetes',
  },
  {
    id: 'SAST-IAC-K8S-RUNASROOT-001',
    name: 'Kubernetes: Container May Run as Root',
    description:
      'The container securityContext has runAsNonRoot: false (or omits it), allowing the process to start as UID 0.',
    severity: 'medium',
    cweId: 'CWE-250',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['yaml'],
    patterns: [
      /runAsNonRoot\s*:\s*false/,
    ],
    excludePatterns: [
      /#\s*(?:nosec|noqa|pragma)/,
    ],
    recommendation:
      'Set runAsNonRoot: true in the pod or container securityContext and ensure the image uses a non-zero UID.',
    cvssScore: 5.5,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L',
    category: 'iac-kubernetes',
  },
  {
    id: 'SAST-IAC-K8S-LIMITS-001',
    name: 'Kubernetes: Missing Resource Limits',
    description:
      'A container spec does not define resources.limits, which can lead to resource exhaustion and denial of service in the cluster.',
    severity: 'low',
    cweId: 'CWE-770',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['yaml'],
    patterns: [
      /containers\s*:/,
    ],
    excludePatterns: [
      /resources\s*:\s*\n\s*limits\s*:/,
      /#\s*(?:nosec|noqa|pragma)/,
    ],
    recommendation:
      'Define resources.limits.cpu and resources.limits.memory for every container to prevent noisy-neighbor resource exhaustion.',
    cvssScore: 3.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L',
    category: 'iac-kubernetes',
  },
  {
    id: 'SAST-IAC-K8S-RBAC-WILDCARD-001',
    name: 'Kubernetes: RBAC Wildcard Verbs/Resources',
    description:
      'A Role or ClusterRole uses verbs: ["*"] or resources: ["*"], granting unrestricted access within the namespace or cluster.',
    severity: 'critical',
    cweId: 'CWE-284',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['yaml'],
    patterns: [
      /(?:verbs|resources)\s*:\s*\[[^\]]*\*\s*[^\]]*\]/,
    ],
    excludePatterns: [
      /#\s*(?:nosec|noqa|pragma)/,
    ],
    recommendation:
      'Replace wildcard verbs/resources with an explicit list of required permissions. Follow the principle of least privilege.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
    category: 'iac-kubernetes',
  },
  {
    id: 'SAST-IAC-K8S-SATOKEN-001',
    name: 'Kubernetes: Service Account Token Auto-Mount Not Disabled',
    description:
      'A pod or service account does not set automountServiceAccountToken: false. Unnecessary tokens increase the blast radius of a compromise.',
    severity: 'medium',
    cweId: 'CWE-668',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['yaml'],
    patterns: [
      /automountServiceAccountToken\s*:\s*true/,
    ],
    excludePatterns: [
      /#\s*(?:nosec|noqa|pragma)/,
    ],
    recommendation:
      'Set automountServiceAccountToken: false for pods that do not need to call the Kubernetes API.',
    cvssScore: 4.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',
    category: 'iac-kubernetes',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // CloudFormation
  // ═══════════════════════════════════════════════════════════════════════════

  {
    id: 'SAST-IAC-CF-S3-ACL-001',
    name: 'CloudFormation: S3 Bucket Public Access',
    description:
      'A CloudFormation template defines an S3 bucket with AccessControl set to PublicRead or PublicReadWrite, exposing objects anonymously.',
    severity: 'high',
    cweId: 'CWE-284',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['yaml', 'json'],
    patterns: [
      /AccessControl["']?\s*:\s*["']PublicRead(?:Write)?["']/,
    ],
    recommendation:
      'Use AccessControl: Private and manage access through IAM policies or pre-signed URLs.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'iac-cloudformation',
  },
  {
    id: 'SAST-IAC-CF-SG-CIDR-001',
    name: 'CloudFormation: Security Group with 0.0.0.0/0',
    description:
      'A CloudFormation security group ingress rule contains CidrIp: 0.0.0.0/0, opening the port to the entire internet.',
    severity: 'high',
    cweId: 'CWE-16',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['yaml', 'json'],
    patterns: [
      /CidrIp["']?\s*:\s*["']0\.0\.0\.0\/0["']/,
    ],
    recommendation:
      'Restrict CidrIp to specific IP ranges (corporate CIDR, VPC CIDR). Avoid 0.0.0.0/0 in production security groups.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
    category: 'iac-cloudformation',
  },
];
