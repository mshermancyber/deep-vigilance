// Container Security Scanner — Dockerfile Analysis
// Analyzes Dockerfile content for misconfigurations, insecure patterns, and violations of best practices.
import { logger } from '../utils/logger.js';
import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ContainerScanViolation {
  ruleId: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cweId: string;
  lineNumber: number;
  lineContent: string;
  snippet: string;
  recommendation: string;
  cvssScore: number;
  category: string;
}

export interface ContainerScanResult {
  dockerfilePath: string;
  totalLines: number;
  baseImage: string | null;
  stages: DockerStage[];
  violations: ContainerScanViolation[];
  score: number; // 0-100, 100 = perfect
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface DockerStage {
  name: string | null;
  from: string;
  fromLine: number;
  hasUserDirective: boolean;
  userDirectiveLine: number | null;
  userValue: string | null;
  hasHealthcheck: boolean;
  healthcheckLine: number | null;
  exposedPorts: Array<{ port: number; protocol: string; line: number }>;
  packageInstalls: Array<{ package: string; line: number }>;
  addCommands: Array<{ source: string; dest: string; line: number; isRemote: boolean }>;
  copyCommands: Array<{ source: string; dest: string; line: number; fromStage?: string }>;
  runWithNetworkCalls: Array<{ line: number; command: string }>;
  secretsInEnv: Array<{ line: number; key: string }>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SENSITIVE_ENV_KEYS = [
  /^PASSWORD$/i, /^PASSWD$/i, /^SECRET$/i, /^SECRET_KEY$/i, /^API_KEY$/i,
  /^API_SECRET$/i, /^ACCESS_KEY$/i, /^ACCESS_TOKEN$/i, /^AUTH_TOKEN$/i,
  /^TOKEN$/i, /^PRIVATE_KEY$/i, /^DB_PASSWORD/i, /^DB_PASS/i, /^DATABASE_URL/i,
  /^REDIS_URL/i, /^JWT_SECRET/i, /^SESSION_SECRET/i, /^AWS_SECRET/i,
  /^AZURE_SECRET/i, /^GCP_SECRET/i, /^OAUTH_CLIENT_SECRET/i,
  /^STRIPE_API_KEY/i, /^STRIPE_SECRET/i, /^GITHUB_TOKEN/i, /^GITLAB_TOKEN/i,
];

const REMOTE_URL_PATTERN = /^(https?:\/\/|ftp:\/\/)/i;

// ---------------------------------------------------------------------------
// Dockerfile Parser
// ---------------------------------------------------------------------------

function parseDockerfileLines(content: string): string[] {
  // Handle line continuations: merge lines ending with backslash
  const rawLines = content.split('\n');
  const merged: string[] = [];
  let current = '';

  for (let i = 0; i < rawLines.length; i++) {
    const line = rawLines[i]!;
    const trimmed = line.replace(/\r$/, '');

    if (trimmed.endsWith('\\')) {
      current += trimmed.slice(0, -1).trimEnd() + ' ';
    } else {
      merged.push(current + trimmed);
      current = '';
    }
  }
  if (current.trim()) {
    merged.push(current.trimEnd());
  }

  return merged;
}

export function parseDockerfile(content: string): {
  lines: string[];
  stages: DockerStage[];
  baseImage: string | null;
} {
  const lines = parseDockerfileLines(content);
  const stages: DockerStage[] = [];
  let currentStage: DockerStage | null = null;
  let baseImage: string | null = null;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;
    const lineNum = lineIdx + 1;
    const trimmed = line.trim();

    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) continue;

    // FROM directive — starts a new stage
    const fromMatch = trimmed.match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i);
    if (fromMatch) {
      if (currentStage) {
        stages.push(currentStage);
      }
      const image = fromMatch[1]!;
      if (!baseImage && stages.length === 0) {
        baseImage = image;
      }
      currentStage = {
        name: fromMatch[2] || null,
        from: image,
        fromLine: lineNum,
        hasUserDirective: false,
        userDirectiveLine: null,
        userValue: null,
        hasHealthcheck: false,
        healthcheckLine: null,
        exposedPorts: [],
        packageInstalls: [],
        addCommands: [],
        copyCommands: [],
        runWithNetworkCalls: [],
        secretsInEnv: [],
      };
      continue;
    }

    if (!currentStage) {
      // Lines before first FROM (syntax directives, comments) — ignore
      continue;
    }

    // USER directive
    const userMatch = trimmed.match(/^USER\s+(\S+)/i);
    if (userMatch) {
      currentStage.hasUserDirective = true;
      currentStage.userDirectiveLine = lineNum;
      currentStage.userValue = userMatch[1]!;
      continue;
    }

    // HEALTHCHECK directive
    const healthMatch = trimmed.match(/^HEALTHCHECK\s+/i);
    if (healthMatch) {
      currentStage.hasHealthcheck = true;
      currentStage.healthcheckLine = lineNum;
      continue;
    }

    // EXPOSE directive
    const exposeMatch = trimmed.match(/^EXPOSE\s+(.+)/i);
    if (exposeMatch) {
      const portsStr = exposeMatch[1]!;
      // Parse multiple ports: "80 443/tcp 8080/udp"
      const portTokens = portsStr.split(/\s+/);
      for (const token of portTokens) {
        const portProtoMatch = token.match(/^(\d+)(?:\/(tcp|udp))?$/i);
        if (portProtoMatch) {
          currentStage.exposedPorts.push({
            port: parseInt(portProtoMatch[1]!, 10),
            protocol: (portProtoMatch[2] || 'tcp').toLowerCase(),
            line: lineNum,
          });
        }
      }
      continue;
    }

    // ADD directive
    const addMatch = trimmed.match(/^ADD\s+(?:--chown=\S+\s+)?(?:--chmod=\S+\s+)?(\S+)\s+(\S+)/i);
    if (addMatch) {
      currentStage.addCommands.push({
        source: addMatch[1]!,
        dest: addMatch[2]!,
        line: lineNum,
        isRemote: REMOTE_URL_PATTERN.test(addMatch[1]!),
      });
      continue;
    }

    // COPY directive
    const copyMatch = trimmed.match(/^COPY\s+(?:--from=(\S+)\s+)?(?:\S+\s+)?(\S+)\s+(\S+)/i);
    if (copyMatch) {
      currentStage.copyCommands.push({
        source: copyMatch[2]!,
        dest: copyMatch[3]!,
        line: lineNum,
        fromStage: copyMatch[1],
      });
      continue;
    }

    // RUN directive — check for curl/wget piped to shell, or other network calls
    const runMatch = trimmed.match(/^RUN\s+(.+)/i);
    if (runMatch) {
      const cmd = runMatch[1]!;
      const potentialNetwork = /(curl|wget)\s.*[|]\s*(bash|sh|zsh|python|perl|ruby|php)/i.test(cmd) ||
        /(curl|wget)\s.*(?:-o\s*-\s*||-O-\s*)\s*[|]\s*(bash|sh|zsh)/i.test(cmd);
      const hasNetwork = /\b(curl|wget|nc|netcat|telnet|ssh)\b/i.test(cmd);

      if (potentialNetwork || hasNetwork) {
        currentStage.runWithNetworkCalls.push({
          line: lineNum,
          command: cmd.slice(0, 200),
        });
      }

      // Detect package manager installs
      const pkgMatch = trimmed.match(/apt-get\s+install\s+(-y\s+)?(.+)/i) ||
        trimmed.match(/apk\s+add\s+(--no-cache\s+)?(.+)/i) ||
        trimmed.match(/yum\s+install\s+(-y\s+)?(.+)/i) ||
        trimmed.match(/dnf\s+install\s+(-y\s+)?(.+)/i) ||
        trimmed.match(/zypper\s+in\s+(.+)/i) ||
        trimmed.match(/pip\s+install\s+(.+)/i) ||
        trimmed.match(/npm\s+install\s+(.+)/i);
      if (pkgMatch) {
        currentStage.packageInstalls.push({
          package: pkgMatch[2] || pkgMatch[1] || '',
          line: lineNum,
        });
      }
      continue;
    }

    // ENV directive — check for secrets
    const envMatch = trimmed.match(/^ENV\s+(\S+)(?:\s*=\s*["']?(\S+)["']?)?/i);
    if (envMatch) {
      const key = envMatch[1]!;
      const isSecret = SENSITIVE_ENV_KEYS.some((re) => re.test(key));
      if (isSecret) {
        currentStage.secretsInEnv.push({
          line: lineNum,
          key: key,
        });
      }
      continue;
    }
  }

  // Push the last stage
  if (currentStage) {
    stages.push(currentStage);
  }

  return { lines, stages, baseImage };
}

// ---------------------------------------------------------------------------
// Rule Evaluators
// ---------------------------------------------------------------------------

function scoreSeverity(severity: string): number {
  const rank: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
  return rank[severity] ?? 3;
}

function checkFromLatest(
  stages: DockerStage[],
  violations: ContainerScanViolation[],
): void {
  for (const stage of stages) {
    const image = stage.from;
    const hasLatestTag = /:\blatest\b/i.test(image) || !/:/.test(image);
    if (hasLatestTag) {
      violations.push({
        ruleId: 'DOCKER-FROM-001',
        title: 'Base image uses "latest" tag',
        description: `Stage "${stage.name || 'unnamed'}" uses base image "${stage.from}" without a specific version tag. Using "latest" produces non-reproducible builds and may introduce breaking changes.`,
        severity: 'high',
        cweId: 'CWE-1104',
        lineNumber: stage.fromLine,
        lineContent: `FROM ${stage.from}`,
        snippet: `FROM ${stage.from}`,
        recommendation: 'Pin the base image to a specific digest or semver tag, e.g. "node:20-alpine" or "node@sha256:...". Use Dependabot/Renovate to automate updates.',
        cvssScore: 7.5,
        category: 'supply-chain',
      });
    }
  }
}

function checkUserRoot(
  stages: DockerStage[],
  violations: ContainerScanViolation[],
): void {
  for (const stage of stages) {
    if (stage.userValue && /^root$/i.test(stage.userValue)) {
      violations.push({
        ruleId: 'DOCKER-USER-001',
        title: 'USER root explicitly set',
        description: `Stage "${stage.name || 'unnamed'}" explicitly sets USER root. Running containers as root increases the blast radius of container breakout vulnerabilities.`,
        severity: 'high',
        cweId: 'CWE-250',
        lineNumber: stage.userDirectiveLine!,
        lineContent: `USER root`,
        snippet: `USER root`,
        recommendation: 'Create a non-root user (e.g. "RUN addgroup -g 1001 app && adduser -u 1001 -G app -s /bin/sh -D app") and switch with "USER app". Set the USER directive early in the stage.',
        cvssScore: 7.0,
        category: 'misconfiguration',
      });
    }
  }
}

function checkMissingUserDirective(
  stages: DockerStage[],
  violations: ContainerScanViolation[],
  totalLines: number,
): void {
  // Check if any stage is missing USER (except builder stages that only COPY --from)
  for (const stage of stages) {
    if (!stage.hasUserDirective && stage.copyCommands.length <= 10) {
      violations.push({
        ruleId: 'DOCKER-USER-002',
        title: 'Missing USER directive — container runs as root',
        description: `Stage "${stage.name || 'unnamed'}" is missing a USER directive and will run as root by default.`,
        severity: 'medium',
        cweId: 'CWE-250',
        lineNumber: stage.fromLine,
        lineContent: `FROM ${stage.from}`,
        snippet: `FROM ${stage.from}`,
        recommendation: 'Add "USER <nonroot>" near the end of the stage after all package installs and file copies. Use a dedicated non-root user with only required permissions.',
        cvssScore: 5.5,
        category: 'misconfiguration',
      });
    }
  }
}

function checkAddRemoteUrl(
  stages: DockerStage[],
  violations: ContainerScanViolation[],
): void {
  for (const stage of stages) {
    for (const add of stage.addCommands) {
      if (add.isRemote) {
        violations.push({
          ruleId: 'DOCKER-ADD-001',
          title: 'ADD with remote URL — prefer curl/wget',
          description: `ADD fetches from a remote URL (${add.source.slice(0, 100)}). ADD does not cache downloads efficiently and lacks progress reporting. Remote URLs in ADD can also mask the origin of the downloaded file.`,
          severity: 'medium',
          cweId: 'CWE-829',
          lineNumber: add.line,
          lineContent: `ADD ${add.source} ${add.dest}`,
          snippet: `ADD ${add.source.slice(0, 80)} ${add.dest}`,
          recommendation: 'Use "RUN curl -fsSL <url> -o <file>" instead, which supports better caching, progress, and can be combined with checksum verification ("RUN echo <sha256> <file> | sha256sum -c").',
          cvssScore: 5.0,
          category: 'supply-chain',
        });
      }
    }
  }
}

function checkMissingHealthcheck(
  stages: DockerStage[],
  violations: ContainerScanViolation[],
): void {
  // Final stage (or only stage) should have HEALTHCHECK
  const finalStage = stages[stages.length - 1];
  if (finalStage && !finalStage.hasHealthcheck) {
    violations.push({
      ruleId: 'DOCKER-HEALTH-001',
      title: 'Missing HEALTHCHECK directive',
      description: `The final stage "${finalStage.name || 'unnamed'}" is missing a HEALTHCHECK. Without it, the container orchestrator cannot determine if the application is healthy or needs restarting.`,
      severity: 'low',
      cweId: 'CWE-1069',
      lineNumber: finalStage.fromLine,
      lineContent: `FROM ${finalStage.from}`,
      snippet: `FROM ${finalStage.from}`,
      recommendation: 'Add "HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD curl -f http://localhost:8080/health || exit 1". Adjust the command to match your application health endpoint.',
      cvssScore: 3.5,
      category: 'observability',
    });
  }
}

function checkExposedPortsWithoutComment(
  stages: DockerStage[],
  violations: ContainerScanViolation[],
  rawContent: string,
): void {
  const rawLines = rawContent.split('\n');
  for (const stage of stages) {
    for (const portInfo of stage.exposedPorts) {
      // Check if the EXPOSE line or preceding comment indicates justification
      const lineIdx = portInfo.line - 1;
      const hasPriorComment = lineIdx > 0 && /^\s*#/.test(rawLines[lineIdx - 1] ?? '');
      const lineContent = (rawLines[lineIdx] ?? '').trim();

      // Check if the EXPOSE line itself has an inline comment indicating purpose
      const hasInlineComment = /#\s*(web|app|api|db|admin|metrics|health|debug|monitoring|service|port)/i.test(lineContent);
      const isWellKnownPort = [80, 443, 3000, 5000, 8080, 8443, 5432, 6379, 27017].includes(portInfo.port);

      if (!hasPriorComment && !isWellKnownPort && !hasInlineComment) {
        violations.push({
          ruleId: 'DOCKER-EXPOSE-001',
          title: 'Exposed port without justification',
          description: `Port ${portInfo.port}/${portInfo.protocol} is exposed without a comment explaining its purpose.`,
          severity: 'info',
          cweId: 'CWE-200',
          lineNumber: portInfo.line,
          lineContent: `EXPOSE ${portInfo.port}/${portInfo.protocol}`,
          snippet: `EXPOSE ${portInfo.port}/${portInfo.protocol}`,
          recommendation: `Add a comment above the EXPOSE line explaining its purpose, e.g. "# ${portInfo.port} = ${portInfo.port === 8080 ? 'application HTTP' : 'custom service'}"`,
          cvssScore: 1.0,
          category: 'documentation',
        });
      }
    }
  }
}

function checkRunCurlPipeShell(
  stages: DockerStage[],
  violations: ContainerScanViolation[],
): void {
  for (const stage of stages) {
    for (const nc of stage.runWithNetworkCalls) {
      // Check for pipe-to-shell pattern specifically
      const isPipeToShell = /(curl|wget)\s.*[|]\s*(bash|sh|zsh|python|perl|ruby|php)/i.test(nc.command);
      if (isPipeToShell) {
        violations.push({
          ruleId: 'DOCKER-RUN-001',
          title: 'RUN with curl/wget piped to shell — potential supply chain risk',
          description: `Stage "${stage.name || 'unnamed'}" uses a pipe from curl/wget to a shell interpreter (${nc.command.slice(0, 120)}). This pattern downloads and executes code without verification, making builds vulnerable to MITM attacks or server compromises.`,
          severity: 'critical',
          cweId: 'CWE-494',
          lineNumber: nc.line,
          lineContent: `RUN ${nc.command.slice(0, 150)}`,
          snippet: `RUN ${nc.command.slice(0, 120)}`,
          recommendation: '1) Download the script and verify its checksum: "RUN curl -fsSL <url> -o /tmp/install.sh && echo \'<sha256> /tmp/install.sh\' | sha256sum -c && bash /tmp/install.sh". 2) Use official package manager repositories. 3) Pin scripts to specific commit hashes.',
          cvssScore: 9.0,
          category: 'supply-chain',
        });
      }
    }
  }
}

function checkSecretsInEnv(
  stages: DockerStage[],
  violations: ContainerScanViolation[],
): void {
  for (const stage of stages) {
    for (const s of stage.secretsInEnv) {
      violations.push({
        ruleId: 'DOCKER-ENV-001',
        title: 'Potential secret in ENV directive',
        description: `Stage "${stage.name || 'unnamed'}" sets ENV with key "${s.key}" which appears to be a secret. Secrets baked into images persist in history layers and can be extracted from the image.`,
        severity: 'critical',
        cweId: 'CWE-798',
        lineNumber: s.line,
        lineContent: `ENV ${s.key}=...`,
        snippet: `ENV ${s.key}=***`,
        recommendation: 'Use Docker build secrets ("--secret id=mysecret") or pass values at runtime via environment variables. Never embed credentials in Dockerfile ENV directives. Use multi-stage builds to avoid secrets in final images.',
        cvssScore: 8.5,
        category: 'credentials',
      });
    }
  }
}

function checkMultiStageInefficiency(
  stages: DockerStage[],
  violations: ContainerScanViolation[],
  rawContent: string,
): void {
  if (stages.length < 2) return;

  const finalStage = stages[stages.length - 1]!;
  const builderStages = stages.slice(0, -1);

  for (const builder of builderStages) {
    // Check if build dependencies are being cleaned up in the builder
    let hasCleanup = false;
    const lines = rawContent.split('\n');

    for (let i = builder.fromLine - 1; i < rawContent.split('\n').length; i++) {
      const line = (lines[i] ?? '').trim();
      if (i >= (stages.find(s => s !== builder && s.fromLine > builder.fromLine)?.fromLine ?? Infinity)) break;
      if (/apt-get\s+(clean|autoremove|purge)/i.test(line) ||
          /rm\s+-rf\s+\/var\/lib\/apt/i.test(line) ||
          /apk\s+del/i.test(line) ||
          /yum\s+clean/i.test(line) ||
          /dnf\s+clean/i.test(line) ||
          /npm\s+prune/i.test(line) ||
          /pip\s+uninstall/i.test(line) ||
          /rm\s+-rf\s+\/root\/\.cache/i.test(line) ||
          /rm\s+-rf\s+\/tmp\//.test(line)) {
        hasCleanup = true;
        break;
      }
    }

    if (!hasCleanup && builder.packageInstalls.length > 0 && builder.name && !finalStage.copyCommands.some(c => c.fromStage === builder.name)) {
      violations.push({
        ruleId: 'DOCKER-MULTI-001',
        title: 'Multi-stage inefficiency — stage not used by final stage',
        description: `Builder stage "${builder.name}" has ${builder.packageInstalls.length} package install(s) but its artifacts are not copied to the final stage via COPY --from=${builder.name}. This suggests the stage may be unnecessary or packages are being duplicated.`,
        severity: 'low',
        cweId: 'CWE-1104',
        lineNumber: builder.fromLine,
        lineContent: `FROM ${builder.from} AS ${builder.name}`,
        snippet: `FROM ${builder.from} AS ${builder.name}`,
        recommendation: 'Verify the stage is used. If build tools are only needed during compilation, copy only the compiled artifacts (e.g., "COPY --from=builder /app/dist ./dist") and ensure build dependencies are not in the final image.',
        cvssScore: 3.0,
        category: 'efficiency',
      });
    }

    if (!hasCleanup && builder.packageInstalls.length > 5) {
      violations.push({
        ruleId: 'DOCKER-MULTI-002',
        title: 'Package cache not cleaned in build stage',
        description: `Builder stage "${builder.name}" installs ${builder.packageInstalls.length} packages without cleaning the package manager cache. This unnecessarily increases layer size.`,
        severity: 'info',
        cweId: 'CWE-1104',
        lineNumber: builder.fromLine,
        lineContent: `FROM ${builder.from} AS ${builder.name}`,
        snippet: `FROM ${builder.from} AS ${builder.name}`,
        recommendation: 'Combine "apt-get update && apt-get install -y <pkgs> && rm -rf /var/lib/apt/lists/*" in a single RUN command to avoid caching intermediate layers. For Alpine, use "apk add --no-cache".',
        cvssScore: 2.0,
        category: 'efficiency',
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Main Scanner Entry Point
// ---------------------------------------------------------------------------

export function scanDockerfile(
  dockerfilePath: string,
  content: string,
): ContainerScanResult {
  logger.info({ dockerfilePath, contentLength: content.length }, 'Scanning Dockerfile');

  const { lines, stages, baseImage } = parseDockerfile(content);
  const violations: ContainerScanViolation[] = [];

  // Run all checks
  checkFromLatest(stages, violations);
  checkUserRoot(stages, violations);
  checkMissingUserDirective(stages, violations, lines.length);
  checkAddRemoteUrl(stages, violations);
  checkMissingHealthcheck(stages, violations);
  checkExposedPortsWithoutComment(stages, violations, content);
  checkRunCurlPipeShell(stages, violations);
  checkSecretsInEnv(stages, violations);
  checkMultiStageInefficiency(stages, violations, content);

  // Compute score: start at 100, subtract based on severity
  const severitySubtractions: Record<string, number> = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 4,
    info: 1,
  };

  let score = 100;
  for (const v of violations) {
    score -= severitySubtractions[v.severity] ?? 0;
  }
  score = Math.max(0, Math.min(100, score));

  const summary = {
    critical: violations.filter(v => v.severity === 'critical').length,
    high: violations.filter(v => v.severity === 'high').length,
    medium: violations.filter(v => v.severity === 'medium').length,
    low: violations.filter(v => v.severity === 'low').length,
    info: violations.filter(v => v.severity === 'info').length,
  };

  return {
    dockerfilePath,
    totalLines: lines.length,
    baseImage,
    stages,
    violations,
    score,
    summary,
  };
}

// ---------------------------------------------------------------------------
// Hash utility for image digests
// ---------------------------------------------------------------------------

export function computeDockerfileHash(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}
