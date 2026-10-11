// Secret Worker — Secrets Exposure Hunter
// Pipeline: clone repo -> fullSecretsScan (file + git history + env files)
// -> redact + hash -> store findings -> foothold export -> complete
//
// Live validation is DISABLED per ruleset §0 — detect/score/redact/report only.
// Raw secrets are never persisted or logged (RULESET §8).

import { Worker, Job } from 'bullmq';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { logger } from './utils/logger.js';
import { startScan, storeFinding, completeScan, failScan } from './utils/scan-store.js';
import { assertScannableUrl } from './utils/ssrf.js';
import {
  fullSecretsScan,
  type SecretFinding,
  type GitSecretFinding,
  type EnvSecretFinding,
  type SecretsScanReport,
} from './sast/secrets-engine.js';

const pexecFile = promisify(execFile);

// ---------------------------------------------------------------------------
// Git clone (same pattern as sast-worker / sca-worker)
// ---------------------------------------------------------------------------

async function cloneRepo(repoUrl: string, branch?: string, token?: string): Promise<string> {
  await assertScannableUrl(repoUrl);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-repo-'));
  let cloneUrl = repoUrl;
  if (token && /^https:\/\//i.test(repoUrl)) {
    cloneUrl = repoUrl.replace(/^https:\/\//i, `https://${encodeURIComponent(token)}@`);
  }
  const args = ['clone', '--depth', '1', '--single-branch'];
  if (branch) args.push('--branch', branch);
  args.push('--', cloneUrl, dir);
  await pexecFile('git', args, {
    timeout: 180000,
    maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/bin/true', GCM_INTERACTIVE: 'never' },
  });
  return dir;
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

const connection = {
  host: process.env.REDIS_HOST || 'redis',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD,
};

// ---------------------------------------------------------------------------
// Confidence → severity mapping (RULESET §5)
// ---------------------------------------------------------------------------

function confidenceToSeverity(confidence: number): string {
  if (confidence >= 0.85) return 'critical';
  if (confidence >= 0.65) return 'high';
  if (confidence >= 0.45) return 'medium';
  return 'low';
}

// ---------------------------------------------------------------------------
// Compute confidence from secret finding properties
// ---------------------------------------------------------------------------
// Base confidence comes from L1 signature match (if a known patternId)
// adjusted by entropy ratio against the pattern's expected entropy floor.
// Lacking the exact entropy_floor per pattern in the engine, we derive a
// conservative estimate from the entropy value itself.

function computeConfidence(finding: SecretFinding, isGitCommit?: boolean): number {
  // Known patterns (L1 signature) start with high base confidence
  let baseConfidence = 0.85; // pattern matched → high base

  // Entropy adjustment: very high entropy (> 5.5) → boost, very low (< 3.0) → damp
  if (finding.entropy >= 5.5) {
    baseConfidence = Math.min(1.0, baseConfidence + 0.1);
  } else if (finding.entropy < 3.0) {
    baseConfidence *= 0.7;
  } else if (finding.entropy < 4.0) {
    baseConfidence *= 0.85;
  }

  // Git history findings get a slight confidence boost (deleted secrets are high-risk)
  if (isGitCommit) {
    baseConfidence = Math.min(1.0, baseConfidence + 0.05);
  }

  return Math.round(baseConfidence * 100) / 100;
}

// ---------------------------------------------------------------------------
// Redaction: hash the raw value, discard immediately (RULESET §8)
// ---------------------------------------------------------------------------
// The engine already provides `secret` (redacted first4+…+last4) and
// `fullMatch` (raw). We SHA-256 the raw value ONCE for dedup, then
// immediately discard it. Only the redacted form and hash are persisted.

function hashSecret(rawValue: string): string {
  return crypto.createHash('sha256').update(rawValue).digest('hex');
}

// ---------------------------------------------------------------------------
// Foothold export (RULESET §9, item 8)
// ---------------------------------------------------------------------------

interface FootholdEntry {
  ref: string;
  kind: string;
  source: string;
  note: string;
}

function writeFootholdFeed(entries: FootholdEntry[]): void {
  if (entries.length === 0) return;
  // Container path /data/exposed-creds.feed.json is bind-mounted from the host.
  // Host should mount ./data:/data so the feed lands at ./data/exposed-creds.feed.json
  // (which resolves to ./data/exposed-creds.feed.json in the repository root).
  const feedPath = '/data/exposed-creds.feed.json';
  try {
    const dir = path.dirname(feedPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(feedPath, JSON.stringify({ exposed: entries }, null, 2), 'utf-8');
    logger.info({ count: entries.length, path: feedPath }, 'Foothold feed written');
  } catch (err) {
    logger.error({ err, path: feedPath }, 'Failed to write foothold feed');
  }
}

// ---------------------------------------------------------------------------
// Utility to determine foothold kind from pattern type
// ---------------------------------------------------------------------------

function footholdKind(patternId: string): string {
  if (/KEY|SECRET|TOKEN|PAT|CRED/i.test(patternId)) {
    if (/AWS|AKIA|ASIA/i.test(patternId)) return 'leaked_access_key';
    if (/PRIVATE/i.test(patternId)) return 'exposed_private_key';
    return 'hardcoded_cred';
  }
  if (/PRIVATE/i.test(patternId)) return 'exposed_private_key';
  if (/URL|DB/i.test(patternId)) return 'exposed_connection_string';
  return 'exposed_token';
}

// ---------------------------------------------------------------------------
// Job processor
// ---------------------------------------------------------------------------

async function processJob(job: Job): Promise<Record<string, unknown>> {
  const { scanId, projectId, options, organizationId } = job.data;
  logger.info({ scanId, repoUrl: options?.repoUrl, targetPath: options?.targetPath }, 'Secret Worker: Processing job');
  await job.updateProgress(5);

  let clonedDir: string | null = null;
  const findingsCounts = { file: 0, git: 0, env: 0, total: 0 };
  const footholdEntries: FootholdEntry[] = [];

  try {
    await startScan(scanId);

    // Determine source path
    let targetPath: string;
    if (options?.repoUrl) {
      logger.info({ scanId, repoUrl: options.repoUrl, branch: options.branch }, 'Secret: Cloning git repository');
      clonedDir = await cloneRepo(options.repoUrl, options.branch, options.gitToken);
      targetPath = clonedDir;
    } else {
      targetPath = options?.targetPath || '/scan';
      if (!fs.existsSync(targetPath)) {
        throw new Error(`Scan path not found: ${targetPath}. Provide a Git repoUrl or a path under the mounted source dir (/scan).`);
      }
    }

    await job.updateProgress(10);

    // -----------------------------------------------------------------------
    // Run secrets scan — live validation DISABLED (RULESET §0)
    // -----------------------------------------------------------------------
    logger.info({ scanId, targetPath }, 'Secret: Running full secrets scan');
    // Git-history scan ONLY for freshly-cloned repos. For a local mounted dir
    // (/scan/...), `git log -p --all` discovers a .git in a parent of the mount
    // and dumps a huge unrelated history at 100% CPU — so skip it for local scans.
    const scanGitHistory = !!clonedDir;
    const report: SecretsScanReport = await fullSecretsScan(targetPath, undefined, true, scanGitHistory);
    await job.updateProgress(50);

    findingsCounts.file = report.fileFindings.length;
    findingsCounts.git = report.gitFindings.length;
    findingsCounts.env = report.envFindings.length;
    findingsCounts.total = report.stats.totalFindings;
    logger.info({ scanId, totalFindings: report.stats.totalFindings, fileFindings: report.fileFindings.length, gitFindings: report.gitFindings.length, envFindings: report.envFindings.length, durationMs: report.stats.durationMs }, 'Secret: Scan complete');

    await job.updateProgress(60);

    // -----------------------------------------------------------------------
    // Process file findings
    // -----------------------------------------------------------------------
    for (const f of report.fileFindings) {
      const secretSha256 = hashSecret(f.fullMatch);
      const confidence = computeConfidence(f);
      const severity = confidenceToSeverity(confidence);

      // NOTE: `fullMatch` is used ONLY for hashing above and discarded after this block.
      // The redacted `f.secret` and `secretSha256` are the only persisted fields.

      await storeFinding(scanId, projectId, organizationId, {
        type: 'secret',
        title: `Exposed secret: ${f.type}`,
        description: `Detected ${f.type} in ${f.file}:${f.line}. Entropy: ${f.entropy.toFixed(2)}. ${f.recommendation}`,
        severity,
        cweId: 'CWE-798', // Use of Hard-coded Credentials
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        filePath: f.file,
        lineNumber: f.line,
        codeSnippet: f.secret, // already redacted
        ruleId: f.patternId,
        ruleName: f.type,
        recommendation: f.recommendation || 'Rotate the credential immediately. Revoke the exposed key/token and scrub from git history.',
        confidence: confidence >= 0.85 ? 'high' : confidence >= 0.65 ? 'medium' : 'low',
        metadata: {
          secret_type: f.patternId,
          provider: f.type,
          redacted: f.secret,
          secret_sha256: secretSha256,
          source: 'repo_fs',
          location: { path: f.file, line: f.line },
          entropy: f.entropy,
          footprint: { ref: f.secret, kind: footholdKind(f.patternId), source: 'repo_fs', note: `${f.type} @ ${f.file}:${f.line}` },
        },
      });

      footholdEntries.push({
        ref: f.secret, // already redacted
        kind: footholdKind(f.patternId),
        source: 'repo_fs',
        note: `${f.type} @ ${f.file}:${f.line}`,
      });
    }

    // -----------------------------------------------------------------------
    // Process git history findings
    // -----------------------------------------------------------------------
    for (const f of report.gitFindings) {
      const secretSha256 = hashSecret(f.fullMatch);
      const confidence = computeConfidence(f, true);
      const severity = confidenceToSeverity(confidence);

      await storeFinding(scanId, projectId, organizationId, {
        type: 'secret',
        title: `Exposed secret in git history: ${f.type}`,
        description: `Detected ${f.type} in commit ${f.commitHash.slice(0, 12)} (${f.author}, ${f.date}) at ${f.file}:${f.line}. ${f.recommendation}`,
        severity,
        cweId: 'CWE-798',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        filePath: f.file,
        lineNumber: f.line,
        codeSnippet: f.secret, // already redacted
        ruleId: f.patternId,
        ruleName: f.type,
        recommendation: f.recommendation || 'Rotate the credential immediately. Revoke the exposed key/token and scrub from git history (git-filter-repo or BFG Repo-Cleaner).',
        confidence: confidence >= 0.85 ? 'high' : confidence >= 0.65 ? 'medium' : 'low',
        metadata: {
          secret_type: f.patternId,
          provider: f.type,
          redacted: f.secret,
          secret_sha256: secretSha256,
          source: 'git_history',
          location: {
            path: f.file,
            line: f.line,
            commit: f.commitHash,
            author: f.author,
            date: f.date,
            message: f.commitMessage,
          },
          entropy: f.entropy,
          footprint: { ref: f.secret, kind: footholdKind(f.patternId), source: 'git_history', note: `${f.type} @ ${f.file}:${f.line} (${f.commitHash.slice(0, 8)})` },
        },
      });

      footholdEntries.push({
        ref: f.secret,
        kind: footholdKind(f.patternId),
        source: 'git_history',
        note: `${f.type} @ ${f.file}:${f.line} (commit ${f.commitHash.slice(0, 8)})`,
      });
    }

    // -----------------------------------------------------------------------
    // Process env file findings
    // -----------------------------------------------------------------------
    for (const f of report.envFindings) {
      const secretSha256 = hashSecret(f.fullMatch);
      const confidence = computeConfidence(f);
      const severity = confidenceToSeverity(confidence);

      await storeFinding(scanId, projectId, organizationId, {
        type: 'secret',
        title: `Exposed secret in environment file: ${f.type} (${f.keyName})`,
        description: `Detected ${f.type} for key "${f.keyName}" in ${f.file}:${f.line}. ${f.recommendation}`,
        severity,
        cweId: 'CWE-798',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        filePath: f.file,
        lineNumber: f.line,
        codeSnippet: f.secret, // already redacted
        ruleId: f.patternId,
        ruleName: f.type,
        recommendation: f.recommendation || 'Remove the credential from environment files and use a secrets manager.',
        confidence: confidence >= 0.85 ? 'high' : confidence >= 0.65 ? 'medium' : 'low',
        metadata: {
          secret_type: f.patternId,
          provider: f.type,
          key_name: f.keyName,
          redacted: f.secret,
          secret_sha256: secretSha256,
          source: 'env_file',
          location: { path: f.file, line: f.line, key: f.keyName },
          entropy: f.entropy,
          footprint: { ref: f.secret, kind: footholdKind(f.patternId), source: 'env_file', note: `${f.type} (${f.keyName}) @ ${f.file}:${f.line}` },
        },
      });

      footholdEntries.push({
        ref: f.secret,
        kind: footholdKind(f.patternId),
        source: 'env_file',
        note: `${f.type} (${f.keyName}) @ ${f.file}:${f.line}`,
      });
    }

    await job.updateProgress(90);

    // -----------------------------------------------------------------------
    // Foothold export (item 8)
    // -----------------------------------------------------------------------
    writeFootholdFeed(footholdEntries);

    // -----------------------------------------------------------------------
    // Complete scan
    // -----------------------------------------------------------------------
    await completeScan(scanId, findingsCounts.total, {
      findingsBreakdown: findingsCounts,
      patternTypesFound: report.stats.patternTypesFound,
      highEntropyCount: report.stats.highEntropyFindings,
      durationMs: report.stats.durationMs,
    });

    logger.info({ scanId, ...findingsCounts }, 'Secret Worker: Job completed');
    return { scanId, status: 'completed', ...findingsCounts };
  } catch (err: any) {
    logger.error({ scanId, err }, 'Secret Worker: Job failed');
    await failScan(scanId, err.message || 'Unknown error during secret scan');
    throw err;
  } finally {
    // Cleanup cloned repo
    if (clonedDir && fs.existsSync(clonedDir)) {
      fs.rmSync(clonedDir, { recursive: true, force: true });
    }
  }
}

// ---------------------------------------------------------------------------
// Worker startup
// ---------------------------------------------------------------------------

const worker = new Worker('secret-scan', processJob, {
  connection,
  concurrency: 4,
  autorun: true,
});

worker.on('completed', (job) => {
  logger.info({ jobId: job.id }, 'Secret Worker: Job completed event');
});

worker.on('failed', (job, err) => {
  logger.error({ jobId: job?.id, err }, 'Secret Worker: Job failed event');
});

logger.info('Secret Worker started — listening on queue "secret-scan"');
