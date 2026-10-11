// ============================================================
// Git Repository Integration Service
// Clone, pull, incremental rescan, webhook handling
// GitHub, GitLab, Bitbucket connectors
// ============================================================

import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import { logger } from '../../core/logging/logger.js';

const execFileAsync = promisify(execFile);

// Sanitize a git ref (branch/tag) to prevent command injection
function sanitizeGitRef(ref: string): string {
  let sanitized = ref.replace(/[^a-zA-Z0-9._\-\/@]/g, '');
  sanitized = sanitized.replace(/\.\./g, '');
  if (sanitized.startsWith('-')) sanitized = sanitized.replace(/^-+/, '');
  if (sanitized !== ref) {
    logger.warn({ original: ref, sanitized }, 'Git ref sanitized — contained disallowed characters');
  }
  return sanitized || 'main';
}

// Sanitize a git URL to prevent command injection
function sanitizeGitUrl(url: string): string {
  if (!/^(https?:\/\/|git@|ssh:\/\/)/.test(url)) {
    throw new Error(`Invalid git URL scheme: ${url.slice(0, 50)}`);
  }
  return url.replace(/[;&|`$(){}[\]<>!\\\n\r]/g, '');
}
const GIT_CLONE_DIR = process.env.GIT_CLONE_DIR || '/tmp/appsec-repos';

export interface GitRepoConfig {
  id: string;
  orgId: string;
  provider: 'github' | 'gitlab' | 'bitbucket' | 'azure' | 'gitea' | 'generic';
  cloneUrl: string;
  authType: 'token' | 'ssh' | 'oauth' | 'app' | 'none';
  authToken?: string;
  defaultBranch: string;
  webhookSecret?: string;
}

export interface CommitInfo {
  hash: string;
  message: string;
  author: string;
  email: string;
  timestamp: string;
  files: string[];  // changed files
  additions: number;
  deletions: number;
}

export interface CloneResult {
  success: boolean;
  repoPath: string;
  defaultBranch: string;
  error?: string;
}

export interface IncrementalDiff {
  baseHash: string;
  targetHash: string;
  changedFiles: string[];
  addedFiles: string[];
  modifiedFiles: string[];
  deletedFiles: string[];
  commits: CommitInfo[];
}

// ---- Clone & Pull ----

export async function cloneRepository(config: GitRepoConfig): Promise<CloneResult> {
  const repoPath = path.join(GIT_CLONE_DIR, config.orgId, config.id);

  if (fs.existsSync(repoPath)) {
    logger.info({ repoPath }, 'Repository already cloned — pulling latest');
    return pullRepository(config);
  }

  try {
    fs.mkdirSync(path.dirname(repoPath), { recursive: true });

    const { args, env } = buildCloneArgs(config, repoPath);
    logger.info({ repoPath, branch: config.defaultBranch }, 'Cloning repository');

    await execFileAsync('git', args, { timeout: 300000, cwd: GIT_CLONE_DIR, env });

    return { success: true, repoPath, defaultBranch: config.defaultBranch };
  } catch (err) {
    logger.error({ err, repoPath }, 'Failed to clone repository');
    return { success: false, repoPath, defaultBranch: config.defaultBranch, error: String(err) };
  }
}

function buildCloneArgs(config: GitRepoConfig, targetPath: string): { args: string[]; env: NodeJS.ProcessEnv } {
  let cloneUrl = config.cloneUrl;

  // Inject auth token for HTTPS URLs via GIT_ASKPASS or credential helper
  const env: Record<string, string> = {};
  if (config.authType === 'token' && config.authToken) {
    if (cloneUrl.startsWith('https://')) {
      // Use git credential helper approach instead of embedding token in URL
      const sanitizedUrl = sanitizeGitUrl(cloneUrl);
      const encodedToken = Buffer.from(`oauth2:${config.authToken}`).toString('base64');
      env.GIT_CONFIG_COUNT = '1';
      env.GIT_CONFIG_KEY_0 = `http.${sanitizedUrl.replace(/https?:\/\//, '')}.extraHeader`;
      env.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${encodedToken}`;
      cloneUrl = sanitizedUrl;
    }
  }

  // For SSH, set the SSH command
  if (config.authType === 'ssh') {
    env.GIT_SSH_COMMAND = 'ssh -i ~/.ssh/appsec_key -o StrictHostKeyChecking=accept-new';
  }

  const sanitizedBranch = sanitizeGitRef(config.defaultBranch);

  return {
    args: ['clone', '--depth', '50', '--single-branch', '--branch', sanitizedBranch, cloneUrl, targetPath],
    env: { ...process.env, ...env },
  };
}

export async function pullRepository(config: GitRepoConfig): Promise<CloneResult> {
  const repoPath = path.join(GIT_CLONE_DIR, config.orgId, config.id);

  if (!fs.existsSync(repoPath)) {
    return cloneRepository(config);
  }

  try {
    const branch = sanitizeGitRef(config.defaultBranch);
    const env: Record<string, string> = {};
    if (config.authType === 'ssh') {
      env.GIT_SSH_COMMAND = 'ssh -i ~/.ssh/appsec_key -o StrictHostKeyChecking=accept-new';
    }

    await execFileAsync('git', ['fetch', 'origin', branch], { timeout: 120000, cwd: repoPath, env: { ...process.env, ...env } });
    await execFileAsync('git', ['checkout', branch], { timeout: 30000, cwd: repoPath });
    await execFileAsync('git', ['reset', '--hard', `origin/${branch}`], { timeout: 30000, cwd: repoPath });

    return { success: true, repoPath, defaultBranch: config.defaultBranch };
  } catch (err) {
    logger.error({ err, repoPath }, 'Failed to pull repository');
    return { success: false, repoPath, defaultBranch: config.defaultBranch, error: String(err) };
  }
}

// ---- Diff & Incremental Analysis ----

export async function getDiff(
  config: GitRepoConfig,
  baseHash: string,
  targetHash: string,
): Promise<IncrementalDiff | null> {
  const repoPath = path.join(GIT_CLONE_DIR, config.orgId, config.id);

  if (!fs.existsSync(repoPath)) {
    logger.error({ repoPath }, 'Repository not found for diff');
    return null;
  }

  try {
    // Get changed files
    const { stdout: diffFiles } = await execFileAsync(
      'git', ['diff', '--name-status', baseHash, targetHash],
      { timeout: 30000, cwd: repoPath },
    );

    const changedFiles: string[] = [];
    const addedFiles: string[] = [];
    const modifiedFiles: string[] = [];
    const deletedFiles: string[] = [];

    for (const line of diffFiles.split('\n').filter(Boolean)) {
      const [status, ...fileParts] = line.split('\t');
      const file = fileParts.join('\t');
      changedFiles.push(file);
      if (status === 'A') addedFiles.push(file);
      else if (status === 'D') deletedFiles.push(file);
      else modifiedFiles.push(file);
    }

    // Get commits between hashes
    const { stdout: logOutput } = await execFileAsync(
      'git', ['log', `--pretty=format:%H|%s|%an|%ae|%aI`, `${baseHash}..${targetHash}`],
      { timeout: 30000, cwd: repoPath },
    );

    const commits: CommitInfo[] = [];
    for (const line of logOutput.split('\n').filter(Boolean)) {
      const [hash, message, author, email, timestamp] = line.split('|');
      if (!hash) continue;

      // Get file stats for this commit
      let statOutput = '';
      try {
        const result = await execFileAsync(
          'git', ['diff', '--stat', `${hash}^`, hash],
          { timeout: 15000, cwd: repoPath },
        );
        statOutput = result.stdout;
      } catch { statOutput = ''; }

      let additions = 0, deletions = 0;
      const statMatch = statOutput.match(/(\d+) insertion.*?(\d+) deletion/);
      if (statMatch) {
        additions = parseInt(statMatch[1]!, 10);
        deletions = parseInt(statMatch[2]!, 10);
      }

      commits.push({
        hash: hash!,
        message: message || '',
        author: author || 'unknown',
        email: email || '',
        timestamp: timestamp || new Date().toISOString(),
        files: [], // Individual commit files can be costly to compute
        additions,
        deletions,
      });
    }

    return {
      baseHash, targetHash, changedFiles, addedFiles,
      modifiedFiles, deletedFiles, commits,
    };
  } catch (err) {
    logger.error({ err, repoPath, baseHash, targetHash }, 'Failed to compute diff');
    return null;
  }
}

export async function getCurrentCommitHash(repoPath: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('git', ['rev-parse', 'HEAD'], { timeout: 10000, cwd: repoPath });
    return stdout.trim();
  } catch {
    return null;
  }
}

// ---- Webhook Payload Parsers ----

export function parseGitHubWebhook(payload: Record<string, unknown>): {
  event: string; branch: string; commitHash: string; baseHash?: string;
} | null {
  try {
    const ref = payload.ref as string;
    const branch = ref?.replace('refs/heads/', '') || 'main';
    const commitHash = (payload.after as string) || (payload.head_commit as Record<string, unknown>)?.id as string;
    const baseHash = payload.before as string;

    return { event: 'push', branch, commitHash, baseHash };
  } catch {
    return null;
  }
}

export function parseGitLabWebhook(payload: Record<string, unknown>): {
  event: string; branch: string; commitHash: string; baseHash?: string;
} | null {
  try {
    const branch = (payload.ref as string)?.replace('refs/heads/', '') || 'main';
    const commitHash = (payload.checkout_sha as string) || (payload.after as string);
    const baseHash = payload.before as string;

    return { event: payload.object_kind as string || 'push', branch, commitHash, baseHash };
  } catch {
    return null;
  }
}

export function parseBitbucketWebhook(payload: Record<string, unknown>): {
  event: string; branch: string; commitHash: string; baseHash?: string;
} | null {
  try {
    const push = payload.push as Record<string, unknown>;
    const changes = push?.changes as Array<Record<string, unknown>>;
    const change = changes?.[0];
    const branch = (change?.new as Record<string, unknown>)?.name as string || 'main';
    const commitHash = ((change?.new as Record<string, unknown>)?.target as Record<string, unknown>)?.hash as string;
    const baseHash = ((change?.old as Record<string, unknown>)?.target as Record<string, unknown>)?.hash as string;

    return { event: 'push', branch, commitHash, baseHash };
  } catch {
    return null;
  }
}

// ---- Incremental Rescan Logic ----

export function filterChangedFilesForLanguage(
  files: string[],
  targetLanguages?: string[],
): string[] {
  if (!targetLanguages || targetLanguages.length === 0) return files;

  const extMap: Record<string, string> = {
    '.js': 'javascript', '.ts': 'typescript', '.py': 'python',
    '.java': 'java', '.go': 'go', '.rs': 'rust', '.rb': 'ruby',
    '.php': 'php', '.cs': 'csharp', '.c': 'c', '.cpp': 'cpp',
  };

  return files.filter(f => {
    const ext = path.extname(f);
    const lang = extMap[ext];
    return lang && targetLanguages.includes(lang);
  });
}

export { GIT_CLONE_DIR };
