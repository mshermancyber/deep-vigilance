// Code Review Worker — runs the static review engines (dependency/typosquat, semantic,
// repo-health) against a cloned git repo or a local path, and persists to code_reviews.
import { Worker, Job } from 'bullmq';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { logger } from './utils/logger.js';
import { assertScannableUrl } from './utils/ssrf.js';
import { startReview, storeReviewFinding, completeReview, failReview, storeHealthMetrics, storeDependencyScan, storeDependencyFinding, ReviewFinding } from './utils/code-review-store.js';
import { scanAllDependencies, DepFinding } from './code-review/dependency-engine.js';
import { analyzeDirectorySemantic, SemanticFinding } from './code-review/semantic-engine.js';
import { analyzeRepositoryHealth, ArchitectureSmell } from './code-review/repo-health-engine.js';

const connection = { host: process.env.REDIS_HOST || 'redis', port: parseInt(process.env.REDIS_PORT || '6379', 10), password: process.env.REDIS_PASSWORD };
const pexecFile = promisify(execFile);

async function cloneRepo(repoUrl: string, branch?: string, token?: string): Promise<string> {
  await assertScannableUrl(repoUrl);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'review-'));
  let cloneUrl = repoUrl;
  if (token && /^https:\/\//i.test(repoUrl)) cloneUrl = repoUrl.replace(/^https:\/\//i, `https://${encodeURIComponent(token)}@`);
  const args = ['clone', '--depth', '1', '--single-branch'];
  if (branch) args.push('--branch', branch);
  args.push('--', cloneUrl, dir);
  await pexecFile('git', args, { timeout: 180000, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/bin/true' } });
  return dir;
}

const depToFinding = (d: DepFinding): ReviewFinding => ({
  findingType: d.type === 'license' ? 'license' : (['supply_chain', 'typosquatting', 'dependency_confusion', 'malicious'].includes(d.type) ? 'supply_chain' : 'dependency'),
  category: d.type, ruleId: `DEP-${d.type.toUpperCase()}`, ruleName: d.title,
  title: `${d.title}: ${d.packageName}@${d.packageVersion}`, description: d.description, severity: d.severity,
  filePath: `${d.ecosystem}:${d.packageName}`, cweId: d.cweId, cvssScore: d.cvssScore,
  recommendedFix: d.recommendation, securityImpact: d.kevMatch ? 'In CISA KEV (known exploited).' : undefined,
});

const semToFinding = (s: SemanticFinding): ReviewFinding => ({
  findingType: s.findingType, category: s.category, ruleId: s.ruleId, ruleName: s.ruleName,
  title: s.title, description: s.description, severity: s.severity, confidenceScore: s.confidenceScore,
  filePath: s.filePath, lineNumber: s.lineNumber, lineRange: s.lineRange, functionName: s.functionName,
  className: s.className, codeSnippet: s.codeSnippet, cweId: s.cweId, owaspCategory: s.owaspCategory,
  cvssScore: s.cvssScore, cvssVector: s.cvssVector, recommendedFix: s.recommendation,
  rootCause: s.rootCause, securityImpact: s.securityImpact, secureCodeExample: s.secureCodeExample,
});

const SMELL_LABELS: Record<string, string> = {
  god_class: 'God Class — excessive responsibility',
  large_package: 'Oversized Package',
  feature_envy: 'Feature Envy — cross-package coupling',
  circular_dependency: 'Circular Dependency',
};
const smellToFinding = (sm: ArchitectureSmell): ReviewFinding => ({
  findingType: 'architecture', category: 'architecture', ruleId: `ARCH-${sm.type.replace(/\s+/g, '-').toUpperCase()}`,
  ruleName: SMELL_LABELS[sm.type] || sm.type,
  title: `${SMELL_LABELS[sm.type] || sm.type}${sm.location ? ': ' + sm.location.split('/').pop() : ''}`,
  description: sm.description, severity: sm.severity,
  filePath: sm.location, recommendedFix: sm.recommendation,
});

async function processJob(job: Job): Promise<Record<string, unknown>> {
  const { reviewId, projectId, organizationId, reviewType, targetPath, repoUrl, gitToken, branch } = job.data;
  const t: string = reviewType || 'full';
  logger.info({ reviewId, reviewType: t, repoUrl, targetPath }, 'Code Review: starting');
  const start = Date.now();
  let cloned: string | null = null;
  try {
    await startReview(reviewId);
    let dir: string;
    if (repoUrl) { logger.info({ reviewId, repoUrl, branch }, 'Code Review: cloning'); cloned = await cloneRepo(repoUrl, branch, gitToken); dir = cloned; }
    else { dir = targetPath || '/scan'; if (!fs.existsSync(dir)) throw new Error(`Review path not found: ${dir}`); }

    const findings: ReviewFinding[] = [];
    const runDep = t === 'dependency' || t === 'security' || t === 'full';
    const runSem = t === 'semantic' || t === 'security' || t === 'full' || t === 'incremental';
    const runHealth = t === 'health' || t === 'full';

    if (runDep) {
      try {
        const depStart = Date.now();
        for (const r of scanAllDependencies(dir)) {
          for (const d of r.findings) findings.push(depToFinding(d));
          try {
            const depScanId = await storeDependencyScan(reviewId, organizationId, projectId || null, {
              ecosystem: r.ecosystem, totalPackages: r.totalPackages,
              vulnerablePackages: r.vulnerablePackages, deprecatedPackages: r.deprecatedPackages,
              endOfLifePackages: r.endOfLifePackages, licenseIssues: r.licenseIssues,
              supplyChainRisks: r.supplyChainRisks, durationMs: Date.now() - depStart,
            });
            for (const d of r.findings) {
              try {
                await storeDependencyFinding(depScanId, organizationId, {
                  packageName: d.packageName, packageVersion: d.packageVersion, ecosystem: d.ecosystem,
                  vulnerabilityType: d.type, cveId: d.cveId, cweId: d.cweId, cvssScore: d.cvssScore,
                  epssScore: d.epssScore, kevMatch: d.kevMatch, severity: d.severity, title: d.title,
                  description: d.description, fixedInVersion: d.fixedInVersion,
                  recommendation: d.recommendation, references: d.references,
                });
              } catch (e) { logger.error({ reviewId, err: e }, 'Failed to store dependency finding'); }
            }
          } catch (e) { logger.error({ reviewId, err: e }, 'Failed to store dependency scan'); }
        }
      }
      catch (e) { logger.error({ reviewId, err: e }, 'dependency engine failed'); }
      await job.updateProgress(30);
    }
    if (runSem) {
      try { for (const s of analyzeDirectorySemantic(dir)) findings.push(semToFinding(s)); }
      catch (e) { logger.error({ reviewId, err: e }, 'semantic engine failed'); }
      await job.updateProgress(70);
    }
    if (runHealth) {
      try {
        const m = analyzeRepositoryHealth(dir);
        for (const sm of m.architectureSmells) findings.push(smellToFinding(sm));
        try { await storeHealthMetrics(reviewId, organizationId, projectId || null, m); }
        catch (e) { logger.error({ reviewId, err: e }, 'Failed to store health metrics'); }
      }
      catch (e) { logger.error({ reviewId, err: e }, 'repo-health engine failed'); }
      await job.updateProgress(90);
    }
    if (t === 'fuzz') {
      findings.push({ findingType: 'fuzz', category: 'fuzzing', severity: 'info', ruleId: 'FUZZ-HARNESS-REQUIRED',
        ruleName: 'Fuzzing requires a harness', title: 'Coverage-guided fuzzing requires an executable harness',
        description: 'Fuzzing executes target functions with mutated inputs; it needs a harness per target and cannot run from a static repo clone. Define fuzz targets (entry points) to enable this review type.',
        recommendedFix: 'Add fuzz harnesses (e.g. libFuzzer/atheris/jazzer entry points) and configure targets in the review options.' });
    }

    for (const f of findings) {
      try { await storeReviewFinding(reviewId, projectId || null, organizationId, f); }
      catch (e) { logger.error({ reviewId, err: e }, 'Code Review: failed to store finding'); }
    }
    await completeReview(reviewId, findings, { durationMs: Date.now() - start, extra: { reviewType: t } });
    await job.updateProgress(100);
    logger.info({ reviewId, total: findings.length }, 'Code Review: complete');
    return { reviewId, total: findings.length };
  } catch (err) {
    logger.error({ reviewId, err }, 'Code Review: failed');
    try { await failReview(reviewId, err instanceof Error ? err.message : String(err)); } catch { /* best effort */ }
    throw err;
  } finally {
    if (cloned) { try { fs.rmSync(cloned, { recursive: true, force: true }); } catch { /* best effort */ } }
  }
}

const worker = new Worker('code-review', processJob, { connection, concurrency: 2, limiter: { max: 6, duration: 60000 }, lockDuration: 300000, stalledInterval: 120000, maxStalledCount: 3 });
worker.on('completed', (j) => logger.info({ jobId: j?.id }, 'Code Review done'));
worker.on('failed', (j, e) => logger.error({ jobId: j?.id, err: e.message }, 'Code Review error'));
logger.info('Code Review Worker running — dependency + semantic + repo-health engines');
