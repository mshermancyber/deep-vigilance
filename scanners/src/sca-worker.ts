// SCA Worker — Software Composition Analysis
// Pipeline: clone repo -> resolve dependencies -> match vulnerabilities ->
// run supply-chain checks -> run license scan -> deduplicate -> store findings
import { Worker, Job } from 'bullmq';
import { logger } from './utils/logger.js';
import { startScan, storeFinding, completeScan, failScan } from './utils/scan-store.js';
import { assertScannableUrl } from './utils/ssrf.js';
import { resolveDependencies, flattenNodes } from './sca/dependency-resolver.js';
import { matchVulnerabilities, type ScaVulnerability } from './sca/vulnerability-matcher.js';
import { scanSupplyChain, type SupplyChainFinding } from './sast/supply-chain-scanner.js';
import { scanLicenses, type LicenseFinding } from './sast/license-scanner.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execFile } from 'child_process';
import { promisify } from 'util';

const pexecFile = promisify(execFile);

// ---------------------------------------------------------------------------
// Git clone (same pattern as sast-worker)
// ---------------------------------------------------------------------------

async function cloneRepo(repoUrl: string, branch?: string, token?: string): Promise<string> {
  await assertScannableUrl(repoUrl);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sca-repo-'));
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
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

// ---------------------------------------------------------------------------
// Job processor
// ---------------------------------------------------------------------------

async function processJob(job: Job): Promise<Record<string, unknown>> {
  const { scanId, projectId, options, organizationId } = job.data;
  logger.info({ scanId, repoUrl: options?.repoUrl, targetPath: options?.targetPath }, 'SCA Worker: Processing job');
  await job.updateProgress(5);

  let clonedDir: string | null = null;
  try {
    await startScan(scanId);

    // Determine source path
    let targetPath: string;
    if (options?.repoUrl) {
      logger.info({ scanId, repoUrl: options.repoUrl, branch: options.branch }, 'SCA: Cloning git repository');
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
    // Phase 1: Resolve dependencies
    // -----------------------------------------------------------------------
    logger.info({ scanId }, 'SCA Phase 1: Resolving dependencies');
    const depTree = await resolveDependencies(targetPath);
    const allDeps = flattenNodes(depTree.rootDependencies);
    logger.info({ scanId, totalDeps: depTree.totalCount, ecosystems: depTree.ecosystems }, 'SCA: Dependencies resolved');
    await job.updateProgress(25);

    // -----------------------------------------------------------------------
    // Phase 2: Match vulnerabilities via OSV.dev
    // -----------------------------------------------------------------------
    logger.info({ scanId, depCount: allDeps.length }, 'SCA Phase 2: Matching vulnerabilities');
    let vulnerabilities: ScaVulnerability[] = [];
    try {
      vulnerabilities = await matchVulnerabilities(allDeps);
    } catch (err) {
      logger.error({ scanId, err }, 'SCA: Vulnerability matching failed (continuing with other checks)');
    }
    logger.info({ scanId, vulnCount: vulnerabilities.length }, 'SCA: Vulnerability matching complete');
    await job.updateProgress(50);

    // -----------------------------------------------------------------------
    // Phase 3: Supply chain checks (typosquatting, dep confusion, protestware)
    // -----------------------------------------------------------------------
    logger.info({ scanId }, 'SCA Phase 3: Supply chain checks');
    let supplyChainFindings: SupplyChainFinding[] = [];
    try {
      const scResult = scanSupplyChain(targetPath);
      supplyChainFindings = scResult.findings;
    } catch (err) {
      logger.error({ scanId, err }, 'SCA: Supply chain scan failed (continuing)');
    }
    logger.info({ scanId, scFindings: supplyChainFindings.length }, 'SCA: Supply chain checks complete');
    await job.updateProgress(70);

    // -----------------------------------------------------------------------
    // Phase 4: License compliance scan
    // -----------------------------------------------------------------------
    logger.info({ scanId }, 'SCA Phase 4: License compliance scan');
    let licenseFindings: LicenseFinding[] = [];
    try {
      const licResult = scanLicenses(targetPath);
      licenseFindings = licResult.findings;
    } catch (err) {
      logger.error({ scanId, err }, 'SCA: License scan failed (continuing)');
    }
    logger.info({ scanId, licFindings: licenseFindings.length }, 'SCA: License scan complete');
    await job.updateProgress(85);

    // -----------------------------------------------------------------------
    // Phase 5: Deduplicate and store findings
    // -----------------------------------------------------------------------
    logger.info({ scanId }, 'SCA Phase 5: Storing findings');

    // Track stored finding keys to deduplicate across phases
    const storedKeys = new Set<string>();
    let totalStoredFindings = 0;

    // Store vulnerability findings
    for (const vuln of vulnerabilities) {
      const findingKey = `vuln:${vuln.id}:${vuln.packageName}@${vuln.packageVersion}`;
      if (storedKeys.has(findingKey)) continue;
      storedKeys.add(findingKey);

      try {
        const cveIds = vuln.aliases.filter(a => a.startsWith('CVE-'));
        await storeFinding(scanId, projectId, organizationId, {
          type: 'sca',
          title: `${vuln.severity.toUpperCase()}: ${vuln.summary || vuln.id} in ${vuln.packageName}@${vuln.packageVersion}`,
          description: vuln.details || vuln.summary || `Known vulnerability ${vuln.id} affects ${vuln.packageName} version ${vuln.packageVersion}.`,
          severity: vuln.severity,
          cweId: vuln.nvdCwes?.[0] || undefined,
          owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
          cvssScore: (vuln.nvdCvssScore ?? vuln.cvssScore) || undefined,
          cvssVector: vuln.nvdCvssVector || undefined,
          cveId: cveIds[0] || undefined,
          epssScore: vuln.epssScore ?? undefined,
          kevMatch: vuln.isKev,
          ruleId: vuln.id,
          ruleName: `OSV-${vuln.id}`,
          recommendation: vuln.fixedVersion
            ? `Upgrade ${vuln.packageName} to version ${vuln.fixedVersion} or later.`
            : `Review vulnerability ${vuln.id} and consider replacing ${vuln.packageName} or applying a workaround.`,
          metadata: {
            category: 'vulnerability',
            osvId: vuln.id,
            cveIds,
            aliases: vuln.aliases,
            packageName: vuln.packageName,
            packageVersion: vuln.packageVersion,
            ecosystem: vuln.ecosystem,
            fixedVersion: vuln.fixedVersion,
            references: vuln.references,
            epssPercentile: vuln.epssPercentile,
            nvdCwes: vuln.nvdCwes,
          },
        });
        totalStoredFindings++;
      } catch (e) {
        logger.error({ scanId, vulnId: vuln.id, err: e }, 'SCA: Failed to store vulnerability finding');
      }
    }

    // Store supply chain findings
    for (const scf of supplyChainFindings) {
      const findingKey = `sc:${scf.ruleId}:${scf.packageName}@${scf.declaredVersion}`;
      if (storedKeys.has(findingKey)) continue;
      storedKeys.add(findingKey);

      try {
        await storeFinding(scanId, projectId, organizationId, {
          type: 'sca',
          title: scf.title,
          description: scf.description,
          severity: scf.severity,
          filePath: scf.filePath,
          lineNumber: scf.lineNumber,
          ruleId: scf.ruleId,
          ruleName: scf.ruleId,
          recommendation: scf.recommendation,
          metadata: {
            category: 'supply-chain',
            subcategory: scf.category,
            packageName: scf.packageName,
            declaredVersion: scf.declaredVersion,
            ecosystem: scf.ecosystem,
            matchDetail: scf.matchDetail,
            references: scf.references,
          },
        });
        totalStoredFindings++;
      } catch (e) {
        logger.error({ scanId, ruleId: scf.ruleId, err: e }, 'SCA: Failed to store supply chain finding');
      }
    }

    // Store license findings
    for (const lf of licenseFindings) {
      const findingKey = `lic:${lf.ruleId}:${lf.dependencyName}@${lf.dependencyVersion}`;
      if (storedKeys.has(findingKey)) continue;
      storedKeys.add(findingKey);

      try {
        await storeFinding(scanId, projectId, organizationId, {
          type: 'sca',
          title: lf.title,
          description: lf.description,
          severity: lf.severity,
          filePath: lf.filePath,
          lineNumber: lf.lineNumber,
          ruleId: lf.ruleId,
          ruleName: lf.ruleId,
          recommendation: lf.recommendation,
          metadata: {
            category: 'license',
            subcategory: lf.category,
            dependencyName: lf.dependencyName,
            dependencyVersion: lf.dependencyVersion,
            licenseId: lf.licenseId,
            licenseName: lf.licenseName,
          },
        });
        totalStoredFindings++;
      } catch (e) {
        logger.error({ scanId, ruleId: lf.ruleId, err: e }, 'SCA: Failed to store license finding');
      }
    }

    await job.updateProgress(95);

    // Build result summary
    const allFindings = [
      ...vulnerabilities.map(v => ({ severity: v.severity, category: 'vulnerability' })),
      ...supplyChainFindings.map(f => ({ severity: f.severity, category: 'supply-chain' })),
      ...licenseFindings.map(f => ({ severity: f.severity, category: 'license' })),
    ];

    const result = {
      scanId,
      projectId,
      organizationId,
      totalFindings: totalStoredFindings,
      severityBreakdown: {
        critical: allFindings.filter(f => f.severity === 'critical').length,
        high: allFindings.filter(f => f.severity === 'high').length,
        medium: allFindings.filter(f => f.severity === 'medium').length,
        low: allFindings.filter(f => f.severity === 'low').length,
        info: allFindings.filter(f => f.severity === 'info').length,
      },
      categoryBreakdown: {
        vulnerability: vulnerabilities.length,
        supplyChain: supplyChainFindings.length,
        license: licenseFindings.length,
      },
      dependencies: {
        total: depTree.totalCount,
        ecosystems: depTree.ecosystems,
        manifests: depTree.manifests.length,
      },
    };

    await completeScan(scanId, totalStoredFindings, {
      totalDependencies: depTree.totalCount,
      ecosystems: depTree.ecosystems,
      vulnerabilities: vulnerabilities.length,
      supplyChainIssues: supplyChainFindings.length,
      licenseIssues: licenseFindings.length,
    });

    await job.updateProgress(100);
    logger.info({ scanId, totalFindings: totalStoredFindings }, 'SCA: Scan complete');
    return result;
  } catch (err) {
    logger.error({ scanId, err }, 'SCA: Scan failed');
    try { await failScan(scanId, err instanceof Error ? err.message : String(err)); } catch { /* best effort */ }
    throw err;
  } finally {
    if (clonedDir) {
      try { fs.rmSync(clonedDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  }
}

// ---------------------------------------------------------------------------
// Worker startup
// ---------------------------------------------------------------------------

const worker = new Worker('sca-scan', processJob, {
  connection,
  concurrency: 4,
  limiter: { max: 10, duration: 60000 },
});

worker.on('completed', (j) => logger.info({ jobId: j?.id }, 'SCA job completed'));
worker.on('failed', (j, e) => logger.error({ jobId: j?.id, err: e.message }, 'SCA job failed'));
logger.info('SCA Worker running');
