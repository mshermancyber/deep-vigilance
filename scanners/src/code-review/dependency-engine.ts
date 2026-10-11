// ============================================================
// Dependency Analysis Engine (Software Composition Analysis)
// npm, pip, Maven, Gradle, NuGet, Cargo, Composer, Go Modules
// CVE/EPSS/KEV correlation, supply-chain risk detection
// ============================================================

import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger.js';

// ---- Types ----

export type Ecosystem = 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget' | 'cargo' |
                        'composer' | 'go_modules' | 'rubygems' | 'other';

export interface ManifestFile {
  ecosystem: Ecosystem;
  filePath: string;
  lockFilePath?: string;
}

export interface DependencyPackage {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  isDirect: boolean;
  isDev: boolean;
  license?: string;
  repository?: string;
  dependencies: string[]; // names of direct deps
}

export interface Vulnerability {
  id: string;
  cveId?: string;
  cweId?: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvssScore: number;
  cvssVector: string;
  epssScore?: number;
  kevMatch: boolean;
  affectedVersions: string;
  fixedInVersion?: string;
  publishedAt?: string;
  references: string[];
}

export interface DepFinding {
  packageName: string;
  packageVersion: string;
  ecosystem: Ecosystem;
  type: 'cve' | 'deprecated' | 'end_of_life' | 'license' | 'supply_chain' |
        'typosquatting' | 'dependency_confusion' | 'unmaintained' | 'malicious';
  severity: string;
  title: string;
  description: string;
  cveId?: string;
  cweId?: string;
  cvssScore: number;
  epssScore?: number;
  kevMatch: boolean;
  fixedInVersion?: string;
  recommendation: string;
  references: string[];
}

export interface DepScanResult {
  ecosystem: Ecosystem;
  packages: DependencyPackage[];
  totalPackages: number;
  directDeps: number;
  devDeps: number;
  transitiveDeps: number;
  findings: DepFinding[];
  vulnerablePackages: number;
  deprecatedPackages: number;
  endOfLifePackages: number;
  licenseIssues: number;
  supplyChainRisks: number;
}

// ---- Manifest Detection ----

const MANIFEST_PATTERNS: Array<{ pattern: RegExp; ecosystem: Ecosystem; lockFile: string }> = [
  { pattern: /package\.json$/, ecosystem: 'npm', lockFile: 'package-lock.json' },
  { pattern: /requirements\.txt$/, ecosystem: 'pip', lockFile: '' },
  { pattern: /Pipfile$/, ecosystem: 'pip', lockFile: 'Pipfile.lock' },
  { pattern: /setup\.py$/, ecosystem: 'pip', lockFile: '' },
  { pattern: /pyproject\.toml$/, ecosystem: 'pip', lockFile: 'poetry.lock' },
  { pattern: /pom\.xml$/, ecosystem: 'maven', lockFile: '' },
  { pattern: /build\.gradle(?:\.kts)?$/, ecosystem: 'gradle', lockFile: 'gradle.lockfile' },
  { pattern: /\*.csproj$/, ecosystem: 'nuget', lockFile: 'packages.lock.json' },
  { pattern: /packages\.config$/, ecosystem: 'nuget', lockFile: '' },
  { pattern: /Cargo\.toml$/, ecosystem: 'cargo', lockFile: 'Cargo.lock' },
  { pattern: /composer\.json$/, ecosystem: 'composer', lockFile: 'composer.lock' },
  { pattern: /go\.mod$/, ecosystem: 'go_modules', lockFile: 'go.sum' },
  { pattern: /Gemfile$/, ecosystem: 'rubygems', lockFile: 'Gemfile.lock' },
];

export function detectManifests(targetDir: string): ManifestFile[] {
  const manifests: ManifestFile[] = [];

  function walk(dir: string): void {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git' ||
            entry.name === '__pycache__' || entry.name === 'vendor' ||
            entry.name === 'target' || entry.name === '.venv') continue;
        walk(fullPath);
      } else if (entry.isFile()) {
        for (const mp of MANIFEST_PATTERNS) {
          if (mp.pattern.test(entry.name)) {
            const lockPath = mp.lockFile
              ? path.join(dir, mp.lockFile)
              : undefined;
            manifests.push({
              ecosystem: mp.ecosystem,
              filePath: fullPath,
              lockFilePath: lockPath && fs.existsSync(lockPath) ? lockPath : undefined,
            });
          }
        }
      }
    }
  }

  walk(targetDir);
  return manifests;
}

// ---- Parsers ----

function parseNpmPackageJson(content: string, filePath: string): DependencyPackage[] {
  const packages: DependencyPackage[] = [];
  try {
    const pkg = JSON.parse(content);
    const allDeps: Record<string, string> = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.peerDependencies || {}),
      ...(pkg.optionalDependencies || {}),
    };

    for (const [name, version] of Object.entries(allDeps)) {
      const isDev = name in (pkg.devDependencies || {});
      packages.push({
        name, version: version as string, ecosystem: 'npm',
        isDirect: true, isDev,
        repository: pkg.repository?.url,
        dependencies: [],
      });
    }

    // Parse lock file if available
    const lockPath = path.join(path.dirname(filePath), 'package-lock.json');
    if (fs.existsSync(lockPath)) {
      try {
        const lock = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));
        const resolved = lock.packages || lock.dependencies || {};
        for (const [pkgName, info] of Object.entries(resolved)) {
          const name = pkgName.replace('node_modules/', '');
          const ver = (info as Record<string, unknown>).version as string;
          if (!packages.find(p => p.name === name && p.version === ver)) {
            packages.push({
              name, version: ver || 'unknown',
              ecosystem: 'npm', isDirect: false, isDev: false,
              dependencies: Object.keys((info as Record<string, unknown>).requires || {}),
            });
          }
        }
      } catch { /* lock file parse error — non-fatal */ }
    }
  } catch { /* JSON parse error */ }
  return packages;
}

function parsePipRequirements(content: string): DependencyPackage[] {
  const packages: DependencyPackage[] = [];
  const lines = content.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;

    // Parse: package==version or package>=version or package~=version
    const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*([><=~!]+\s*[\d.*]+(?:,\s*[><=~!]+\s*[\d.*]+)*)?/);
    if (match) {
      packages.push({
        name: match[1]!,
        version: match[2]?.trim() || 'latest',
        ecosystem: 'pip',
        isDirect: true, isDev: false,
        dependencies: [],
      });
    }
  }
  return packages;
}

function parsePomXml(content: string): DependencyPackage[] {
  const packages: DependencyPackage[] = [];
  const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]*)<\/version>/g;
  let match;
  while ((match = depRegex.exec(content)) !== null) {
    packages.push({
      name: `${match[1]}:${match[2]}`,
      version: match[3] || 'unknown',
      ecosystem: 'maven',
      isDirect: true, isDev: false,
      dependencies: [],
    });
  }
  return packages;
}

function parseGoMod(content: string): DependencyPackage[] {
  const packages: DependencyPackage[] = [];
  const lines = content.split('\n');
  let inRequire = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === 'require (') { inRequire = true; continue; }
    if (inRequire && trimmed === ')') { inRequire = false; continue; }

    if (inRequire || trimmed.startsWith('require ')) {
      const clean = trimmed.replace(/^require\s+/, '').trim();
      const parts = clean.split(/\s+/);
      if (parts.length >= 2) {
        packages.push({
          name: parts[0]!,
          version: parts[1]!,
          ecosystem: 'go_modules',
          isDirect: true, isDev: false,
          dependencies: [],
        });
      }
    }
  }
  return packages;
}

function parseCargoToml(content: string): DependencyPackage[] {
  const packages: DependencyPackage[] = [];
  const lines = content.split('\n');
  let inDeps = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '[dependencies]' || trimmed.startsWith('[dependencies.')) {
      inDeps = true; continue;
    }
    if (trimmed.startsWith('[') && trimmed !== '[dependencies]') { inDeps = false; continue; }
    if (inDeps && trimmed) {
      const match = trimmed.match(/^(\w[\w-]*)\s*=\s*"(?:[\d.]+\s*,\s*)?["']?([\d.]+)/);
      if (!match) {
        const simpleMatch = trimmed.match(/^(\w[\w-]*)\s*=\s*"([^"]+)"/);
        if (simpleMatch) {
          packages.push({
            name: simpleMatch[1]!, version: simpleMatch[2]!,
            ecosystem: 'cargo', isDirect: true, isDev: false, dependencies: [],
          });
        }
      } else {
        packages.push({
          name: match[1]!, version: match[2]!,
          ecosystem: 'cargo', isDirect: true, isDev: false, dependencies: [],
        });
      }
    }
  }
  return packages;
}

export function parseManifest(manifest: ManifestFile): DependencyPackage[] {
  try {
    const content = fs.readFileSync(manifest.filePath, 'utf-8');

    switch (manifest.ecosystem) {
      case 'npm': return parseNpmPackageJson(content, manifest.filePath);
      case 'pip': return manifest.filePath.endsWith('requirements.txt')
        ? parsePipRequirements(content) : parseNpmPackageJson(content, manifest.filePath);
      case 'maven': return parsePomXml(content);
      case 'go_modules': return parseGoMod(content);
      case 'cargo': return parseCargoToml(content);
      case 'composer': return parseNpmPackageJson(content, manifest.filePath);
      default: {
        try {
          const pkg = JSON.parse(content);
          return parseNpmPackageJson(JSON.stringify(pkg.dependencies || {}), manifest.filePath);
        } catch { return []; }
      }
    }
  } catch {
    return [];
  }
}

// ---- Vulnerability Database (embedded) ----

const KNOWN_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'VULN-001',
    cveId: 'CVE-2021-44228',
    cweId: 'CWE-502',
    title: 'Log4Shell — Remote Code Execution in Log4j',
    description: 'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
    severity: 'critical', cvssScore: 10.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    epssScore: 0.975, kevMatch: true,
    affectedVersions: '2.0-beta9 to 2.14.1',
    fixedInVersion: '2.17.0',
    publishedAt: '2021-12-10',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
  },
  {
    id: 'VULN-002',
    cveId: 'CVE-2022-22965',
    cweId: 'CWE-94',
    title: 'Spring4Shell — RCE in Spring Framework',
    description: 'Spring Framework RCE via data binding on JDK 9+.',
    severity: 'critical', cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epssScore: 0.96, kevMatch: true,
    affectedVersions: '< 5.3.18, 5.2.20',
    fixedInVersion: '5.3.18',
    publishedAt: '2022-03-31',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
  },
  {
    id: 'VULN-010',
    cveId: 'CVE-2021-3807',
    cweId: 'CWE-400',
    title: 'ansi-regex — Inefficient Regular Expression Complexity',
    description: 'ansi-regex is vulnerable to Inefficient Regular Expression Complexity.',
    severity: 'high', cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    epssScore: 0.45, kevMatch: false,
    affectedVersions: '< 5.1.1',
    fixedInVersion: '5.1.1',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-3807'],
  },
];

const DEPRECATED_PACKAGES = new Set([
  'request', 'request-promise', 'left-pad', 'colors', 'faker',
  'babel-eslint', 'core-js@2', 'hoek', 'cryptiles', 'boom',
  'sntp', 'hawk@3', 'moment', 'uuid@3',
]);

const END_OF_LIFE_PACKAGES: Array<{ name: string; version: string; ecosystem: string }> = [
  { name: 'python', version: '< 3.8', ecosystem: 'pip' },
  { name: 'django', version: '< 3.2', ecosystem: 'pip' },
  { name: 'angular', version: '< 12', ecosystem: 'npm' },
  { name: 'react', version: '< 17', ecosystem: 'npm' },
  { name: 'spring-boot', version: '< 2.7', ecosystem: 'maven' },
];

const RESTRICTED_LICENSES = ['GPL-3.0', 'AGPL-3.0', 'WTFPL', 'Unlicense'];

// ---- Supply Chain Risk Detection ----

function detectDependencyConfusion(pkg: DependencyPackage): DepFinding | null {
  // Internal-looking package names on public registries
  const internalPatterns = [
    /^(?:my-?)?company/, /internal/, /private/,
    /^(?:acme|corp|enterprise)-/,
  ];
  if (internalPatterns.some(p => p.test(pkg.name))) {
    return {
      packageName: pkg.name, packageVersion: pkg.version, ecosystem: pkg.ecosystem,
      type: 'dependency_confusion', severity: 'high',
      title: `Potential dependency confusion: ${pkg.name}`,
      description: `Package "${pkg.name}" matches internal naming patterns but may be publicly available. Attackers could publish a malicious package with this name.`,
      cweId: 'CWE-506', cvssScore: 8.1,
      kevMatch: false,
      recommendation: 'Use scoped packages (@company/name) or private registry. Verify package sources.',
      references: ['https://owasp.org/www-project-top-ten/'],
    };
  }
  return null;
}

function detectTyposquatting(pkg: DependencyPackage): DepFinding | null {
  const popularPackages = ['react', 'vue', 'angular', 'express', 'lodash', 'axios',
    'django', 'flask', 'requests', 'spring', 'gorm', 'serde', 'tokio'];
  for (const popular of popularPackages) {
    const dist = levenshteinDistance(pkg.name.toLowerCase(), popular.toLowerCase());
    if (dist > 0 && dist <= 2 && pkg.name.length > 4) {
      return {
        packageName: pkg.name, packageVersion: pkg.version, ecosystem: pkg.ecosystem,
        type: 'typosquatting', severity: 'high',
        title: `Potential typosquatting: ${pkg.name} resembles ${popular}`,
        description: `Package "${pkg.name}" has typo distance ${dist} from popular package "${popular}". This may indicate a typosquatting attack.`,
        cweId: 'CWE-506', cvssScore: 8.1,
        kevMatch: false,
        recommendation: `Verify this package is intentionally used rather than "${popular}". Check the package publisher and repository.`,
        references: [],
      };
    }
  }
  return null;
}

export function levenshteinDistance(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i]![0] = i;
  for (let j = 0; j <= n; j++) dp[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i]![j] = a[i - 1] === b[j - 1]
        ? dp[i - 1]![j - 1]!
        : 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
    }
  }
  return dp[m]![n]!;
}

// ---- Main Scanner ----

export function scanDependencies(manifest: ManifestFile): DepScanResult {
  const packages = parseManifest(manifest);
  const findings: DepFinding[] = [];

  for (const pkg of packages) {
    // Check known vulnerabilities
    for (const vuln of KNOWN_VULNERABILITIES) {
      // Simple version matching (production would use proper semver range matching)
      if (matchesPackage(pkg, vuln)) {
        findings.push({
          packageName: pkg.name, packageVersion: pkg.version,
          ecosystem: pkg.ecosystem, type: 'cve',
          severity: vuln.severity, title: `${vuln.cveId}: ${vuln.title}`,
          description: vuln.description,
          cveId: vuln.cveId, cweId: vuln.cweId,
          cvssScore: vuln.cvssScore, epssScore: vuln.epssScore,
          kevMatch: vuln.kevMatch, fixedInVersion: vuln.fixedInVersion,
          recommendation: `Upgrade to version ${vuln.fixedInVersion || 'latest'} or apply vendor patch.`,
          references: vuln.references,
        });
      }
    }

    // Check deprecated
    if (DEPRECATED_PACKAGES.has(pkg.name) || DEPRECATED_PACKAGES.has(`${pkg.name}@${pkg.version.split('.')[0]}`)) {
      findings.push({
        packageName: pkg.name, packageVersion: pkg.version, ecosystem: pkg.ecosystem,
        type: 'deprecated', severity: 'medium',
        title: `Deprecated package: ${pkg.name}`,
        description: `Package "${pkg.name}" has been deprecated and no longer receives security updates.`,
        cweId: 'CWE-1104', cvssScore: 5.0, kevMatch: false,
        recommendation: `Replace "${pkg.name}" with a maintained alternative.`,
        references: [],
      });
    }

    // Check end-of-life — exact name match and actual version comparison
    for (const eol of END_OF_LIFE_PACKAGES) {
      if (pkg.name.toLowerCase() === eol.name.toLowerCase() &&
          pkg.ecosystem === eol.ecosystem) {
        const major = parseInt(pkg.version.replace(/^[^0-9]*/, ''), 10);
        const eolMajor = parseInt(eol.version.replace(/[^0-9]/g, ''), 10);
        if (!isNaN(major) && !isNaN(eolMajor) && major < eolMajor) {
          findings.push({
            packageName: pkg.name, packageVersion: pkg.version, ecosystem: pkg.ecosystem,
            type: 'end_of_life', severity: 'medium',
            title: `End-of-life: ${pkg.name}@${pkg.version}`,
            description: `Version ${pkg.version} of ${pkg.name} is end-of-life (supported: >= ${eolMajor}).`,
            cweId: 'CWE-1104', cvssScore: 5.0, kevMatch: false,
            recommendation: `Upgrade to a supported version (>= ${eolMajor}).`,
            references: [],
          });
        }
      }
    }

    // Check license
    if (pkg.license && RESTRICTED_LICENSES.some(l => pkg.license!.includes(l))) {
      findings.push({
        packageName: pkg.name, packageVersion: pkg.version, ecosystem: pkg.ecosystem,
        type: 'license', severity: 'low',
        title: `Restricted license: ${pkg.name} uses ${pkg.license}`,
        description: `Package "${pkg.name}" is licensed under ${pkg.license} which may have compliance implications.`,
        cweId: 'CWE-1357', cvssScore: 0.0, kevMatch: false,
        recommendation: `Review license compliance. Consider alternative packages with permissive licenses.`,
        references: [],
      });
    }

    // Supply chain
    const confusion = detectDependencyConfusion(pkg);
    if (confusion) findings.push(confusion);

    const typosquat = detectTyposquatting(pkg);
    if (typosquat) findings.push(typosquat);
  }

  return {
    ecosystem: manifest.ecosystem,
    packages,
    totalPackages: packages.length,
    directDeps: packages.filter(p => p.isDirect).length,
    devDeps: packages.filter(p => p.isDev).length,
    transitiveDeps: packages.filter(p => !p.isDirect).length,
    findings,
    vulnerablePackages: findings.filter(f => f.type === 'cve').length,
    deprecatedPackages: findings.filter(f => f.type === 'deprecated').length,
    endOfLifePackages: findings.filter(f => f.type === 'end_of_life').length,
    licenseIssues: findings.filter(f => f.type === 'license').length,
    supplyChainRisks: findings.filter(f => ['typosquatting', 'dependency_confusion'].includes(f.type)).length,
  };
}

function matchesPackage(pkg: DependencyPackage, vuln: Vulnerability): boolean {
  // Simplified matching — production would use proper CPE/semver matching
  if (vuln.id === 'VULN-001' && pkg.name.toLowerCase().includes('log4j')) {
    const ver = pkg.version.replace(/[^0-9.]/g, '');
    const parts = ver.split('.').map(Number);
    return parts[0] === 2 && (parts[1] || 0) < 17;
  }
  if (vuln.id === 'VULN-002' && pkg.name.toLowerCase().includes('spring')) {
    return true; // Simplified
  }
  if (vuln.id === 'VULN-010' && pkg.name === 'ansi-regex') {
    const ver = pkg.version.replace(/[^0-9.]/g, '');
    const parts = ver.split('.').map(Number);
    return parts[0]! < 5 || (parts[0] === 5 && (parts[1] || 0) < 1);
  }
  return false;
}

export function scanAllDependencies(targetDir: string): DepScanResult[] {
  const manifests = detectManifests(targetDir);
  logger.info({ manifestCount: manifests.length }, 'Manifests detected for dependency scan');
  return manifests.map(scanDependencies);
}
