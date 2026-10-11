// Transitive Dependency Resolver
// Reads package manifests across ecosystems (npm, pip, Maven, Go) and builds
// a full dependency tree with Package URL (purl) identifiers.
import { logger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DependencyNode {
  name: string;
  version: string;
  ecosystem: string;
  isDev: boolean;
  children: DependencyNode[];
  purl: string;
}

export interface DependencyTree {
  projectPath: string;
  rootDependencies: DependencyNode[];
  totalCount: number;
  ecosystems: string[];
  manifests: string[];
}

// ---------------------------------------------------------------------------
// PURL generation — https://github.com/package-url/purl-spec
// ---------------------------------------------------------------------------

function buildPurl(ecosystem: string, name: string, version: string): string {
  const typeMap: Record<string, string> = {
    npm: 'npm',
    pypi: 'pypi',
    maven: 'maven',
    go: 'golang',
  };
  const purlType = typeMap[ecosystem] || ecosystem;

  if (ecosystem === 'maven' && name.includes(':')) {
    const [group, artifact] = name.split(':');
    return `pkg:${purlType}/${encodeURIComponent(group!)}/${encodeURIComponent(artifact!)}@${encodeURIComponent(version)}`;
  }

  // npm scoped packages: @scope/name -> pkg:npm/%40scope/name@version
  if (ecosystem === 'npm' && name.startsWith('@')) {
    const [scope, pkg] = name.split('/');
    return `pkg:${purlType}/${encodeURIComponent(scope!)}/${encodeURIComponent(pkg!)}@${encodeURIComponent(version)}`;
  }

  return `pkg:${purlType}/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

// ---------------------------------------------------------------------------
// npm: package.json + package-lock.json
// ---------------------------------------------------------------------------

interface NpmLockDep {
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  dependencies?: Record<string, NpmLockDep>;
  requires?: Record<string, string>;
}

interface NpmLockfileV2 {
  lockfileVersion?: number;
  packages?: Record<string, {
    version?: string;
    resolved?: string;
    dev?: boolean;
    devOptional?: boolean;
    dependencies?: Record<string, string>;
  }>;
  dependencies?: Record<string, NpmLockDep>;
}

function resolveNpmV1Dependencies(
  lockDeps: Record<string, NpmLockDep>,
  isDev: boolean,
  visited: Set<string>,
): DependencyNode[] {
  const nodes: DependencyNode[] = [];
  for (const [name, info] of Object.entries(lockDeps)) {
    const key = `${name}@${info.version}`;
    if (visited.has(key)) continue;
    visited.add(key);

    const devFlag = isDev || (info.dev === true);
    const children = info.dependencies
      ? resolveNpmV1Dependencies(info.dependencies, devFlag, visited)
      : [];

    nodes.push({
      name,
      version: info.version,
      ecosystem: 'npm',
      isDev: devFlag,
      children,
      purl: buildPurl('npm', name, info.version),
    });
  }
  return nodes;
}

function resolveNpmV2Packages(
  packages: NonNullable<NpmLockfileV2['packages']>,
): DependencyNode[] {
  // v2/v3 lockfile: packages keyed by path ("node_modules/lodash", "node_modules/@scope/foo")
  // Build a flat list first, then assemble parent-child relationships from nested node_modules paths.
  const nodeMap = new Map<string, DependencyNode>();
  const childrenMap = new Map<string, string[]>(); // parent path -> child paths

  const sortedPaths = Object.keys(packages)
    .filter(p => p !== '' && p.startsWith('node_modules/'))
    .sort();

  for (const pkgPath of sortedPaths) {
    const info = packages[pkgPath]!;
    // Extract name from the last node_modules/ segment
    const lastNm = pkgPath.lastIndexOf('node_modules/');
    const name = pkgPath.slice(lastNm + 'node_modules/'.length);
    const version = info.version || '0.0.0';
    const isDev = info.dev === true || info.devOptional === true;

    const node: DependencyNode = {
      name,
      version,
      ecosystem: 'npm',
      isDev,
      children: [],
      purl: buildPurl('npm', name, version),
    };
    nodeMap.set(pkgPath, node);

    // Find parent path
    const parentPath = pkgPath.slice(0, lastNm > 0 ? lastNm - 1 : 0);
    if (!childrenMap.has(parentPath)) childrenMap.set(parentPath, []);
    childrenMap.get(parentPath)!.push(pkgPath);
  }

  // Assemble children
  for (const [parentPath, childPaths] of childrenMap) {
    const parentNode = nodeMap.get(parentPath);
    if (parentNode) {
      for (const cp of childPaths) {
        const child = nodeMap.get(cp);
        if (child) parentNode.children.push(child);
      }
    }
  }

  // Root dependencies are directly under node_modules/ (no nested node_modules in path)
  const roots: DependencyNode[] = [];
  for (const [pkgPath, node] of nodeMap) {
    const segments = pkgPath.split('node_modules/').filter(Boolean);
    if (segments.length === 1) {
      roots.push(node);
    }
  }

  return roots;
}

function resolveNpm(projectPath: string): DependencyNode[] {
  const pkgJsonPath = path.join(projectPath, 'package.json');
  const lockPath = path.join(projectPath, 'package-lock.json');

  if (!fs.existsSync(pkgJsonPath)) return [];

  let pkgJson: Record<string, unknown>;
  try {
    pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
  } catch (e) {
    logger.warn({ path: pkgJsonPath, err: e }, 'SCA: Failed to parse package.json');
    return [];
  }

  // If we have a lockfile, use it for the full transitive tree
  if (fs.existsSync(lockPath)) {
    try {
      const lockData: NpmLockfileV2 = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));

      // v2/v3 lockfile format (packages key)
      if (lockData.packages && Object.keys(lockData.packages).length > 1) {
        logger.info({ path: lockPath }, 'SCA: Using npm lockfile v2/v3');
        return resolveNpmV2Packages(lockData.packages);
      }

      // v1 lockfile format (dependencies key)
      if (lockData.dependencies) {
        logger.info({ path: lockPath }, 'SCA: Using npm lockfile v1');
        const visited = new Set<string>();
        return resolveNpmV1Dependencies(lockData.dependencies, false, visited);
      }
    } catch (e) {
      logger.warn({ path: lockPath, err: e }, 'SCA: Failed to parse package-lock.json, falling back to package.json');
    }
  }

  // Fallback: parse package.json only (no transitive deps)
  const nodes: DependencyNode[] = [];
  const deps = (pkgJson.dependencies || {}) as Record<string, string>;
  const devDeps = (pkgJson.devDependencies || {}) as Record<string, string>;

  for (const [name, versionRange] of Object.entries(deps)) {
    const version = versionRange.replace(/^[~^>=<\s]+/, '');
    nodes.push({
      name,
      version,
      ecosystem: 'npm',
      isDev: false,
      children: [],
      purl: buildPurl('npm', name, version),
    });
  }

  for (const [name, versionRange] of Object.entries(devDeps)) {
    const version = versionRange.replace(/^[~^>=<\s]+/, '');
    nodes.push({
      name,
      version,
      ecosystem: 'npm',
      isDev: true,
      children: [],
      purl: buildPurl('npm', name, version),
    });
  }

  return nodes;
}

// ---------------------------------------------------------------------------
// Python: requirements.txt / Pipfile.lock
// ---------------------------------------------------------------------------

function resolveRequirementsTxt(filePath: string): DependencyNode[] {
  const nodes: DependencyNode[] = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) continue;

      // Handle: package==version, package>=version, package~=version, package (no version)
      const match = line.match(/^([a-zA-Z0-9_.-]+)\s*(?:\[.*?\])?\s*(?:([=!<>~]=?)\s*(.+?))?(?:\s*;.*)?(?:\s*#.*)?$/);
      if (!match) continue;

      const name = match[1]!;
      const version = match[3] ? match[3].split(',')[0]!.trim() : 'unknown';

      nodes.push({
        name,
        version,
        ecosystem: 'pypi',
        isDev: false,
        children: [],
        purl: buildPurl('pypi', name, version),
      });
    }
  } catch (e) {
    logger.warn({ path: filePath, err: e }, 'SCA: Failed to parse requirements.txt');
  }
  return nodes;
}

function resolvePipfileLock(filePath: string): DependencyNode[] {
  const nodes: DependencyNode[] = [];
  try {
    const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

    const processSection = (section: Record<string, { version?: string }>, isDev: boolean) => {
      for (const [name, info] of Object.entries(section)) {
        const version = info.version ? info.version.replace(/^==/, '') : 'unknown';
        nodes.push({
          name,
          version,
          ecosystem: 'pypi',
          isDev,
          children: [],
          purl: buildPurl('pypi', name, version),
        });
      }
    };

    if (content.default) processSection(content.default as Record<string, { version?: string }>, false);
    if (content.develop) processSection(content.develop as Record<string, { version?: string }>, true);
  } catch (e) {
    logger.warn({ path: filePath, err: e }, 'SCA: Failed to parse Pipfile.lock');
  }
  return nodes;
}

function resolvePython(projectPath: string): DependencyNode[] {
  const allNodes: DependencyNode[] = [];

  // Pipfile.lock (has full transitive deps)
  const pipfileLock = path.join(projectPath, 'Pipfile.lock');
  if (fs.existsSync(pipfileLock)) {
    allNodes.push(...resolvePipfileLock(pipfileLock));
    return allNodes;
  }

  // requirements.txt variants
  const reqFiles = [
    'requirements.txt',
    'requirements-dev.txt',
    'requirements_dev.txt',
    'requirements-test.txt',
    'dev-requirements.txt',
  ];

  for (const reqFile of reqFiles) {
    const reqPath = path.join(projectPath, reqFile);
    if (fs.existsSync(reqPath)) {
      const isDev = reqFile.includes('dev') || reqFile.includes('test');
      const nodes = resolveRequirementsTxt(reqPath);
      if (isDev) nodes.forEach(n => { n.isDev = true; });
      allNodes.push(...nodes);
    }
  }

  return allNodes;
}

// ---------------------------------------------------------------------------
// Maven: pom.xml
// ---------------------------------------------------------------------------

function resolveMaven(projectPath: string): DependencyNode[] {
  const pomPath = path.join(projectPath, 'pom.xml');
  if (!fs.existsSync(pomPath)) return [];

  const nodes: DependencyNode[] = [];
  try {
    const content = fs.readFileSync(pomPath, 'utf-8');

    // Simple XML parsing for dependency blocks — we avoid pulling in a full XML
    // parser to keep the scanner lightweight. This handles standard pom.xml layout.
    const depBlockMatch = content.match(/<dependencies>([\s\S]*?)<\/dependencies>/);
    if (!depBlockMatch) return [];

    const depBlock = depBlockMatch[1]!;
    const depRegex = /<dependency>\s*<groupId>(.*?)<\/groupId>\s*<artifactId>(.*?)<\/artifactId>\s*(?:<version>(.*?)<\/version>)?\s*(?:<scope>(.*?)<\/scope>)?\s*(?:<type>.*?<\/type>\s*)?(?:<optional>.*?<\/optional>\s*)?(?:<exclusions>[\s\S]*?<\/exclusions>\s*)?<\/dependency>/g;

    let match: RegExpExecArray | null;
    while ((match = depRegex.exec(depBlock)) !== null) {
      const groupId = match[1]!.trim();
      const artifactId = match[2]!.trim();
      const version = match[3]?.trim() || 'managed';
      const scope = match[4]?.trim() || 'compile';
      const name = `${groupId}:${artifactId}`;
      const isDev = scope === 'test' || scope === 'provided';

      nodes.push({
        name,
        version,
        ecosystem: 'maven',
        isDev,
        children: [],
        purl: buildPurl('maven', name, version),
      });
    }
  } catch (e) {
    logger.warn({ path: pomPath, err: e }, 'SCA: Failed to parse pom.xml');
  }
  return nodes;
}

// ---------------------------------------------------------------------------
// Go: go.mod / go.sum
// ---------------------------------------------------------------------------

function resolveGo(projectPath: string): DependencyNode[] {
  const goModPath = path.join(projectPath, 'go.mod');
  const goSumPath = path.join(projectPath, 'go.sum');

  const nodes: DependencyNode[] = [];
  const seenModules = new Set<string>();

  // Parse go.mod first (direct + indirect)
  if (fs.existsSync(goModPath)) {
    try {
      const content = fs.readFileSync(goModPath, 'utf-8');
      let inRequireBlock = false;

      for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();

        if (line.startsWith('require (') || line === 'require(') {
          inRequireBlock = true;
          continue;
        }
        if (inRequireBlock && line === ')') {
          inRequireBlock = false;
          continue;
        }

        // Single-line require: require module/path v1.2.3
        const singleReq = line.match(/^require\s+(\S+)\s+(v\S+)/);
        if (singleReq) {
          const name = singleReq[1]!;
          const version = singleReq[2]!;
          const key = `${name}@${version}`;
          if (!seenModules.has(key)) {
            seenModules.add(key);
            nodes.push({
              name,
              version,
              ecosystem: 'go',
              isDev: false,
              children: [],
              purl: buildPurl('go', name, version),
            });
          }
          continue;
        }

        // Inside require block: module/path v1.2.3 // indirect
        if (inRequireBlock) {
          const blockReq = line.match(/^(\S+)\s+(v\S+)/);
          if (blockReq) {
            const name = blockReq[1]!;
            const version = blockReq[2]!;
            const isIndirect = line.includes('// indirect');
            const key = `${name}@${version}`;
            if (!seenModules.has(key)) {
              seenModules.add(key);
              nodes.push({
                name,
                version,
                ecosystem: 'go',
                isDev: isIndirect, // treat indirect as dev-like
                children: [],
                purl: buildPurl('go', name, version),
              });
            }
          }
        }
      }
    } catch (e) {
      logger.warn({ path: goModPath, err: e }, 'SCA: Failed to parse go.mod');
    }
  }

  // Supplement with go.sum (may contain transitive deps not in go.mod)
  if (fs.existsSync(goSumPath)) {
    try {
      const content = fs.readFileSync(goSumPath, 'utf-8');
      for (const rawLine of content.split('\n')) {
        const line = rawLine.trim();
        if (!line) continue;

        // Format: module/path v1.2.3 h1:hash= or module/path v1.2.3/go.mod h1:hash=
        const match = line.match(/^(\S+)\s+(v\S+?)(?:\/go\.mod)?\s+/);
        if (!match) continue;

        const name = match[1]!;
        const version = match[2]!;
        const key = `${name}@${version}`;
        if (!seenModules.has(key)) {
          seenModules.add(key);
          nodes.push({
            name,
            version,
            ecosystem: 'go',
            isDev: false,
            children: [],
            purl: buildPurl('go', name, version),
          });
        }
      }
    } catch (e) {
      logger.warn({ path: goSumPath, err: e }, 'SCA: Failed to parse go.sum');
    }
  }

  return nodes;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function countNodes(nodes: DependencyNode[]): number {
  let count = 0;
  for (const node of nodes) {
    count += 1 + countNodes(node.children);
  }
  return count;
}

function flattenNodes(nodes: DependencyNode[]): DependencyNode[] {
  const result: DependencyNode[] = [];
  for (const node of nodes) {
    result.push(node);
    result.push(...flattenNodes(node.children));
  }
  return result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function findManifestDirs(root: string, maxDepth = 4): string[] {
  const dirs = new Set<string>();
  const SKIP = new Set(['node_modules', '.git', 'vendor', '__pycache__', '.tox', 'dist', 'build', 'target', '.venv', 'venv']);
  const MANIFEST_NAMES = new Set([
    'package.json', 'package-lock.json',
    'requirements.txt', 'Pipfile.lock',
    'pom.xml',
    'go.mod', 'go.sum',
  ]);

  function walk(dir: string, depth: number) {
    if (depth > maxDepth) return;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    let hasManifest = false;
    for (const e of entries) {
      if (e.isFile() && MANIFEST_NAMES.has(e.name)) { hasManifest = true; }
      if (e.isDirectory() && !SKIP.has(e.name) && !e.name.startsWith('.')) {
        walk(path.join(dir, e.name), depth + 1);
      }
    }
    if (hasManifest) dirs.add(dir);
  }

  walk(root, 0);
  return [...dirs];
}

function resolveDir(dirPath: string, ecosystems: Set<string>, manifests: string[]): DependencyNode[] {
  const deps: DependencyNode[] = [];

  const pkgJsonPath = path.join(dirPath, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    manifests.push(pkgJsonPath);
    const lockPath = path.join(dirPath, 'package-lock.json');
    if (fs.existsSync(lockPath)) manifests.push(lockPath);
    const npmDeps = resolveNpm(dirPath);
    if (npmDeps.length > 0) {
      ecosystems.add('npm');
      deps.push(...npmDeps);
    }
  }

  const pyDeps = resolvePython(dirPath);
  if (pyDeps.length > 0) {
    ecosystems.add('pypi');
    for (const f of ['requirements.txt', 'Pipfile.lock', 'requirements-dev.txt', 'requirements_dev.txt', 'requirements-test.txt', 'dev-requirements.txt']) {
      const p = path.join(dirPath, f);
      if (fs.existsSync(p)) manifests.push(p);
    }
    deps.push(...pyDeps);
  }

  const pomPath = path.join(dirPath, 'pom.xml');
  if (fs.existsSync(pomPath)) {
    manifests.push(pomPath);
    const mavenDeps = resolveMaven(dirPath);
    if (mavenDeps.length > 0) {
      ecosystems.add('maven');
      deps.push(...mavenDeps);
    }
  }

  const goModPath = path.join(dirPath, 'go.mod');
  const goSumPath = path.join(dirPath, 'go.sum');
  if (fs.existsSync(goModPath) || fs.existsSync(goSumPath)) {
    if (fs.existsSync(goModPath)) manifests.push(goModPath);
    if (fs.existsSync(goSumPath)) manifests.push(goSumPath);
    const goDeps = resolveGo(dirPath);
    if (goDeps.length > 0) {
      ecosystems.add('go');
      deps.push(...goDeps);
    }
  }

  return deps;
}

export async function resolveDependencies(projectPath: string): Promise<DependencyTree> {
  logger.info({ projectPath }, 'SCA: Resolving dependencies');

  const rootDependencies: DependencyNode[] = [];
  const ecosystems = new Set<string>();
  const manifests: string[] = [];

  const dirs = findManifestDirs(projectPath);
  logger.info({ projectPath, manifestDirs: dirs.length }, 'SCA: Found manifest directories');

  for (const dir of dirs) {
    const deps = resolveDir(dir, ecosystems, manifests);
    rootDependencies.push(...deps);
  }

  const totalCount = countNodes(rootDependencies);

  logger.info({
    projectPath,
    ecosystems: [...ecosystems],
    totalDeps: totalCount,
    manifests: manifests.length,
  }, 'SCA: Dependency resolution complete');

  return {
    projectPath,
    rootDependencies,
    totalCount,
    ecosystems: [...ecosystems],
    manifests,
  };
}

export { flattenNodes, countNodes, buildPurl };
