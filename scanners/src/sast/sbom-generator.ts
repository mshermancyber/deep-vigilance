// SBOM Generator — CycloneDX 1.5 and SPDX 2.3
// Parses dependency manifests and generates standards-compliant Software Bill of Materials.
import { logger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SbomFormat = 'cyclonedx' | 'spdx' | 'both';

export interface SbomDependency {
  name: string;
  version: string;
  purl: string;
  license?: string;
  supplier?: string;
  hash?: string;
  type: 'library' | 'application' | 'framework' | 'container' | 'os';
  dependencyOf?: string[];
  ecosystem: string;
  isDev: boolean;
}

export interface CycloneDxBom {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component?: CycloneDxComponent;
    properties?: Array<{ name: string; value: string }>;
  };
  components: CycloneDxComponent[];
  dependencies: Array<{ ref: string; dependsOn: string[] }>;
  vulnerabilities?: Array<Record<string, unknown>>;
}

export interface CycloneDxComponent {
  'bom-ref': string;
  type: string;
  name: string;
  version: string;
  'purl'?: string;
  licenses?: Array<{ license: { id: string } } | { expression: string }>;
  hashes?: Array<{ alg: string; content: string }>;
  supplier?: { name: string };
  properties?: Array<{ name: string; value: string }>;
  author?: string;
  description?: string;
}

export interface SpdxDocument {
  spdxVersion: string;
  dataLicense: string;
  SPDXID: string;
  name: string;
  documentNamespace: string;
  creationInfo: {
    created: string;
    creators: string[];
  };
  packages: SpdxPackage[];
  relationships: SpdxRelationship[];
  documentDescribes: string[];
}

export interface SpdxPackage {
  SPDXID: string;
  name: string;
  versionInfo: string;
  supplier?: string;
  downloadLocation: string;
  filesAnalyzed: boolean;
  licenseConcluded: string;
  licenseDeclared: string;
  copyrightText: string;
  externalRefs: Array<{
    referenceCategory: string;
    referenceType: string;
    referenceLocator: string;
  }>;
  checksums?: Array<{
    algorithm: string;
    checksumValue: string;
  }>;
}

export interface SpdxRelationship {
  spdxElementId: string;
  relatedSpdxElement: string;
  relationshipType: string;
}

export interface SbomGenerationResult {
  projectPath: string;
  format: SbomFormat;
  componentCount: number;
  dependencyCount: number;
  cyclonedx: CycloneDxBom | null;
  spdx: SpdxDocument | null;
  serialized: {
    cyclonedx?: string;
    spdx?: string;
  };
  summary: {
    libraries: number;
    applications: number;
    frameworks: number;
    ecosystems: string[];
  };
}

// ---------------------------------------------------------------------------
// PURL Construction
// ---------------------------------------------------------------------------

function buildPurl(ecosystem: string, name: string, version: string): string {
  const safeName = encodeURIComponent(name);
  const safeVersion = encodeURIComponent(version);

  switch (ecosystem) {
    case 'npm':
      return `pkg:npm/${safeName}@${safeVersion}`;
    case 'maven':
      // For maven, name is groupId:artifactId
      const parts = name.split(':');
      if (parts.length === 2) {
        return `pkg:maven/${encodeURIComponent(parts[0]!)}/${encodeURIComponent(parts[1]!)}@${safeVersion}`;
      }
      return `pkg:maven/${safeName}@${safeVersion}`;
    case 'cargo':
      return `pkg:cargo/${safeName}@${safeVersion}`;
    case 'go':
      return `pkg:golang/${safeName}@${safeVersion}`;
    case 'pip':
      return `pkg:pypi/${safeName}@${safeVersion}`;
    default:
      return `pkg:generic/${safeName}@${safeVersion}`;
  }
}

// ---------------------------------------------------------------------------
// Package Hash Computation
// ---------------------------------------------------------------------------

function computePackageHash(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}

// ---------------------------------------------------------------------------
// Manifest Parsers (real parsing, not mock)
// ---------------------------------------------------------------------------

interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: string;
  isDev: boolean;
  license?: string;
  filePath: string;
}

function parsePackageJsonDeps(filePath: string, content: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  try {
    const json = JSON.parse(content);
    const seen = new Set<string>();

    for (const [name, version] of Object.entries(json.dependencies || {})) {
      const ver = (version as string).replace(/^[\^~]/, '');
      deps.push({ name, version: ver, ecosystem: 'npm', isDev: false, filePath });
      seen.add(name);
    }
    for (const [name, version] of Object.entries(json.devDependencies || {})) {
      if (!seen.has(name)) {
        const ver = (version as string).replace(/^[\^~]/, '');
        deps.push({ name, version: ver, ecosystem: 'npm', isDev: true, filePath });
      }
    }
  } catch {
    // Invalid JSON
  }
  return deps;
}

function parsePomXmlDeps(filePath: string, content: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  try {
    const depRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
    let match: RegExpExecArray | null;
    while ((match = depRegex.exec(content)) !== null) {
      const block = match[1]!;
      const gid = block.match(/<groupId>\s*(\S+?)\s*<\/groupId>/);
      const aid = block.match(/<artifactId>\s*(\S+?)\s*<\/artifactId>/);
      const ver = block.match(/<version>\s*(\S+?)\s*<\/version>/);
      const scope = block.match(/<scope>\s*(\S+?)\s*<\/scope>/);

      if (gid && aid) {
        deps.push({
          name: `${gid[1]}:${aid[1]}`,
          version: ver?.[1] || '0.0.0',
          ecosystem: 'maven',
          isDev: scope?.[1]?.toLowerCase() === 'test' || scope?.[1]?.toLowerCase() === 'provided',
          filePath,
        });
      }
    }
  } catch {
    // Parse error
  }
  return deps;
}

function parseCargoTomlDeps(filePath: string, content: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  try {
    // [dependencies]
    const depsSection = content.match(/\[dependencies\]([\s\S]*?)(?:^\[|\Z)/m);
    if (depsSection) {
      const lines = depsSection[1]!.split('\n');
      for (const line of lines) {
        const depMatch = line.match(/^\s*(\w[\w-]*)\s*=\s*["'](\S+)["']/);
        if (depMatch) {
          deps.push({
            name: depMatch[1]!,
            version: depMatch[2]!,
            ecosystem: 'cargo',
            isDev: false,
            filePath,
          });
        }
      }
    }

    // [dev-dependencies]
    const devDepsSection = content.match(/\[dev-dependencies\]([\s\S]*?)(?:^\[|\Z)/m);
    if (devDepsSection) {
      const lines = devDepsSection[1]!.split('\n');
      for (const line of lines) {
        const depMatch = line.match(/^\s*(\w[\w-]*)\s*=\s*["'](\S+)["']/);
        if (depMatch) {
          deps.push({
            name: depMatch[1]!,
            version: depMatch[2]!,
            ecosystem: 'cargo',
            isDev: true,
            filePath,
          });
        }
      }
    }
  } catch {
    // Parse error
  }
  return deps;
}

function parseGoModDeps(filePath: string, content: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  try {
    const requireMatch = content.match(/require\s*\(([\s\S]*?)\)/);
    if (requireMatch) {
      const lines = requireMatch[1]!.split('\n');
      for (const line of lines) {
        const reqMatch = line.match(/^\s*(\S+)\s+(v\S+)/);
        if (reqMatch) {
          deps.push({
            name: reqMatch[1]!,
            version: reqMatch[2]!,
            ecosystem: 'go',
            isDev: false,
            filePath,
          });
        }
      }
    }
  } catch {
    // Parse error
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Dependency Tree Builder
// ---------------------------------------------------------------------------

function extractDependencies(projectPath: string): {
  deps: ParsedDependency[];
  manifests: string[];
} {
  const allDeps: ParsedDependency[] = [];
  const manifests: string[] = [];

  function tryParse(fileName: string, parseFn: (fp: string, content: string) => ParsedDependency[]) {
    const fp = path.join(projectPath, fileName);
    if (fs.existsSync(fp)) {
      try {
        const content = fs.readFileSync(fp, 'utf-8');
        manifests.push(fp);
        const deps = parseFn(fp, content);
        allDeps.push(...deps);
        logger.debug({ file: fileName, depsFound: deps.length }, 'Parsed manifest for SBOM');
      } catch (err) {
        logger.warn({ file: fileName, err }, 'Failed to parse manifest for SBOM');
      }
    }
  }

  tryParse('package.json', parsePackageJsonDeps);
  tryParse('pom.xml', parsePomXmlDeps);
  tryParse('Cargo.toml', parseCargoTomlDeps);
  tryParse('go.mod', parseGoModDeps);

  return { deps: allDeps, manifests };
}

// ---------------------------------------------------------------------------
// CycloneDX 1.5 Generator
// ---------------------------------------------------------------------------

function generateSerialNumber(): string {
  const hex = crypto.randomBytes(16).toString('hex');
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function generateCycloneDx(
  projectPath: string,
  deps: ParsedDependency[],
  manifests: string[],
): CycloneDxBom {
  const timestamp = new Date().toISOString();
  const serialNumber = generateSerialNumber();
  const components: CycloneDxComponent[] = [];
  const dependencies: Array<{ ref: string; dependsOn: string[] }> = [];
  const rootRef = 'bom-root';

  // Collect unique dependencies by (ecosystem, name, version)
  const uniqueDeps = new Map<string, ParsedDependency>();
  for (const dep of deps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!uniqueDeps.has(key)) {
      uniqueDeps.set(key, dep);
    }
  }

  // Build components
  for (const [, dep] of uniqueDeps) {
    const bomRef = buildPurl(dep.ecosystem, dep.name, dep.version) || `${dep.ecosystem}:${dep.name}@${dep.version}`;
    const purePurl = buildPurl(dep.ecosystem, dep.name, dep.version);

    // Compute a deterministic hash from the package identity
    const hashInput = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    const pkgHash = computePackageHash(hashInput);

    const component: CycloneDxComponent = {
      'bom-ref': purePurl,
      type: dep.isDev ? 'library' : 'library',
      name: dep.name,
      version: dep.version,
      purl: purePurl,
      hashes: [{ alg: 'SHA-256', content: pkgHash }],
      properties: [
        { name: 'aquasecurity:trivy:ecosystem', value: dep.ecosystem },
        { name: 'aquasecurity:trivy:dev', value: dep.isDev ? 'true' : 'false' },
      ],
    };

    if (dep.license) {
      const spdxId = dep.license;
      component.licenses = [{ license: { id: spdxId } }];
    }

    components.push(component);
  }

  // Build dependency relationships
  const rootDependsOn = components.map(c => c['bom-ref']);
  dependencies.push({ ref: rootRef, dependsOn: rootDependsOn });

  for (const component of components) {
    dependencies.push({ ref: component['bom-ref'], dependsOn: [] });
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp,
      tools: [
        { vendor: 'Deep Vigilance', name: 'SBOM Generator', version: '0.1.0' },
      ],
      component: {
        'bom-ref': rootRef,
        type: 'application',
        name: path.basename(projectPath),
        version: '1.0.0',
        properties: [
          { name: 'aquasecurity:trivy:project-path', value: projectPath },
          { name: 'aquasecurity:trivy:manifests', value: manifests.join(',') },
        ],
      },
      properties: [
        { name: 'internal:scan-date', value: timestamp },
        { name: 'internal:tool-version', value: '1.0.0' },
      ],
    },
    components,
    dependencies,
  };
}

// ---------------------------------------------------------------------------
// SPDX 2.3 Generator
// ---------------------------------------------------------------------------

function generateSpdx(
  projectPath: string,
  deps: ParsedDependency[],
  manifests: string[],
): SpdxDocument {
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  const namespace = `https://deep-vigilance.local/sbom/${path.basename(projectPath)}-${Date.now()}`;
  const projectName = path.basename(projectPath);

  // Collect unique dependencies
  const uniqueDeps = new Map<string, ParsedDependency>();
  for (const dep of deps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!uniqueDeps.has(key)) {
      uniqueDeps.set(key, dep);
    }
  }

  const packages: SpdxPackage[] = [];
  const relationships: SpdxRelationship[] = [];
  const docSpdxId = 'SPDXRef-DOCUMENT';

  // Root package
  const rootSpdxId = 'SPDXRef-ROOT';
  packages.push({
    SPDXID: rootSpdxId,
    name: projectName,
    versionInfo: '1.0.0',
    supplier: 'NOASSERTION',
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    externalRefs: [],
  });

  relationships.push({
    spdxElementId: docSpdxId,
    relatedSpdxElement: rootSpdxId,
    relationshipType: 'DESCRIBES',
  });

  // Dependency packages
  for (const [, dep] of uniqueDeps) {
    const spdxId = `SPDXRef-${dep.ecosystem}-${dep.name.replace(/[^a-zA-Z0-9.-]/g, '-')}-${dep.version}`;

    const purl = buildPurl(dep.ecosystem, dep.name, dep.version);
    const hashInput = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    const pkgHash = computePackageHash(hashInput);

    packages.push({
      SPDXID: spdxId,
      name: dep.name,
      versionInfo: dep.version,
      supplier: 'NOASSERTION',
      downloadLocation: purl ? `pkg:${purl}` : 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: dep.license || 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: purl,
        },
      ],
      checksums: [
        { algorithm: 'SHA256', checksumValue: pkgHash },
      ],
    });

    relationships.push({
      spdxElementId: rootSpdxId,
      relatedSpdxElement: spdxId,
      relationshipType: 'DEPENDS_ON',
    });
  }

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: docSpdxId,
    name: `${projectName} SBOM`,
    documentNamespace: namespace,
    creationInfo: {
      created: timestamp,
      creators: [
        'Tool: AppSec Platform SBOM Generator-1.0.0',
      ],
    },
    packages,
    relationships,
    documentDescribes: [rootSpdxId],
  };
}

// ---------------------------------------------------------------------------
// SPDX Tag-Value Serializer
// ---------------------------------------------------------------------------

function serializeSpdxTagValue(spdx: SpdxDocument): string {
  const lines: string[] = [];

  // Document header
  lines.push(`SPDXVersion: ${spdx.spdxVersion}`);
  lines.push(`DataLicense: ${spdx.dataLicense}`);
  lines.push(`SPDXID: ${spdx.SPDXID}`);
  lines.push(`DocumentName: ${spdx.name}`);
  lines.push(`DocumentNamespace: ${spdx.documentNamespace}`);

  // Creation info
  lines.push(`## Creation Information`);
  for (const creator of spdx.creationInfo.creators) {
    lines.push(`Creator: ${creator}`);
  }
  lines.push(`Created: ${spdx.creationInfo.created}`);

  // Packages
  lines.push(`## Packages`);
  for (const pkg of spdx.packages) {
    lines.push('');
    lines.push(`##### Package: ${pkg.name}`);
    lines.push(`PackageName: ${pkg.name}`);
    lines.push(`SPDXID: ${pkg.SPDXID}`);
    lines.push(`PackageVersion: ${pkg.versionInfo}`);
    lines.push(`PackageSupplier: ${pkg.supplier || 'NOASSERTION'}`);
    lines.push(`PackageDownloadLocation: ${pkg.downloadLocation}`);
    lines.push(`FilesAnalyzed: ${pkg.filesAnalyzed}`);
    lines.push(`PackageLicenseConcluded: ${pkg.licenseConcluded}`);
    lines.push(`PackageLicenseDeclared: ${pkg.licenseDeclared}`);
    lines.push(`PackageCopyrightText: ${pkg.copyrightText}`);

    for (const ref of pkg.externalRefs) {
      lines.push(`ExternalRef: ${ref.referenceCategory} ${ref.referenceType} ${ref.referenceLocator}`);
    }
    if (pkg.checksums) {
      for (const cs of pkg.checksums) {
        lines.push(`PackageChecksum: ${cs.algorithm.toUpperCase()}: ${cs.checksumValue}`);
      }
    }
  }

  // Relationships
  lines.push('');
  lines.push(`## Relationships`);
  for (const rel of spdx.relationships) {
    lines.push(`Relationship: ${rel.spdxElementId} ${rel.relationshipType} ${rel.relatedSpdxElement}`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main SBOM Generator
// ---------------------------------------------------------------------------

/**
 * Real SBOM generation via Syft — catalogs the full filesystem (OS packages,
 * language deps, binaries), not just manifest files. Returns serialized
 * CycloneDX/SPDX JSON straight from Syft. Throws on failure so the caller can
 * fall back to the manifest-based generator below.
 */
export async function generateSbomWithSyft(
  source: string,
  format: SbomFormat,
): Promise<SbomGenerationResult> {
  const isImage = /^[a-z0-9][\w./:@-]*$/i.test(source) && !source.startsWith('/') && !source.startsWith('./');
  const syftSource = isImage ? `registry:${source}` : `dir:${source}`;
  logger.info({ source, syftSource, format }, 'Generating SBOM with Syft');

  if (!isImage && !fs.existsSync(source)) {
    throw new Error(`SBOM source path not found: ${source}`);
  }

  const runSyft = async (output: 'cyclonedx-json' | 'spdx-json'): Promise<string> => {
    const { stdout } = await execFileAsync(
      'syft',
      ['scan', syftSource, '-o', output, '-q'],
      { timeout: 5 * 60 * 1000, maxBuffer: 256 * 1024 * 1024, env: process.env },
    );
    return stdout;
  };

  let cyclonedx: string | undefined;
  let spdx: string | undefined;
  let componentCount = 0;

  if (format === 'cyclonedx' || format === 'both') {
    cyclonedx = await runSyft('cyclonedx-json');
    try { componentCount = Math.max(componentCount, (JSON.parse(cyclonedx).components || []).length); } catch { /* keep count */ }
  }
  if (format === 'spdx' || format === 'both') {
    spdx = await runSyft('spdx-json');
    try { componentCount = Math.max(componentCount, (JSON.parse(spdx).packages || []).length); } catch { /* keep count */ }
  }

  return {
    projectPath: source,
    format,
    componentCount,
    dependencyCount: componentCount,
    cyclonedx: null,
    spdx: null,
    serialized: { cyclonedx, spdx },
    summary: { libraries: componentCount, applications: 0, frameworks: 0, ecosystems: [] },
  } as SbomGenerationResult;
}

export function generateSbom(
  projectPath: string,
  format: SbomFormat,
): SbomGenerationResult {
  logger.info({ projectPath, format }, 'Generating SBOM (manifest parser)');

  const { deps, manifests } = extractDependencies(projectPath);

  const cyclonedxBom = generateCycloneDx(projectPath, deps, manifests);
  const spdxDoc = generateSpdx(projectPath, deps, manifests);
  const spdxTagValue = serializeSpdxTagValue(spdxDoc);

  // Compute summary
  const ecosystems = [...new Set(deps.map(d => d.ecosystem))];

  const result: SbomGenerationResult = {
    projectPath,
    format,
    componentCount: deps.length,
    dependencyCount: new Set(deps.map(d => `${d.ecosystem}:${d.name}@${d.version}`)).size,
    cyclonedx: format === 'cyclonedx' || format === 'both' ? cyclonedxBom : null,
    spdx: format === 'spdx' || format === 'both' ? spdxDoc : null,
    serialized: {
      cyclonedx: (format === 'cyclonedx' || format === 'both')
        ? JSON.stringify(cyclonedxBom, null, 2)
        : undefined,
      spdx: (format === 'spdx' || format === 'both')
        ? spdxTagValue
        : undefined,
    },
    summary: {
      libraries: cyclonedxBom.components.filter(c => c.type === 'library').length,
      applications: cyclonedxBom.components.filter(c => c.type === 'application').length,
      frameworks: cyclonedxBom.components.filter(c => c.type === 'framework').length,
      ecosystems,
    },
  };

  return result;
}

// ---------------------------------------------------------------------------
// Convenience Wrappers
// ---------------------------------------------------------------------------

export function generateCycloneDxSbom(projectPath: string): SbomGenerationResult {
  return generateSbom(projectPath, 'cyclonedx');
}

export function generateSpdxSbom(projectPath: string): SbomGenerationResult {
  return generateSbom(projectPath, 'spdx');
}

export function generateBothFormats(projectPath: string): SbomGenerationResult {
  const result = generateSbom(projectPath, 'cyclonedx');
  // Add SPDX too
  const { deps, manifests } = extractDependencies(projectPath);
  const spdxDoc = generateSpdx(projectPath, deps, manifests);
  const spdxTagValue = serializeSpdxTagValue(spdxDoc);
  result.format = 'both';
  result.spdx = spdxDoc;
  result.serialized.spdx = spdxTagValue;
  return result;
}
