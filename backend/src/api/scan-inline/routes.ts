import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';
import { logger } from '../../core/logging/logger.js';

// The scanner engine is a SEPARATE package (@appsec/scanners) that is NOT
// present in the backend's build context, so it must never be resolved at
// compile time. Types are kept local (the shapes we use), and the modules are
// imported at runtime via non-literal specifiers so tsc doesn't try to resolve
// them. In dev/prod the package is mounted into node_modules; if it's absent
// the endpoint returns 503 and the server still boots.
type SecretFinding = Record<string, any>;
type ScaVulnerability = Record<string, any>;
type DependencyNode = Record<string, any>;

interface ScanEngine {
  getLanguage: (filename: string) => string | null;
  scanFileWithAllRules: (filename: string, content: string, language: string) => any[];
  scanFileForSecrets: (filename: string, content: string) => SecretFinding[];
  matchVulnerabilities: (deps: DependencyNode[]) => Promise<ScaVulnerability[]>;
  buildPurl: (ecosystem: string, name: string, version: string) => string;
}

let enginePromise: Promise<ScanEngine | null> | null = null;

// Non-literal specifier keeps tsc from resolving @appsec/scanners at build time.
const dynImport = (spec: string): Promise<any> => import(/* @vite-ignore */ spec);

function loadEngine(): Promise<ScanEngine | null> {
  if (!enginePromise) {
    enginePromise = (async () => {
      try {
        const base = '@appsec/scanners/src';
        const [sastEngine, allRules, secrets, scaMatch, scaDeps] = await Promise.all([
          dynImport(`${base}/sast/engine.js`),
          dynImport(`${base}/sast/all-rules.js`),
          dynImport(`${base}/sast/secrets-engine.js`),
          dynImport(`${base}/sca/vulnerability-matcher.js`),
          dynImport(`${base}/sca/dependency-resolver.js`),
        ]);
        return {
          getLanguage: sastEngine.getLanguage,
          scanFileWithAllRules: allRules.scanFileWithAllRules,
          scanFileForSecrets: secrets.scanFileForSecrets,
          matchVulnerabilities: scaMatch.matchVulnerabilities,
          buildPurl: scaDeps.buildPurl,
        };
      } catch (err) {
        logger.error({ err }, 'Inline scan engine (@appsec/scanners) unavailable in this container');
        return null;
      }
    })();
  }
  return enginePromise;
}

const inlineRateLimiter = rateLimit({
  windowMs: 60_000, // 1 minute
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.headers['x-api-key'] as string) || req.ip || 'unknown',
  message: { error: 'Too many requests. Rate limit: 120/minute.' },
});

// ---------------------------------------------------------------------------
// Severity mapping for secret types
// ---------------------------------------------------------------------------

function mapSecretSeverity(type: string): string {
  const t = type.toLowerCase();

  // Critical: private keys, connection strings with passwords
  if (
    /\b(?:rsa|ec|dsa|openssh|ssh\s+dsa|ecdsa|ed25519)\s+private\s+key\b/i.test(t) ||
    /\bpgp\s+private\s+key\b/i.test(t) ||
    /\bpkcs8\b/i.test(t) ||
    /\bencrypted\s+private\s+key\b/i.test(t) ||
    /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|sql\s*server|couchdb|cassandra|neo4j|elasticsearch|database)\s+connection\s+string\b/i.test(t) ||
    /\bazure\s+connection\s+string\b/i.test(t)
  ) {
    return 'critical';
  }

  // High: API keys, tokens, webhook URLs
  if (
    /\b(?:aws|github|gitlab|bitbucket|google|openai|anthropic|stripe|slack|discord|telegram|heroku|twilio|sendgrid|mailgun|datadog|pagerduty|linear|notion|figma|dropbox|shopify|facebook|twitter|microsoft)\b/i.test(t) &&
    !/\bconnection\s+string\b/i.test(t)
  ) {
    return 'high';
  }
  if (
    /\b(?:bot\s+token|webhook\s+url|oauth|access\s+key|secret\s+key|restricted\s+key|publishable\s+key|app\s+credentials|installation\s+token|refresh\s+token|deploy\s+token|feed\s+token|trigger\s+token|app\s+password|client\s+secret|service\s+account|sas\s+token|storage\s+key|cosmos|service\s+bus)\b/i.test(t)
  ) {
    return 'high';
  }
  if (
    /\bapi\s+(?:key|secret|token)\b/i.test(t) &&
    !/\bgeneric\b/i.test(t)
  ) {
    return 'high';
  }

  // Medium: generic passwords, tokens, certificates
  if (
    /\bpassword\s+assignment\b/i.test(t) ||
    /\bpassword\s+property\b/i.test(t) ||
    /\bpassword\s+variable\b/i.test(t) ||
    /\bpassword\s+in\s+(?:config|code|file)\b/i.test(t) ||
    /\bjwt\b/i.test(t) ||
    /\bbearer\s+token\b/i.test(t) ||
    /\bx\.509\s+certificate\b/i.test(t) ||
    /\bcertificate\s+chain\b/i.test(t) ||
    /\bcertificate\s+signing\b/i.test(t) ||
    /\bcertificate\s+file\b/i.test(t) ||
    /\bgeneric\s+(?:secret|password|token)\b/i.test(t) ||
    /\btoken\s+(?:variable|in\s+(?:header|query))\b/i.test(t) ||
    /\bapi\s+key\s+in\s+query\b/i.test(t) ||
    /\bdatabase\s+(?:url|path)\b/i.test(t) ||
    /\bsqlite\b/i.test(t) ||
    /\bprivate\s+key\s+(?:header|string|value)/i.test(t)
  ) {
    return 'medium';
  }

  // Low: public keys, references
  if (
    /\bssh\s+public\s+key\b/i.test(t) ||
    /\bpublic\s+key\b/i.test(t) ||
    /\bcertificate\s+reference\b/i.test(t) ||
    /\bdummy\b/i.test(t) ||
    /\bexample\b/i.test(t) ||
    /\btest\s+(?:key|secret|token)\b/i.test(t)
  ) {
    return 'low';
  }

  return 'high';
}

export const scanInlineRouter = Router();

const inlineScanSchema = z.object({
  filename: z.string().min(1).max(500),
  content: z.string().min(1).max(5_000_000),
  language: z.string().max(50).optional(),
});

// ---------------------------------------------------------------------------
// Manifest filenames we recognise for SCA
// ---------------------------------------------------------------------------

const MANIFEST_EXTS: Record<string, string> = {
  'package.json': 'npm',
  'requirements.txt': 'pypi',
  'go.mod': 'go',
  'pom.xml': 'maven',
  Gemfile: 'rubygems',
  'Cargo.toml': 'cargo',
  'composer.json': 'composer',
};

function isManifest(filename: string): boolean {
  const base = filename.split('/').pop() || filename;
  return base in MANIFEST_EXTS;
}

// ---------------------------------------------------------------------------
// Inline manifest parser — extracts direct dependency list from a single
// manifest file content.
// ---------------------------------------------------------------------------

interface ParsedDep {
  name: string;
  version: string;
  ecosystem: string;
  line?: number;
}

function parseDependenciesFromContent(filename: string, content: string): ParsedDep[] {
  const base = filename.split('/').pop() || filename;
  const ecosystem = MANIFEST_EXTS[base];
  if (!ecosystem) return [];

  switch (base) {
    case 'package.json':
      return parsePackageJson(content, ecosystem);
    case 'requirements.txt':
      return parseRequirementsTxt(content, ecosystem);
    case 'go.mod':
      return parseGoMod(content, ecosystem);
    case 'pom.xml':
      return parsePomXml(content, ecosystem);
    case 'Gemfile':
      return parseGemfile(content, ecosystem);
    case 'Cargo.toml':
      return parseCargoToml(content, ecosystem);
    case 'composer.json':
      return parseComposerJson(content, ecosystem);
    default:
      return [];
  }
}

// --- package.json -----------------------------------------------------------

function parsePackageJson(content: string, ecosystem: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  try {
    const pkg = JSON.parse(content);
    const allDeps: Record<string, string> = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
    };
    for (const [name, versionRange] of Object.entries(allDeps)) {
      const version = (versionRange as string).replace(/^[~^>=<\s]+/, '');
      deps.push({ name, version, ecosystem });
    }
  } catch {
    // invalid JSON — skip
  }
  return deps;
}

// --- requirements.txt -------------------------------------------------------

function parseRequirementsTxt(content: string, ecosystem: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;

    // name==version, name>=version, name~=version, name!=version, name<=version
    const match = line.match(/^([a-zA-Z0-9_.-]+)\s*(?:\[.*?\])?\s*(?:([=!<>~]=?)\s*(.+?))?(?:\s*;.*)?(?:\s*#.*)?$/);
    if (!match) continue;

    const name = match[1]!;
    const version = match[3] ? match[3].split(',')[0]!.trim() : 'unknown';
    deps.push({ name, version, ecosystem, line: i + 1 });
  }
  return deps;
}

// --- go.mod -----------------------------------------------------------------

function parseGoMod(content: string, ecosystem: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const lines = content.split('\n');
  let inRequireBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();

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
      deps.push({ name: singleReq[1]!, version: singleReq[2]!, ecosystem, line: i + 1 });
      continue;
    }

    // Inside require block: module/path v1.2.3
    if (inRequireBlock) {
      const blockReq = line.match(/^(\S+)\s+(v\S+)/);
      if (blockReq) {
        deps.push({ name: blockReq[1]!, version: blockReq[2]!, ecosystem, line: i + 1 });
      }
    }
  }
  return deps;
}

// --- pom.xml ----------------------------------------------------------------

function parsePomXml(content: string, ecosystem: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  // Extract <dependencies> block(s)
  const depBlockMatches = content.matchAll(/<dependencies>([\s\S]*?)<\/dependencies>/g);
  for (const blockMatch of depBlockMatches) {
    const depBlock = blockMatch[1]!;
    const depRegex = /<dependency>\s*<groupId>(.*?)<\/groupId>\s*<artifactId>(.*?)<\/artifactId>\s*(?:<version>(.*?)<\/version>)?\s*(?:<scope>.*?<\/scope>\s*)?(?:<type>.*?<\/type>\s*)?(?:<optional>.*?<\/optional>\s*)?(?:<exclusions>[\s\S]*?<\/exclusions>\s*)?<\/dependency>/g;
    let match: RegExpExecArray | null;
    while ((match = depRegex.exec(depBlock)) !== null) {
      const groupId = match[1]!.trim();
      const artifactId = match[2]!.trim();
      const version = match[3]?.trim() || 'managed';
      deps.push({ name: `${groupId}:${artifactId}`, version, ecosystem });
    }
  }
  return deps;
}

// --- Gemfile ----------------------------------------------------------------

function parseGemfile(content: string, ecosystem: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!line || line.startsWith('#')) continue;

    // gem 'name', '~> 1.2.3'  or  gem 'name', '1.2.3'  or just gem 'name'
    const match = line.match(/^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"](?:~>?\s*)?([^'"]+)['"])?/);
    if (match) {
      deps.push({
        name: match[1]!,
        version: match[2] || 'unknown',
        ecosystem,
        line: i + 1,
      });
    }
  }
  return deps;
}

// --- Cargo.toml -------------------------------------------------------------

function parseCargoToml(content: string, ecosystem: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  const lines = content.split('\n');
  let inDeps = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const trimmed = line.trim();

    if (/^\[dependencies\]/.test(trimmed)) {
      inDeps = true;
      continue;
    }
    // Exit on next section header
    if (inDeps && /^\[.*\]/.test(trimmed)) {
      inDeps = false;
      continue;
    }
    if (!inDeps) continue;
    if (!trimmed || trimmed.startsWith('#')) continue;

    // name = "version"  or  name = { version = "1.0", ... }
    const simpleMatch = trimmed.match(/^(\S+)\s*=\s*"([^"]+)"/);
    if (simpleMatch) {
      deps.push({ name: simpleMatch[1]!, version: simpleMatch[2]!, ecosystem, line: i + 1 });
      continue;
    }
    // name = { version = "1.0", features = [...] }
    const tableMatch = trimmed.match(/^(\S+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"[^}]*\}/);
    if (tableMatch) {
      deps.push({ name: tableMatch[1]!, version: tableMatch[2]!, ecosystem, line: i + 1 });
    }
  }
  return deps;
}

// --- composer.json ----------------------------------------------------------

function parseComposerJson(content: string, ecosystem: string): ParsedDep[] {
  const deps: ParsedDep[] = [];
  try {
    const composer = JSON.parse(content);
    const allDeps: Record<string, string> = {
      ...(composer.require || {}),
      ...(composer['require-dev'] || {}),
    };
    for (const [name, versionRange] of Object.entries(allDeps)) {
      // Composer versions like "^1.2", "~1.2.3", "1.2.3"
      const version =
        typeof versionRange === 'string'
          ? versionRange.replace(/^[~^>=<\s]+/, '')
          : String(versionRange);
      deps.push({ name, version, ecosystem });
    }
  } catch {
    // invalid JSON — skip
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Map a SastFinding to the inline API response shape */
function toInlineFinding(f: {
  ruleId: string;
  ruleName: string;
  severity: string;
  cweId: string;
  lineNumber: number;
  description: string;
  codeSnippet: string;
}) {
  return {
    ruleId: f.ruleId,
    ruleName: f.ruleName,
    severity: f.severity,
    cweId: f.cweId,
    line: f.lineNumber,
    message: f.description,
    snippet: f.codeSnippet,
    engine: 'sast' as const,
  } satisfies InlineFinding;
}

/** Map a SecretFinding to the inline API response shape */
function secretToInlineFinding(f: SecretFinding): InlineFinding {
  return {
    ruleId: f.patternId,
    ruleName: f.type,
    severity: mapSecretSeverity(f.type),
    cweId: 'CWE-798',
    line: f.line,
    message: f.recommendation,
    snippet: f.secret,
    engine: 'secret',
  };
}

/** Map an ScaVulnerability to the inline API response shape */
function scaToInlineFinding(v: ScaVulnerability): InlineFinding {
  return {
    ruleId: v.id,
    ruleName: v.summary,
    severity: v.severity,
    cweId: v.nvdCwes?.[0] ?? '',
    line: 0,
    message: `${v.packageName}@${v.packageVersion}: ${v.summary}`,
    snippet: '',
    engine: 'sca',
  };
}

interface InlineFinding {
  ruleId: string;
  ruleName: string;
  severity: string;
  cweId: string;
  line: number;
  message: string;
  snippet: string;
  engine: 'sast' | 'sca' | 'secret';
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

scanInlineRouter.post('/inline', inlineRateLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const parsed = inlineScanSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid request', details: parsed.error.flatten() });
      return;
    }

    const { filename, content, language: providedLang } = parsed.data;

    const engine = await loadEngine();
    if (!engine) {
      res.status(503).json({ error: 'Inline scan engine unavailable in this deployment.' });
      return;
    }

    // Detect language from filename, or use the caller-provided language hint
    const language = providedLang || engine.getLanguage(filename);
    if (!language) {
      res.status(400).json({
        error: 'Could not determine language from filename. Provide a "language" field.',
      });
      return;
    }

    const startTime = performance.now();

    // --- SAST scan ---
    const rawFindings = engine.scanFileWithAllRules(filename, content, language);
    const findings: InlineFinding[] = rawFindings.map(toInlineFinding);

    // --- Secrets scan ---
    const secretFindings = engine.scanFileForSecrets(filename, content);
    const secretInlineFindings = secretFindings.map(secretToInlineFinding);
    findings.push(...secretInlineFindings);

    // --- SCA manifest scan ---
    if (isManifest(filename)) {
      const parsedDeps = parseDependenciesFromContent(filename, content);
      if (parsedDeps.length > 0) {
        const depNodes: DependencyNode[] = parsedDeps.map((d) => ({
          name: d.name,
          version: d.version,
          ecosystem: d.ecosystem,
          isDev: false,
          children: [],
          purl: engine.buildPurl(d.ecosystem, d.name, d.version),
        }));

        try {
          const vulns = await engine.matchVulnerabilities(depNodes);
          const scaFindings = vulns.map(scaToInlineFinding);
          findings.push(...scaFindings);
        } catch {
          // SCA lookup failed — surface SAST results without SCA enrichment
        }
      }
    }

    const durationMs = Math.round(performance.now() - startTime);

    res.json({ findings, durationMs });
  } catch (err) {
    next(err);
  }
});
