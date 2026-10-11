// M18-M21: Rule Ecosystem — Universal Importer, Rule Management, CI/CD Integration, Secrets Detection

import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import YAML from 'yaml';
import { query } from '../../core/db/pool.js';
import { logger } from '../../core/logging/logger.js';

const execFileAsync = promisify(execFile);
const RULE_CLONE_DIR = process.env.RULE_CLONE_DIR || '/tmp/appsec-rules';

// M18: Universal Rule Importer (25 golden sources)
export interface RuleSource {
  name: string;
  url: string;
  type: 'sast' | 'dast' | 'fuzz' | 'secret' | 'iac' | 'container' | 'mobile' | 'vulndb';
  orgId?: string;
  lastSynced?: string;
  ruleCount: number;
  enabled: boolean;
  schedule: string;
}

export const GOLDEN_RULE_SOURCES: RuleSource[] = [
  { name: 'semgrep-rules', url: 'https://github.com/semgrep/semgrep-rules', type: 'sast', ruleCount: 3000, enabled: true, schedule: 'daily' },
  { name: 'codeql', url: 'https://github.com/github/codeql', type: 'sast', ruleCount: 5000, enabled: true, schedule: 'daily' },
  { name: 'gitlab-sast-rules', url: 'https://gitlab.com/gitlab-org/security-products/sast-rules', type: 'sast', ruleCount: 500, enabled: true, schedule: 'daily' },
  { name: 'trailofbits-semgrep', url: 'https://github.com/trailofbits/semgrep-rules', type: 'sast', ruleCount: 200, enabled: true, schedule: 'daily' },
  { name: 'gosec', url: 'https://github.com/securego/gosec', type: 'sast', ruleCount: 40, enabled: true, schedule: 'weekly' },
  { name: 'bandit', url: 'https://github.com/PyCQA/bandit', type: 'sast', ruleCount: 70, enabled: true, schedule: 'weekly' },
  { name: 'spotbugs', url: 'https://github.com/spotbugs/spotbugs', type: 'sast', ruleCount: 400, enabled: true, schedule: 'weekly' },
  { name: 'find-sec-bugs', url: 'https://github.com/find-sec-bugs/find-sec-bugs', type: 'sast', ruleCount: 100, enabled: true, schedule: 'weekly' },
  { name: 'pmd', url: 'https://github.com/pmd/pmd', type: 'sast', ruleCount: 300, enabled: true, schedule: 'weekly' },
  { name: 'nuclei-templates', url: 'https://github.com/projectdiscovery/nuclei-templates', type: 'dast', ruleCount: 9000, enabled: true, schedule: 'daily' },
  { name: 'fuzzdb', url: 'https://github.com/fuzzdb-project/fuzzdb', type: 'fuzz', ruleCount: 10000, enabled: true, schedule: 'weekly' },
  { name: 'PayloadsAllTheThings', url: 'https://github.com/swisskyrepo/PayloadsAllTheThings', type: 'fuzz', ruleCount: 500, enabled: true, schedule: 'weekly' },
  { name: 'SecLists', url: 'https://github.com/danielmiessler/SecLists', type: 'fuzz', ruleCount: 100, enabled: true, schedule: 'weekly' },
  { name: 'gitleaks', url: 'https://github.com/gitleaks/gitleaks', type: 'secret', ruleCount: 200, enabled: true, schedule: 'daily' },
  { name: 'trufflehog', url: 'https://github.com/trufflesecurity/trufflehog', type: 'secret', ruleCount: 800, enabled: true, schedule: 'daily' },
  { name: 'checkov', url: 'https://github.com/bridgecrewio/checkov', type: 'iac', ruleCount: 1000, enabled: true, schedule: 'daily' },
  { name: 'trivy', url: 'https://github.com/aquasecurity/trivy', type: 'container', ruleCount: 50000, enabled: true, schedule: 'daily' },
  { name: 'grype', url: 'https://github.com/anchore/grype', type: 'vulndb', ruleCount: 30000, enabled: true, schedule: 'daily' },
  { name: 'syft', url: 'https://github.com/anchore/syft', type: 'container', ruleCount: 0, enabled: true, schedule: 'daily' },
  { name: 'MobSF', url: 'https://github.com/MobSF/Mobile-Security-Framework-MobSF', type: 'mobile', ruleCount: 100, enabled: true, schedule: 'weekly' },
  { name: 'OWASP-MSTG', url: 'https://github.com/OWASP/owasp-mastg', type: 'mobile', ruleCount: 150, enabled: true, schedule: 'weekly' },
  { name: 'OWASP-ASVS', url: 'https://github.com/OWASP/ASVS', type: 'sast', ruleCount: 286, enabled: true, schedule: 'weekly' },
  { name: 'OWASP-wstg', url: 'https://github.com/OWASP/wstg', type: 'dast', ruleCount: 200, enabled: true, schedule: 'weekly' },
  { name: 'CIS-Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks', type: 'iac', ruleCount: 100, enabled: true, schedule: 'monthly' },
  { name: 'OSV', url: 'https://osv.dev', type: 'vulndb', ruleCount: 100000, enabled: true, schedule: 'daily' },
];

export interface SyncResult {
  source: string;
  rulesAdded: number;
  rulesUpdated: number;
  rulesRemoved: number;
  conflicts: number;
  durationMs: number;
  status: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Turn a GitHub/GitLab URL into a cloneable git URL. */
function toCloneUrl(url: string): string {
  if (/\.git$/.test(url)) return url;
  // Detect known git forges
  if (/github\.com|gitlab\.com|gitlab\.org|bitbucket\.org/.test(url)) {
    const normalised = url.replace(/\/+$/, '');
    return `${normalised}.git`;
  }
  return url; // non-git URL, used as-is
}

function isGitUrl(url: string): boolean {
  return /github\.com|gitlab\.|bitbucket\.org|git\.\w+/.test(url);
}

/** Map arbitrary severity strings to the DB enum. */
function mapSeverity(s?: string): string {
  switch ((s ?? 'medium').toLowerCase()) {
    case 'critical': case 'error': case 'blocker': return 'critical';
    case 'high': return 'high';
    case 'medium': case 'warn': case 'warning': return 'medium';
    case 'low': case 'note': return 'low';
    case 'info': case 'none': case 'informational': return 'info';
    default: return 'medium';
  }
}

/** Derive a fallback source-wide category from the source type. */
function fallbackCategory(type: string): string {
  const map: Record<string, string> = {
    sast: 'static-analysis',
    dast: 'dynamic-analysis',
    fuzz: 'fuzzing',
    secret: 'secrets',
    iac: 'iac-security',
    container: 'container-security',
    mobile: 'mobile-security',
    vulndb: 'vulnerability-database',
  };
  return map[type] ?? 'static-analysis';
}

/** Detect the specific rule-format within a source. */
function detectFormat(source: RuleSource): string {
  const n = source.name.toLowerCase();
  const u = source.url.toLowerCase();
  if (n.includes('semgrep') || u.includes('semgrep')) return 'semgrep';
  if (n.includes('codeql') || u.includes('codeql')) return 'codeql';
  if (n.includes('gitleaks') || u.includes('gitleaks')) return 'gitleaks';
  if (n.includes('nuclei') || u.includes('nuclei')) return 'nuclei';
  if (n.includes('gosec') || u.includes('gosec')) return 'gosec';
  if (n.includes('bandit') || u.includes('bandit')) return 'bandit';
  return 'generic';
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

/** Recursively traverse `dir` and collect every file whose extension is in the set. */
function findRuleFiles(dir: string): string[] {
  const exts = new Set(['.yaml', '.yml', '.json', '.xml', '.ql', '.toml']);
  const files: string[] = [];

  function walk(d: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch { return; }
    for (const e of entries) {
      if (e.name.startsWith('.') || e.name === 'node_modules') continue;
      const fp = path.join(d, e.name);
      if (e.isDirectory()) walk(fp);
      else if (e.isFile() && exts.has(path.extname(e.name).toLowerCase())) files.push(fp);
    }
  }
  walk(dir);
  return files;
}

// ---------------------------------------------------------------------------
// TOML parser (gitleaks-specific)
// ---------------------------------------------------------------------------

function parseGitleaksToml(content: string): Array<{
  id: string; description: string; regex: string; severity: string;
}> {
  const rules: Array<{ id: string; description: string; regex: string; severity: string }> = [];
  const lines = content.split('\n');
  let cur: Record<string, string> | null = null;
  let inTriple = false;
  let tripleKey = '';
  let tripleVal = '';

  for (const raw of lines) {
    const line = raw.trim();

    // Start / end of a [[rules]] block
    if (line.startsWith('[[') && line.endsWith(']]')) {
      if (cur?.id) rules.push(cur as { id: string; description: string; regex: string; severity: string });
      cur = {};
      inTriple = false;
      tripleKey = '';
      tripleVal = '';
      continue;
    }
    if (!cur) continue;

    // Inside triple-quoted string
    if (inTriple) {
      const endIdx = line.indexOf("'''");
      if (endIdx >= 0) {
        tripleVal += '\n' + line.slice(0, endIdx);
        cur[tripleKey] = tripleVal;
        inTriple = false;
        tripleKey = '';
        tripleVal = '';
      } else {
        tripleVal += '\n' + raw; // preserve original indentation
      }
      continue;
    }

    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const k = line.slice(0, eq).trim();
    let v = line.slice(eq + 1).trim();

    // Triple-quoted start
    if (v.startsWith("'''")) {
      const rest = v.slice(3);
      if (rest.endsWith("'''")) {
        v = rest.slice(0, -3);
        cur[k] = v;
      } else {
        inTriple = true;
        tripleKey = k;
        tripleVal = rest;
      }
      continue;
    }

    // Strip surrounding quotes
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    cur[k] = v;
  }

  if (cur?.id) rules.push(cur as { id: string; description: string; regex: string; severity: string });
  return rules;
}

// ---------------------------------------------------------------------------
// CodeQL QL-file header parser
// ---------------------------------------------------------------------------

function parseCodeQLHeader(_filePath: string, content: string): {
  ruleId: string; name: string; severity: string; description: string;
} | null {
  const id = content.match(/@id\s+(\S+)/);
  if (!id) return null;
  const name = content.match(/@name\s+(.+)/);
  const sev = content.match(/@severity\s+(\S+)/);
  const desc = content.match(/@description\s+(.+?)(?:\n@|\n\s*\n|\n$)/s);
  return {
    ruleId: id[1]!,
    name: name?.[1]?.trim() ?? id[1]!,
    severity: mapSeverity(sev?.[1]),
    description: desc?.[1]?.trim() ?? '',
  };
}

// ---------------------------------------------------------------------------
// Rule-file parser dispatcher
// ---------------------------------------------------------------------------

function parseRuleFile(
  filePath: string,
  format: string,
  source: RuleSource,
): Array<{
  ruleId: string; name: string; description: string; category: string;
  severity: string; languages: string[]; patterns: unknown[]; patternType: string;
  cweId?: string; owaspCategory?: string;
}> {
  const content = fs.readFileSync(filePath, 'utf-8');
  const baseCat = fallbackCategory(source.type);
  const results: Array<any> = [];

  try {
    switch (format) {
      // ---- semgrep YAML ----
      case 'semgrep': {
        const doc = YAML.parse(content);
        if (!doc) return results;
        const rules = Array.isArray(doc.rules) ? doc.rules : Array.isArray(doc) ? doc : [];
        for (const r of rules) {
          if (!r?.id) continue;
          const langs = r.languages ? (Array.isArray(r.languages) ? r.languages.map(String) : [String(r.languages)]) : [];
          const meta = r.metadata ?? {};
          results.push({
            ruleId: String(r.id),
            name: String(r.id),
            description: r.message ?? r.description ?? '',
            category: meta.category ?? r.category ?? baseCat,
            severity: mapSeverity(r.severity ?? meta.severity),
            languages: langs,
            patterns: r.pattern ? [{ pattern: r.pattern }] : (r.patterns ?? r.patterns_either ?? []),
            patternType: 'semgrep',
            cweId: meta.cwe ? (Array.isArray(meta.cwe) ? String(meta.cwe[0]) : String(meta.cwe)) : undefined,
            owaspCategory: meta.owasp ? (Array.isArray(meta.owasp) ? String(meta.owasp[0]) : String(meta.owasp)) : undefined,
          });
        }
        break;
      }

      // ---- CodeQL .ql files ----
      case 'codeql': {
        if (!filePath.endsWith('.ql')) break;
        const h = parseCodeQLHeader(filePath, content);
        if (h) {
          results.push({
            ruleId: h.ruleId, name: h.name, description: h.description,
            category: baseCat, severity: h.severity, languages: [],
            patterns: [{ qlPath: filePath }], patternType: 'codeql',
          });
        }
        break;
      }

      // ---- gitleaks TOML ----
      case 'gitleaks': {
        if (!filePath.endsWith('.toml')) break;
        for (const r of parseGitleaksToml(content)) {
          results.push({
            ruleId: `gitleaks-${r.id}`, name: r.id, description: r.description ?? '',
            category: 'secrets', severity: mapSeverity(r.severity || 'high'),
            languages: [], patterns: [{ regex: r.regex }], patternType: 'regex',
          });
        }
        break;
      }

      // ---- nuclei YAML ----
      case 'nuclei': {
        if (!filePath.endsWith('.yaml') && !filePath.endsWith('.yml')) break;
        const doc = YAML.parse(content);
        if (!doc?.id) break;
        const info = doc.info ?? {};
        results.push({
          ruleId: `nuclei-${doc.id}`, name: info.name ?? String(doc.id),
          description: info.description ?? '', category: baseCat,
          severity: mapSeverity(info.severity),
          languages: [],
          patterns: [{ requests: doc.requests ?? doc.http ?? [], matchers: doc.matchers ?? [] }],
          patternType: 'custom',
          cweId: info.cwe ? String(info.cwe) : undefined,
        });
        break;
      }

      // ---- Generic (YAML / JSON) ----
      default: {
        if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
          const doc = YAML.parse(content);
          if (!doc) return results;
          const candidates = doc.rules ?? doc.rule ?? (doc.Rules || null);
          const arr = Array.isArray(candidates) ? candidates : (candidates ? [candidates] : [doc]);
          for (const r of arr) {
            if (!r || typeof r !== 'object') continue;
            const rid = r.id ?? r.rule_id ?? r.name ?? r.ruleId;
            if (!rid) continue;
            results.push({
              ruleId: String(rid), name: r.name ?? String(rid),
              description: r.description ?? r.message ?? '', category: r.category ?? baseCat,
              severity: mapSeverity(r.severity ?? 'medium'),
              languages: Array.isArray(r.languages) ? r.languages.map(String) : [],
              patterns: r.patterns ?? (r.pattern ? [r.pattern] : []),
              patternType: r.type ?? 'custom',
              cweId: r.cwe ? String(r.cwe) : undefined,
            });
          }
        } else if (filePath.endsWith('.json')) {
          const doc = JSON.parse(content);
          const candidates = doc.rules ?? doc.rule ?? doc.findings ?? (Array.isArray(doc) ? doc : [doc]);
          const arr = Array.isArray(candidates) ? candidates : [candidates];
          for (const r of arr) {
            if (!r || typeof r !== 'object') continue;
            const rid = r.id ?? r.rule_id ?? r.name ?? r.ruleId;
            if (!rid) continue;
            results.push({
              ruleId: String(rid), name: r.name ?? String(rid),
              description: r.description ?? r.message ?? '', category: r.category ?? baseCat,
              severity: mapSeverity(r.severity ?? 'medium'),
              languages: Array.isArray(r.languages) ? r.languages.map(String) : [],
              patterns: [r], patternType: 'custom',
              cweId: r.cwe ? String(r.cwe) : undefined,
            });
          }
        }
        break;
      }
    }
  } catch (err) {
    logger.warn({ filePath, err }, 'Skipping unparseable rule file');
  }

  return results;
}

// ---------------------------------------------------------------------------
// Ensure a row exists in rule_sync_sources
// ---------------------------------------------------------------------------

async function ensureSourceRecord(
  source: RuleSource,
  orgId: string,
): Promise<string> {
  const existing = await query(
    'SELECT id FROM rule_sync_sources WHERE org_id = $1 AND source_name = $2',
    [orgId, source.name],
  );
  if (existing.rows.length > 0) {
    return (existing.rows[0] as { id: string }).id;
  }

  const id = uuidv4();
  await query(
    `INSERT INTO rule_sync_sources (id, org_id, source_name, source_url, source_type,
                                     sync_enabled, sync_schedule, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
    [id, orgId, source.name, source.url, source.type, source.enabled, source.schedule],
  );
  return id;
}

/** Resolve an org ID from the source, an override, or the first org in the DB. */
async function resolveOrgId(source: RuleSource, override?: string): Promise<string> {
  if (override) return override;
  if (source.orgId) return source.orgId;

  const result = await query('SELECT id FROM organizations ORDER BY created_at LIMIT 1');
  if (result.rows.length > 0) return (result.rows[0] as { id: string }).id;

  // No org exists yet — create a system org
  const sysId = uuidv4();
  await query(
    'INSERT INTO organizations (id, name, settings) VALUES ($1, $2, $3)',
    [sysId, 'System', JSON.stringify({ system: true })],
  );
  return sysId;
}

// ---------------------------------------------------------------------------
// M18: syncRuleSource  (REAL implementation)
// ---------------------------------------------------------------------------

export async function syncRuleSource(
  source: RuleSource,
  orgIdOverride?: string,
): Promise<SyncResult> {
  const startedAt = Date.now();
  logger.info({ source: source.name, url: source.url }, 'Starting rule source sync');

  let orgId: string;
  let sourceId: string;

  try {
    orgId = await resolveOrgId(source, orgIdOverride);
    sourceId = await ensureSourceRecord(source, orgId);
  } catch (err) {
    logger.error({ err, source: source.name }, 'Failed to initialise sync source record');
    return {
      source: source.name, rulesAdded: 0, rulesUpdated: 0, rulesRemoved: 0,
      conflicts: 0, durationMs: Date.now() - startedAt, status: 'failed',
    };
  }

  // Non-git URLs are not currently auto-syncable; mark as skipped.
  if (!isGitUrl(source.url)) {
    logger.warn({ source: source.name, url: source.url }, 'Non-git URL cannot be cloned — syncing as metadata-only');
    await query(
      `UPDATE rule_sync_sources SET last_synced_at = NOW(), rules_count = $1, updated_at = NOW() WHERE id = $2`,
      [0, sourceId],
    );
    return {
      source: source.name, rulesAdded: 0, rulesUpdated: 0, rulesRemoved: 0,
      conflicts: 0, durationMs: Date.now() - startedAt, status: 'skipped',
    };
  }

  const format = detectFormat(source);
  const safeName = source.name.replace(/[^a-zA-Z0-9_-]/g, '_');
  const cloneDir = path.join(RULE_CLONE_DIR, safeName);
  let currentCommitHash: string | null = null;
  let allRules: Array<{
    ruleId: string; name: string; description: string; category: string;
    severity: string; languages: string[]; patterns: unknown[]; patternType: string;
    cweId?: string; owaspCategory?: string;
  }> = [];

  try {
    // Clean and clone
    fs.mkdirSync(RULE_CLONE_DIR, { recursive: true });
    if (fs.existsSync(cloneDir)) fs.rmSync(cloneDir, { recursive: true, force: true });

    const cloneUrl = toCloneUrl(source.url);
    logger.info({ cloneUrl, cloneDir }, 'Cloning rule repository');
    await execFileAsync('git', ['clone', '--depth', '1', cloneUrl, cloneDir], { timeout: 300000 });

    const { stdout: hashOut } = await execFileAsync('git', ['rev-parse', 'HEAD'], { timeout: 10000, cwd: cloneDir });
    currentCommitHash = hashOut.trim();

    // Find and parse rule files
    const ruleFiles = findRuleFiles(cloneDir);
    logger.info({ source: source.name, fileCount: ruleFiles.length }, 'Found rule files in cloned repo');

    for (const fp of ruleFiles) {
      const parsed = parseRuleFile(fp, format, source);
      allRules.push(...parsed);
    }

    // Deduplicate by ruleId
    const seen = new Set<string>();
    const unique = allRules.filter(r => {
      if (seen.has(r.ruleId)) return false;
      seen.add(r.ruleId);
      return true;
    });
    logger.info({ source: source.name, totalParsed: allRules.length, unique: unique.length }, 'Parsed rules');

    // UPSERT into sast_rules
    let added = 0;
    let updated = 0;

    for (const rule of unique) {
      const existing = await query(
        'SELECT id FROM sast_rules WHERE org_id = $1 AND rule_id = $2',
        [orgId, rule.ruleId],
      );

      if (existing.rows.length > 0) {
        await query(
          `UPDATE sast_rules SET
             name = $1, description = $2, category = $3, severity = $4,
             languages = $5::text[], patterns = $6::jsonb, pattern_type = $7,
             cwe_id = $8, owasp_category = $9, source_repo = $10,
             updated_at = NOW()
           WHERE org_id = $11 AND rule_id = $12`,
          [
            rule.name, rule.description, rule.category, rule.severity,
            rule.languages, JSON.stringify(rule.patterns), rule.patternType,
            rule.cweId ?? null, rule.owaspCategory ?? null, source.url,
            orgId, rule.ruleId,
          ],
        );
        updated++;
      } else {
        await query(
          `INSERT INTO sast_rules
             (id, org_id, rule_id, name, description, category, severity,
              languages, patterns, pattern_type, source_repo, enabled,
              created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text[], $9::jsonb,
                   $10, $11, $12, NOW(), NOW())`,
          [
            uuidv4(), orgId, rule.ruleId, rule.name, rule.description,
            rule.category, rule.severity, rule.languages,
            JSON.stringify(rule.patterns), rule.patternType,
            source.url, source.enabled,
          ],
        );
        added++;
      }
    }

    // Update sync source metadata
    await query(
      `UPDATE rule_sync_sources SET
         last_synced_at = NOW(), last_commit_hash = $1, rules_count = $2,
         updated_at = NOW()
       WHERE id = $3`,
      [currentCommitHash, unique.length, sourceId],
    );

    // Record sync history
    const durationMs = Date.now() - startedAt;
    await query(
      `INSERT INTO rule_sync_history
         (id, source_id, rules_added, rules_updated, rules_removed,
          conflicts, sync_duration_ms, status, synced_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'completed', NOW())`,
      [uuidv4(), sourceId, added, updated, 0, 0, durationMs],
    );

    logger.info({ source: source.name, added, updated, durationMs }, 'Rule sync completed');
    return {
      source: source.name, rulesAdded: added, rulesUpdated: updated,
      rulesRemoved: 0, conflicts: 0, durationMs, status: 'completed',
    };
  } catch (err) {
    const durationMs = Date.now() - startedAt;
    const errMsg = String(err);
    logger.error({ err, source: source.name }, 'Rule sync failed');

    try {
      await query(
        `INSERT INTO rule_sync_history
           (id, source_id, rules_added, rules_updated, rules_removed,
            conflicts, sync_duration_ms, status, error_message, synced_at)
         VALUES ($1, $2, 0, 0, 0, 0, $3, 'failed', $4, NOW())`,
        [uuidv4(), sourceId, durationMs, errMsg],
      );
    } catch { /* best-effort */ }

    return {
      source: source.name, rulesAdded: 0, rulesUpdated: 0, rulesRemoved: 0,
      conflicts: 0, durationMs, status: 'failed',
    };
  } finally {
    if (fs.existsSync(cloneDir)) {
      try { fs.rmSync(cloneDir, { recursive: true, force: true }); }
      catch { /* best-effort cleanup */ }
    }
  }
}

// ---------------------------------------------------------------------------
// M19: getRuleLibraryStats  (REAL implementation, queries sast_rules)
// ---------------------------------------------------------------------------

export interface RuleLibrary {
  totalRules: number;
  byCategory: Record<string, number>;
  byLanguage: Record<string, number>;
  bySource: Record<string, number>;
  topPerformers: Array<{ ruleId: string; precision: number; tpRate: number }>;
  noisyRules: Array<{ ruleId: string; fpRate: number; recommendation: string }>;
}

export async function getRuleLibraryStats(): Promise<RuleLibrary> {
  logger.info('Collecting rule library statistics from sast_rules table');

  const [totalRes, catRes, langRes, srcRes, topRes, noisyRes] = await Promise.all([
    query('SELECT COUNT(*)::int AS total FROM sast_rules'),
    query('SELECT category, COUNT(*)::int AS cnt FROM sast_rules GROUP BY category ORDER BY cnt DESC'),
    query(`SELECT lang, COUNT(*)::int AS cnt
           FROM sast_rules, unnest(languages) AS lang
           GROUP BY lang ORDER BY cnt DESC`),
    query('SELECT source_repo, COUNT(*)::int AS cnt FROM sast_rules WHERE source_repo IS NOT NULL GROUP BY source_repo ORDER BY cnt DESC'),
    // Top 20 by precision (only where at least one TP or FP recorded)
    query(`SELECT rule_id, true_positives, false_positives,
                  CASE WHEN (true_positives + false_positives) > 0
                    THEN ROUND(true_positives::numeric / (true_positives + false_positives), 4)
                    ELSE 0 END AS precision,
                  CASE WHEN (true_positives + false_negatives) > 0
                    THEN ROUND(true_positives::numeric / (true_positives + false_negatives), 4)
                    ELSE 0 END AS recall
           FROM sast_rules
           WHERE (true_positives + false_positives) > 0
              OR (true_positives + false_negatives) > 0
           ORDER BY precision DESC, true_positives DESC
           LIMIT 20`),
    // Noisiest 20 by FP-rate (require at least 10 total FP+TP to avoid bias)
    query(`SELECT rule_id, false_positives, true_positives,
                  CASE WHEN (false_positives + true_positives) > 0
                    THEN ROUND(false_positives::numeric / (false_positives + true_positives), 4)
                    ELSE 0 END AS fp_rate
           FROM sast_rules
           WHERE (false_positives + true_positives) >= 10
           ORDER BY fp_rate DESC, false_positives DESC
           LIMIT 20`),
  ]);

  const totalRules = (totalRes.rows[0] as { total: number } | undefined)?.total ?? 0;

  const byCategory: Record<string, number> = {};
  for (const r of catRes.rows) { byCategory[(r as any).category] = (r as any).cnt; }

  const byLanguage: Record<string, number> = {};
  for (const r of langRes.rows) { byLanguage[(r as any).lang] = (r as any).cnt; }

  const bySource: Record<string, number> = {};
  for (const r of srcRes.rows) { bySource[(r as any).source_repo] = (r as any).cnt; }

  const topPerformers = topRes.rows.map((r: any) => ({
    ruleId: r.rule_id as string,
    precision: parseFloat(r.precision),
    tpRate: parseFloat(r.recall),
  }));

  const noisyRules = noisyRes.rows.map((r: any) => {
    const fpRate = parseFloat(r.fp_rate);
    let recommendation: string;
    if (fpRate > 0.5) recommendation = 'Consider disabling or reducing severity. High false-positive rate detected.';
    else if (fpRate > 0.3) recommendation = 'Add exclude patterns to reduce noise. Moderate false-positive rate.';
    else recommendation = 'Monitor for false-positive trends.';
    return { ruleId: r.rule_id as string, fpRate, recommendation };
  });

  return { totalRules, byCategory, byLanguage, bySource, topPerformers, noisyRules };
}

// ---------------------------------------------------------------------------
// M19: listRuleSources  (REAL implementation, queries rule_sync_sources)
// ---------------------------------------------------------------------------

export async function listRuleSources(): Promise<RuleSource[]> {
  const result = await query(
    `SELECT source_name, source_url, source_type, last_synced_at, rules_count,
            sync_enabled, sync_schedule
     FROM rule_sync_sources
     ORDER BY source_name`,
  );

  return result.rows.map((r: any) => ({
    name: r.source_name as string,
    url: r.source_url as string,
    type: r.source_type as RuleSource['type'],
    lastSynced: r.last_synced_at ? (r.last_synced_at as Date).toISOString() : undefined,
    ruleCount: (r.rules_count as number) ?? 0,
    enabled: r.sync_enabled as boolean,
    schedule: r.sync_schedule as string,
  }));
}

// ---------------------------------------------------------------------------
// M20: CI/CD Integration  (unchanged)
// ---------------------------------------------------------------------------

export interface CICDConfig {
  platform: 'github-actions' | 'gitlab-ci' | 'jenkins' | 'bitbucket' | 'azure-devops' | 'circleci';
  scanType: string;
  failOn: string;
  sarifOutput: boolean;
}

export function generateCICDYaml(config: CICDConfig): string {
  if (config.platform === 'github-actions') {
    return [
      'name: AppSec Scan',
      'on: [pull_request]',
      'jobs:',
      '  scan:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: appsec-platform/scan-action@v1',
      '        with:',
      `          scan-type: ${config.scanType}`,
      `          fail-on: ${config.failOn}`,
      `          sarif-output: ${config.sarifOutput}`,
    ].join('\n');
  }
  if (config.platform === 'gitlab-ci') {
    return [
      'appsec_scan:',
      '  stage: test',
      '  image: appsec/scanner:latest',
      '  script:',
      `    - appsec scan --type ${config.scanType} --fail-on ${config.failOn}`,
      '  artifacts:',
      '    reports:',
      '      sast: results.sarif',
    ].join('\n');
  }
  return '';
}

// ---------------------------------------------------------------------------
// M21: Secrets Detection  (unchanged)
// ---------------------------------------------------------------------------

export interface SecretFinding {
  type: string;
  file: string;
  line: number;
  secret: string;
  validated: boolean;
  recommendation: string;
}

export function scanForSecrets(content: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const patterns: Array<{ type: string; regex: RegExp; rec: string }> = [
    { type: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/, rec: 'Rotate immediately via IAM. Use IAM roles instead of long-lived keys.' },
    { type: 'GitHub Token', regex: /ghp_[0-9a-zA-Z]{36}/, rec: 'Revoke at github.com/settings/tokens. Use GitHub App tokens.' },
    { type: 'Private Key', regex: /-----BEGIN\s(?:RSA|EC|DSA|OPENSSH)\sPRIVATE\sKEY-----/, rec: 'Remove from code. Store in vault/HSM/secret manager.' },
    { type: 'Generic API Key', regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["']/i, rec: 'Move to environment variable or secret manager. Rotate if exposed.' },
    { type: 'Password in Code', regex: /password\s*[:=]\s*["'][^"']{6,}["']/i, rec: 'Remove hardcoded password. Use secret manager with dynamic secrets.' },
    { type: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, rec: 'Never hardcode JWT tokens. Use short-lived tokens from auth service.' },
    { type: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+/, rec: 'Rotate webhook URL. Use Slack App with OAuth instead.' },
  ];
  const lines = content.split('\n');
  for (const pattern of patterns) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.regex.test(lines[i]!)) {
        findings.push({
          type: pattern.type, file: filePath, line: i + 1,
          secret: '***REDACTED***', validated: false, recommendation: pattern.rec,
        });
      }
    }
  }
  return findings;
}
