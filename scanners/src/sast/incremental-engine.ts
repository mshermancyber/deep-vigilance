import { createHash } from 'crypto';
import fs from 'fs';
import path from 'path';
import { SastFinding } from './engine.js';
import { logger } from '../utils/logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Maps file path to SHA-256 hex digest. */
export type FileHashIndex = Map<string, string>;

/** Classifies every file in the intersection of two hash indices. */
export interface FileChangeSet {
  added: string[];
  modified: string[];
  deleted: string[];
  unchanged: string[];
}

/**
 * Call graph: maps each caller file to the list of callee files it
 * directly imports or invokes.
 */
export type CallGraph = Map<string, string[]>;

/**
 * Dependency (reverse-call) graph: maps each file to the list of other
 * files that depend on it.  When available this avoids re-building the
 * reverse graph from the call graph.
 */
export type DependencyGraph = Map<string, string[]>;

/** A single entry in the scan result cache. */
export interface ScanCacheEntry {
  fileHash: string;
  findings: SastFinding[];
  scannedAt: number;
}

export type ChangeType = 'added' | 'modified' | 'deleted' | 'unchanged';

// ---------------------------------------------------------------------------
// LRU Cache
// ---------------------------------------------------------------------------

/**
 * Fixed-capacity LRU cache backed by a plain Map.
 *
 * JavaScript Map preserves insertion order, so we can implement LRU
 * eviction by deleting-and-re-inserting on access and deleting the
 * first key when the capacity is exceeded.
 */
export class ScanResultCache {
  private readonly maxSize: number;
  private readonly store: Map<string, ScanCacheEntry>;

  /**
   * @param maxSize  Maximum number of entries (default 50 000).
   */
  constructor(maxSize: number = 50_000) {
    this.maxSize = maxSize;
    this.store = new Map();
  }

  /** Retrieve an entry, promoting it to the most-recently-used position. */
  get(filePath: string): ScanCacheEntry | undefined {
    if (!this.store.has(filePath)) return undefined;
    const entry = this.store.get(filePath)!;
    // Re-insert to move to the end (most-recently-used)
    this.store.delete(filePath);
    this.store.set(filePath, entry);
    return entry;
  }

  /** Insert or update an entry, evicting the least-recently-used if full. */
  set(filePath: string, entry: ScanCacheEntry): void {
    if (this.store.has(filePath)) {
      this.store.delete(filePath);
    }
    this.store.set(filePath, entry);
    this.evictIfNeeded();
  }

  /** Remove an entry.  Returns true if it existed. */
  delete(filePath: string): boolean {
    return this.store.delete(filePath);
  }

  /** Check existence without affecting LRU order. */
  has(filePath: string): boolean {
    return this.store.has(filePath);
  }

  /** Current number of entries. */
  get size(): number {
    return this.store.size;
  }

  /** Empty the cache entirely. */
  clear(): void {
    this.store.clear();
  }

  // ----- internal helpers -----

  private evictIfNeeded(): void {
    while (this.store.size > this.maxSize) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) {
        this.store.delete(oldest);
      } else {
        break;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Directories to skip during recursive walks
// ---------------------------------------------------------------------------

export const SKIP_DIRS: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
  '.next',
  '.nuxt',
  'target',
  '.idea',
  '.vscode',
  'coverage',
  '.nyc_output',
  'bower_components',
  'bin',
  'obj',
  'out',
  '.serverless',
  '.terraform',
]);

// ===========================================================================
// 1. computeFileHash
// ===========================================================================

/**
 * Read a file from disk and return its SHA-256 hex digest.
 *
 * Reads as a raw Buffer so that the hash is correct for both text and
 * binary files.  Returns `null` on any I/O error (permission denied,
 * file-not-found, symlink loop, etc.) rather than throwing.
 */
export function computeFileHash(filePath: string): string | null {
  try {
    const buffer = fs.readFileSync(filePath);
    const hash = createHash('sha256');
    hash.update(buffer);
    return hash.digest('hex');
  } catch (err) {
    logger.warn({ filePath, err }, 'Failed to compute file hash');
    return null;
  }
}

// ===========================================================================
// 2. buildFileHashIndex
// ===========================================================================

/**
 * Recursively walk `targetPath` and compute the SHA-256 hash for every
 * file encountered.  Directories in `SKIP_DIRS` are ignored, as are
 * dot-directories.
 *
 * Returns a `Map<string, string>` (file path -> hex digest).  Files that
 * could not be read (permission errors, binary files confused by
 * encoding-passing in other scan code, etc.) are silently omitted.
 */
export function buildFileHashIndex(targetPath: string): FileHashIndex {
  const index: FileHashIndex = new Map();

  function walk(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith('.')) continue;
        walk(fullPath);
      } else if (entry.isFile()) {
        const hash = computeFileHash(fullPath);
        if (hash !== null) {
          index.set(fullPath, hash);
        }
      }
    }
  }

  try {
    const stat = fs.statSync(targetPath);
    if (stat.isDirectory()) {
      walk(targetPath);
    } else if (stat.isFile()) {
      const hash = computeFileHash(targetPath);
      if (hash !== null) {
        index.set(targetPath, hash);
      }
    }
  } catch (err) {
    logger.error({ targetPath, err }, 'Failed to build file hash index');
  }

  return index;
}

// ===========================================================================
// 3. getChangedFiles
// ===========================================================================

/**
 * Compare two file-hash indices and classify every file.
 *
 * Uses Set operations for O(n + m) performance (where n = |oldIndex|,
 * m = |newIndex|).  A file is considered:
 *  - **added**    – present only in `newIndex`
 *  - **modified** – present in both but with different hashes
 *  - **deleted**  – present only in `oldIndex`
 *  - **unchanged** – present in both with identical hashes
 */
export function getChangedFiles(
  oldIndex: FileHashIndex,
  newIndex: FileHashIndex,
): FileChangeSet {
  const oldFiles = new Set(oldIndex.keys());
  const newFiles = new Set(newIndex.keys());

  const added: string[] = [];
  const modified: string[] = [];
  const deleted: string[] = [];
  const unchanged: string[] = [];

  // Iterate over the old index; files that still exist fall into
  // modified or unchanged based on hash comparison.
  for (const filePath of oldFiles) {
    if (newFiles.has(filePath)) {
      const oldHash = oldIndex.get(filePath)!;
      const newHash = newIndex.get(filePath)!;
      if (oldHash === newHash) {
        unchanged.push(filePath);
      } else {
        modified.push(filePath);
      }
    } else {
      deleted.push(filePath);
    }
  }

  // Files only in the new index are additions.
  for (const filePath of newFiles) {
    if (!oldFiles.has(filePath)) {
      added.push(filePath);
    }
  }

  return { added, modified, deleted, unchanged };
}

// ===========================================================================
// 4. getCachedScanResults
// ===========================================================================

/**
 * Look up a file in the scan result cache.
 *
 * If the cached hash matches the current `fileHash` the cached findings
 * are returned immediately and no re-scan is required.  If there is no
 * match (or no entry), `null` is returned to signal that the file must
 * be re-scanned.
 */
export function getCachedScanResults(
  filePath: string,
  fileHash: string,
  cache: ScanResultCache,
): SastFinding[] | null {
  const entry = cache.get(filePath);
  if (!entry) {
    return null;
  }
  if (entry.fileHash !== fileHash) {
    return null;
  }
  return entry.findings;
}

// ===========================================================================
// 5. getAffectedFiles
// ===========================================================================

/**
 * Given a set of changed files and a call graph, find the transitive
 * closure of all files that (directly or indirectly) call into the
 * changed files.
 *
 * **Algorithm (BFS)**
 *
 * 1. Build a reverse-call graph by inverting the edges of `callGraph`
 *    (or by consuming the pre-built `dependencyGraph` if provided).
 * 2. Seed a BFS queue with every file in `changedFiles`.
 * 3. For each dequeued file, enqueue every file that calls into it
 *    (its dependents), continuing until the queue is empty.
 * 4. Return the visited set.
 *
 * @param changedFiles     Files that have been added / modified / deleted.
 * @param callGraph        Forward call graph (caller -> [callee, ...]).
 * @param dependencyGraph  Optional pre-built reverse graph.  When provided
 *                         the function will still enrich it with any edges
 *                         missing from the forward graph, but this avoids
 *                         a second pass over the call graph.
 */
export function getAffectedFiles(
  changedFiles: Set<string>,
  callGraph: CallGraph,
  dependencyGraph?: DependencyGraph,
): Set<string> {
  // Build the reverse graph: callee -> set of callers.
  const reverseGraph: Map<string, Set<string>> = new Map();

  // If a pre-built dependency graph is available, consume it first.
  if (dependencyGraph) {
    for (const [file, dependents] of dependencyGraph) {
      const set = reverseGraph.get(file) ?? new Set();
      for (const dep of dependents) set.add(dep);
      reverseGraph.set(file, set);
    }
  }

  // Invert every edge of the forward call graph and merge the results.
  for (const [caller, callees] of callGraph) {
    for (const callee of callees) {
      let dependents = reverseGraph.get(callee);
      if (!dependents) {
        dependents = new Set();
        reverseGraph.set(callee, dependents);
      }
      dependents.add(caller);
    }
  }

  // BFS from the set of changed files outward.
  const affected = new Set<string>();
  const queue: string[] = [];

  for (const file of changedFiles) {
    if (!affected.has(file)) {
      affected.add(file);
      queue.push(file);
    }
  }

  while (queue.length > 0) {
    const current = queue.shift()!;
    const dependents = reverseGraph.get(current);
    if (!dependents) continue;

    for (const dependent of dependents) {
      if (!affected.has(dependent)) {
        affected.add(dependent);
        queue.push(dependent);
      }
    }
  }

  return affected;
}

// ===========================================================================
// 6. shouldRescanFile
// ===========================================================================

/**
 * Decide whether a file must be re-scanned given its change type and
 * the current rule-category context.
 *
 * | Change type | Behaviour                                                |
 * |-------------+----------------------------------------------------------|
 * | `added`     | Always scan.                                             |
 * | `modified`  | Always re-scan.                                          |
 * | `deleted`   | Remove from cache (if provided); no scan needed.         |
 * | `unchanged` | Re-scan only when `ruleCategories` contains categories   |
 * |             | that were not already present in the cached findings.    |
 *
 * @param filePath         Absolute path to the file.
 * @param changeType       How the file changed between scans.
 * @param ruleCategories   Set of rule categories that are considered
 *                         "active" or "changed" since the last scan.
 * @param cache            Optional cache instance; used for deleted-file
 *                         cleanup and unchanged-file category checks.
 */
export function shouldRescanFile(
  filePath: string,
  changeType: ChangeType,
  ruleCategories: Set<string>,
  cache?: ScanResultCache,
): boolean {
  switch (changeType) {
    case 'added':
      return true;

    case 'modified':
      return true;

    case 'deleted':
      if (cache) {
        cache.delete(filePath);
      }
      return false;

    case 'unchanged': {
      // Without any rule-category changes there is nothing to re-discover.
      if (ruleCategories.size === 0) return false;

      // Without a cache we must assume a re-scan is needed.
      if (!cache) return true;

      const entry = cache.get(filePath);
      if (!entry) return true;

      // Collect the categories present in the cached findings.
      const existingCategories = new Set<string>();
      for (const finding of entry.findings) {
        existingCategories.add(finding.ruleCategory);
      }

      // If any new rule category could affect this file, re-scan.
      for (const cat of ruleCategories) {
        if (!existingCategories.has(cat)) return true;
      }

      return false;
    }

    default:
      return true;
  }
}

// ===========================================================================
// 7. mergeScanResults
// ===========================================================================

/**
 * Produce a stable fingerprint for a finding, used for deduplication.
 *
 * The fingerprint is the first 16 hex characters of the SHA-256 of
 * `ruleId | filePath | lineNumber | match`.
 */
export function computeFindingHash(finding: SastFinding): string {
  const raw = `${finding.ruleId}|${finding.filePath}|${finding.lineNumber}|${finding.match}`;
  return createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

/**
 * Merge cached findings from unchanged files with freshly scanned
 * findings from changed / re-scanned files, deduplicating by finding
 * hash.
 *
 * New results take precedence over cached ones: if a finding appears in
 * both sets (same ruleId + filePath + lineNumber + match) the new
 * version is kept because it reflects the most up-to-date rule set.
 *
 * @param cachedResults  Map from file path to cached findings (unchanged).
 * @param newResults     Map from file path to freshly scanned findings.
 * @returns A single flat, deduplicated array of findings.
 */
export function mergeScanResults(
  cachedResults: Map<string, SastFinding[]>,
  newResults: Map<string, SastFinding[]>,
): SastFinding[] {
  const merged: SastFinding[] = [];
  const seenHashes = new Set<string>();

  // Process new results first so they take precedence.
  for (const findings of newResults.values()) {
    for (const finding of findings) {
      const hash = computeFindingHash(finding);
      if (!seenHashes.has(hash)) {
        seenHashes.add(hash);
        merged.push(finding);
      }
    }
  }

  // Append cached results that weren't superseded.
  for (const findings of cachedResults.values()) {
    for (const finding of findings) {
      const hash = computeFindingHash(finding);
      if (!seenHashes.has(hash)) {
        seenHashes.add(hash);
        merged.push(finding);
      }
    }
  }

  return merged;
}
