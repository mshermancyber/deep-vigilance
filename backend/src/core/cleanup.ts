// Retention / housekeeping jobs.
//
// A long-lived AppSec install accumulates data that nobody reads again: scan
// rows and their findings, generated report blobs, audit entries, delivered
// notifications, API request history, webhook dead letters, and completed
// BullMQ jobs sitting in Redis. This module prunes all of it on a timer.
//
// Everything is driven from .env (see config/index.ts):
//
//   CLEANUP_INTERVAL_MIN          how often a cycle runs (0 = disable cleanup)
//   RETAIN_SCANS_DAYS             scans + their findings/evidence/crawl results
//   RETAIN_AUDIT_LOG_DAYS         audit_log
//   RETAIN_REPORTS_DAYS           reports rows + the files on disk
//   RETAIN_NOTIFICATIONS_DAYS     delivered/failed notifications
//   RETAIN_CODE_REVIEWS_DAYS      code_reviews + cascaded findings
//   RETAIN_API_HISTORY_DAYS       api_request_history
//   RETAIN_WEBHOOK_DLQ_DAYS       webhook_dead_letters
//   RETAIN_QUEUE_JOBS_DAYS        completed/failed BullMQ jobs in Redis
//
// Any threshold set to 0 means "never prune this table", so an operator can
// enable housekeeping selectively.
//
// Design notes:
//   * Deletes run in batches (CLEANUP_BATCH_SIZE) so a first run against a
//     large database never holds a table lock for minutes.
//   * `findings.scan_id` references `scans(id)` WITHOUT `ON DELETE CASCADE`,
//     so findings MUST be deleted before their scans or the delete fails with
//     a foreign-key violation. Child tables that DO cascade (dast_evidence,
//     dast_crawl_results, finding_comments, ...) are left to the database.
//   * `sbom_exports.scan_id` is a bare UUID with no FK, so it would be left
//     dangling; those rows are detached explicitly.
//   * Only terminal-state rows are touched. A scan that is still `queued` or
//     `running` is never pruned regardless of age — that is the reaper's job
//     (core/reaper.ts), and it marks such scans `failed` first.
//   * A safety rail (CLEANUP_MAX_TABLE_FRACTION) aborts a table's prune if the
//     configured window would remove more than that share of the table, which
//     catches a mistyped retention value before it destroys live data.

import { getConfig } from '../config/index.js';
import { logger } from './logging/logger.js';
import { query } from './db/pool.js';
import { queueManager, QueueName } from './queue/manager.js';
import fs from 'fs/promises';
import path from 'path';

const DAY_MS = 24 * 60 * 60 * 1000;

/** Queues whose completed/failed jobs are trimmed from Redis. */
const ALL_QUEUES: QueueName[] = [
  QueueName.SAST_SCAN,
  QueueName.DAST_SCAN,
  QueueName.API_SCAN,
  QueueName.SCA_SCAN,
  QueueName.SECRET_SCAN,
  QueueName.REPORT_GENERATION,
  QueueName.NOTIFICATION,
  QueueName.SCHEDULED_TASK,
  QueueName.CODE_REVIEW,
];

export interface CleanupTaskResult {
  task: string;
  deleted: number;
  skipped?: string;
}

export interface CleanupReport {
  startedAt: string;
  durationMs: number;
  tasks: CleanupTaskResult[];
  totalDeleted: number;
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

function daysAgo(days: number): Date {
  return new Date(Date.now() - days * DAY_MS);
}

/**
 * Count how many rows a prune would remove and compare against the table size.
 * Returns a reason string when the prune must be skipped, or null to proceed.
 */
async function guardTableFraction(
  table: string,
  whereClause: string,
  params: unknown[],
): Promise<string | null> {
  const maxFraction = getConfig().CLEANUP_MAX_TABLE_FRACTION;
  if (maxFraction >= 1) return null;

  const { rows } = await query<{ doomed: string; total: string }>(
    `SELECT
       (SELECT COUNT(*) FROM ${table} WHERE ${whereClause}) AS doomed,
       (SELECT COUNT(*) FROM ${table}) AS total`,
    params,
  );
  const doomed = Number(rows[0]?.doomed ?? 0);
  const total = Number(rows[0]?.total ?? 0);

  // Nothing to delete, or a small table where a high fraction is meaningless.
  if (doomed === 0 || total === 0) return null;
  if (total < 1000) return null;

  const fraction = doomed / total;
  if (fraction > maxFraction) {
    return `would delete ${doomed}/${total} rows (${(fraction * 100).toFixed(1)}%) ` +
      `which exceeds CLEANUP_MAX_TABLE_FRACTION=${maxFraction}; check your retention settings`;
  }
  return null;
}

/**
 * Delete in bounded batches until no rows remain. `sql` must be a DELETE whose
 * last positional parameter is the batch limit.
 */
async function deleteInBatches(sql: string, params: unknown[]): Promise<number> {
  const batchSize = getConfig().CLEANUP_BATCH_SIZE;
  let total = 0;
  // Hard stop so a pathological loop can never spin forever.
  for (let i = 0; i < 1000; i++) {
    const result = await query(sql, [...params, batchSize]);
    const n = result.rowCount ?? 0;
    total += n;
    if (n < batchSize) break;
  }
  return total;
}

// ────────────────────────────────────────────────────────────────────────────
// Individual cleanup tasks
// ────────────────────────────────────────────────────────────────────────────

/**
 * Prune finished scans and everything hanging off them.
 *
 * Order matters: findings first (no cascade from scans), then the scans. Rows
 * in a non-terminal status are excluded so a live scan is never removed.
 */
async function cleanupScans(days: number): Promise<CleanupTaskResult[]> {
  const cutoff = daysAgo(days);
  const results: CleanupTaskResult[] = [];

  const terminal = `status IN ('completed', 'failed', 'cancelled')`;
  const scanWhere = `${terminal} AND COALESCE(completed_at, updated_at, created_at) < $1`;

  const guard = await guardTableFraction('scans', scanWhere, [cutoff]);
  if (guard) {
    logger.warn({ task: 'scans', reason: guard }, 'Cleanup: skipped scan prune');
    return [{ task: 'scans', deleted: 0, skipped: guard }];
  }

  // 1. Detach SBOM exports — scan_id has no FK, so these would dangle.
  const detached = await query(
    `UPDATE sbom_exports SET scan_id = NULL
      WHERE scan_id IN (SELECT id FROM scans WHERE ${scanWhere})`,
    [cutoff],
  );
  if ((detached.rowCount ?? 0) > 0) {
    results.push({ task: 'sbom_exports.scan_id detached', deleted: detached.rowCount ?? 0 });
  }

  // 2. Findings belonging to those scans. Cascades to dast_evidence and
  //    finding_comments.
  const findingsDeleted = await deleteInBatches(
    `DELETE FROM findings
      WHERE id IN (
        SELECT f.id FROM findings f
          JOIN scans s ON s.id = f.scan_id
         WHERE s.${terminal}
           AND COALESCE(s.completed_at, s.updated_at, s.created_at) < $1
         LIMIT $2
      )`,
    [cutoff],
  );
  results.push({ task: 'findings', deleted: findingsDeleted });

  // 3. The scans themselves. Cascades to dast_crawl_results.
  const scansDeleted = await deleteInBatches(
    `DELETE FROM scans
      WHERE id IN (
        SELECT id FROM scans WHERE ${scanWhere} LIMIT $2
      )`,
    [cutoff],
  );
  results.push({ task: 'scans', deleted: scansDeleted });

  return results;
}

/**
 * Prune report rows and the generated files they point at.
 *
 * There is no `file_path` column: both producers write `<id>.<format>` into
 * REPORT_DIR (see workers/report-worker.ts and services/report-generator), so
 * the filename is derived the same way here. `id` is a UUID and `format` is
 * CHECK-constrained by the schema, so the name cannot contain a path segment;
 * it is still run through basename() and bounded to REPORT_DIR for safety.
 *
 * The file is removed before its row. If unlinking fails for any reason other
 * than "already gone", the row is kept so the next cycle retries instead of
 * orphaning a blob on disk forever.
 */
async function cleanupReports(days: number): Promise<CleanupTaskResult[]> {
  const cutoff = daysAgo(days);
  const results: CleanupTaskResult[] = [];
  const reportDir = path.resolve(getConfig().REPORT_DIR);

  const where = `status IN ('completed', 'failed') AND created_at < $1`;
  const guard = await guardTableFraction('reports', where, [cutoff]);
  if (guard) {
    logger.warn({ task: 'reports', reason: guard }, 'Cleanup: skipped report prune');
    return [{ task: 'reports', deleted: 0, skipped: guard }];
  }

  const { rows } = await query<{ id: string; format: string; status: string }>(
    `SELECT id, format, status FROM reports WHERE ${where} LIMIT 10000`,
    [cutoff],
  );
  if (rows.length === 0) return [{ task: 'reports', deleted: 0 }];

  const deletableIds: string[] = [];
  let filesRemoved = 0;

  for (const row of rows) {
    // A 'failed' report never produced a file; drop the row directly.
    if (row.status === 'failed') {
      deletableIds.push(row.id);
      continue;
    }

    const filename = path.basename(`${row.id}.${row.format}`);
    const resolved = path.resolve(reportDir, filename);
    if (!resolved.startsWith(reportDir + path.sep)) {
      logger.warn(
        { reportId: row.id, filename },
        'Cleanup: derived report path escapes REPORT_DIR, leaving file on disk',
      );
      deletableIds.push(row.id);
      continue;
    }

    try {
      await fs.unlink(resolved);
      filesRemoved++;
      deletableIds.push(row.id);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        // Already gone — the row is safe to drop.
        deletableIds.push(row.id);
      } else {
        logger.warn(
          { err, reportId: row.id },
          'Cleanup: could not remove report file, keeping row for the next cycle',
        );
      }
    }
  }

  if (filesRemoved > 0) {
    results.push({ task: 'report files', deleted: filesRemoved });
  }

  let rowsDeleted = 0;
  if (deletableIds.length > 0) {
    const result = await query(
      `DELETE FROM reports WHERE id = ANY($1::uuid[])`,
      [deletableIds],
    );
    rowsDeleted = result.rowCount ?? 0;
  }
  results.push({ task: 'reports', deleted: rowsDeleted });

  return results;
}

/** Generic "delete rows older than N days" prune for an append-only table. */
async function cleanupByAge(
  table: string,
  timestampColumn: string,
  days: number,
  extraWhere?: string,
): Promise<CleanupTaskResult> {
  const cutoff = daysAgo(days);
  const where = extraWhere
    ? `${timestampColumn} < $1 AND ${extraWhere}`
    : `${timestampColumn} < $1`;

  const guard = await guardTableFraction(table, where, [cutoff]);
  if (guard) {
    logger.warn({ task: table, reason: guard }, 'Cleanup: skipped prune');
    return { task: table, deleted: 0, skipped: guard };
  }

  const deleted = await deleteInBatches(
    `DELETE FROM ${table}
      WHERE ctid IN (SELECT ctid FROM ${table} WHERE ${where} LIMIT $2)`,
    [cutoff],
  );
  return { task: table, deleted };
}

/** Drop expired auth artefacts. These have an explicit expires_at, so age is exact. */
async function cleanupExpiredAuth(): Promise<CleanupTaskResult[]> {
  const results: CleanupTaskResult[] = [];
  for (const table of ['sessions', 'password_resets', 'mfa_challenges']) {
    try {
      const deleted = await deleteInBatches(
        `DELETE FROM ${table}
          WHERE ctid IN (SELECT ctid FROM ${table} WHERE expires_at < NOW() LIMIT $1)`,
        [],
      );
      results.push({ task: `${table} (expired)`, deleted });
    } catch (err) {
      logger.warn({ err, table }, 'Cleanup: expired-auth prune failed');
      results.push({ task: `${table} (expired)`, deleted: 0, skipped: String(err) });
    }
  }
  return results;
}

/** Trim completed/failed BullMQ jobs out of Redis. */
async function cleanupQueueJobs(days: number): Promise<CleanupTaskResult> {
  const olderThanMs = days * DAY_MS;
  let cleaned = 0;
  for (const q of ALL_QUEUES) {
    try {
      await queueManager.cleanOldJobs(q, olderThanMs);
      cleaned++;
    } catch (err) {
      logger.debug({ err, queue: q }, 'Cleanup: queue trim skipped (queue not ready?)');
    }
  }
  return { task: `queues trimmed (${cleaned}/${ALL_QUEUES.length})`, deleted: 0 };
}

// ────────────────────────────────────────────────────────────────────────────
// Cycle
// ────────────────────────────────────────────────────────────────────────────

/**
 * Run one full housekeeping cycle. Exported so the admin API and tests can
 * trigger it on demand. Each task is isolated: one failure does not abort
 * the rest of the cycle.
 */
export async function runCleanupCycle(): Promise<CleanupReport> {
  const config = getConfig();
  const startedAt = new Date();
  const tasks: CleanupTaskResult[] = [];

  logger.info('Cleanup: starting cycle');

  const run = async (label: string, fn: () => Promise<CleanupTaskResult[] | CleanupTaskResult>) => {
    try {
      const out = await fn();
      tasks.push(...(Array.isArray(out) ? out : [out]));
    } catch (err) {
      logger.error({ err, task: label }, 'Cleanup: task failed');
      tasks.push({ task: label, deleted: 0, skipped: String(err) });
    }
  };

  if (config.RETAIN_SCANS_DAYS > 0) {
    await run('scans', () => cleanupScans(config.RETAIN_SCANS_DAYS));
  }
  if (config.RETAIN_REPORTS_DAYS > 0) {
    await run('reports', () => cleanupReports(config.RETAIN_REPORTS_DAYS));
  }
  if (config.RETAIN_AUDIT_LOG_DAYS > 0) {
    await run('audit_log', () => cleanupByAge('audit_log', 'created_at', config.RETAIN_AUDIT_LOG_DAYS));
  }
  if (config.RETAIN_NOTIFICATIONS_DAYS > 0) {
    await run('notifications', () =>
      // Only delivered/abandoned notifications; 'pending' ones are still live.
      cleanupByAge('notifications', 'created_at', config.RETAIN_NOTIFICATIONS_DAYS,
        `status IN ('sent', 'failed')`),
    );
  }
  if (config.RETAIN_CODE_REVIEWS_DAYS > 0) {
    await run('code_reviews', () =>
      // Terminal states only — a review in cloning/indexing/analyzing/reviewing/
      // fuzzing is still in flight and must survive the prune.
      cleanupByAge('code_reviews', 'created_at', config.RETAIN_CODE_REVIEWS_DAYS,
        `status IN ('completed', 'failed', 'cancelled', 'partial')`),
    );
  }
  if (config.RETAIN_API_HISTORY_DAYS > 0) {
    await run('api_request_history', () =>
      cleanupByAge('api_request_history', 'created_at', config.RETAIN_API_HISTORY_DAYS),
    );
  }
  if (config.RETAIN_WEBHOOK_DLQ_DAYS > 0) {
    await run('webhook_dead_letters', () =>
      cleanupByAge('webhook_dead_letters', 'created_at', config.RETAIN_WEBHOOK_DLQ_DAYS),
    );
  }

  // Expired sessions/resets/MFA challenges are always pruned — they are dead
  // weight by definition and carry no retention value.
  await run('expired auth', () => cleanupExpiredAuth());

  if (config.RETAIN_QUEUE_JOBS_DAYS > 0) {
    await run('queue jobs', () => cleanupQueueJobs(config.RETAIN_QUEUE_JOBS_DAYS));
  }

  const totalDeleted = tasks.reduce((sum, t) => sum + t.deleted, 0);
  const durationMs = Date.now() - startedAt.getTime();

  logger.info(
    { totalDeleted, durationMs, tasks: tasks.filter((t) => t.deleted > 0 || t.skipped) },
    'Cleanup: cycle complete',
  );

  return {
    startedAt: startedAt.toISOString(),
    durationMs,
    tasks,
    totalDeleted,
  };
}

/**
 * Schedule the housekeeping cycle.
 *
 * Start this from `server.ts` (the always-on API process) for the same reason
 * as the reaper: the container does not run `workers/main.ts`.
 */
export function startCleanupJobs(): void {
  const intervalMin = getConfig().CLEANUP_INTERVAL_MIN;

  if (intervalMin <= 0) {
    logger.info('Cleanup: disabled (CLEANUP_INTERVAL_MIN=0)');
    return;
  }

  logger.info({ intervalMin }, 'Cleanup: scheduling retention jobs');

  // Delay the first cycle so migrations and queue wiring finish first, and so
  // a crash-looping container never hammers the database with prunes.
  setTimeout(() => {
    runCleanupCycle().catch((err) => logger.error({ err }, 'Cleanup: initial cycle failed'));

    setInterval(() => {
      runCleanupCycle().catch((err) => logger.error({ err }, 'Cleanup: cycle failed'));
    }, intervalMin * 60 * 1000);
  }, 60_000);
}
