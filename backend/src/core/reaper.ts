import { getConfig } from '../config/index.js';
import { logger } from './logging/logger.js';
import { query } from './db/pool.js';
import { queueManager } from './queue/manager.js';
import { QueueName } from './queue/manager.js';

const SCAN_QUEUES: QueueName[] = [
  QueueName.SAST_SCAN,
  QueueName.DAST_SCAN,
  QueueName.API_SCAN,
  QueueName.SCA_SCAN,
  QueueName.SECRET_SCAN,
];

interface StuckScan {
  id: string;
  status: string;
}

function minutesAgo(minutes: number): Date {
  const d = new Date();
  d.setMinutes(d.getMinutes() - minutes);
  return d;
}

async function hasActiveJobs(): Promise<boolean> {
  for (const q of SCAN_QUEUES) {
    try {
      const stats = await queueManager.getQueueStats(q);
      if (stats.active > 0 || stats.waiting > 0) {
        return true;
      }
    } catch {
      // Queue may not be initialised yet — treat as no active jobs.
    }
  }
  return false;
}

async function runReaperCycle(): Promise<void> {
  const config = getConfig();
  const maxRuntimeMin = config.SCAN_MAX_RUNTIME_MIN;
  const threshold = minutesAgo(maxRuntimeMin);

  logger.info(
    { maxRuntimeMin, threshold: threshold.toISOString() },
    'Reaper: starting cycle',
  );

  try {
    // 1. Fetch all scans that are still queued or running.
    const { rows } = await query<StuckScan>(
      `SELECT id, status FROM scans WHERE status IN ('queued', 'running')`,
    );

    if (rows.length === 0) {
      logger.info('Reaper: no stuck scans found');
      return;
    }

    // 2. For 'queued' scans we additionally verify that no active/waiting
    //    BullMQ jobs exist across the scan queues before reaping.
    let bullmqActive = false;
    let bullmqChecked = false;
    const hasQueued = rows.some((r) => r.status === 'queued');

    if (hasQueued) {
      bullmqActive = await hasActiveJobs();
      bullmqChecked = true;
    }

    // 3. Classify each row as reaped or kept.
    const toReap: string[] = [];

    for (const row of rows) {
      if (row.status === 'running') {
        // Reap 'running' scans whose started_at or updated_at is past threshold.
        // We can't check started_at/updated_at in the initial query because
        // the threshold comparison is dynamic; we re-query or filter here.
        // For simplicity, re-query each candidate, or better: include the
        // timestamp columns in the initial query.
        // Let's handle this by re-fetching with the threshold inline.
        toReap.push(row.id);
      } else if (row.status === 'queued') {
        // Only reap queued scans when no active/waiting BullMQ jobs exist.
        if (bullmqChecked && !bullmqActive) {
          toReap.push(row.id);
        }
      }
    }

    if (toReap.length === 0) {
      logger.info('Reaper: no scans to reap after filtering');
      return;
    }

    // 4. Bulk-update all reaped scans in one shot.  For safety, only update
    //    those that haven't changed status since we read them.
    //    We also apply the time threshold at UPDATE time for 'running' scans.
    const result = await query(
      `UPDATE scans
         SET status = 'failed',
             error_message = 'Reaped: exceeded max runtime or abandoned (no active worker)',
             completed_at = NOW(),
             updated_at = NOW()
       WHERE id = ANY($1::uuid[])
         AND status IN ('queued', 'running')
         AND (
           status = 'queued'
           OR (
             status = 'running'
             AND (
               started_at IS NULL
               OR started_at < $2
               OR updated_at < $2
             )
           )
         )`,
      [toReap, threshold],
    );

    const reapedCount = result.rowCount ?? 0;
    if (reapedCount > 0) {
      logger.warn(
        { reapedCount, candidateCount: toReap.length },
        'Reaper: reaped stuck scans',
      );
    } else {
      logger.info(
        { candidateCount: toReap.length },
        'Reaper: no scans were actually reaped (status may have changed)',
      );
    }
  } catch (err) {
    logger.error({ err }, 'Reaper: cycle failed');
  }
}

export function startReaper(): void {
  logger.info('Reaper: scheduling (initial delay 5s, then every 20 min)');

  // Initial short delay so workers have time to boot before the first cycle.
  setTimeout(() => {
    runReaperCycle().catch((err) =>
      logger.error({ err }, 'Reaper: initial cycle failed'),
    );

    setInterval(() => {
      runReaperCycle().catch((err) =>
        logger.error({ err }, 'Reaper: cycle failed'),
      );
    }, 20 * 60 * 1000);
  }, 5_000);
}
