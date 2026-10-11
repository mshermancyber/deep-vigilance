import cron from 'node-cron';
import { parseExpression } from 'cron-parser';
import { v4 as uuidv4 } from 'uuid';
import { query } from '../../core/db/pool.js';
import { logger } from '../../core/logging/logger.js';
import { queueManager, QueueName, JobPriority } from '../../core/queue/manager.js';

// ──────────────────────────────────────────────
// Exported Types
// ──────────────────────────────────────────────

/** Valid scan types that can be scheduled. */
export type ScanType = 'sast' | 'dast' | 'api' | 'sca' | 'secret' | 'full';

/** Pre-defined schedule frequencies. */
export type ScheduleFrequency = 'hourly' | 'daily' | 'weekly' | 'monthly' | 'cron' | 'now';

/** Full representation of a scheduled scan record used by the cron engine. */
export interface CronSchedule {
  id: string;
  orgId: string;
  projectId: string;
  name: string;
  scanType: ScanType;
  schedule: ScheduleFrequency;
  cronExpression?: string;
  timezone: string;
  options: Record<string, unknown>;
  enabled: boolean;
  lastRun: string | null;
  nextRun: string | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

/** Runtime information about an active cron task, exposed for monitoring. */
export interface CronTaskInfo {
  scheduleId: string;
  name: string;
  frequency: ScheduleFrequency;
  cronExpression: string;
  timezone: string;
  enabled: boolean;
  isRunning: boolean;
  lastRun: string | null;
  nextRun: string | null;
}

/** Fields that can be passed to updateSchedule to alter the cron task in memory. */
export interface ScheduleUpdateData {
  schedule?: ScheduleFrequency;
  cronExpression?: string;
  timezone?: string;
  enabled?: boolean;
  options?: Record<string, unknown>;
  name?: string;
}

// ──────────────────────────────────────────────
// Internal State
// ──────────────────────────────────────────────

/** Map of schedule ID -> active cron task entry. */
const activeTasks = new Map<string, CronTaskEntry>();

/** Set of schedule IDs whose scan is currently being executed (overlap guard). */
const executingSchedules = new Set<string>();

interface CronTaskEntry {
  task: cron.ScheduledTask;
  schedule: CronSchedule;
}

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────

// 'now' is one-shot and never maps to a cron expression (registerTask returns
// early for it), so it is excluded from this recurring-frequency map.
const FREQUENCY_MAP: Record<Exclude<ScheduleFrequency, 'now'>, string> = {
  hourly: '0 * * * *',
  daily: '0 0 * * *',
  weekly: '0 0 * * 0',
  monthly: '0 0 1 * *',
  cron: '', // resolved dynamically from cronExpression
};

// ──────────────────────────────────────────────
// Helper Functions
// ──────────────────────────────────────────────

/**
 * Resolve the 5-field cron expression for a given schedule.
 * Throws if the schedule uses type 'cron' but no expression is set,
 * or if the expression fails validation.
 */
function resolveCronExpression(schedule: CronSchedule): string {
  if (schedule.schedule === 'cron') {
    if (!schedule.cronExpression) {
      throw new Error(
        `Schedule ${schedule.id} ("${schedule.name}") is type 'cron' but has no cronExpression`,
      );
    }
    if (!cron.validate(schedule.cronExpression)) {
      throw new Error(
        `Schedule ${schedule.id} ("${schedule.name}"): invalid cron expression "${schedule.cronExpression}"`,
      );
    }
    return schedule.cronExpression;
  }
  if (schedule.schedule === 'now') {
    // One-shot schedules are executed immediately, never registered as a cron job.
    throw new Error(`Schedule ${schedule.id} ("${schedule.name}") is one-shot (type=now) and has no cron expression`);
  }
  return FREQUENCY_MAP[schedule.schedule];
}

/**
 * Compute the next run time for a schedule using cron-parser.
 * Returns null if no future occurrence exists or parsing fails.
 */
function computeNextRunDate(schedule: CronSchedule): Date | null {
  try {
    const expression = resolveCronExpression(schedule);
    const interval = parseExpression(expression, {
      tz: schedule.timezone,
      currentDate: new Date(),
    });
    if (!interval.hasNext()) return null;
    return interval.next().toDate();
  } catch (err) {
    logger.warn(
      { err, scheduleId: schedule.id, name: schedule.name },
      'Failed to compute next run date',
    );
    return null;
  }
}

/**
 * Map a scan type to the BullMQ queue(s) that should process it.
 * A 'full' scan spawns all three scan types.
 */
function resolveQueues(scanType: ScanType): QueueName[] {
  switch (scanType) {
    case 'sast':
      return [QueueName.SAST_SCAN];
    case 'dast':
      return [QueueName.DAST_SCAN];
    case 'api':
      return [QueueName.API_SCAN];
    case 'sca':
      return [QueueName.SCA_SCAN];
    case 'secret':
      return [QueueName.SECRET_SCAN];
    case 'full':
      return [QueueName.SAST_SCAN, QueueName.DAST_SCAN, QueueName.API_SCAN, QueueName.SCA_SCAN, QueueName.SECRET_SCAN];
  }
}

/**
 * Build a ScanJob-compatible payload from a CronSchedule and the new scan ID.
 */
function buildScanJobPayload(
  schedule: CronSchedule,
  scanId: string,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    scanId,
    projectId: schedule.projectId,
    options: schedule.options,
    userId: schedule.createdBy,
    organizationId: schedule.orgId,
  };

  if (typeof schedule.options.targetUrl === 'string' && schedule.options.targetUrl) {
    payload.targetUrl = schedule.options.targetUrl;
  }
  if (typeof schedule.options.targetPath === 'string' && schedule.options.targetPath) {
    payload.targetPath = schedule.options.targetPath;
  }

  return payload;
}

/**
 * Build a CronSchedule object from a raw database row.
 */
function rowToSchedule(row: Record<string, unknown>): CronSchedule {
  return {
    id: row.id as string,
    orgId: row.org_id as string,
    projectId: row.project_id as string,
    name: row.name as string,
    scanType: row.scan_type as ScanType,
    schedule: row.schedule as ScheduleFrequency,
    cronExpression: (row.cron_expression as string) ?? undefined,
    timezone: (row.timezone as string) ?? 'UTC',
    options: (row.options as Record<string, unknown>) ?? {},
    enabled: row.enabled as boolean,
    lastRun: (row.last_run as string) ?? null,
    nextRun: (row.next_run as string) ?? null,
    createdBy: (row.created_by as string) ?? '',
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  };
}

// ──────────────────────────────────────────────
// Core Execution Logic
// ──────────────────────────────────────────────

/**
 * Execute a scheduled scan: create the scan record in the database,
 * enqueue the appropriate BullMQ job(s), and update the schedule metadata.
 *
 * If a scan for this schedule is already running (tracked via the overlap
 * guard), the execution is silently skipped and a warning is logged.
 */
async function executeScheduledScan(schedule: CronSchedule): Promise<void> {
  // ── Overlap guard ────────────────────────────────────────────
  if (executingSchedules.has(schedule.id)) {
    logger.warn(
      {
        scheduleId: schedule.id,
        name: schedule.name,
        scanType: schedule.scanType,
      },
      'Scheduled scan overlap detected — skipping this tick. A previous scan is still running.',
    );
    return;
  }

  executingSchedules.add(schedule.id);
  const scanId = uuidv4();
  const now = new Date();

  try {
    // ── 1. Insert a new scan record ─────────────────────────
    const metadata = JSON.stringify({ scheduled_scan_id: schedule.id });
    const optionsJson = JSON.stringify(schedule.options);

    await query(
      `INSERT INTO scans
         (id, org_id, project_id, scan_type, name, status, options, metadata, started_by, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, 'queued', $6, $7, $8, $9, $9)`,
      [
        scanId,
        schedule.orgId,
        schedule.projectId,
        schedule.scanType,
        `[Scheduled] ${schedule.name}`,
        optionsJson,
        metadata,
        schedule.createdBy || null,
        now,
      ],
    );

    // ── 2. Enqueue BullMQ job(s) ────────────────────────────
    const queues = resolveQueues(schedule.scanType);
    const jobPayload = buildScanJobPayload(schedule, scanId);

    for (const queueName of queues) {
      await queueManager.addJob(
        queueName,
        `scheduled-scan:${scanId}`,
        jobPayload,
        JobPriority.NORMAL,
      );
    }

    // ── 3. Update schedule metadata (last_run, next_run) ────
    const nextRun = computeNextRunDate(schedule);

    await query(
      `UPDATE scheduled_scans SET last_run = $1, next_run = $2, updated_at = $3 WHERE id = $4`,
      [now, nextRun, now, schedule.id],
    );

    logger.info(
      {
        scheduleId: schedule.id,
        scanId,
        name: schedule.name,
        scanType: schedule.scanType,
        queues: queues.map((q) => q.toString()),
        nextRun: nextRun?.toISOString() ?? null,
      },
      'Scheduled scan executed successfully',
    );
  } catch (err) {
    logger.error(
      { err, scheduleId: schedule.id, scanId, name: schedule.name },
      'Failed to execute scheduled scan',
    );
    throw err;
  } finally {
    executingSchedules.delete(schedule.id);
  }
}

// ──────────────────────────────────────────────
// Task Registration / Removal
// ──────────────────────────────────────────────

/**
 * Register a single CronSchedule as a node-cron task.
 * Schedules with type 'now' are ignored (they are one-shot).
 * Throws if the cron expression is invalid.
 */
function registerTask(schedule: CronSchedule): void {
  if (schedule.schedule === 'now') {
    logger.debug(
      { scheduleId: schedule.id, name: schedule.name },
      'Skipping registration for one-shot schedule (type=now)',
    );
    return;
  }

  const expression = resolveCronExpression(schedule);

  const task = cron.schedule(
    expression,
    () => {
      // Fire-and-forget — errors are caught inside executeScheduledScan
      executeScheduledScan(schedule).catch((err) => {
        logger.error(
          { err, scheduleId: schedule.id, name: schedule.name },
          'Unhandled error in scheduled scan execution callback',
        );
      });
    },
    {
      scheduled: false,
      timezone: schedule.timezone,
    },
  );

  activeTasks.set(schedule.id, { task, schedule });
  task.start();

  logger.info(
    {
      scheduleId: schedule.id,
      name: schedule.name,
      expression,
      timezone: schedule.timezone,
    },
    'Cron task registered',
  );
}

/**
 * Stop and destroy a cron task by schedule ID.
 * Safe to call even if no task is registered.
 */
function unregisterTask(scheduleId: string): void {
  const entry = activeTasks.get(scheduleId);
  if (!entry) return;

  try {
    // node-cron v3 ScheduledTask exposes stop() only (no destroy()).
    entry.task.stop();
  } catch (err) {
    logger.warn({ err, scheduleId }, 'Error while stopping cron task');
  }

  activeTasks.delete(scheduleId);
  executingSchedules.delete(scheduleId);

  logger.info({ scheduleId, name: entry.schedule.name }, 'Cron task removed');
}

// ──────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────

/**
 * Start the cron scheduler.
 *
 * Loads all enabled scheduled scans from the database and registers a
 * node-cron task for each recurring schedule. One-shot schedules
 * (type = 'now') are skipped during startup.
 */
export async function startScheduler(): Promise<void> {
  logger.info('Starting cron scheduler...');

  try {
    const result = await query(
      `SELECT * FROM scheduled_scans WHERE enabled = TRUE ORDER BY created_at ASC`,
    );

    let registeredCount = 0;

    for (const row of result.rows) {
      const schedule = rowToSchedule(row as Record<string, unknown>);

      if (schedule.schedule === 'now') {
        logger.info(
          { scheduleId: schedule.id, name: schedule.name },
          'Skipping one-shot schedule (type=now) during scheduler startup',
        );
        continue;
      }

      try {
        registerTask(schedule);
        registeredCount++;
      } catch (err) {
        logger.error(
          { err, scheduleId: schedule.id, name: schedule.name },
          'Failed to register cron task for schedule',
        );
      }
    }

    logger.info(
      { totalLoaded: result.rows.length, registered: registeredCount },
      'Cron scheduler started',
    );
  } catch (err) {
    logger.error({ err }, 'Failed to start cron scheduler');
    throw err;
  }
}

/**
 * Stop the cron scheduler.
 *
 * Destroys all active cron tasks and clears the overlap guard set.
 */
export function stopScheduler(): void {
  logger.info({ taskCount: activeTasks.size }, 'Stopping cron scheduler...');

  for (const scheduleId of activeTasks.keys()) {
    unregisterTask(scheduleId);
  }

  executingSchedules.clear();

  logger.info('Cron scheduler stopped');
}

/**
 * Dynamically add a new schedule without restarting the scheduler.
 *
 * The schedule record must already exist in the database. For recurring
 * schedules a node-cron task is registered. For one-shot schedules
 * (type = 'now') the scan is executed immediately.
 *
 * If a task for the same schedule ID is already registered, the call
 * is a no-op (a warning is logged).
 */
export function addSchedule(schedule: CronSchedule): void {
  if (activeTasks.has(schedule.id)) {
    logger.warn(
      { scheduleId: schedule.id, name: schedule.name },
      'Schedule already registered — skipping duplicate',
    );
    return;
  }

  if (schedule.schedule === 'now') {
    logger.info(
      { scheduleId: schedule.id, name: schedule.name },
      'One-shot schedule (type=now) — executing immediately',
    );
    executeScheduledScan(schedule).catch((err) => {
      logger.error(
        { err, scheduleId: schedule.id, name: schedule.name },
        'One-shot scheduled scan execution failed',
      );
    });
    return;
  }

  try {
    registerTask(schedule);
  } catch (err) {
    logger.error(
      { err, scheduleId: schedule.id, name: schedule.name },
      'Failed to add schedule to cron scheduler',
    );
    throw err;
  }
}

/**
 * Remove a schedule by its ID.
 *
 * Stops and destroys the associated cron task if active. Does not touch
 * the database record — the caller is responsible for that.
 */
export function removeSchedule(scheduleId: string): void {
  unregisterTask(scheduleId);
}

/**
 * Update a schedule's timing configuration without restarting the scheduler.
 *
 * This method expects the caller to have already persisted the changes to
 * the database (e.g., via the PATCH endpoint). It re-reads the current
 * database record to register a new cron task.
 *
 * If the update disables the schedule or sets it to 'now', any existing
 * cron task is removed and not re-registered.
 *
 * @param scheduleId - The ID of the schedule to update.
 * @param updates    - Partial schedule fields used to decide re-registration
 *                     (enabled, schedule type). The actual timing values
 *                     are re-read from the database.
 */
export async function updateSchedule(
  scheduleId: string,
  updates: ScheduleUpdateData,
): Promise<void> {
  // Remove the old cron task regardless (no-op if none exists)
  unregisterTask(scheduleId);

  // If the schedule was disabled or changed to one-shot, don't re-register
  if (updates.enabled === false || updates.schedule === 'now') {
    logger.info(
      {
        scheduleId,
        enabled: updates.enabled,
        schedule: updates.schedule,
      },
      'Schedule disabled or set to one-shot — cron task not re-registered',
    );
    return;
  }

  try {
    const result = await query(
      'SELECT * FROM scheduled_scans WHERE id = $1',
      [scheduleId],
    );

    if (result.rows.length === 0) {
      logger.warn({ scheduleId }, 'Schedule not found in database — cannot re-register');
      return;
    }

    const schedule = rowToSchedule(result.rows[0] as Record<string, unknown>);

    // Double-check the stored record — if it's now disabled or 'now', skip
    if (!schedule.enabled || schedule.schedule === 'now') {
      logger.info(
        { scheduleId, enabled: schedule.enabled, schedule: schedule.schedule },
        'Updated schedule is disabled or one-shot — not registering cron task',
      );
      return;
    }

    registerTask(schedule);
  } catch (err) {
    logger.error({ err, scheduleId }, 'Failed to update schedule in cron scheduler');
    throw err;
  }
}

/**
 * Return runtime information about all active cron tasks.
 *
 * Useful for health checks, monitoring, and the dashboard.
 */
export function getActiveTasks(): CronTaskInfo[] {
  const tasks: CronTaskInfo[] = [];

  for (const [scheduleId, entry] of activeTasks) {
    const s = entry.schedule;
    tasks.push({
      scheduleId,
      name: s.name,
      frequency: s.schedule,
      cronExpression: resolveCronExpression(s),
      timezone: s.timezone,
      enabled: s.enabled,
      isRunning: executingSchedules.has(scheduleId),
      lastRun: s.lastRun,
      nextRun: s.nextRun,
    });
  }

  return tasks;
}

/**
 * Check whether a scan for the given schedule is currently being executed.
 *
 * This reflects the in-memory overlap guard state and is primarily useful
 * for monitoring and debugging.
 */
export function isScheduleExecuting(scheduleId: string): boolean {
  return executingSchedules.has(scheduleId);
}
