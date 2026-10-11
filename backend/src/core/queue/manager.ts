import { Queue, Worker, Job, QueueEvents } from 'bullmq';
import { getConfig } from '../../config/index.js';
import { logger } from '../logging/logger.js';
import { query } from '../db/pool.js';

export enum QueueName {
SAST_SCAN = 'sast-scan',
DAST_SCAN = 'dast-scan',
API_SCAN = 'api-scan',
SCA_SCAN = 'sca-scan',
SECRET_SCAN = 'secret-scan',
REPORT_GENERATION = 'report-generation',
NOTIFICATION = 'notification',
SCHEDULED_TASK = 'scheduled-task',
CODE_REVIEW = 'code-review',
}

export enum JobPriority {
  LOW = 10,
  NORMAL = 5,
  HIGH = 2,
  CRITICAL = 1,
}

export interface ScanJob {
  scanId: string;
  projectId: string;
  targetUrl?: string;
  targetPath?: string;
  options: Record<string, unknown>;
  userId: string;
  organizationId: string;
}

export interface ReportJob {
  reportId: string;
  projectId: string;
  templateType: string;
  format: 'pdf' | 'html' | 'json' | 'csv' | 'markdown';
  filters: Record<string, unknown>;
  userId: string;
}

export interface NotificationJob {
  type: 'email' | 'slack' | 'teams' | 'discord' | 'webhook';
  target: string;
  payload: Record<string, unknown>;
  userId?: string;
}

const connection = {
  host: getConfig().REDIS_HOST,
  port: getConfig().REDIS_PORT,
  password: getConfig().REDIS_PASSWORD,
};

const defaultJobOptions = {
  removeOnComplete: { age: 7 * 24 * 3600 },
  removeOnFail: { age: 30 * 24 * 3600 },
  attempts: 3,
  backoff: {
    type: 'exponential' as const,
    delay: 5000,
  },
};

const SCAN_QUEUES = new Set<QueueName>([
QueueName.SAST_SCAN,
QueueName.DAST_SCAN,
QueueName.API_SCAN,
QueueName.SCA_SCAN,
QueueName.SECRET_SCAN,
]);

class QueueManager {
  private queues: Map<QueueName, Queue> = new Map();
  private events: Map<QueueName, QueueEvents> = new Map();
  private workers: Map<QueueName, Worker> = new Map();

  getQueue(name: QueueName): Queue {
    if (!this.queues.has(name)) {
      const queue = new Queue(name, {
        connection,
        defaultJobOptions,
      });
      this.queues.set(name, queue);

      // Note: BullMQ v2+ removed QueueScheduler; delayed/stalled job handling
      // is now built into Worker, so no separate scheduler is required.
      const events = new QueueEvents(name, { connection });
      this.events.set(name, events);

      events.on('completed', ({ jobId, returnvalue }) => {
        logger.info({ queue: name, jobId }, 'Job completed');
        if (SCAN_QUEUES.has(name)) {
          this.reconcileScanCompletion(queue, name, jobId, returnvalue as unknown as Record<string, unknown> | undefined)
            .catch((err) => {
              logger.error({ queue: name, jobId, err }, 'Reconciliation handler error');
            });
        }
      });

      events.on('failed', ({ jobId, failedReason }) => {
        logger.error({ queue: name, jobId, failedReason }, 'Job failed');
      });

      logger.info({ queue: name }, 'Queue initialized');
    }
    return this.queues.get(name)!;
  }

  async addJob<T extends Record<string, unknown>>(
    queueName: QueueName,
    name: string,
    data: T,
    priority: JobPriority = JobPriority.NORMAL,
  ): Promise<Job<T>> {
    const queue = this.getQueue(queueName);
    // Deterministic jobId (derived from name) so jobs can be located for
    // cancellation and to dedupe accidental duplicate enqueues of the same
    // resource. BullMQ forbids ':' in a custom job id (Redis key separator),
    // so sanitize it — the human-readable job name keeps its original form.
    const jobId = name.replace(/:/g, '-');
    const job = await queue.add(name, data, { priority, jobId });
    logger.info({ queue: queueName, jobId: job.id, name }, 'Job added to queue');
    return job as Job<T>;
  }

  async addBulk<T extends Record<string, unknown>>(
    queueName: QueueName,
    jobs: Array<{ name: string; data: T; priority?: JobPriority }>,
  ): Promise<Job<T>[]> {
    const queue = this.getQueue(queueName);
    const addedJobs = await queue.addBulk(
      jobs.map((j) => ({
        name: j.name,
        data: j.data,
        opts: { priority: j.priority ?? JobPriority.NORMAL, jobId: j.name.replace(/:/g, '-') },
      })),
    );
    logger.info({ queue: queueName, count: addedJobs.length }, 'Bulk jobs added');
    return addedJobs as Job<T>[];
  }

  async getJob(queueName: QueueName, jobId: string): Promise<Job | null> {
    const queue = this.getQueue(queueName);
    return (await queue.getJob(jobId)) ?? null;
  }

  async cancelJob(queueName: QueueName, jobId: string): Promise<void> {
    const job = await this.getJob(queueName, jobId);
    if (job) {
      await job.remove();
      logger.info({ queue: queueName, jobId }, 'Job cancelled');
    }
  }

  async pauseQueue(queueName: QueueName): Promise<void> {
    const queue = this.getQueue(queueName);
    await queue.pause();
    logger.info({ queue: queueName }, 'Queue paused');
  }

  async resumeQueue(queueName: QueueName): Promise<void> {
    const queue = this.getQueue(queueName);
    await queue.resume();
    logger.info({ queue: queueName }, 'Queue resumed');
  }

  async getQueueStats(queueName: QueueName): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
    delayed: number;
  }> {
    const queue = this.getQueue(queueName);
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      queue.getWaitingCount(),
      queue.getActiveCount(),
      queue.getCompletedCount(),
      queue.getFailedCount(),
      queue.getDelayedCount(),
    ]);
    return { waiting, active, completed, failed, delayed };
  }

  async cleanOldJobs(queueName: QueueName, olderThanMs: number): Promise<void> {
    const queue = this.getQueue(queueName);
    await queue.clean(olderThanMs, 1000, 'completed');
    await queue.clean(olderThanMs, 1000, 'failed');
  }

  private async reconcileScanCompletion(
    queue: Queue,
    queueName: QueueName,
    jobId: string,
    returnvalue: Record<string, unknown> | undefined,
  ): Promise<void> {
    try {
      const job = await queue.getJob(jobId);
      if (!job) {
        logger.warn({ queue: queueName, jobId }, 'Job not found for reconciliation');
        return;
      }

      const scanId = job.data?.scanId as string | undefined;
      if (!scanId) {
        logger.warn({ queue: queueName, jobId }, 'No scanId in job data, skipping reconciliation');
        return;
      }

      const result = await query<{ status: string; findings_count: number }>(
        'SELECT status, findings_count FROM scans WHERE id = $1',
        [scanId],
      );

      if (result.rows.length === 0) {
        logger.warn({ queue: queueName, jobId, scanId }, 'Scan not found in database');
        return;
      }

      const row = result.rows[0]!;
      const { status: previousStatus } = row;

      // Idempotent: only reconcile if still queued or running
      if (previousStatus !== 'queued' && previousStatus !== 'running') {
        return;
      }

      const findingsCount =
        (returnvalue?.findingsCount as number) ??
        (returnvalue?.totalFindings as number) ??
        0;

      logger.warn({ scanId, previousStatus, queue: queueName, jobId }, 'Reconciling scan completion');

      await query(
        `UPDATE scans SET status = 'completed', completed_at = NOW(), updated_at = NOW(),
          findings_count = COALESCE(findings_count, $2)
         WHERE id = $1`,
        [scanId, findingsCount],
      );
    } catch (err) {
      logger.error({ queue: queueName, jobId, err }, 'Scan completion reconciliation error');
    }
  }

  async closeAll(): Promise<void> {
    for (const worker of this.workers.values()) {
      await worker.close();
    }
    for (const events of this.events.values()) {
      await events.close();
    }
    for (const queue of this.queues.values()) {
      await queue.close();
    }
    logger.info('All queues closed');
  }
}

export const queueManager = new QueueManager();
