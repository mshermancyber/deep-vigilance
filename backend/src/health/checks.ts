// Health check system — validates all service dependencies
import { testConnection as testDB } from '../core/db/pool.js';
import { getRedis } from '../core/redis/client.js';
import { queueManager } from '../core/queue/manager.js';
import { APP_VERSION } from '../version.js';

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  uptime: number;
  memory: { heapUsed: number; heapTotal: number; rss: number };
  checks: Record<string, { status: string; latency?: number; error?: string }>;
}

export async function getFullHealth(): Promise<HealthStatus> {
  const checks: Record<string, { status: string; latency?: number; error?: string }> = {};
  let overall: HealthStatus['status'] = 'healthy';

  // Database check
  const dbStart = Date.now();
  try { const ok = await testDB(); checks.database = { status: ok ? 'ok' : 'error', latency: Date.now() - dbStart }; if (!ok) overall = 'degraded'; }
  catch (e) { checks.database = { status: 'error', error: String(e) }; overall = 'unhealthy'; }

  // Redis check
  try { const r = getRedis(); await r.ping(); checks.redis = { status: 'ok' }; } catch (e) { checks.redis = { status: 'error', error: String(e) }; if (overall === 'healthy') overall = 'degraded'; }

  // Queue check
  try {
    await queueManager.getQueueStats('sast-scan' as any);
    checks.queue = { status: 'ok', latency: 0 };
  } catch (e) { checks.queue = { status: 'error', error: String(e) }; }

  return { status: overall, timestamp: new Date().toISOString(), version: APP_VERSION, uptime: process.uptime(), memory: process.memoryUsage(), checks };
}

export async function getLiveness(): Promise<{ status: string }> {
  return { status: 'alive' };
}

export async function getReadiness(): Promise<{ ready: boolean; checks: Record<string, boolean> }> {
  const dbOk = await testDB();
  return { ready: dbOk, checks: { database: dbOk } };
}
