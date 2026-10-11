import Redis from 'ioredis';
import { getConfig } from '../../config/index.js';
import { logger } from '../logging/logger.js';

let redisClient: Redis | null = null;
let redisSubscriber: Redis | null = null;

export function createRedisClient(): Redis {
  if (redisClient) return redisClient;

  const config = getConfig();

  redisClient = new Redis({
    host: config.REDIS_HOST,
    port: config.REDIS_PORT,
    password: config.REDIS_PASSWORD,
    retryStrategy(times) {
      const delay = Math.min(times * 200, 5000);
      logger.warn({ times, delay }, 'Redis connection retry');
      return delay;
    },
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    lazyConnect: false,
    connectTimeout: 10000,
    keepAlive: 30000,
    family: 4,
  });

  redisClient.on('connect', () => logger.info('Redis connected'));
  redisClient.on('ready', () => logger.info('Redis ready'));
  redisClient.on('error', (err) => logger.error({ err }, 'Redis error'));
  redisClient.on('close', () => logger.warn('Redis connection closed'));

  return redisClient;
}

export function createRedisSubscriber(): Redis {
  if (redisSubscriber) return redisSubscriber;

  redisSubscriber = createRedisClient().duplicate();

  redisSubscriber.on('connect', () => logger.info('Redis subscriber connected'));
  redisSubscriber.on('error', (err) => logger.error({ err }, 'Redis subscriber error'));

  return redisSubscriber;
}

export function getRedis(): Redis {
  if (!redisClient) return createRedisClient();
  return redisClient;
}

export function getRedisSubscriber(): Redis {
  if (!redisSubscriber) return createRedisSubscriber();
  return redisSubscriber;
}

export async function closeRedis(): Promise<void> {
  if (redisSubscriber) {
    await redisSubscriber.quit();
    redisSubscriber = null;
  }
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
  }
  logger.info('Redis connections closed');
}

export async function cacheGet<T>(key: string): Promise<T | null> {
  const redis = getRedis();
  const value = await redis.get(key);
  if (!value) return null;
  try {
    return JSON.parse(value) as T;
  } catch {
    return value as unknown as T;
  }
}

export async function cacheSet(
  key: string,
  value: unknown,
  ttlSeconds: number = 300,
): Promise<void> {
  const redis = getRedis();
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  if (ttlSeconds > 0) {
    await redis.setex(key, ttlSeconds, serialized);
  } else {
    await redis.set(key, serialized);
  }
}

export async function cacheDelete(key: string): Promise<void> {
  const redis = getRedis();
  await redis.del(key);
}

export async function cacheDeletePattern(pattern: string): Promise<void> {
  const redis = getRedis();
  const keys = await redis.keys(pattern);
  if (keys.length > 0) {
    await redis.del(...keys);
  }
}
