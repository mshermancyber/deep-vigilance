import pg from 'pg';
import { getConfig } from '../../config/index.js';
import { logger } from '../logging/logger.js';

const { Pool } = pg;

let poolInstance: pg.Pool | null = null;

export function createPool(): pg.Pool {
  if (poolInstance) return poolInstance;

  const config = getConfig();

  poolInstance = new Pool({
    host: config.DB_HOST,
    port: config.DB_PORT,
    database: config.DB_NAME,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
    max: 50,
    min: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    statement_timeout: 60000,
    application_name: 'appsec-backend',
    ssl: config.DB_SSL ? { rejectUnauthorized: true } : false,
  });

  poolInstance.on('error', (err: Error) => {
    logger.error({ err }, 'Unexpected database pool error');
  });

  poolInstance.on('connect', () => {
    logger.debug('New database connection established');
  });

  return poolInstance;
}

export function getPool(): pg.Pool {
  if (!poolInstance) return createPool();
  return poolInstance;
}

export async function testConnection(): Promise<boolean> {
  try {
    const pool = getPool();
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    logger.info('Database connection verified successfully');
    return true;
  } catch (err) {
    logger.error({ err }, 'Database connection test failed');
    return false;
  }
}

export async function closePool(): Promise<void> {
  if (poolInstance) {
    await poolInstance.end();
    poolInstance = null;
    logger.info('Database pool closed');
  }
}

export async function query<T extends pg.QueryResultRow = Record<string, unknown>>(
  text: string,
  params?: unknown[],
): Promise<pg.QueryResult<T>> {
  const pool = getPool();
  const start = Date.now();
  try {
    const result = await pool.query<T>(text, params);
    const duration = Date.now() - start;
    if (duration > 1000) {
      logger.warn({ duration, query: text.slice(0, 200) }, 'Slow query detected');
    }
    return result;
  } catch (err) {
    logger.error({ err, query: text.slice(0, 200), params }, 'Database query failed');
    throw err;
  }
}

export async function transaction<T>(
  callback: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}
