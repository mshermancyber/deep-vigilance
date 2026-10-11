// Database migration runner — applies all migrations in order
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { getPool } from '../core/db/pool.js';
import { logger } from '../core/logging/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Resolve the migrations directory across environments: repo/dev layout,
// the bundled location inside the backend image (/app/postgres/migrations),
// and an explicit override.
function resolveMigrationsDir(): string | null {
  const candidates = [
    process.env.MIGRATIONS_DIR,
    path.resolve(__dirname, '..', '..', '..', 'postgres', 'migrations'), // repo: backend/dist/migrations -> repo/postgres
    path.resolve(__dirname, '..', '..', 'postgres', 'migrations'),       // image: /app/dist/migrations -> /app/postgres
    path.resolve(process.cwd(), 'postgres', 'migrations'),
  ].filter(Boolean) as string[];
  return candidates.find((d) => fs.existsSync(d)) ?? null;
}

export async function runMigrations(): Promise<void> {
  const MIGRATIONS_DIR = resolveMigrationsDir();
  if (!MIGRATIONS_DIR) {
    // Fail soft: never crash startup over missing migration files. Apply them
    // via `npm run migrate` from a checkout, or ensure they are bundled in the image.
    logger.error('Migrations directory not found — skipping auto-migrate. Run `npm run migrate` or bundle postgres/migrations into the image.');
    return;
  }
  const pool = getPool();
  logger.info({ dir: MIGRATIONS_DIR }, 'Running database migrations');

  const files = fs.readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort();
  logger.info({ count: files.length, files }, 'Migration files found');

  // Create migrations tracking table if not exists
  await pool.query(`CREATE TABLE IF NOT EXISTS _migrations (id SERIAL PRIMARY KEY, filename VARCHAR(255) UNIQUE NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);

  for (const file of files) {
    const { rows } = await pool.query('SELECT id FROM _migrations WHERE filename = $1', [file]);
    if (rows.length > 0) { logger.info({ file }, 'Migration already applied — skipped'); continue; }

    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf-8');
    logger.info({ file }, 'Applying migration');

    try {
      await pool.query(sql);
      await pool.query('INSERT INTO _migrations (filename) VALUES ($1)', [file]);
      logger.info({ file }, 'Migration applied successfully');
    } catch (err) {
      logger.error({ file, err }, 'Migration failed');
      throw err;
    }
  }

  logger.info('All migrations complete');
}

// Only self-execute (and exit) when invoked directly as a CLI (`npm run migrate`),
// not when imported by the server for startup migrations.
const isMain = !!process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  runMigrations()
    .then(() => { logger.info('Migration runner complete'); process.exit(0); })
    .catch((err) => { logger.error({ err }, 'Migration runner failed'); process.exit(1); });
}
