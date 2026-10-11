import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('production'),
  DB_HOST: z.string().default('postgres'),
  DB_PORT: z.coerce.number().default(5432),
  DB_NAME: z.string().default('appsec_platform'),
  DB_USER: z.string().default('appsec_user'),
  DB_PASSWORD: z.string().min(1),
  // Enable TLS to PostgreSQL. Leave false for the internal (encrypted) docker
  // network where the containerized postgres has no TLS; set true for an external
  // managed database that requires SSL (then certs are verified).
  DB_SSL: z.string().default('false').transform((v) => v === 'true' || v === '1'),
  REDIS_HOST: z.string().default('redis'),
  REDIS_PORT: z.coerce.number().default(6379),
  REDIS_PASSWORD: z.string().min(1),
  JWT_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),
  ENCRYPTION_KEY: z.string().length(32),
  API_PORT: z.coerce.number().default(3000),
  WS_PORT: z.coerce.number().default(3001),
  CORS_ORIGIN: z.string().default('https://localhost'),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(1000),
  SMTP_HOST: z.string().default('mailhog'),
  SMTP_PORT: z.coerce.number().default(1025),
  SMTP_USER: z.string().default(''),
  SMTP_PASS: z.string().default(''),
  SMTP_FROM: z.string().default('noreply@example.com'),
  CHROMIUM_URL: z.string().default('http://chromium:9222'),
  SCANNER_API_URL: z.string().default('https://backend:3000'),
  SCAN_MAX_RUNTIME_MIN: z.coerce.number().default(30),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

  // ── Retention / cleanup jobs ───────────────────────────────────────────────
  // How often the housekeeping cycle runs. 0 disables cleanup entirely.
  CLEANUP_INTERVAL_MIN: z.coerce.number().int().min(0).default(360),
  // Age thresholds in days. 0 means "never prune this table".
  RETAIN_SCANS_DAYS: z.coerce.number().int().min(0).default(90),
  RETAIN_AUDIT_LOG_DAYS: z.coerce.number().int().min(0).default(365),
  RETAIN_REPORTS_DAYS: z.coerce.number().int().min(0).default(90),
  RETAIN_NOTIFICATIONS_DAYS: z.coerce.number().int().min(0).default(30),
  RETAIN_CODE_REVIEWS_DAYS: z.coerce.number().int().min(0).default(90),
  RETAIN_API_HISTORY_DAYS: z.coerce.number().int().min(0).default(30),
  RETAIN_WEBHOOK_DLQ_DAYS: z.coerce.number().int().min(0).default(30),
  // Completed/failed BullMQ jobs older than this are trimmed from Redis.
  RETAIN_QUEUE_JOBS_DAYS: z.coerce.number().int().min(0).default(7),
  // Generated report files under REPORT_DIR older than RETAIN_REPORTS_DAYS are
  // deleted alongside their DB rows.
  REPORT_DIR: z.string().default('/data/reports'),
  // Rows deleted per statement, so a first run on a large DB does not lock the
  // table for minutes at a time.
  CLEANUP_BATCH_SIZE: z.coerce.number().int().min(100).max(100000).default(5000),
  // Safety rail: refuse a cycle that would delete more than this share of a
  // table (guards against a misconfigured retention window wiping live data).
  CLEANUP_MAX_TABLE_FRACTION: z.coerce.number().min(0).max(1).default(0.5),
});

export type EnvConfig = z.infer<typeof envSchema>;

let cachedConfig: EnvConfig | null = null;

// Substrings that mark a value as a placeholder/dev default rather than a real secret.
const WEAK_SECRET_MARKERS = [
  'change_in_production', 'change-in-production', 'changeme', 'change_me',
  'placeholder', 'example', 'your_', 'replace_me', 'default',
];

// Exact dev-default values shipped in the sample .env — never valid in production.
const KNOWN_DEFAULT_SECRETS = new Set([
  'aes256_encryption_key_32_bytes_!!',
  'appsec_secure_password_2024',
  'redis_secure_password_2024',
  'chrome_internal_token',
  'Admin123!@#ChangeMe',
]);

function isWeakSecret(value: string | undefined): boolean {
  if (!value) return false;
  const lower = value.toLowerCase();
  if (KNOWN_DEFAULT_SECRETS.has(value)) return true;
  return WEAK_SECRET_MARKERS.some((m) => lower.includes(m));
}

function assertProductionSecrets(cfg: EnvConfig): void {
  if (cfg.NODE_ENV !== 'production') {
    // In non-production, warn but allow dev defaults.
    const devCandidates: Array<[string, string | undefined]> = [
      ['JWT_SECRET', cfg.JWT_SECRET], ['JWT_REFRESH_SECRET', cfg.JWT_REFRESH_SECRET],
      ['ENCRYPTION_KEY', cfg.ENCRYPTION_KEY], ['DB_PASSWORD', cfg.DB_PASSWORD],
      ['REDIS_PASSWORD', cfg.REDIS_PASSWORD], ['ADMIN_PASSWORD', process.env.ADMIN_PASSWORD],
      ['CHROMIUM_TOKEN', process.env.CHROMIUM_TOKEN],
    ];
    for (const [name, val] of devCandidates) {
      if (isWeakSecret(val)) console.warn(`⚠️  ${name} uses a known dev/default value — must be replaced before production.`);
    }
    return;
  }

  const checks: Array<[string, string | undefined]> = [
    ['JWT_SECRET', cfg.JWT_SECRET],
    ['JWT_REFRESH_SECRET', cfg.JWT_REFRESH_SECRET],
    ['ENCRYPTION_KEY', cfg.ENCRYPTION_KEY],
    ['DB_PASSWORD', cfg.DB_PASSWORD],
    ['REDIS_PASSWORD', cfg.REDIS_PASSWORD],
    ['ADMIN_PASSWORD', process.env.ADMIN_PASSWORD],
    ['CHROMIUM_TOKEN', process.env.CHROMIUM_TOKEN],
  ];
  const offenders = checks.filter(([, v]) => isWeakSecret(v)).map(([n]) => n);
  if (cfg.JWT_SECRET === cfg.JWT_REFRESH_SECRET) offenders.push('JWT_REFRESH_SECRET (must differ from JWT_SECRET)');
  if (offenders.length > 0) {
    console.error(`❌ Refusing to start in production with weak/default secrets: ${offenders.join(', ')}. Set strong, unique values.`);
    process.exit(1);
  }
}

export function loadConfig(): EnvConfig {
  if (cachedConfig) return cachedConfig;

  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    console.error('❌ Invalid environment configuration:', result.error.format());
    process.exit(1);
  }

  assertProductionSecrets(result.data);

  cachedConfig = result.data;
  return cachedConfig;
}

export function getConfig(): EnvConfig {
  if (!cachedConfig) return loadConfig();
  return cachedConfig;
}

export const config = {
  get isProduction(): boolean {
    return getConfig().NODE_ENV === 'production';
  },
  get isDevelopment(): boolean {
    return getConfig().NODE_ENV === 'development';
  },
  get isTest(): boolean {
    return getConfig().NODE_ENV === 'test';
  },
};
