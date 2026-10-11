import https from 'https';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import { Server as WebSocketServer } from 'socket.io';
import { getConfig } from './config/index.js';
import { logger } from './core/logging/logger.js';
import { testConnection } from './core/db/pool.js';
import { startReaper } from './core/reaper.js';
import { startCleanupJobs } from './core/cleanup.js';
import { createRedisClient } from './core/redis/client.js';
import { buildRouter } from './api/router.js';
import { errorHandler, notFoundHandler } from './core/errors/handler.js';
import { authMiddleware } from './middleware/auth.js';
import { auditLogger } from './middleware/audit.js';
import { requestIdMiddleware } from './middleware/request-id.js';
import { rateLimiter } from './middleware/rate-limiter.js';
import { securityHeaders } from './middleware/security.js';
import { csrfProtection } from './middleware/csrf.js';
import { setupWebSocket } from './websocket/ws-server.js';
import { initializePlatform } from './init.js';
import { runMigrations } from './migrations/run.js';
import { APP_VERSION } from './version.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const config = getConfig();

// CORS origin: `*` (or empty) reflects the request origin so the app works from any
// host/IP (localhost, a private-network address, a phone) — credentials stay enabled because the
// origin is reflected, not literally `*`. Restrict exposure with a network firewall.
// A comma-separated list pins specific origins.
function resolveCorsOrigin(): boolean | string[] {
  const o = (config.CORS_ORIGIN || '').trim();
  if (!o || o === '*') return true;
  return o.split(',').map((s) => s.trim()).filter(Boolean);
}
const corsOrigin = resolveCorsOrigin();

function loadSSLOptions(): https.ServerOptions {
  const certDir = path.resolve(__dirname, '..', 'certs');
  const keyPath = path.join(certDir, 'internal.key');
  const certPath = path.join(certDir, 'internal.crt');

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    return {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
      minVersion: 'TLSv1.2',
      ciphers: [
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-CHACHA20-POLY1305',
        'ECDHE-RSA-CHACHA20-POLY1305',
      ].join(':'),
      honorCipherOrder: true,
    };
  }

  logger.warn('SSL certificates not found, falling back to HTTP only');
  return {};
}

function createApp(): express.Application {
  const app = express();

  app.set('trust proxy', 1);

  app.use(requestIdMiddleware);

  app.use(morgan('combined', {
    stream: { write: (msg: string) => logger.info({ component: 'http' }, msg.trim()) },
  }));

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'", 'wss:', 'https:'],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
  }));

  app.use(securityHeaders);

  app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (_req, res) => {
      if (res.getHeader('Content-Type')?.toString().includes('image')) return false;
      return compression.filter(_req, res);
    },
  }));

  app.use(cors({
    origin: corsOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-API-Key',
      'X-CSRF-Token',
      'X-Request-ID',
    ],
    exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
    maxAge: 86400,
  }));

  app.use(express.json({
    limit: '10mb',
    verify: (_req, _res, buf: Buffer) => {
      try { JSON.parse(buf.toString()); } catch { throw new Error('Invalid JSON'); }
    },
  }));

  app.use(express.urlencoded({ extended: true, limit: '10mb' }));
  app.use(cookieParser());

  app.use(rateLimiter);

  app.use(auditLogger);

  app.get('/api/health', async (_req, res) => {
    const dbOk = await testConnection();
    res.status(dbOk ? 200 : 503).json({
      status: dbOk ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      version: APP_VERSION,
      checks: {
        database: dbOk ? 'ok' : 'error',
      },
    });
  });

  app.get('/api/health/liveness', (_req, res) => {
    res.status(200).json({ status: 'alive' });
  });

  app.get('/api/health/readiness', async (_req, res) => {
    const dbOk = await testConnection();
    res.status(dbOk ? 200 : 503).json({ ready: dbOk });
  });

  app.use(authMiddleware);
  app.use(csrfProtection);

  const apiRouter = buildRouter();
  app.use('/api', apiRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

async function startServer(): Promise<void> {
  logger.info({ env: config.NODE_ENV }, 'Starting Application Security Platform...');

  await createRedisClient();
  logger.info('Redis connected');

  const dbOk = await testConnection();
  if (!dbOk) {
    logger.error('Database connection failed — exiting');
    process.exit(1);
  }

  // Apply pending DB migrations on every startup (idempotent — tracked in
  // _migrations). This guarantees schema fixes reach every environment, not
  // just whoever remembers to run `npm run migrate`.
  await runMigrations();

  // Initialize platform (creates default org/admin if first run)
  await initializePlatform();

  // Stuck-scan reaper — the API server is the always-on process, so start it
  // here (workers/main.ts is a separate entry the backend container doesn't run).
  startReaper();

  // Retention / housekeeping jobs — same reasoning as the reaper: this is the
  // always-on process. Disabled when CLEANUP_INTERVAL_MIN=0.
  startCleanupJobs();

  const app = createApp();
  const sslOptions = loadSSLOptions();

  let httpServer: http.Server | https.Server;
  const hasSSL = sslOptions.key && sslOptions.cert;

  if (hasSSL) {
    httpServer = https.createServer(sslOptions, app);
    httpServer.listen(config.API_PORT, () => {
      logger.info({ port: config.API_PORT }, 'HTTPS API server listening');
    });
  } else {
    httpServer = http.createServer(app);
    httpServer.listen(config.API_PORT, () => {
      logger.info({ port: config.API_PORT }, 'HTTP API server listening');
    });
  }

  const wss = new WebSocketServer(httpServer, {
    cors: { origin: corsOrigin, methods: ['GET', 'POST'], credentials: true },
    pingInterval: 30000,
    pingTimeout: 10000,
    connectTimeout: 10000,
    maxHttpBufferSize: 1e6,
    transports: ['websocket', 'polling'],
  });

  setupWebSocket(wss);
  logger.info({ port: config.WS_PORT }, 'WebSocket server ready');

  httpServer.keepAliveTimeout = 65000;
  httpServer.headersTimeout = 66000;

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutdown signal received');
    httpServer.close(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });
    setTimeout(() => {
      logger.warn('Forced shutdown after timeout');
      process.exit(1);
    }, 15000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => {
    logger.error({ err: reason }, 'Unhandled rejection');
  });
  process.on('uncaughtException', (err) => {
    logger.error({ err }, 'Uncaught exception — shutting down');
    process.exit(1);
  });
}

startServer().catch((err) => {
  logger.error({ err }, 'Failed to start server');
  process.exit(1);
});

export { createApp };
