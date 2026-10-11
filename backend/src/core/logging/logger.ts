import pino from 'pino';
import { getConfig } from '../../config/index.js';

const config = getConfig();

export const logger = pino({
  level: config.LOG_LEVEL,
  name: 'appsec-platform',
  formatters: {
    level(label) {
      return { level: label };
    },
    bindings(bindings) {
      return {
        pid: bindings.pid,
        host: bindings.hostname,
        service: 'backend',
      };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      'password',
      'token',
      'authorization',
      'cookie',
      'secret',
      'apiKey',
      '*.password',
      '*.token',
      '*.secret',
      '*.apiKey',
    ],
    censor: '***REDACTED***',
  },
  serializers: {
    req: (req) => ({
      id: req.id,
      method: req.method,
      url: req.url,
      remoteAddress: req.remoteAddress,
      userAgent: req.headers?.['user-agent'],
    }),
    res: (res) => ({
      statusCode: res.statusCode,
    }),
    err: pino.stdSerializers.err,
  },
  transport: config.NODE_ENV === 'development'
    ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'SYS:HH:MM:ss' } }
    : undefined,
});

export function createChildLogger(context: Record<string, unknown>) {
  return logger.child(context);
}

export type AppLogger = typeof logger;
