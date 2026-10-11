import { Request, Response, NextFunction } from 'express';
import { logger } from '../core/logging/logger.js';

export interface AuditEntry {
  requestId: string;
  userId?: string;
  orgId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  method: string;
  path: string;
  statusCode: number;
  ip: string;
  userAgent?: string;
  changes?: Record<string, unknown>;
  timestamp: string;
  duration: number;
}

const auditLog = logger.child({ component: 'audit' });

export function auditLogger(req: Request, res: Response, next: NextFunction): void {
  const startTime = Date.now();

  const originalJson = res.json.bind(res);
  res.json = function (body: unknown) {
    (res as any).__responseBody = body;
    return originalJson(body);
  };

  res.on('finish', () => {
    const duration = Date.now() - startTime;

    if (req.path.startsWith('/api/health')) return;

    const entry: AuditEntry = {
      requestId: req.requestId,
      userId: req.userId,
      orgId: req.orgId,
      action: `${req.method} ${req.route?.path || req.path}`,
      resource: req.baseUrl + req.path,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      ip: req.ip || req.socket.remoteAddress || 'unknown',
      userAgent: req.headers['user-agent'],
      timestamp: new Date().toISOString(),
      duration,
    };

    const logLevel = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    auditLog[logLevel](entry, 'Audit entry');
  });

  next();
}
