import { Request, Response, NextFunction } from 'express';
import { logger } from '../logging/logger.js';

export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public code: string = 'INTERNAL_ERROR',
    public details?: unknown,
  ) {
    super(message);
    this.name = 'AppError';
    Error.captureStackTrace(this, this.constructor);
  }

  static badRequest(message: string, details?: unknown): AppError {
    return new AppError(400, message, 'BAD_REQUEST', details);
  }

  static unauthorized(message: string = 'Authentication required'): AppError {
    return new AppError(401, message, 'UNAUTHORIZED');
  }

  static forbidden(message: string = 'Insufficient permissions'): AppError {
    return new AppError(403, message, 'FORBIDDEN');
  }

  static notFound(message: string = 'Resource not found'): AppError {
    return new AppError(404, message, 'NOT_FOUND');
  }

  static conflict(message: string): AppError {
    return new AppError(409, message, 'CONFLICT');
  }

  static tooMany(message: string = 'Too many requests'): AppError {
    return new AppError(429, message, 'TOO_MANY_REQUESTS');
  }

  static internal(message: string = 'Internal server error'): AppError {
    return new AppError(500, message, 'INTERNAL_ERROR');
  }

  static serviceUnavailable(message: string = 'Service unavailable'): AppError {
    return new AppError(503, message, 'SERVICE_UNAVAILABLE');
  }
}

function redactSensitive(obj: unknown, depth = 0): unknown {
  if (depth > 5 || obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(item => redactSensitive(item, depth + 1));
  return Object.fromEntries(
    Object.entries(obj as Record<string, unknown>).map(([k, v]) =>
      /password|secret|token|credential|auth|key|apikey/i.test(k)
        ? [k, '[REDACTED]']
        : [k, typeof v === 'object' ? redactSensitive(v, depth + 1) : v],
    ),
  );
}

export function notFoundHandler(req: Request, _res: Response, next: NextFunction): void {
  next(AppError.notFound(`Route not found: ${req.method} ${req.originalUrl}`));
}

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  const requestId = req.requestId || 'unknown';

  if (err instanceof AppError) {
    logger.warn({
      requestId,
      statusCode: err.statusCode,
      code: err.code,
      message: err.message,
      path: req.path,
    }, 'Application error');

    res.status(err.statusCode).json({
      error: err.message,
      code: err.code,
      details: err.details,
      requestId,
      timestamp: new Date().toISOString(),
    });
    return;
  }

  const redactedBody = req.body ? redactSensitive(req.body) : undefined;

  logger.error({
    requestId,
    err,
    path: req.path,
    method: req.method,
    body: redactedBody,
  }, 'Unhandled error');

  res.status(500).json({
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    requestId,
    timestamp: new Date().toISOString(),
  });
}
