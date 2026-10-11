import { Request, Response, NextFunction } from 'express';
import { jwtService, TokenPayload } from '../core/auth/jwt.js';
import { Permission, hasPermission } from '../core/auth/permissions.js';
import { logger } from '../core/logging/logger.js';
import { ACCESS_COOKIE } from '../core/auth/cookies.js';
import { query } from '../core/db/pool.js';

export { Permission };

const PUBLIC_PATHS = [
  '/api/health',
  '/api/health/liveness',
  '/api/health/readiness',
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/refresh',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
  '/api/auth/verify-email',
  '/api/auth/mfa-setup',
  '/api/auth/mfa-verify',
  '/api/setup',
  '/api/code-review/webhook',
];

function isPublicPath(path: string): boolean {
  return PUBLIC_PATHS.some((p) => path === p || path.startsWith(p + '/'));
}

export async function authMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (isPublicPath(req.path)) {
    return next();
  }

  const authHeader = req.headers.authorization;
  const apiKey = req.headers['x-api-key'] as string | undefined;
  const cookieToken = (req as any).cookies?.[ACCESS_COOKIE] as string | undefined;

  if (!authHeader && !apiKey && !cookieToken) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  try {
    if (apiKey) {
      const payload = jwtService.verifyApiKey(apiKey);
      // A valid signature is not enough — the key must still exist, be
      // un-revoked and un-expired in the DB (fail closed). This makes DB-side
      // revocation actually take effect.
      const keyResult = await query(
        'SELECT revoked, expires_at FROM api_keys WHERE id = $1',
        [payload.jti],
      );
      const keyRow = keyResult.rows[0] as Record<string, unknown> | undefined;
      if (!keyRow || keyRow.revoked === true ||
          (keyRow.expires_at && new Date(keyRow.expires_at as string) < new Date())) {
        res.status(401).json({ error: 'API key is invalid, expired, or revoked' });
        return;
      }
      attachUserToRequest(req, payload);
      return next();
    }

    // Bearer header (programmatic clients) or HttpOnly access cookie (SPA).
    let token: string | undefined;
    if (authHeader) {
      const parts = authHeader.split(' ');
      if (parts.length !== 2 || parts[0] !== 'Bearer') {
        res.status(401).json({ error: 'Invalid authorization header format. Use: Bearer <token>' });
        return;
      }
      token = parts[1]!;
    } else if (cookieToken) {
      token = cookieToken;
    }

    if (token) {
      if (await jwtService.isBlacklisted(token)) {
        res.status(401).json({ error: 'Token has been revoked' });
        return;
      }

      const payload = jwtService.verifyAccessToken(token);

      if (payload.type !== 'access') {
        res.status(401).json({ error: 'Invalid token type' });
        return;
      }

      attachUserToRequest(req, payload);
      return next();
    }
  } catch (err) {
    logger.warn({ err, path: req.path }, 'Authentication failed');
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }
}

function attachUserToRequest(req: Request, payload: TokenPayload): void {
  req.userId = payload.sub;
  req.orgId = payload.org;
  req.role = payload.role;
  req.permissions = payload.permissions;
}

export function requirePermission(...permissions: Permission[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.permissions || !req.role) {
      res.status(403).json({ error: 'Forbidden — insufficient permissions' });
      return;
    }

    const hasAccess = permissions.some((p) => hasPermission(req.role as any, p));

    if (!hasAccess) {
      logger.warn({
        userId: req.userId,
        role: req.role,
        required: permissions,
        path: req.path,
      }, 'Permission denied');

      res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have the required permissions for this action.',
        required: permissions,
      });
      return;
    }

    next();
  };
}

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.role || !roles.includes(req.role)) {
      res.status(403).json({
        error: 'Forbidden',
        message: 'Your role does not have access to this resource.',
      });
      return;
    }
    next();
  };
}

export function optionalAuth(req: Request, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader) return next();

  try {
    const parts = authHeader.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      const payload = jwtService.verifyAccessToken(parts[1]!);
      attachUserToRequest(req, payload);
    }
  } catch {
    // Token invalid but auth is optional — continue without user context
  }

  next();
}
