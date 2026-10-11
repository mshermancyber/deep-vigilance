import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { ACCESS_COOKIE, CSRF_COOKIE } from '../core/auth/cookies.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function timingSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/**
 * Double-submit CSRF protection. Only enforced when the request is authenticated
 * via the access_token cookie (i.e. the browser auto-attaches credentials) — the
 * exact case vulnerable to CSRF. Header-authenticated requests (Authorization /
 * X-Api-Key) and unauthenticated requests (login/register/refresh have no access
 * cookie yet) are exempt, as an attacker cannot set custom headers cross-origin.
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return next();

  const hasHeaderAuth = !!req.headers.authorization || !!req.headers['x-api-key'];
  if (hasHeaderAuth) return next();

  const accessCookie = (req as any).cookies?.[ACCESS_COOKIE];
  if (!accessCookie) return next(); // not cookie-authenticated → not CSRF-able here

  const cookieToken = (req as any).cookies?.[CSRF_COOKIE];
  const headerToken = req.headers['x-csrf-token'];

  if (
    typeof cookieToken !== 'string' || cookieToken.length === 0 ||
    typeof headerToken !== 'string' || headerToken.length === 0 ||
    !timingSafeEqual(cookieToken, headerToken)
  ) {
    res.status(403).json({ error: 'CSRF token missing or invalid' });
    return;
  }

  next();
}
