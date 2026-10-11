import { Response } from 'express';
import crypto from 'crypto';
import type { TokenPair } from './jwt.js';

export const ACCESS_COOKIE = 'access_token';
export const REFRESH_COOKIE = 'refresh_token';
export const CSRF_COOKIE = 'csrf_token';

// Refresh cookie is scoped to the auth path so it is only sent to /api/auth/*.
const REFRESH_PATH = '/api/auth';
const REFRESH_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

// The platform is HTTPS-only, so auth cookies are always Secure.
const SECURE = true;

/**
 * Sets HttpOnly access/refresh cookies plus a readable double-submit CSRF cookie.
 * Returns the CSRF token so the login/refresh response can also hand it to the SPA.
 */
export function setAuthCookies(res: Response, tokens: TokenPair): string {
  res.cookie(ACCESS_COOKIE, tokens.accessToken, {
    httpOnly: true,
    secure: SECURE,
    sameSite: 'strict',
    path: '/',
    maxAge: tokens.expiresIn * 1000,
  });

  res.cookie(REFRESH_COOKIE, tokens.refreshToken, {
    httpOnly: true,
    secure: SECURE,
    sameSite: 'strict',
    path: REFRESH_PATH,
    maxAge: REFRESH_MAX_AGE_MS,
  });

  // Double-submit CSRF token: readable by the SPA (not HttpOnly) so it can echo
  // it back in the X-CSRF-Token header on mutating requests.
  const csrfToken = crypto.randomBytes(32).toString('hex');
  res.cookie(CSRF_COOKIE, csrfToken, {
    httpOnly: false,
    secure: SECURE,
    sameSite: 'strict',
    path: '/',
    maxAge: REFRESH_MAX_AGE_MS,
  });

  return csrfToken;
}

export function clearAuthCookies(res: Response): void {
  res.clearCookie(ACCESS_COOKIE, { path: '/' });
  res.clearCookie(REFRESH_COOKIE, { path: REFRESH_PATH });
  res.clearCookie(CSRF_COOKIE, { path: '/' });
}
