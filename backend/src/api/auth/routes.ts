import { Router, Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { z } from 'zod';
import { jwtService } from '../../core/auth/jwt.js';
import { Role, ROLE_PERMISSIONS } from '../../core/auth/permissions.js';
import { query } from '../../core/db/pool.js';
import { logger } from '../../core/logging/logger.js';
import { validateBody, validateParams } from '../../middleware/validate.js';
import { authRateLimiter } from '../../middleware/rate-limiter.js';
import { AppError } from '../../core/errors/handler.js';
import { requirePermission, Permission } from '../../middleware/auth.js';
import { v4 as uuidv4 } from 'uuid';
import { verifyTOTP, verifyBackupCode } from '../../core/auth/totp.js';
import { setAuthCookies, clearAuthCookies, REFRESH_COOKIE, ACCESS_COOKIE } from '../../core/auth/cookies.js';

export const authRouter = Router();

const loginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
  mfaCode: z.string().optional(),
});

const registerSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(12).max(128)
    .regex(/[A-Z]/, 'Must contain uppercase')
    .regex(/[a-z]/, 'Must contain lowercase')
    .regex(/[0-9]/, 'Must contain number')
    .regex(/[^A-Za-z0-9]/, 'Must contain special character'),
  name: z.string().min(1).max(100),
  organizationName: z.string().min(1).max(100).optional(),
});


const forgotPasswordSchema = z.object({
  email: z.string().email().max(255),
});

const resetPasswordSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(12).max(128)
    .regex(/[A-Z]/).regex(/[a-z]/).regex(/[0-9]/).regex(/[^A-Za-z0-9]/),
});

authRouter.post('/login', authRateLimiter, validateBody(loginSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body;

    const result = await query(
      `SELECT u.id, u.email, u.password_hash, u.name, u.role, u.org_id, u.disabled, u.mfa_enabled,
              o.name as org_name
       FROM users u
       JOIN organizations o ON u.org_id = o.id
       WHERE u.email = $1 AND u.deleted_at IS NULL`,
      [email.toLowerCase().trim()],
    );

    if (result.rows.length === 0) {
      throw AppError.unauthorized('Invalid email or password');
    }

    const user = result.rows[0] as Record<string, unknown>;

    if (user.disabled) {
      throw AppError.forbidden('Account has been disabled. Contact your administrator.');
    }

    const passwordValid = await bcrypt.compare(password, user.password_hash as string);
    if (!passwordValid) {
      logger.warn({ email }, 'Failed login attempt');
      throw AppError.unauthorized('Invalid email or password');
    }

    if (user.mfa_enabled) {
      const mfaCode = req.body.mfaCode;
      if (!mfaCode) {
        const mfaChallengeId = uuidv4();
        await query(
          `INSERT INTO mfa_challenges (id, user_id, created_at, expires_at)
           VALUES ($1, $2, NOW(), NOW() + INTERVAL '5 minutes')`,
          [mfaChallengeId, user.id],
        );
        res.status(200).json({
          requiresMfa: true,
          mfaChallengeId,
        });
        return;
      }

      const mfaResult = await query(
        `SELECT id FROM mfa_challenges
         WHERE user_id = $1 AND expires_at > NOW() AND used = false
         ORDER BY created_at DESC LIMIT 1`,
        [user.id],
      );
      if (mfaResult.rows.length === 0) {
        throw AppError.unauthorized('MFA challenge expired. Please login again.');
      }

      const mfaSetup = await query(
        'SELECT secret, backup_codes FROM mfa_setup WHERE user_id = $1 AND verified = true',
        [user.id],
      );
      if (mfaSetup.rows.length === 0) {
        throw AppError.unauthorized('MFA is enabled but not configured. Contact your administrator.');
      }

      const setup = mfaSetup.rows[0] as Record<string, unknown>;
      const secret = (user.mfa_secret || setup.secret) as string;
      let mfaValid = false;

      if (/^\d{6}$/.test(mfaCode)) {
        mfaValid = verifyTOTP(secret, mfaCode);
      } else {
        const backupCodes = (setup.backup_codes || []) as string[];
        const idx = verifyBackupCode(mfaCode, backupCodes);
        if (idx >= 0) {
          mfaValid = true;
          backupCodes.splice(idx, 1);
          await query('UPDATE mfa_setup SET backup_codes = $1, updated_at = NOW() WHERE user_id = $2',
            [backupCodes, user.id]);
        }
      }

      if (!mfaValid) {
        logger.warn({ userId: user.id }, 'Failed MFA verification attempt');
        throw AppError.unauthorized('Invalid MFA code');
      }

      await query('UPDATE mfa_challenges SET used = true WHERE user_id = $1 AND used = false', [user.id]);
    }

    const tokens = jwtService.generateTokenPair(
      user.id as string,
      user.email as string,
      user.org_id as string,
      user.role as Role,
    );

    await query(
      `INSERT INTO audit_log (user_id, org_id, action, resource, ip_address, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [user.id, user.org_id, 'user.login', 'auth', req.ip, JSON.stringify({ email })],
    );

    logger.info({ userId: user.id, email }, 'User logged in');

    const csrfToken = setAuthCookies(res, tokens);
    res.json({
      csrfToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        orgId: user.org_id,
        orgName: user.org_name,
        permissions: ROLE_PERMISSIONS[user.role as Role] || [],
      },
    });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/register', authRateLimiter, validateBody(registerSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, name, organizationName } = req.body;
    const normalizedEmail = email.toLowerCase().trim();

    const existing = await query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      throw AppError.conflict('A user with this email already exists');
    }

    const orgId = uuidv4();
    await query(
      `INSERT INTO organizations (id, name, created_at, updated_at)
       VALUES ($1, $2, NOW(), NOW())`,
      [orgId, organizationName || `${name}'s Organization`],
    );

    const userId = uuidv4();
    const passwordHash = await bcrypt.hash(password, 14);

    await query(
      `INSERT INTO users (id, email, password_hash, name, role, org_id, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
      [userId, normalizedEmail, passwordHash, name, Role.ADMIN, orgId],
    );

    await query(
      `INSERT INTO audit_log (user_id, org_id, action, resource, ip_address, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [userId, orgId, 'user.register', 'auth', req.ip, JSON.stringify({ email: normalizedEmail })],
    );

    logger.info({ userId, email: normalizedEmail }, 'New user and organization created');

    const tokens = jwtService.generateTokenPair(userId, normalizedEmail, orgId, Role.ADMIN);

    const csrfToken = setAuthCookies(res, tokens);
    res.status(201).json({
      csrfToken,
      user: {
        id: userId,
        email: normalizedEmail,
        name,
        role: Role.ADMIN,
        orgId,
        orgName: organizationName || `${name}'s Organization`,
        permissions: ROLE_PERMISSIONS[Role.ADMIN],
      },
    });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/refresh', async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Refresh token comes from the HttpOnly cookie (falls back to body for
    // programmatic clients).
    const refreshToken = (req.cookies?.[REFRESH_COOKIE] as string | undefined) || req.body?.refreshToken;
    if (!refreshToken) {
      throw AppError.unauthorized('Refresh token required');
    }
    if (await jwtService.isBlacklisted(refreshToken)) {
      throw AppError.unauthorized('Refresh token has been revoked');
    }
    const payload = jwtService.verifyRefreshToken(refreshToken);

    const result = await query(
      'SELECT id, email, role, org_id, disabled FROM users WHERE id = $1 AND deleted_at IS NULL',
      [payload.sub],
    );

    if (result.rows.length === 0 || (result.rows[0] as Record<string, unknown>).disabled) {
      throw AppError.unauthorized('User account not found or disabled');
    }

    await jwtService.blacklistToken(refreshToken, 'rotation');

    const user = result.rows[0] as Record<string, unknown>;
    const tokens = jwtService.generateTokenPair(
      user.id as string, user.email as string,
      user.org_id as string, user.role as Role,
    );

    const csrfToken = setAuthCookies(res, tokens);
    res.json({ csrfToken });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/logout', async (req: Request, res: Response) => {
  const headerToken = req.headers.authorization?.replace('Bearer ', '');
  const cookieToken = req.cookies?.[ACCESS_COOKIE] as string | undefined;
  const token = headerToken || cookieToken;
  if (token) {
    await jwtService.blacklistToken(token);
  }
  clearAuthCookies(res);
  res.json({ message: 'Logged out successfully' });
});

authRouter.post('/forgot-password', authRateLimiter, validateBody(forgotPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = req.body;
    const result = await query('SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL', [email.toLowerCase()]);
    if (result.rows.length > 0) {
      const userId = (result.rows[0] as Record<string, unknown>).id;
      await query('UPDATE password_resets SET used = true WHERE user_id = $1 AND used = false', [userId]);
      const resetToken = crypto.randomBytes(32).toString('base64url');
      const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
      await query(
        `INSERT INTO password_resets (user_id, token, expires_at, created_at)
         VALUES ($1, $2, NOW() + INTERVAL '1 hour', NOW())`,
        [userId, tokenHash],
      );
      logger.info({ email }, 'Password reset token generated');
    }
    res.json({ message: 'If the email exists, a reset link has been sent.' });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/reset-password', validateBody(resetPasswordSchema), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token, password } = req.body;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const result = await query(
      `SELECT user_id FROM password_resets
       WHERE token = $1 AND used = false AND expires_at > NOW()`,
      [tokenHash],
    );

    if (result.rows.length === 0) {
      throw AppError.badRequest('Invalid or expired reset token');
    }

    const userId = (result.rows[0] as Record<string, unknown>).user_id as string;
    const passwordHash = await bcrypt.hash(password, 14);

    await query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [passwordHash, userId]);
    await query('UPDATE password_resets SET used = true WHERE token = $1', [tokenHash]);

    logger.info({ userId }, 'Password reset successfully');

    res.json({ message: 'Password has been reset successfully.' });
  } catch (err) {
    next(err);
  }
});

authRouter.get('/me', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await query(
      `SELECT u.id, u.email, u.name, u.role, u.org_id, u.mfa_enabled, o.name as org_name
       FROM users u JOIN organizations o ON u.org_id = o.id
       WHERE u.id = $1 AND u.deleted_at IS NULL`,
      [req.userId],
    );

    if (result.rows.length === 0) throw AppError.notFound('User not found');

    const user = result.rows[0] as Record<string, unknown>;
    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      orgId: user.org_id,
      orgName: user.org_name,
      mfaEnabled: user.mfa_enabled,
      permissions: ROLE_PERMISSIONS[user.role as Role] || [],
    });
  } catch (err) {
    next(err);
  }
});

authRouter.put('/change-password',
  requirePermission(Permission.SETTINGS_MANAGE),
  validateBody(z.object({
    currentPassword: z.string().min(1),
    newPassword: z.string().min(12).max(128),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const result = await query('SELECT password_hash FROM users WHERE id = $1', [req.userId]);
      if (result.rows.length === 0) throw AppError.notFound('User not found');

      const valid = await bcrypt.compare(currentPassword, (result.rows[0] as Record<string, unknown>).password_hash as string);
      if (!valid) throw AppError.badRequest('Current password is incorrect');

      const newHash = await bcrypt.hash(newPassword, 14);
      await query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, req.userId]);

      logger.info({ userId: req.userId }, 'Password changed');
      res.json({ message: 'Password changed successfully' });
    } catch (err) {
      next(err);
    }
  },
);

// ---- API keys (issuance / listing / revocation) ----
// Keys are JWTs (type=api_key) backed by a row in api_keys; the auth middleware
// validates the row (revoked/expired) on every request, so revocation here is
// immediately effective.

authRouter.post('/api-keys',
  requirePermission(Permission.SETTINGS_MANAGE),
  validateBody(z.object({
    name: z.string().min(1).max(100),
    expiresInDays: z.number().int().min(1).max(365).optional().default(365),
  })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, expiresInDays } = req.body;
      const userRow = await query('SELECT email, role FROM users WHERE id = $1 AND deleted_at IS NULL', [req.userId]);
      if (userRow.rows.length === 0) throw AppError.notFound('User not found');
      const user = userRow.rows[0] as Record<string, unknown>;

      const keyId = uuidv4();
      const token = jwtService.generateApiKey(
        req.userId as string, user.email as string, req.orgId as string, user.role as Role, keyId,
      );
      const keyHash = crypto.createHash('sha256').update(token).digest('hex');

      await query(
        `INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, permissions, expires_at, revoked, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW() + ($7 || ' days')::interval, false, NOW(), NOW())`,
        [keyId, req.userId, name, keyHash, token.slice(0, 8), ROLE_PERMISSIONS[user.role as Role] || [], String(expiresInDays)],
      );

      logger.info({ keyId, userId: req.userId, name }, 'API key issued');
      res.status(201).json({
        id: keyId,
        name,
        apiKey: token,
        expiresInDays,
        note: 'Store this key now — it is not retrievable again.',
      });
    } catch (err) { next(err); }
  },
);

authRouter.get('/api-keys',
  requirePermission(Permission.SETTINGS_VIEW),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        `SELECT id, name, key_prefix, last_used, expires_at, revoked, created_at
         FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`,
        [req.userId],
      );
      res.json({ data: result.rows });
    } catch (err) { next(err); }
  },
);

authRouter.delete('/api-keys/:id',
  requirePermission(Permission.SETTINGS_MANAGE),
  validateParams(z.object({ id: z.string().uuid() })),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await query(
        'UPDATE api_keys SET revoked = true, updated_at = NOW() WHERE id = $1 AND user_id = $2',
        [req.params.id, req.userId],
      );
      if (result.rowCount === 0) throw AppError.notFound('API key not found');
      logger.info({ keyId: req.params.id, userId: req.userId }, 'API key revoked');
      res.json({ message: 'API key revoked' });
    } catch (err) { next(err); }
  },
);
