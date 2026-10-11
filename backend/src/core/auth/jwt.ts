import jwt, { SignOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { getConfig } from '../../config/index.js';
import { Role, Permission, ROLE_PERMISSIONS } from './permissions.js';
import { logger } from '../logging/logger.js';
import { getRedis } from '../redis/client.js';

export interface TokenPayload {
  sub: string;
  email: string;
  org: string;
  role: Role;
  permissions: Permission[];
  type: 'access' | 'refresh' | 'api_key';
  mfa_verified?: boolean;
  iat?: number;
  exp?: number;
  jti?: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

class JwtService {
  private readonly accessSecret: string;
  private readonly refreshSecret: string;
  private readonly accessExpiresIn: string;
  private readonly refreshExpiresIn: string;

  constructor() {
    const config = getConfig();
    this.accessSecret = config.JWT_SECRET;
    this.refreshSecret = config.JWT_REFRESH_SECRET;
    this.accessExpiresIn = config.JWT_EXPIRES_IN;
    this.refreshExpiresIn = config.JWT_REFRESH_EXPIRES_IN;
  }

  generateTokenPair(
    userId: string,
    email: string,
    orgId: string,
    role: Role,
  ): TokenPair {
    const permissions = ROLE_PERMISSIONS[role] ?? [];

    const basePayload = {
      sub: userId,
      email,
      org: orgId,
      role,
      permissions,
    };

    const accessToken = this.sign(
      { ...basePayload, type: 'access' },
      this.accessSecret,
      { expiresIn: this.accessExpiresIn as SignOptions['expiresIn'] },
    );

    const refreshToken = this.sign(
      { ...basePayload, type: 'refresh' },
      this.refreshSecret,
      { expiresIn: this.refreshExpiresIn as SignOptions['expiresIn'] },
    );

    const expiresInSeconds = this.parseExpiresIn(this.accessExpiresIn);

    return { accessToken, refreshToken, expiresIn: expiresInSeconds };
  }

  generateApiKey(
    userId: string,
    email: string,
    orgId: string,
    role: Role,
    keyId: string,
  ): string {
    return this.sign(
      {
        sub: userId,
        email,
        org: orgId,
        role,
        permissions: ROLE_PERMISSIONS[role] ?? [],
        type: 'api_key',
        jti: keyId,
      },
      this.accessSecret,
      { expiresIn: '365d' },
    );
  }

  verifyAccessToken(token: string): TokenPayload {
    return this.verify(token, this.accessSecret) as TokenPayload;
  }

  verifyRefreshToken(token: string): TokenPayload {
    return this.verify(token, this.refreshSecret) as TokenPayload;
  }

  verifyApiKey(token: string): TokenPayload {
    const payload = this.verify(token, this.accessSecret) as TokenPayload;
    if (payload.type !== 'api_key') {
      throw new jwt.JsonWebTokenError('Token is not an API key');
    }
    return payload;
  }

  decode(token: string): TokenPayload | null {
    try {
      return jwt.decode(token) as TokenPayload;
    } catch {
      return null;
    }
  }

  isTokenExpired(token: string): boolean {
    const decoded = this.decode(token);
    if (!decoded?.exp) return true;
    return Date.now() >= decoded.exp * 1000;
  }

  private sign(
    payload: Omit<TokenPayload, 'iat' | 'exp'>,
    secret: string,
    options: SignOptions,
  ): string {
    return jwt.sign(payload as object, secret, {
      ...options,
      algorithm: 'HS256',
      issuer: 'appsec-platform',
      audience: 'appsec-platform-api',
      jwtid: crypto.randomUUID(),
    });
  }

  private verify(token: string, secret: string): TokenPayload {
    try {
      return jwt.verify(token, secret, {
        algorithms: ['HS256'],
        issuer: 'appsec-platform',
        audience: 'appsec-platform-api',
        clockTolerance: 30,
      }) as TokenPayload;
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        logger.warn({ err }, 'Token expired');
      } else if (err instanceof jwt.JsonWebTokenError) {
        logger.warn({ err }, 'Invalid token');
      }
      throw err;
    }
  }

  // Local positive cache in front of the shared Redis store. Redis is the source
  // of truth so revocation propagates across replicas and survives restarts; the
  // local map only short-circuits repeat checks for tokens this process revoked.
  private readonly blacklist = new Map<string, number>();
  private blacklistCleanupInterval: ReturnType<typeof setInterval> | null = null;

  private blacklistKey(hash: string): string {
    return `jwt:blacklist:${hash}`;
  }

  async blacklistToken(token: string, reason: string = 'logout'): Promise<void> {
    const hash = this.hashToken(token);
    const decoded = this.decode(token);
    const now = Date.now();
    const expiresAt = decoded?.exp ? decoded.exp * 1000 : now + 86400000;
    const ttlSeconds = Math.max(1, Math.ceil((expiresAt - now) / 1000));
    this.blacklist.set(hash, expiresAt);
    try {
      await getRedis().set(this.blacklistKey(hash), reason, 'EX', ttlSeconds);
    } catch (err) {
      // Local cache still covers this process; log so the operator notices Redis issues.
      logger.error({ err, tokenHash: hash }, 'Failed to persist token blacklist to Redis');
    }
    logger.info({ tokenHash: hash }, 'Token blacklisted');
    this.scheduleCleanup();
  }

  async isBlacklisted(token: string): Promise<boolean> {
    const hash = this.hashToken(token);
    const expiresAt = this.blacklist.get(hash);
    if (expiresAt !== undefined) {
      if (Date.now() <= expiresAt) return true; // local positive hit
      this.blacklist.delete(hash);
    }
    try {
      const exists = await getRedis().exists(this.blacklistKey(hash));
      return exists === 1;
    } catch (err) {
      // Fail open on Redis outage (availability over a brief revocation gap);
      // the local cache still enforces revocations issued by this process.
      logger.error({ err }, 'Redis blacklist check failed; relying on local cache');
      return false;
    }
  }

  private scheduleCleanup(): void {
    if (this.blacklistCleanupInterval) return;
    this.blacklistCleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [hash, expiresAt] of this.blacklist) {
        if (now > expiresAt) this.blacklist.delete(hash);
      }
      if (this.blacklist.size === 0 && this.blacklistCleanupInterval) {
        clearInterval(this.blacklistCleanupInterval);
        this.blacklistCleanupInterval = null;
      }
    }, 60000);
    this.blacklistCleanupInterval.unref();
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  private parseExpiresIn(expiresIn: string): number {
    const match = expiresIn.match(/^(\d+)(s|m|h|d)$/);
    if (!match) return 900;
    const value = parseInt(match[1]!, 10);
    const unit = match[2];
    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 3600;
      case 'd': return value * 86400;
      default: return 900;
    }
  }
}

export const jwtService = new JwtService();
