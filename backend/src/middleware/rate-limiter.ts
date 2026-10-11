import rateLimit from 'express-rate-limit';
import { getConfig } from '../config/index.js';

const config = getConfig();

export const rateLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX_REQUESTS || 5000,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests',
    message: 'Rate limit exceeded. Please wait before making additional requests.',
    retryAfter: 'See Retry-After header',
  },
  skip: (req) => req.path === '/api/health' || req.path === '/api/health/liveness',
  keyGenerator: (req) => {
    const xff = req.headers['x-forwarded-for'];
    const clientIp = typeof xff === 'string' ? xff.split(',')[0]!.trim() : req.ip;
    return clientIp || 'unknown';
  },
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts',
    message: 'Please wait 15 minutes before trying again.',
  },
  skipSuccessfulRequests: true,
});
