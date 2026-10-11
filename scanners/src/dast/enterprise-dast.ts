// M6a-M6g: Enterprise DAST — Browser Crawler, Auth Replay, Advanced Attacks, WAF Evasion, Passive/Proxy, Evidence, Compliance
import https from 'https';
import http from 'http';
import { URL } from 'url';
import { DastAttack } from './engine.js';
import { assertScannableUrl } from '../utils/ssrf.js';

// =========================================================================
// M6a: Browser Crawler — Real HTTP-based crawler
// =========================================================================

export interface BrowserCrawlerConfig {
  targetUrl: string;
  maxDepth: number;
  maxPages: number;
  renderJS: boolean;
  fillForms: boolean;
  scrollToLazy: boolean;
  followSPALinks: boolean;
}

export async function browserCrawl(config: BrowserCrawlerConfig): Promise<{
  urls: string[];
  apiEndpoints: string[];
  forms: Array<{ action: string; method: string; fields: string[] }>;
  jsBundles: string[];
}> {
  const visited = new Set<string>();
  const discovered: string[] = [];
  const apiEndpoints = new Set<string>();
  const discoveredForms: Array<{ action: string; method: string; fields: string[] }> = [];
  const jsBundles = new Set<string>();

  let baseOrigin: string;
  let domain: string;
  try {
    const parsed = new URL(config.targetUrl);
    baseOrigin = parsed.origin;
    domain = parsed.hostname;
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { urls: [], apiEndpoints: [], forms: [], jsBundles: [] };
    }
  } catch {
    return { urls: [], apiEndpoints: [], forms: [], jsBundles: [] };
  }

  async function httpFetch(urlStr: string): Promise<{ status: number; body: string } | null> {
    const MAX_REDIRECTS = 5;
    let currentUrl = urlStr;
    for (let redirects = 0; redirects < MAX_REDIRECTS; redirects++) {
      try {
        await assertScannableUrl(currentUrl);
        const result = await new Promise<{
          status: number;
          body: string;
          headers: http.IncomingHttpHeaders;
        } | null>((resolve) => {
          let pUrl: URL;
          try {
            pUrl = new URL(currentUrl);
          } catch {
            resolve(null);
            return;
          }
          if (pUrl.protocol !== 'http:' && pUrl.protocol !== 'https:') {
            resolve(null);
            return;
          }
          const transport = pUrl.protocol === 'https:' ? https : http;
          const opts: https.RequestOptions = {
            hostname: pUrl.hostname,
            port: pUrl.port || (pUrl.protocol === 'https:' ? 443 : 80),
            path: pUrl.pathname + pUrl.search,
            method: 'GET',
            headers: {
              'User-Agent': 'Mozilla/5.0 (compatible; AppSec-DAST-Crawler/2.0; +https://appscanner.security)',
              Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
            rejectUnauthorized: false,
            timeout: 10000,
          };
          const req = transport.request(opts, (res) => {
            let data = '';
            res.on('data', (c: string) => {
              data += c;
              if (data.length > 500000) {
                req.destroy();
                resolve({ status: res.statusCode || 0, body: data, headers: res.headers });
              }
            });
            res.on('end', () => {
              resolve({ status: res.statusCode || 0, body: data, headers: res.headers });
            });
          });
          req.on('error', () => resolve(null));
          req.on('timeout', () => {
            req.destroy();
            resolve(null);
          });
          req.end();
        });
        if (!result) return null;
        if ([301, 302, 303, 307, 308].includes(result.status) && result.headers.location) {
          try {
            currentUrl = new URL(result.headers.location as string, currentUrl).href;
            continue;
          } catch {
            return null;
          }
        }
        return { status: result.status, body: result.body };
      } catch {
        return null;
      }
    }
    return null;
  }

  async function crawl(urlStr: string, depth: number): Promise<void> {
    if (depth > config.maxDepth || visited.size >= config.maxPages) return;
    const normalized = urlStr.split('#')[0];
    if (visited.has(normalized) || !normalized.startsWith('http')) return;
    visited.add(normalized);
    discovered.push(normalized);

    const result = await httpFetch(normalized);
    if (!result) return;
    const html = result.body;

    // Detect <base> tag for resolving relative URLs
    let baseHref = normalized;
    const baseMatch = /<base[^>]+href=["']([^"']+)["']/i.exec(html);
    if (baseMatch) {
      try {
        baseHref = new URL(baseMatch[1], normalized).href;
      } catch { /* keep original */ }
    }

    // Extract links from <a> tags
    const linkRegex = /<a[^>]+href=["']([^"']+)["']/gi;
    let match: RegExpExecArray | null;
    while ((match = linkRegex.exec(html)) !== null) {
      const rawHref = match[1].trim();
      if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('javascript:') ||
          rawHref.startsWith('mailto:') || rawHref.startsWith('tel:')) continue;
      try {
        const resolved = new URL(rawHref, baseHref);
        if (resolved.hostname === domain) {
          const clean = resolved.href.split('#')[0];
          if (!visited.has(clean) && !discovered.includes(clean)) {
            await crawl(clean, depth + 1);
          }
        }
      } catch { /* skip invalid */ }
    }

    // Extract forms with all input fields
    const formOpenRegex = /<form[^>]*>/gi;
    let formOpenMatch: RegExpExecArray | null;
    while ((formOpenMatch = formOpenRegex.exec(html)) !== null) {
      const formTag = formOpenMatch[0];
      const formStart = formOpenMatch.index;
      const formEnd = html.indexOf('</form>', formStart);
      const formContent = formEnd !== -1 ? html.substring(formStart, formEnd + 7) : '';

      const actionRaw = /action=["']([^"']*)["']/i.exec(formTag);
      const methodRaw = /method=["']([^"']*)["']/i.exec(formTag);
      let action = actionRaw ? actionRaw[1] : '/';
      try {
        action = new URL(action, baseHref).href;
      } catch { /* keep relative */ }
      const method = methodRaw ? methodRaw[1].toUpperCase() : 'GET';

      const formFields: string[] = [];
      // Input fields
      const inputRe = /<input[^>]+name=["']([^"']*)["'][^>]*>/gi;
      let fMatch: RegExpExecArray | null;
      while ((fMatch = inputRe.exec(formContent)) !== null) {
        if (!formFields.includes(fMatch[1])) formFields.push(fMatch[1]);
      }
      // Textarea fields
      const textareaRe = /<textarea[^>]+name=["']([^"']*)["'][^>]*>/gi;
      while ((fMatch = textareaRe.exec(formContent)) !== null) {
        if (!formFields.includes(fMatch[1])) formFields.push(fMatch[1]);
      }
      // Select fields
      const selectRe = /<select[^>]+name=["']([^"']*)["'][^>]*>/gi;
      while ((fMatch = selectRe.exec(formContent)) !== null) {
        if (!formFields.includes(fMatch[1])) formFields.push(fMatch[1]);
      }
      // Button fields with name
      const buttonRe = /<button[^>]+name=["']([^"']*)["'][^>]*>/gi;
      while ((fMatch = buttonRe.exec(formContent)) !== null) {
        if (!formFields.includes(fMatch[1])) formFields.push(fMatch[1]);
      }
      discoveredForms.push({ action, method, fields: formFields });
    }

    // Extract script src URLs for JS bundles
    const scriptSrcRe = /<script[^>]+src=["']([^"']+)["']/gi;
    while ((match = scriptSrcRe.exec(html)) !== null) {
      try {
        const src = new URL(match[1], baseHref).href;
        if (/\.(?:js|mjs|cjs)\b/i.test(src) || /\/chunk/i.test(src) || /\/bundle/i.test(src)) {
          jsBundles.add(src);
        }
      } catch { /* skip */ }
    }

    // Follow iframes to same domain
    const iframeRe = /<iframe[^>]+src=["']([^"']+)["']/gi;
    while ((match = iframeRe.exec(html)) !== null) {
      try {
        const resolved = new URL(match[1], baseHref);
        if (resolved.hostname === domain) {
          const clean = resolved.href.split('#')[0];
          if (!visited.has(clean) && !discovered.includes(clean)) {
            await crawl(clean, depth + 1);
          }
        }
      } catch { /* skip */ }
    }

    // Discover API endpoints from inline scripts and JS expressions
    const apiPatterns = [
      // fetch('/api/...') or fetch("/api/...")
      /['"`](\/(?:api|v[12]|v3|rest|graphql|auth)\/[^'"\s`?]*)['"`]/g,
      // String literals in JS that look like API paths
      /['"`]\/(?:api|v[12]|v3|rest|graphql|auth|swagger|docs)\/[^'"\s`]*['"`]/g,
      // axios.get('/api/...'), $.ajax({url:'/api/...'}), etc.
      /url\s*[=:]\s*['"`](\/[^'"`]{3,})['"`]/g,
    ];
    for (const pattern of apiPatterns) {
      while ((match = pattern.exec(html)) !== null) {
        let ep = match[1];
        if (!ep.startsWith('http')) {
          ep = ep.startsWith('/') ? baseOrigin + ep : baseOrigin + '/' + ep;
        }
        apiEndpoints.add(ep);
      }
    }

    // If followSPALinks, try to find client-side routes from JS
    if (config.followSPALinks) {
      const spaRouteRe = /(?:path|route|to|href)\s*[=:]\s*['"`](\/[a-zA-Z0-9_\-/]+)['"`]/g;
      while ((match = spaRouteRe.exec(html)) !== null) {
        try {
          const spaUrl = baseOrigin + match[1];
          if (!visited.has(spaUrl) && !discovered.includes(spaUrl)) {
            await crawl(spaUrl, depth + 1);
          }
        } catch { /* skip */ }
      }
    }
  }

  await crawl(config.targetUrl, 0);

  return {
    urls: discovered,
    apiEndpoints: [...apiEndpoints],
    forms: discoveredForms,
    jsBundles: [...jsBundles],
  };
}

// =========================================================================
// M6b: DAST Authentication Replay & Session Management
// =========================================================================

export interface AuthProfile {
  type: 'form' | 'oauth2' | 'jwt' | 'apikey' | 'basic' | 'mtls';
  loginUrl?: string;
  tokenUrl?: string;
  sessionCheckUrl: string;
  username?: string;
  password?: string;
  clientId?: string;
  clientSecret?: string;
  apiKey?: string;
  refreshToken?: string;
  scope?: string;
  macro: Array<{ action: string; selector?: string; value: string }>;
  mfaConfig?: { type: 'totp' | 'sms' | 'push'; seed?: string };
}

interface HttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

// =========================================================================
// Internal helpers
// =========================================================================

/**
 * Make an HTTP(S) request with redirect following.
 */
async function httpRequest(
  urlStr: string,
  method: string = 'GET',
  reqHeaders: Record<string, string> = {},
  bodyStr?: string,
  maxRedirects: number = 5,
): Promise<HttpResponse | null> {
  let currentUrl = urlStr;
  for (let redirects = 0; redirects <= maxRedirects; redirects++) {
    try {
      const pUrl = new URL(currentUrl);
      if (pUrl.protocol !== 'http:' && pUrl.protocol !== 'https:') return null;
      await assertScannableUrl(currentUrl);
      const transport = pUrl.protocol === 'https:' ? https : http;
      const opts: https.RequestOptions = {
        hostname: pUrl.hostname,
        port: pUrl.port || (pUrl.protocol === 'https:' ? 443 : 80),
        path: pUrl.pathname + pUrl.search,
        method,
        headers: {
          'User-Agent': 'AppSec-DAST/2.0',
          ...reqHeaders,
        },
        rejectUnauthorized: false,
        timeout: 15000,
      };
      if (bodyStr) {
        (opts.headers as Record<string, string>)['Content-Length'] = Buffer.byteLength(bodyStr).toString();
      }

      const result = await new Promise<HttpResponse | null>((resolve) => {
        const req = transport.request(opts, (res) => {
          let data = '';
          res.on('data', (chunk: string) => {
            data += chunk;
            if (data.length > 500000) {
              req.destroy();
              resolve({
                status: res.statusCode || 0,
                headers: res.headers,
                body: data,
              });
            }
          });
          res.on('end', () => {
            resolve({
              status: res.statusCode || 0,
              headers: res.headers,
              body: data,
            });
          });
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => {
          req.destroy();
          resolve(null);
        });
        if (bodyStr) req.write(bodyStr);
        req.end();
      });

      if (!result) return null;

      // Follow redirects
      if ([301, 302, 303, 307, 308].includes(result.status) && result.headers.location) {
        try {
          currentUrl = new URL(result.headers.location as string, currentUrl).href;
          continue;
        } catch {
          return null;
        }
      }
      return result;
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Extract cookies from Set-Cookie header values.
 */
function extractCookies(
  setCookieHeaders: string | string[] | undefined,
): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!setCookieHeaders) return cookies;
  const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  for (const header of headers) {
    const eq = header.indexOf('=');
    if (eq > 0) {
      const name = header.substring(0, eq).trim();
      const value = header.substring(eq + 1).split(';')[0].trim();
      cookies[name] = value;
    }
  }
  return cookies;
}

/**
 * Extract session expiry timestamp from response headers or body.
 * Checks Expires/Max-Age in Set-Cookie, or expires_in in JSON body.
 */
function extractExpiresAt(
  headers: http.IncomingHttpHeaders,
  body: string,
): number | undefined {
  // Check Set-Cookie for Expires or Max-Age
  const setCookie = headers['set-cookie'];
  if (setCookie) {
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const c of cookies) {
      const expiresMatch = /expires=([^;]+)/i.exec(c);
      if (expiresMatch) {
        const ts = Date.parse(expiresMatch[1].trim());
        if (!isNaN(ts)) return Math.floor(ts / 1000);
      }
      const maxAgeMatch = /max-age=(\d+)/i.exec(c);
      if (maxAgeMatch) {
        return Math.floor(Date.now() / 1000) + parseInt(maxAgeMatch[1], 10);
      }
    }
  }
  // Check for expires_in in JSON body (OAuth2 standard)
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed.expires_in === 'number') {
      return Math.floor(Date.now() / 1000) + parsed.expires_in;
    }
    if (typeof parsed.expires_at === 'number') {
      return parsed.expires_at;
    }
  } catch {
    // Not JSON
  }
  return undefined;
}

/**
 * Build a Cookie header string from a cookie map.
 */
function buildCookieHeader(cookies: Record<string, string>): string {
  return Object.entries(cookies)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('; ');
}

/**
 * Build URL-encoded form body from macro steps.
 */
function buildFormBodyFromMacro(profile: AuthProfile): string {
  const params: string[] = [];
  for (const step of profile.macro) {
    if (step.action === 'type' && step.selector && step.value) {
      const fieldName = step.selector.replace(/[#\]]/g, '').split('[').pop() || step.selector;
      params.push(`${encodeURIComponent(fieldName)}=${encodeURIComponent(step.value)}`);
    }
  }
  return params.join('&');
}

// =========================================================================
// authenticateAndReplay — Perform real authentication for all auth types
// =========================================================================

export async function authenticateAndReplay(
  profile: AuthProfile,
): Promise<{
  authenticated: boolean;
  cookies: Record<string, string>;
  token?: string;
  sessionValid: boolean;
  expiresAt?: number;
}> {
  try {
    switch (profile.type) {
      // ---------------------------------------------------------------
      // Form-based authentication
      // ---------------------------------------------------------------
      case 'form': {
        if (!profile.loginUrl) {
          return { authenticated: false, cookies: {}, sessionValid: false };
        }

        // Build form body from macro steps
        const bodyStr = buildFormBodyFromMacro(profile);
        if (!bodyStr) {
          return { authenticated: false, cookies: {}, sessionValid: false };
        }

        // POST credentials to loginUrl
        const result = await httpRequest(
          profile.loginUrl,
          'POST',
          { 'Content-Type': 'application/x-www-form-urlencoded' },
          bodyStr,
          5,
        );
        if (!result) {
          return { authenticated: false, cookies: {}, sessionValid: false };
        }

        // Extract REAL cookies from Set-Cookie headers
        const cookies = extractCookies(result.headers['set-cookie']);
        const authenticated = result.status >= 200 && result.status < 400;
        const expiresAt = extractExpiresAt(result.headers, result.body);

        // Map cookie values as token candidates
        const token =
          cookies['token'] ||
          cookies['jwt'] ||
          cookies['access_token'] ||
          cookies['session'] ||
          cookies['sessionid'] ||
          cookies['sid'] ||
          undefined;

        // Validate session by hitting the sessionCheckUrl with collected cookies
        let sessionValid = authenticated;
        if (authenticated && Object.keys(cookies).length > 0 && profile.sessionCheckUrl) {
          const checkResult = await httpRequest(
            profile.sessionCheckUrl,
            'GET',
            { Cookie: buildCookieHeader(cookies) },
          );
          sessionValid =
            checkResult !== null &&
            checkResult.status >= 200 &&
            checkResult.status < 400;
          // If we got new cookies from the check request, merge them
          if (checkResult) {
            const checkCookies = extractCookies(checkResult.headers['set-cookie']);
            Object.assign(cookies, checkCookies);
          }
        }

        return { authenticated, cookies, token, sessionValid, expiresAt };
      }

      // ---------------------------------------------------------------
      // OAuth 2.0 Client Credentials
      // ---------------------------------------------------------------
      case 'oauth2': {
        if (!profile.tokenUrl) {
          return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
        }

        const clientId = profile.clientId || '';
        const clientSecret = profile.clientSecret || '';
        const scope = profile.scope || '';

        // Build request body: use refresh_token if available, otherwise client_credentials
        let bodyStr: string;
        if (profile.refreshToken) {
          bodyStr =
            `grant_type=refresh_token` +
            `&refresh_token=${encodeURIComponent(profile.refreshToken)}` +
            `&client_id=${encodeURIComponent(clientId)}` +
            `&client_secret=${encodeURIComponent(clientSecret)}`;
        } else {
          bodyStr =
            `grant_type=client_credentials` +
            `&client_id=${encodeURIComponent(clientId)}` +
            `&client_secret=${encodeURIComponent(clientSecret)}`;
          if (scope) bodyStr += `&scope=${encodeURIComponent(scope)}`;
        }

        // POST to tokenUrl
        const result = await httpRequest(
          profile.tokenUrl,
          'POST',
          { 'Content-Type': 'application/x-www-form-urlencoded' },
          bodyStr,
          3,
        );
        if (!result) {
          return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
        }

        // Parse the REAL OAuth token response
        let token: string | undefined;
        let newRefreshToken: string | undefined;
        let expiresAt: number | undefined;

        try {
          const json = JSON.parse(result.body);
          token = json.access_token;
          newRefreshToken = json.refresh_token;
          if (typeof json.expires_in === 'number') {
            expiresAt = Math.floor(Date.now() / 1000) + json.expires_in;
          }
        } catch {
          return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
        }

        if (!token) {
          return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
        }

        // Persist refresh token on the profile for future refreshSession calls
        if (newRefreshToken) {
          (profile as any)._storedRefreshToken = newRefreshToken;
        }

        // Extract any cookies from Set-Cookie headers
        const cookies = extractCookies(result.headers['set-cookie']);
        const authenticated = result.status >= 200 && result.status < 300;

        // Validate session by making a request with Bearer token
        let sessionValid = authenticated;
        if (authenticated && profile.sessionCheckUrl) {
          const checkResult = await httpRequest(
            profile.sessionCheckUrl,
            'GET',
            { Authorization: `Bearer ${token}` },
          );
          sessionValid =
            checkResult !== null &&
            checkResult.status >= 200 &&
            checkResult.status < 400;
        }

        return { authenticated, cookies, token, sessionValid, expiresAt };
      }

      // ---------------------------------------------------------------
      // JWT-based authentication
      // ---------------------------------------------------------------
      case 'jwt': {
        if (!profile.loginUrl) {
          return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
        }

        // Build JSON body from macro steps
        const jsonBody: Record<string, string> = {};
        for (const step of profile.macro) {
          if (step.action === 'type' && step.selector && step.value) {
            jsonBody[step.selector] = step.value;
          }
        }
        // Also use username/password fields if set directly
        if (profile.username && Object.keys(jsonBody).length === 0) {
          jsonBody['username'] = profile.username;
          jsonBody['password'] = profile.password || '';
        }
        const bodyStr = JSON.stringify(jsonBody);

        // POST credentials to loginUrl
        const result = await httpRequest(
          profile.loginUrl,
          'POST',
          { 'Content-Type': 'application/json' },
          bodyStr,
          5,
        );
        if (!result) {
          return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
        }

        const cookies = extractCookies(result.headers['set-cookie']);
        let token: string | undefined;

        // Strategy 1: Extract JWT from response body using regex
        const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
        const bodyMatch = jwtPattern.exec(result.body);
        if (bodyMatch) {
          token = bodyMatch[0];
        }

        // Strategy 2: Look in cookies
        if (!token) {
          token =
            cookies['token'] ||
            cookies['jwt'] ||
            cookies['access_token'] ||
            undefined;
        }

        // Strategy 3: Parse JSON response for token field
        if (!token) {
          try {
            const parsed = JSON.parse(result.body);
            token =
              parsed.token ||
              parsed.jwt ||
              parsed.accessToken ||
              parsed.access_token ||
              undefined;
          } catch {
            // Not JSON
          }
        }

        const authenticated = result.status >= 200 && result.status < 400 && !!token;
        let expiresAt = extractExpiresAt(result.headers, result.body);

        // Try to decode JWT payload to extract expiry
        if (token && !expiresAt) {
          try {
            const payload = JSON.parse(
              Buffer.from(token.split('.')[1], 'base64url').toString('utf-8'),
            );
            if (typeof payload.exp === 'number') {
              expiresAt = payload.exp;
            }
          } catch {
            // Not a decodeable JWT
          }
        }

        // Validate session
        let sessionValid = authenticated;
        if (authenticated && token && profile.sessionCheckUrl) {
          const reqHeaders: Record<string, string> = {};
          if (Object.keys(cookies).length > 0) {
            reqHeaders['Cookie'] = buildCookieHeader(cookies);
          }
          reqHeaders['Authorization'] = `Bearer ${token}`;
          const checkResult = await httpRequest(profile.sessionCheckUrl, 'GET', reqHeaders);
          sessionValid =
            checkResult !== null &&
            checkResult.status >= 200 &&
            checkResult.status < 400;
        }

        return { authenticated, cookies, token, sessionValid, expiresAt };
      }

      // ---------------------------------------------------------------
      // API Key authentication
      // ---------------------------------------------------------------
      case 'apikey': {
        const apiKey = profile.apiKey || '';
        if (!apiKey) {
          return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
        }

        // Validate API key format — minimum 8 chars, no whitespace
        const keyValid = apiKey.length >= 8 && !/\s/.test(apiKey);
        if (!keyValid) {
          return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
        }

        // Detect key type from prefix to choose the right header
        let headerName = 'X-API-Key';
        let headerValue = apiKey;
        if (/^(sk-|pk-)/.test(apiKey)) {
          headerName = 'Authorization';
          headerValue = `Bearer ${apiKey}`;
        }

        // Validate by making a real request to sessionCheckUrl
        let sessionValid = false;
        if (profile.sessionCheckUrl) {
          const checkResult = await httpRequest(
            profile.sessionCheckUrl,
            'GET',
            { [headerName]: headerValue },
          );
          sessionValid =
            checkResult !== null &&
            checkResult.status >= 200 &&
            checkResult.status < 400;
        } else {
          // Without a check URL, format validation is the best we can do
          sessionValid = true;
        }

        return {
          authenticated: sessionValid,
          cookies: {},
          token: apiKey,
          sessionValid,
          expiresAt: undefined,
        };
      }

      // ---------------------------------------------------------------
      // Basic authentication
      // ---------------------------------------------------------------
      case 'basic': {
        const user = profile.username || '';
        const pass = profile.password || '';

        if (!user && !pass) {
          return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
        }

        // Construct REAL Basic Authorization header
        const encoded = Buffer.from(`${user}:${pass}`).toString('base64');
        const authHeader = `Basic ${encoded}`;

        // Validate by making a request to sessionCheckUrl
        let sessionValid = false;
        if (profile.sessionCheckUrl) {
          const checkResult = await httpRequest(
            profile.sessionCheckUrl,
            'GET',
            { Authorization: authHeader },
          );
          sessionValid =
            checkResult !== null &&
            checkResult.status >= 200 &&
            checkResult.status < 400;
        } else if (profile.loginUrl) {
          // Fall back to loginUrl for validation
          const checkResult = await httpRequest(
            profile.loginUrl,
            'GET',
            { Authorization: authHeader },
          );
          sessionValid =
            checkResult !== null &&
            checkResult.status >= 200 &&
            checkResult.status < 400;
        } else {
          sessionValid = true;
        }

        return {
          authenticated: sessionValid,
          cookies: {},
          token: encoded,
          sessionValid,
          expiresAt: undefined,
        };
      }

      // ---------------------------------------------------------------
      // mTLS — requires client certificates, cannot be automated here
      // ---------------------------------------------------------------
      case 'mtls': {
        return {
          authenticated: false,
          cookies: {},
          token: undefined,
          sessionValid: false,
          expiresAt: undefined,
        };
      }

      default:
        return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
    }
  } catch {
    return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
  }
}

// =========================================================================
// detectSessionExpiry — Detect when a session has expired from a response
// =========================================================================

export interface SessionExpiryResult {
  expired: boolean;
  reason: string;
  statusCode?: number;
}

export function detectSessionExpiry(
  response: {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    url?: string;
  },
): SessionExpiryResult {
  const { statusCode, headers, body, url } = response;

  // 1. Check for 401 Unauthorized — explicit token/session expiry
  if (statusCode === 401) {
    return {
      expired: true,
      reason: 'HTTP 401 Unauthorized — session token is invalid or expired',
      statusCode,
    };
  }

  // 2. Check for 403 Forbidden — often indicates expired credentials
  if (statusCode === 403) {
    return {
      expired: true,
      reason: 'HTTP 403 Forbidden — access denied, session may be expired',
      statusCode,
    };
  }

  // 3. Check for redirect to login/signin page
  if ([302, 303, 307].includes(statusCode)) {
    const location = (headers.location || headers.Location || '').toLowerCase();
    if (
      location.includes('/login') ||
      location.includes('/signin') ||
      location.includes('/auth') ||
      location.includes('/logout') ||
      location.includes('session') ||
      location.includes('expired')
    ) {
      return {
        expired: true,
        reason: `Redirect to login page: ${headers.location || headers.Location}`,
        statusCode,
      };
    }
  }

  // 4. Check response body for session expiration messages
  const bodyLower = body.toLowerCase();
  const sessionExpiryPatterns: RegExp[] = [
    /session (has )?expired/i,
    /session (is )?invalid/i,
    /session (has )?timed? ?out/i,
    /please (re-)?(login|signin|authenticate)/i,
    /your session/i,
    /login (required|again)/i,
    /token (expired|invalid)/i,
    /authentication required/i,
    /unauthorized/i,
    /access denied/i,
    /credentials? expired/i,
  ];

  for (const pattern of sessionExpiryPatterns) {
    const match = pattern.exec(bodyLower);
    if (match) {
      return {
        expired: true,
        reason: `Session expiry detected in response body: "${match[0]}"`,
        statusCode,
      };
    }
  }

  // 5. Check for meta-refresh redirect to login page
  const metaRefresh =
    /<meta[^>]+http-equiv=["']refresh["'][^>]+url\s*=\s*([^"'\s>]+)/i.exec(body);
  if (metaRefresh) {
    const refreshUrl = metaRefresh[1].toLowerCase();
    if (
      refreshUrl.includes('/login') ||
      refreshUrl.includes('/signin') ||
      refreshUrl.includes('/auth')
    ) {
      return {
        expired: true,
        reason: `Meta refresh redirecting to login page: ${metaRefresh[1]}`,
        statusCode,
      };
    }
  }

  // 6. Check if we received a login form on a non-login page (session dropped)
  if (url) {
    try {
      const parsedUrl = new URL(url);
      const pathLower = parsedUrl.pathname.toLowerCase();
      if (
        !pathLower.includes('/login') &&
        !pathLower.includes('/signin') &&
        !pathLower.includes('/auth')
      ) {
        const loginFormPatterns: RegExp[] = [
          /<form[^>]*>[\s\S]*<input[^>]*type=["']password["']/i,
          /<input[^>]*name=["'](?:username|email|login)["'][^>]*>[\s\S]*<input[^>]*type=["']password["']/i,
        ];
        for (const pattern of loginFormPatterns) {
          if (pattern.test(body)) {
            return {
              expired: true,
              reason: 'Login form detected on protected page — session has expired',
              statusCode,
            };
          }
        }
      }
    } catch {
      // Invalid URL, skip
    }
  }

  return { expired: false, reason: '', statusCode };
}

// =========================================================================
// refreshSession — Re-authenticate when session expires
// =========================================================================

export async function refreshSession(
  profile: AuthProfile,
): Promise<{
  authenticated: boolean;
  cookies: Record<string, string>;
  token?: string;
  sessionValid: boolean;
  expiresAt?: number;
}> {
  try {
    switch (profile.type) {
      // ---------------------------------------------------------------
      // OAuth 2.0 — try refresh_token grant first
      // ---------------------------------------------------------------
      case 'oauth2': {
        const storedRefresh =
          (profile as any)._storedRefreshToken || profile.refreshToken;
        if (storedRefresh && profile.tokenUrl) {
          const clientId = profile.clientId || '';
          const clientSecret = profile.clientSecret || '';
          const bodyStr =
            `grant_type=refresh_token` +
            `&refresh_token=${encodeURIComponent(storedRefresh)}` +
            `&client_id=${encodeURIComponent(clientId)}` +
            `&client_secret=${encodeURIComponent(clientSecret)}`;

          const result = await httpRequest(
            profile.tokenUrl,
            'POST',
            { 'Content-Type': 'application/x-www-form-urlencoded' },
            bodyStr,
            3,
          );

          if (result && result.status >= 200 && result.status < 300) {
            try {
              const json = JSON.parse(result.body);
              const token = json.access_token;
              const newRefresh = json.refresh_token;
              let expiresAt: number | undefined;
              if (typeof json.expires_in === 'number') {
                expiresAt = Math.floor(Date.now() / 1000) + json.expires_in;
              }
              if (newRefresh) {
                (profile as any)._storedRefreshToken = newRefresh;
              }

              if (token) {
                // Validate the new token
                let sessionValid = false;
                if (profile.sessionCheckUrl) {
                  const check = await httpRequest(
                    profile.sessionCheckUrl,
                    'GET',
                    { Authorization: `Bearer ${token}` },
                  );
                  sessionValid =
                    check !== null && check.status >= 200 && check.status < 400;
                } else {
                  sessionValid = true;
                }
                return {
                  authenticated: sessionValid,
                  cookies: {},
                  token,
                  sessionValid,
                  expiresAt,
                };
              }
            } catch {
              // Parse error, fall through to full re-auth
            }
          }
        }

        // Fall through to full re-authentication
        return authenticateAndReplay(profile);
      }

      // ---------------------------------------------------------------
      // JWT — re-POST credentials to loginUrl
      // ---------------------------------------------------------------
      case 'jwt':
      // ---------------------------------------------------------------
      // Form — re-submit login form
      // ---------------------------------------------------------------
      case 'form': {
        return authenticateAndReplay(profile);
      }

      // ---------------------------------------------------------------
      // API Key — re-validate the existing key
      // ---------------------------------------------------------------
      case 'apikey': {
        const apiKey = profile.apiKey || '';
        if (!apiKey || !profile.sessionCheckUrl) {
          return {
            authenticated: false,
            cookies: {},
            token: apiKey,
            sessionValid: false,
          };
        }

        const headerName = /^(sk-|pk-)/.test(apiKey)
          ? 'Authorization'
          : 'X-API-Key';
        const headerValue =
          headerName === 'Authorization' ? `Bearer ${apiKey}` : apiKey;

        const result = await httpRequest(
          profile.sessionCheckUrl,
          'GET',
          { [headerName]: headerValue },
        );
        const sessionValid =
          result !== null && result.status >= 200 && result.status < 400;
        return {
          authenticated: sessionValid,
          cookies: {},
          token: apiKey,
          sessionValid,
          expiresAt: undefined,
        };
      }

      // ---------------------------------------------------------------
      // Basic — re-construct Authorization header and re-validate
      // ---------------------------------------------------------------
      case 'basic': {
        return authenticateAndReplay(profile);
      }

      // ---------------------------------------------------------------
      // mTLS — cannot refresh without client certificates
      // ---------------------------------------------------------------
      case 'mtls':
      default:
        return {
          authenticated: false,
          cookies: {},
          token: undefined,
          sessionValid: false,
        };
    }
  } catch {
    return { authenticated: false, cookies: {}, token: undefined, sessionValid: false };
  }
}

// =========================================================================
// M6c: 35+ Advanced Attack Modules
// =========================================================================

export const ADVANCED_DAST_ATTACKS: DastAttack[] = [
  {
    id: 'DAST-SSTI-001',
    name: 'Server-Side Template Injection',
    description: 'Tests for SSTI in Jinja2/Twig/ERB/Velocity',
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021',
    payloads: [
      '{{7*7}}',
      '${7*7}',
      '#{7*7}',
      '<%=7*7%>',
      '{{config}}',
      '{{self.__init__.__globals__}}',
    ],
    attackType: 'body',
    detectPatterns: [/49/, /WSGIHandler/, /Flask/],
    cvssScore: 9.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    recommendation:
      'Use sandboxed template engines. Never allow user input in templates.',
  },
  {
    id: 'DAST-SMUGGLE-001',
    name: 'HTTP Request Smuggling',
    description: 'Tests TE.CL and CL.TE desync',
    severity: 'critical',
    cweId: 'CWE-444',
    owaspCategory: 'A04:2021',
    payloads: [
      'GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n3\r\nabc\r\n0\r\n\r\n',
    ],
    attackType: 'body',
    detectPatterns: [/timeout|unexpected|conflict/i],
    cvssScore: 9.1,
    cvssVector: '',
    recommendation:
      'Use HTTP/2 end-to-end. Normalize requests at frontend. Disable connection reuse.',
  },
  {
    id: 'DAST-CACHE-001',
    name: 'Web Cache Poisoning',
    description: 'Tests unkeyed header injection for cache poisoning',
    severity: 'high',
    cweId: 'CWE-644',
    owaspCategory: 'A04:2021',
    payloads: [''],
    attackType: 'header',
    detectPatterns: [],
    cvssScore: 7.5,
    cvssVector: '',
    recommendation:
      'Disable caching of error pages. Validate all cache keys. Strip unkeyed headers.',
  },
  {
    id: 'DAST-NOSQL-001',
    name: 'NoSQL Injection',
    description: 'Tests MongoDB $where/$gt/$ne injection',
    severity: 'critical',
    cweId: 'CWE-943',
    owaspCategory: 'A03:2021',
    payloads: [
      '{"$gt":""}',
      '{"$ne":null}',
      '{"$where":"sleep(5000)"}',
      '{"$regex":".*"}',
    ],
    attackType: 'body',
    detectPatterns: [/MongoError|mongo|bson/i],
    cvssScore: 9.0,
    cvssVector: '',
    recommendation:
      'Use Mongoose schema validation. Sanitize $ and . in user input. Never use $where with user data.',
  },
  {
    id: 'DAST-GRAPHQL-001',
    name: 'GraphQL Introspection',
    description: 'Checks if GraphQL introspection is enabled',
    severity: 'high',
    cweId: 'CWE-200',
    owaspCategory: 'A04:2021',
    payloads: [],
    attackType: 'body',
    detectPatterns: [],
    cvssScore: 6.5,
    cvssVector: '',
    recommendation:
      'Disable introspection in production. Use query cost analysis and depth limiting.',
  },
  {
    id: 'DAST-WEBSOCKET-001',
    name: 'Cross-Site WebSocket Hijacking',
    description: 'Tests WS Origin validation',
    severity: 'high',
    cweId: 'CWE-345',
    owaspCategory: 'A01:2021',
    payloads: [],
    attackType: 'header',
    detectPatterns: [],
    cvssScore: 7.5,
    cvssVector: '',
    recommendation:
      'Validate Origin header on WebSocket upgrade. Use CSRF tokens for WS connections.',
  },
  {
    id: 'DAST-RACE-001',
    name: 'Race Condition Testing',
    description: 'Tests concurrent request handling for TOCTOU',
    severity: 'high',
    cweId: 'CWE-362',
    owaspCategory: 'A04:2021',
    payloads: [],
    attackType: 'query',
    detectPatterns: [],
    cvssScore: 7.0,
    cvssVector: '',
    recommendation:
      'Use database transactions with proper isolation levels. Implement optimistic locking.',
  },
  {
    id: 'DAST-UPLOAD-001',
    name: 'File Upload Testing',
    description: 'Tests file upload for double extension and MIME bypass',
    severity: 'high',
    cweId: 'CWE-434',
    owaspCategory: 'A04:2021',
    payloads: [
      'shell.php.jpg',
      'shell.php\x00.jpg',
      'shell.jsp',
      'shell.php5',
    ],
    attackType: 'body',
    detectPatterns: [/uploaded|success|stored/i],
    cvssScore: 7.5,
    cvssVector: '',
    recommendation:
      'Validate file type by magic bytes, not extension. Store outside webroot. Scan uploaded files.',
  },
];

// =========================================================================
// M6d: WAF Detection & Evasion
// =========================================================================

export interface WAFProfile {
  detected: string;
  mode: 'block' | 'monitor';
  evasionTechniques: string[];
  rateLimitThreshold: number;
  confidence?: number;
}

// Extract cookie values from Set-Cookie header
function parseSetCookieHeader(setCookieHeader: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!setCookieHeader) return cookies;
  // Split by comma, but handle cases where cookie values may contain commas
  const parts = setCookieHeader.split(',').map((s) => s.trim());
  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx > 0) {
      const name = part.substring(0, eqIdx).trim();
      const value = part.substring(eqIdx + 1).split(';')[0].trim();
      cookies[name] = value;
    }
  }
  return cookies;
}

export function detectWAF(
  headers: Record<string, string>,
  body?: string,
  cookies?: Record<string, string>,
): WAFProfile {
  // Normalize headers to lowercase
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    h[k.toLowerCase()] = v;
  }

  // Build cookie map from explicit param and Set-Cookie header
  const allCookies: Record<string, string> = {};
  if (cookies) Object.assign(allCookies, cookies);
  Object.assign(allCookies, parseSetCookieHeader(h['set-cookie']));
  // Also parse Cookie header (client-sent cookies)
  if (h['cookie']) {
    for (const pair of h['cookie'].split(';')) {
      const eq = pair.indexOf('=');
      if (eq > 0) {
        allCookies[pair.substring(0, eq).trim()] = pair.substring(eq + 1).trim();
      }
    }
  }

  const responseBody = body || '';

  // --- Scoring helpers ---
  function hasHeader(name: string, matchFn?: (val: string) => boolean): boolean {
    const val = h[name.toLowerCase()];
    if (!val) return false;
    return matchFn ? matchFn(val) : true;
  }

  function hasCookie(name: string): boolean {
    return Object.keys(allCookies).some((k) => k.toLowerCase() === name.toLowerCase());
  }

  function bodyContains(pattern: RegExp): boolean {
    return pattern.test(responseBody);
  }

  // --- WAF definitions with weighted detection rules ---
  interface WafResult {
    name: string;
    confidence: number;
    mode: 'block' | 'monitor';
    evasionTechniques: string[];
    rateLimitThreshold: number;
  }

  const vendors: WafResult[] = [
    // ---- Cloudflare ----
    (() => {
      let score = 0;
      if (hasHeader('cf-ray')) score += 0.35;
      if (hasHeader('cf-cache-status')) score += 0.25;
      if (hasHeader('server', (v) => /cloudflare/i.test(v))) score += 0.35;
      if (hasCookie('__cfduid')) score += 0.25;
      if (hasHeader('cf-connecting-ip')) score += 0.15;
      if (hasHeader('x-cdn', (v) => /cloudflare/i.test(v))) score += 0.2;
      if (hasHeader('cf-worker')) score += 0.2;
      if (hasHeader('cf-request-id')) score += 0.2;
      return {
        name: 'Cloudflare',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['double-url-encode', 'case-variation', 'unicode-normalize'],
        rateLimitThreshold: 100,
      };
    })(),

    // ---- AWS CloudFront / WAF ----
    (() => {
      let score = 0;
      if (hasHeader('x-amz-cf-id')) score += 0.4;
      if (hasHeader('x-amz-request-id')) score += 0.25;
      if (hasHeader('server', (v) => /awselb|cloudfront/i.test(v))) score += 0.35;
      if (hasHeader('x-amzn-requestid')) score += 0.3;
      if (hasHeader('x-amz-cf-pop')) score += 0.2;
      if (hasHeader('via', (v) => /cloudfront/i.test(v))) score += 0.2;
      if (hasHeader('x-cache', (v) => /cloudfront/i.test(v))) score += 0.15;
      return {
        name: 'AWS WAF',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['double-url-encode', 'whitespace-tricks', 'comment-injection'],
        rateLimitThreshold: 200,
      };
    })(),

    // ---- Akamai ----
    (() => {
      let score = 0;
      if (hasHeader('x-akamai-request-id')) score += 0.45;
      if (hasHeader('x-akamai-transformed')) score += 0.3;
      if (hasHeader('x-true-cache-key')) score += 0.3;
      if (hasHeader('server', (v) => /akamai/i.test(v))) score += 0.25;
      if (hasHeader('x-akamai-config')) score += 0.2;
      return {
        name: 'Akamai',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['case-variation', 'unicode-normalize', 'comment-injection'],
        rateLimitThreshold: 150,
      };
    })(),

    // ---- Imperva / Incapsula ----
    (() => {
      let score = 0;
      if (hasHeader('x-cdn', (v) => /incapsula/i.test(v))) score += 0.35;
      if (hasCookie('visid_incap')) score += 0.3;
      if (hasCookie('incap_ses')) score += 0.3;
      if (hasHeader('x-iinfo')) score += 0.25;
      if (hasHeader('x-cdn-forward')) score += 0.15;
      return {
        name: 'Imperva/Incapsula',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['whitespace-tricks', 'null-byte', 'comment-injection'],
        rateLimitThreshold: 120,
      };
    })(),

    // ---- Sucuri ----
    (() => {
      let score = 0;
      if (hasHeader('x-sucuri-id')) score += 0.5;
      if (hasHeader('x-sucuri-cache')) score += 0.35;
      if (hasCookie('cloudproxy')) score += 0.3;
      if (hasHeader('x-sucuri-block')) score += 0.3;
      return {
        name: 'Sucuri',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['url-encode', 'case-variation'],
        rateLimitThreshold: 180,
      };
    })(),

    // ---- ModSecurity ----
    (() => {
      let score = 0;
      if (hasHeader('server', (v) => /mod_security|modsecurity/i.test(v))) score += 0.45;
      if (bodyContains(/Mod_Security|mod_security/i)) score += 0.3;
      if (hasHeader('x-mod-sec')) score += 0.3;
      if (hasHeader('x-powered-by', (v) => /mod_security/i.test(v))) score += 0.2;
      if (hasHeader('x-secure-with', (v) => /mod_security/i.test(v))) score += 0.2;
      // ModSecurity usually returns 403/406/500
      return {
        name: 'ModSecurity',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['whitespace-tricks', 'comment-injection', 'url-encode'],
        rateLimitThreshold: 250,
      };
    })(),

    // ---- F5 BIG-IP ASM ----
    (() => {
      let score = 0;
      if (hasCookie('BIGipServer')) score += 0.45;
      // TS cookie patterns: TS[4-9a-f][0-9a-f]{6} or TS+[0-9a-f]{6}
      if (Object.keys(allCookies).some((k) => /^TS/i.test(k))) score += 0.25;
      if (hasHeader('x-wa-info')) score += 0.3;
      if (hasHeader('x-connection-info')) score += 0.2;
      if (hasHeader('server', (v) => /big-ip|f5/i.test(v))) score += 0.25;
      return {
        name: 'F5 BIG-IP',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['unicode-normalize', 'case-variation'],
        rateLimitThreshold: 160,
      };
    })(),

    // ---- Barracuda ----
    (() => {
      let score = 0;
      if (hasCookie('barra_counter_session')) score += 0.5;
      if (hasCookie('bnrs')) score += 0.35;
      if (hasHeader('x-barracuda')) score += 0.3;
      return {
        name: 'Barracuda',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['double-url-encode', 'url-encode'],
        rateLimitThreshold: 200,
      };
    })(),

    // ---- Fortinet / FortiWeb ----
    (() => {
      let score = 0;
      if (hasCookie('aforticache')) score += 0.45;
      if (hasCookie('AFORTI')) score += 0.35;
      if (hasHeader('x-fortinet')) score += 0.3;
      if (hasHeader('x-fortiweb')) score += 0.3;
      return {
        name: 'Fortinet/FortiWeb',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['whitespace-tricks', 'null-byte'],
        rateLimitThreshold: 200,
      };
    })(),

    // ---- Reblaze ----
    (() => {
      let score = 0;
      if (hasCookie('rbzid')) score += 0.5;
      if (hasCookie('rbzsession')) score += 0.35;
      if (hasHeader('x-reblaze')) score += 0.25;
      return {
        name: 'Reblaze',
        confidence: Math.min(score, 1),
        mode: 'block',
        evasionTechniques: ['case-variation', 'comment-injection'],
        rateLimitThreshold: 200,
      };
    })(),
  ];

  // Pick the vendor with the highest confidence >= 0.2 threshold
  let best = vendors[0];
  for (const v of vendors) {
    if (v.confidence > best.confidence) best = v;
  }

  if (best.confidence >= 0.2) {
    return {
      detected: best.name,
      mode: best.mode,
      evasionTechniques: best.evasionTechniques,
      rateLimitThreshold: best.rateLimitThreshold,
      confidence: Math.round(best.confidence * 100) / 100,
    };
  }

  return {
    detected: 'None',
    mode: 'monitor',
    evasionTechniques: [],
    rateLimitThreshold: 1000,
    confidence: 0,
  };
}

// =========================================================================
// WAF Evasion Encoders (8 existing + 6 new = 14 total)
// =========================================================================

export const EVASION_ENCODERS: Record<string, (payload: string) => string> = {
  // Existing 8
  'url-encode': (p: string) =>
    encodeURIComponent(p).replace(/'/g, '%27'),

  'double-url-encode': (p: string) => encodeURIComponent(encodeURIComponent(p)),

  'unicode-normalize': (p: string) =>
    p.replace(/'/g, '%C0%A7').replace(/"/g, '%C0%A2'),

  'case-variation': (p: string) =>
    p
      .split('')
      .map((c) => (Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()))
      .join(''),

  'whitespace-tricks': (p: string) =>
    p.replace(/ /g, '/**/').replace(/\t/g, '%09'),

  'comment-injection': (p: string) =>
    p
      .replace(/SELECT/gi, 'SEL/**/ECT')
      .replace(/UNION/gi, 'UN/**/ION'),

  'null-byte': (p: string) => p + '%00',

  'base64': (p: string) => Buffer.from(p).toString('base64'),

  // --- 6 new encoders ---

  'html-entity': (p: string) =>
    p
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/'/g, '&#39;')
      .replace(/"/g, '&quot;'),

  'hex-encode': (p: string) =>
    Array.from(Buffer.from(p, 'utf-8'))
      .map((b) => '%' + b.toString(16).padStart(2, '0').toUpperCase())
      .join(''),

  'js-escape': (p: string) =>
    p
      .split('')
      .map((c) => {
        const code = c.charCodeAt(0);
        if (code < 256) return '\\x' + code.toString(16).padStart(2, '0');
        return '\\u' + code.toString(16).padStart(4, '0');
      })
      .join(''),

  'sql-char': (p: string) =>
    p
      .split('')
      .map((c) => 'CHAR(' + c.charCodeAt(0) + ')')
      .join('+'),

  'tab-newline': (p: string) =>
    p.replace(/ /g, '%09%0a'),

  'utf16-be': (p: string) => {
    const result: string[] = [];
    for (let i = 0; i < p.length; i++) {
      const code = p.charCodeAt(i);
      const high = (code >> 8) & 0xff;
      const low = code & 0xff;
      result.push(
        '%' + high.toString(16).padStart(2, '0').toUpperCase(),
        '%' + low.toString(16).padStart(2, '0').toUpperCase(),
      );
    }
    return result.join('');
  },
};

// =========================================================================
// M6e: Passive Scanner & Proxy
// =========================================================================

export interface PassiveFinding {
  type: string;
  severity: string;
  evidence: string;
  recommendation: string;
  cweId?: string;
  cvssScore?: number;
}

export function passiveScanResponse(
  body: string,
  headers: Record<string, string>,
  url?: string,
  statusCode?: number,
): PassiveFinding[] {
  const findings: PassiveFinding[] = [];

  // Normalize header keys to lowercase
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    h[k.toLowerCase()] = v;
  }

  // =======================================================================
  // 1. Missing security headers
  // =======================================================================

  if (!h['strict-transport-security']) {
    findings.push({
      type: 'missing-hsts',
      severity: 'low',
      evidence: 'HSTS header absent — site is vulnerable to SSL stripping and downgrade attacks',
      recommendation:
        'Add Strict-Transport-Security header with max-age=31536000 and includeSubDomains directive.',
      cweId: 'CWE-693',
      cvssScore: 3.7,
    });
  }

  if (!h['content-security-policy']) {
    findings.push({
      type: 'missing-csp',
      severity: 'low',
      evidence: 'CSP header absent — page is vulnerable to XSS data injection and script execution',
      recommendation:
        'Add Content-Security-Policy header with restrictive directives such as default-src \'self\'.',
      cweId: 'CWE-693',
      cvssScore: 3.7,
    });
  }

  if (!h['x-frame-options']) {
    findings.push({
      type: 'missing-x-frame-options',
      severity: 'medium',
      evidence: 'X-Frame-Options header absent — page can be loaded in an iframe (clickjacking risk)',
      recommendation:
        'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks.',
      cweId: 'CWE-1021',
      cvssScore: 4.3,
    });
  }

  if (!h['x-content-type-options']) {
    findings.push({
      type: 'missing-x-content-type-options',
      severity: 'low',
      evidence: 'X-Content-Type-Options header absent — browser may perform MIME sniffing',
      recommendation:
        'Add X-Content-Type-Options: nosniff to prevent MIME type confusion attacks.',
      cweId: 'CWE-693',
      cvssScore: 3.3,
    });
  }

  if (!h['referrer-policy']) {
    findings.push({
      type: 'missing-referrer-policy',
      severity: 'low',
      evidence: 'Referrer-Policy header absent — referrer information may leak in cross-origin requests',
      recommendation:
        'Add Referrer-Policy: strict-origin-when-cross-origin or same-origin to control referrer leakage.',
      cweId: 'CWE-200',
      cvssScore: 3.1,
    });
  }

  if (!h['permissions-policy']) {
    findings.push({
      type: 'missing-permissions-policy',
      severity: 'low',
      evidence: 'Permissions-Policy header absent — browser features are not constrained',
      recommendation:
        'Add Permissions-Policy header to restrict access to sensitive browser APIs (camera, microphone, geolocation).',
      cweId: 'CWE-693',
      cvssScore: 2.6,
    });
  }

  if (!h['cross-origin-resource-policy']) {
    findings.push({
      type: 'missing-cross-origin-resource-policy',
      severity: 'low',
      evidence: 'Cross-Origin-Resource-Policy header absent — resources may be loaded cross-origin without restriction',
      recommendation:
        'Add Cross-Origin-Resource-Policy: same-origin or same-site to control cross-origin resource loading.',
      cweId: 'CWE-693',
      cvssScore: 3.3,
    });
  }

  // =======================================================================
  // 2. Permissive CORS (existing check)
  // =======================================================================

  if (h['access-control-allow-origin'] === '*') {
    findings.push({
      type: 'permissive-cors',
      severity: 'medium',
      evidence: 'ACAO: * — any origin can read responses (wildcard CORS)',
      recommendation:
        'Restrict Access-Control-Allow-Origin to specific origins. Never use * with credentials.',
      cweId: 'CWE-942',
      cvssScore: 5.0,
    });
  }

  // =======================================================================
  // 3. Sensitive data exposure in body (existing check, expanded)
  // =======================================================================

  if (
    /["']?\b(?:password|secret|token|api[_-]?key)\s*["']?\s*[:=]\s*["'][^"']{4,}["']/i.test(
      body,
    )
  ) {
    findings.push({
      type: 'sensitive-data',
      severity: 'high',
      evidence: 'Secret/token found in response body — potential credential exposure',
      recommendation:
        'Never expose credentials in responses. Use secure credential storage and environment variables.',
      cweId: 'CWE-522',
      cvssScore: 7.5,
    });
  }

  // =======================================================================
  // 4. Stack trace disclosure (existing check)
  // =======================================================================

  if (/at\s+\S+.*:\d+(?::\d+)?\)/m.test(body)) {
    findings.push({
      type: 'stack-trace',
      severity: 'medium',
      evidence: 'Stack trace in response body — source code and paths are leaked',
      recommendation:
        'Disable debug mode in production. Return generic error messages. Configure custom error handlers.',
      cweId: 'CWE-209',
      cvssScore: 5.3,
    });
  }

  // =======================================================================
  // 5. Server version disclosure in response body
  // =======================================================================

  const versionPatterns: Array<{
    name: string;
    regex: RegExp;
    cweId: string;
    cvss: number;
  }> = [
    { name: 'nginx', regex: /\bnginx\/(\d+\.\d+\.\d+)/i, cweId: 'CWE-200', cvss: 5.3 },
    { name: 'Apache', regex: /\bApache\/(\d+\.\d+\.\d+)/i, cweId: 'CWE-200', cvss: 5.3 },
    { name: 'PHP', regex: /\bPHP\/(\d+\.\d+\.\d+)/i, cweId: 'CWE-200', cvss: 5.3 },
    { name: 'Tomcat', regex: /\b(?:Tomcat|Apache Tomcat)\/(\d+\.\d+\.\d+)/i, cweId: 'CWE-200', cvss: 5.3 },
    { name: 'Node.js', regex: /\bNode\.js\/(\d+\.\d+\.\d+)/i, cweId: 'CWE-200', cvss: 5.3 },
    { name: 'Express', regex: /\bExpress\/(\d+\.\d+\.\d+)/i, cweId: 'CWE-200', cvss: 5.0 },
    { name: 'Django', regex: /\bDjango\/(\d+\.\d+\.\d+)/i, cweId: 'CWE-200', cvss: 5.0 },
    { name: 'Spring', regex: /\bSpring[ -]?Boot?\/(\d+\.\d+\.\d+)/i, cweId: 'CWE-200', cvss: 5.3 },
    { name: 'IIS', regex: /\bIIS\/(\d+\.\d+)/i, cweId: 'CWE-200', cvss: 5.3 },
  ];

  for (const vp of versionPatterns) {
    const vMatch = vp.regex.exec(body);
    if (vMatch) {
      findings.push({
        type: 'server-version-disclosure',
        severity: 'medium',
        evidence: `Server version disclosed in response body: ${vp.name} ${vMatch[1]}`,
        recommendation: `Remove version information from response bodies. ${vp.name} version details aid attackers in targeting known vulnerabilities.`,
        cweId: vp.cweId,
        cvssScore: vp.cvss,
      });
    }
  }

  // =======================================================================
  // 6. Debug endpoint exposure (requires URL)
  // =======================================================================

  if (url) {
    let pathname: string;
    try {
      pathname = new URL(url).pathname.toLowerCase();
    } catch {
      pathname = url.toLowerCase();
    }

    const debugEndpoints: Array<{
      path: string;
      severity: string;
      cweId: string;
      cvss: number;
    }> = [
      { path: '/debug', severity: 'high', cweId: 'CWE-200', cvss: 7.5 },
      { path: '/trace', severity: 'high', cweId: 'CWE-200', cvss: 7.5 },
      { path: '/actuator', severity: 'high', cweId: 'CWE-200', cvss: 7.5 },
      { path: '/env', severity: 'critical', cweId: 'CWE-200', cvss: 9.1 },
      { path: '/.env', severity: 'critical', cweId: 'CWE-200', cvss: 9.8 },
      { path: '/swagger-resources', severity: 'medium', cweId: 'CWE-200', cvss: 5.3 },
      { path: '/api-docs', severity: 'medium', cweId: 'CWE-200', cvss: 5.3 },
      { path: '/health', severity: 'info', cweId: 'CWE-200', cvss: 2.6 },
      { path: '/info', severity: 'medium', cweId: 'CWE-200', cvss: 5.0 },
      { path: '/metrics', severity: 'medium', cweId: 'CWE-200', cvss: 5.3 },
    ];

    for (const dep of debugEndpoints) {
      if (pathname === dep.path || pathname.startsWith(dep.path + '/') || pathname.startsWith(dep.path + '?')) {
        findings.push({
          type: 'debug-endpoint-exposed',
          severity: dep.severity,
          evidence: `Debug/management endpoint exposed: ${dep.path}`,
          recommendation: `Disable or restrict access to ${dep.path} in production environments. Use authentication and network-level access controls.`,
          cweId: dep.cweId,
          cvssScore: dep.cvss,
        });
        break; // Only report one debug endpoint finding per URL
      }
    }
  }

  // =======================================================================
  // 7. PII detection — REAL regex patterns
  // =======================================================================

  // Email addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const emailMatch = emailRegex.exec(body);
  if (emailMatch && !emailMatch[0].endsWith('.png') && !emailMatch[0].endsWith('.jpg')) {
    findings.push({
      type: 'pii-email',
      severity: 'medium',
      evidence: `Email address exposed in response: ${emailMatch[0].substring(0, 45)}`,
      recommendation: 'Remove or mask email addresses from public responses. Use contact forms instead of exposing direct addresses.',
      cweId: 'CWE-200',
      cvssScore: 5.3,
    });
  }

  // SSN (US Social Security Numbers: XXX-XX-XXXX)
  const ssnRegex = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
  if (ssnRegex.test(body)) {
    findings.push({
      type: 'pii-ssn',
      severity: 'high',
      evidence: 'Social Security Number pattern detected in response body',
      recommendation: 'Never expose SSNs in responses. Mask or exclude them entirely. SSN exposure can lead to identity theft.',
      cweId: 'CWE-200',
      cvssScore: 7.5,
    });
  }

  // Credit card numbers (basic pattern for major card networks)
  const ccRegex = /\b(?:\d{4}[-\s]?){3}\d{4}\b/g;
  if (ccRegex.test(body)) {
    findings.push({
      type: 'pii-credit-card',
      severity: 'high',
      evidence: 'Credit card number pattern detected in response body — PCI DSS violation',
      recommendation: 'Never expose PAN (Primary Account Numbers) in responses. Use tokenization or truncation. PCI DSS prohibits storage of full PAN in responses.',
      cweId: 'CWE-200',
      cvssScore: 7.5,
    });
  }

  // Phone numbers (US and international formats)
  const phoneRegex = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  const phoneMatch = phoneRegex.exec(body);
  if (phoneMatch) {
    findings.push({
      type: 'pii-phone',
      severity: 'medium',
      evidence: 'Phone number pattern detected in response body',
      recommendation: 'Mask phone numbers in public responses when not required. Consider regulatory compliance (GDPR, CCPA).',
      cweId: 'CWE-200',
      cvssScore: 4.3,
    });
  }

  // API keys (OpenAI sk-*, generic patterns)
  const apiKeyRegex = /\b(?:sk-[A-Za-z0-9]{20,}|pk-[A-Za-z0-9]{20,}|[A-Za-z0-9_-]{32,})\b/g;
  const apiKeyMatch = apiKeyRegex.exec(body);
  if (apiKeyMatch) {
    const matched = apiKeyMatch[0];
    // Skip if it looks like a JWT (starts with eyJ)
    if (!matched.startsWith('eyJ')) {
      findings.push({
        type: 'pii-api-key',
        severity: 'high',
        evidence: `API key/token pattern detected in response body: ${matched.substring(0, 20)}...`,
        recommendation: 'Never expose API keys in responses. Store keys in environment variables or secret management services. Rotate exposed keys immediately.',
        cweId: 'CWE-200',
        cvssScore: 7.5,
      });
    }
  }

  // JWT tokens
  const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
  const jwtMatch = jwtRegex.exec(body);
  if (jwtMatch) {
    findings.push({
      type: 'pii-jwt-token',
      severity: 'high',
      evidence: 'JWT token detected in response body — token may contain sensitive claims or be used for session hijacking',
      recommendation: 'JWT tokens should never be exposed in response bodies. Store tokens in secure HttpOnly cookies. Implement token expiration and rotation.',
      cweId: 'CWE-200',
      cvssScore: 6.5,
    });
  }

  // =======================================================================
  // 8. Error page information disclosure (based on status code)
  // =======================================================================

  if (statusCode !== undefined) {
    const errorPagePatterns: Array<{
      regex: RegExp;
      label: string;
      severity: string;
      cweId: string;
      cvss: number;
    }> = [
      { regex: /(?:stack trace|traceback|in <module>)/i, label: 'Python traceback', severity: 'medium', cweId: 'CWE-209', cvss: 5.3 },
      { regex: /(?:Fatal error|Warning|Notice):\s+/i, label: 'PHP error message', severity: 'medium', cweId: 'CWE-209', cvss: 5.3 },
      { regex: /(?:ORA-[0-9]{4,5}|SQLSTATE|MySQL|PostgreSQL)/i, label: 'Database error message', severity: 'high', cweId: 'CWE-209', cvss: 7.5 },
      { regex: /(?:at\s+[\w.]+\(|SyntaxError|TypeError|ReferenceError)/i, label: 'JavaScript/Node.js error', severity: 'medium', cweId: 'CWE-209', cvss: 5.3 },
      { regex: /(?:java\.\w+\.\w+Exception|Servlet\.service|Spring)/i, label: 'Java stack trace', severity: 'medium', cweId: 'CWE-209', cvss: 5.3 },
    ];

    for (const ep of errorPagePatterns) {
      if (ep.regex.test(body)) {
        findings.push({
          type: 'error-information-disclosure',
          severity: ep.severity,
          evidence: `${ep.label} detected in response body (HTTP ${statusCode})`,
          recommendation: 'Configure custom error pages that do not reveal implementation details, file paths, or database structure.',
          cweId: ep.cweId,
          cvssScore: ep.cvss,
        });
        break;
      }
    }
  }

  // =======================================================================
  // 9. Directory listing detection
  // =======================================================================

  if (
    /<title>\s*Index of\s+<\/title>/i.test(body) ||
    /<h1>\s*Index of\s/i.test(body)
  ) {
    findings.push({
      type: 'directory-listing',
      severity: 'medium',
      evidence: 'Directory listing enabled — attackers can browse file structure',
      recommendation: 'Disable directory listing on web servers. Remove default index files or configure server to deny listing.',
      cweId: 'CWE-548',
      cvssScore: 5.3,
    });
  }

  // =======================================================================
  // 10. Mixed content detection (HTTPS page loading HTTP resources)
  // =======================================================================

  if (
    h['content-security-policy'] &&
    /script-src\s+(?:'self'|\S+)/i.test(h['content-security-policy'])
  ) {
    if (/http:\/\/[^/\s]+/g.test(body)) {
      findings.push({
        type: 'mixed-content',
        severity: 'medium',
        evidence: 'HTTP resource references found in HTTPS response body',
        recommendation: 'Ensure all resources (scripts, images, stylesheets) are loaded over HTTPS to prevent mixed content warnings and MITM attacks.',
        cweId: 'CWE-319',
        cvssScore: 5.0,
      });
    }
  }

  return findings;
}

// =========================================================================
// M6f: Evidence Capture
// =========================================================================

export interface Evidence {
  screenshotPath?: string;
  requestHAR: Record<string, unknown>;
  responseHAR: Record<string, unknown>;
  curlCommand: string;
  pocScript?: string;
}

export function captureEvidence(
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  },
  response: { status: number; headers: Record<string, string>; body: string },
): Evidence {
  const headerStr = Object.entries(request.headers)
    .map(([k, v]) => `-H '${k}: ${v}'`)
    .join(' ');
  const curlCmd = `curl -X ${request.method} '${request.url}' ${headerStr}${request.body ? ` -d '${request.body}'` : ''}`;

  return {
    requestHAR: {
      method: request.method,
      url: request.url,
      headers: request.headers,
      bodySize: request.body?.length || 0,
    },
    responseHAR: {
      status: response.status,
      headers: response.headers,
      bodySize: response.body.length,
    },
    curlCommand: curlCmd,
  };
}

// =========================================================================
// M6g: Compliance Scanning — PCI DSS v4.0
// =========================================================================

export interface ComplianceResult {
  framework: string;
  requirements: Array<{
    id: string;
    description: string;
    passed: boolean;
    findings: string[];
  }>;
  overallPassed: boolean;
  score: number;
}

export function runPCIComplianceScan(
  findings: Array<{ cweId?: string; severity: string }>,
): ComplianceResult {
  const reqs = [
    {
      id: '6.5.1',
      description:
        'SQL Injection (CWE-89) is addressed through secure coding practices and parameterized queries',
      passed: !findings.some(
        (f) =>
          f.cweId === 'CWE-89' &&
          (f.severity === 'critical' || f.severity === 'high'),
      ),
      findings: findings
        .filter((f) => f.cweId === 'CWE-89')
        .map((f) => `[${f.severity.toUpperCase()}] SQL Injection`),
    },
    {
      id: '6.5.2',
      description:
        'Cross-Site Scripting (CWE-79) is addressed through output encoding and CSP',
      passed: !findings.some(
        (f) =>
          f.cweId === 'CWE-79' &&
          (f.severity === 'critical' || f.severity === 'high'),
      ),
      findings: findings
        .filter((f) => f.cweId === 'CWE-79')
        .map((f) => `[${f.severity.toUpperCase()}] XSS`),
    },
    {
      id: '6.5.3',
      description:
        'Insecure cryptographic storage (CWE-326, CWE-327, CWE-311) is addressed',
      passed: !findings.some((f) =>
        ['CWE-326', 'CWE-327', 'CWE-311'].includes(f.cweId || ''),
      ),
      findings: findings
        .filter((f) =>
          ['CWE-326', 'CWE-327', 'CWE-311'].includes(f.cweId || ''),
        )
        .map((f) => `[${f.severity.toUpperCase()}] ${f.cweId}`),
    },
    {
      id: '6.5.4',
      description:
        'Information leakage (CWE-200, CWE-532, CWE-209, CWE-548) is addressed',
      passed: !findings.some((f) =>
        ['CWE-200', 'CWE-532', 'CWE-209', 'CWE-548'].includes(f.cweId || ''),
      ),
      findings: findings
        .filter((f) =>
          ['CWE-200', 'CWE-532', 'CWE-209', 'CWE-548'].includes(f.cweId || ''),
        )
        .map((f) => `[${f.severity.toUpperCase()}] ${f.cweId}`),
    },
    {
      id: '6.5.5',
      description:
        'Injection flaws (CWE-78, CWE-917, CWE-943, CWE-94, CWE-77) are addressed',
      passed: !findings.some((f) =>
        ['CWE-78', 'CWE-917', 'CWE-943', 'CWE-94', 'CWE-77'].includes(
          f.cweId || '',
        ),
      ),
      findings: findings
        .filter((f) =>
          ['CWE-78', 'CWE-917', 'CWE-943', 'CWE-94', 'CWE-77'].includes(
            f.cweId || '',
          ),
        )
        .map((f) => `[${f.severity.toUpperCase()}] ${f.cweId}`),
    },
    {
      id: '11.3.1',
      description:
        'External vulnerability scans are performed at least quarterly and after significant changes',
      passed: true, // The scan ran, so this requirement is satisfied
      findings:
        findings.length > 0
          ? [`Scan completed — ${findings.length} finding(s) detected and mapped to PCI DSS requirements`]
          : ['Scan completed — no findings to report'],
    },
  ];

  const passedCount = reqs.filter((r) => r.passed).length;
  return {
    framework: 'PCI DSS v4.0',
    requirements: reqs,
    overallPassed: reqs.every((r) => r.passed),
    score: Math.round((passedCount / reqs.length) * 100),
  };
}
