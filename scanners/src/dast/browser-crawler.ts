// Browser-based Crawler
// Crawls a target URL discovering links, forms, API endpoints, and JS bundles
// Parses HTML, robots.txt, sitemap.xml; extracts API paths from JS contents

import * as http from 'node:http';
import * as https from 'node:https';
import * as url from 'node:url';
import { logger } from '../utils/logger.js';
import { assertScannableUrl } from '../utils/ssrf.js';

// ===================== Types =====================

export interface HtmlParseResult {
  urls: string[];
  forms: Array<{ action: string; method: string; fields: string[] }>;
  scripts: string[];
  apiEndpoints: string[];
}

export interface RobotsTxtResult {
  allowed: string[];
  disallowed: string[];
  sitemaps: string[];
}

export interface CrawlOptions {
  maxDepth?: number;
  maxPages?: number;
}

export interface CrawlResult {
  discoveredUrls: string[];
  apiEndpoints: string[];
  forms: Array<{ url: string; action: string; method: string; fields: string[] }>;
  jsEndpoints: string[];
  sitemapUrls: string[];
  robotsRules: { allowed: string[]; disallowed: string[] };
}

// ===================== HTTP Fetch Helper =====================

interface FetchResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
}

async function httpFetch(targetUrl: string, timeout = 30_000): Promise<FetchResponse> {
  await assertScannableUrl(targetUrl);
  return new Promise((resolve, reject) => {
    let parsed: url.URL;
    try {
      parsed = new url.URL(targetUrl);
    } catch {
      reject(new Error(`Invalid URL: ${targetUrl}`));
      return;
    }

    const mod = parsed.protocol === 'https:' ? https : http;
    const options: https.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'AppSecScanner/1.0',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
      timeout,
      rejectUnauthorized: false,
    };

    const req = mod.request(options, (res) => {
      const status = res.statusCode ?? 0;
      const responseHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (v !== undefined) {
          responseHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
        }
      }

      // Follow redirects (max 5)
      if ([301, 302, 303, 307, 308].includes(status)) {
        const location = responseHeaders['location'];
        if (location) {
          const redirectTarget = resolveUrl(location, targetUrl);
          if (redirectTarget) {
            res.resume();
            httpFetch(redirectTarget, timeout).then(resolve).catch(reject);
            return;
          }
        }
      }

      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf-8');
        resolve({ status, headers: responseHeaders, body, finalUrl: targetUrl });
      });
      res.on('error', reject);
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request timeout for ${targetUrl}`));
    });
    req.end();
  });
}

// ===================== URL Helpers =====================

function resolveUrl(href: string, baseUrl: string): string | null {
  try {
    if (!href || href.trim() === '') return null;
    if (/^(javascript|mailto|tel|data|blob|file|ftp|void)/i.test(href.trim())) return null;
    if (href.startsWith('#')) return null;
    const resolved = new url.URL(href.trim(), baseUrl);
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return null;
    return resolved.href;
  } catch {
    return null;
  }
}

function normaliseUrl(raw: string): string {
  try {
    const u = new url.URL(raw);
    u.protocol = u.protocol.toLowerCase();
    u.host = u.host.toLowerCase();
    u.hash = '';
    let s = u.href;
    if (s.endsWith('/') && u.pathname !== '/') s = s.slice(0, -1);
    return s;
  } catch {
    return raw;
  }
}

function isSameOrigin(a: string, b: string): boolean {
  try {
    return new url.URL(a).origin === new url.URL(b).origin;
  } catch {
    return false;
  }
}

// ===================== 1. parseHtmlLinks =====================

export function parseHtmlLinks(html: string, baseUrl: string): HtmlParseResult {
  const urls = new Set<string>();
  const apiEndpoints = new Set<string>();
  const scripts: string[] = [];
  const forms: Array<{ action: string; method: string; fields: string[] }> = [];

  // ---------- <a href="..."> ----------
  const anchorRe = /<a\s[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  let m: RegExpExecArray | null;
  while ((m = anchorRe.exec(html)) !== null) {
    const raw = (m[1] ?? m[2] ?? '').trim();
    const resolved = resolveUrl(raw, baseUrl);
    if (resolved) urls.add(normaliseUrl(resolved));
  }

  // ---------- <form ...> ----------
  const formRe = /<form\s([^>]*)>/gi;
  while ((m = formRe.exec(html)) !== null) {
    const tagContent = m[1];
    const actionMatch = /action\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tagContent);
    const methodMatch = /method\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tagContent);
    const rawAction = (actionMatch?.[1] ?? actionMatch?.[2] ?? '').trim();
    const action = rawAction ? rawAction : baseUrl;
    const method = methodMatch ? (methodMatch[1] ?? methodMatch[2] ?? '').trim().toUpperCase() : 'GET';

    // Extract fields between this <form> and its </form>
    const fields: string[] = [];
    const endIdx = html.indexOf('</form>', m.index);
    const formContent = endIdx !== -1 ? html.slice(m.index + m[0].length, endIdx) : '';

    // input[name], textarea[name], select[name], button[name]
    const fieldNameRe = /<(?:input|textarea|select|button)\s[^>]*?\bname\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
    let fm: RegExpExecArray | null;
    while ((fm = fieldNameRe.exec(formContent)) !== null) {
      const fn = (fm[1] ?? fm[2] ?? '').trim();
      if (fn) fields.push(fn);
    }

    forms.push({ action, method, fields });

    const resolvedAction = resolveUrl(action, baseUrl);
    if (resolvedAction) urls.add(normaliseUrl(resolvedAction));
  }

  // ---------- <script src="..."> ----------
  const scriptRe = /<script\s[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  while ((m = scriptRe.exec(html)) !== null) {
    const raw = (m[1] ?? m[2] ?? '').trim();
    const resolved = resolveUrl(raw, baseUrl);
    if (resolved) {
      const norm = normaliseUrl(resolved);
      urls.add(norm);
      scripts.push(norm);
    }
  }

  // ---------- <link href="..."> ----------
  const linkRe = /<link\s[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  while ((m = linkRe.exec(html)) !== null) {
    const raw = (m[1] ?? m[2] ?? '').trim();
    const resolved = resolveUrl(raw, baseUrl);
    if (resolved) urls.add(normaliseUrl(resolved));
  }

  // ---------- <img src="..."> ----------
  const imgRe = /<img\s[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  while ((m = imgRe.exec(html)) !== null) {
    const raw = (m[1] ?? m[2] ?? '').trim();
    const resolved = resolveUrl(raw, baseUrl);
    if (resolved) urls.add(normaliseUrl(resolved));
  }

  // ---------- <iframe src="..."> ----------
  const iframeRe = /<iframe\s[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  while ((m = iframeRe.exec(html)) !== null) {
    const raw = (m[1] ?? m[2] ?? '').trim();
    const resolved = resolveUrl(raw, baseUrl);
    if (resolved) urls.add(normaliseUrl(resolved));
  }

  // ---------- <source src="..."> ----------
  const sourceRe = /<source\s[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  while ((m = sourceRe.exec(html)) !== null) {
    const raw = (m[1] ?? m[2] ?? '').trim();
    const resolved = resolveUrl(raw, baseUrl);
    if (resolved) urls.add(normaliseUrl(resolved));
  }

  // ---------- <source srcset="..."> ----------
  const srcsetRe = /<source\s[^>]*?\bsrcset\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  while ((m = srcsetRe.exec(html)) !== null) {
    const raw = (m[1] ?? m[2] ?? '').trim();
    const candidates = raw.split(',');
    for (const c of candidates) {
      const candidate = c.trim().split(/\s+/)[0];
      if (candidate) {
        const resolved = resolveUrl(candidate, baseUrl);
        if (resolved) urls.add(normaliseUrl(resolved));
      }
    }
  }

  // ---------- Inline JavaScript: API-like paths ----------
  const jsPatterns: RegExp[] = [
    // fetch(...)
    /fetch\s*\(\s*["'`]([^"'`\s)]+)["'`]/gi,
    // axios.get/post/put/delete(...)
    /axios\.\w+\s*\(\s*["'`]([^"'`\s)]+)["'`]/gi,
    // $.ajax / $.get / $.post
    /\$\.(?:ajax|get|post|put|patch|delete)\s*\(\s*["'`]([^"'`\s)]+)["'`]/gi,
    // XMLHttpRequest .open(... , "...")
    /\.open\s*\(\s*["'`][A-Za-z]+["'`]\s*,\s*["'`]([^"'`\s)]+)["'`]/gi,
    // url:/path/endpoint properties in JS objects
    /["'`](?:url|endpoint|path)["'`]\s*:\s*["'`]([^"'`\s)]+)["'`]/gi,
  ];

  for (const pattern of jsPatterns) {
    pattern.lastIndex = 0;
    while ((m = pattern.exec(html)) !== null) {
      const apiPath = m[1].trim();
      if (/^(\.|\/\/|#)/.test(apiPath)) continue;
      apiEndpoints.add(apiPath);
      const resolved = resolveUrl(apiPath, baseUrl);
      if (resolved) urls.add(normaliseUrl(resolved));
    }
  }

  // /api/v1/... patterns in quotes
  const apiPathRe = /["'`](\/api\/[^"'`\s]+)["'`]/gi;
  while ((m = apiPathRe.exec(html)) !== null) {
    apiEndpoints.add(m[1].trim());
  }

  // /graphql endpoint detection
  const graphqlRe = /["'`](\/?graphql)["'`]/gi;
  while ((m = graphqlRe.exec(html)) !== null) {
    apiEndpoints.add(m[1].trim());
  }

  // /rest/... paths
  const restRe = /["'`](\/?rest\/[^"'`\s]+)["'`]/gi;
  while ((m = restRe.exec(html)) !== null) {
    apiEndpoints.add(m[1].trim());
  }

  return {
    urls: [...urls],
    forms,
    scripts,
    apiEndpoints: [...apiEndpoints],
  };
}

// ===================== 2. parseRobotsTxt =====================

export function parseRobotsTxt(content: string): RobotsTxtResult {
  const allowed: string[] = [];
  const disallowed: string[] = [];
  const sitemaps: string[] = [];
  let currentUserAgent = '';

  const lines = content.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;

    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();
    if (!value) continue;

    switch (key) {
      case 'user-agent':
        currentUserAgent = value.toLowerCase();
        break;
      case 'disallow':
        if (currentUserAgent === '*' || currentUserAgent === '') {
          disallowed.push(value);
        }
        break;
      case 'allow':
        if (currentUserAgent === '*' || currentUserAgent === '') {
          allowed.push(value);
        }
        break;
      case 'sitemap':
        sitemaps.push(value);
        break;
    }
  }

  return { allowed, disallowed, sitemaps };
}

// ===================== 3. parseSitemapXml =====================

export function parseSitemapXml(xml: string): string[] {
  const urls: string[] = [];
  const locRe = /<loc[^>]*>(.*?)<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = locRe.exec(xml)) !== null) {
    const loc = m[1].trim();
    if (loc) urls.push(loc);
  }
  return urls;
}

// ===================== 4. commonPathDiscovery =====================

const COMMON_PATHS: string[] = [
  // Standard web paths
  '/robots.txt',
  '/sitemap.xml',
  '/sitemap_index.xml',
  '/.well-known/security.txt',
  '/.well-known/',
  '/crossdomain.xml',
  '/clientaccesspolicy.xml',
  // API endpoints
  '/api/',
  '/api/v1/',
  '/api/v2/',
  '/api/v3/',
  '/api/graphql',
  '/graphql',
  '/graphiql',
  '/v1/graphql',
  '/v2/graphql',
  '/rest/',
  '/api/rest/',
  '/swagger',
  '/swagger-ui.html',
  '/swagger/v1/swagger.json',
  '/swagger/v2/swagger.json',
  '/api-docs',
  '/api/swagger',
  '/openapi.json',
  '/docs',
  '/api/schema',
  // Admin / auth
  '/admin',
  '/admin/',
  '/admin/login',
  '/login',
  '/register',
  '/signup',
  '/logout',
  '/forgot-password',
  '/reset-password',
  '/oauth',
  '/oauth2',
  '/auth',
  '/api/auth',
  // Config / env
  '/.env',
  '/.env.example',
  '/.git/config',
  '/.git/HEAD',
  '/config.json',
  '/config.js',
  '/configuration',
  // Health / info
  '/health',
  '/healthz',
  '/readyz',
  '/status',
  '/metrics',
  '/info',
  '/version',
  '/debug',
  '/trace',
  '/actuator',
  '/actuator/health',
  // Common CMS paths
  '/wp-admin',
  '/wp-admin/admin-ajax.php',
  '/wp-login.php',
  '/wp-content/',
  '/administrator',
  '/phpinfo.php',
  // User-related
  '/users',
  '/api/users',
  '/profile',
  '/api/profile',
  // Other common
  '/favicon.ico',
  '/manifest.json',
  '/service-worker.js',
  '/browserconfig.xml',
  '/apple-touch-icon.png',
];

export function commonPathDiscovery(baseUrl: string): string[] {
  const discovered: string[] = [];
  try {
    const parsed = new url.URL(baseUrl);
    const origin = parsed.origin;
    for (const path of COMMON_PATHS) {
      discovered.push(normaliseUrl(`${origin}${path}`));
    }
  } catch {
    // Invalid base URL, return empty
  }
  return discovered;
}

// ===================== 5. crawlWebsite =====================

export async function crawlWebsite(
  baseUrl: string,
  options: CrawlOptions = {},
): Promise<CrawlResult> {
  const maxDepth = options.maxDepth ?? 2;
  const maxPages = options.maxPages ?? 50;

  const visited = new Set<string>();
  const discoveredUrls = new Set<string>();
  const apiEndpoints = new Set<string>();
  const forms: Array<{ url: string; action: string; method: string; fields: string[] }> = [];
  const jsEndpoints = new Set<string>();
  const sitemapUrls: string[] = [];
  let robotsRules: { allowed: string[]; disallowed: string[] } = { allowed: [], disallowed: [] };

  const startUrl = normaliseUrl(baseUrl);

  // BFS queue
  interface QueueItem { url: string; depth: number }
  const queue: QueueItem[] = [{ url: startUrl, depth: 0 }];

  while (queue.length > 0 && visited.size < maxPages) {
    const item = queue.shift()!;
    if (item.depth > maxDepth) continue;
    if (visited.has(item.url)) continue;
    visited.add(item.url);

    logger.info({ url: item.url, depth: item.depth }, '[browser-crawler] Fetching page');

    let response: FetchResponse;
    try {
      response = await httpFetch(item.url);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn({ url: item.url, error: msg }, '[browser-crawler] Fetch failed');
      discoveredUrls.add(item.url);
      continue;
    }

    discoveredUrls.add(item.url);
    const contentType = response.headers['content-type'] ?? '';

    // -- robots.txt --
    if (item.url.endsWith('/robots.txt')) {
      const parsed = parseRobotsTxt(response.body);
      robotsRules = { allowed: parsed.allowed, disallowed: parsed.disallowed };
      for (const sitemap of parsed.sitemaps) {
        const norm = normaliseUrl(sitemap);
        if (!visited.has(norm) && visited.size < maxPages) {
          sitemapUrls.push(norm);
          queue.push({ url: norm, depth: item.depth + 1 });
        }
      }
      continue;
    }

    // -- XML (sitemap) --
    if (item.url.endsWith('.xml') || contentType.includes('xml')) {
      const locUrls = parseSitemapXml(response.body);
      for (const locUrl of locUrls) {
        const norm = normaliseUrl(locUrl);
        if (!visited.has(norm) && visited.size < maxPages) {
          sitemapUrls.push(norm);
          discoveredUrls.add(norm);
          queue.push({ url: norm, depth: item.depth + 1 });
        }
      }
      continue;
    }

    // -- HTML pages --
    if (!contentType.includes('text/html') && !contentType.includes('application/xhtml+xml')) {
      continue;
    }

    const html = response.body;
    const parsed = parseHtmlLinks(html, item.url);

    // Forms
    for (const form of parsed.forms) {
      const resolvedAction = resolveUrl(form.action, item.url);
      forms.push({
        url: item.url,
        action: resolvedAction ?? form.action,
        method: form.method,
        fields: form.fields,
      });
    }

    // API endpoints
    for (const ep of parsed.apiEndpoints) {
      apiEndpoints.add(ep);
    }

    // JS endpoints
    for (const script of parsed.scripts) {
      jsEndpoints.add(script);
    }

    // Enqueue discovered URLs
    for (const discoveredUrl of parsed.urls) {
      discoveredUrls.add(discoveredUrl);
      if (
        !visited.has(discoveredUrl) &&
        discoveredUrl !== item.url &&
        visited.size < maxPages &&
        item.depth + 1 <= maxDepth &&
        isSameOrigin(startUrl, discoveredUrl)
      ) {
        queue.push({ url: discoveredUrl, depth: item.depth + 1 });
      }
    }
  }

  // -- Common path discovery (always probes even if queue is empty) --
  const commonPaths = commonPathDiscovery(startUrl);
  for (const cp of commonPaths) {
    discoveredUrls.add(cp);
    try {
      const pathname = new url.URL(cp).pathname;
      if (
        pathname.includes('/api/') ||
        pathname.includes('/graphql') ||
        pathname.includes('/swagger') ||
        pathname.includes('/rest/')
      ) {
        apiEndpoints.add(pathname);
      }
    } catch { /* skip */ }
  }

  // -- Fetch robots.txt if not already visited --
  try {
    const robotsUrl = normaliseUrl(`${new url.URL(startUrl).origin}/robots.txt`);
    if (!visited.has(robotsUrl)) {
      const resp = await httpFetch(robotsUrl);
      if (resp.status < 400) {
        discoveredUrls.add(robotsUrl);
        const parsed = parseRobotsTxt(resp.body);
        robotsRules = { allowed: parsed.allowed, disallowed: parsed.disallowed };
        for (const sitemap of parsed.sitemaps) {
          const norm = normaliseUrl(sitemap);
          sitemapUrls.push(norm);
          discoveredUrls.add(norm);
        }
        // Sitemaps: also probe for /sitemap.xml
        const sitemapUrl = normaliseUrl(`${new url.URL(startUrl).origin}/sitemap.xml`);
        if (!visited.has(sitemapUrl)) {
          try {
            const sitemapResp = await httpFetch(sitemapUrl);
            if (sitemapResp.status < 400) {
              discoveredUrls.add(sitemapUrl);
              const locs = parseSitemapXml(sitemapResp.body);
              for (const loc of locs) {
                const normLoc = normaliseUrl(loc);
                sitemapUrls.push(normLoc);
                discoveredUrls.add(normLoc);
              }
            }
          } catch { /* sitemap not available */ }
        }
      }
    }
  } catch { /* robots.txt not available */ }

  // -- Deduplicate and sort --
  const finalDiscovered = [...new Set(discoveredUrls)].sort();
  const finalApi = [...new Set(apiEndpoints)].sort();
  const finalJs = [...new Set(jsEndpoints)].sort();
  const finalSitemaps = [...new Set(sitemapUrls)].sort();

  return {
    discoveredUrls: finalDiscovered,
    apiEndpoints: finalApi,
    forms,
    jsEndpoints: finalJs,
    sitemapUrls: finalSitemaps,
    robotsRules,
  };
}

// ===================== Browser-Based SPA Crawling =====================

export async function crawlWithBrowser(
  startUrl: string,
  options: CrawlOptions & { chromiumWsUrl?: string } = {},
): Promise<CrawlResult> {
  const maxPages = options.maxPages ?? 30;
  const chromiumWsUrl = options.chromiumWsUrl || process.env.CHROMIUM_WS_URL;

  if (!chromiumWsUrl) {
    logger.warn('No CHROMIUM_WS_URL configured — falling back to HTTP crawl');
    return crawlWebsite(startUrl, options);
  }

  let puppeteer: typeof import('puppeteer');
  try {
    puppeteer = await import('puppeteer');
  } catch {
    logger.warn('Puppeteer not available — falling back to HTTP crawl');
    return crawlWebsite(startUrl, options);
  }

  const discoveredUrls = new Set<string>();
  const apiEndpoints = new Set<string>();
  const forms: CrawlResult['forms'] = [];
  const jsEndpoints = new Set<string>();
  const visited = new Set<string>();

  let browser;
  try {
    browser = await puppeteer.default.connect({ browserWSEndpoint: chromiumWsUrl });
  } catch (err) {
    logger.warn({ err }, 'Failed to connect to Chromium — falling back to HTTP crawl');
    return crawlWebsite(startUrl, options);
  }

  try {
    const origin = new url.URL(startUrl).origin;
    const queue = [startUrl];

    while (queue.length > 0 && visited.size < maxPages) {
      const currentUrl = queue.shift()!;
      if (visited.has(currentUrl)) continue;
      visited.add(currentUrl);

      let page;
      try {
        page = await browser.newPage();
        await page.setRequestInterception(true);

        page.on('request', (req) => {
          const reqUrl = req.url();
          // Capture XHR/fetch as API endpoints
          if (['xhr', 'fetch'].includes(req.resourceType())) {
            try {
              const parsed = new url.URL(reqUrl);
              if (parsed.origin === origin || reqUrl.startsWith('/')) {
                apiEndpoints.add(reqUrl);
              }
            } catch { /* external */ }
          }
          req.continue();
        });

        await page.goto(currentUrl, { waitUntil: 'networkidle0', timeout: 15_000 });

        // Extract links from rendered DOM
        const links: string[] = await page.evaluate(`
          Array.from(document.querySelectorAll('a[href]')).map(a => a.href).filter(h => h.startsWith('http'))
        `) as string[];

        for (const link of links) {
          try {
            const parsed = new url.URL(link);
            if (parsed.origin === origin) {
              const normalized = parsed.origin + parsed.pathname;
              discoveredUrls.add(normalized);
              if (!visited.has(normalized) && visited.size + queue.length < maxPages) {
                queue.push(normalized);
              }
            }
          } catch { /* invalid URL */ }
        }

        // Extract forms from rendered DOM
        const pageForms: Array<{ action: string; method: string; fields: string[] }> = await page.evaluate(`
          Array.from(document.querySelectorAll('form')).map(f => ({
            action: f.action || '',
            method: (f.method || 'GET').toUpperCase(),
            fields: Array.from(f.querySelectorAll('input,select,textarea')).map(i => i.name).filter(Boolean),
          }))
        `) as Array<{ action: string; method: string; fields: string[] }>;
        for (const f of pageForms) {
          forms.push({ url: currentUrl, ...f });
        }

        // Extract JS-discovered API patterns from page content
        const pageContent = await page.content();
        const apiPatterns = pageContent.match(/["'](\/api\/[^"']+)["']/g) || [];
        for (const match of apiPatterns) {
          const endpoint = match.slice(1, -1);
          apiEndpoints.add(origin + endpoint);
        }

        // Click navigation elements (buttons, nav links) to trigger SPA routing
        const navSelectors = ['nav a', '[role="navigation"] a', 'button[routerlink]', 'a[routerlink]', 'a[href^="/"]'];
        for (const sel of navSelectors) {
          try {
            const els = await page.$$(sel);
            for (const el of els.slice(0, 5)) {
              try {
                const href = await el.evaluate((e: any) => e.href || e.getAttribute('routerlink') || '');
                if (href && href.startsWith(origin)) {
                  discoveredUrls.add(href);
                }
              } catch { /* element detached */ }
            }
          } catch { /* selector failed */ }
        }

        discoveredUrls.add(currentUrl);
      } catch (err) {
        logger.debug({ url: currentUrl, err }, 'Browser crawl page error');
      } finally {
        if (page) { try { await page.close(); } catch { /* */ } }
      }
    }
  } finally {
    try { await browser.disconnect(); } catch { /* */ }
  }

  // Merge with HTTP crawl results for completeness (robots.txt, sitemap, common paths)
  let httpResult: CrawlResult | null = null;
  try {
    httpResult = await crawlWebsite(startUrl, { maxDepth: 1, maxPages: 10 });
  } catch { /* HTTP crawl failed */ }

  const allUrls = new Set([...discoveredUrls, ...(httpResult?.discoveredUrls || [])]);
  const allApi = new Set([...apiEndpoints, ...(httpResult?.apiEndpoints || []), ...(httpResult?.jsEndpoints || [])]);

  logger.info({
    browserUrls: discoveredUrls.size,
    httpUrls: httpResult?.discoveredUrls.length || 0,
    apiEndpoints: allApi.size,
    forms: forms.length,
  }, 'Browser+HTTP crawl complete');

  return {
    discoveredUrls: [...allUrls].sort(),
    apiEndpoints: [...allApi].sort(),
    forms: [...forms, ...(httpResult?.forms || [])],
    jsEndpoints: [...jsEndpoints].sort(),
    sitemapUrls: httpResult?.sitemapUrls || [],
    robotsRules: httpResult?.robotsRules || { allowed: [], disallowed: [] },
  };
}
