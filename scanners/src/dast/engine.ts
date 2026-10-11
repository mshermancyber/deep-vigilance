import { logger } from '../utils/logger.js';

export interface DastTarget {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  contentType?: string;
}

export interface DastAttack {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cweId: string;
  owaspCategory: string;
  payloads: string[];
  attackType: 'query' | 'body' | 'header' | 'cookie' | 'path' | 'verb';
  detectPatterns: RegExp[];
  xssContextCheck?: boolean;
  cvssScore: number;
  cvssVector: string;
  recommendation: string;
}

export interface DastFinding {
  attackId: string;
  attackName: string;
  target: string;
  method: string;
  parameter: string;
  payload: string;
  evidence: string;
  severity: string;
  severityRank: number;
  cweId: string;
  owaspCategory: string;
  cvssScore: number;
  cvssVector: string;
  recommendation: string;
  description: string;
}

const SEVERITY_RANK: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

export const DAST_ATTACKS: DastAttack[] = [
  {
    id: 'DAST-SQLI-001',
    name: 'SQL Injection',
    description: 'Tests for SQL injection vulnerabilities by injecting SQL metacharacters and statements.',
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    attackType: 'query',
    payloads: [
      "'", "''", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
      "admin'--", "1' OR '1'='1'#", "' AND 1=2--", "'; DROP TABLE users--",
      "1 AND 1=1", "1 AND 1=2", "' WAITFOR DELAY '0:0:5'--",
      "1' ORDER BY 1--", "' UNION SELECT NULL,NULL,NULL--",
      "1)) AND 1337=1337 AND ((('1'='1",
      "'; EXEC xp_cmdshell('dir')--",
    ],
    detectPatterns: [
      /(mysql.*syntax|error in your SQL syntax)/i,
      /(microsoft.*odbc|odbc.*driver.*sql)/i,
      /(ORA-[0-9]{4,5})/,
      /(PostgreSQL.*ERROR)/,
      /(SQLite3?::?\w*Exception)/i,
      /(unclosed quotation mark)/i,
      /(SQL.*syntax.*error)/i,
      /(You have an error in your SQL)/i,
      /(quoted string not properly terminated)/i,
    ],
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    recommendation: 'Use parameterized queries and input validation. Never concatenate user input into SQL statements.',
  },
  {
    id: 'DAST-XSS-001',
    name: 'Cross-Site Scripting (XSS)',
    description: 'Tests for reflected and stored XSS vulnerabilities.',
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    attackType: 'query',
    payloads: [
      '<script>alert(1)</script>',
      '"><script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      'javascript:alert(1)',
      '<body onload=alert(1)>',
      '"><img src=x onerror=prompt(1)>',
      '<iframe src=javascript:alert(1)>',
      '"><ScRiPt>alert(1)</ScRiPt>',
      '<scr<script>ipt>alert(1)</scr</script>ipt>',
      '{{constructor.constructor("alert(1)")()}}',
      '${alert(1)}',
    ],
    detectPatterns: [
      /(<script>alert\(1\)<\/script>)/i,
      /(<img[^>]+onerror)/i,
      /(<svg[^>]+onload)/i,
    ],
    xssContextCheck: true,
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    recommendation: 'Encode output contextually. Implement CSP headers. Use framework auto-escaping features.',
  },
  {
    id: 'DAST-SSRF-001',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Tests for SSRF vulnerabilities by attempting to access internal resources.',
    severity: 'high',
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 - SSRF',
    attackType: 'query',
    payloads: [
      'http://169.254.169.254/latest/meta-data/',
      'http://127.0.0.1:8080',
      'http://localhost:3000',
      'http://[::1]:6379',
      'http://0.0.0.0',
      'file:///etc/passwd',
      'gopher://127.0.0.1:6379/_INFO',
      'dict://127.0.0.1:6379/INFO',
    ],
    detectPatterns: [
      /(ami-id|instance-id|public-keys|security-credentials)/,
      /(root:.*:0:0:)/,
    ],
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    recommendation: 'Validate and sanitize URLs. Use allowlists for remote hosts. Block requests to internal IP ranges.',
  },
  {
    id: 'DAST-CMDI-001',
    name: 'Command Injection',
    description: 'Tests for OS command injection vulnerabilities.',
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    attackType: 'query',
    payloads: [
      '; ls -la', '| ls -la', '`ls -la`', '$(ls -la)',
      '& dir', '&& whoami', '|| whoami',
      '| cat /etc/passwd', '; cat /etc/passwd',
      '; /bin/cat /etc/passwd', 'powershell Get-Process',
    ],
    detectPatterns: [
      /(root:.*:0:0:)/,
      /(Directory of |Volume in drive)/i,
    ],
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    recommendation: 'Avoid shell interpreters. Use execFile with array arguments. Validate and sanitize all inputs.',
  },
  {
    id: 'DAST-PT-001',
    name: 'Path Traversal',
    description: 'Tests for directory traversal vulnerabilities.',
    severity: 'high',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 - Broken Access Control',
    attackType: 'query',
    payloads: [
      '../../../etc/passwd', '..%2F..%2F..%2Fetc%2Fpasswd',
      '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..\\..\\..\\windows\\win.ini', '....\\\\....\\\\....\\\\windows\\\\win.ini',
    ],
    detectPatterns: [
      /(root:.*:0:0:)/,
      /(\[fonts\]|\[extensions\])/,
    ],
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    recommendation: 'Use allowlists for file paths. Normalize and validate all file access requests.',
  },
  {
    id: 'DAST-XXE-001',
    name: 'XML External Entity (XXE)',
    description: 'Tests for XXE vulnerabilities by injecting external entity declarations.',
    severity: 'high',
    cweId: 'CWE-611',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    attackType: 'body',
    payloads: [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://INTERNAL_HOST"> %xxe;]>',
    ],
    detectPatterns: [
      /(root:.*:0:0:)/,
    ],
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    recommendation: 'Disable external entities in XML parsers. Use JSON instead of XML.',
  },
  {
    id: 'DAST-CSRF-001',
    name: 'Cross-Site Request Forgery (CSRF)',
    description: 'Tests for missing CSRF tokens on state-changing requests.',
    severity: 'medium',
    cweId: 'CWE-352',
    owaspCategory: 'A01:2021 - Broken Access Control',
    attackType: 'header',
    payloads: [],
    detectPatterns: [],
    cvssScore: 6.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
    recommendation: 'Implement CSRF tokens for all state-changing requests. Use SameSite cookie attribute.',
  },
  {
    id: 'DAST-HEADER-001',
    name: 'Missing Security Headers',
    description: 'Checks for missing HTTP security headers.',
    severity: 'low',
    cweId: 'CWE-693',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    attackType: 'header',
    payloads: [],
    detectPatterns: [],
    cvssScore: 3.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
    recommendation: 'Implement HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers.',
  },
  {
    id: 'DAST-CORS-001',
    name: 'CORS Misconfiguration',
    description: 'Tests for overly permissive CORS configurations.',
    severity: 'medium',
    cweId: 'CWE-942',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    attackType: 'header',
    payloads: [],
    detectPatterns: [],
    cvssScore: 5.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    recommendation: 'Restrict Access-Control-Allow-Origin to specific origins. Never use wildcard with credentials.',
  },
  {
    id: 'DAST-JWT-001',
    name: 'JWT Security Issues',
    description: 'Tests for common JWT implementation flaws.',
    severity: 'high',
    cweId: 'CWE-347',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    attackType: 'header',
    payloads: [],
    detectPatterns: [],
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    recommendation: 'Verify JWT signatures. Use strong algorithms. Set appropriate expiration times.',
  },
];

export function generateAttackVectors(target: DastTarget): Array<{ target: DastTarget; attack: DastAttack; payload: string }> {
  const vectors: Array<{ target: DastTarget; attack: DastAttack; payload: string }> = [];

  for (const attack of DAST_ATTACKS) {
    if (attack.attackType === 'header' || attack.payloads.length === 0) {
      vectors.push({ target, attack, payload: '' });
      continue;
    }

    for (const payload of attack.payloads.slice(0, 10)) {
      const modifiedTarget = { ...target };

      switch (attack.attackType) {
        case 'query': {
          const url = new URL(target.url);
          if (url.searchParams.toString()) {
            const params = url.searchParams;
            const firstKey = [...params.keys()][0] || 'q';
            params.set(firstKey, params.get(firstKey)! + payload);
            modifiedTarget.url = url.toString();
          } else {
            modifiedTarget.url = `${target.url}?q=${encodeURIComponent(payload)}`;
          }
          break;
        }
        case 'body':
          if (target.body && (target.contentType?.includes('json') || target.contentType?.includes('xml'))) {
            modifiedTarget.body = payload;
          }
          break;
        case 'path':
          modifiedTarget.url = target.url.replace(/\/$/, '') + '/' + payload;
          break;
        default:
          break;
      }

      vectors.push({ target: modifiedTarget, attack, payload });
    }
  }

  return vectors;
}

export async function analyzeResponse(
  _target: DastTarget,
  attack: DastAttack,
  responseBody: string,
  responseHeaders: Record<string, string>,
  responseStatus?: number,
  baselineBody?: string,
): Promise<DastFinding[]> {
  const findings: DastFinding[] = [];

  if (attack.attackType === 'header') {
    switch (attack.id) {
      case 'DAST-HEADER-001': {
        const requiredHeaders = {
          'strict-transport-security': { name: 'HSTS', val: 'max-age=' },
          'content-security-policy': { name: 'CSP', val: '' },
          'x-frame-options': { name: 'X-Frame-Options', val: '' },
          'x-content-type-options': { name: 'X-Content-Type-Options', val: 'nosniff' },
          'referrer-policy': { name: 'Referrer-Policy', val: '' },
        };
        const missing: string[] = [];
        for (const [header, info] of Object.entries(requiredHeaders)) {
          if (!responseHeaders[header]) {
            missing.push(info.name);
          }
        }
        if (missing.length > 0) {
          findings.push({
            attackId: attack.id, attackName: attack.name,
            target: _target.url, method: _target.method,
            parameter: 'response-headers', payload: '',
            evidence: `Missing: ${missing.join(', ')}`,
            severity: 'low', severityRank: 4,
            cweId: attack.cweId, owaspCategory: attack.owaspCategory,
            cvssScore: attack.cvssScore, cvssVector: attack.cvssVector,
            recommendation: attack.recommendation,
            description: `Missing security headers: ${missing.join(', ')}`,
          });
        }
        break;
      }
      case 'DAST-CORS-001': {
        const acao = responseHeaders['access-control-allow-origin'];
        if (acao === '*' || acao === 'null') {
          findings.push({
            attackId: attack.id, attackName: attack.name,
            target: _target.url, method: _target.method,
            parameter: 'Access-Control-Allow-Origin', payload: '',
            evidence: `ACAO header value: ${acao}`,
            severity: 'medium', severityRank: 3,
            cweId: attack.cweId, owaspCategory: attack.owaspCategory,
            cvssScore: attack.cvssScore, cvssVector: attack.cvssVector,
            recommendation: attack.recommendation,
            description: `Overly permissive CORS configuration: ${acao}`,
          });
        }
        break;
      }
      case 'DAST-CSRF-001': {
        if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(_target.method.toUpperCase())) break;
        // Skip if the endpoint returned 404/405 — it doesn't actually accept this method
        if (responseStatus && (responseStatus === 404 || responseStatus === 405)) break;
        // JSON-only APIs protected by CORS preflight don't need CSRF tokens
        const ct = responseHeaders['content-type'] || '';
        if (ct.includes('application/json')) break;
        // SPA catch-all: if POST returns identical HTML as GET baseline, it's not a real endpoint
        if (baselineBody && ct.includes('text/html') && responseBody.slice(0, 2000) === baselineBody.slice(0, 2000)) break;
        // SameSite cookies also mitigate CSRF
        const setCookie = responseHeaders['set-cookie'] || '';
        if (/samesite\s*=\s*(strict|lax)/i.test(setCookie)) break;
        const hasCsrf = responseHeaders['x-csrf-token'] || responseHeaders['x-xsrf-token'];
        if (!hasCsrf) {
          findings.push({
            attackId: attack.id, attackName: attack.name,
            target: _target.url, method: _target.method,
            parameter: 'csrf-token', payload: '',
            evidence: 'No CSRF token header found in response',
            severity: 'medium', severityRank: 3,
            cweId: attack.cweId, owaspCategory: attack.owaspCategory,
            cvssScore: attack.cvssScore, cvssVector: attack.cvssVector,
            recommendation: attack.recommendation,
            description: 'No CSRF protection detected for state-changing request.',
          });
        }
        break;
      }
    }
  }

  if (attack.detectPatterns && attack.detectPatterns.length > 0) {
    // Skip error responses for injection findings — 4xx/5xx with generic error
    // pages often contain words like "syntax" or reflect input in error context
    if (responseStatus && responseStatus >= 400 && attack.attackType === 'query') {
      const isErrorPage = /<!DOCTYPE|<html|Internal Server Error|Not Found|Bad Request/i.test(responseBody);
      if (isErrorPage) return findings;
    }

    for (const pattern of attack.detectPatterns) {
      if (pattern.test(responseBody)) {
        // XSS context check: payload must appear in HTML context, not inside
        // JSON strings, JS object literals, or error stack traces
        if (attack.xssContextCheck) {
          const isJsonResponse = (responseHeaders['content-type'] || '').includes('application/json');
          const isInsideScript = /<script[^>]*>[\s\S]*?"[^"]*<script>alert/i.test(responseBody);
          const isErrorDump = /stack|trace|Error|exception/i.test(responseBody.slice(0, 500));
          if (isJsonResponse || isInsideScript || isErrorDump) continue;
        }

        findings.push({
          attackId: attack.id, attackName: attack.name,
          target: _target.url, method: _target.method,
          parameter: attack.attackType, payload: attack.payloads[0] || '',
          evidence: responseBody.slice(0, 300),
          severity: attack.severity, severityRank: SEVERITY_RANK[attack.severity] || 3,
          cweId: attack.cweId, owaspCategory: attack.owaspCategory,
          cvssScore: attack.cvssScore, cvssVector: attack.cvssVector,
          recommendation: attack.recommendation,
          description: attack.description,
        });
        break;
      }
    }
  }

  return findings;
}

export function crawlTarget(
  targetUrl: string,
  _options: { maxDepth?: number; maxPages?: number } = {},
): string[] {
  const urls = [targetUrl];

  try {
    const parsed = new URL(targetUrl);
    const commonPaths = [
      // Discovery
      '/', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/crossdomain.xml',
      '/clientaccesspolicy.xml', '/favicon.ico', '/humans.txt',

      // API endpoints
      '/api', '/api/', '/api/v1/', '/api/v2/', '/api/v3/', '/api/v4/',
      '/rest/', '/rest/v1/', '/rest/v2/', '/graphql', '/graphiql', '/playground',
      '/api-docs', '/api-docs/', '/swagger', '/swagger/', '/swagger-ui.html', '/swagger-ui/',
      '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml', '/redoc',
      '/docs', '/docs/', '/doc/', '/documentation', '/api/swagger.json',
      '/v1/', '/v2/', '/v3/',

      // Auth / user
      '/login', '/signin', '/sign-in', '/register', '/signup', '/sign-up', '/logout',
      '/auth', '/auth/', '/oauth', '/oauth/', '/oauth/token', '/oauth/authorize',
      '/api/auth', '/api/login', '/api/register', '/api/auth/login',
      '/api/users', '/api/user', '/users', '/user', '/account', '/profile', '/me',
      '/api/me', '/api/profile', '/api/account', '/password-reset', '/forgot-password',
      '/api/token', '/api/refresh', '/token', '/.auth',

      // Admin panels
      '/admin', '/admin/', '/administrator', '/manager', '/console',
      '/dashboard', '/panel', '/controlpanel', '/cpanel',
      '/wp-admin', '/wp-admin/', '/wp-login.php', '/wp-json/', '/wp-json/wp/v2/',
      '/admin/login', '/admin/dashboard', '/adminpanel',
      '/phpmyadmin', '/phpmyadmin/', '/pma/', '/adminer', '/adminer.php',
      '/pgadmin', '/pgadmin/', '/database',

      // Health/monitoring
      '/health', '/healthz', '/health/', '/healthcheck', '/ready', '/readyz', '/live', '/livez',
      '/status', '/status/', '/ping', '/pong',
      '/metrics', '/metrics/', '/prometheus', '/_metrics',
      '/info', '/version', '/build-info', '/env', '/actuator', '/actuator/health',
      '/actuator/info', '/actuator/env', '/actuator/beans', '/actuator/mappings',
      '/actuator/configprops', '/actuator/loggers', '/actuator/threaddump',
      '/__health', '/_health', '/_status', '/server-status', '/server-info',

      // Debug / dev
      '/debug', '/debug/', '/trace', '/trace/', '/test', '/test/',
      '/console/', '/devtools', '/_debug', '/__debug',
      '/elmah.axd', '/trace.axd', '/errors', '/error', '/error/',
      '/phpinfo', '/phpinfo.php', '/info.php', '/test.php',
      '/_profiler', '/_wdt', '/profiler',

      // Config / sensitive files
      '/.env', '/.env.local', '/.env.production', '/.env.backup',
      '/.git', '/.git/', '/.git/config', '/.git/HEAD', '/.gitignore',
      '/.svn', '/.svn/', '/.svn/entries',
      '/.htaccess', '/.htpasswd', '/web.config',
      '/config', '/config/', '/config.json', '/config.yaml', '/config.yml', '/config.xml',
      '/settings', '/settings.json', '/app.config', '/application.yml',
      '/package.json', '/composer.json', '/Gemfile', '/requirements.txt',
      '/Dockerfile', '/docker-compose.yml',
      '/backup', '/backup/', '/backups/', '/dump', '/dump.sql', '/database.sql',
      '/.DS_Store', '/Thumbs.db', '/.idea/', '/.vscode/',

      // Common app paths
      '/assets/', '/static/', '/public/', '/uploads/', '/upload/', '/files/', '/media/',
      '/images/', '/img/', '/css/', '/js/', '/fonts/',
      '/download', '/downloads/', '/export', '/import',
      '/search', '/api/search', '/api/v1/search',
      '/feed', '/feed/', '/rss', '/atom.xml',
      '/sitemap', '/archive', '/archives',
      '/contact', '/about', '/terms', '/privacy', '/faq',
      '/cart', '/checkout', '/orders', '/api/orders', '/api/products', '/products',
      '/api/v1/users', '/api/v1/products', '/api/v1/orders',

      // CMS / frameworks
      '/wp-content/', '/wp-includes/', '/wp-cron.php', '/xmlrpc.php',
      '/joomla/', '/drupal/', '/magento/', '/craft/',
      '/strapi/', '/ghost/', '/keystone/', '/payload/',
      '/rails/info', '/rails/mailers', '/_next/', '/_nuxt/',

      // Cloud / infra
      '/.aws/', '/aws/', '/.azure/', '/.gcp/',
      '/kubernetes', '/k8s', '/.kube/',

      // WebSocket
      '/ws', '/ws/', '/wss', '/websocket', '/socket', '/socket.io/',
      '/hub', '/signalr', '/signalr/',

      // GraphQL variations
      '/graphql/console', '/graphql/playground', '/altair', '/voyager',
      '/api/graphql', '/v1/graphql',
    ];

    for (const path of commonPaths) {
      urls.push(`${parsed.origin}${path}`);
    }
  } catch {
    // Invalid URL, skip crawling
  }

  return urls;
}
