// M6e: Passive Scanner
// Analyzes HTTP responses for security issues WITHOUT sending attacks
// Checks: security headers, cookie flags, information disclosure, tech fingerprinting, sensitive data

import { logger } from '../utils/logger.js';

// ===================== Types =====================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface PassiveFinding {
  type: string;
  severity: Severity;
  evidence: string;
  recommendation: string;
  cweId: string;
  category: string;
}

export interface PassiveScanResult {
  findings: PassiveFinding[];
  targetUrl: string;
  scanTime: string;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

// ===================== Security Headers Configuration =====================

interface SecurityHeaderRule {
  name: string;
  description: string;
  severity: Severity;
  cweId: string;
  expectedValue: RegExp;
  recommendation: string;
}

const REQUIRED_SECURITY_HEADERS: Record<string, SecurityHeaderRule> = {
  'strict-transport-security': {
    name: 'HTTP Strict Transport Security (HSTS)',
    description: 'Enforces HTTPS connections and prevents downgrade attacks',
    severity: 'low',
    cweId: 'CWE-523',
    expectedValue: /max-age=\d+/i,
    recommendation: 'Add Strict-Transport-Security header with max-age=31536000; includeSubDomains; preload. This forces all future connections to use HTTPS.',
  },
  'content-security-policy': {
    name: 'Content Security Policy (CSP)',
    description: 'Controls which resources can be loaded, mitigating XSS and data injection attacks',
    severity: 'low',
    cweId: 'CWE-1021',
    expectedValue: /default-src|script-src|style-src|frame-src|object-src/i,
    recommendation: 'Add Content-Security-Policy header with restrictive directives. Prefer nonces or hashes over unsafe-inline. Use strict-dynamic for modern CSP.',
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    description: 'Prevents clickjacking by controlling if the page can be embedded in frames',
    severity: 'low',
    cweId: 'CWE-1021',
    expectedValue: /DENY|SAMEORIGIN/i,
    recommendation: 'Add X-Frame-Options: DENY (preferred) or SAMEORIGIN to prevent clickjacking attacks.',
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME type sniffing which can lead to drive-by download attacks',
    severity: 'low',
    cweId: 'CWE-200',
    expectedValue: /nosniff/i,
    recommendation: 'Add X-Content-Type-Options: nosniff to prevent browsers from MIME-type sniffing responses.',
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    description: 'Controls how much referrer information is sent with requests',
    severity: 'low',
    cweId: 'CWE-200',
    expectedValue: /strict-origin-when-cross-origin|strict-origin|no-referrer|same-origin/i,
    recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin (or stricter) to control referrer information leakage.',
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    description: 'Controls which browser APIs and features the page can use',
    severity: 'info',
    cweId: 'CWE-693',
    expectedValue: /.+/,
    recommendation: 'Add Permissions-Policy header to restrict browser feature access (geolocation, camera, microphone, etc.).',
  },
  'cache-control': {
    name: 'Cache-Control',
    description: 'Controls how and for how long responses are cached',
    severity: 'low',
    cweId: 'CWE-524',
    expectedValue: /no-store|no-cache|private|max-age=\d+/i,
    recommendation: 'Set Cache-Control: no-store, no-cache for sensitive pages. Use appropriate caching for public assets.',
  },
  'cross-origin-opener-policy': {
    name: 'Cross-Origin-Opener-Policy (COOP)',
    description: 'Isolates cross-origin windows to prevent side-channel attacks',
    severity: 'low',
    cweId: 'CWE-693',
    expectedValue: /same-origin|same-origin-allow-popups/i,
    recommendation: 'Add Cross-Origin-Opener-Policy: same-origin to isolate your origin from cross-origin windows.',
  },
  'cross-origin-embedder-policy': {
    name: 'Cross-Origin-Embedder-Policy (COEP)',
    description: 'Prevents loading cross-origin resources that don\'t explicitly grant permission',
    severity: 'low',
    cweId: 'CWE-693',
    expectedValue: /require-corp/i,
    recommendation: 'Add Cross-Origin-Embedder-Policy: require-corp for cross-origin isolation (enables powerful features like SharedArrayBuffer).',
  },
  'cross-origin-resource-policy': {
    name: 'Cross-Origin-Resource-Policy (CORP)',
    description: 'Controls which origins can load cross-origin resources',
    severity: 'low',
    cweId: 'CWE-693',
    expectedValue: /same-origin|same-site/i,
    recommendation: 'Add Cross-Origin-Resource-Policy: same-origin to restrict resource sharing to same-origin only.',
  },
};

// ===================== Information Disclosure Patterns =====================

interface DisclosureRule {
  type: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  cweId: string;
  recommendation: string;
}

const DISCLOSURE_PATTERNS: DisclosureRule[] = [
  {
    type: 'server-version-leak',
    name: 'Server Version Disclosure',
    pattern: /^(Apache\/[0-9]|nginx\/[0-9]|IIS\/[0-9]|Tomcat\/[0-9]|Jetty\/[0-9]|JBoss\/[0-9]|Oracle)/i,
    severity: 'medium',
    cweId: 'CWE-200',
    recommendation: 'Remove or obscure version information from Server response headers. Use a generic server banner.',
  },
  {
    type: 'stack-trace',
    name: 'Stack Trace Exposure',
    pattern: /at\s+[\w$]+(?:\.(?:[\w$]+))*\s*\(.*:\d+(?::\d+)?\)/m,
    severity: 'high',
    cweId: 'CWE-209',
    recommendation: 'Disable debug mode and detailed error pages in production. Configure custom error handlers that return generic messages. Set ASP.NET customErrors=RemoteOnly, PHP display_errors=Off, or Node NODE_ENV=production.',
  },
  {
    type: 'database-error',
    name: 'Database Error Disclosure',
    pattern: /(?:SQL(?:STATE| syntax| error)|ORA-\d{4,5}|PostgreSQL.*ERROR|MySQL.*Error|SQLite.*error|Mongo(?:Error|DBError)|Driver.*error)/i,
    severity: 'high',
    cweId: 'CWE-209',
    recommendation: 'Catch database exceptions and return generic error messages. Log detailed database errors server-side only.',
  },
  {
    type: 'debug-info',
    name: 'Debug Mode Disabled',
    pattern: /(?:DEBUG|TRACE)\s*\[|<!--\s*DEBUG|app\.debug|debug_enabled|APP_DEBUG|APP_ENV\s*=\s*"?(?:dev|debug|test|staging)/i,
    severity: 'high',
    cweId: 'CWE-215',
    recommendation: 'Disable all debug endpoints, debug mode, and development configurations in production. Set NODE_ENV=production, APP_ENV=production, etc.',
  },
  {
    type: 'email-disclosure',
    name: 'Email Address Exposure',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    severity: 'low',
    cweId: 'CWE-200',
    recommendation: 'Avoid exposing email addresses in page content. Use contact forms instead of mailto: links. Obfuscate or use JavaScript-less CAPTCHAs for email display.',
  },
  {
    type: 'internal-ip-disclosure',
    name: 'Internal IP Address Exposure',
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/,
    severity: 'high',
    cweId: 'CWE-200',
    recommendation: 'Remove internal IP addresses from all response content. Use relative references or DNS names instead.',
  },
  {
    type: 'api-key-disclosure',
    name: 'API Key / Token Exposure',
    pattern: /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*["']?[A-Za-z0-9_-]{16,}|sk-[a-zA-Z0-9]{20,}|pk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|SG\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/i,
    severity: 'critical',
    cweId: 'CWE-798',
    recommendation: 'Never expose API keys, tokens, or secrets in HTML responses. Remove immediately and rotate compromised keys. Use server-side environment variables for secrets.',
  },
  {
    type: 'jwt-disclosure',
    name: 'JWT Token Exposure',
    pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
    severity: 'high',
    cweId: 'CWE-200',
    recommendation: 'Avoid leaking JWT tokens in response bodies or URLs. Use HttpOnly cookies for token storage and ensure tokens are transmitted only via Authorization headers.',
  },
  {
    type: 'internal-path-disclosure',
    name: 'Internal Path / File Disclosure',
    pattern: /(?:\/[a-z_]+){2,}\.(?:php|asp|aspx|jsp|py|rb|java|ts|js|json|yml|yaml|xml|config)/i,
    severity: 'medium',
    cweId: 'CWE-200',
    recommendation: 'Remove internal file system paths from responses. Use virtual paths or route names instead of physical file paths.',
  },
  {
    type: 'database-connection-leak',
    name: 'Database Connection String Exposure',
    pattern: /(?:mysql|postgres(?:ql)?|mongo(?:db)?|sqlite|oracle|jdbc|mongodb\+srv):\/\/[^\s"'<>]+|connection_string|Server=\s*[^;]+;Database=/i,
    severity: 'critical',
    cweId: 'CWE-200',
    recommendation: 'Never expose database connection strings in HTTP responses. Use environment variables or secure secret stores. Rotate exposed credentials immediately.',
  },
  {
    type: 'credit-card-disclosure',
    name: 'Credit Card Number Exposure',
    pattern: /\b(?:\d[ -]*?){13,16}\b/g,
    severity: 'critical',
    cweId: 'CWE-200',
    recommendation: 'Never include full credit card numbers in responses. Mask all but the last four digits. Consider using tokenization for payment processing.',
  },
  {
    type: 'ssn-disclosure',
    name: 'Social Security Number Exposure',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/,
    severity: 'critical',
    cweId: 'CWE-200',
    recommendation: 'Never include SSNs in responses. Mask or omit them entirely. Use tokenization where possible.',
  },
  {
    type: 'aws-key-disclosure',
    name: 'AWS Access Key Exposure',
    pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/,
    severity: 'critical',
    cweId: 'CWE-798',
    recommendation: 'Never expose AWS access keys in responses. Rotate exposed keys immediately and use IAM roles instead of long-lived credentials.',
  },
  {
    type: 'private-key-disclosure',
    name: 'Private Key / Certificate Exposure',
    pattern: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+KEY-----/,
    severity: 'critical',
    cweId: 'CWE-798',
    recommendation: 'Never expose private keys, certificates, or SSH keys in HTTP responses. Remove them from web-accessible locations immediately.',
  },
  {
    type: 'graphql-introspection',
    name: 'GraphQL Introspection Enabled',
    pattern: /"__schema"\s*:\s*\{|"queryType"\s*:\s*\{|"mutationType"\s*:\s*\{|"subscriptionType"\s*:\s*\{/,
    severity: 'medium',
    cweId: 'CWE-200',
    recommendation: 'Disable GraphQL introspection in production. It exposes the full API schema to potential attackers. Use a whitelist approach for production queries.',
  },
  {
    type: 'sensitive-comment',
    name: 'Sensitive Developer Comment',
    pattern: /<!--\s*(?:TODO|FIXME|HACK|XXX|FIXME:|TODO:|NOTE:|BUG:|ISSUE:)\s*[^>]*-->/i,
    severity: 'low',
    cweId: 'CWE-200',
    recommendation: 'Remove developer comments and annotations from production HTML. Sensitive information in comments can aid attackers.',
  },
  {
    type: 'oauth-client-secret',
    name: 'OAuth Client Secret Exposure',
    pattern: /(?:client_secret|client_id|redirect_uri)\s*[:=]\s*["'][^"']{4,}["']/i,
    severity: 'high',
    cweId: 'CWE-798',
    recommendation: 'Protect OAuth client credentials in server-side code. Never expose client secrets in HTML responses, JavaScript, or source maps.',
  },
  {
    type: 'php-error-display',
    name: 'PHP Error Displayed',
    pattern: /(?:PHP\s+(?:Fatal\s+)?Error|PHP\s+Warning|PHP\s+Notice|Parse\s+error|Fatal error:\s*Uncaught)/i,
    severity: 'high',
    cweId: 'CWE-209',
    recommendation: 'Set display_errors = Off in production php.ini. Log errors to a file instead of displaying them to users.',
  },
  {
    type: 'aspnet-error',
    name: 'ASP.NET Error Details',
    pattern: /(?:Stack Trace:|Source Error:|Line \d+:|\]\s+System\.[A-Z]\w+\.|Exception Details:|Server Error in)/i,
    severity: 'high',
    cweId: 'CWE-209',
    recommendation: 'Set customErrors mode to RemoteOnly or On in web.config. Disable debug. Return generic error pages.',
  },
  {
    type: 'token-in-url',
    name: 'Sensitive Token in URL',
    pattern: /[?&](?:token|access_token|api_key|secret|bearer|auth|sid|session)=[^&\s]{8,}/i,
    severity: 'high',
    cweId: 'CWE-598',
    recommendation: 'Never include authentication tokens, API keys, or session IDs in URL query parameters. Use HTTP Authorization headers (e.g., Bearer token) for transmission.',
  },
  {
    type: 'tech-version-fingerprint',
    name: 'Technology Version Fingerprinting',
    pattern: /<meta\s+name=["']generator["'][^>]*content=["'](?:WordPress|Drupal|Joomla|vBulletin|phpBB|Magento|Shopify)[^"']*\d+\.\d+/i,
    severity: 'low',
    cweId: 'CWE-200',
    recommendation: 'Remove generator meta tags from production HTML or update them to not reveal version numbers. This obscures technology versions from automated scanners.',
  },
  {
    type: 'env-file-exposure',
    name: 'Environment File / Credential Exposure',
    pattern: /(?:APP_KEY=|DB_HOST=|DB_PASSWORD=|DB_USERNAME=|REDIS_PASSWORD=|SECRET_KEY=|SECRET=|STRIPE_)/i,
    severity: 'critical',
    cweId: 'CWE-200',
    recommendation: 'Block access to .env files and configuration files in web server configuration. Never expose environment variables in HTML responses.',
  },
  {
    type: 'directory-listing',
    name: 'Directory Listing Enabled',
    pattern: /<title>Index of\s+\/|<h1>Index of\s+\//i,
    severity: 'high',
    cweId: 'CWE-548',
    recommendation: 'Disable directory listing in your web server configuration. For Apache: Options -Indexes. For Nginx: autoindex off. For IIS: disable Directory Browsing.',
  },
  {
    type: 'cloud-service-metadata',
    name: 'Cloud Service Metadata URL',
    pattern: /169\.254\.169\.254/i,
    severity: 'high',
    cweId: 'CWE-200',
    recommendation: 'Remove references to cloud metadata endpoints from responses. These can indicate SSRF vulnerabilities or cloud provider information leakage.',
  },
  {
    type: 'webhook-url-disclosure',
    name: 'Webhook URL / Callback Disclosure',
    pattern: /(?:webhook|callback|notification|slack|discord|teams|hooks)\.(?:com|io|app).*\/[a-zA-Z0-9_\/-]{10,}/i,
    severity: 'high',
    cweId: 'CWE-200',
    recommendation: 'Never expose webhook URLs in client-side code or responses. Webhook URLs with tokens can be used to send malicious data to the webhook endpoint.',
  },
];

// ===================== Technology Detection Patterns =====================

interface TechDetection {
  tech: string;
  category: string;
  headers: Array<{ header: string; pattern: RegExp }>;
  bodyPatterns: Array<{ pattern: RegExp; weight: number }>;
}

const TECH_DETECTIONS: TechDetection[] = [
  { tech: 'PHP', category: 'Backend Language', headers: [{ header: 'x-powered-by', pattern: /PHP/i }], bodyPatterns: [{ pattern: /\.php(?:\?|$)/i, weight: 5 }] },
  { tech: 'ASP.NET', category: 'Backend Framework', headers: [{ header: 'x-powered-by', pattern: /ASP\.NET|ASP/i }, { header: 'x-aspnet-version', pattern: /.+/i }], bodyPatterns: [{ pattern: /__VIEWSTATE|__EVENTVALIDATION/i, weight: 15 }, { pattern: /\.aspx(?:\?|$)/i, weight: 5 }] },
  { tech: 'Express.js', category: 'Backend Framework', headers: [{ header: 'x-powered-by', pattern: /Express/i }], bodyPatterns: [] },
  { tech: 'Ruby on Rails', category: 'Backend Framework', headers: [{ header: 'x-powered-by', pattern: /Phusion|Passenger/i }, { header: 'server', pattern: /passenger|unicorn/i }], bodyPatterns: [{ pattern: /csrf-param="authenticity_token"/i, weight: 20 }, { pattern: /<input[^>]*name="utf8"/i, weight: 10 }] },
  { tech: 'Django', category: 'Backend Framework', headers: [{ header: 'server', pattern: /wsgiref|gunicorn|uwsgi/i }, { header: 'x-frame-options', pattern: /SAMEORIGIN/i }], bodyPatterns: [{ pattern: /csrfmiddlewaretoken/i, weight: 20 }, { pattern: /__admin_interface/i, weight: 5 }] },
  { tech: 'Spring Boot', category: 'Backend Framework', headers: [{ header: 'x-application-context', pattern: /.+/i }], bodyPatterns: [{ pattern: /"timestamp":\d+,"status":\d+,"error":"/i, weight: 15 }] },
  { tech: 'Nginx', category: 'Web Server', headers: [{ header: 'server', pattern: /nginx/i }], bodyPatterns: [] },
  { tech: 'Apache', category: 'Web Server', headers: [{ header: 'server', pattern: /apache/i }], bodyPatterns: [] },
  { tech: 'IIS', category: 'Web Server', headers: [{ header: 'server', pattern: /iis/i }], bodyPatterns: [{ pattern: /<!--\[if/i, weight: 2 }] },
  { tech: 'Tomcat', category: 'Application Server', headers: [{ header: 'server', pattern: /tomcat/i }, { header: 'x-powered-by', pattern: /tomcat/i }], bodyPatterns: [{ pattern: /Apache Tomcat/i, weight: 10 }] },
  { tech: 'Node.js', category: 'Runtime', headers: [{ header: 'x-powered-by', pattern: /Express/i }, { header: 'server', pattern: /node/i }], bodyPatterns: [] },
  { tech: 'Python', category: 'Runtime', headers: [{ header: 'server', pattern: /gunicorn|uwsgi|wsgiref/i }], bodyPatterns: [{ pattern: /\.py(?:\?|$)/i, weight: 5 }] },
  { tech: 'WordPress', category: 'CMS', headers: [{ header: 'x-powered-by', pattern: /WordPress/i }], bodyPatterns: [{ pattern: /wp-content|wp-includes|wp-admin/i, weight: 15 }, { pattern: /<meta\s+name="generator"[^>]*WordPress/i, weight: 10 }, { pattern: /\/wp-json\//i, weight: 10 }] },
  { tech: 'Drupal', category: 'CMS', headers: [{ header: 'x-powered-by', pattern: /Drupal/i }], bodyPatterns: [{ pattern: /drupal\.js|Drupal\.settings/i, weight: 15 }, { pattern: /<meta\s+name="generator"[^>]*Drupal/i, weight: 10 }] },
  { tech: 'Joomla', category: 'CMS', headers: [], bodyPatterns: [{ pattern: /\/media\/jui\//i, weight: 10 }, { pattern: /<meta\s+name="generator"[^>]*Joomla/i, weight: 10 }, { pattern: /\.joomla/i, weight: 5 }] },
  { tech: 'Varnish', category: 'CDN/Cache', headers: [{ header: 'via', pattern: /varnish/i }, { header: 'x-varnish', pattern: /\d+/i }], bodyPatterns: [] },
  { tech: 'Cloudflare', category: 'CDN', headers: [{ header: 'server', pattern: /cloudflare/i }, { header: 'cf-ray', pattern: /.+/i }], bodyPatterns: [{ pattern: /cloudflare/i, weight: 5 }] },
  { tech: 'Google Analytics', category: 'Analytics', headers: [], bodyPatterns: [{ pattern: /google-analytics\.com\/analytics/i, weight: 15 }, { pattern: /gtag\(/i, weight: 10 }, { pattern: /ga\(/i, weight: 10 }] },
  { tech: 'jQuery', category: 'JavaScript Library', headers: [], bodyPatterns: [{ pattern: /jquery[.\-]?\d+\.\d+\.\d+\.?(?:min)?\.js|jquery\s+v\d+\.\d+\.\d+/i, weight: 15 }, { pattern: /\$\(|jQuery\(/i, weight: 5 }] },
  { tech: 'React', category: 'JavaScript Framework', headers: [], bodyPatterns: [{ pattern: /react\.(?:production|development)\.js|React\.createElement|__REACT_DEVTOOLS/i, weight: 15 }, { pattern: /data-reactroot|data-reactid/i, weight: 10 }] },
  { tech: 'Angular', category: 'JavaScript Framework', headers: [], bodyPatterns: [{ pattern: /angular\.(?:min\.)?js|ng-app|ng-controller|ng-repeat|ng-model/i, weight: 15 }, { pattern: /Zone\.js|zone\.js|__zone_symbol__/i, weight: 10 }] },
  { tech: 'Vue.js', category: 'JavaScript Framework', headers: [], bodyPatterns: [{ pattern: /vue\.(?:min\.)?js|v-bind|v-model|v-if|v-for|v-show|vue-[\w-]+/i, weight: 15 }] },
  { tech: 'Bootstrap', category: 'CSS Framework', headers: [], bodyPatterns: [{ pattern: /bootstrap\.(?:min\.)?css|bootstrap\.(?:min\.)?js/i, weight: 15 }, { pattern: /class="[^"]*\bcol-(?:xs|sm|md|lg)-\d+\b/i, weight: 5 }] },
  { tech: 'GraphQL', category: 'API Technology', headers: [], bodyPatterns: [{ pattern: /\/graphql|"query"\s*:|"mutation"\s*:/i, weight: 15 }] },
  { tech: 'Stripe', category: 'Payment', headers: [], bodyPatterns: [{ pattern: /stripe\.com\/v3\//i, weight: 15 }, { pattern: /stripe_publishable_key|Stripe\.setPublishableKey/i, weight: 10 }] },
];

// ===================== Plugin: Cookie Security Checks =====================

function checkCookieSecurity(
  setCookieHeader: string | undefined
): PassiveFinding[] {
  const findings: PassiveFinding[] = [];

  if (!setCookieHeader) return findings;

  // Parse Set-Cookie headers - they can be comma-joined but we handle carefully
  const cookieHeaders: string[] = [];

  // Handle multiple Set-Cookie headers already joined into one string with comma
  // Basic heuristic: split on ", " between cookies (not within cookie attributes)
  if (typeof setCookieHeader === 'string') {
    // Split on ', ' only if the , is followed by a cookie name pattern
    const parts = setCookieHeader.split(/, (?=[a-zA-Z0-9!#$%&'*+\-.^_`|~]+=)/g);
    cookieHeaders.push(...parts);
  }

  for (const cookieStr of cookieHeaders) {
    const parts = cookieStr.split(';').map((s: string) => s.trim());
    if (parts.length === 0) continue;

    const nameValue = parts[0];
    const cookieName = nameValue.split('=')[0]?.trim();
    const cookieValue = nameValue.split('=').slice(1).join('=');
    const attributes = parts.slice(1).map((a: string) => a.toLowerCase());

    // Check HttpOnly flag (prevents JavaScript access)
    if (!attributes.some((a: string) => a === 'httponly')) {
      findings.push({
        type: 'cookie-no-httponly',
        severity: 'medium',
        evidence: `Cookie '${cookieName}' is missing the HttpOnly flag - accessible via JavaScript (XSS risk)`,
        recommendation: 'Add the HttpOnly flag to all cookies that do not require JavaScript access. This prevents XSS attacks from stealing session tokens.',
        cweId: 'CWE-1004',
        category: 'Insecure Cookie',
      });
    }

    // Check Secure flag (ensures HTTPS-only transmission)
    if (!attributes.some((a: string) => a === 'secure')) {
      findings.push({
        type: 'cookie-no-secure',
        severity: 'high',
        evidence: `Cookie '${cookieName}' is missing the Secure flag - may be transmitted over unencrypted HTTP`,
        recommendation: 'Add the Secure flag to all cookies to ensure they are only transmitted over HTTPS connections, preventing network-level eavesdropping.',
        cweId: 'CWE-614',
        category: 'Insecure Cookie',
      });
    }

    // Check SameSite attribute (CSRF protection)
    const sameSiteAttr = attributes.find((a: string) => a.startsWith('samesite'));
    if (!sameSiteAttr) {
      findings.push({
        type: 'cookie-no-samesite',
        severity: 'low',
        evidence: `Cookie '${cookieName}' is missing the SameSite attribute - may be vulnerable to CSRF`,
        recommendation: 'Add SameSite=Lax (default in modern browsers) or SameSite=Strict to cookies for CSRF protection. SameSite=None requires Secure flag.',
        cweId: 'CWE-1275',
        category: 'Insecure Cookie',
      });
    } else if (sameSiteAttr.includes('none')) {
      // SameSite=None requires Secure
      if (!attributes.some((a: string) => a === 'secure')) {
        findings.push({
          type: 'cookie-samesite-none-without-secure',
          severity: 'high',
          evidence: `Cookie '${cookieName}' uses SameSite=None but is missing the Secure flag - browsers will reject it`,
          recommendation: 'Cookies with SameSite=None MUST also have the Secure flag set. Add the Secure flag or change to SameSite=Lax/Strict.',
          cweId: 'CWE-1275',
          category: 'Insecure Cookie',
        });
      }
    }

    // Check for session cookies without proper flags
    if (/(?:session|sid|token|auth|jwt|connect|credentials)/i.test(cookieName) && cookieValue.length > 8) {
      if (!attributes.some((a: string) => a === 'httponly') || !attributes.some((a: string) => a === 'secure')) {
        findings.push({
          type: 'insecure-session-cookie',
          severity: 'high',
          evidence: `Session/authentication cookie '${cookieName}' is missing critical security flags (HttpOnly, Secure)`,
          recommendation: 'Session/authentication cookies MUST have both HttpOnly and Secure flags set. Add SameSite=Strict for additional CSRF protection.',
          cweId: 'CWE-614',
          category: 'Insecure Cookie',
        });
      }
    }

    // Check for long Max-Age on session cookies
    const maxAgeAttr = attributes.find((a: string) => a.startsWith('max-age'));
    if (maxAgeAttr) {
      const maxAgeMatch = maxAgeAttr.match(/max-age=(\d+)/);
      if (maxAgeMatch) {
        const maxAgeSeconds = parseInt(maxAgeMatch[1], 10);
        if (maxAgeSeconds > 86400 && /(?:session|token|auth)/i.test(cookieName)) {
          findings.push({
            type: 'long-lived-session-cookie',
            severity: 'medium',
            evidence: `Session cookie '${cookieName}' has a long lifespan: ${Math.round(maxAgeSeconds / 86400)} day(s) (${maxAgeSeconds}s)`,
            recommendation: 'Reduce session cookie lifetime. For most applications, session cookies should expire within 24 hours (86400 seconds) or less. Use sliding expiration for active sessions.',
            cweId: 'CWE-613',
            category: 'Insecure Cookie',
          });
        }
      }
    }

    // Check for Path=/ on session cookies (too broad)
    const pathAttr = attributes.find((a: string) => a.startsWith('path'));
    if (pathAttr && pathAttr === 'path=/' && /(?:session|token|auth)/i.test(cookieName)) {
      // This is informational-only - Path=/ is common and often necessary
      // We only flag if it's a really sensitive cookie
      findings.push({
        type: 'cookie-root-path',
        severity: 'info',
        evidence: `Cookie '${cookieName}' is accessible on all paths (Path=/)`,
        recommendation: 'Consider setting a more restrictive cookie path if the cookie is only needed on specific application paths.',
        cweId: 'CWE-1004',
        category: 'Insecure Cookie',
      });
    }

    // Check for Expires with far-future date
    const expiresAttr = attributes.find((a: string) => a.startsWith('expires'));
    if (expiresAttr && expiresAttr.includes('203') && /(?:session|token|auth)/i.test(cookieName)) {
      findings.push({
        type: 'cookie-far-future-expires',
        severity: 'medium',
        evidence: `Cookie '${cookieName}' has a far-future expiration date`,
        recommendation: 'Avoid far-future expiration dates for session and authentication cookies. Use shorter-lived tokens with refresh mechanisms.',
        cweId: 'CWE-613',
        category: 'Insecure Cookie',
      });
    }
  }

  return findings;
}

// ===================== Plugin: Technology Detection =====================

function detectTechnologies(
  headers: Record<string, string>,
  body: string
): PassiveFinding[] {
  const findings: PassiveFinding[] = [];
  const detected = new Set<string>();

  const lowerHeaders: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    lowerHeaders[key.toLowerCase()] = value;
  }

  for (const tech of TECH_DETECTIONS) {
    let score = 0;

    // Check headers
    for (const { header, pattern } of tech.headers) {
      const value = lowerHeaders[header];
      if (value && pattern.test(value)) {
        score += 20;
      }
    }

    // Check body patterns
    for (const { pattern, weight } of tech.bodyPatterns) {
      let match;
      // Reset regex state
      pattern.lastIndex = 0;
      if ((match = pattern.exec(body)) !== null) {
        score += weight;
      }
    }

    if (score >= 15 && !detected.has(tech.tech)) {
      detected.add(tech.tech);
      findings.push({
        type: 'technology-detected',
        severity: 'info',
        evidence: `Detected technology: ${tech.tech} (${tech.category}) - confidence score: ${score}`,
        recommendation: 'Review if this technology is expected. Consider obscuring technology headers to reduce attack surface.',
        cweId: 'CWE-200',
        category: 'Technology Fingerprinting',
      });
    }
  }

  return findings;
}

// ===================== Main Scanning Functions =====================

/**
 * Analyze HTTP response headers for security issues.
 */
function checkSecurityHeaders(headers: Record<string, string>): PassiveFinding[] {
  const findings: PassiveFinding[] = [];

  const lowerHeaders: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    lowerHeaders[key.toLowerCase()] = value;
  }

  for (const [headerName, rule] of Object.entries(REQUIRED_SECURITY_HEADERS)) {
    const value = lowerHeaders[headerName];

    if (!value) {
      // Header is completely missing
      findings.push({
        type: `missing-${headerName}`,
        severity: rule.severity,
        evidence: `Missing security header: ${rule.name} (${headerName})`,
        recommendation: rule.recommendation,
        cweId: rule.cweId,
        category: 'Missing Security Header',
      });
    } else if (!rule.expectedValue.test(value)) {
      // Header exists but has weak/unexpected value
      findings.push({
        type: `weak-${headerName}`,
        severity: 'low',
        evidence: `Weak security header value for ${rule.name} (${headerName}): '${value.slice(0, 200)}'`,
        recommendation: rule.recommendation,
        cweId: rule.cweId,
        category: 'Weak Security Header',
      });
    }
  }

  // ---- Specialized HSTS checks ----
  const hsts = lowerHeaders['strict-transport-security'];
  if (hsts) {
    // Check for includeSubDomains
    if (!/includeSubDomains/i.test(hsts)) {
      findings.push({
        type: 'hsts-no-subdomains',
        severity: 'low',
        evidence: 'HSTS header is missing the includeSubDomains directive - subdomains are not protected',
        recommendation: 'Add includeSubDomains to the HSTS header to extend protection to all subdomains.',
        cweId: 'CWE-523',
        category: 'Weak Security Header',
      });
    }

    // Check max-age
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (maxAge < 31536000) {
        findings.push({
          type: 'hsts-insufficient-max-age',
          severity: 'low',
          evidence: `HSTS max-age is ${maxAge}s (${Math.round(maxAge / 86400)} days) - recommended minimum is 31536000s (1 year)`,
          recommendation: 'Set HSTS max-age to at least 31536000 seconds (1 year). For preload readiness: max-age=31536000; includeSubDomains; preload',
          cweId: 'CWE-523',
          category: 'Weak Security Header',
        });
      }
    }

    // Check for preload
    if (!/preload/i.test(hsts)) {
      // preload is optional, informational
      findings.push({
        type: 'hsts-no-preload',
        severity: 'info',
        evidence: 'HSTS header does not include the preload directive - cannot be submitted to browser preload lists',
        recommendation: 'Consider adding the preload directive and submitting to https://hstspreload.org/ for maximum HSTS protection.',
        cweId: 'CWE-523',
        category: 'Weak Security Header',
      });
    }
  }

  // ---- Specialized CSP checks ----
  const csp = lowerHeaders['content-security-policy'];
  if (csp) {
    if (/unsafe-inline/i.test(csp) && !/'nonce-/.test(csp) && !/sha(?:256|384|512)-/.test(csp)) {
      findings.push({
        type: 'csp-unsafe-inline',
        severity: 'medium',
        evidence: 'CSP uses unsafe-inline without nonces or hashes - weakens XSS protection significantly',
        recommendation: 'Avoid unsafe-inline in CSP. Use strict-dynamic with nonces or hash-based CSP for modern applications. Example: script-src \'strict-dynamic\' \'nonce-random123\';',
        cweId: 'CWE-1021',
        category: 'Weak Security Header',
      });
    }

    if (/unsafe-eval/i.test(csp)) {
      findings.push({
        type: 'csp-unsafe-eval',
        severity: 'low',
        evidence: 'CSP allows unsafe-eval - reduces protection against injection attacks',
        recommendation: 'Remove unsafe-eval from CSP if possible. If required by the application, consider a more restrictive CSP with nonces.',
        cweId: 'CWE-1021',
        category: 'Weak Security Header',
      });
    }

    // Check if CSP is too permissive with wildcard
    if (/default-src\s+\*|\*\.unsafe-inline/i.test(csp)) {
      findings.push({
        type: 'csp-wildcard',
        severity: 'medium',
        evidence: 'CSP uses overly permissive wildcard (*) directive',
        recommendation: 'Avoid wildcard (*) in CSP directives. Restrict to specific origins and protocols.',
        cweId: 'CWE-1021',
        category: 'Weak Security Header',
      });
    }
  }

  // ---- CORS checks ----
  const acao = lowerHeaders['access-control-allow-origin'];
  const acac = lowerHeaders['access-control-allow-credentials'];

  if (acao === '*') {
    findings.push({
      type: 'cors-wildcard-origin',
      severity: 'medium',
      evidence: 'CORS allows all origins: Access-Control-Allow-Origin: * - any website can make cross-origin requests',
      recommendation: 'Restrict Access-Control-Allow-Origin to specific, trusted origins. Never use wildcard (*) with credentials.',
      cweId: 'CWE-942',
      category: 'CORS Misconfiguration',
    });
  } else if (acao && acao !== '*' && acao !== 'null') {
    // Specific origin allowed - check that it's not an extremely permissive pattern
    if (acao.includes('*') || acao === 'null') {
      findings.push({
        type: 'cors-permissive-origin',
        severity: 'medium',
        evidence: `CORS permissive origin pattern: ${acao}`,
        recommendation: 'Avoid patterns with wildcards or null origins. Use explicit allowed origins.',
        cweId: 'CWE-942',
        category: 'CORS Misconfiguration',
      });
    }
  }

  if (acao === '*' && acac === 'true') {
    findings.push({
      type: 'cors-credentials-wildcard',
      severity: 'high',
      evidence: 'Dangerous CORS configuration: Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true',
      recommendation: 'This configuration is invalid in browsers but indicates a serious misconfiguration. Use explicit origin instead of wildcard when credentials are enabled.',
      cweId: 'CWE-942',
      category: 'CORS Misconfiguration',
    });
  }

  // ---- Additional header checks ----
  const server = lowerHeaders['server'];
  if (server) {
    const versionMatch = server.match(/([a-zA-Z]+)\/(\d+\.\d+(?:\.\d+)?)/);
    if (versionMatch) {
      findings.push({
        type: 'server-version-disclosure',
        severity: 'medium',
        evidence: `Server header reveals software and version: '${versionMatch[1]} ${versionMatch[2]}'`,
        recommendation: 'Remove version information from the Server header. For Nginx: server_tokens off. For Apache: ServerTokens Prod.',
        cweId: 'CWE-200',
        category: 'Information Disclosure',
      });
    }
  }

  // X-Powered-By
  const poweredBy = lowerHeaders['x-powered-by'];
  if (poweredBy) {
    findings.push({
      type: 'x-powered-by-disclosure',
      severity: 'info',
      evidence: `X-Powered-By header reveals backend technology: '${poweredBy}'`,
      recommendation: 'Remove the X-Powered-By header to obscure the backend technology stack from attackers.',
      cweId: 'CWE-200',
      category: 'Information Disclosure',
    });
  }

  // X-AspNet-Version
  if (lowerHeaders['x-aspnet-version']) {
    findings.push({
      type: 'aspnet-version-disclosure',
      severity: 'low',
      evidence: `X-AspNet-Version header reveals ASP.NET version: '${lowerHeaders['x-aspnet-version']}'`,
      recommendation: 'Remove the X-AspNet-Version header in web.config by setting <httpRuntime enableVersionHeader="false" />.',
      cweId: 'CWE-200',
      category: 'Information Disclosure',
    });
  }

  // X-AspNetMvc-Version
  if (lowerHeaders['x-aspnetmvc-version']) {
    findings.push({
      type: 'aspnetmvc-version-disclosure',
      severity: 'low',
      evidence: `X-AspNetMvc-Version header reveals ASP.NET MVC version: '${lowerHeaders['x-aspnetmvc-version']}'`,
      recommendation: 'Remove X-AspNetMvc-Version header. Add <MvcHttpHandler /> and custom headers removal in web.config.',
      cweId: 'CWE-200',
      category: 'Information Disclosure',
    });
  }

  // WWW-Authenticate header (exposed auth scheme)
  if (lowerHeaders['www-authenticate']) {
    findings.push({
      type: 'www-authenticate-exposed',
      severity: 'low',
      evidence: `WWW-Authenticate header reveals authentication scheme: '${lowerHeaders['www-authenticate']}'`,
      recommendation: 'Review if the authentication scheme needs to be exposed. Consider using custom authentication headers.',
      cweId: 'CWE-200',
      category: 'Information Disclosure',
    });
  }

  // X-Debug-* headers
  for (const [header, value] of Object.entries(lowerHeaders)) {
    if (/^x-debug/i.test(header) || /^x-*trace/i.test(header)) {
      findings.push({
        type: 'debug-header-exposed',
        severity: 'high',
        evidence: `Debug header exposed: '${header}: ${value}'`,
        recommendation: 'Remove debug headers from production responses. Debug headers can leak sensitive application internals.',
        cweId: 'CWE-215',
        category: 'Information Disclosure',
      });
    }

    // Custom internal headers that shouldn't be exposed
    if (/^x-(?:internal|private|secret|hidden)/i.test(header)) {
      findings.push({
        type: 'internal-header-exposed',
        severity: 'medium',
        evidence: `Internal header exposed: '${header}: ${value}'`,
        recommendation: 'Remove internal headers from responses sent to clients. Internal headers are for server-to-server communication only.',
        cweId: 'CWE-200',
        category: 'Information Disclosure',
      });
    }
  }

  return findings;
}

/**
 * Analyze response body for sensitive data and information disclosure.
 */
function checkResponseBody(body: string): PassiveFinding[] {
  const findings: PassiveFinding[] = [];

  for (const disclosure of DISCLOSURE_PATTERNS) {
    // Reset regex state for global patterns
    disclosure.pattern.lastIndex = 0;

    const matches = body.match(disclosure.pattern);
    if (!matches || matches.length === 0) continue;

    let evidence = '';
    const firstMatch = matches[0];

    // Truncate very long matches
    const truncated = firstMatch.length > 180
      ? firstMatch.slice(0, 180) + '...'
      : firstMatch;

    // Special handling for common cases
    switch (disclosure.type) {
      case 'email-disclosure':
        evidence = `Found ${matches.length} email address(es) exposed in response body`;
        break;

      case 'credit-card-disclosure': {
        // Apply Luhn check to reduce false positives
        const validCCs = matches.filter((m) => {
          const digits = m.replace(/\D/g, '');
          if (digits.length < 13 || digits.length > 16) return false;
          let sum = 0;
          let alternate = false;
          for (let i = digits.length - 1; i >= 0; i--) {
            let n = parseInt(digits[i], 10);
            if (alternate) {
              n *= 2;
              if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
          }
          return sum % 10 === 0;
        });
        if (validCCs.length === 0) continue; // Skip if Luhn check fails
        evidence = `Found ${validCCs.length} potential credit card number(s) matching Luhn algorithm in response body`;
        break;
      }

      case 'sensitive-comment':
        evidence = `Found developer comment: '${truncated.replace(/<!--/, '').replace(/-->/, '').trim()}'`;
        break;

      default:
        evidence = `Found '${truncated}' in response body`;
        break;
    }

    findings.push({
      type: disclosure.type,
      severity: disclosure.severity,
      evidence,
      recommendation: disclosure.recommendation,
      cweId: disclosure.cweId,
      category: 'Information Disclosure',
    });
  }

  return findings;
}

// ===================== Public API =====================

/**
 * Analyze HTTP response headers and body for security issues.
 * This is the core passive scanning function - no attack payloads are sent.
 */
export function passiveScanResponse(
  body: string,
  headers: Record<string, string>,
  targetUrl?: string
): PassiveFinding[] {
  const findings: PassiveFinding[] = [];

  // 1. Check security headers
  const headerFindings = checkSecurityHeaders(headers);
  findings.push(...headerFindings);

  // 2. Check cookie security
  const cookieFindings = checkCookieSecurity(headers['set-cookie']);
  findings.push(...cookieFindings);

  // 3. Check response body for information disclosure
  const bodyFindings = checkResponseBody(body);
  findings.push(...bodyFindings);

  // 4. Detect technologies
  const techFindings = detectTechnologies(headers, body);
  findings.push(...techFindings);

  // Log the scan results
  const severityCount = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };

  logger.info(
    { targetUrl: targetUrl || 'unknown', findingsCount: findings.length, ...severityCount },
    targetUrl ? `Passive scan completed for ${targetUrl}` : 'Passive scan completed'
  );

  return findings;
}

/**
 * Full passive scan: fetches a URL and analyzes the response for security issues.
 */
export async function passiveScanUrl(
  targetUrl: string,
  additionalHeaders?: Record<string, string>
): Promise<PassiveScanResult> {
  logger.info({ targetUrl }, 'Starting passive URL scan');

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000);

    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'AppSec-DAST-Passive/2.0 (Security Scanner)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        ...additionalHeaders,
      },
      redirect: 'follow',
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // Build headers record
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      // If the header already exists (e.g., set-cookie), append with comma
      const lowerKey = key.toLowerCase();
      if (responseHeaders[lowerKey]) {
        responseHeaders[lowerKey] += ', ' + value;
      } else {
        responseHeaders[lowerKey] = value;
      }
    });

    const body = await response.text();

    const findings = passiveScanResponse(body, responseHeaders, targetUrl);

    const summary = {
      total: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      info: findings.filter((f) => f.severity === 'info').length,
    };

    return {
      findings,
      targetUrl,
      scanTime: new Date().toISOString(),
      summary,
    };
  } catch (err) {
    logger.error({ targetUrl, err: (err as Error).message }, 'Passive URL scan failed');

    return {
      findings: [],
      targetUrl,
      scanTime: new Date().toISOString(),
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };
  }
}
