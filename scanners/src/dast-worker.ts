// DAST Worker — Real HTTP-based dynamic scanning with attack payloads
import { Worker, Job } from 'bullmq';
import https from 'https';
import http from 'http';
import { logger } from './utils/logger.js';
import { assertScannableUrl } from './utils/ssrf.js';
import { startScan, storeFinding, completeScan, failScan } from './utils/scan-store.js';
import { DAST_ATTACKS, DastFinding, crawlTarget, generateAttackVectors, analyzeResponse } from './dast/engine.js';
import { ADVANCED_DAST_ATTACKS, passiveScanResponse, detectWAF, EVASION_ENCODERS } from './dast/enterprise-dast.js';
import {
  API_SECURITY_ATTACKS,
  generateBolaPayloads,
  generateBflaPayloads,
  generateMassAssignmentPayloads,
  analyzeBolaResponse,
  analyzeBflaResponse,
  analyzeMassAssignmentResponse,
  testRateLimiting,
} from './dast/api-security.js';
import { runNuclei } from './dast/nuclei-scanner.js';
import { runNikto } from './dast/nikto-scanner.js';
import { execSync } from 'child_process';

// ---------------------------------------------------------------------------
// P2: Pre-flight binary availability check — used for optional external tools
// ---------------------------------------------------------------------------
function isBinaryAvailable(name: string): boolean {
  try {
    execSync(`which ${name} 2>/dev/null || command -v ${name} 2>/dev/null`, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}
import { detectBlindSqli } from './dast/blind-sqli.js';
import { crawlWithBrowser } from './dast/browser-crawler.js';
import {
  createOobServer,
  OOBInteractionServer,
  generateOobSsrfPayloads,
  generateOobXxePayloads,
  generateOobRcePayloads,
  generateOobSqliPayloads,
  buildOobFinding,
} from './dast/oob-interaction.js';

const connection = { host: process.env.REDIS_HOST || 'redis', port: parseInt(process.env.REDIS_PORT || '6379', 10), password: process.env.REDIS_PASSWORD };

// Merge core + advanced + API security attack modules (10 + 8 + 8 = 26 total)
const ALL_ATTACKS = [...DAST_ATTACKS, ...ADVANCED_DAST_ATTACKS, ...API_SECURITY_ATTACKS];

// OOB interaction server — lazily initialized singleton for blind vuln detection.
let _oobServerPromise: Promise<OOBInteractionServer> | null = null;
async function ensureOobServer(): Promise<OOBInteractionServer> {
  if (!_oobServerPromise) {
    _oobServerPromise = createOobServer();
  }
  return _oobServerPromise;
}

async function makeHttpRequest(target: { url: string; method: string; headers: Record<string,string>; body?: string; timeout?: number }): Promise<{ status: number; headers: Record<string,string>; body: string; timing: number }> {
  // SSRF guard: blocks cloud-metadata/link-local always, and private ranges
  // unless ALLOW_PRIVATE_SCAN_TARGETS=true (for self-hosted internal scanning).
  await assertScannableUrl(target.url);
  return new Promise((resolve, reject) => {
    const pUrl = new URL(target.url);
    const opts: https.RequestOptions = {
      hostname: pUrl.hostname, port: pUrl.port || (pUrl.protocol === 'https:' ? 443 : 80),
      path: pUrl.pathname + pUrl.search, method: target.method,
      headers: { ...target.headers, 'User-Agent': 'AppSec-DAST/2.0' },
      rejectUnauthorized: false, timeout: target.timeout || 15000,
    };
    const transport = pUrl.protocol === 'https:' ? https : http;
    const start = Date.now();
    const req = transport.request(opts, (res) => {
      let data = '';
      res.on('data', (c: string) => data += c);
      res.on('end', () => {
        const h: Record<string,string> = {};
        for (const [k, v] of Object.entries(res.headers)) { if (v) h[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v; }
        resolve({ status: res.statusCode || 0, headers: h, body: data.slice(0, 500000), timing: Date.now() - start });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    if (target.body && ['POST','PUT','PATCH'].includes(target.method.toUpperCase())) req.write(target.body);
    req.end();
  });
}

async function processJob(job: Job): Promise<Record<string,unknown>> {
  const { scanId, projectId, options, organizationId } = job.data;
  const targetUrl = options?.targetUrl || 'https://example.com';
  const findings: DastFinding[] = [];
  logger.info({ scanId, targetUrl }, 'DAST Worker: Starting dynamic scan');

  try {
    await startScan(scanId);
    await job.updateProgress(5);
    // Step 1: Crawl target (browser-based for SPA, falls back to HTTP)
    let urls: string[];
    try {
      const crawlResult = await crawlWithBrowser(targetUrl, { maxDepth: 3, maxPages: 50 });
      urls = crawlResult.discoveredUrls;
      if (crawlResult.apiEndpoints.length > 0) {
        urls = [...new Set([...urls, ...crawlResult.apiEndpoints])];
      }
      logger.info({ scanId, urlCount: urls.length, apiEndpoints: crawlResult.apiEndpoints.length }, 'Browser crawl complete');
    } catch (err) {
      logger.warn({ scanId, err }, 'Browser crawl failed, using static crawl');
      urls = crawlTarget(targetUrl, { maxDepth: 3, maxPages: 50 });
    }
    await job.updateProgress(10);

    // Step 2: WAF detection on baseline response
    let wafProfile = { detected: 'None', mode: 'monitor', evasionTechniques: [] as string[], rateLimitThreshold: 1000 } as ReturnType<typeof detectWAF>;
    try {
      const baseline = await makeHttpRequest({ url: targetUrl, method: 'GET', headers: { 'Accept': '*/*' } });
      wafProfile = detectWAF(baseline.headers);
      logger.info({ scanId, waf: wafProfile.detected }, 'WAF detected');
    } catch { /* target unreachable */ }

    // Step 3: Passive scan on baseline
    const passiveFindings: DastFinding[] = [];
    for (const url of urls.slice(0, 10)) {
      try {
        const resp = await makeHttpRequest({ url, method: 'GET', headers: { 'Accept': '*/*' } });
        const pfs = passiveScanResponse(resp.body, resp.headers);
        passiveFindings.push(...pfs.map(pf => ({
          attackId: 'DAST-PASSIVE', attackName: pf.type, target: url, method: 'GET',
          parameter: 'response', payload: '', evidence: pf.evidence,
          severity: pf.severity, severityRank: {critical:1,high:2,medium:3,low:4,info:5}[pf.severity]||3,
          cweId: '', owaspCategory: '', cvssScore: 0, cvssVector: '', recommendation: pf.recommendation, description: pf.evidence,
        })));
      } catch { continue; }
    }
    findings.push(...passiveFindings);
    await job.updateProgress(25);

    // Step 3b: Session fixation active probe (P2)
    // Sends a session cookie captured from one response in a new request.
    // If the server accepts it without rotating the session ID, emit a finding.
    try {
      logger.info({ scanId }, 'Running session fixation probe');
      // Collect Set-Cookie session cookies from baseline responses
      const sessionCookies = new Map<string, string>(); // name → value
      for (const url of urls.slice(0, 5)) {
        try {
          const resp = await makeHttpRequest({ url, method: 'GET', headers: { 'Accept': '*/*' } });
          const setCookie = resp.headers['set-cookie'] || '';
          // Match session-like cookies: session, sid, JSESSIONID, PHPSESSID, connect.sid, etc.
          const sessionMatch = setCookie.match(/(?:session|sid|JSESSIONID|PHPSESSID|connect\.sid|auth|token|csrf)_?[a-z]*=([^;]+)/i);
          if (sessionMatch?.[1] && !sessionCookies.has(sessionMatch[0]!)) {
            sessionCookies.set(sessionMatch[0]!, sessionMatch[1]!);
            logger.debug({ scanId, cookie: sessionMatch[0]!.split('=')[0] }, 'Session cookie captured for fixation probe');
          }
        } catch { continue; }
      }

      if (sessionCookies.size > 0) {
        // Probe: send a second request with the same cookie; check if it's still valid
        for (const [cookieName, cookieValue] of sessionCookies) {
          try {
            const probeResp = await makeHttpRequest({
              url: urls[0]!,
              method: 'GET',
              headers: { 'Accept': '*/*', 'Cookie': cookieName },
              timeout: 10000,
            });
            // Check if the response issues a new session cookie (rotation)
            const newSetCookie = probeResp.headers['set-cookie'] || '';
            const hasRotated = new RegExp(cookieName.split('=')[0] + '=', 'i').test(newSetCookie)
              && !newSetCookie.includes(cookieValue.slice(0, 8));

            if (!hasRotated && probeResp.status < 400) {
              // Session not rotated — potential fixation
              findings.push({
                attackId: 'DAST-SESSION-FIX-001',
                attackName: 'Session Fixation',
                target: urls[0]!,
                method: 'GET',
                parameter: 'Cookie',
                payload: cookieName,
                evidence: `Session cookie accepted without rotation. Cookie: ${cookieName.split('=')[0]}`,
                severity: 'medium',
                severityRank: 3,
                cweId: 'CWE-384',
                owaspCategory: 'A07:2021 - Identification and Authentication Failures',
                cvssScore: 6.1,
                cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N',
                recommendation: 'Rotate session tokens after login. Bind sessions to client attributes (IP, User-Agent). Implement strict session timeout.',
                description: 'Server did not issue a new session token when presented with an existing session cookie — this is a session fixation vulnerability.',
              });
              break; // One finding per target
            }
          } catch { continue; }
        }
      }
    } catch (err) {
      logger.warn({ scanId, err }, 'Session fixation probe failed (non-fatal)');
    }

    // Step 3c: OAuth / OIDC redirect_uri and state parameter validation (P2)
    try {
      logger.info({ scanId }, 'Running OAuth/OIDC configuration check');
      for (const url of urls.slice(0, 5)) {
        try {
          const resp = await makeHttpRequest({ url, method: 'GET', headers: { 'Accept': '*/*' } });
          const body = resp.body;
          const headers = resp.headers;

          // Check for OAuth/OIDC endpoints in response body
          const hasOAuth = /authorize\?|oauth2?|openid-configuration|\.well-known\/openid|\/authorize|\/token|\/userinfo/i.test(body || '');
          const hasOidcDiscovery = /openid-configuration/i.test(body || '');

          // Look for redirect_uri in links/forms/script contexts
          if (hasOAuth || hasOidcDiscovery) {
            // Check if redirect_uri parameter is present in any links
            const redirectUriMatches = (body || '').match(/redirect_uri[=:]\s*["']?([^"'\s&]+)/gi);
            if (redirectUriMatches && redirectUriMatches.length > 0) {
              for (const match of redirectUriMatches) {
                // Extract the URI value
                const uriValue = match.replace(/redirect_uri[=:]\s*["']?/i, '').replace(/["']/g, '');
                // Check if redirect URI appears wildcard/opencode
                if (uriValue === '*' || uriValue === '' || /^https?:\/\/[^/]*\*/.test(uriValue)) {
                  findings.push({
                    attackId: 'DAST-OAUTH-REDIRECT-001',
                    attackName: 'OAuth Weak redirect_uri',
                    target: url,
                    method: 'GET',
                    parameter: 'redirect_uri',
                    payload: uriValue,
                    evidence: `Potentially weak redirect_uri: ${uriValue}`,
                    severity: 'high',
                    severityRank: 2,
                    cweId: 'CWE-601',
                    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
                    cvssScore: 7.4,
                    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
                    recommendation: 'Validate redirect_uri against a strict allowlist. Never use wildcards or open redirectors.',
                    description: `OAuth endpoint found with potentially weak redirect_uri: ${uriValue}. This may allow authorization code interception.`,
                  });
                }
              }
            }

            // Check for missing state parameter
            const hasStateParam = /state=/.test(body || '');
            const authLinks = (body || '').match(/\/authorize\?[^"'\s]+/gi);
            if (authLinks && authLinks.length > 0 && !hasStateParam) {
              findings.push({
                attackId: 'DAST-OAUTH-STATE-001',
                attackName: 'OAuth Missing state Parameter',
                target: url,
                method: 'GET',
                parameter: 'state',
                payload: '',
                evidence: 'OAuth authorization URL found without state parameter',
                severity: 'medium',
                severityRank: 3,
                cweId: 'CWE-352',
                owaspCategory: 'A07:2021 - Identification and Authentication Failures',
                cvssScore: 6.8,
                cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N',
                recommendation: 'Always include a cryptographically random state parameter in OAuth authorization requests and validate it on callback.',
                description: 'OAuth authorization endpoint detected without a state parameter — vulnerable to CSRF attacks against the OAuth flow.',
              });
            }
          }
        } catch { continue; }
      }
    } catch (err) {
      logger.warn({ scanId, err }, 'OAuth/OIDC check failed (non-fatal)');
    }
    await job.updateProgress(27);

    // Step 3d: CSRF token presence check on state-changing endpoints (P2)
    // For each POST/PUT/DELETE endpoint discovered, check whether the
    // response content contains a CSRF token pattern.  If not, emit a finding.
    try {
      logger.info({ scanId }, 'Running CSRF token presence check');
      const stateChangingUrls = urls.filter(u => {
        // Heuristic: URLs that look like they handle state changes
        return /\/(?:login|signup|register|submit|create|update|delete|edit|settings?|profile|account|checkout|payment|upload|publish|save|config)/i.test(u);
      }).slice(0, 10);

      for (const url of stateChangingUrls) {
        try {
          const resp = await makeHttpRequest({ url, method: 'GET', headers: { 'Accept': 'text/html, application/json' }, timeout: 10000 });
          const body = resp.body || '';
          const headers = resp.headers;

          // Check for presence of CSRF token patterns in body
          const csrfPatterns = [
            /<input[^>]+name=["'](?:_csrf|csrf[_-]?token|_token|authenticity_token|__RequestVerificationToken|nonce)["']/i,
            /<meta[^>]+name=["']csrf[_-]?token["']/i,
            /xsrf|xsrfToken|x-csrf-token|x-csrftoken|_csrf/i,
            /csrf[_-]?token["']?\s*[:=]/i,
          ];
          const hasCsrfInBody = csrfPatterns.some(p => p.test(body));
          const hasCsrfHeader = (headers['x-csrf-token'] || headers['csrf-token']) !== undefined;

          if (!hasCsrfInBody && !hasCsrfHeader && resp.status >= 200 && resp.status < 400) {
            findings.push({
              attackId: 'DAST-CSRF-MISSING-001',
              attackName: 'Missing CSRF Token',
              target: url,
              method: 'GET',
              parameter: 'response',
              payload: '',
              evidence: `State-changing endpoint at ${url} does not expose a CSRF token in HTML or headers.`,
              severity: 'medium',
              severityRank: 3,
              cweId: 'CWE-352',
              owaspCategory: 'A01:2021 - Broken Access Control',
              cvssScore: 6.5,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
              recommendation: 'Implement CSRF tokens for all state-changing requests. Use the SameSite cookie attribute as defense-in-depth.',
              description: `The endpoint at ${url} does not include a CSRF token in the response body or custom headers. State-changing requests (POST/PUT/DELETE) to this endpoint may be vulnerable to CSRF attacks.`,
            });
            break; // One finding per target is sufficient
          }
        } catch { continue; }
      }
    } catch (err) {
      logger.warn({ scanId, err }, 'CSRF token check failed (non-fatal)');
    }

    // Step 4: Active attack testing
    const methods = ['GET', 'POST'];
    let processed = 0;
    const totalTargets = urls.length * methods.length;

    // Pre-fetch baseline GET responses for root + a few paths to detect SPA catch-all
    const baselineCache = new Map<string, string>();
    try {
      const rootResp = await makeHttpRequest({ url: urls[0]!, method: 'GET', headers: { 'Accept': '*/*' } });
      if (rootResp.status >= 200 && rootResp.status < 300) {
        const rootBody = rootResp.body.slice(0, 2000);
        baselineCache.set(urls[0]!, rootBody);
        // Check a non-existent path — if it returns identical content, this is a SPA catch-all
        const probeUrl = new URL(urls[0]!).origin + '/__dast_spa_probe_' + Date.now();
        try {
          const probeResp = await makeHttpRequest({ url: probeUrl, method: 'GET', headers: { 'Accept': '*/*' } });
          if (probeResp.status === 200 && probeResp.body.slice(0, 2000) === rootBody) {
            // SPA detected — use root baseline for all URLs
            for (const url of urls) baselineCache.set(url, rootBody);
            logger.info({ scanId }, 'SPA catch-all detected — baseline applied to all paths');
          }
        } catch { /* probe failed, not SPA */ }
      }
    } catch { /* target unreachable */ }

    for (const url of urls) {
      for (const method of methods) {
        processed++;
        if (processed % 5 === 0) await job.updateProgress(25 + Math.floor((processed / totalTargets) * 65));

        const baseTarget = { url, method, headers: { 'Accept': '*/*', 'Content-Type': 'application/json' }, body: method !== 'GET' ? '{"test":true}' : undefined };

        try {
          // For each attack module, generate vectors and test
          for (const attack of ALL_ATTACKS.slice(0, 10)) { // Limit per URL for performance
            if (attack.attackType === 'header' || attack.payloads.length === 0) {
              const resp = await makeHttpRequest(baseTarget);
              const baseline = baselineCache.get(url);
              const afs = await analyzeResponse(baseTarget, attack, resp.body, resp.headers, resp.status, baseline);
              findings.push(...afs);
              continue;
            }

            for (const payload of attack.payloads.slice(0, 3)) { // 3 payloads per attack
              const modifiedTarget = { ...baseTarget };
              const pUrl = new URL(url);

              switch (attack.attackType) {
                case 'query': pUrl.searchParams.set('q', payload); modifiedTarget.url = pUrl.toString(); break;
                case 'body': modifiedTarget.body = payload; break;
                case 'path': modifiedTarget.url = url.replace(/\/$/, '') + '/' + encodeURIComponent(payload); break;
              }

              // Apply WAF evasion if needed
              let testPayload = payload;
              if (wafProfile.detected !== 'None' && wafProfile.evasionTechniques.length > 0) {
                const technique = wafProfile.evasionTechniques[0]!;
                const encoder = EVASION_ENCODERS[technique];
                if (encoder) testPayload = encoder(payload);
              }

              try {
                const resp = await makeHttpRequest(modifiedTarget);
                // Baseline comparison: if the response body is identical to the
                // clean baseline, the server isn't processing the injected input
                const baseline = baselineCache.get(url);
                if (baseline && resp.body.slice(0, 2000) === baseline) continue;

                const afs = await analyzeResponse(modifiedTarget, attack, resp.body, resp.headers, resp.status);
                if (afs.length > 0) {
                  findings.push(...afs.map(f => ({ ...f, evidence: f.evidence + ` [WAF: ${wafProfile.detected}]` })));
                  break; // Found, move to next attack
                }
              } catch { continue; }
            }
          }
        } catch { continue; }
      }
    }

    await job.updateProgress(78);

    // Step 4b: OOB (Out-of-Band) interaction probing for blind SSRF/XXE/RCE/SQLi.
    // Mints unique tokens, injects OOB payloads into target URLs, then polls
    // the local callback listener for interaction evidence.
    const oobServer = await ensureOobServer();
    const oobFindings: DastFinding[] = [];
    const oobTypes = ['SSRF', 'XXE', 'RCE', 'SQLI'] as const;
    const oobPayloadGens: Record<string, (token: string, cb: string) => Array<{ payload: string; description: string; attackType: string }>> = {
      SSRF: generateOobSsrfPayloads,
      XXE: generateOobXxePayloads,
      RCE: generateOobRcePayloads,
      SQLI: generateOobSqliPayloads,
    };

    let oobProbes = 0;
    const oobUrls = urls.slice(0, 3); // limit OOB to first 3 URLs for performance
    const totalOobProbes = oobUrls.length * oobTypes.length;

    for (const url of oobUrls) {
      for (const vulnType of oobTypes) {
        oobProbes++;
        if (oobProbes % 2 === 0) await job.updateProgress(78 + Math.floor((oobProbes / totalOobProbes) * 7));

        const gen = oobPayloadGens[vulnType];
        if (!gen) continue;

        const { token, callbackUrl } = oobServer.mintToken({
          vulnType: vulnType as 'SSRF' | 'XXE' | 'RCE' | 'SQLI',
          target: url,
          payload: '',
        });

        const payloads = gen(token, callbackUrl);

        for (const pl of payloads.slice(0, 3)) { // 3 payloads per vuln type
          const baseTarget = {
            url,
            method: pl.attackType === 'body' ? 'POST' : 'GET',
            headers: {
              'Accept': '*/*',
              'Content-Type': pl.attackType === 'body' ? 'application/xml' : 'text/plain',
            },
            body: pl.attackType === 'body' ? pl.payload : undefined,
          };

          let modifiedTarget = { ...baseTarget };
          if (pl.attackType === 'query') {
            const pUrl = new URL(url);
            // Inject payloads into common parameter names
            for (const param of ['url', 'q', 'id', 'search', 'redirect', 'callback', 'next', 'return', 'file', 'path', 'page']) {
              pUrl.searchParams.set(param, pl.payload);
            }
            modifiedTarget.url = pUrl.toString();
          } else if (pl.attackType === 'path') {
            modifiedTarget.url = url.replace(/\/$/, '') + '/' + encodeURIComponent(pl.payload);
          }

          try {
            // Send the probe to the target (this triggers the target to call back to us)
            await makeHttpRequest({ ...modifiedTarget, timeout: 10000 });

            // Poll for callback — 5 second window as specified
            const record = await oobServer.checkCallback(token, 5000);
            if (record) {
              const finding = buildOobFinding(
                vulnType as 'SSRF' | 'XXE' | 'RCE' | 'SQLI',
                url,
                modifiedTarget.method,
                pl.payload,
                record,
              );
              oobFindings.push(finding);
              logger.warn({
                scanId,
                vulnType,
                token,
                remoteIp: record.remoteIp,
                payload: pl.payload.slice(0, 100),
              }, 'OOB interaction confirmed — blind vulnerability detected!');
              break; // confirmed, move to next vuln type
            }
          } catch {
            // Target may have rejected the probe; continue to next payload.
            continue;
          }
        }
      }
    }

    if (oobFindings.length > 0) {
      findings.push(...oobFindings);
      logger.info({ scanId, oobFindings: oobFindings.length }, 'OOB-confirmed blind vulnerabilities found');
    }

    await job.updateProgress(85);

    // Step 4c: API Security Testing (OWASP API Top 10 2023)
    // BOLA, BFLA, Mass Assignment, Rate Limiting, Excessive Data Exposure
    const apiSecurityFindings: DastFinding[] = [];
    const apiSecAttacks = [...API_SECURITY_ATTACKS];

    // Extract credentials and config from job options
    const primaryToken = options?.primaryCredentials?.token as string | undefined;
    const primaryUserId = options?.primaryCredentials?.userId as string | undefined;
    const secondaryToken = options?.secondaryCredentials?.token as string | undefined;
    const secondaryUserId = options?.secondaryCredentials?.userId as string | undefined;
    const adminEndpoints = (options?.adminEndpoints as string[]) || [];
    const apiSpecUrl = options?.apiSpecUrl as string | undefined;
    const resourceTypes = (options?.bolaResourceTypes as string[]) || ['users', 'accounts', 'orders', 'profiles'];

    // ---- BOLA: Broken Object Level Authorization ----
    if (primaryToken && secondaryToken && primaryUserId && secondaryUserId) {
      logger.info({ scanId, primaryUserId, secondaryUserId }, 'API Security: Testing BOLA with dual credentials');
      try {
        for (const resourceType of resourceTypes) {
          const bolaVectors = generateBolaPayloads(resourceType, primaryUserId, secondaryUserId);
          // Limit to avoid excessive requests
          for (const vector of bolaVectors.slice(0, 15)) {
            const bolaAttack = apiSecAttacks.find(a => a.id === 'DAST-API-BOLA-001');
            if (!bolaAttack) continue;

            const fullUrl = targetUrl.replace(/\/$/, '') + vector.path;
            try {
              // Make request with primary user's token to access secondary user's resource
              const resp = await makeHttpRequest({
                url: fullUrl,
                method: 'GET',
                headers: {
                  Authorization: `Bearer ${primaryToken}`,
                  Accept: 'application/json',
                  'Content-Type': 'application/json',
                },
              });

              // If we got a 200 with data, check for PII exposure
              if (resp.status >= 200 && resp.status < 300 && resp.body.length > 20) {
                const bolaAnalysis = analyzeBolaResponse(resp.body, [
                  'email', 'password', 'ssn', 'credit_card', 'token',
                  'secret', 'address', 'phone', 'role',
                ]);
                if (bolaAnalysis.exposed) {
                  apiSecurityFindings.push({
                    attackId: bolaAttack.id,
                    attackName: bolaAttack.name,
                    target: fullUrl,
                    method: 'GET',
                    parameter: 'path',
                    payload: vector.path,
                    evidence: bolaAnalysis.evidence,
                    severity: bolaAttack.severity,
                    severityRank: 1,
                    cweId: bolaAttack.cweId,
                    owaspCategory: bolaAttack.owaspCategory,
                    cvssScore: bolaAttack.cvssScore,
                    cvssVector: bolaAttack.cvssVector,
                    recommendation: bolaAttack.recommendation,
                    description: `${bolaAttack.description} — ${vector.description}`,
                  });
                }
              }
            } catch { /* request failed, continue */ }
          }
        }
      } catch (err) {
        logger.warn({ scanId, err }, 'BOLA testing failed (non-fatal)');
      }
    }

    // ---- BFLA: Broken Function Level Authorization ----
    if (primaryToken) {
      logger.info({ scanId, endpoints: adminEndpoints.length }, 'API Security: Testing BFLA');
      try {
        const bflaAttack = apiSecAttacks.find(a => a.id === 'DAST-API-BFLA-001');
        if (bflaAttack) {
          // Collect admin endpoints from config + discovered URLs
          const discoveredAdminUrls = urls
            .filter(u => /\/admin\b|\/manage\b|\/system\b|\/config\b|\/users\b.*\badmin/i.test(u))
            .slice(0, 10);

          const allAdminEndpoints = [...new Set([...adminEndpoints, ...discoveredAdminUrls])];
          // If no admin endpoints found, use standard set
          const bflaTargets = generateBflaPayloads(
            primaryToken,
            allAdminEndpoints.length > 0 ? allAdminEndpoints : [],
            targetUrl,
          );

          for (const bflaTarget of bflaTargets.slice(0, 20)) {
            try {
              const resp = await makeHttpRequest({
                url: bflaTarget.url,
                method: bflaTarget.method as string,
                headers: bflaTarget.headers as Record<string, string>,
                body: bflaTarget.body,
              });

              const bflaAnalysis = analyzeBflaResponse(resp.status, resp.body);
              if (bflaAnalysis.vulnerable) {
                apiSecurityFindings.push({
                  attackId: bflaAttack.id,
                  attackName: bflaAttack.name,
                  target: bflaTarget.url,
                  method: bflaTarget.method,
                  parameter: 'path',
                  payload: bflaTarget.url,
                  evidence: bflaAnalysis.evidence,
                  severity: bflaAttack.severity,
                  severityRank: 1,
                  cweId: bflaAttack.cweId,
                  owaspCategory: bflaAttack.owaspCategory,
                  cvssScore: bflaAttack.cvssScore,
                  cvssVector: bflaAttack.cvssVector,
                  recommendation: bflaAttack.recommendation,
                  description: bflaAttack.description,
                });
                break; // One confirmed BFLA is enough
              }
            } catch { /* request failed, continue */ }
          }
        }
      } catch (err) {
        logger.warn({ scanId, err }, 'BFLA testing failed (non-fatal)');
      }
    }

    // ---- Mass Assignment ----
    {
      logger.info({ scanId }, 'API Security: Testing mass assignment');
      try {
        const massAttack = apiSecAttacks.find(a => a.id === 'DAST-API-MASS-001');
        if (massAttack) {
          // Find POST/PUT/PATCH endpoints from discovered URLs
          const apiPaths = urls
            .filter(u => /\/(?:api|rest|v[12])\/.*(?:user|account|profile|register|create|update)/i.test(u))
            .slice(0, 5);

          const testUrls = apiPaths.length > 0 ? apiPaths : [targetUrl];
          const massPayloads = generateMassAssignmentPayloads();

          for (const url of testUrls) {
            for (const mp of massPayloads.slice(0, 6)) {
              for (const method of ['POST', 'PUT', 'PATCH']) {
                try {
                  const resp = await makeHttpRequest({
                    url,
                    method,
                    headers: {
                      Authorization: primaryToken ? `Bearer ${primaryToken}` : '',
                      Accept: 'application/json',
                      'Content-Type': 'application/json',
                    },
                    body: mp.body,
                  });

                  // Check if the privileged field was reflected
                  const fieldNames = Object.keys(mp.extraFields);
                  for (const field of fieldNames) {
                    const analysis = analyzeMassAssignmentResponse(resp.body, field);
                    if (analysis.reflected) {
                      apiSecurityFindings.push({
                        attackId: massAttack.id,
                        attackName: massAttack.name,
                        target: url,
                        method,
                        parameter: 'body',
                        payload: mp.body.slice(0, 200),
                        evidence: analysis.evidence,
                        severity: massAttack.severity,
                        severityRank: 2,
                        cweId: massAttack.cweId,
                        owaspCategory: massAttack.owaspCategory,
                        cvssScore: massAttack.cvssScore,
                        cvssVector: massAttack.cvssVector,
                        recommendation: massAttack.recommendation,
                        description: `${massAttack.description} — ${mp.label}`,
                      });
                      break;
                    }
                  }
                } catch { /* request failed, continue */ }
              }
            }
          }
        }
      } catch (err) {
        logger.warn({ scanId, err }, 'Mass assignment testing failed (non-fatal)');
      }
    }

    // ---- Rate Limiting Detection ----
    {
      logger.info({ scanId }, 'API Security: Testing rate limiting');
      try {
        const rateAttack = apiSecAttacks.find(a => a.id === 'DAST-API-RATELIMIT-001');
        if (rateAttack) {
          const rateResult = await testRateLimiting(
            async (t) => {
              const resp = await makeHttpRequest({
                url: t.url,
                method: t.method,
                headers: t.headers,
              });
              return { status: resp.status, headers: resp.headers, body: resp.body };
            },
            targetUrl,
            15,
          );

          if (!rateResult.rateLimited) {
            apiSecurityFindings.push({
              attackId: rateAttack.id,
              attackName: rateAttack.name,
              target: targetUrl,
              method: 'GET',
              parameter: 'rate',
              payload: `${rateResult.burstCount} rapid requests`,
              evidence: rateResult.evidence,
              severity: rateAttack.severity,
              severityRank: 3,
              cweId: rateAttack.cweId,
              owaspCategory: rateAttack.owaspCategory,
              cvssScore: rateAttack.cvssScore,
              cvssVector: rateAttack.cvssVector,
              recommendation: rateAttack.recommendation,
              description: rateAttack.description,
            });
          }
        }
      } catch (err) {
        logger.warn({ scanId, err }, 'Rate limiting test failed (non-fatal)');
      }
    }

    // ---- Excessive Data Exposure (on discovered API endpoints) ----
    {
      logger.info({ scanId }, 'API Security: Testing excessive data exposure');
      try {
        const edataAttack = apiSecAttacks.find(a => a.id === 'DAST-API-EDATA-001');
        if (edataAttack) {
          const apiEndpoints = urls.filter(u => /\/(?:api|rest|v[12])\//i.test(u)).slice(0, 5);
          const testEndpoints = apiEndpoints.length > 0 ? apiEndpoints : [targetUrl];

          for (const endpoint of testEndpoints) {
            for (const payload of edataAttack.payloads.slice(0, 3)) {
              try {
                const resp = await makeHttpRequest({
                  url: endpoint + payload,
                  method: 'GET',
                  headers: {
                    Authorization: primaryToken ? `Bearer ${primaryToken}` : '',
                    Accept: 'application/json',
                  },
                });

                if (resp.status >= 200 && resp.status < 300 && resp.body.length > 20) {
                  for (const pattern of edataAttack.detectPatterns) {
                    if (pattern.test(resp.body)) {
                      apiSecurityFindings.push({
                        attackId: edataAttack.id,
                        attackName: edataAttack.name,
                        target: endpoint,
                        method: 'GET',
                        parameter: 'query',
                        payload: payload,
                        evidence: `Sensitive fields detected in response: ${resp.body.slice(0, 300)}`,
                        severity: edataAttack.severity,
                        severityRank: 3,
                        cweId: edataAttack.cweId,
                        owaspCategory: edataAttack.owaspCategory,
                        cvssScore: edataAttack.cvssScore,
                        cvssVector: edataAttack.cvssVector,
                        recommendation: edataAttack.recommendation,
                        description: edataAttack.description,
                      });
                      break;
                    }
                  }
                }
              } catch { /* request failed, continue */ }
            }
          }
        }
      } catch (err) {
        logger.warn({ scanId, err }, 'Excessive data exposure test failed (non-fatal)');
      }
    }

    if (apiSecurityFindings.length > 0) {
      findings.push(...apiSecurityFindings);
      logger.info({ scanId, apiSecFindings: apiSecurityFindings.length }, 'API security findings detected');
    }

    await job.updateProgress(87);

    // Step 5: Blind SQLi detection on discovered parameters
    try {
      logger.info({ scanId }, 'Running blind SQLi detection');
      for (const url of urls.slice(0, 5)) {
        const blindTarget = { url, method: 'GET', headers: { 'Accept': '*/*' } };
        const blindFindings = await detectBlindSqli(
          blindTarget,
          async (t) => {
            const resp = await makeHttpRequest({ ...t, timeout: 20000 });
            return { status: resp.status, body: resp.body, timing: resp.timing };
          },
          { timeThresholdMs: 4000, confirmRounds: 2 },
        );
        findings.push(...blindFindings);
      }
    } catch (err) {
      logger.warn({ scanId, err }, 'Blind SQLi detection failed (non-fatal)');
    }
    await job.updateProgress(88);

    // Step 6: Nuclei template scan (optional — requires nuclei binary)
    if (isBinaryAvailable('nuclei')) {
      try {
        logger.info({ scanId }, 'Running Nuclei scan');
        const nucleiFindings = await runNuclei(targetUrl, {
          severity: 'critical,high,medium',
          timeout: 10,
          rateLimit: 50,
        });
        findings.push(...nucleiFindings);
        logger.info({ scanId, nucleiFindings: nucleiFindings.length }, 'Nuclei findings added');
      } catch (err) {
        logger.warn({ scanId, err }, 'Nuclei scan failed (non-fatal)');
      }
    } else {
      logger.info({ scanId }, 'Nuclei binary not found — skipping template scan');
    }
    await job.updateProgress(92);

    // Step 7: Nikto web server scan (optional — requires nikto binary)
    if (isBinaryAvailable('nikto')) {
      try {
        logger.info({ scanId }, 'Running Nikto scan');
        const niktoFindings = await runNikto(targetUrl, { maxTime: 300, timeout: 10 });
        findings.push(...niktoFindings);
        logger.info({ scanId, niktoFindings: niktoFindings.length }, 'Nikto findings added');
      } catch (err) {
        logger.warn({ scanId, err }, 'Nikto scan failed (non-fatal)');
      }
    } else {
      logger.info({ scanId }, 'Nikto binary not found — skipping web server scan');
    }
    await job.updateProgress(95);

    // Dedupe: missing-header / passive issues are host-level (same on every page) — collapse
    // to one per type instead of one per crawled URL. Injection findings stay per location
    // (attack + target + parameter). This cuts the per-URL header spam dramatically.
    const isHostLevel = (f: DastFinding) => f.attackId === 'DAST-PASSIVE'
      || /missing|header|hsts|csp|policy|x-frame|x-content|referrer|cors|clickjack/i.test(`${f.attackName} ${f.attackId}`);
    const seen = new Set<string>();
    const deduped: DastFinding[] = [];
    for (const f of findings) {
      const key = isHostLevel(f) ? `H|${f.attackId}|${f.attackName}` : `${f.attackId}|${f.target}|${f.parameter}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(f);
    }
    findings.length = 0; findings.push(...deduped);
    const result = { scanId, projectId, organizationId, findings, totalFindings: findings.length,
      severityBreakdown: { critical: findings.filter(f=>f.severity==='critical').length, high: findings.filter(f=>f.severity==='high').length, medium: findings.filter(f=>f.severity==='medium').length, low: findings.filter(f=>f.severity==='low').length, info: findings.filter(f=>f.severity==='info').length },
      wafDetected: wafProfile.detected, urlsCrawled: urls.length, attacksRun: ALL_ATTACKS.length };
    // Persist findings + mark the scan completed so it leaves 'queued'/'running'.
    for (const f of findings) {
      try {
        await storeFinding(scanId, projectId, organizationId, {
          type: 'dast', title: f.attackName || f.attackId || 'DAST finding',
          description: f.description || f.evidence || '', severity: f.severity || 'info',
          cweId: f.cweId || undefined, owaspCategory: f.owaspCategory || undefined,
          cvssScore: f.cvssScore || undefined, cvssVector: f.cvssVector || undefined,
          filePath: f.target || targetUrl, ruleId: f.attackId || undefined,
          ruleName: f.attackName || undefined, recommendation: f.recommendation || undefined,
          codeSnippet: f.payload || undefined,
        });
      } catch (e) { logger.error({ scanId, err: e }, 'DAST: failed to store finding'); }
    }
    await completeScan(scanId, findings.length, { wafDetected: wafProfile.detected, urlsCrawled: urls.length, attacksRun: ALL_ATTACKS.length });
    await job.updateProgress(100);
    logger.info({ scanId, totalFindings: findings.length }, 'DAST complete');
    return result;
  } catch (err) {
    logger.error({ scanId, err }, 'DAST failed');
    try { await failScan(scanId, err instanceof Error ? err.message : String(err)); } catch { /* best effort */ }
    throw err;
  }
}

const worker = new Worker('dast-scan', processJob, { connection, concurrency: 2, limiter: { max: 5, duration: 60000 } });
worker.on('completed', (j) => logger.info({ jobId: j?.id }, 'DAST done'));
worker.on('failed', (j, e) => logger.error({ jobId: j?.id, err: e.message }, 'DAST error'));
logger.info('DAST Worker running — 26 attack modules (core + advanced + API security) + Nuclei + Nikto + Blind SQLi + OOB + rate limiting + session fixation + OAuth loaded');
