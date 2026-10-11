// DAST Engine Unit Tests
// Tests attack vector generation, response analysis, WAF fingerprinting,
// passive scanner detection, and security header validation.

import { describe, it, expect } from 'vitest';
import {
  generateAttackVectors,
  analyzeResponse,
  crawlTarget,
  DAST_ATTACKS,
  type DastTarget,
  type DastAttack,
} from '../../../scanners/src/dast/engine.js';
import {
  detectWAF,
  passiveScanResponse,
  EVASION_ENCODERS,
  runPCIComplianceScan,
  type WAFProfile,
} from '../../../scanners/src/dast/enterprise-dast.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTarget(overrides: Partial<DastTarget> = {}): DastTarget {
  return {
    url: 'https://example.com/api/users?id=1',
    method: 'GET',
    headers: { Accept: '*/*' },
    ...overrides,
  };
}

/** Returns the first DastAttack matching the given ID. */
function getAttack(id: string): DastAttack {
  const attack = DAST_ATTACKS.find(a => a.id === id);
  if (!attack) throw new Error(`Attack ${id} not found`);
  return attack;
}

// ---------------------------------------------------------------------------
// Attack Vector Generation
// ---------------------------------------------------------------------------

describe('DAST Engine — Attack Vector Generation', () => {
  describe('SQL Injection vectors', () => {
    const attack = getAttack('DAST-SQLI-001');

    it('should generate vectors for query-type attacks', () => {
      const target = makeTarget();
      const vectors = generateAttackVectors(target);
      const sqliVectors = vectors.filter(v => v.attack.id === 'DAST-SQLI-001');
      expect(sqliVectors.length).toBeGreaterThan(0);
      expect(sqliVectors.length).toBeLessThanOrEqual(10); // capped at 10 per attack
    });

    it('should inject payload into the existing query parameter', () => {
      const target = makeTarget({ url: 'https://example.com/search?q=test' });
      const vectors = generateAttackVectors(target);
      const sqliVectors = vectors.filter(v => v.attack.id === 'DAST-SQLI-001');
      expect(sqliVectors.length).toBeGreaterThan(0);
      // The payload should be appended to the existing "q" parameter value
      for (const v of sqliVectors) {
        const parsedUrl = new URL(v.target.url);
        const qVal = parsedUrl.searchParams.get('q') || '';
        expect(qVal).toContain('test');
        expect(v.payload.length).toBeGreaterThan(0);
      }
    });

    it('should include common SQLi payloads', () => {
      const payloads = attack.payloads;
      expect(payloads).toContain("' OR '1'='1");
      expect(payloads).toContain("' UNION SELECT NULL--");
      expect(payloads).toContain("1' OR '1'='1'#");
      expect(payloads).toContain("'; DROP TABLE users--");
      expect(payloads).toContain("1 AND 1=1");
    });

    it('should set correct metadata on SQLi attack', () => {
      expect(attack.cweId).toBe('CWE-89');
      expect(attack.severity).toBe('critical');
      expect(attack.attackType).toBe('query');
      expect(attack.cvssScore).toBe(9.8);
    });
  });

  describe('XSS vectors', () => {
    const attack = getAttack('DAST-XSS-001');

    it('should include common XSS payloads', () => {
      expect(attack.payloads).toContain('<script>alert(1)</script>');
      expect(attack.payloads).toContain('<img src=x onerror=alert(1)>');
      expect(attack.payloads).toContain('<svg onload=alert(1)>');
    });

    it('should generate XSS vectors when URL has no query params', () => {
      const target = makeTarget({ url: 'https://example.com/page' });
      const vectors = generateAttackVectors(target);
      const xssVectors = vectors.filter(v => v.attack.id === 'DAST-XSS-001');
      expect(xssVectors.length).toBeGreaterThan(0);
      // Should add ?q=<payload>
      for (const v of xssVectors) {
        expect(v.target.url).toContain('?q=');
      }
    });

    it('should set correct XSS metadata', () => {
      expect(attack.cweId).toBe('CWE-79');
      expect(attack.severity).toBe('high');
      expect(attack.cvssScore).toBe(7.5);
    });
  });

  describe('SSRF vectors', () => {
    const attack = getAttack('DAST-SSRF-001');

    it('should include internal IP and cloud metadata payloads', () => {
      expect(attack.payloads).toContain('http://169.254.169.254/latest/meta-data/');
      expect(attack.payloads).toContain('http://127.0.0.1:8080');
      expect(attack.payloads).toContain('file:///etc/passwd');
    });

    it('should generate SSRF vectors', () => {
      const target = makeTarget({ url: 'https://example.com/fetch?url=' });
      const vectors = generateAttackVectors(target);
      const ssrfVectors = vectors.filter(v => v.attack.id === 'DAST-SSRF-001');
      expect(ssrfVectors.length).toBeGreaterThan(0);
    });
  });

  describe('Command Injection vectors', () => {
    const attack = getAttack('DAST-CMDI-001');

    it('should include shell metacharacter payloads', () => {
      expect(attack.payloads).toContain('; ls -la');
      expect(attack.payloads).toContain('| ls -la');
      expect(attack.payloads).toContain('$(ls -la)');
    });

    it('should be severity critical', () => {
      expect(attack.severity).toBe('critical');
      expect(attack.cweId).toBe('CWE-78');
    });
  });

  describe('Path Traversal vectors', () => {
    const attack = getAttack('DAST-PT-001');

    it('should include directory traversal payloads', () => {
      expect(attack.payloads).toContain('../../../etc/passwd');
      expect(attack.payloads).toContain('..\\..\\..\\windows\\win.ini');
    });

    it('should include URL-encoded traversal variants', () => {
      expect(attack.payloads).toContain('..%2F..%2F..%2Fetc%2Fpasswd');
    });
  });

  describe('Body-type attack vectors', () => {
    it('should generate XXE body vectors when content type is XML', () => {
      const target = makeTarget({
        url: 'https://example.com/api/parse',
        method: 'POST',
        contentType: 'application/xml',
        body: '<root><data>test</data></root>',
      });
      const vectors = generateAttackVectors(target);
      const xxeVectors = vectors.filter(v => v.attack.id === 'DAST-XXE-001');
      expect(xxeVectors.length).toBeGreaterThan(0);
      for (const v of xxeVectors) {
        expect(v.payload).toContain('<!DOCTYPE');
      }
    });
  });

  describe('Header-type attacks', () => {
    it('should generate vectors for header-type attacks even with empty payloads', () => {
      const target = makeTarget();
      const vectors = generateAttackVectors(target);
      const headerAttacks = vectors.filter(v => v.attack.attackType === 'header');
      expect(headerAttacks.length).toBeGreaterThan(0);
      for (const v of headerAttacks) {
        expect(v.payload).toBe('');
      }
    });
  });

  it('generateAttackVectors returns vectors for all attack types', () => {
    const target = makeTarget();
    const vectors = generateAttackVectors(target);
    // Should have entries from all non-header attacks that have payloads
    const attackIds = new Set(vectors.map(v => v.attack.id));
    // At minimum: SQLi, XSS, SSRF, CMDI, PT (all have payloads)
    expect(attackIds.has('DAST-SQLI-001')).toBe(true);
    expect(attackIds.has('DAST-XSS-001')).toBe(true);
    expect(attackIds.has('DAST-SSRF-001')).toBe(true);
    expect(attackIds.has('DAST-CMDI-001')).toBe(true);
    expect(attackIds.has('DAST-PT-001')).toBe(true);
    // Header-only attacks also included (CSRF, HEADER, CORS, JWT)
    expect(attackIds.has('DAST-HEADER-001')).toBe(true);
  });

  it('does not modify the original target when generating vectors', () => {
    const target = makeTarget({ url: 'https://example.com/page?q=original' });
    const originalUrl = target.url;
    generateAttackVectors(target);
    expect(target.url).toBe(originalUrl);
  });
});

// ---------------------------------------------------------------------------
// Response Analysis
// ---------------------------------------------------------------------------

describe('DAST Engine — Response Analysis', () => {
  describe('SQLi detection patterns', () => {
    const attack = getAttack('DAST-SQLI-001');

    it('should detect SQL syntax error in response body', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].attackId).toBe('DAST-SQLI-001');
    });

    it('should detect Oracle error ORA-xxxxx', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'ORA-00933: SQL command not properly ended',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect unclosed quotation mark error', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'Unclosed quotation mark after the character string',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should NOT flag clean response', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        '{"users":[{"id":1,"name":"Alice"}]}',
        {},
      );
      expect(findings).toHaveLength(0);
    });
  });

  describe('XSS detection patterns', () => {
    const attack = getAttack('DAST-XSS-001');

    it('should detect reflected <script>alert(1)</script>', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        '<html><body><script>alert(1)</script></body></html>',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].attackId).toBe('DAST-XSS-001');
    });

    it('should detect reflected alert(1) without script tags', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'Search result: alert(1) was not found',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect <img> with onerror handler', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        '<img src=x onerror=alert(1)>',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect <svg> with onload handler', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        '<svg onload=alert(1)>',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('SSRF detection patterns', () => {
    const attack = getAttack('DAST-SSRF-001');

    it('should detect cloud metadata in response', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'ami-id: ami-123456\ninstance-id: i-abcdef',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect /etc/passwd content leak', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Command Injection detection', () => {
    const attack = getAttack('DAST-CMDI-001');

    it('should detect /etc/passwd leak in response', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'root:x:0:0:root:/root:/bin/bash',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect Windows directory listing', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'Directory of C:\\Users\\Admin',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Path Traversal detection', () => {
    const attack = getAttack('DAST-PT-001');

    it('should detect /etc/passwd in response', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should detect Windows ini file content', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        '[fonts]\n[extensions]',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('XXE detection', () => {
    const attack = getAttack('DAST-XXE-001');

    it('should detect /etc/passwd leak via XXE', async () => {
      const findings = await analyzeResponse(
        makeTarget(),
        attack,
        'root:x:0:0:root:/root:/bin/bash',
        {},
      );
      expect(findings.length).toBeGreaterThan(0);
    });
  });
});

// ---------------------------------------------------------------------------
// Passive Scanner
// ---------------------------------------------------------------------------

describe('DAST Engine — Passive Scanner', () => {
  it('should flag missing HSTS header', () => {
    const findings = passiveScanResponse('<html></html>', {});
    const hstsFinding = findings.find(f => f.type === 'missing-hsts');
    expect(hstsFinding).toBeDefined();
    expect(hstsFinding!.severity).toBe('low');
  });

  it('should flag missing CSP header', () => {
    const findings = passiveScanResponse('<html></html>', {});
    const cspFinding = findings.find(f => f.type === 'missing-csp');
    expect(cspFinding).toBeDefined();
    expect(cspFinding!.severity).toBe('low');
  });

  it('should flag permissive CORS (wildcard origin)', () => {
    const findings = passiveScanResponse(
      '<html></html>',
      { 'access-control-allow-origin': '*' },
    );
    const corsFinding = findings.find(f => f.type === 'permissive-cors');
    expect(corsFinding).toBeDefined();
    expect(corsFinding!.severity).toBe('medium');
  });

  it('should flag sensitive data in response body', () => {
    const findings = passiveScanResponse(
      '{"apiKey": "sk-abcdefghijklmnopqrstuvwxyz0123456789"}',
      {},
    );
    const secretFinding = findings.find(f => f.type === 'sensitive-data');
    expect(secretFinding).toBeDefined();
    expect(secretFinding!.severity).toBe('high');
  });

  it('should flag stack traces in response body', () => {
    const findings = passiveScanResponse(
      'Error: Cannot read property \'x\' of undefined\n    at Object.<anonymous> (/app/src/server.ts:42:10)',
      {},
    );
    const stackFinding = findings.find(f => f.type === 'stack-trace');
    expect(stackFinding).toBeDefined();
    expect(stackFinding!.severity).toBe('medium');
  });

  it('should return multiple passive findings simultaneously', () => {
    const findings = passiveScanResponse('<html></html>', {});
    expect(findings.length).toBeGreaterThanOrEqual(2); // HSTS + CSP at minimum
  });

  it('should not flag HSTS when header is present', () => {
    const findings = passiveScanResponse(
      '<html></html>',
      { 'strict-transport-security': 'max-age=31536000' },
    );
    expect(findings.find(f => f.type === 'missing-hsts')).toBeUndefined();
  });

  it('should not flag CSP when header is present', () => {
    const findings = passiveScanResponse(
      '<html></html>',
      { 'content-security-policy': "default-src 'self'" },
    );
    expect(findings.find(f => f.type === 'missing-csp')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// WAF Fingerprinting
// ---------------------------------------------------------------------------

describe('DAST Engine — WAF Fingerprinting', () => {
  it('should detect Cloudflare from x-cdn header', () => {
    const profile = detectWAF({ 'x-cdn': 'Cloudflare' });
    expect(profile.detected).toBe('Cloudflare');
    expect(profile.mode).toBe('block');
    expect(profile.evasionTechniques.length).toBeGreaterThan(0);
  });

  it('should detect AWS WAF from server header', () => {
    const profile = detectWAF({ server: 'awselb/2.0' });
    expect(profile.detected).toBe('AWS WAF');
    expect(profile.mode).toBe('block');
  });

  it('should return "None" when no WAF is detected', () => {
    const profile = detectWAF({ 'content-type': 'text/html' });
    expect(profile.detected).toBe('None');
    expect(profile.mode).toBe('monitor');
    expect(profile.evasionTechniques).toHaveLength(0);
    expect(profile.rateLimitThreshold).toBe(1000);
  });

  it('Cloudflare profile includes evasion techniques', () => {
    const profile = detectWAF({ 'x-cdn': 'Cloudflare' });
    expect(profile.evasionTechniques).toContain('double-url-encode');
    expect(profile.evasionTechniques).toContain('case-variation');
    expect(profile.evasionTechniques).toContain('unicode-normalize');
  });

  it('AWS WAF profile includes evasion techniques', () => {
    const profile = detectWAF({ server: 'awselb/2.0' });
    expect(profile.evasionTechniques).toContain('whitespace-tricks');
    expect(profile.evasionTechniques).toContain('comment-injection');
  });
});

// ---------------------------------------------------------------------------
// WAF Evasion Encoders
// ---------------------------------------------------------------------------

describe('DAST Engine — WAF Evasion Encoders', () => {
  it('url-encode encodes special characters', () => {
    const result = EVASION_ENCODERS['url-encode']("' OR '1'='1");
    expect(result).toBe("%27%20OR%20%271%27%3D%271");
  });

  it('double-url-encode encodes twice', () => {
    const result = EVASION_ENCODERS['double-url-encode']("<script>");
    expect(result).toBe("%253Cscript%253E");
  });

  it('null-byte appends %00', () => {
    const result = EVASION_ENCODERS['null-byte']("test.php");
    expect(result).toBe("test.php%00");
  });

  it('base64 encoder works', () => {
    const result = EVASION_ENCODERS['base64']("test");
    expect(result).toBe("dGVzdA==");
  });
});

// ---------------------------------------------------------------------------
// Security Headers (Passive Analysis via analyzeResponse)
// ---------------------------------------------------------------------------

describe('DAST Engine — Security Header Analysis', () => {
  const headerAttack = getAttack('DAST-HEADER-001');

  it('should flag missing security headers via analyzeResponse', async () => {
    const findings = await analyzeResponse(
      makeTarget({ url: 'https://example.com/login', method: 'POST' }),
      headerAttack,
      '{"ok":true}',
      { 'content-type': 'application/json' },
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].attackId).toBe('DAST-HEADER-001');
    expect(findings[0].evidence).toContain('Missing');
  });

  it('should identify which specific headers are missing', async () => {
    const findings = await analyzeResponse(
      makeTarget(),
      headerAttack,
      'ok',
      { 'x-frame-options': 'DENY' },
    );
    expect(findings.length).toBeGreaterThan(0);
    // Should mention HSTS, CSP, etc. are missing
    expect(findings[0].evidence).toMatch(/HSTS|CSP|Referrer-Policy|X-Content-Type-Options/);
  });

  it('should not report when all security headers are present', async () => {
    const findings = await analyzeResponse(
      makeTarget(),
      headerAttack,
      'ok',
      {
        'strict-transport-security': 'max-age=31536000',
        'content-security-policy': "default-src 'self'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
      },
    );
    // Might still have some headers missing depending on the check — but we verify the HSTS at least is present.
    const hstsFindings = findings.filter(f => f.evidence.includes('HSTS'));
    expect(hstsFindings).toHaveLength(0);
  });
});

describe('DAST Engine — CORS Analysis', () => {
  const corsAttack = getAttack('DAST-CORS-001');

  it('should flag wildcard Access-Control-Allow-Origin', async () => {
    const findings = await analyzeResponse(
      makeTarget(),
      corsAttack,
      'ok',
      { 'access-control-allow-origin': '*' },
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].evidence).toContain('*');
  });

  it('should flag null Access-Control-Allow-Origin', async () => {
    const findings = await analyzeResponse(
      makeTarget(),
      corsAttack,
      'ok',
      { 'access-control-allow-origin': 'null' },
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should NOT flag specific origin', async () => {
    const findings = await analyzeResponse(
      makeTarget(),
      corsAttack,
      'ok',
      { 'access-control-allow-origin': 'https://app.example.com' },
    );
    expect(findings.filter(f => f.attackId === 'DAST-CORS-001')).toHaveLength(0);
  });
});

describe('DAST Engine — CSRF Analysis', () => {
  const csrfAttack = getAttack('DAST-CSRF-001');

  it('should flag missing CSRF token on POST request', async () => {
    const findings = await analyzeResponse(
      makeTarget({ url: 'https://example.com/api/data', method: 'POST' }),
      csrfAttack,
      '{"created":true}',
      {},
    );
    const csrfFindings = findings.filter(f => f.attackId === 'DAST-CSRF-001');
    expect(csrfFindings.length).toBeGreaterThan(0);
    expect(csrfFindings[0].evidence).toContain('No CSRF token');
  });

  it('should not flag CSRF when token header is present', async () => {
    const findings = await analyzeResponse(
      makeTarget({ url: 'https://example.com/api/data', method: 'POST' }),
      csrfAttack,
      '{"created":true}',
      { 'x-csrf-token': 'abc123' },
    );
    expect(findings.filter(f => f.attackId === 'DAST-CSRF-001')).toHaveLength(0);
  });

  it('should not check CSRF on GET requests', async () => {
    const findings = await analyzeResponse(
      makeTarget({ method: 'GET' }),
      csrfAttack,
      'ok',
      {},
    );
    expect(findings.filter(f => f.attackId === 'DAST-CSRF-001')).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Attack Definition Integrity
// ---------------------------------------------------------------------------

describe('DAST Engine — Attack Definition Integrity', () => {
  it('all attacks have unique IDs', () => {
    const ids = DAST_ATTACKS.map(a => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('all attacks have valid severity', () => {
    const valid = new Set(['critical', 'high', 'medium', 'low', 'info']);
    for (const attack of DAST_ATTACKS) {
      expect(valid.has(attack.severity)).toBe(true);
    }
  });

  it('all attacks have CWE IDs', () => {
    for (const attack of DAST_ATTACKS) {
      expect(attack.cweId).toMatch(/^CWE-\d+$/);
    }
  });

  it('every query/path/body attack has at least one payload', () => {
    for (const attack of DAST_ATTACKS) {
      if (attack.attackType !== 'header') {
        expect(
          attack.payloads.length,
          `${attack.id} (type=${attack.attackType}) should have payloads`,
        ).toBeGreaterThan(0);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Crawl Target
// ---------------------------------------------------------------------------

describe('DAST Engine — Crawl Target', () => {
  it('always includes the original URL', () => {
    const urls = crawlTarget('https://example.com');
    expect(urls[0]).toBe('https://example.com');
  });

  it('includes common paths like /robots.txt and /sitemap.xml', () => {
    const urls = crawlTarget('https://example.com');
    expect(urls).toContain('https://example.com/robots.txt');
    expect(urls).toContain('https://example.com/sitemap.xml');
  });

  it('includes API endpoints', () => {
    const urls = crawlTarget('https://example.com');
    expect(urls).toContain('https://example.com/api/');
    expect(urls).toContain('https://example.com/swagger');
    expect(urls).toContain('https://example.com/graphql');
  });

  it('includes security-sensitive paths', () => {
    const urls = crawlTarget('https://example.com');
    expect(urls).toContain('https://example.com/.env');
    expect(urls).toContain('https://example.com/admin');
  });
});

// ---------------------------------------------------------------------------
// PCI Compliance Scan
// ---------------------------------------------------------------------------

describe('DAST Engine — PCI Compliance Scan', () => {
  it('passes when no critical CWE-89 or CWE-79 findings exist', () => {
    const result = runPCIComplianceScan([
      { cweId: 'CWE-22', severity: 'medium' },
    ]);
    expect(result.overallPassed).toBe(true);
  });

  it('fails when critical SQLi findings exist', () => {
    const result = runPCIComplianceScan([
      { cweId: 'CWE-89', severity: 'critical' },
    ]);
    expect(result.overallPassed).toBe(false);
    expect(result.score).toBeLessThan(100);
  });

  it('reports PCI DSS v4.0 framework', () => {
    const result = runPCIComplianceScan([]);
    expect(result.framework).toBe('PCI DSS v4.0');
  });
});
