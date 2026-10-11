// =============================================================================
// Precision / recall evaluation test for the secrets detection engine.
// ALL secrets in this file are SYNTHETIC — never real credentials.
// =============================================================================

import { describe, it, expect } from 'vitest';
import { scanFileForSecrets } from '../sast/secrets-engine.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Run each positive case through the scanner; count true positives and
 *  false negatives. A "positive" case MUST produce ≥ 1 finding. */
function evaluatePositive(cases: { type: string; line: string }[]): { tp: number; fn: number } {
  let tp = 0;
  let fn = 0;
  for (const c of cases) {
    const findings = scanFileForSecrets('test.ts', c.line);
    if (findings.length >= 1) {
      tp++;
    } else {
      fn++;
    }
  }
  return { tp, fn };
}

/** Run each negative case through the scanner; count true negatives and
 *  false positives. A "negative" case MUST produce 0 findings. */
function evaluateNegative(cases: { type: string; line: string }[]): { tn: number; fp: number } {
  let tn = 0;
  let fp = 0;
  for (const c of cases) {
    const findings = scanFileForSecrets('test.ts', c.line);
    if (findings.length === 0) {
      tn++;
    } else {
      fp++;
    }
  }
  return { tn, fp };
}

// ---------------------------------------------------------------------------
// SYNTHETIC positive corpus — every entry embeds a format-valid but FAKE secret
// ---------------------------------------------------------------------------

const POSITIVE_CORPUS: { type: string; line: string }[] = [
  // AWS Access Key ID — AKIA + 16 [0-9A-Z]
  {
    type: 'AWS Access Key ID (AKIA)',
    line: 'AWS_ACCESS_KEY_ID=AKIA7XKJ2MPQ9R5VT03N8W',
  },
  // GitHub Personal Access Token (classic) — ghp_ + 36 [a-zA-Z0-9]
  {
    type: 'GitHub PAT',
    line: 'GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
  },
  // GitLab Personal Access Token — glpat- + 20-40 [a-zA-Z0-9\-_]
  {
    type: 'GitLab PAT',
    line: 'GITLAB_TOKEN=glpat-AbCdEfGhIjKlMnOpQrSt',
  },
  // Slack Bot Token — xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}
  {
    type: 'Slack Bot Token',
    line: 'SLACK_BOT_TOKEN=xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx',
  },
  // Google API Key — AIza + exactly 35 [0-9A-Za-z\-_] (total match 39 chars)
  {
    type: 'Google API Key',
    line: 'GOOGLE_API_KEY=AIzaAbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
  },
  // Stripe Live Secret Key — sk_live_ + 24+ [a-zA-Z0-9]
  {
    type: 'Stripe Live Secret Key',
    line: 'STRIPE_KEY=sk_live_AbCdEfGhIjKlMnOpQrStUvWx',
  },
  // RSA Private Key (single-line synthetic PEM block with >50 chars payload)
  {
    type: 'PEM RSA Private Key',
    line:
      '-----BEGIN RSA PRIVATE KEY-----' +
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/==' +
      '-----END RSA PRIVATE KEY-----',
  },
  // JWT token — eyJ… . eyJ… . …
  {
    type: 'JWT Token',
    line:
      'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.' +
      'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.' +
      'AbCdEfGhIjKlMnOpQrStUvWxYz',
  },
  // npm Access Token — npm_ + 36 [a-zA-Z0-9]
  {
    type: 'npm Access Token',
    line: 'NPM_TOKEN=npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
  },
  // SendGrid API Key — SG. + 22 [a-zA-Z0-9\-_] + . + 43 [a-zA-Z0-9\-_]
  {
    type: 'SendGrid API Key',
    line:
      'SENDGRID_KEY=SG.AbCdEfGhIjKlMnOpQrStUv.' +
      'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789012345678',
  },
  // OpenAI API Key — sk- + 20-50 [a-zA-Z0-9]
  {
    type: 'OpenAI API Key',
    line: 'OPENAI_API_KEY=sk-AbCdEfGhIjKlMnOpQrStUvWxYz01234',
  },
  // Anthropic API Key — sk-ant-[a-z0-9]{2,5}-[a-zA-Z0-9]{32,60}
  {
    type: 'Anthropic API Key',
    line:
      'ANTHROPIC_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
  },
  // Generic high-entropy Base64 string (80+ chars)
  {
    type: 'High-Entropy Base64 String',
    line:
      'SECRET_BASE64=' +
      'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789/+' +
      'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789/+' +
      'ABCDEFGH',
  },
];

// ---------------------------------------------------------------------------
// NEGATIVE corpus — every entry must NOT be flagged
// ---------------------------------------------------------------------------

const NEGATIVE_CORPUS: { type: string; line: string }[] = [
  // AWS documented example key (denylisted)
  {
    type: 'AWS example access key',
    line: 'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
  },
  // Placeholder x's
  {
    type: 'X placeholder',
    line: 'PLACEHOLDER=xxxxxxxxxxxx',
  },
  // Denylisted exact match
  {
    type: 'changeme placeholder',
    line: 'PASSWORD=changeme',
  },
  // Empty string (no secret)
  {
    type: 'empty value',
    line: '',
  },
  // Environment variable reference — not a secret itself
  {
    type: 'process.env reference',
    line: "const token = process.env.SECRET",
  },
  // 40-hex-char git SHA (matches regex but entropy < 4.5 threshold)
  {
    type: '40-hex git SHA',
    line: 'commit a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
  },
  // Uppercase UUID (npm legacy pattern requires lowercase [a-f0-9])
  {
    type: 'UUID (uppercase)',
    line: 'REQUEST_ID=550E8400-E29B-41D4-A716-446655440000',
  },
  // MD5 hash — 32 hex chars, no pattern matches this length
  {
    type: 'MD5 hash',
    line: 'MD5_HASH=d41d8cd98f00b204e9800998ecf8427e',
  },
  // Plain English sentence — no pattern matches
  {
    type: 'plain English sentence',
    line: 'The quick brown fox jumps over the lazy dog',
  },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Secrets Engine — Precision / Recall Evaluation', () => {
  // -- Positive cases (must be detected) ------------------------------------

  for (const c of POSITIVE_CORPUS) {
    it(`POSITIVE: should detect ${c.type}`, () => {
      const findings = scanFileForSecrets('test.ts', c.line);
      expect(
        findings.length,
        `Expected ≥1 finding for "${c.type}" but got ${findings.length}. Line: ${c.line}`,
      ).toBeGreaterThanOrEqual(1);
    });
  }

  // -- Negative cases (must NOT be detected) --------------------------------

  for (const c of NEGATIVE_CORPUS) {
    it(`NEGATIVE: should NOT flag ${c.type}`, () => {
      const findings = scanFileForSecrets('test.ts', c.line);
      expect(
        findings.length,
        `Expected 0 findings for "${c.type}" but got ${findings.length} (${findings.map(f => f.patternId).join(', ')}). Line: "${c.line}"`,
      ).toBe(0);
    });
  }

  // -- Aggregate precision / recall -----------------------------------------

  it('should meet precision ≥ 0.95 and recall ≥ 0.90', () => {
    const { tp, fn } = evaluatePositive(POSITIVE_CORPUS);
    const { fp } = evaluateNegative(NEGATIVE_CORPUS);

    const precision = tp / (tp + fp);
    const recall = tp / (tp + fn);

    console.log('=== Precision / Recall Report ===');
    console.log(`  True Positives  : ${tp}`);
    console.log(`  False Positives : ${fp}`);
    console.log(`  False Negatives : ${fn}`);
    console.log(`  Precision       : ${(precision * 100).toFixed(1)}%`);
    console.log(`  Recall          : ${(recall * 100).toFixed(1)}%`);

    expect(precision, `Precision ${(precision * 100).toFixed(1)}% < 95%`).toBeGreaterThanOrEqual(0.95);
    expect(recall, `Recall ${(recall * 100).toFixed(1)}% < 90%`).toBeGreaterThanOrEqual(0.90);
  });
});
