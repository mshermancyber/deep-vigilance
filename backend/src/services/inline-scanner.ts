// =============================================================================
// Inline Scanner Service — Lightweight synchronous scanning for IDE integration.
// Runs SAST pattern rules + secrets detection in-process. No cross-file taint.
// =============================================================================

import path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface InlineFinding {
  ruleId: string;
  ruleName: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cweId?: string;
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  codeSnippet: string;
  recommendation: string;
  engine: 'sast' | 'secret' | 'sca';
  language?: string;
  match?: string;
}

export interface InlineScanRequest {
  filename: string;
  content: string;
  language?: string;
  engines?: ('sast' | 'secret' | 'sca')[];
}

export interface InlineScanResponse {
  findings: InlineFinding[];
  meta: {
    filename: string;
    language: string;
    engines: string[];
    lines: number;
    durationMs: number;
  };
}

// ---------------------------------------------------------------------------
// Language detection (mirrors scanners/src/sast/engine.ts)
// ---------------------------------------------------------------------------

const FILE_EXTENSIONS: Record<string, string> = {
  '.java': 'java', '.kt': 'kotlin', '.scala': 'java',
  '.cs': 'csharp',
  '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.c': 'cpp', '.h': 'cpp', '.hpp': 'cpp',
  '.go': 'go',
  '.py': 'python', '.pyi': 'python',
  '.rb': 'ruby',
  '.php': 'php', '.phtml': 'php',
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript',
  '.jsx': 'javascript',
  '.rs': 'rust',
  '.swift': 'swift',
  '.tf': 'terraform', '.tfvars': 'terraform',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.json': 'json',
  '.sh': 'shell', '.bash': 'shell',
  '.ps1': 'powershell',
  '.sql': 'sql',
  '.r': 'r',
  '.toml': 'toml',
  '.ini': 'ini',
  '.cfg': 'ini',
  '.xml': 'xml',
  '.html': 'html', '.htm': 'html',
  '.css': 'css', '.scss': 'css', '.less': 'css',
  '.md': 'markdown',
  '.dockerfile': 'dockerfile',
  '.lock': 'lockfile',
  '.txt': 'text',
};

export function getLanguage(filePath: string): string | null {
  const ext = path.extname(filePath);
  if (FILE_EXTENSIONS[ext]) return FILE_EXTENSIONS[ext];

  const basename = path.basename(filePath);
  if (basename === 'Dockerfile') return 'dockerfile';
  if (basename.startsWith('Dockerfile.')) return 'dockerfile';
  if (basename === 'Makefile') return 'makefile';
  if (basename === 'Gemfile') return 'ruby';
  if (basename === 'Rakefile') return 'ruby';
  if (basename.endsWith('file')) return null;

  return null;
}

// ---------------------------------------------------------------------------
// SAST Rule definitions (curated subset for inline scanning)
// ---------------------------------------------------------------------------

interface InlineSastRule {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cweId: string;
  languages: string[];
  patterns: RegExp[];
  excludePatterns?: RegExp[];
  recommendation: string;
  category: string;
}

const SAST_RULES: InlineSastRule[] = [
  // --- SQL Injection ---
  {
    id: 'SAST-SQLI-001', name: 'SQL Injection via String Concatenation',
    severity: 'critical', cweId: 'CWE-89', category: 'injection',
    languages: ['java', 'csharp', 'javascript', 'typescript', 'python', 'php', 'ruby', 'go', 'kotlin', 'swift'],
    patterns: [
      /("SELECT\s.*"\s*\+|'SELECT\s.*'\s*\+|`SELECT\s.*`\s*\+)/i,
      /(`(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{)/i,
      /(["'](?:SELECT|INSERT|UPDATE|DELETE)\s[^"']*["']\s*\.\s*\$)/i,
      /(String\.format\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE))/i,
      /(f?"(?:SELECT|INSERT|UPDATE|DELETE)\s[^"]*"\s*\+)\s*\w+/i,
      /(\.execute\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+)/i,
      /(\.query\s*\(\s*`\$\{.*(?:SELECT|INSERT|UPDATE|DELETE))/i,
      /(cursor\.execute\s*\(\s*f?["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*%.*\))/i,
      /(db\.query\s*\(\s*`[^`]*\$\{[^}]*\}[^`]*(?:SELECT|INSERT|UPDATE|DELETE))/i,
      /(\.raw\s*\(\s*`[^`]*(?:SELECT|INSERT)[^`]*`)/i,
    ],
    excludePatterns: [
      /\$\d/, /,\s*params\b/, /,\s*\[/, /\?\s*[,)]/, /=\s*\$\d/,
      /<Select\b/, /toString\s*\(/, /throw\s+new\s+\w*(?:Exception|Error)/i,
      /log(?:ger)?\.(?:info|warn|error|debug|trace)\s*\(/i,
    ],
    recommendation: 'Use parameterized queries or an ORM with proper escaping.',
  },
  // --- XSS ---
  {
    id: 'SAST-XSS-001', name: 'Cross-Site Scripting (XSS)',
    severity: 'high', cweId: 'CWE-79', category: 'injection',
    languages: ['javascript', 'typescript', 'python', 'php', 'ruby', 'java', 'csharp', 'go'],
    patterns: [
      /innerHTML\s*=\s*[A-Za-z_$][\w$.[\]]*\s*[;,)]?/,
      /innerHTML\s*=\s*[^;]*\+/,
      /innerHTML\s*=\s*`[^`]*\$\{/,
      /(dangerouslySetInnerHTML\s*=\s*\{)/,
      /(document\.write\s*\(\s*[A-Za-z_$][\w$.]*)/,
      /(\$\s*\([^)]*\)\s*\.html\s*\(\s*[A-Za-z_$][\w$.]*\s*\))/,
      /(v-html\s*=\s*["'][^"']*[A-Za-z_$])/,
    ],
    recommendation: 'Sanitize user input before rendering. Use textContent instead of innerHTML.',
  },
  // --- Command Injection ---
  {
    id: 'SAST-CMDI-001', name: 'Command Injection',
    severity: 'critical', cweId: 'CWE-78', category: 'injection',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php', 'java', 'go', 'rust'],
    patterns: [
      /(exec\s*\(\s*(?:`\$\{|[^`"'][^)]*\$\{))/,
      /(\bexec\s*\(\s*`[^`]*\$\{)/,
      /(child_process\.exec\s*\(\s*[^,)]*\$\{)/,
      /(os\.system\s*\(\s*f?["'][^"']*%[^"']*["'])/,
      /(os\.system\s*\(\s*[^)]*\+)/,
      /(subprocess\.run\s*\(\s*f?["'][^"']*\{[^}]*\}[^"']*["'])/,
      /(Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)]*\+)/,
      /(popen\s*\(\s*[^,)]*\$\w+\s*[,)])/,
      /(shell_exec\s*\(\s*[^)]*\$\w+[^)]*\))/,
      /(Process\.start\s*\(\s*"(?:cmd|bash|sh|powershell)"\s*,\s*[^)]*\+)/i,
    ],
    recommendation: 'Use execFile or spawn instead of exec. Avoid shell interpreters.',
  },
  // --- Hardcoded Secrets ---
  {
    id: 'SAST-SECRET-001', name: 'Hardcoded Secrets',
    severity: 'critical', cweId: 'CWE-798', category: 'credentials',
    languages: ['all'],
    patterns: [
      /(password\s*[:=]\s*["'][^"']{8,}["'])/i,
      /(secret\s*[:=]\s*["'][^"']{12,}["'])/i,
      /(api_?key\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["'])/i,
      /((?:auth|bearer|session|refresh)_?token\s*[:=]\s*["'][A-Za-z0-9._-]{20,}["'])/i,
      /(private_?key\s*[:=]\s*["'][A-Za-z0-9+/]{20,}["'])/i,
      /(access_?key\s*[:=]\s*["'][A-Za-z0-9]{20,}["'])/i,
      /(-----BEGIN\s(?:RSA|EC|DSA|OPENSSH)\sPRIVATE\sKEY-----)/,
      /(AKIA[0-9A-Z]{16})/,
      /(ghp_[0-9a-zA-Z]{36})/,
      /(github_pat_[0-9a-zA-Z_]{36,})/,
      /(sk-[a-zA-Z0-9]{32,})/,
    ],
    recommendation: 'Store secrets in environment variables or a secrets manager.',
  },
  // --- Weak Cryptography ---
  {
    id: 'SAST-CRYPTO-001', name: 'Weak Cryptographic Algorithm',
    severity: 'high', cweId: 'CWE-327', category: 'cryptography',
    languages: ['all'],
    patterns: [
      /(?:hashlib\.(?:md5|sha1)\s*\()/i,
      /(\.createHash\s*\(\s*["'](?:md5|sha-?1)["'])/i,
      /(MessageDigest\s*\.\s*getInstance\s*\(\s*["'](?:MD5|SHA-?1)["'])/i,
      /(Cipher\s*\.\s*getInstance\s*\(\s*["'](?:DES|RC4|[^"']*ECB)["'])/i,
      /(CryptoJS\s*\.\s*(?:MD5|SHA1|RC4|DES|TripleDES)\s*\()/,
      /(createCipheriv\s*\(\s*["'](?:des|rc4|[a-z0-9-]*-ecb)["'])/i,
      /(HashAlgorithm\s*\.\s*MD5\b)/i,
    ],
    recommendation: 'Use AES-256-GCM for encryption, SHA-256 or SHA-3 for hashing.',
  },
  // --- Path Traversal ---
  {
    id: 'SAST-PT-001', name: 'Path Traversal Vulnerability',
    severity: 'high', cweId: 'CWE-22', category: 'access-control',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php', 'java', 'go', 'csharp'],
    patterns: [
      /(fs\.readFile\s*\(\s*[^,)]*\$\{)/,
      /(open\s*\(\s*[^)]*\+\s*\w+\s*\+\s*["'])/,
      /(path\.join\s*\(\s*[^)]*req\.(?:query|params|body))/i,
      /(file_get_contents\s*\(\s*[^)]*\$\w+)/,
    ],
    recommendation: 'Use allowlists for file access. Normalize and validate file paths.',
  },
  // --- SSRF ---
  {
    id: 'SAST-SSRF-001', name: 'Server-Side Request Forgery (SSRF)',
    severity: 'high', cweId: 'CWE-918', category: 'ssrf',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php', 'java', 'go'],
    patterns: [
      /(axios\.(?:get|post|put|delete)\s*\(\s*(?:`\$\{|req\.(?:query|params|body)))/i,
      /(fetch\s*\(\s*(?:`[^`]*\$\{[^}]*req\.|req\.(?:query|params|body)))/i,
      /(requests\.(?:get|post|put|delete)\s*\(\s*(?:f?["'][^"']*\{[^}]*\}[^"']*["']|req\.|request\.))/i,
      /(file_get_contents\s*\(\s*[^)]*\$\w+\))/,
    ],
    recommendation: 'Validate and sanitize URLs. Use allowlists for target hosts.',
  },
  // --- Insecure Deserialization ---
  {
    id: 'SAST-DESER-001', name: 'Insecure Deserialization',
    severity: 'critical', cweId: 'CWE-502', category: 'deserialization',
    languages: ['java', 'python', 'javascript', 'typescript', 'php', 'ruby', 'csharp'],
    patterns: [
      /(ObjectInputStream\s*\w+\s*=\s*new\s+ObjectInputStream\s*\([^)]*request)/i,
      /(pickle\.loads?\s*\(\s*request)/i,
      /(yaml\.load\s*\(\s*[^,)]*\))/,
      /(eval\s*\(\s*(?:req\.(?:body|query|params)|JSON\.parse))/i,
      /(unserialize\s*\(\s*[^)]*\$(?:_GET|_POST|_REQUEST))/i,
      /(BinaryFormatter\s*\.\s*Deserialize)/i,
    ],
    recommendation: 'Never deserialize untrusted data. Use safe serialization formats.',
  },
  // --- XXE ---
  {
    id: 'SAST-XXE-001', name: 'XML External Entity (XXE) Injection',
    severity: 'high', cweId: 'CWE-611', category: 'xxe',
    languages: ['all'],
    patterns: [
      /(DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\))/,
      /(SAXParserFactory\s*\.\s*newInstance\s*\(\s*\))/,
      /(XMLInputFactory\s*\.\s*newFactory\s*\(\s*\))/,
      /(\.setFeature\s*\(\s*"http:\/\/apache\.org\/xml\/features\/disallow-doctype-decl"\s*,\s*false)/,
    ],
    recommendation: 'Disable external entities in XML parsers. Prefer JSON over XML.',
  },
  // --- Prototype Pollution ---
  {
    id: 'SAST-PROTO-001', name: 'Prototype Pollution',
    severity: 'high', cweId: 'CWE-1321', category: 'injection',
    languages: ['javascript', 'typescript'],
    patterns: [
      /(Object\.assign\s*\(\s*\{\}\s*,\s*req\.(?:body|query|params))/i,
      /(\.extend\s*\(\s*[^,)]*,\s*req\.(?:body|query|params))/i,
      /(\.merge\s*\(\s*[^,)]*,\s*req\.(?:body|query|params))/i,
      /(lodash\.merge\s*\(\s*[^,)]*,\s*req\.(?:body|query|params))/i,
    ],
    recommendation: 'Use Object.create(null) for dictionaries. Validate property keys.',
  },
  // --- Open Redirect ---
  {
    id: 'SAST-OR-001', name: 'Open Redirect',
    severity: 'medium', cweId: 'CWE-601', category: 'access-control',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php', 'java', 'go', 'csharp'],
    patterns: [
      /(res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\.\w+|`[^`]*\$\{[^}]*req))/i,
      /(window\.location\s*=\s*(?:req\.|params\.|searchParams\.))/i,
      /(?<!\/)(header\s*\(\s*["']Location:\s*["']\.\s*\$(?:_GET|_POST))/i,
    ],
    recommendation: 'Validate redirect URLs against an allowlist.',
  },
  // --- Insecure JWT ---
  {
    id: 'SAST-JWT-001', name: 'Insecure JWT Configuration',
    severity: 'high', cweId: 'CWE-347', category: 'authentication',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    patterns: [
      /(algorithms\s*:\s*\[\s*["']none["']\s*\])/i,
      /(jwt\.decode\s*\(\s*\w+\s*\))/,
      /(ignoreExpiration\s*:\s*true)/,
      /(\.setSigningKey\s*\(\s*"")/,
    ],
    recommendation: 'Always verify JWT signatures. Never use "none" algorithm.',
  },
  // --- Dangerous Functions ---
  {
    id: 'SAST-DANGER-001', name: 'Use of Dangerous Function',
    severity: 'high', cweId: 'CWE-676', category: 'dangerous-functions',
    languages: ['javascript', 'typescript', 'python', 'php'],
    patterns: [
      /(?<![.\w])eval\s*\(/,
      /(?<![.\w])exec\s*\(/,
      /child_process\.(?:exec|execSync|execFile)\s*\(/,
      /(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen))\s*\(/,
      /(\bnew\s+Function\s*\()/,
      /(\bsetTimeout\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*[,)]))/,
      /(\bsetInterval\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*[,)]))/,
    ],
    recommendation: 'Avoid eval(), exec(), and Function() constructors with untrusted input.',
  },
  // --- ReDoS ---
  {
    id: 'SAST-REDOS-001', name: 'ReDoS - Inefficient Regular Expression',
    severity: 'medium', cweId: 'CWE-1333', category: 'dos',
    languages: ['all'],
    patterns: [
      /(\/\^?\(\.\*\)\+\$?\/)/,
      /(\/\^?\(\.\+\)\+.*\$?\/)/,
      /((?:\(\?:\.\*\)\+))/,
    ],
    recommendation: 'Use non-backtracking regex features. Set timeout limits.',
  },
  // --- Debug Code ---
  {
    id: 'SAST-DEBUG-001', name: 'Debug Code in Production',
    severity: 'low', cweId: 'CWE-489', category: 'debug',
    languages: ['all'],
    patterns: [
      /(console\.log\s*\(.*(?:password|secret|token|credential|apiKey|api_key|private.?key))/i,
      /(console\.(?:debug|dir|trace)\s*\(.*(?:password|secret|token|credential))/i,
      /(var_dump\s*\(\s*\$\w+\))/,
      /(System\.out\.println\s*\(\s*.*(?:token|secret|key|password))/i,
    ],
    recommendation: 'Remove debug statements from production code.',
  },
];

// ---------------------------------------------------------------------------
// Comment detection (mirrors scanners/src/sast/engine.ts)
// ---------------------------------------------------------------------------

const HASH_COMMENT_LANGS = new Set([
  'python', 'ruby', 'shell', 'bash', 'yaml', 'dockerfile', 'makefile', 'perl', 'toml', 'r', 'ini',
]);

function isCommentLine(line: string, language: string): boolean {
  const t = line.trim();
  if (!t) return false;
  if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('<!--')) return true;
  if (HASH_COMMENT_LANGS.has(language) && t.startsWith('#')) return true;
  if (language === 'sql' && t.startsWith('--')) return true;
  return false;
}

// ---------------------------------------------------------------------------
// SAST: Pattern-based file scanning (mirrors scanFile in engine.ts)
// ---------------------------------------------------------------------------

function scanFileSast(_filePath: string, content: string, language: string): InlineFinding[] {
  const findings: InlineFinding[] = [];
  const lines = content.split('\n');

  const relevantRules = SAST_RULES.filter(
    rule => rule.languages.includes('all') || rule.languages.includes(language),
  );

  for (const rule of relevantRules) {
    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;

      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx]!;
        if (isCommentLine(line, language)) continue;

        // Check exclude patterns
        if (rule.excludePatterns) {
          let excluded = false;
          for (const ep of rule.excludePatterns) {
            ep.lastIndex = 0;
            if (ep.test(line)) { excluded = true; break; }
          }
          if (excluded) continue;
        }

        pattern.lastIndex = 0;
        const match = pattern.exec(line);

        if (match) {
          const contextStart = Math.max(0, lineIdx - 2);
          const contextEnd = Math.min(lines.length, lineIdx + 3);
          const codeSnippet = lines.slice(contextStart, contextEnd).join('\n');

          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            cweId: rule.cweId,
            line: lineIdx + 1,
            column: match.index + 1,
            endLine: lineIdx + 1,
            endColumn: match.index + match[0].length + 1,
            codeSnippet: codeSnippet.slice(0, 500),
            recommendation: rule.recommendation,
            engine: 'sast',
            language,
            match: match[0].slice(0, 100),
          });
        }
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Secrets: Pattern-based secret detection (lightweight inline version)
// ---------------------------------------------------------------------------

interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  recommendation: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { id: 'AWS-ACCESS-KEY', name: 'AWS Access Key ID', regex: /(?:AKIA|ASIA|AROA|AIDA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}/g, recommendation: 'Rotate the AWS access key immediately via IAM.' },
  { id: 'AWS-SECRET-KEY', name: 'AWS Secret Access Key', regex: /(?<![a-zA-Z0-9+/=])[a-zA-Z0-9+/]{40}(?![a-zA-Z0-9+/=])/g, recommendation: 'Rotate the AWS secret key immediately.' },
  { id: 'GITHUB-TOKEN', name: 'GitHub Personal Access Token', regex: /ghp_[0-9a-zA-Z]{36}/g, recommendation: 'Revoke the GitHub token immediately.' },
  { id: 'GITHUB-FINE-GRAINED', name: 'GitHub Fine-Grained Token', regex: /github_pat_[0-9a-zA-Z_]{36,}/g, recommendation: 'Revoke the GitHub token immediately.' },
  { id: 'OPENAI-KEY', name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{32,}/g, recommendation: 'Rotate the OpenAI API key.' },
  { id: 'SLACK-TOKEN', name: 'Slack Token', regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, recommendation: 'Revoke the Slack token.' },
  { id: 'GENERIC-PASSWORD', name: 'Generic Password Assignment', regex: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{6,}["']/gi, recommendation: 'Store passwords in environment variables.' },
  { id: 'GENERIC-SECRET', name: 'Generic Secret', regex: /(?:secret|api[_-]?key|api[_-]?secret)\s*[:=]\s*["'][^"'\s]{8,}["']/gi, recommendation: 'Store secrets in a secrets manager.' },
  { id: 'PRIVATE-KEY', name: 'Private Key Block', regex: /-----BEGIN\s(?:RSA|EC|DSA|OPENSSH)\sPRIVATE\sKEY-----/g, recommendation: 'Never commit private keys. Use a secrets manager.' },
  { id: 'JWT-TOKEN', name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, recommendation: 'Do not hardcode JWT tokens.' },
  { id: 'GOOGLE-API-KEY', name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, recommendation: 'Restrict Google API key usage.' },
  { id: 'HEROKU-KEY', name: 'Heroku API Key', regex: /[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g, recommendation: 'Rotate the Heroku API key.' },
  { id: 'STRIPE-KEY', name: 'Stripe API Key', regex: /(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}/g, recommendation: 'Rotate the Stripe API key.' },
  { id: 'DATABASE-URL', name: 'Database Connection String', regex: /(?:mysql|postgres|mongodb|redis|sqlite):\/\/[^"'\s]{10,}/gi, recommendation: 'Use environment variables for connection strings.' },
  { id: 'BEARER-TOKEN', name: 'Bearer Token', regex: /bearer[_\s]?token\s*[:=]\s*["'][A-Za-z0-9._\-]{16,}["']/gi, recommendation: 'Store bearer tokens securely.' },
];

function redactSecret(secret: string): string {
  if (secret.length <= 20) {
    return secret.slice(0, 4) + '...' + secret.slice(-4);
  }
  return secret.slice(0, 6) + '...' + secret.slice(-6);
}

function computeEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function scanFileSecrets(_filePath: string, content: string): InlineFinding[] {
  const findings: InlineFinding[] = [];
  const lines = content.split('\n');
  const seenSecrets = new Set<string>();

  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx]!;
      regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = regex.exec(line)) !== null) {
        const matchedValue = match[0] || match[1] || '';
        if (matchedValue.length < 8) continue;

        const dedupKey = `${pattern.id}:${matchedValue}`;
        if (seenSecrets.has(dedupKey)) continue;
        seenSecrets.add(dedupKey);

        const entropy = computeEntropy(matchedValue);
        // Skip low-entropy matches unless it's a password/secret assignment
        if (entropy < 2.5 && !['GENERIC-PASSWORD', 'GENERIC-SECRET', 'DATABASE-URL'].includes(pattern.id)) {
          continue;
        }

        findings.push({
          ruleId: pattern.id,
          ruleName: pattern.name,
          severity: 'high',
          cweId: 'CWE-798',
          line: lineIdx + 1,
          column: match.index + 1,
          endLine: lineIdx + 1,
          endColumn: match.index + matchedValue.length + 1,
          codeSnippet: redactSecret(matchedValue),
          recommendation: pattern.recommendation,
          engine: 'secret',
          match: redactSecret(matchedValue),
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// SCA: Manifest type detection (lightweight inline check)
// ---------------------------------------------------------------------------

function isManifestFile(filename: string): boolean {
  const name = path.basename(filename);
  const manifestNames = [
    'package.json', 'package-lock.json', 'yarn.lock', 'npm-shrinkwrap.json',
    'requirements.txt', 'Pipfile', 'Pipfile.lock', 'setup.py', 'pyproject.toml',
    'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle',
    'go.mod', 'go.sum',
    'Gemfile', 'Gemfile.lock',
    'Cargo.toml', 'Cargo.lock',
    'composer.json', 'composer.lock',
    'packages.config', '*.csproj', '*.fsproj',
    'CMakeLists.txt', 'conanfile.txt', 'conanfile.py',
    'pubspec.yaml',
    'Podfile', 'Podfile.lock',
  ];
  return manifestNames.some(m => {
    if (m.includes('*')) {
      const regex = new RegExp('^' + m.replace(/\*/g, '.*') + '$');
      return regex.test(name);
    }
    return name === m;
  });
}

function scanFileSca(filename: string, _content: string): InlineFinding[] {
  const findings: InlineFinding[] = [];

  if (isManifestFile(filename)) {
    const name = path.basename(filename);
    findings.push({
      ruleId: 'SCA-MANIFEST-001',
      ruleName: 'Dependency Manifest Detected',
      severity: 'info',
      cweId: 'CWE-1104',
      line: 1,
      codeSnippet: `Manifest file: ${name}`,
      recommendation: 'Run a full async SCA scan for complete dependency vulnerability analysis. This inline check only confirms manifest presence.',
      engine: 'sca',
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function scanInline(request: InlineScanRequest): InlineScanResponse {
  const startTime = Date.now();
  const { filename, content, language: providedLanguage, engines } = request;

  const language = providedLanguage || getLanguage(filename) || 'text';
  const enabledEngines = engines || ['sast', 'secret', 'sca'];
  const lines = content.split('\n').length;

  const allFindings: InlineFinding[] = [];

  if (enabledEngines.includes('sast')) {
    const sastFindings = scanFileSast(filename, content, language);
    allFindings.push(...sastFindings);
  }

  if (enabledEngines.includes('secret')) {
    const secretFindings = scanFileSecrets(filename, content);
    allFindings.push(...secretFindings);
  }

  if (enabledEngines.includes('sca')) {
    const scaFindings = scanFileSca(filename, content);
    allFindings.push(...scaFindings);
  }

  return {
    findings: allFindings,
    meta: {
      filename,
      language,
      engines: enabledEngines,
      lines,
      durationMs: Date.now() - startTime,
    },
  };
}
