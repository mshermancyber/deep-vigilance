import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger.js';

export interface SastRule {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cweId: string;
  owaspCategory: string;
  languages: string[];
  patterns: RegExp[];
  excludePatterns?: RegExp[];
  recommendation: string;
  cvssScore: number;
  cvssVector: string;
  category: string;
}

export interface SastFinding {
  ruleId: string;
  ruleName: string;
  ruleCategory: string;
  title: string;
  description: string;
  severity: string;
  severityRank: number;
  filePath: string;
  lineNumber: number;
  lineRange: string;
  codeSnippet: string;
  cweId: string;
  owaspCategory: string;
  cvssScore: number;
  cvssVector: string;
  recommendation: string;
  references: string[];
  language: string;
  match: string;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 1, high: 2, medium: 3, low: 4, info: 5,
};

const FILE_EXTENSIONS: Record<string, string> = {
  '.java': 'java', '.kt': 'kotlin', '.scala': 'java',
  '.cs': 'csharp',
  '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.c': 'cpp', '.h': 'cpp', '.hpp': 'cpp',
  '.go': 'go',
  '.py': 'python',
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
  'Dockerfile': 'dockerfile',
  '.sh': 'shell', '.bash': 'shell',
  '.ps1': 'powershell',
};

const IGNORE_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv', 'vendor',
  '.next', '.nuxt', 'dist', 'build', 'target', '.idea', '.vscode',
  'coverage', '.nyc_output', 'bower_components',
]);

export function getLanguage(filePath: string): string | null {
  const ext = path.extname(filePath);
  if (FILE_EXTENSIONS[ext]) return FILE_EXTENSIONS[ext];

  const basename = path.basename(filePath);
  if (basename === 'Dockerfile') return 'dockerfile';
  if (basename.startsWith('Dockerfile.')) return 'dockerfile';
  if (basename === 'Makefile') return 'makefile';
  if (basename.endsWith('.config.js') || basename.endsWith('.config.ts')) return 'javascript';

  return null;
}

// =============================================================================
// Comprehensive SAST Rule Definitions
// =============================================================================

export const SAST_RULES: SastRule[] = [
  // --- SQL Injection ---
  {
    id: 'SAST-SQLI-001',
    name: 'SQL Injection via String Concatenation',
    description: 'SQL query built with string concatenation may allow SQL injection.',
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
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
      /(\.createQueryBuilder\([^)]*\)\.where\(\s*`[^`]*\$\{)/i,
    ],
    // Suppress when the query is parameterized ($1/$2 placeholders, a params array, or ?
    // bind markers) — the interpolated part is then placeholders, not user data.
    // R4 tuning: UI component names. R5: toString, error messages, log statements, assertions
    excludePatterns: [
      /\$\d/, /,\s*params\b/, /,\s*\[/, /\?\s*[,)]/, /=\s*\$\d/,
      /<Select\b/, /Select\s+(?:panel|query|option|value|item|multiple|component|row|column|placeholder|label|input|aggregation|alias|source)/i,
      /toString\s*\(/, /\.format\s*\(\s*"[^"]*(?:Expected|Invalid|Failed|Error|Unknown|Unsupported|Cannot|Could not|No such|Not found|Missing)/i,
      /throw\s+new\s+\w*(?:Exception|Error|Argument)/i, /assert\b/i,
      /log(?:ger)?\.(?:info|warn|error|debug|trace)\s*\(/i,
      /"(?:delete|update|insert)\s+(?:\w+\s+)?(?:from|for|of|in|into)\s/i,
    ],
    recommendation: 'Use parameterized queries or an ORM with proper escaping. Never concatenate user input into SQL statements.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },

  // --- XSS ---
  {
    id: 'SAST-XSS-001',
    name: 'Cross-Site Scripting (XSS)',
    description: 'Unsanitized user input rendered in HTML output may lead to XSS.',
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript', 'python', 'php', 'ruby', 'java', 'csharp', 'go'],
    // Only flag DYNAMIC sinks (variable / concatenation / template-interpolation).
    // A static string literal assigned to innerHTML is not injectable.
    patterns: [
      /innerHTML\s*=\s*[A-Za-z_$][\w$.[\]]*\s*[;,)]?/,        // innerHTML = someVar
      /innerHTML\s*=\s*[^;]*\+/,                              // innerHTML = '...' + x
      /innerHTML\s*=\s*`[^`]*\$\{/,                            // innerHTML = `...${x}`
      /(dangerouslySetInnerHTML\s*=\s*\{)/,
      /(document\.write\s*\(\s*[A-Za-z_$][\w$.]*)/,            // write(var), not write('static')
      /(\$\s*\([^)]*\)\s*\.html\s*\(\s*[A-Za-z_$][\w$.]*\s*\))/,
      /(v-html\s*=\s*["'][^"']*[A-Za-z_$])/,
      /(ng-bind-html\s*=)/,
    ],
    recommendation: 'Sanitize all user input before rendering. Use textContent instead of innerHTML. Implement Content Security Policy (CSP).',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    category: 'injection',
  },

  // --- Command Injection ---
  {
    id: 'SAST-CMDI-001',
    name: 'Command Injection',
    description: 'User input used in shell command execution may allow command injection.',
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
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
      /(\bpopen\s*\(\s*\w+\s*[,)])/,
      /(eval\s*\(\s*`[^`]*`)/,
      /(shell_exec\s*\(\s*[^)]*\$\w+[^)]*\))/,
      /(Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)]*\w+\s*\+\s*\w+)/,
      /(Process\.start\s*\(\s*"(?:cmd|bash|sh|powershell)"\s*,\s*[^)]*\+)/i,
    ],
    recommendation: 'Use execFile or spawn instead of exec. Avoid shell interpreters. Use array-based argument passing. Validate and sanitize all inputs.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },

  // --- Hardcoded Secrets ---
  {
    id: 'SAST-SECRET-001',
    name: 'Hardcoded Secrets',
    description: 'Hardcoded passwords, API keys, tokens, or credentials found in source code.',
    severity: 'critical',
    cweId: 'CWE-798',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
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
    recommendation: 'Store secrets in environment variables, a secrets manager (Vault, AWS Secrets Manager), or use a .env file excluded from version control. Rotate exposed credentials immediately.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'credentials',
  },

  // --- Weak Cryptography ---
  {
    id: 'SAST-CRYPTO-001',
    name: 'Weak Cryptographic Algorithm',
    description: 'Use of deprecated or insecure cryptographic algorithms.',
    severity: 'high',
    cweId: 'CWE-327',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['all'],
    // Match actual weak-crypto API *usage*, not the bare words "MD5"/"SHA1"/"DES"
    // which appear constantly in comments, identifiers, IOC strings, and docstrings.
    patterns: [
      /(?:hashlib\.(?:md5|sha1)\s*\()/i,                                   // python
      /(\.createHash\s*\(\s*["'](?:md5|sha-?1)["'])/i,                      // node crypto
      /(createHmac\s*\(\s*["'](?:md5|sha-?1)["'])/i,                        // node hmac
      /(MessageDigest\s*\.\s*getInstance\s*\(\s*["'](?:MD5|SHA-?1)["'])/i,  // java
      /(Cipher\s*\.\s*getInstance\s*\(\s*["'](?:DES|RC4|[^"']*ECB)["'])/i,  // java weak cipher/mode
      /(CryptoJS\s*\.\s*(?:MD5|SHA1|RC4|DES|TripleDES)\s*\()/,             // crypto-js
      /(createCipheriv\s*\(\s*["'](?:des|rc4|[a-z0-9-]*-ecb)["'])/i,        // node ECB/DES/RC4
      /(HashAlgorithm\s*\.\s*MD5\b)/i,                                      // .NET
      /(encryption_algorithm\s*=\s*["'](?:md5|sha1|des|rc4)["'])/i,
    ],
    recommendation: 'Use AES-256-GCM for symmetric encryption, RSA-4096 or ECDH for asymmetric, SHA-256 or SHA-3 for hashing, and PBKDF2/bcrypt/Argon2 for password hashing.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'cryptography',
  },

  // --- Path Traversal ---
  {
    id: 'SAST-PT-001',
    name: 'Path Traversal Vulnerability',
    description: 'User input used in file path construction may allow path traversal attacks.',
    severity: 'high',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php', 'java', 'go', 'csharp'],
    patterns: [
      /(fs\.readFile\s*\(\s*[^,)]*\$\{)/,
      /(open\s*\(\s*[^)]*\+\s*\w+\s*\+\s*["'])/,
      /(path\.join\s*\(\s*[^)]*req\.(?:query|params|body))/i,
      /(file_get_contents\s*\(\s*[^)]*\$\w+)/,
      /(\.SendFile\s*\(\s*.*req\.(?:query|params))/i,
    ],
    recommendation: 'Use allowlists for file access. Normalize and validate file paths. Use chroot or container isolation. Never construct file paths directly from user input.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'access-control',
  },

  // --- SSRF ---
  {
    id: 'SAST-SSRF-001',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'User-controlled URL used in server-side HTTP requests.',
    severity: 'high',
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 - SSRF',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php', 'java', 'go'],
    patterns: [
      /(axios\.(?:get|post|put|delete)\s*\(\s*(?:`\$\{|req\.(?:query|params|body)))/i,
      /(fetch\s*\(\s*(?:`[^`]*\$\{[^}]*req\.|req\.(?:query|params|body)))/i,
      /(requests\.(?:get|post|put|delete)\s*\(\s*(?:f?["'][^"']*\{[^}]*\}[^"']*["']|req\.|request\.))/i,
      /(open-uri\s*\(\s*[^)]*params)/i,
      /(file_get_contents\s*\(\s*[^)]*\$\w+\))/,
      /(http\.Client\(\)\.(?:Get|Post)\s*\(\s*[^)]*req\.)/i,
    ],
    recommendation: 'Validate and sanitize URLs. Use allowlists for target hosts. Block internal IP ranges. Use a dedicated HTTP client with SSRF protection.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    category: 'ssrf',
  },

  // --- Insecure Deserialization ---
  {
    id: 'SAST-DESER-001',
    name: 'Insecure Deserialization',
    description: 'Deserialization of untrusted data may lead to remote code execution.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['java', 'python', 'javascript', 'typescript', 'php', 'ruby', 'csharp'],
    patterns: [
      /(ObjectInputStream\s*\w+\s*=\s*new\s+ObjectInputStream\s*\([^)]*request)/i,
      /(pickle\.loads?\s*\(\s*request)/i,
      /(yaml\.load\s*\(\s*[^,)]*\))/,
      /(JSON\.parse\s*\(\s*.*without\s+try)/,
      /(eval\s*\(\s*(?:req\.(?:body|query|params)|JSON\.parse))/i,
      /(unserialize\s*\(\s*[^)]*\$(?:_GET|_POST|_REQUEST))/i,
      /(Marshal\.load\s*\(\s*.*request)/i,
      /(BinaryFormatter\s*\.\s*Deserialize)/i,
      /(\.Deserialize\s*\(\s*\w)/,
    ],
    recommendation: 'Never deserialize untrusted data. Use safe serialization formats (JSON, Protocol Buffers). Implement integrity checks (HMAC signatures).',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },

  // --- XXE ---
  {
    id: 'SAST-XXE-001',
    name: 'XML External Entity (XXE) Injection',
    description: 'XML parser configured to allow external entities may expose internal files.',
    severity: 'high',
    cweId: 'CWE-611',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['all'],
    patterns: [
      /(DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\))/,
      /(SAXParserFactory\s*\.\s*newInstance\s*\(\s*\))/,
      /(XMLInputFactory\s*\.\s*newFactory\s*\(\s*\))/,
      /(\.setFeature\s*\(\s*"http:\/\/apache\.org\/xml\/features\/disallow-doctype-decl"\s*,\s*false)/,
      /(etree\.parse\s*\(\s*[^)]*\)\s*$)/m,
      /(simplexml_load_string\s*\(\s*[^,)]*\$(?:_GET|_POST|_REQUEST))/i,
    ],
    recommendation: 'Disable external entities in XML parsers. Use DocumentBuilderFactory with FEATURE_SECURE_PROCESSING. Prefer JSON over XML.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'xxe',
  },

  // --- Prototype Pollution ---
  {
    id: 'SAST-PROTO-001',
    name: 'Prototype Pollution',
    description: 'Unsafe object merge or extend may allow prototype pollution in JavaScript.',
    severity: 'high',
    cweId: 'CWE-1321',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['javascript', 'typescript'],
    patterns: [
      /(Object\.assign\s*\(\s*\{\}\s*,\s*req\.(?:body|query|params))/i,
      /(\.extend\s*\(\s*[^,)]*,\s*req\.(?:body|query|params))/i,
      /(\.merge\s*\(\s*[^,)]*,\s*req\.(?:body|query|params))/i,
      /(lodash\.merge\s*\(\s*[^,)]*,\s*req\.(?:body|query|params))/i,
      /(\.set\s*\(\s*\{[^}]*\}\s*,\s*req\.(?:body|query|params)\.\w+\s*,\s*req\.(?:body|query|params)\.\w+)/i,
    ],
    recommendation: 'Use Object.create(null) for dictionaries. Validate property keys. Use safe merge utilities that whitelist allowed keys.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'injection',
  },

  // --- Open Redirect ---
  {
    id: 'SAST-OR-001',
    name: 'Open Redirect',
    description: 'User-controlled URL used in redirect may enable phishing attacks.',
    severity: 'medium',
    cweId: 'CWE-601',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php', 'java', 'go', 'csharp'],
    patterns: [
      /(res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\.\w+|`[^`]*\$\{[^}]*req))/i,
      /(window\.location\s*=\s*(?:req\.|params\.|searchParams\.))/i,
      /(redirect\s*\(\s*(?:request\.args|request\.form))/i,
      /(?<!\/)(header\s*\(\s*["']Location:\s*["']\.\s*\$(?:_GET|_POST))/i,
    ],
    recommendation: 'Validate redirect URLs against an allowlist. Use relative redirects when possible. Warn users before redirecting to external sites.',
    cvssScore: 6.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    category: 'access-control',
  },

  // --- Insecure JWT ---
  {
    id: 'SAST-JWT-001',
    name: 'Insecure JWT Configuration',
    description: 'JWT library configured with insecure options like "none" algorithm.',
    severity: 'high',
    cweId: 'CWE-347',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    patterns: [
      /(algorithms\s*:\s*\[\s*["']none["']\s*\])/i,
      /(jwt\.decode\s*\(\s*\w+\s*\))/,
      /(ignoreExpiration\s*:\s*true)/,
      /(verify_signature\s*=\s*False)/,
      /(\.setSigningKey\s*\(\s*"")/,
      /(jwt\.verify\s*\(\s*\w+\s*,\s*["'][^"']*["']\s*,\s*\{\s*algorithms\s*:\s*\[\s*["']HS256["']\s*\])/,
    ],
    recommendation: 'Always verify JWT signatures. Use strong algorithms (RS256, ES256). Never use "none" algorithm. Validate issuer and audience claims.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'authentication',
  },

  // --- Unsafe Regex (ReDoS) ---
  {
    id: 'SAST-REDOS-001',
    name: 'ReDoS - Inefficient Regular Expression',
    description: 'Regular expression with exponential backtracking may cause denial of service.',
    severity: 'medium',
    cweId: 'CWE-1333',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['all'],
    patterns: [
      /(\/\^?\(\.\*\)\+\$?\/)/,
      /(\/\^?\(\.\+\)\+.*\$?\/)/,
      /((?:\(\?:\.\*\)\+))/,
      /((?:\(\?:\.\+\)\+))/,
      /(\/\^?\([^/)]{0,200}\|[^/)]{0,200}\)\+\$?\/)/,
    ],
    recommendation: 'Use non-backtracking regex features. Set timeout limits on regex execution. Use RE2 or Rust regex for untrusted inputs.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
    category: 'dos',
  },

  // --- Debug Code ---
  {
    id: 'SAST-DEBUG-001',
    name: 'Debug Code in Production',
    description: 'Debug statements, logging of sensitive data, or development utilities found in code.',
    severity: 'low',
    cweId: 'CWE-489',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['all'],
    patterns: [
      /(console\.log\s*\(.*(?:password|secret|token|credential|apiKey|api_key|private.?key))/i,
      /(console\.(?:debug|dir|trace)\s*\(.*(?:password|secret|token|credential))/i,
      /(var_dump\s*\(\s*\$\w+\))/,
      /(logger\.debug\s*\(\s*.*password)/i,
      /(System\.out\.println\s*\(\s*.*(?:token|secret|key|password))/i,
    ],
    recommendation: 'Remove debug statements from production code. Use structured logging at appropriate levels. Never log sensitive data.',
    cvssScore: 2.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
    category: 'debug',
  },

  // --- Dangerous Functions ---
  {
    id: 'SAST-DANGER-001',
    name: 'Use of Dangerous Function',
    description: 'Function known to be dangerous when used with untrusted input.',
    severity: 'high',
    cweId: 'CWE-676',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript', 'python', 'php'],
    // Match BARE eval/exec calls (builtins), not method calls like dlg.exec()/re.exec()
    // (Qt/regex) — the leading (?<![.\w]) excludes `.exec(`. Plus real shell-exec APIs.
    patterns: [
      /(?<![.\w])eval\s*\(/,
      /(?<![.\w])exec\s*\(/,                                  // python builtin exec(
      /child_process\.(?:exec|execSync|execFile)\s*\(/,       // node shell exec
      /(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen))\s*\(/, // python shell
      /(\bnew\s+Function\s*\()/,
      /(\bsetTimeout\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*[,)]))/,  // string-arg setTimeout
      /(\bsetInterval\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*[,)]))/,
    ],
    recommendation: 'Avoid using eval(), exec(), and Function() constructors. Use safer alternatives specific to the use case. Never pass user input to these functions.',
    cvssScore: 8.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'dangerous-functions',
  },
];

export function shouldScanFile(filePath: string, includePatterns: string[], excludePatterns: string[]): boolean {
  const language = getLanguage(filePath);
  if (!language) return false;

  const normalizedPath = filePath.replace(/\\/g, '/');
  const parts = normalizedPath.split('/');

  for (const part of parts) {
    if (IGNORE_DIRS.has(part)) return false;
  }

  for (const pattern of excludePatterns) {
    const regex = new RegExp(pattern.replace(/\*/g, '.*').replace(/\?/g, '.'));
    if (regex.test(normalizedPath)) return false;
  }

  if (includePatterns.length > 0 && includePatterns[0] !== '**/*') {
    const matched = includePatterns.some(pattern => {
      const regex = new RegExp(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*').replace(/\?/g, '.'));
      return regex.test(normalizedPath);
    });
    if (!matched) return false;
  }

  return true;
}

// Whole-line comment detector — used to skip rule matches on pure comment lines
// (a major false-positive source: rule keywords like "md5"/"eval" inside comments).
const HASH_COMMENT_LANGS = new Set(['python', 'ruby', 'shell', 'bash', 'yaml', 'dockerfile', 'makefile', 'perl', 'toml', 'r', 'ini']);
export function isCommentLine(line: string, language: string): boolean {
  const t = line.trim();
  if (!t) return false;
  if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('<!--')) return true;
  if (HASH_COMMENT_LANGS.has(language) && t.startsWith('#')) return true;
  if (language === 'sql' && t.startsWith('--')) return true;
  return false;
}

export function scanFile(
  filePath: string,
  content: string,
  language: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
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
        pattern.lastIndex = 0;
        const match = pattern.exec(line);

        if (match) {
          const contextStart = Math.max(0, lineIdx - 2);
          const contextEnd = Math.min(lines.length, lineIdx + 3);
          const codeSnippet = lines.slice(contextStart, contextEnd).join('\n');

          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            ruleCategory: rule.category,
            title: `${rule.name} in ${path.basename(filePath)}`,
            description: rule.description,
            severity: rule.severity,
            severityRank: SEVERITY_RANK[rule.severity] || 3,
            filePath,
            lineNumber: lineIdx + 1,
            lineRange: `${contextStart + 1}-${contextEnd}`,
            codeSnippet: codeSnippet.slice(0, 500),
            cweId: rule.cweId,
            owaspCategory: rule.owaspCategory,
            cvssScore: rule.cvssScore,
            cvssVector: rule.cvssVector,
            recommendation: rule.recommendation,
            references: [
              `https://cwe.mitre.org/data/definitions/${rule.cweId.replace('CWE-', '')}.html`,
            ],
            language,
            match: match[0].slice(0, 100),
          });
        }
      }
    }
  }

  return findings;
}

export function scanDirectory(
  targetPath: string,
  includePatterns: string[],
  excludePatterns: string[],
): SastFinding[] {
  const allFindings: SastFinding[] = [];

  function walkDir(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith('.')) continue;
        walkDir(fullPath);
      } else if (entry.isFile()) {
        if (!shouldScanFile(fullPath, includePatterns, excludePatterns)) continue;

        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          const language = getLanguage(fullPath);
          if (!language) continue;

          const findings = scanFile(fullPath, content, language);
          allFindings.push(...findings);
        } catch {
          // Skip binary files, permission errors
        }
      }
    }
  }

  try {
    const stat = fs.statSync(targetPath);
    if (stat.isDirectory()) {
      walkDir(targetPath);
    } else if (stat.isFile()) {
      const language = getLanguage(targetPath);
      if (language) {
        const content = fs.readFileSync(targetPath, 'utf-8');
        allFindings.push(...scanFile(targetPath, content, language));
      }
    }
  } catch (err) {
    logger.error({ targetPath, err }, 'Failed to scan path');
  }

  return allFindings;
}

export function getSastRules(): SastRule[] {
  return SAST_RULES;
}

export function getRuleById(id: string): SastRule | undefined {
  return SAST_RULES.find(r => r.id === id);
}
