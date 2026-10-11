/**
 * Pre-curated bundle of high-quality security rules derived from the Semgrep
 * community rules repository.  Each rule targets one of the OWASP/CWE top
 * vulnerability categories and is already converted to the SastRule format
 * consumed by the deep-vigilance SAST engine.
 *
 * Coverage:
 *   CWE-798  Hardcoded Credentials
 *   CWE-79   Cross-Site Scripting (XSS)
 *   CWE-89   SQL Injection
 *   CWE-78   OS Command Injection
 *   CWE-327  Weak Cryptography / CWE-328 Weak Hash
 *   CWE-502  Insecure Deserialization
 *   CWE-918  Server-Side Request Forgery (SSRF)
 *   CWE-22   Path Traversal
 *   CWE-94   Code Injection
 *   CWE-611  XML External Entity (XXE)
 *
 * Languages: Python, JavaScript/TypeScript, Java, Go, Ruby, PHP
 */

import type { SastRule } from './engine.js';

// ─── Helper ──────────────────────────────────────────────────────────────────

function r(pattern: string, flags = 'i'): RegExp {
  return new RegExp(pattern, flags);
}

// ─── CWE-798: Hardcoded Credentials ─────────────────────────────────────────

const hardcodedCredentialRules: SastRule[] = [
  {
    id: 'SAST-SG-HARDCODED-SECRET-PY-001',
    name: 'Hardcoded Password in Python Assignment',
    description: 'A variable whose name suggests it holds a password is assigned a string literal. Hard-coded credentials in source code risk exposure through version control and compiled artifacts.',
    severity: 'high',
    cweId: 'CWE-798',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    languages: ['python'],
    patterns: [
      r('(?:password|passwd|pwd|secret|api_key|apikey|api_secret|auth_token|access_token)\\s*=\\s*["\'][^"\']{3,}["\']'),
    ],
    excludePatterns: [
      r('(?:password|secret|api_key)\\s*=\\s*(?:os\\.environ|os\\.getenv|config\\.|settings\\.|None|""|\'\'|environ)'),
      r('#\\s*(?:nosec|noqa|pragma)'),
    ],
    recommendation: 'Remove hard-coded credentials and use environment variables, secrets managers, or vault services.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'credentials',
  },
  {
    id: 'SAST-SG-HARDCODED-SECRET-JS-001',
    name: 'Hardcoded Secret in JavaScript/TypeScript',
    description: 'A constant or variable named with a secret-related keyword is assigned a string literal. Secrets committed to source repositories can be harvested by attackers.',
    severity: 'high',
    cweId: 'CWE-798',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('(?:const|let|var)\\s+(?:\\w*(?:password|secret|api_?key|token|auth|credential)\\w*)\\s*=\\s*["\'][^"\']{3,}["\']'),
    ],
    excludePatterns: [
      r('process\\.env'),
      r('=\\s*["\'](?:test|example|placeholder|changeme|xxx|TODO)["\']'),
    ],
    recommendation: 'Remove hard-coded credentials and use environment variables, secrets managers, or vault services.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'credentials',
  },
  {
    id: 'SAST-SG-HARDCODED-SECRET-JAVA-001',
    name: 'Hardcoded Password in Java String',
    description: 'A Java variable whose name contains "password", "secret", or "key" is assigned a string literal. This practice violates secure coding standards and risks credential leakage.',
    severity: 'high',
    cweId: 'CWE-798',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    languages: ['java', 'kotlin'],
    patterns: [
      r('(?:String|final\\s+String)\\s+\\w*(?:password|secret|apiKey|authToken|accessKey)\\w*\\s*=\\s*"[^"]{3,}"'),
    ],
    excludePatterns: [
      r('(?:_NAME|_KEY|_FIELD|_HEADER|_INDEX|_TYPE|_PREFIX|_SUFFIX|_SETTINGS|_MESSAGE|_PARAM|_ATTRIBUTE|_SCHEME|_ENDPOINT|_PATH|_PROPERTY|_CONSTANT)\\s*='),
      r('(?:HIDE_|MASK_|REDACT_|CONNECTOR_|NULL_OR_EMPTY)'),
    ],
    recommendation: 'Remove hard-coded credentials and use environment variables, secrets managers, or vault services.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'credentials',
  },
  {
    id: 'SAST-SG-HARDCODED-SECRET-GO-001',
    name: 'Hardcoded Credential in Go',
    description: 'A Go variable with a name indicating a secret is assigned a string literal. Secrets should be loaded from environment variables or secret management services.',
    severity: 'high',
    cweId: 'CWE-798',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    languages: ['go'],
    patterns: [
      r('(?:password|secret|apiKey|authToken|accessKey|privateKey)\\s*(?::=|=)\\s*"[^"]{3,}"'),
    ],
    excludePatterns: [
      r('os\\.Getenv'),
    ],
    recommendation: 'Remove hard-coded credentials and use environment variables, secrets managers, or vault services.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'credentials',
  },
  {
    id: 'SAST-SG-HARDCODED-SECRET-RUBY-001',
    name: 'Hardcoded Secret in Ruby',
    description: 'A Ruby variable or constant with a secret-related name is assigned a string literal. Credentials should be stored securely outside source code.',
    severity: 'high',
    cweId: 'CWE-798',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    languages: ['ruby'],
    patterns: [
      r('(?:password|secret|api_key|auth_token|access_key)\\s*=\\s*["\'][^"\']{3,}["\']'),
    ],
    excludePatterns: [
      r('ENV\\['),
      r('Rails\\.application\\.credentials'),
    ],
    recommendation: 'Remove hard-coded credentials and use environment variables, Rails credentials, or vault services.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'credentials',
  },
  {
    id: 'SAST-SG-AWS-KEY-001',
    name: 'AWS Access Key ID in Source Code',
    description: 'Detected a string matching the AWS Access Key ID pattern (AKIA...). AWS keys in source code can be exploited to gain unauthorized cloud access.',
    severity: 'critical',
    cweId: 'CWE-798',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    languages: ['all'],
    patterns: [
      r('(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}'),
    ],
    recommendation: 'Remove AWS keys from source code. Use IAM roles, instance profiles, or AWS Secrets Manager instead.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'credentials',
  },
];

// ─── CWE-79: Cross-Site Scripting (XSS) ─────────────────────────────────────

const xssRules: SastRule[] = [
  {
    id: 'SAST-SG-XSS-JS-INNERHTML-001',
    name: 'Insecure innerHTML Assignment',
    description: 'Direct assignment to innerHTML with dynamic content can lead to cross-site scripting. Attackers can inject malicious scripts that execute in victim browsers.',
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('\\.innerHTML\\s*='),
      r('\\.outerHTML\\s*='),
    ],
    excludePatterns: [
      r('\\.innerHTML\\s*=\\s*["\']\\s*["\']'),
      r('\\.innerHTML\\s*=\\s*""'),
      r('DOMPurify\\.sanitize'),
    ],
    recommendation: 'Use textContent instead of innerHTML, or sanitize input with DOMPurify before inserting into the DOM.',
    cvssScore: 6.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    category: 'xss',
  },
  {
    id: 'SAST-SG-XSS-JS-DOCUMENT-WRITE-001',
    name: 'Dangerous document.write Usage',
    description: 'document.write() and document.writeln() inject content directly into the DOM and can facilitate XSS attacks when used with untrusted data.',
    severity: 'medium',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('document\\.write\\s*\\('),
      r('document\\.writeln\\s*\\('),
    ],
    recommendation: 'Avoid document.write(). Use DOM APIs like createElement/appendChild with proper encoding.',
    cvssScore: 6.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    category: 'xss',
  },
  {
    id: 'SAST-SG-XSS-REACT-DANGEROUSLY-001',
    name: 'React dangerouslySetInnerHTML',
    description: 'dangerouslySetInnerHTML bypasses React\'s built-in XSS protection. If the HTML content comes from user input, it enables stored or reflected XSS.',
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('dangerouslySetInnerHTML'),
    ],
    recommendation: 'Avoid dangerouslySetInnerHTML. If necessary, sanitize the content with DOMPurify before rendering.',
    cvssScore: 6.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    category: 'xss',
  },
  {
    id: 'SAST-SG-XSS-PY-MARKSAFE-001',
    name: 'Django mark_safe with Dynamic Content',
    description: 'mark_safe() tells Django to skip HTML escaping. If used with user-controlled content, it enables XSS attacks.',
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['python'],
    patterns: [
      r('mark_safe\\s*\\('),
    ],
    excludePatterns: [
      r('mark_safe\\s*\\(\\s*["\'][^"\']*["\']\\s*\\)'),
    ],
    recommendation: 'Avoid mark_safe() with dynamic content. Use Django\'s template auto-escaping or the escape filter instead.',
    cvssScore: 6.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    category: 'xss',
  },
  {
    id: 'SAST-SG-XSS-PHP-ECHO-001',
    name: 'PHP Unescaped Output',
    description: 'Using echo or print with user input variables without htmlspecialchars() or htmlentities() can lead to reflected or stored XSS.',
    severity: 'medium',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['php'],
    patterns: [
      r('echo\\s+\\$_(?:GET|POST|REQUEST|COOKIE)'),
      r('print\\s+\\$_(?:GET|POST|REQUEST|COOKIE)'),
    ],
    recommendation: 'Always apply htmlspecialchars($input, ENT_QUOTES, \'UTF-8\') before echoing user input.',
    cvssScore: 6.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    category: 'xss',
  },
  {
    id: 'SAST-SG-XSS-JAVA-SERVLET-001',
    name: 'Java Servlet Response Writer XSS',
    description: 'Writing user input directly to HttpServletResponse without encoding allows reflected XSS attacks.',
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['java'],
    patterns: [
      r('getWriter\\(\\)\\.(?:print|println|write)\\s*\\(.*getParameter'),
      r('getOutputStream\\(\\)\\.(?:print|println|write)\\s*\\(.*getParameter'),
    ],
    recommendation: 'Encode output using OWASP Java Encoder or a templating engine with auto-escaping.',
    cvssScore: 6.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    category: 'xss',
  },
];

// ─── CWE-89: SQL Injection ──────────────────────────────────────────────────

const sqlInjectionRules: SastRule[] = [
  {
    id: 'SAST-SG-SQLI-PY-FORMAT-001',
    name: 'Python SQL String Formatting',
    description: 'SQL query constructed using Python string formatting (%, .format(), f-string). This pattern enables SQL injection when user input is included.',
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['python'],
    patterns: [
      r('(?:execute|executemany|raw)\\s*\\(\\s*["\']\\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*%s'),
      r('(?:execute|executemany|raw)\\s*\\(\\s*["\']\\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*\\.format\\s*\\('),
      r('(?:execute|executemany|raw)\\s*\\(\\s*f["\'].*\\{'),
      r('cursor\\.execute\\s*\\(.*\\+'),
    ],
    excludePatterns: [
      r('cursor\\.execute\\s*\\([^,]+,\\s*[\\(\\[]'),
      r('cursor\\.execute\\s*\\([^,]+,\\s*\\{'),
    ],
    recommendation: 'Use parameterized queries or prepared statements instead of string concatenation for SQL queries.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-SQLI-JS-CONCAT-001',
    name: 'JavaScript SQL String Concatenation',
    description: 'SQL query built with string concatenation or template literals. This is the primary vector for SQL injection in Node.js applications.',
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('(?:query|execute|raw)\\s*\\(\\s*[`"\']\\s*(?:SELECT|INSERT|UPDATE|DELETE).*\\$\\{'),
      r('(?:query|execute|raw)\\s*\\(\\s*["\']\\s*(?:SELECT|INSERT|UPDATE|DELETE).*\\+'),
    ],
    excludePatterns: [
      r('\\$\\d'),
      r('\\?'),
    ],
    recommendation: 'Use parameterized queries or prepared statements instead of string concatenation for SQL queries.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-SQLI-JAVA-CONCAT-001',
    name: 'Java SQL String Concatenation',
    description: 'A SQL statement is built using string concatenation in Java. This is a common SQL injection vector, especially with user-supplied input.',
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['java'],
    patterns: [
      r('(?:executeQuery|executeUpdate|execute|prepareStatement)\\s*\\(\\s*"\\s*(?:SELECT|INSERT|UPDATE|DELETE).*"\\s*\\+'),
      r('(?:createQuery|createNativeQuery)\\s*\\(\\s*"\\s*(?:SELECT|INSERT|UPDATE|DELETE).*"\\s*\\+'),
    ],
    recommendation: 'Use PreparedStatement with parameterized queries. For JPA, use named parameters (:param) or Criteria API.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-SQLI-GO-SPRINTF-001',
    name: 'Go SQL Query with fmt.Sprintf',
    description: 'SQL query constructed with fmt.Sprintf or string concatenation in Go. This can lead to SQL injection if user input is interpolated.',
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['go'],
    patterns: [
      r('(?:Query|Exec|QueryRow|QueryContext|ExecContext)\\s*\\(.*fmt\\.Sprintf\\s*\\(\\s*"\\s*(?:SELECT|INSERT|UPDATE|DELETE)'),
      r('(?:Query|Exec|QueryRow)\\s*\\(\\s*"\\s*(?:SELECT|INSERT|UPDATE|DELETE).*"\\s*\\+'),
    ],
    recommendation: 'Use parameterized queries with $1/$2 or ? placeholders. Never build SQL with fmt.Sprintf and user input.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-SQLI-RUBY-INTERP-001',
    name: 'Ruby SQL String Interpolation',
    description: 'SQL query built using Ruby string interpolation (#{...}). ActiveRecord\'s where() with interpolation is a common Rails SQL injection vector.',
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['ruby'],
    patterns: [
      r('(?:where|find_by_sql|execute|select|joins|having|order|group)\\s*\\(\\s*".*#\\{'),
      r('(?:where|find_by_sql|execute)\\s*\\(\\s*\'.*\'\\s*\\+'),
    ],
    recommendation: 'Use ActiveRecord parameterized queries: where("name = ?", input) or where(name: input).',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-SQLI-PHP-CONCAT-001',
    name: 'PHP SQL String Concatenation',
    description: 'SQL query constructed by concatenating PHP variables. Using user input directly in SQL queries enables injection attacks.',
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['php'],
    patterns: [
      r('(?:mysql_query|mysqli_query|pg_query|query)\\s*\\(.*\\$_(?:GET|POST|REQUEST|COOKIE)'),
      r('(?:mysql_query|mysqli_query|pg_query|query)\\s*\\(\\s*"\\s*(?:SELECT|INSERT|UPDATE|DELETE).*"\\s*\\.\\s*\\$'),
    ],
    recommendation: 'Use PDO prepared statements with bound parameters. Never concatenate user input into SQL.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
];

// ─── CWE-78: OS Command Injection ──────────────────────────────────────────

const commandInjectionRules: SastRule[] = [
  {
    id: 'SAST-SG-CMDI-PY-001',
    name: 'Python OS Command Injection',
    description: 'User input passed to os.system(), subprocess with shell=True, or os.popen() can allow arbitrary command execution.',
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['python'],
    patterns: [
      r('os\\.system\\s*\\('),
      r('os\\.popen\\s*\\('),
      r('subprocess\\.(?:call|run|Popen|check_output|check_call)\\s*\\(.*shell\\s*=\\s*True'),
      r('commands\\.getoutput\\s*\\('),
    ],
    excludePatterns: [
      r('os\\.system\\s*\\(\\s*["\'][^"\']*["\']\\s*\\)'),
    ],
    recommendation: 'Avoid passing user input to shell commands. Use subprocess with shell=False and a list of arguments.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-CMDI-JS-001',
    name: 'Node.js Command Injection via child_process',
    description: 'child_process.exec() passes commands through the shell, enabling command injection if user input is included.',
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('child_process\\.exec\\s*\\('),
      r('exec\\s*\\(.*\\+'),
      r('execSync\\s*\\(.*\\+'),
      r('exec\\s*\\(\\s*`'),
    ],
    excludePatterns: [
      r('child_process\\.exec\\s*\\(\\s*["\'][^"\']*["\']\\s*[,\\)]'),
    ],
    recommendation: 'Use child_process.execFile() or child_process.spawn() with an arguments array instead of exec().',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-CMDI-JAVA-001',
    name: 'Java Runtime Command Execution',
    description: 'Runtime.getRuntime().exec() with string concatenation can lead to command injection. ProcessBuilder is safer but still requires input validation.',
    severity: 'high',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['java'],
    patterns: [
      r('Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(.*\\+'),
      r('Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(.*String\\.format'),
      r('new\\s+ProcessBuilder\\s*\\(.*\\+'),
    ],
    recommendation: 'Use ProcessBuilder with a string array for arguments. Validate and sanitize all inputs.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-CMDI-GO-001',
    name: 'Go Command Injection via exec.Command',
    description: 'Using exec.Command with user-controlled arguments without validation can enable command injection.',
    severity: 'high',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['go'],
    patterns: [
      r('exec\\.Command\\s*\\(\\s*"(?:bash|sh|cmd)"\\s*,\\s*"-c"'),
      r('exec\\.Command\\s*\\(.*\\+'),
    ],
    recommendation: 'Avoid using shell interpreters (bash -c). Pass commands and arguments directly to exec.Command.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-CMDI-RUBY-001',
    name: 'Ruby Dangerous System/Exec Call',
    description: 'Ruby system(), exec(), backtick, and %x() calls pass input through the shell. User input in these calls enables command injection.',
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['ruby'],
    patterns: [
      r('system\\s*\\(.*#\\{'),
      r('system\\s*\\(.*\\+'),
      r('exec\\s*\\(.*#\\{'),
      r('^\\s*`[^`]*#\\{'),
      r('%x\\([^)]*#\\{'),
      r('IO\\.popen\\s*\\('),
      r('Open3\\.(?:capture2|capture3|pipeline)\\s*\\('),
    ],
    excludePatterns: [
      r('raise\\b|Error|Exception|ArgumentError|ExecutionError'),
      r('description:|title:|message:|label:|text:|gfm:|tooltip:'),
      r('puts\\b|warn\\b|log\\b|info\\b|debug\\b'),
    ],
    recommendation: 'Use the multi-argument form of system() or Open3: system("cmd", arg1, arg2) to avoid shell interpretation.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-CMDI-PHP-001',
    name: 'PHP Command Injection',
    description: 'PHP functions like exec(), system(), passthru(), and shell_exec() execute system commands. User input in these calls enables remote code execution.',
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['php'],
    patterns: [
      r('(?:exec|system|passthru|shell_exec|popen|proc_open)\\s*\\(.*\\$_(?:GET|POST|REQUEST|COOKIE)'),
      r('(?:exec|system|passthru|shell_exec|popen|proc_open)\\s*\\(.*\\$(?!_)\\w+'),
    ],
    excludePatterns: [
      r('escapeshellarg|escapeshellcmd'),
    ],
    recommendation: 'Use escapeshellarg() on all arguments and escapeshellcmd() on commands. Prefer safe alternatives to shell execution.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
];

// ─── CWE-327/328: Weak Cryptography ────────────────────────────────────────

const weakCryptoRules: SastRule[] = [
  {
    id: 'SAST-SG-CRYPTO-PY-MD5-001',
    name: 'Python MD5 Hash Usage',
    description: 'MD5 is cryptographically broken and unsuitable for security purposes. Collision attacks are practical and well-documented.',
    severity: 'medium',
    cweId: 'CWE-328',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['python'],
    patterns: [
      r('hashlib\\.md5\\s*\\('),
      r('hashlib\\.new\\s*\\(\\s*["\']md5["\']'),
      r('Crypto\\.Hash\\.MD5'),
      r('Cryptodome\\.Hash\\.MD5'),
    ],
    recommendation: 'Use strong hash functions (SHA-256/SHA-3) instead of weak ones (MD5, SHA-1). For passwords, use bcrypt or argon2.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'cryptography',
  },
  {
    id: 'SAST-SG-CRYPTO-PY-SHA1-001',
    name: 'Python SHA1 Hash Usage',
    description: 'SHA-1 is considered cryptographically weak. Known collision attacks exist (SHAttered). Not suitable for security-critical applications.',
    severity: 'medium',
    cweId: 'CWE-327',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['python'],
    patterns: [
      r('hashlib\\.sha1\\s*\\('),
      r('hashlib\\.new\\s*\\(\\s*["\']sha1["\']'),
    ],
    recommendation: 'Replace SHA-1 with SHA-256 or SHA-3. Use hashlib.sha256() as a drop-in replacement.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'cryptography',
  },
  {
    id: 'SAST-SG-CRYPTO-PY-DES-001',
    name: 'Python DES/Blowfish/RC4 Cipher Usage',
    description: 'DES, Blowfish, and RC4 are insecure cipher algorithms with known vulnerabilities. They provide insufficient security for modern applications.',
    severity: 'high',
    cweId: 'CWE-327',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['python'],
    patterns: [
      r('(?:Crypto|Cryptodome)\\.Cipher\\.DES\\.new'),
      r('(?:Crypto|Cryptodome)\\.Cipher\\.Blowfish\\.new'),
      r('(?:Crypto|Cryptodome)\\.Cipher\\.ARC4\\.new'),
      r('(?:Crypto|Cryptodome)\\.Cipher\\.XOR\\.new'),
    ],
    recommendation: 'Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption. Replace all legacy cipher algorithms.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'cryptography',
  },
  {
    id: 'SAST-SG-CRYPTO-JS-CREATEHASH-001',
    name: 'Node.js Weak Hash Function',
    description: 'createHash() called with MD5 or SHA-1. These algorithms have known collision attacks and should not be used for security.',
    severity: 'medium',
    cweId: 'CWE-328',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('createHash\\s*\\(\\s*["\'](?:md5|sha1|md4)["\']'),
    ],
    recommendation: 'Use createHash(\'sha256\') or createHash(\'sha512\') instead of weak hash algorithms.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'cryptography',
  },
  {
    id: 'SAST-SG-CRYPTO-JS-PSEUDORANDOM-001',
    name: 'Node.js Insecure Random Number Generator',
    description: 'crypto.pseudoRandomBytes() is not cryptographically secure. Math.random() is also insecure for security-sensitive operations.',
    severity: 'medium',
    cweId: 'CWE-338',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('crypto\\.pseudoRandomBytes'),
      r('Math\\.random\\s*\\(\\)'),
    ],
    excludePatterns: [
      r('(?:test|spec|mock|stub)'),
      r('(?:color|opacity|delay|animation|jitter|shuffle|sample|example|placeholder|display|position|layout|offset|size|width|height|angle|rotation)'),
    ],
    recommendation: 'Use crypto.randomBytes() or crypto.getRandomValues() for cryptographically secure random numbers.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'cryptography',
  },
  {
    id: 'SAST-SG-CRYPTO-JAVA-WEAK-001',
    name: 'Java Weak Cryptographic Algorithm',
    description: 'Usage of DES, DESede (3DES), RC4, or MD5/SHA-1 for message digests. These algorithms have known cryptographic weaknesses.',
    severity: 'high',
    cweId: 'CWE-327',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['java'],
    patterns: [
      r('Cipher\\.getInstance\\s*\\(\\s*"(?:DES|DESede|RC4|RC2|Blowfish)"'),
      r('MessageDigest\\.getInstance\\s*\\(\\s*"(?:MD5|SHA-1|SHA1|MD2|MD4)"'),
    ],
    recommendation: 'Use AES/GCM/NoPadding for encryption and SHA-256/SHA-512 for digests.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'cryptography',
  },
  {
    id: 'SAST-SG-CRYPTO-RUBY-MD5-001',
    name: 'Ruby Weak Hash Algorithm',
    description: 'Digest::MD5 and Digest::SHA1 are weak hash algorithms. MD5 is broken and SHA-1 has practical collision attacks.',
    severity: 'medium',
    cweId: 'CWE-328',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['ruby'],
    patterns: [
      r('Digest::MD5'),
      r('Digest::SHA1'),
      r('OpenSSL::Digest::MD5'),
      r('OpenSSL::Digest::SHA1'),
    ],
    excludePatterns: [
      r('(?:etag|cache_key|fingerprint|hexdigest.*uuid|content_hash)'),
    ],
    recommendation: 'Use Digest::SHA256 or Digest::SHA512 instead of MD5 or SHA1.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'cryptography',
  },
  {
    id: 'SAST-SG-CRYPTO-PHP-WEAK-001',
    name: 'PHP Weak Cryptographic Function',
    description: 'PHP functions md5(), sha1(), crypt(), and str_rot13() provide inadequate cryptographic strength for security purposes.',
    severity: 'medium',
    cweId: 'CWE-328',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['php'],
    patterns: [
      r('\\bmd5\\s*\\('),
      r('\\bsha1\\s*\\('),
      r('\\bmd5_file\\s*\\('),
      r('\\bsha1_file\\s*\\('),
      r('\\bstr_rot13\\s*\\('),
      r('\\bcrypt\\s*\\('),
    ],
    excludePatterns: [
      r('password_hash'),
      r('password_verify'),
    ],
    recommendation: 'Use password_hash()/password_verify() for passwords. Use hash(\'sha256\', $data) for general hashing.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'cryptography',
  },
  {
    id: 'SAST-SG-CRYPTO-GO-WEAK-001',
    name: 'Go Weak Hash/Cipher Usage',
    description: 'Usage of crypto/md5, crypto/sha1, crypto/des, or crypto/rc4. These algorithms have known weaknesses.',
    severity: 'medium',
    cweId: 'CWE-327',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['go'],
    patterns: [
      r('"crypto/md5"'),
      r('"crypto/sha1"'),
      r('"crypto/des"'),
      r('"crypto/rc4"'),
      r('md5\\.New\\(\\)'),
      r('sha1\\.New\\(\\)'),
      r('des\\.NewCipher'),
    ],
    recommendation: 'Use crypto/sha256 or crypto/sha512 for hashing. Use crypto/aes with GCM mode for encryption.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'cryptography',
  },
];

// ─── CWE-502: Insecure Deserialization ──────────────────────────────────────

const deserializationRules: SastRule[] = [
  {
    id: 'SAST-SG-DESER-PY-PICKLE-001',
    name: 'Python Pickle Deserialization',
    description: 'pickle.loads() and pickle.load() can execute arbitrary code during deserialization. This is a well-known RCE vector in Python.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['python'],
    patterns: [
      r('pickle\\.loads?\\s*\\('),
      r('cPickle\\.loads?\\s*\\('),
      r('shelve\\.open\\s*\\('),
      r('yaml\\.load\\s*\\('),
      r('yaml\\.unsafe_load\\s*\\('),
    ],
    excludePatterns: [
      r('yaml\\.safe_load'),
      r('yaml\\.SafeLoader'),
    ],
    recommendation: 'Avoid pickle for untrusted data. Use JSON or yaml.safe_load(). For complex objects, use marshmallow or pydantic.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },
  {
    id: 'SAST-SG-DESER-JS-001',
    name: 'Node.js Insecure Deserialization',
    description: 'node-serialize and js-yaml without safe mode can lead to arbitrary code execution through crafted serialized data.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('serialize\\.unserialize\\s*\\('),
      r('node-serialize'),
      r('js-yaml.*\\.load\\s*\\('),
    ],
    excludePatterns: [
      r('safeLoad'),
      r('JSON_SCHEMA'),
      r('SAFE_SCHEMA'),
    ],
    recommendation: 'Avoid deserializing untrusted data. Use JSON.parse() for data exchange. For YAML, use yaml.safeLoad().',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },
  {
    id: 'SAST-SG-DESER-JAVA-001',
    name: 'Java Unsafe Deserialization',
    description: 'ObjectInputStream.readObject() deserializes arbitrary Java objects, enabling remote code execution through gadget chains.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['java'],
    patterns: [
      r('ObjectInputStream.*readObject\\s*\\('),
      r('readUnshared\\s*\\('),
      r('XMLDecoder'),
      r('XStream.*fromXML'),
      r('enableDefaultTyping'),
      r('ObjectMapper.*enableDefaultTyping'),
    ],
    recommendation: 'Avoid Java serialization for untrusted input. Use JSON with strict type checking. Add serialization filters with ObjectInputFilter.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },
  {
    id: 'SAST-SG-DESER-RUBY-001',
    name: 'Ruby Unsafe Deserialization',
    description: 'Marshal.load(), YAML.load(), and Oj.load() can execute arbitrary code when processing untrusted input.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['ruby'],
    patterns: [
      r('Marshal\\.load\\s*\\('),
      r('Marshal\\.restore\\s*\\('),
      r('YAML\\.load\\s*\\('),
      r('Oj\\.load\\s*\\('),
    ],
    excludePatterns: [
      r('YAML\\.safe_load'),
      r('Psych\\.safe_load'),
    ],
    recommendation: 'Use YAML.safe_load() instead of YAML.load(). Use JSON for data exchange. Avoid Marshal with untrusted data.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },
  {
    id: 'SAST-SG-DESER-PHP-001',
    name: 'PHP Unserialize Usage',
    description: 'unserialize() can trigger arbitrary object instantiation and magic method execution, leading to remote code execution.',
    severity: 'high',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['php'],
    patterns: [
      r('\\bunserialize\\s*\\('),
    ],
    excludePatterns: [
      r('unserialize\\s*\\(\\s*["\'][^"\']+["\']'),
    ],
    recommendation: 'Use json_decode() instead of unserialize(). If unserialize is required, pass allowed_classes as the second argument.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },
];

// ─── CWE-918: Server-Side Request Forgery (SSRF) ───────────────────────────

const ssrfRules: SastRule[] = [
  {
    id: 'SAST-SG-SSRF-PY-001',
    name: 'Python SSRF via requests/urllib',
    description: 'Server-side HTTP requests with user-controlled URLs can be exploited to scan internal networks, access metadata services, or exfiltrate data.',
    severity: 'high',
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 - Server-Side Request Forgery',
    languages: ['python'],
    patterns: [
      r('requests\\.(?:get|post|put|delete|head|patch)\\s*\\(.*\\+'),
      r('requests\\.(?:get|post|put|delete|head|patch)\\s*\\(\\s*f["\']'),
      r('urllib\\.request\\.urlopen\\s*\\('),
      r('urlopen\\s*\\(.*\\+'),
    ],
    recommendation: 'Validate and whitelist URLs before making server-side requests. Block internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x).',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'ssrf',
  },
  {
    id: 'SAST-SG-SSRF-JS-001',
    name: 'Node.js SSRF via fetch/axios',
    description: 'Server-side fetch/axios/http requests with user-controlled URLs enable SSRF attacks against internal services and cloud metadata endpoints.',
    severity: 'high',
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 - Server-Side Request Forgery',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('(?:fetch|axios\\.get|axios\\.post|axios|got|request|superagent)\\s*\\(.*req\\.(?:query|params|body)'),
      r('(?:fetch|axios\\.get|axios\\.post|axios)\\s*\\(.*\\+'),
      r('(?:fetch|axios)\\s*\\(\\s*`.*\\$\\{'),
    ],
    recommendation: 'Validate and whitelist destination URLs. Use a URL parser to reject private/internal IP ranges before making requests.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'ssrf',
  },
  {
    id: 'SAST-SG-SSRF-JAVA-001',
    name: 'Java SSRF via URL/HttpClient',
    description: 'Java URL, HttpURLConnection, or HttpClient requests with user-controlled URLs can reach internal services or cloud metadata APIs.',
    severity: 'high',
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 - Server-Side Request Forgery',
    languages: ['java'],
    patterns: [
      r('new\\s+URL\\s*\\(.*getParameter'),
      r('HttpClients?\\.new.*getParameter'),
      r('RestTemplate.*getParameter'),
      r('WebClient.*getParameter'),
    ],
    recommendation: 'Validate URLs against a whitelist. Use a URL parser to block requests to private IP ranges and metadata endpoints.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'ssrf',
  },
];

// ─── CWE-22: Path Traversal ────────────────────────────────────────────────

const pathTraversalRules: SastRule[] = [
  {
    id: 'SAST-SG-PATH-PY-001',
    name: 'Python Path Traversal',
    description: 'File operations using user-controlled paths without sanitization enable directory traversal attacks to read or write arbitrary files.',
    severity: 'high',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['python'],
    patterns: [
      r('open\\s*\\(.*\\+'),
      r('open\\s*\\(\\s*f["\']'),
      r('os\\.path\\.join\\s*\\(.*request'),
      r('send_file\\s*\\(.*request'),
      r('shutil\\.copy\\s*\\(.*request'),
    ],
    excludePatterns: [
      r('os\\.path\\.abspath'),
      r('os\\.path\\.realpath'),
      r('pathlib\\.Path.*resolve'),
    ],
    recommendation: 'Validate and sanitize file paths. Use os.path.realpath() and verify the canonical path stays within the intended directory.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'path-traversal',
  },
  {
    id: 'SAST-SG-PATH-JS-001',
    name: 'Node.js Path Traversal',
    description: 'File system operations with user-controlled paths enable traversal attacks (../../etc/passwd) to access files outside the intended directory.',
    severity: 'high',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('fs\\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|access|stat)\\s*\\(.*req\\.(?:query|params|body)'),
      r('fs\\.(?:readFile|readFileSync|writeFile|writeFileSync)\\s*\\(.*\\+'),
      r('path\\.join\\s*\\(.*req\\.(?:query|params|body)'),
      r('res\\.sendFile\\s*\\(.*req\\.'),
    ],
    excludePatterns: [
      r('path\\.resolve.*\\.startsWith'),
    ],
    recommendation: 'Resolve the full path with path.resolve() and verify it starts with the allowed base directory before any file operation.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'path-traversal',
  },
  {
    id: 'SAST-SG-PATH-JAVA-001',
    name: 'Java Path Traversal in Servlet',
    description: 'Using HttpServletRequest parameters to construct file paths enables directory traversal attacks against the server file system.',
    severity: 'high',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['java'],
    patterns: [
      r('new\\s+File\\s*\\(.*getParameter'),
      r('Paths\\.get\\s*\\(.*getParameter'),
      r('new\\s+FileInputStream\\s*\\(.*getParameter'),
      r('Files\\.(?:read|write|copy|move|delete).*getParameter'),
    ],
    recommendation: 'Canonicalize file paths and validate they remain under the intended base directory. Use an allow-list for filenames.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'path-traversal',
  },
  {
    id: 'SAST-SG-PATH-PHP-001',
    name: 'PHP Path Traversal via User Input',
    description: 'PHP file functions using superglobal variables ($_GET, $_POST) as paths allow attackers to read or modify arbitrary server files.',
    severity: 'high',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['php'],
    patterns: [
      r('(?:file_get_contents|fopen|include|require|readfile|file)\\s*\\(.*\\$_(?:GET|POST|REQUEST)'),
      r('(?:include|require)(?:_once)?\\s*\\(.*\\$'),
      r('(?:unlink|rmdir|rename|copy|move_uploaded_file)\\s*\\(.*\\$_(?:GET|POST|REQUEST)'),
    ],
    recommendation: 'Use basename() to strip directory components. Validate against an allow-list and use realpath() to resolve paths.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'path-traversal',
  },
];

// ─── CWE-94: Code Injection ────────────────────────────────────────────────

const codeInjectionRules: SastRule[] = [
  {
    id: 'SAST-SG-CODEINJ-PY-EVAL-001',
    name: 'Python eval/exec with Dynamic Input',
    description: 'eval() and exec() execute arbitrary Python code. User-controlled input in these functions enables remote code execution.',
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['python'],
    patterns: [
      r('\\beval\\s*\\('),
      r('\\bexec\\s*\\('),
      r('\\bcompile\\s*\\(.*["\']exec["\']'),
    ],
    excludePatterns: [
      r('eval\\s*\\(\\s*["\'][^"\']*["\']\\s*\\)'),
      r('ast\\.literal_eval'),
    ],
    recommendation: 'Never use eval()/exec() with user input. Use ast.literal_eval() for safe literal parsing or a sandboxed environment.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-CODEINJ-JS-EVAL-001',
    name: 'JavaScript eval/Function Constructor',
    description: 'eval() and new Function() interpret strings as code. User input in these constructs enables cross-site scripting and server-side code injection.',
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    patterns: [
      r('\\beval\\s*\\('),
      r('new\\s+Function\\s*\\('),
      r('setTimeout\\s*\\(\\s*["\']'),
      r('setInterval\\s*\\(\\s*["\']'),
    ],
    excludePatterns: [
      r('eval\\s*\\(\\s*["\'][^"\']*["\']\\s*\\)'),
    ],
    recommendation: 'Never use eval() or new Function() with dynamic input. Use JSON.parse() for data and safe template engines for rendering.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-CODEINJ-RUBY-EVAL-001',
    name: 'Ruby eval/class_eval/instance_eval',
    description: 'Ruby eval methods execute arbitrary code strings. When combined with user input, they enable remote code execution.',
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['ruby'],
    patterns: [
      r('\\beval\\s*\\('),
      r('\\bclass_eval\\s*\\('),
      r('\\bmodule_eval\\s*\\('),
      r('\\binstance_eval\\s*\\('),
      r('\\bsend\\s*\\(.*params'),
      r('\\bconstantize\\b'),
    ],
    excludePatterns: [
      r('eval\\s*\\(\\s*["\'][^"\']*["\']\\s*\\)'),
      r('redis\\.eval\\b|Redis.*eval'),
      r('rescue\\s+NameError'),
    ],
    recommendation: 'Avoid eval-family methods with user input. Use whitelists for allowed operations. Replace send() with explicit method calls.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
  {
    id: 'SAST-SG-CODEINJ-PHP-EVAL-001',
    name: 'PHP Code Injection via eval/preg_replace',
    description: 'eval(), assert(), and preg_replace with /e modifier execute arbitrary PHP code. User input in these functions enables RCE.',
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['php'],
    patterns: [
      r('\\beval\\s*\\('),
      r('\\bassert\\s*\\(.*\\$'),
      r('preg_replace\\s*\\(.*["\']/[^/]*e'),
      r('create_function\\s*\\('),
    ],
    recommendation: 'Never use eval() or assert() with user input. Use preg_replace_callback() instead of preg_replace with /e.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
];

// ─── CWE-611: XML External Entity (XXE) ────────────────────────────────────

const xxeRules: SastRule[] = [
  {
    id: 'SAST-SG-XXE-PY-001',
    name: 'Python XML Parser Without Defused Library',
    description: 'Standard Python XML parsers (xml.etree, xml.dom, xml.sax) process external entities by default, enabling XXE attacks that can read files or perform SSRF.',
    severity: 'high',
    cweId: 'CWE-611',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['python'],
    patterns: [
      r('xml\\.etree\\.ElementTree\\.parse\\s*\\('),
      r('xml\\.etree\\.ElementTree\\.fromstring\\s*\\('),
      r('xml\\.dom\\.minidom\\.parse\\s*\\('),
      r('xml\\.dom\\.minidom\\.parseString\\s*\\('),
      r('xml\\.sax\\.parse\\s*\\('),
      r('lxml\\.etree\\.parse\\s*\\('),
      r('lxml\\.etree\\.fromstring\\s*\\('),
    ],
    excludePatterns: [
      r('defusedxml'),
      r('resolve_entities\\s*=\\s*False'),
    ],
    recommendation: 'Use defusedxml library (defusedxml.ElementTree) which disables external entity processing by default.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'xxe',
  },
  {
    id: 'SAST-SG-XXE-JAVA-001',
    name: 'Java XML Parser with External Entities Enabled',
    description: 'Java XML parsers (DocumentBuilder, SAXParser, XMLInputFactory) process external entities by default unless explicitly disabled, enabling XXE attacks.',
    severity: 'high',
    cweId: 'CWE-611',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['java'],
    patterns: [
      r('DocumentBuilderFactory\\.newInstance\\s*\\('),
      r('SAXParserFactory\\.newInstance\\s*\\('),
      r('XMLInputFactory\\.newInstance\\s*\\('),
      r('XMLInputFactory\\.newFactory\\s*\\('),
      r('TransformerFactory\\.newInstance\\s*\\('),
      r('SchemaFactory\\.newInstance\\s*\\('),
    ],
    excludePatterns: [
      r('setFeature\\s*\\(.*DISALLOW_DOCTYPE'),
      r('setFeature\\s*\\(.*external-general-entities.*false'),
      r('setProperty\\s*\\(.*ACCESS_EXTERNAL_DTD.*""'),
    ],
    recommendation: 'Disable external entity processing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'xxe',
  },
  {
    id: 'SAST-SG-XXE-PHP-001',
    name: 'PHP XML Parser with Entity Loading',
    description: 'PHP simplexml_load_string(), DOMDocument, and XMLReader process external entities when LIBXML_NOENT is not set or entity loading is enabled.',
    severity: 'high',
    cweId: 'CWE-611',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['php'],
    patterns: [
      r('simplexml_load_string\\s*\\('),
      r('simplexml_load_file\\s*\\('),
      r('new\\s+DOMDocument'),
      r('DOMDocument.*loadXML'),
      r('LIBXML_NOENT'),
      r('libxml_disable_entity_loader\\s*\\(\\s*false'),
    ],
    excludePatterns: [
      r('libxml_disable_entity_loader\\s*\\(\\s*true'),
    ],
    recommendation: 'Call libxml_disable_entity_loader(true) before parsing XML. Use LIBXML_NONET to prevent network access during parsing.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'xxe',
  },
  {
    id: 'SAST-SG-XXE-GO-001',
    name: 'Go XML Decoder Without Entity Restrictions',
    description: 'Go encoding/xml does not support external entities natively, but improper use of third-party XML libraries can still introduce XXE vulnerabilities.',
    severity: 'medium',
    cweId: 'CWE-611',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['go'],
    patterns: [
      r('xml\\.NewDecoder\\s*\\('),
      r('xml\\.Unmarshal\\s*\\('),
      r('libxml2'),
    ],
    recommendation: 'Use the standard encoding/xml package which does not support external entities. Avoid third-party XML libraries that do.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'xxe',
  },
];

// ─── Additional high-value rules ────────────────────────────────────────────

const additionalRules: SastRule[] = [
  // JWT None algorithm
  {
    id: 'SAST-SG-JWT-NONE-001',
    name: 'JWT None Algorithm Accepted',
    description: 'JWT libraries configured to accept the "none" algorithm allow attackers to forge tokens without a signature, bypassing authentication entirely.',
    severity: 'critical',
    cweId: 'CWE-327',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript', 'python', 'java', 'ruby', 'go'],
    patterns: [
      r('algorithms?\\s*[=:]\\s*\\[?\\s*["\']none["\']'),
      r('algorithm\\s*[=:]\\s*["\']none["\']'),
    ],
    excludePatterns: [
      r('(?:test|spec|mock|fixture)'),
      r('(?:ssl|tls|cert).*verify'),
    ],
    recommendation: 'Never accept the "none" algorithm. Explicitly specify allowed algorithms: algorithms: ["RS256"] or algorithms: ["HS256"].',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'cryptography',
  },
  // Insecure TLS/SSL
  {
    id: 'SAST-SG-TLS-VERIFY-DISABLED-001',
    name: 'TLS Certificate Verification Disabled',
    description: 'Disabling SSL/TLS certificate verification allows man-in-the-middle attacks. Attackers can intercept and modify all traffic.',
    severity: 'high',
    cweId: 'CWE-295',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['python', 'javascript', 'typescript', 'ruby', 'go'],
    patterns: [
      r('verify\\s*=\\s*False'),
      r('VERIFY_NONE'),
      r('rejectUnauthorized\\s*:\\s*false'),
      r('NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*["\']0["\']'),
      r('InsecureSkipVerify\\s*:\\s*true'),
      r('ssl_verify_mode.*VERIFY_NONE'),
    ],
    recommendation: 'Always verify TLS certificates in production. Use proper CA bundles and pin certificates for sensitive connections.',
    cvssScore: 7.4,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'cryptography',
  },
  // Insecure cookie
  {
    id: 'SAST-SG-COOKIE-SECURE-001',
    name: 'Cookie Without Secure Flag',
    description: 'Cookies transmitted without the Secure flag can be intercepted over unencrypted HTTP connections, exposing session tokens.',
    severity: 'medium',
    cweId: 'CWE-614',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript', 'python', 'java', 'ruby', 'php'],
    patterns: [
      r('(?:set-cookie|Set-Cookie|setCookie|set_cookie).*(?:secure\\s*[=:]\\s*false|httponly\\s*[=:]\\s*false)'),
      r('setSecure\\s*\\(\\s*false\\s*\\)'),
      r('cookie.*secure.*false'),
    ],
    recommendation: 'Set cookies with Secure, HttpOnly, and SameSite flags. Use HTTPS for all cookie transmission.',
    cvssScore: 4.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
    category: 'sensitive-cookies',
  },
  // Open redirect
  {
    id: 'SAST-SG-OPENREDIRECT-001',
    name: 'Open Redirect via User Input',
    description: 'Redirecting to a user-supplied URL without validation enables phishing attacks. Attackers can redirect victims to malicious look-alike sites.',
    severity: 'medium',
    cweId: 'CWE-601',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript', 'python', 'java', 'ruby', 'php'],
    patterns: [
      r('res\\.redirect\\s*\\(.*req\\.(?:query|params|body)'),
      r('redirect_to\\s*\\(.*params'),
      r('HttpResponseRedirect\\s*\\(.*request'),
      r('sendRedirect\\s*\\(.*getParameter'),
      r('header\\s*\\(\\s*["\']Location:.*\\$_(?:GET|POST|REQUEST)'),
    ],
    recommendation: 'Validate redirect URLs against a whitelist of allowed domains. Use relative paths for internal redirects.',
    cvssScore: 6.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    category: 'open-redirect',
  },
  // CORS misconfiguration
  {
    id: 'SAST-SG-CORS-WILDCARD-001',
    name: 'Permissive CORS Configuration',
    description: 'Access-Control-Allow-Origin set to "*" with credentials allowed enables cross-origin data theft. Reflecting the Origin header is equally dangerous.',
    severity: 'medium',
    cweId: 'CWE-346',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript', 'python', 'java', 'ruby', 'php'],
    patterns: [
      r('Access-Control-Allow-Origin.*\\*'),
      r('origin\\s*:\\s*true'),
      r('allowedOrigins?\\s*[=:].*\\*'),
    ],
    recommendation: 'Restrict CORS to specific trusted origins. Never use wildcard (*) with credentials. Validate the Origin header server-side.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'access-control',
  },
  // SSTI
  {
    id: 'SAST-SG-SSTI-001',
    name: 'Server-Side Template Injection',
    description: 'User input embedded directly in template rendering enables server-side template injection, potentially leading to remote code execution.',
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['python', 'java', 'javascript', 'typescript', 'ruby'],
    patterns: [
      r('render_template_string\\s*\\('),
      r('Template\\s*\\(.*request'),
      r('Jinja2.*from_string'),
      r('Environment.*from_string'),
      r('ERB\\.new\\s*\\(.*params'),
    ],
    recommendation: 'Never pass user input directly to template engines. Use pre-compiled templates with parameterized data.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'injection',
  },
];

// ─── Combined export ────────────────────────────────────────────────────────

/**
 * Pre-curated bundle of high-quality security rules derived from the Semgrep
 * community rules repository, converted to the deep-vigilance SastRule format.
 *
 * Contains 55+ rules covering 10 top CWE categories across 6 languages.
 */
export const SEMGREP_RULES_BUNDLE: SastRule[] = [
  ...hardcodedCredentialRules,
  ...xssRules,
  ...sqlInjectionRules,
  ...commandInjectionRules,
  ...weakCryptoRules,
  ...deserializationRules,
  ...ssrfRules,
  ...pathTraversalRules,
  ...codeInjectionRules,
  ...xxeRules,
  ...additionalRules,
];

/**
 * Get rules from the bundle filtered by CWE ID.
 */
export function getSemgrepBundleRulesByCwe(cweId: string): SastRule[] {
  return SEMGREP_RULES_BUNDLE.filter(rule => rule.cweId === cweId);
}

/**
 * Get rules from the bundle filtered by language.
 */
export function getSemgrepBundleRulesByLanguage(language: string): SastRule[] {
  return SEMGREP_RULES_BUNDLE.filter(
    rule => rule.languages.includes(language) || rule.languages.includes('all'),
  );
}

/**
 * Get rules from the bundle filtered by severity.
 */
export function getSemgrepBundleRulesBySeverity(severity: SastRule['severity']): SastRule[] {
  return SEMGREP_RULES_BUNDLE.filter(rule => rule.severity === severity);
}

/**
 * Get a summary of the bundle contents.
 */
export function getSemgrepBundleSummary(): {
  totalRules: number;
  bySeverity: Record<string, number>;
  byCwe: Record<string, number>;
  byCategory: Record<string, number>;
  byLanguage: Record<string, number>;
} {
  const bySeverity: Record<string, number> = {};
  const byCwe: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  const byLanguage: Record<string, number> = {};

  for (const rule of SEMGREP_RULES_BUNDLE) {
    bySeverity[rule.severity] = (bySeverity[rule.severity] || 0) + 1;
    if (rule.cweId) byCwe[rule.cweId] = (byCwe[rule.cweId] || 0) + 1;
    byCategory[rule.category] = (byCategory[rule.category] || 0) + 1;
    for (const lang of rule.languages) {
      byLanguage[lang] = (byLanguage[lang] || 0) + 1;
    }
  }

  return {
    totalRules: SEMGREP_RULES_BUNDLE.length,
    bySeverity,
    byCwe,
    byCategory,
    byLanguage,
  };
}
