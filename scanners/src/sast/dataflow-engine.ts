// ============================================================
// Dataflow / Taint-Tracking Engine (M5c)
// Real BFS graph traversal, AST node analysis, scoring math
// ============================================================

import { logger } from '../utils/logger.js';
import type { IRNode, CallGraphNode } from './ast-engine.js';

// ---------------------------------------------------------------------------
// #region -- Types & Interfaces
// ---------------------------------------------------------------------------

export type TaintCategory =
  | 'HTTP'
  | 'FRAMEWORK'
  | 'FILE'
  | 'DATABASE'
  | 'ENVIRONMENT';

export type SinkCategory =
  | 'SQL'
  | 'COMMAND'
  | 'FILE'
  | 'HTTP_SSRF'
  | 'TEMPLATE'
  | 'CODE'
  | 'LDAP'
  | 'XPATH'
  | 'NOSQL';

export type SanitizerCategory =
  | 'PREPARED_STATEMENT'
  | 'ORM_SAFE'
  | 'INPUT_VALIDATION'
  | 'HTML_ENCODING'
  | 'TYPE_COERCION'
  | 'PATH_SANITIZER'
  | 'AUTH_CHECK';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SourceLocation {
  line: number;
  column: number;
  filePath: string;
}

export interface TaintSource {
  /** Machine-readable category e.g. "HTTP", "FRAMEWORK" */
  type: TaintCategory;
  /** The AST node where taint originates */
  node: IRNode;
  location: SourceLocation;
  /** Human-readable description */
  description: string;
}

export interface Sink {
  type: SinkCategory;
  node: IRNode;
  location: SourceLocation;
  description: string;
  severity: Severity;
}

export interface Sanitizer {
  type: SanitizerCategory;
  node: IRNode;
  location: SourceLocation;
  description: string;
}

export interface TaintPathNode {
  functionName: string;
  lineNumber: number;
  columnNumber: number;
  description: string;
}

export interface TaintPath {
  id: string;
  source: TaintSource;
  sink: Sink;
  pathNodes: TaintPathNode[];
  sanitizers: Sanitizer[];
  /** Count of AST nodes traversed */
  pathLength: number;
  /** 0 (blocked) -> 1 (fully reachable) */
  reachabilityScore: number;
  /** True if a sanitizer severs this path */
  isBlocked: boolean;
}

export interface TaintReport {
  summary: {
    totalPaths: number;
    reachablePaths: number;
    blockedPaths: number;
    totalSources: number;
    totalSinks: number;
    totalSanitizers: number;
  };
  severityDistribution: Record<SinkCategory, { critical: number; high: number; medium: number; low: number }>;
  topFlows: TaintPath[];
  recommendations: string[];
}

// ---------------------------------------------------------------------------
// #endregion
// #region -- Pattern Maps (untrusted entry points)
// ---------------------------------------------------------------------------

/**
 * Every entry is a tuple of [pattern, category, description].
 * Patterns are tested against the concatenation of callee chains
 * (e.g. "req.body.foo" is matched as "req.body").
 */
const TAINT_SOURCE_PATTERNS: Array<{
  pattern: RegExp;
  category: TaintCategory;
  description: string;
}> = [
  // ---- HTTP (Express / Node.js / Koa / Fastify / Hapi) ----
  { pattern: /\breq\.body\b/,      category: 'HTTP', description: 'Request body input (untrusted)' },
  { pattern: /\breq\.query\b/,     category: 'HTTP', description: 'URL query parameter input (untrusted)' },
  { pattern: /\breq\.params\b/,    category: 'HTTP', description: 'URL path parameter input (untrusted)' },
  { pattern: /\breq\.headers\b/,   category: 'HTTP', description: 'HTTP request header input (untrusted)' },
  { pattern: /\breq\.cookies\b/,   category: 'HTTP', description: 'Cookie input (untrusted)' },
  { pattern: /\bctx\.request\.body\b/, category: 'HTTP', description: 'Koa/Fastify request body (untrusted)' },
  { pattern: /\bctx\.query\b/,     category: 'HTTP', description: 'Koa/Fastify query string (untrusted)' },
  { pattern: /\brequest\.body\b/,  category: 'HTTP', description: 'HTTP request body (untrusted)' },

  // ---- PHP superglobals ----
  { pattern: /\$_GET\b/,      category: 'HTTP',     description: 'PHP $_GET superglobal' },
  { pattern: /\$_POST\b/,     category: 'HTTP',     description: 'PHP $_POST superglobal' },
  { pattern: /\$_REQUEST\b/,  category: 'HTTP',     description: 'PHP $_REQUEST superglobal' },
  { pattern: /\$_COOKIE\b/,   category: 'HTTP',     description: 'PHP $_COOKIE superglobal' },
  { pattern: /\$_SERVER\b/,   category: 'HTTP',     description: 'PHP $_SERVER superglobal' },
  { pattern: /\$_FILES\b/,    category: 'HTTP',     description: 'PHP $_FILES superglobal' },
  { pattern: /\$_ENV\b/,      category: 'ENVIRONMENT', description: 'PHP $_ENV superglobal' },

  // ---- Framework annotations (Java Spring / C# / Kotlin) ----
  { pattern: /@RequestBody\b/,   category: 'FRAMEWORK', description: 'Spring @RequestBody annotation' },
  { pattern: /@RequestParam\b/,  category: 'FRAMEWORK', description: 'Spring @RequestParam annotation' },
  { pattern: /@PathVariable\b/,  category: 'FRAMEWORK', description: 'Spring @PathVariable annotation' },
  { pattern: /@RequestHeader\b/, category: 'FRAMEWORK', description: 'Spring @RequestHeader annotation' },
  { pattern: /@CookieValue\b/,   category: 'FRAMEWORK', description: 'Spring @CookieValue annotation' },
  { pattern: /@ModelAttribute\b/,category: 'FRAMEWORK', description: 'Spring @ModelAttribute annotation' },
  { pattern: /@QueryParam\b/,    category: 'FRAMEWORK', description: 'JAX-RS @QueryParam annotation' },
  { pattern: /@PathParam\b/,     category: 'FRAMEWORK', description: 'JAX-RS @PathParam annotation' },
  { pattern: /@FormParam\b/,     category: 'FRAMEWORK', description: 'JAX-RS @FormParam annotation' },
  { pattern: /@FromBody\b/,      category: 'FRAMEWORK', description: 'ASP.NET [FromBody] attribute' },
  { pattern: /@FromQuery\b/,     category: 'FRAMEWORK', description: 'ASP.NET [FromQuery] attribute' },
  { pattern: /@FromRoute\b/,     category: 'FRAMEWORK', description: 'ASP.NET [FromRoute] attribute' },
  { pattern: /@FromHeader\b/,    category: 'FRAMEWORK', description: 'ASP.NET [FromHeader] attribute' },

  // ---- Python web frameworks ----
  { pattern: /\brequest\.args\b/,       category: 'FRAMEWORK', description: 'Flask request.args (untrusted)' },
  { pattern: /\brequest\.form\b/,       category: 'FRAMEWORK', description: 'Flask request.form (untrusted)' },
  { pattern: /\brequest\.json\b/,       category: 'FRAMEWORK', description: 'Flask request.json (untrusted)' },
  { pattern: /\brequest\.data\b/,       category: 'FRAMEWORK', description: 'Flask request.data (untrusted)' },
  { pattern: /\brequest\.cookies\b/,    category: 'FRAMEWORK', description: 'Flask request.cookies (untrusted)' },
  { pattern: /\brequest\.files\b/,      category: 'FRAMEWORK', description: 'Flask request.files (untrusted)' },
  { pattern: /\brequest\.headers\b/,    category: 'FRAMEWORK', description: 'Flask request.headers (untrusted)' },

  // ---- Go Gin / Echo / Fiber ----
  { pattern: /\bc\.Query\b/,   category: 'FRAMEWORK', description: 'Gin c.Query() (untrusted)' },
  { pattern: /\bc\.Param\b/,   category: 'FRAMEWORK', description: 'Gin c.Param() (untrusted)' },
  { pattern: /\bc\.PostForm\b/,category: 'FRAMEWORK', description: 'Gin c.PostForm() (untrusted)' },
  { pattern: /\bc\.Bind\b/,    category: 'FRAMEWORK', description: 'Gin c.Bind() (untrusted)' },
  { pattern: /\bc\.FormValue\b/,category: 'FRAMEWORK', description: 'Echo/Fiber FormValue (untrusted)' },
  { pattern: /\bc\.QueryParam\b/,category: 'FRAMEWORK', description: 'Echo/Fiber QueryParam (untrusted)' },

  // ---- File-read entry points ----
  { pattern: /\bfs\.readFile\b/,             category: 'FILE', description: 'Node fs.readFile() (may read untrusted paths)' },
  { pattern: /\bfs\.readFileSync\b/,         category: 'FILE', description: 'Node fs.readFileSync() (may read untrusted paths)' },
  { pattern: /\bfile_get_contents\b/,        category: 'FILE', description: 'PHP file_get_contents() (may read untrusted paths)' },
  { pattern: /\bFile\.ReadAllText\b/,        category: 'FILE', description: '.NET File.ReadAllText() (may read untrusted paths)' },
  { pattern: /\bfopen\b/,                    category: 'FILE', description: 'C/PHP fopen() (may read untrusted paths)' },
  { pattern: /\bopen\s*\(/,                  category: 'FILE', description: 'Python open() (may read untrusted paths)' },
  { pattern: /\bPath\.ReadFile\b/,           category: 'FILE', description: 'Rust std::fs::read_to_string' },

  // ---- Database-result secondary taint ----
  { pattern: /\bdb\.query\b/,            category: 'DATABASE', description: 'Database query result (secondary taint)' },
  { pattern: /\bconnection\.query\b/,    category: 'DATABASE', description: 'SQL query result (secondary taint)' },
  { pattern: /\bpool\.query\b/,          category: 'DATABASE', description: 'Pool query result (secondary taint)' },
  { pattern: /\bexecuteQuery\b/,         category: 'DATABASE', description: 'JDBC executeQuery result (secondary taint)' },
  { pattern: /\brovider\.ExecuteReader\b/,category: 'DATABASE', description: 'ADO.NET reader (secondary taint)' },
  { pattern: /\brawQuery\b/,             category: 'DATABASE', description: 'Doctrine raw query result' },
  { pattern: /\bcursor\.fetch\b/,        category: 'DATABASE', description: 'Database cursor fetch (secondary taint)' },
  { pattern: /\bfindAll\b/,              category: 'DATABASE', description: 'ORM findAll result (secondary taint)' },
  { pattern: /\bfindOne\b/,              category: 'DATABASE', description: 'ORM findOne result (secondary taint)' },
  { pattern: /\bfindMany\b/,             category: 'DATABASE', description: 'ORM findMany result (secondary taint)' },

  // ---- Environment ----
  { pattern: /\bprocess\.env\b/,   category: 'ENVIRONMENT', description: 'Node process.env (may contain secrets from env)' },
  { pattern: /\bos\.Getenv\b/,     category: 'ENVIRONMENT', description: 'Go os.Getenv()' },
  { pattern: /\bSystem\.getenv\b/, category: 'ENVIRONMENT', description: 'Java System.getenv()' },
  { pattern: /\benv\.\w+\b/,       category: 'ENVIRONMENT', description: 'Environment variable access' },
];

// ---------------------------------------------------------------------------
// #endregion
// #region -- Sink Pattern Maps
// ---------------------------------------------------------------------------

const SINK_PATTERNS: Array<{
  pattern: RegExp;
  category: SinkCategory;
  description: string;
  severity: Severity;
}> = [
  // ---- SQL Injection sinks ----
  { pattern: /\bdb\.execute\b/,                   category: 'SQL', severity: 'critical', description: 'SQL execute() call' },
  { pattern: /\bconnection\.query\b/,              category: 'SQL', severity: 'critical', description: 'SQL query() call' },
  { pattern: /\bpool\.query\b/,                    category: 'SQL', severity: 'critical', description: 'Pool query() call' },
  { pattern: /\bEntityManager\.createNativeQuery\b/, category: 'SQL', severity: 'critical', description: 'JPA native query' },
  { pattern: /\b\.raw\b/,                          category: 'SQL', severity: 'critical', description: 'Raw SQL query' },
  { pattern: /\b\.queryRaw\b/,                     category: 'SQL', severity: 'critical', description: 'Prisma raw query' },
  { pattern: /\b\.\$queryRaw\b/,                   category: 'SQL', severity: 'critical', description: 'Prisma $queryRaw' },
  { pattern: /\bsequelize\.query\b/,               category: 'SQL', severity: 'critical', description: 'Sequelize raw query' },
  { pattern: /\bjdbcTemplate\.query\b/,            category: 'SQL', severity: 'critical', description: 'Spring JDBC template query' },
  { pattern: /\b\.query\b/,                        category: 'SQL', severity: 'high',   description: 'Database query call' },
  { pattern: /\bcursor\.execute\b/,                category: 'SQL', severity: 'critical', description: 'Python db cursor execute' },
  { pattern: /\bmysqli_query\b/,                   category: 'SQL', severity: 'critical', description: 'PHP mysqli_query' },
  { pattern: /\bpg_query\b/,                       category: 'SQL', severity: 'critical', description: 'PHP pg_query' },
  { pattern: /\bsqlalchemy\.text\b/,               category: 'SQL', severity: 'high',   description: 'SQLAlchemy text()' },
  { pattern: /\bdb\.exec\b/,                       category: 'SQL', severity: 'critical', description: 'Go db.Exec' },
  { pattern: /\bdatabase\.Execute\b/,              category: 'SQL', severity: 'critical', description: 'Go database/sql Execute' },

  // ---- Command Injection sinks ----
  { pattern: /\bchild_process\.exec\b/,  category: 'COMMAND', severity: 'critical', description: 'Node child_process.exec()' },
  { pattern: /\bchild_process\.execSync\b/, category: 'COMMAND', severity: 'critical', description: 'Node child_process.execSync()' },
  { pattern: /\bexec\b/,                   category: 'COMMAND', severity: 'critical', description: 'Shell exec() call' },
  { pattern: /\bspawn\b/,                  category: 'COMMAND', severity: 'high',   description: 'Process spawn' },
  { pattern: /\bexecSync\b/,               category: 'COMMAND', severity: 'critical', description: 'Synchronous exec' },
  { pattern: /\bos\.system\b/,             category: 'COMMAND', severity: 'critical', description: 'Python os.system()' },
  { pattern: /\bRuntime\.exec\b/,          category: 'COMMAND', severity: 'critical', description: 'Java Runtime.exec()' },
  { pattern: /\bProcess\.Start\b/,         category: 'COMMAND', severity: 'critical', description: '.NET Process.Start()' },
  { pattern: /\bsubprocess\.run\b/,        category: 'COMMAND', severity: 'high',   description: 'Python subprocess.run()' },
  { pattern: /\bsubprocess\.Popen\b/,      category: 'COMMAND', severity: 'high',   description: 'Python subprocess.Popen' },
  { pattern: /\bshell_exec\b/,             category: 'COMMAND', severity: 'critical', description: 'PHP shell_exec()' },
  { pattern: /\bpopen\b/,                  category: 'COMMAND', severity: 'high',   description: 'PHP popen()' },
  { pattern: /\bexec.Command\b/,           category: 'COMMAND', severity: 'high',   description: 'Go exec.Command()' },
  { pattern: /\bos\.execvp\b/,             category: 'COMMAND', severity: 'critical', description: 'Go syscall exec' },

  // ---- File write sinks ----
  { pattern: /\bfs\.writeFile\b/,           category: 'FILE', severity: 'high', description: 'Node fs.writeFile()' },
  { pattern: /\bfs\.writeFileSync\b/,       category: 'FILE', severity: 'high', description: 'Node fs.writeFileSync()' },
  { pattern: /\bfs\.appendFile\b/,          category: 'FILE', severity: 'high', description: 'Node fs.appendFile()' },
  { pattern: /\bFile\.WriteAllText\b/,      category: 'FILE', severity: 'high', description: '.NET File.WriteAllText()' },
  { pattern: /\bopen\s*\([^)]*['"][rwxa]/, category: 'FILE', severity: 'high', description: 'open() with write mode' },
  { pattern: /\bfwrite\b/,                  category: 'FILE', severity: 'high', description: 'PHP fwrite()' },
  { pattern: /\bfputs\b/,                   category: 'FILE', severity: 'high', description: 'PHP fputs()' },
  { pattern: /\bfile_put_contents\b/,       category: 'FILE', severity: 'high', description: 'PHP file_put_contents()' },
  { pattern: /\bioutil\.WriteFile\b/,       category: 'FILE', severity: 'high', description: 'Go ioutil.WriteFile' },
  { pattern: /\bos\.WriteFile\b/,           category: 'FILE', severity: 'high', description: 'Go os.WriteFile' },

  // ---- SSRF sinks ----
  { pattern: /\bfetch\b/,                   category: 'HTTP_SSRF', severity: 'high',   description: 'fetch() URL request' },
  { pattern: /\baxios\.get\b/,              category: 'HTTP_SSRF', severity: 'high',   description: 'Axios GET request' },
  { pattern: /\baxios\.post\b/,             category: 'HTTP_SSRF', severity: 'high',   description: 'Axios POST request' },
  { pattern: /\baxios\.put\b/,              category: 'HTTP_SSRF', severity: 'high',   description: 'Axios PUT request' },
  { pattern: /\baxios\.delete\b/,           category: 'HTTP_SSRF', severity: 'high',   description: 'Axios DELETE request' },
  { pattern: /\brequests\.get\b/,           category: 'HTTP_SSRF', severity: 'high',   description: 'Python requests.get()' },
  { pattern: /\brequests\.post\b/,          category: 'HTTP_SSRF', severity: 'high',   description: 'Python requests.post()' },
  { pattern: /\brequests\.put\b/,           category: 'HTTP_SSRF', severity: 'high',   description: 'Python requests.put()' },
  { pattern: /\bhttp\.Get\b/,               category: 'HTTP_SSRF', severity: 'high',   description: 'Go http.Get()' },
  { pattern: /\bhttp\.Post\b/,              category: 'HTTP_SSRF', severity: 'high',   description: 'Go http.Post()' },
  { pattern: /\bhttp\.Client\b/,            category: 'HTTP_SSRF', severity: 'high',   description: 'Go http.Client request' },
  { pattern: /\bHttpClient\b/,              category: 'HTTP_SSRF', severity: 'high',   description: '.NET HttpClient request' },
  { pattern: /\bUrlConnection\b/,           category: 'HTTP_SSRF', severity: 'high',   description: 'Java URLConnection' },
  { pattern: /\bopen-uri\b/,                category: 'HTTP_SSRF', severity: 'high',   description: 'Ruby open-uri' },
  { pattern: /\bnet\.http\b/,               category: 'HTTP_SSRF', severity: 'high',   description: 'Ruby Net::HTTP' },
  { pattern: /\bcurl_exec\b/,               category: 'HTTP_SSRF', severity: 'high',   description: 'PHP curl_exec()' },

  // ---- Template injection sinks ----
  { pattern: /\brender\b/,                      category: 'TEMPLATE', severity: 'medium', description: 'Template render() call' },
  { pattern: /\bejs\.render\b/,                 category: 'TEMPLATE', severity: 'high', description: 'EJS template render' },
  { pattern: /\bejs\.renderFile\b/,             category: 'TEMPLATE', severity: 'high', description: 'EJS renderFile' },
  { pattern: /\bJinja2\.from_string\b/,         category: 'TEMPLATE', severity: 'high', description: 'Jinja2 from_string (SSTI risk)' },
  { pattern: /\bTemplate\(\)\.render\b/,        category: 'TEMPLATE', severity: 'high', description: 'Go html/template render' },
  { pattern: /\bthymeleaf\.render\b/,           category: 'TEMPLATE', severity: 'medium', description: 'Thymeleaf render' },
  { pattern: /\bMustache\.render\b/,            category: 'TEMPLATE', severity: 'medium', description: 'Mustache render' },
  { pattern: /\bHandlebars\.compile\b/,         category: 'TEMPLATE', severity: 'high', description: 'Handlebars compile' },
  { pattern: /\bpug\.render\b/,                 category: 'TEMPLATE', severity: 'medium', description: 'Pug render' },
  { pattern: /\bnunjucks\.renderString\b/,      category: 'TEMPLATE', severity: 'high', description: 'Nunjucks renderString' },
  { pattern: /\b\.render\(/,                    category: 'TEMPLATE', severity: 'medium', description: 'Template rendering' },

  // ---- Code evaluation sinks ----
  { pattern: /\beval\b/,              category: 'CODE', severity: 'critical', description: 'Code eval()' },
  { pattern: /\bFunction\b/,          category: 'CODE', severity: 'critical', description: 'Function constructor' },
  { pattern: /\bexec\b/,              category: 'CODE', severity: 'critical', description: 'Dynamic code execution' },
  { pattern: /\bcompile\b/,           category: 'CODE', severity: 'high',   description: 'Code compile()' },
  { pattern: /\bsetTimeout\b/,        category: 'CODE', severity: 'high',   description: 'setTimeout with dynamic string' },
  { pattern: /\bsetInterval\b/,       category: 'CODE', severity: 'high',   description: 'setInterval with dynamic string' },

  // ---- LDAP injection ----
  { pattern: /\bldap\.search\b/,     category: 'LDAP', severity: 'high', description: 'LDAP search query' },
  { pattern: /\bLdapConnection\b/,   category: 'LDAP', severity: 'high', description: 'LDAP connection query' },

  // ---- XPath injection ----
  { pattern: /\bxpath\.evaluate\b/,  category: 'XPATH', severity: 'high', description: 'XPath evaluate' },

  // ---- NoSQL injection ----
  { pattern: /\bmongodb\.find\b/,     category: 'NOSQL', severity: 'high', description: 'MongoDB find()' },
  { pattern: /\bmongodb\.aggregate\b/,category: 'NOSQL', severity: 'high', description: 'MongoDB aggregate()' },
  { pattern: /\bcollection\.find\b/,  category: 'NOSQL', severity: 'high', description: 'Mongo collection find' },
];

// ---------------------------------------------------------------------------
// #endregion
// #region -- Sanitizer Pattern Maps
// ---------------------------------------------------------------------------

const SANITIZER_PATTERNS: Array<{
  pattern: RegExp;
  category: SanitizerCategory;
  description: string;
}> = [
  // ---- Prepared statements (parameterized queries break taint) ----
  { pattern: /\bPreparedStatement\b/,                       category: 'PREPARED_STATEMENT', description: 'Java PreparedStatement' },
  { pattern: /\bbind_param\b/,                              category: 'PREPARED_STATEMENT', description: 'PHP prepared statement bind_param' },
  { pattern: /\bplaceholder\b/,                             category: 'PREPARED_STATEMENT', description: 'SQL placeholder usage' },
  { pattern: /\$1/,                                         category: 'PREPARED_STATEMENT', description: 'PostgreSQL positional parameter' },
  { pattern: /\?:/,                                         category: 'PREPARED_STATEMENT', description: 'SQLite positional parameter' },
  { pattern: /\bparametrize\b/,                             category: 'PREPARED_STATEMENT', description: 'Parameterized query helper' },
  { pattern: /\bparameterize\b/,                            category: 'PREPARED_STATEMENT', description: 'Parameterized query helper' },
  { pattern: /\bquery\s*\(\s*['"`]\w+\s*,\s*\w+\s*\)/,     category: 'PREPARED_STATEMENT', description: 'Parameterized query call' },

  // ---- ORM safe methods ----
  { pattern: /\bModel\.find\s*\(\s*\{/,        category: 'ORM_SAFE', description: 'ORM Model.find with object param (safe)' },
  { pattern: /\bModel\.findById\b/,             category: 'ORM_SAFE', description: 'Mongoose findById (safe)' },
  { pattern: /\bModel\.findOne\s*\(\s*\{/,     category: 'ORM_SAFE', description: 'ORM findOne with object (safe)' },
  { pattern: /\bModel\.findByPk\b/,             category: 'ORM_SAFE', description: 'Sequelize findByPk (safe)' },
  { pattern: /\bModel\.findAll\s*\(\s*\{/,     category: 'ORM_SAFE', description: 'ORM findAll with object (safe)' },
  { pattern: /\bmodel\.objects\.get\b/,         category: 'ORM_SAFE', description: 'Django ORM get (safe)' },
  { pattern: /\bmodel\.objects\.filter\b/,      category: 'ORM_SAFE', description: 'Django ORM filter (safe)' },
  { pattern: /\bdatabase\.table\b/,             category: 'ORM_SAFE', description: 'Laravel Eloquent (safe)' },
  { pattern: /\bsqlalchemy\.select\b/,          category: 'ORM_SAFE', description: 'SQLAlchemy select (safe)' },

  // ---- Input validation ----
  { pattern: /\bexpress.validator\b/,        category: 'INPUT_VALIDATION', description: 'express-validator middleware' },
  { pattern: /\bbody\(\)\.isString\b/,       category: 'INPUT_VALIDATION', description: 'express-validator chain' },
  { pattern: /\bsanitizeBody\b/,             category: 'INPUT_VALIDATION', description: 'express-validator sanitizeBody' },
  { pattern: /\bcheck\b/,                    category: 'INPUT_VALIDATION', description: 'express-validator check()' },
  { pattern: /\bvalidationResult\b/,          category: 'INPUT_VALIDATION', description: 'express-validator validationResult' },
  { pattern: /\bJoi\.object\b/,              category: 'INPUT_VALIDATION', description: 'Joi schema validation' },
  { pattern: /\bJoi\.string\b/,              category: 'INPUT_VALIDATION', description: 'Joi string validation' },
  { pattern: /\bjoi\.validate\b/,            category: 'INPUT_VALIDATION', description: 'Joi validation call' },
  { pattern: /\bclass.validator\b/,           category: 'INPUT_VALIDATION', description: 'class-validator decorators' },
  { pattern: /\b@IsString\b/,                category: 'INPUT_VALIDATION', description: 'class-validator @IsString' },
  { pattern: /\b@IsInt\b/,                   category: 'INPUT_VALIDATION', description: 'class-validator @IsInt' },
  { pattern: /\b@IsEmail\b/,                 category: 'INPUT_VALIDATION', description: 'class-validator @IsEmail' },
  { pattern: /\b@IsUUID\b/,                  category: 'INPUT_VALIDATION', description: 'class-validator @IsUUID' },
  { pattern: /\b@Matches\b/,                 category: 'INPUT_VALIDATION', description: 'class-validator @Matches' },
  { pattern: /\b@Min\b/,                     category: 'INPUT_VALIDATION', description: 'class-validator @Min' },
  { pattern: /\b@Max\b/,                     category: 'INPUT_VALIDATION', description: 'class-validator @Max' },
  { pattern: /\b@Length\b/,                  category: 'INPUT_VALIDATION', description: 'class-validator @Length' },
  { pattern: /\b@NotBlank\b/,                category: 'INPUT_VALIDATION', description: 'class-validator @NotBlank' },
  { pattern: /\bpydantic\.BaseModel\b/,     category: 'INPUT_VALIDATION', description: 'Pydantic model validation' },
  { pattern: /\bField\(.*validators\b/,      category: 'INPUT_VALIDATION', description: 'Pydantic Field validators' },
  { pattern: /\bvalidator\.validate\b/,       category: 'INPUT_VALIDATION', description: 'Validator validation call' },
  { pattern: /\bvalidate\b/,                  category: 'INPUT_VALIDATION', description: 'General validation call' },
  { pattern: /\bschema\.parse\b/,             category: 'INPUT_VALIDATION', description: 'Zod schema parse' },
  { pattern: /\bschema\.safeParse\b/,         category: 'INPUT_VALIDATION', description: 'Zod schema safeParse' },
  { pattern: /\bz\.object\b/,                category: 'INPUT_VALIDATION', description: 'Zod schema object' },
  { pattern: /\byup\.object\b/,              category: 'INPUT_VALIDATION', description: 'Yup schema object' },
  { pattern: /\byup\.string\b/,              category: 'INPUT_VALIDATION', description: 'Yup string validation' },

  // ---- HTML encoding / sanitization ----
  { pattern: /\bsanitize-html\b/,        category: 'HTML_ENCODING', description: 'sanitize-html library' },
  { pattern: /\bDOMPurify\b/,            category: 'HTML_ENCODING', description: 'DOMPurify sanitization' },
  { pattern: /\bhtmlspecialchars\b/,     category: 'HTML_ENCODING', description: 'PHP htmlspecialchars()' },
  { pattern: /\bhtmlentities\b/,         category: 'HTML_ENCODING', description: 'PHP htmlentities()' },
  { pattern: /\bescapeHtml\b/,           category: 'HTML_ENCODING', description: 'Escape HTML function' },
  { pattern: /\bescape\(/,               category: 'HTML_ENCODING', description: 'General escape function' },
  { pattern: /\b_.escape\b/,             category: 'HTML_ENCODING', description: 'lodash _.escape()' },
  { pattern: /\bmark\.safe\b/,           category: 'HTML_ENCODING', description: 'Python markupsafe' },
  { pattern: /\bMarkup\.escape\b/,       category: 'HTML_ENCODING', description: 'Jinja2 Markup.escape' },
  { pattern: /\bhtml\.escape\b/,         category: 'HTML_ENCODING', description: 'Python html.escape' },
  { pattern: /\bxss\b/,                  category: 'HTML_ENCODING', description: 'XSS protection library' },
  { pattern: /\bencodeURIComponent\b/,   category: 'HTML_ENCODING', description: 'URL encoding' },
  { pattern: /\bhtmlEncode\b/,           category: 'HTML_ENCODING', description: '.NET HtmlEncode' },

  // ---- Type coercion ----
  { pattern: /\bparseInt\b/,              category: 'TYPE_COERCION', description: 'parseInt() type coercion' },
  { pattern: /\bparseFloat\b/,            category: 'TYPE_COERCION', description: 'parseFloat() type coercion' },
  { pattern: /\bNumber\b/,                category: 'TYPE_COERCION', description: 'Number() type coercion' },
  { pattern: /\bNumber\.parseInt\b/,      category: 'TYPE_COERCION', description: 'Number.parseInt()' },
  { pattern: /\bInteger\.parseInt\b/,     category: 'TYPE_COERCION', description: 'Java Integer.parseInt()' },
  { pattern: /\bInteger\.valueOf\b/,      category: 'TYPE_COERCION', description: 'Java Integer.valueOf()' },
  { pattern: /\bint\b/,                   category: 'TYPE_COERCION', description: 'int cast' },
  { pattern: /\bfloat\b/,                 category: 'TYPE_COERCION', description: 'float cast' },
  { pattern: /\bstr\b/,                   category: 'TYPE_COERCION', description: 'str cast' },
  { pattern: /\bString\.valueOf\b/,       category: 'TYPE_COERCION', description: 'Java String.valueOf()' },
  { pattern: /\bToString\b/,              category: 'TYPE_COERCION', description: '.NET ToString()' },
  { pattern: /\bConvert\.ToInt32\b/,      category: 'TYPE_COERCION', description: '.NET Convert.ToInt32' },
  { pattern: /\bas\s+\w+/,                category: 'TYPE_COERCION', description: 'TypeScript type assertion' },
  { pattern: /\(\s*\w+\s*\)\s*\(/,        category: 'TYPE_COERCION', description: 'C-style cast' },

  // ---- Path sanitization ----
  { pattern: /\bpath\.normalize\b/,       category: 'PATH_SANITIZER', description: 'Path normalization' },
  { pattern: /\bpath\.resolve\b/,         category: 'PATH_SANITIZER', description: 'Path resolution' },
  { pattern: /\bbasename\b/,              category: 'PATH_SANITIZER', description: 'Path basename stripping' },
  { pattern: /\bsanitizePath\b/,          category: 'PATH_SANITIZER', description: 'Path sanitizer utility' },

  // ---- Auth checks ----
  { pattern: /\bisAuthenticated\b/,       category: 'AUTH_CHECK', description: 'Auth guard check' },
  { pattern: /\bensureAuthenticated\b/,   category: 'AUTH_CHECK', description: 'Auth guard check' },
  { pattern: /\b@Authenticated\b/,        category: 'AUTH_CHECK', description: 'Python Flask auth decorator' },
  { pattern: /\b@PreAuthorize\b/,         category: 'AUTH_CHECK', description: 'Spring @PreAuthorize' },
  { pattern: /\b@Secured\b/,              category: 'AUTH_CHECK', description: 'Spring @Secured' },
  { pattern: /\bAuthorize\b/,             category: 'AUTH_CHECK', description: '.NET [Authorize]' },
  { pattern: /\bcheckAuth\b/,             category: 'AUTH_CHECK', description: 'Custom auth check' },
  { pattern: /\brequireAuth\b/,           category: 'AUTH_CHECK', description: 'Auth requirement middleware' },
];

// ---------------------------------------------------------------------------
// #endregion
// #region -- AST Walking Helpers
// ---------------------------------------------------------------------------

/**
 * Walk an IRNode tree recursively, calling `visit` on every node.
 * Returns collected results from visit callbacks that return non-null.
 */
function walkAST<T>(nodes: IRNode[], visit: (node: IRNode, depth: number) => T | null): T[] {
  const results: T[] = [];

  function dfs(node: IRNode, depth: number): void {
    const result = visit(node, depth);
    if (result !== null) {
      results.push(result);
    }
    for (const child of node.children) {
      dfs(child, depth + 1);
    }
  }

  for (const node of nodes) {
    dfs(node, 0);
  }

  return results;
}

/**
 * Extract a "call chain" string from an IRNode, joining by ".".
 * e.g. a CallExpr with name "req.body.toString" -> "req.body.toString"
 */
function getCallChain(node: IRNode): string {
  if (!node.name) return '';
  // If metadata has receiver + method, reconstruct the chain
  const receiver = (node.metadata?.receiver ?? '') as string;
  const method = (node.metadata?.method ?? '') as string;
  if (receiver && method) {
    return `${receiver}.${method}`;
  }
  return node.name;
}

/**
 * Build a unique string key for a location for dedup.
 */
function locationKey(loc: SourceLocation): string {
  return `${loc.filePath}:${loc.line}:${loc.column}`;
}

// ---------------------------------------------------------------------------
// #endregion
// #region -- 1. Identify Taint Sources
// ---------------------------------------------------------------------------

/**
 * Walk the AST to find all taint entry points.
 *
 * Examines every IRNode's call chain and annotation metadata against a
 * comprehensive set of patterns covering HTTP, framework, file, database,
 * and environment sources.
 */
export function identifyTaintSources(
  ast: IRNode[],
  filePath: string = '',
): TaintSource[] {
  const seen = new Set<string>();
  const sources: TaintSource[] = [];

  for (const node of ast) {
    const chain = getCallChain(node);

    for (const sp of TAINT_SOURCE_PATTERNS) {
      if (sp.pattern.test(chain)) {
        const loc: SourceLocation = {
          line: node.lineNumber,
          column: node.columnNumber,
          filePath,
        };
        const key = locationKey(loc) + sp.category;
        if (seen.has(key)) continue;
        seen.add(key);

        sources.push({
          type: sp.category,
          node,
          location: loc,
          description: sp.description,
        });
        break; // first match wins
      }
    }

    // Also check annotation metadata for framework sources
    if (node.type === 'VariableDecl' && node.metadata?.annotation) {
      const annoMatch = (node.name ?? '').match(/@(\w+)/);
      if (annoMatch) {
        const anno = `@${annoMatch[1]!}`;
        for (const sp of TAINT_SOURCE_PATTERNS) {
          if (sp.pattern.test(anno)) {
            const loc: SourceLocation = {
              line: node.lineNumber,
              column: node.columnNumber,
              filePath,
            };
            const key = locationKey(loc) + sp.category;
            if (seen.has(key)) continue;
            seen.add(key);

            sources.push({
              type: sp.category,
              node,
              location: loc,
              description: sp.description,
            });
            break;
          }
        }
      }
    }
  }

  logger.debug({ sourceCount: sources.length }, 'Taint sources identified');
  return sources;
}

// ---------------------------------------------------------------------------
// #endregion
// #region -- 2. Identify Sinks
// ---------------------------------------------------------------------------

/**
 * Walk the AST to find all dangerous sinks.
 *
 * Matches call expressions and function names against patterns for SQL,
 * command execution, file writes, SSRF, template injection, code eval,
 * LDAP, XPath, and NoSQL injection.
 */
export function identifySinks(
  ast: IRNode[],
  filePath: string = '',
): Sink[] {
  const seen = new Set<string>();
  const sinks: Sink[] = [];

  for (const node of ast) {
    const chain = getCallChain(node);

    for (const sp of SINK_PATTERNS) {
      if (sp.pattern.test(chain) || sp.pattern.test(node.name ?? '')) {
        const loc: SourceLocation = {
          line: node.lineNumber,
          column: node.columnNumber,
          filePath,
        };
        const key = locationKey(loc) + sp.category;
        if (seen.has(key)) continue;
        seen.add(key);

        sinks.push({
          type: sp.category,
          node,
          location: loc,
          description: sp.description,
          severity: sp.severity,
        });
        break;
      }
    }
  }

  logger.debug({ sinkCount: sinks.length }, 'Sinks identified');
  return sinks;
}

// ---------------------------------------------------------------------------
// #endregion
// #region -- 3. Identify Sanitizers
// ---------------------------------------------------------------------------

/**
 * Walk the AST to find validation / sanitization constructs.
 *
 * Covers prepared statements, ORM safe methods, input validation libraries
 * (Joi, Zod, Yup, pydantic, class-validator, express-validator), HTML
 * encoding (DOMPurify, sanitize-html, htmlspecialchars), type coercion
 * (parseInt, Number()), path sanitizers, and auth guards.
 */
export function identifySanitizers(
  ast: IRNode[],
  filePath: string = '',
): Sanitizer[] {
  const seen = new Set<string>();
  const sanitizers: Sanitizer[] = [];

  for (const node of ast) {
    const chain = getCallChain(node);

    for (const sp of SANITIZER_PATTERNS) {
      if (sp.pattern.test(chain) || sp.pattern.test(node.name ?? '')) {
        const loc: SourceLocation = {
          line: node.lineNumber,
          column: node.columnNumber,
          filePath,
        };
        const key = locationKey(loc) + sp.category;
        if (seen.has(key)) continue;
        seen.add(key);

        sanitizers.push({
          type: sp.category,
          node,
          location: loc,
          description: sp.description,
        });
        break;
      }
    }

    // Check decorator / annotation metadata
    if (node.type === 'VariableDecl' && node.metadata?.decorator) {
      const decoStr = node.name ?? '';
      for (const sp of SANITIZER_PATTERNS) {
        if (sp.pattern.test(decoStr)) {
          const loc: SourceLocation = {
            line: node.lineNumber,
            column: node.columnNumber,
            filePath,
          };
          const key = locationKey(loc) + sp.category;
          if (seen.has(key)) continue;
          seen.add(key);

          sanitizers.push({
            type: sp.category,
            node,
            location: loc,
            description: sp.description,
          });
          break;
        }
      }
    }
  }

  // Check for import/require statements that import known sanitizers
  for (const node of ast) {
    if (node.type !== 'Import') continue;
    const importStr = node.name ?? '';
    const sanitizerLibs = [
      'sanitize-html', 'dompurify', 'validator', 'joi', 'yup',
      'zod', 'express-validator', 'class-validator', 'pydantic',
      'markupsafe', 'xss',
    ];
    for (const lib of sanitizerLibs) {
      if (importStr.includes(lib)) {
        const loc: SourceLocation = {
          line: node.lineNumber,
          column: node.columnNumber,
          filePath,
        };
        const key = locationKey(loc) + lib;
        if (seen.has(key)) continue;
        seen.add(key);

        sanitizers.push({
          type: 'INPUT_VALIDATION',
          node,
          location: loc,
          description: `Import of sanitization library: ${lib}`,
        });
        break;
      }
    }
  }

  logger.debug({ sanitizerCount: sanitizers.length }, 'Sanitizers identified');
  return sanitizers;
}

// ---------------------------------------------------------------------------
// #endregion
// #region -- 4. Trace Taint (BFS through call graph)
// ---------------------------------------------------------------------------

/**
 * Perform BFS from each taint source through the call graph, checking
 * whether any sink is reachable without passing through a sanitizer.
 *
 * For each source -> sink path found:
 *  - Records every function / call-site along the path with line numbers
 *  - Computes a reachability score between 0 and 1
 *  - Identifies any sanitizers that block or reduce the path
 *
 * Returns an array of TaintPath objects. The caller should deduplicate
 * by source/sink pair if needed.
 */
export function traceTaint(
  sources: TaintSource[],
  sinks: Sink[],
  sanitizers: Sanitizer[],
  callGraph: Map<string, CallGraphNode>,
): TaintPath[] {
  const paths: TaintPath[] = [];
  let pathId = 0;

  // ---- Build a lookup: source node line -> list of sanitizers before it ----
  const sanitizersByApproxLine = buildSanitizerLineIndex(sanitizers);

  // ---- Build adjacency from call graph for BFS ----
  const adjacency = buildCallGraphAdjacency(callGraph);

  // ---- For each source, run BFS to every reachable sink ----
  for (const source of sources) {
    const sourceFuncName = findEnclosingFunctionName(source.node, callGraph);

    for (const sink of sinks) {
      pathId++;

      const sinkFuncName = findEnclosingFunctionName(sink.node, callGraph);

      // BFS from source's function to sink's function
      const bfsResult = bfsShortestPath(
        sourceFuncName,
        sinkFuncName,
        adjacency,
        callGraph,
        source,
        sink,
        sanitizersByApproxLine,
        sanitizers,
      );

      // If BFS found a path (or we can still reason about it), build record
      const pathNodes = bfsResult?.pathNodes ?? buildLinearPathNodes(source, sink, sourceFuncName, sinkFuncName);
      const encounteredSanitizers = bfsResult?.encounteredSanitizers ?? findSanitizersBetween(
        source, sink, sanitizers,
      );

      const rawScore = computeReachabilityScore(
        { source, sink, pathNodes, sanitizers: encounteredSanitizers, pathLength: pathNodes.length, reachabilityScore: 0, isBlocked: false, id: '' },
        encounteredSanitizers,
      );

      const isBlocked = encounteredSanitizers.some(s =>
        s.type === 'PREPARED_STATEMENT' ||
        s.type === 'INPUT_VALIDATION'
      );

      paths.push({
        id: `TP-${String(pathId).padStart(4, '0')}`,
        source,
        sink,
        pathNodes,
        sanitizers: encounteredSanitizers,
        pathLength: pathNodes.length,
        reachabilityScore: rawScore,
        isBlocked,
      });
    }
  }

  // Sort by reachability score descending (most dangerous first)
  paths.sort((a, b) => b.reachabilityScore - a.reachabilityScore);

  logger.debug({ totalPaths: paths.length }, 'Taint tracing complete');
  return paths;
}

// ---------------------------------------------------------------------------
// #region -- BFS Internals
// ---------------------------------------------------------------------------

/**
 * Build a simple adjacency list from the call graph.
 * Maps functionName -> list of callee function names.
 */
function buildCallGraphAdjacency(
  callGraph: Map<string, CallGraphNode>,
): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const [, node] of callGraph) {
    adj.set(node.functionName, [...node.callees]);
  }
  return adj;
}

/**
 * Index sanitizers by approximate line number for fast lookup.
 */
function buildSanitizerLineIndex(
  sanitizers: Sanitizer[],
): Map<number, Sanitizer[]> {
  const idx = new Map<number, Sanitizer[]>();
  for (const s of sanitizers) {
    const line = s.node.lineNumber;
    if (!idx.has(line)) idx.set(line, []);
    idx.get(line)!.push(s);
  }
  return idx;
}

interface BfsResult {
  pathNodes: TaintPathNode[];
  encounteredSanitizers: Sanitizer[];
}

/**
 * BFS shortest path from `startFunc` to `targetFunc` through the call graph.
 * Returns the shortest call chain and any sanitizers encountered along the
 * function bodies on that chain.
 *
 * Falls back to a direct linear path if start/target can't be resolved in
 * the call graph.
 */
function bfsShortestPath(
  startFunc: string | null,
  targetFunc: string | null,
  adjacency: Map<string, string[]>,
  callGraph: Map<string, CallGraphNode>,
  source: TaintSource,
  sink: Sink,
  sanitizersByLine: Map<number, Sanitizer[]>,
  allSanitizers: Sanitizer[],
): BfsResult | null {
  // If either function can't be resolved, return null so the caller can
  // fall back to linear path estimation.
  if (!startFunc || !targetFunc) return null;
  if (startFunc === targetFunc) {
    // Same function: source and sink in the same function body.
    const pathNodes: TaintPathNode[] = [];
    const functionNode = callGraph.get(startFunc);
    if (functionNode) {
      pathNodes.push({
        functionName: startFunc,
        lineNumber: functionNode.lineNumber,
        columnNumber: 0,
        description: `Function entry: ${startFunc}`,
      });
    }

    const encounteredSanitizers = findSanitizersBetween(source, sink, allSanitizers);

    pathNodes.push({
      functionName: startFunc,
      lineNumber: sink.node.lineNumber,
      columnNumber: sink.node.columnNumber,
      description: `${sink.type} sink: ${sink.description}`,
    });

    return { pathNodes, encounteredSanitizers };
  }

  // Standard BFS
  const visited = new Set<string>();
  const queue: Array<{ func: string; path: string[] }> = [];
  const predecessors = new Map<string, string | null>();

  queue.push({ func: startFunc, path: [startFunc] });
  visited.add(startFunc);
  predecessors.set(startFunc, null);

  while (queue.length > 0) {
    const { func, path } = queue.shift()!;

    if (func === targetFunc) {
      // Reconstructed path found -- build TaintPathNode array
      const pathNodes = buildPathNodesFromFuncList(path, callGraph, source, sink);
      const encounteredSanitizers = findSanitizersBetween(source, sink, allSanitizers);
      return { pathNodes, encounteredSanitizers };
    }

    const callees = adjacency.get(func) ?? [];
    for (const callee of callees) {
      if (!visited.has(callee)) {
        visited.add(callee);
        const newPath = [...path, callee];
        queue.push({ func: callee, path: newPath });
        predecessors.set(callee, func);
      }
    }
  }

  // No path found in call graph -- return null to allow linear fallback
  return null;
}

/**
 * Build TaintPathNode array from a list of function names representing
 * the BFS-discovered call chain.
 */
function buildPathNodesFromFuncList(
  funcList: string[],
  callGraph: Map<string, CallGraphNode>,
  source: TaintSource,
  sink: Sink,
): TaintPathNode[] {
  const nodes: TaintPathNode[] = [];

  // Source node
  nodes.push({
    functionName: funcList[0] ?? 'unknown',
    lineNumber: source.node.lineNumber,
    columnNumber: source.node.columnNumber,
    description: `Taint source: ${source.description} (${source.type})`,
  });

  // Intermediate functions (skip first and last since we add them separately)
  for (let i = 1; i < funcList.length - 1; i++) {
    const fn = funcList[i]!;
    const cgNode = callGraph.get(fn);
    nodes.push({
      functionName: fn,
      lineNumber: cgNode?.lineNumber ?? 0,
      columnNumber: 0,
      description: `Function call: ${fn}`,
    });
  }

  // Sink node
  nodes.push({
    functionName: funcList[funcList.length - 1] ?? 'unknown',
    lineNumber: sink.node.lineNumber,
    columnNumber: sink.node.columnNumber,
    description: `${sink.type} sink: ${sink.description}`,
  });

  return nodes;
}

/**
 * Build a linear path between source and sink when call graph analysis
 * can't resolve the chain.
 */
function buildLinearPathNodes(
  source: TaintSource,
  sink: Sink,
  sourceFunc: string | null,
  sinkFunc: string | null,
): TaintPathNode[] {
  const nodes: TaintPathNode[] = [];

  nodes.push({
    functionName: sourceFunc ?? 'unknown',
    lineNumber: source.node.lineNumber,
    columnNumber: source.node.columnNumber,
    description: `Taint source: ${source.description} (${source.type})`,
  });

  // If different functions, add an intermediate hop
  if (sourceFunc && sinkFunc && sourceFunc !== sinkFunc) {
    nodes.push({
      functionName: `${sourceFunc} -> ${sinkFunc}`,
      lineNumber: Math.floor((source.node.lineNumber + sink.node.lineNumber) / 2),
      columnNumber: 0,
      description: `Data flow from ${sourceFunc} to ${sinkFunc}`,
    });
  }

  nodes.push({
    functionName: sinkFunc ?? 'unknown',
    lineNumber: sink.node.lineNumber,
    columnNumber: sink.node.columnNumber,
    description: `${sink.type} sink: ${sink.description}`,
  });

  return nodes;
}

/**
 * Find any sanitizers that exist on lines between source and sink.
 */
function findSanitizersBetween(
  source: TaintSource,
  sink: Sink,
  sanitizers: Sanitizer[],
): Sanitizer[] {
  const minLine = Math.min(source.node.lineNumber, sink.node.lineNumber);
  const maxLine = Math.max(source.node.lineNumber, sink.node.lineNumber);

  return sanitizers.filter(s => {
    const sl = s.node.lineNumber;
    return sl >= minLine && sl <= maxLine;
  });
}

/**
 * Find the enclosing function name for a given node by looking it up
 * in the call graph (uses line number proximity as heuristic).
 */
function findEnclosingFunctionName(
  node: IRNode,
  callGraph: Map<string, CallGraphNode>,
): string | null {
  let bestFunc: string | null = null;
  let bestDelta = Infinity;

  for (const [name, cgNode] of callGraph) {
    if (cgNode.lineNumber <= node.lineNumber) {
      const delta = node.lineNumber - cgNode.lineNumber;
      if (delta < bestDelta) {
        bestDelta = delta;
        bestFunc = name;
      }
    }
  }

  return bestFunc;
}

// ---------------------------------------------------------------------------
// #endregion
// #endregion
// #region -- 5. Compute Reachability Score
// ---------------------------------------------------------------------------

/**
 * Compute a reachability score for a taint path, reflecting how likely
 * the taint is to be exploitable.
 *
 * Scoring rules:
 *  - Starts at 1.0 (fully reachable, direct taint)
 *  - Prepared statements / ORM safe methods: score *= 0.05 (effectively blocked)
 *  - Input validation: score *= 0.15 (heavily mitigated)
 *  - HTML encoding: score *= 0.25 (XSS mitigated, other vectors may still apply)
 *  - Path sanitization: score *= 0.35
 *  - Type coercion: score *= 0.3
 *  - Auth check: score *= 0.8 (narrows but doesn't eliminate attack surface)
 *  - Multiple sanitizers stack multiplicatively
 *  - Path length > 5: score *= 0.9 (longer paths are harder to exploit)
 *  - Path length > 10: score *= 0.8
 *
 * Returns a value between 0 and 1.
 */
export function computeReachabilityScore(
  path: TaintPath,
  _sanitizers?: Sanitizer[],
): number {
  let score = 1.0;

  // Use provided sanitizers or the ones stored on the path
  const sanitizers = _sanitizers ?? path.sanitizers;

  // No taint? No reachability.
  if (path.pathLength === 0) return 0;

  // ---- Sanitizer penalties ----
  const strongestSanitizer = new Map<SanitizerCategory, number>();

  // Pick the strongest multiplier per category (first = best defense wins)
  for (const s of sanitizers) {
    const multiplier = sanitizerMultiplier(s.type);
    const existing = strongestSanitizer.get(s.type);
    if (existing === undefined || multiplier < existing) {
      strongestSanitizer.set(s.type, multiplier);
    }
  }

  // Apply each category once (multiplicative)
  for (const multiplier of strongestSanitizer.values()) {
    score *= multiplier;
  }

  // ---- Path length penalties ----
  if (path.pathLength > 10) {
    score *= 0.8;
  } else if (path.pathLength > 5) {
    score *= 0.9;
  }

  // ---- Blocked paths floor ----
  if (path.isBlocked) {
    score = Math.min(score, 0.05);
  }

  // Clamp to [0, 1]
  return Math.max(0, Math.min(1, score));
}

/**
 * Return the multiplier for a given sanitizer category.
 * Lower values mean stronger mitigation.
 */
function sanitizerMultiplier(category: SanitizerCategory): number {
  switch (category) {
    case 'PREPARED_STATEMENT':
      return 0.05;  // Effectively blocks SQL injection
    case 'ORM_SAFE':
      return 0.1;   // Safe ORM methods block injection
    case 'INPUT_VALIDATION':
      return 0.15;  // Strong mitigation (schema validation)
    case 'HTML_ENCODING':
      return 0.25;  // Blocks XSS but not other vectors
    case 'PATH_SANITIZER':
      return 0.35;  // Reduces path traversal risk
    case 'TYPE_COERCION':
      return 0.3;   // Narrowing to numeric types reduces attack surface
    case 'AUTH_CHECK':
      return 0.8;   // Auth reduces but doesn't prevent exploitation
    default:
      return 1.0;   // Unknown sanitizer, no reduction
  }
}

// ---------------------------------------------------------------------------
// #endregion
// #region -- 6. Generate Taint Report
// ---------------------------------------------------------------------------

/**
 * Produce a comprehensive taint analysis report from a list of TaintPath
 * objects.
 *
 * Includes:
 *  - Summary statistics (total / reachable / blocked paths, source/sink/sanitizer counts)
 *  - Per-sink severity distribution
 *  - Top 10 most critical taint flows (sorted by reachability score)
 *  - Actionable recommendations for adding sanitizers
 */
export function generateTaintReport(taintPaths: TaintPath[]): TaintReport {
  const totalPaths = taintPaths.length;
  const reachablePaths = taintPaths.filter(p => !p.isBlocked && p.reachabilityScore > 0.1);
  const blockedPaths = taintPaths.filter(p => p.isBlocked || p.reachabilityScore <= 0.1);

  // Collect unique sources, sinks, sanitizers
  const sourceKeys = new Set<string>();
  const sinkKeys = new Set<string>();
  const sanitizerKeys = new Set<string>();

  for (const tp of taintPaths) {
    sourceKeys.add(locationKey(tp.source.location) + tp.source.type);
    sinkKeys.add(locationKey(tp.sink.location) + tp.sink.type);
    for (const s of tp.sanitizers) {
      sanitizerKeys.add(locationKey(s.location) + s.type);
    }
  }

  // ---- Severity distribution per sink category ----
  const severityDistribution: Record<string, { critical: number; high: number; medium: number; low: number }> = {};

  for (const tp of taintPaths) {
    const cat = tp.sink.type;
    if (!severityDistribution[cat]) {
      severityDistribution[cat] = { critical: 0, high: 0, medium: 0, low: 0 };
    }
    const sev = tp.sink.severity;
    if (sev === 'critical') severityDistribution[cat]!.critical++;
    else if (sev === 'high') severityDistribution[cat]!.high++;
    else if (sev === 'medium') severityDistribution[cat]!.medium++;
    else severityDistribution[cat]!.low++;
  }

  // ---- Top 10 most critical flows ----
  const sorted = [...taintPaths].sort((a, b) => {
    // Sort first by reachability score (descending), then by severity rank
    const scoreDiff = b.reachabilityScore - a.reachabilityScore;
    if (Math.abs(scoreDiff) > 0.01) return scoreDiff;
    return severityRank(b.sink.severity) - severityRank(a.sink.severity);
  });

  const topFlows = sorted.slice(0, 10);

  // ---- Recommendations ----
  const recommendations = buildRecommendations(taintPaths);

  return {
    summary: {
      totalPaths,
      reachablePaths: reachablePaths.length,
      blockedPaths: blockedPaths.length,
      totalSources: sourceKeys.size,
      totalSinks: sinkKeys.size,
      totalSanitizers: sanitizerKeys.size,
    },
    severityDistribution: severityDistribution as Record<SinkCategory, { critical: number; high: number; medium: number; low: number }>,
    topFlows,
    recommendations,
  };
}

/**
 * Rank severity for sorting (critical first).
 */
function severityRank(severity: Severity): number {
  switch (severity) {
    case 'critical': return 0;
    case 'high':     return 1;
    case 'medium':   return 2;
    case 'low':      return 3;
    case 'info':     return 4;
    default:         return 5;
  }
}

/**
 * Build actionable recommendations based on the taint paths found.
 */
function buildRecommendations(taintPaths: TaintPath[]): string[] {
  const recs: string[] = [];
  const added = new Set<string>();

  // Check for missing sanitizer categories
  const hasSqlSanitizer = taintPaths.some(p =>
    p.sanitizers.some(s => s.type === 'PREPARED_STATEMENT' || s.type === 'ORM_SAFE'),
  );
  const hasInputValidation = taintPaths.some(p =>
    p.sanitizers.some(s => s.type === 'INPUT_VALIDATION'),
  );
  const hasHtmlEncoding = taintPaths.some(p =>
    p.sanitizers.some(s => s.type === 'HTML_ENCODING'),
  );
  const hasTypeCoercion = taintPaths.some(p =>
    p.sanitizers.some(s => s.type === 'TYPE_COERCION'),
  );

  // Count unmitigated sinks by category
  const unmitigatedSinks = new Map<SinkCategory, number>();
  for (const tp of taintPaths) {
    if (tp.isBlocked || tp.reachabilityScore <= 0.1) continue;
    unmitigatedSinks.set(tp.sink.type, (unmitigatedSinks.get(tp.sink.type) ?? 0) + 1);
  }

  if (unmitigatedSinks.size === 0) {
    recs.push('No unmitigated taint paths found. Existing sanitizers appear adequate.');
    return recs;
  }

  // Specific recommendations per sink category
  for (const [cat, count] of unmitigatedSinks) {
    switch (cat) {
      case 'SQL':
        if (!hasSqlSanitizer) {
          recs.push(`CRITICAL: ${count} SQL injection path(s) unmitigated. Use parameterized queries (PreparedStatement, bind_param, or ORM safe methods) for all database operations.`);
          added.add('sql');
        }
        break;
      case 'COMMAND':
        recs.push(`CRITICAL: ${count} command injection path(s) unmitigated. Avoid shell execution with user input. Use execFile/spawn with array arguments and validate all input.`);
        added.add('command');
        break;
      case 'FILE':
        recs.push(`HIGH: ${count} file write path(s) unmitigated. Validate and sanitize file paths. Use path.normalize() and reject paths with ".." segments.`);
        added.add('file');
        break;
      case 'HTTP_SSRF':
        recs.push(`HIGH: ${count} SSRF path(s) unmitigated. Validate URLs against an allowlist. Block internal IP ranges and use a dedicated HTTP client with SSRF protection.`);
        added.add('ssrf');
        break;
      case 'TEMPLATE':
        if (!hasHtmlEncoding) {
          recs.push(`HIGH: ${count} template injection path(s) unmitigated. Sanitize all user input before template rendering and avoid rendering user-controlled templates.`);
          added.add('template');
        }
        break;
      case 'CODE':
        recs.push(`CRITICAL: ${count} code execution path(s) unmitigated. Avoid eval(), Function(), and exec() with user input. Use safe alternatives.`);
        added.add('code');
        break;
      case 'NOSQL':
        recs.push(`HIGH: ${count} NoSQL injection path(s) unmitigated. Validate and sanitize input used in MongoDB queries. Use schema validation (Zod, Joi).`);
        added.add('nosql');
        break;
      default:
        recs.push(`HIGH: ${count} unmitigated ${cat} path(s). Review and add appropriate input validation for this sink type.`);
    }
  }

  // General recommendations
  if (!hasInputValidation && !added.has('any')) {
    recs.push('GENERAL: Add centralized input validation using a schema validation library (Joi, Zod, Yup, Pydantic) for all external inputs.');
    added.add('any');
  }

  if (!hasTypeCoercion) {
    recs.push('GENERAL: Apply type coercion (parseInt, Number()) to numeric inputs to reduce injection surface.');
  }

  // Critical sink categories missing coverage
  const highRiskCategories: SinkCategory[] = ['SQL', 'COMMAND', 'CODE'];
  for (const cat of highRiskCategories) {
    if (unmitigatedSinks.has(cat) && !added.has(`highrisk-${cat}`)) {
      recs.push(`HIGH PRIORITY: Address all ${cat} injection paths before production deployment.`);
      added.add(`highrisk-${cat}`);
    }
  }

  return recs;
}

// ---------------------------------------------------------------------------
// #endregion
// ---------------------------------------------------------------------------
// #region -- Utility: aggregate taint paths by source/sink
// ---------------------------------------------------------------------------

/**
 * Merge duplicate taint paths that share the same source and sink type,
 * keeping the highest-reachability path.
 */
export function deduplicateTaintPaths(paths: TaintPath[]): TaintPath[] {
  const best = new Map<string, TaintPath>();

  for (const p of paths) {
    const key = `${p.source.type}->${p.sink.type}:${locationKey(p.source.location)}-${locationKey(p.sink.location)}`;
    const existing = best.get(key);
    if (!existing || p.reachabilityScore > existing.reachabilityScore) {
      best.set(key, p);
    }
  }

  return [...best.values()].sort((a, b) => b.reachabilityScore - a.reachabilityScore);
}

// ---------------------------------------------------------------------------
// #endregion
// #region -- Utility: full pipeline convenience helper
// ---------------------------------------------------------------------------

/**
 * Run the full taint analysis pipeline on an AST:
 *  1. Identify taint sources
 *  2. Identify sinks
 *  3. Identify sanitizers
 *  4. Trace taint through the call graph
 *  5. Deduplicate paths
 *  6. Generate report
 *
 * This is the primary entry point for most consumers.
 */
export function analyzeDataflow(
  ast: IRNode[],
  callGraph: Map<string, CallGraphNode>,
  filePath: string = '',
): {
  sources: TaintSource[];
  sinks: Sink[];
  sanitizers: Sanitizer[];
  taintPaths: TaintPath[];
  report: TaintReport;
} {
  logger.info({ filePath, astSize: ast.length, callGraphSize: callGraph.size }, 'Starting dataflow analysis');

  const sources = identifyTaintSources(ast, filePath);
  const sinks = identifySinks(ast, filePath);
  const sanitizers = identifySanitizers(ast, filePath);

  logger.debug({
    sourcesFound: sources.length,
    sinksFound: sinks.length,
    sanitizersFound: sanitizers.length,
  }, 'Taint analysis: identification complete');

  if (sources.length === 0 || sinks.length === 0) {
    logger.info('No taint sources or sinks found; skipping trace');
    const emptyPaths: TaintPath[] = [];
    return {
      sources,
      sinks,
      sanitizers,
      taintPaths: emptyPaths,
      report: generateTaintReport(emptyPaths),
    };
  }

  const rawPaths = traceTaint(sources, sinks, sanitizers, callGraph);
  const taintPaths = deduplicateTaintPaths(rawPaths);
  const report = generateTaintReport(taintPaths);

  logger.info({
    totalPaths: taintPaths.length,
    reachablePaths: report.summary.reachablePaths,
    blockedPaths: report.summary.blockedPaths,
  }, 'Dataflow analysis complete');

  return { sources, sinks, sanitizers, taintPaths, report };
}

// ---------------------------------------------------------------------------
// #endregion
// #region -- Cross-File Taint Analysis
// ---------------------------------------------------------------------------

export interface FileAnalysis {
  filePath: string;
  ast: IRNode[];
  callGraph: Map<string, CallGraphNode>;
  exports: string[];
  imports: Array<{ source: string; symbols: string[] }>;
}

export function analyzeProjectDataflow(
  fileAnalyses: FileAnalysis[],
  maxCrossFileDepth = 3,
): {
  sources: TaintSource[];
  sinks: Sink[];
  sanitizers: Sanitizer[];
  taintPaths: TaintPath[];
  report: TaintReport;
  crossFileEdges: number;
} {
  logger.info({ fileCount: fileAnalyses.length }, 'Starting cross-file dataflow analysis');

  const mergedCallGraph = new Map<string, CallGraphNode>();
  const allSources: TaintSource[] = [];
  const allSinks: Sink[] = [];
  const allSanitizers: Sanitizer[] = [];

  // Phase 1: Collect per-file data and build qualified names
  const exportMap = new Map<string, string>();
  for (const fa of fileAnalyses) {
    const prefix = fa.filePath.replace(/\.[^.]+$/, '').replace(/[/\\]/g, '.');

    for (const [name, node] of fa.callGraph) {
      const qualifiedName = `${prefix}::${name}`;
      mergedCallGraph.set(qualifiedName, {
        ...node,
        functionName: qualifiedName,
        filePath: fa.filePath,
        callees: node.callees.map(c => `${prefix}::${c}`),
        callers: node.callers.map(c => `${prefix}::${c}`),
      });
    }

    for (const exp of fa.exports) {
      exportMap.set(exp, `${prefix}::${exp}`);
      const baseName = exp.split('.').pop() || exp;
      if (!exportMap.has(baseName)) exportMap.set(baseName, `${prefix}::${exp}`);
    }

    const sources = identifyTaintSources(fa.ast, fa.filePath);
    const sinks = identifySinks(fa.ast, fa.filePath);
    const sanitizers = identifySanitizers(fa.ast, fa.filePath);
    allSources.push(...sources);
    allSinks.push(...sinks);
    allSanitizers.push(...sanitizers);
  }

  // Phase 2: Resolve cross-file import edges
  let crossFileEdges = 0;
  for (const fa of fileAnalyses) {
    const prefix = fa.filePath.replace(/\.[^.]+$/, '').replace(/[/\\]/g, '.');

    for (const imp of fa.imports) {
      for (const sym of imp.symbols) {
        const qualifiedImport = exportMap.get(sym);
        if (!qualifiedImport) continue;
        const importerPrefix = prefix;

        for (const [name, node] of mergedCallGraph) {
          if (!name.startsWith(importerPrefix + '::')) continue;

          const localCallees = node.callees;
          const localRef = `${importerPrefix}::${sym}`;
          if (localCallees.includes(localRef) && mergedCallGraph.has(qualifiedImport)) {
            const idx = localCallees.indexOf(localRef);
            if (idx >= 0) localCallees[idx] = qualifiedImport;

            const target = mergedCallGraph.get(qualifiedImport);
            if (target && !target.callers.includes(name)) {
              target.callers.push(name);
            }
            crossFileEdges++;
          }
        }
      }
    }
  }

  logger.info({ mergedNodes: mergedCallGraph.size, crossFileEdges }, 'Cross-file call graph built');

  if (allSources.length === 0 || allSinks.length === 0) {
    logger.info('No cross-file taint sources or sinks found');
    const emptyPaths: TaintPath[] = [];
    return {
      sources: allSources,
      sinks: allSinks,
      sanitizers: allSanitizers,
      taintPaths: emptyPaths,
      report: generateTaintReport(emptyPaths),
      crossFileEdges,
    };
  }

  const rawPaths = traceTaint(allSources, allSinks, allSanitizers, mergedCallGraph);

  // Filter paths that exceed max cross-file depth
  const filteredPaths = rawPaths.filter(p => {
    const uniqueFiles = new Set(p.pathNodes.map(n => {
      const parts = n.functionName.split('::');
      return parts.length > 1 ? parts[0] : 'unknown';
    }));
    return uniqueFiles.size <= maxCrossFileDepth;
  });

  const taintPaths = deduplicateTaintPaths(filteredPaths);
  const report = generateTaintReport(taintPaths);

  logger.info({
    totalPaths: taintPaths.length,
    reachablePaths: report.summary.reachablePaths,
    blockedPaths: report.summary.blockedPaths,
    crossFileEdges,
  }, 'Cross-file dataflow analysis complete');

  return { sources: allSources, sinks: allSinks, sanitizers: allSanitizers, taintPaths, report, crossFileEdges };
}

// ---------------------------------------------------------------------------
// #endregion
// ============================================================
