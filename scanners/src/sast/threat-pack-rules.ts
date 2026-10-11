/**
 * Threat-Informed SAST Rule Pack — RCE-class vulnerabilities.
 *
 * Curated rules targeting the most exploited vulnerability classes seen in
 * real-world attacks: unsafe deserialization, server-side template injection,
 * JNDI/Log4Shell, JWT flaws, NoSQL injection, GraphQL misconfig, and
 * language-specific dangers for Go, Rust, and CI/CD pipelines.
 *
 * Each rule maps to a CWE, carries a CVSS 3.1 vector, and includes an
 * actionable recommendation.  Patterns are designed to be specific enough to
 * minimise false positives; safe patterns are excluded where known.
 */
import { SastRule } from './engine.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function re(pattern: string, flags = 'i'): RegExp {
  return new RegExp(pattern, flags);
}

// ─── Rule Pack ────────────────────────────────────────────────────────────────

export const THREAT_PACK_RULES: SastRule[] = [

  // ═══════════════════════════════════════════════════════════════════════════
  // INSECURE DESERIALIZATION  (CWE-502,  A08:2021)
  // ═══════════════════════════════════════════════════════════════════════════

  // 1 ─ Java ObjectInputStream.readObject
  {
    id: 'SAST-TP-DESER-JAVA-OBJECTINPUTSTREAM',
    name: 'Java: Unsafe Deserialization via ObjectInputStream',
    description:
      'ObjectInputStream.readObject() called on untrusted data can execute arbitrary code. Attackers craft serialised payloads that execute during deserialization.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['java'],
    patterns: [
      re('ObjectInputStream\\s*\\w*\\s*=\\s*new\\s+ObjectInputStream\\s*\\('),
      re('\\.readObject\\s*\\('),
    ],
    excludePatterns: [
      // Look-ahead white-lists — trust only hard-coded file paths, not sockets
      re('new\\s+ObjectInputStream\\s*\\(\\s*(?:new\\s+FileInputStream|Files\\.newInputStream|getClass\\(\\)\\.getResourceAsStream)'),
    ],
    recommendation:
      'Never deserialise untrusted data with ObjectInputStream. Use JSON, Protocol Buffers, or a type-safe serialisation library. If Java serialisation is unavoidable, use a LookAheadObjectInputStream or a JEP-290 global filter.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },

  // 2 ─ Java XMLDecoder
  {
    id: 'SAST-TP-DESER-JAVA-XMLDECODER',
    name: 'Java: Unsafe Deserialization via XMLDecoder',
    description:
      'XMLDecoder deserialises arbitrary Java objects from XML.  Attackers can embed <object> tags that invoke Runtime.exec() or load remote classes.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['java'],
    patterns: [
      re('XMLDecoder\\s*\\w*\\s*=\\s*new\\s+XMLDecoder\\s*\\('),
      re('\\.readObject\\s*\\('),
    ],
    excludePatterns: [
      // XMLDecoder reading from a static bundled resource file
      re('new\\s+XMLDecoder\\s*\\(\\s*(?:new\\s+FileInputStream|getClass\\(\\)\\.getResourceAsStream)\\s*\\('),
      // Used only in test fixtures
      re('XMLDecoder\\s*\\w*\\s*=\\s*null'),
    ],
    recommendation:
      'Replace XMLDecoder with a safe XML parser (SAX/DOM) with external-entity processing disabled. Prefer JSON or Protobuf for data interchange.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },

  // 3 ─ Java SnakeYAML Yaml().load(
  {
    id: 'SAST-TP-DESER-JAVA-SNAKEYAML',
    name: 'Java: Unsafe YAML Deserialization via SnakeYAML',
    description:
      'SnakeYAML\'s Yaml().load() will instantiate arbitrary Java classes declared in YAML !! tags, leading to RCE.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['java'],
    patterns: [
      re('new\\s+Yaml\\s*\\(\\s*\\)\\s*\\.\\s*load\\s*\\('),
      re('Yaml\\s*\\(\\s*\\)\\s*\\.\\s*load\\s*\\('),
    ],
    excludePatterns: [
      re('new\\s+Yaml\\s*\\(\\s*new\\s+Constructor\\s*\\(\\s*\\w+\\.class\\s*\\)\\s*\\)'), // type-safe constructor
    ],
    recommendation:
      'Use Yaml(new Constructor(MyClass.class)) with a restricted type, or call yaml.loadAs(input, MyClass.class). Prefer yaml.load() only with a SafeConstructor.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },

  // 4 ─ Java Jackson polymorphic deserialization
  {
    id: 'SAST-TP-DESER-JAVA-JACKSON',
    name: 'Java: Jackson Polymorphic Deserialization Enabled',
    description:
      'Jackson ObjectMapper configured with enableDefaultTyping() or default-typing can instantiate arbitrary classes based on JSON type hints, enabling RCE gadgets.',
    severity: 'high',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['java'],
    patterns: [
      re('enableDefaultTyping\\s*\\('),
      re('@JsonTypeInfo\\s*\\('),
      re('ObjectMapper\\.DefaultTyping'),
    ],
    excludePatterns: [
      re('enableDefaultTyping\\s*\\(\\s*ObjectMapper\\.DefaultTyping\\.NON_FINAL\\s*\\)'), // still risky, but less so
    ],
    recommendation:
      'Avoid enableDefaultTyping(). Use explicit @JsonSubTypes or a custom TypeResolver with a strict allow-list. Prefer the default Jackson behaviour which does not use polymorphic typing for unknown classes.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'deserialization',
  },

  // 5 ─ Python pickle.load(s)
  {
    id: 'SAST-TP-DESER-PY-PICKLE',
    name: 'Python: Unsafe Deserialization via pickle',
    description:
      'pickle.load() / pickle.loads() on untrusted data can execute arbitrary Python code through __reduce__ gadgets.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['python'],
    patterns: [
      re('pickle\\.loads?\\s*\\('),
      re('_pickle\\.loads?\\s*\\('),
      re('cPickle\\.loads?\\s*\\('),
      re('dill\\.loads?\\s*\\('),
    ],
    excludePatterns: [
      re('pickle\\.loads?\\s*\\(\\s*open\\s*\\('),   // loading from a local file via open() is intentional
    ],
    recommendation:
      'Never unpickle data from untrusted sources. Use JSON, MessagePack, or Protocol Buffers. If pickle is absolutely necessary, sign data with HMAC and verify the signature before unpickling.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },

  // 6 ─ Python yaml.load() without SafeLoader
  {
    id: 'SAST-TP-DESER-PY-YAML',
    name: 'Python: Unsafe YAML Deserialization via yaml.load',
    description:
      'yaml.load() without Loader=SafeLoader can instantiate arbitrary Python objects, leading to RCE.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['python'],
    patterns: [
      re('yaml\\.load\\s*\\([^)]*\\)'),
    ],
    excludePatterns: [
      re('yaml\\.load\\s*\\([^,)]*,\\s*Loader\\s*=\\s*(?:yaml\\.)?SafeLoader'),
      re('yaml\\.load\\s*\\([^,)]*,\\s*(?:yaml\\.)?SafeLoader'),
    ],
    recommendation:
      'Always use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). These restrict deserialization to basic Python types only.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },

  // 7 ─ Python marshal.loads
  {
    id: 'SAST-TP-DESER-PY-MARSHAL',
    name: 'Python: Unsafe Deserialization via marshal.loads',
    description:
      'marshal.loads() can execute arbitrary code when fed crafted bytecode. The marshal module is not designed to be safe against malicious data.',
    severity: 'high',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['python'],
    patterns: [
      re('marshal\\.loads?\\s*\\('),
    ],
    excludePatterns: [
      re('marshal\\.loads?\\s*\\(\\s*(?:open|file)\\s*\\('), // loading from a controlled local file
    ],
    recommendation:
      'Do not use marshal for data from untrusted sources. It is a format-specific serialisation for .pyc files. Use JSON or pickle with HMAC signatures.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'deserialization',
  },

  // 8 ─ PHP unserialize()
  {
    id: 'SAST-TP-DESER-PHP-UNSERIALIZE',
    name: 'PHP: Unsafe Deserialization via unserialize()',
    description:
      'unserialize() on user-controlled input can trigger PHP gadget chains (PHPGGC) leading to RCE, file inclusion, or SQL injection.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['php'],
    patterns: [
      re('unserialize\\s*\\(\\s*\\$(?:_GET|_POST|_REQUEST|_COOKIE|_SERVER)'),
      re('unserialize\\s*\\(\\s*\\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\\b'),
      re('unserialize\\s*\\(\\s*(?:\\$request|\\$input|\\$body|\\$_|file_get_contents\\s*\\(\\s*["\']php://input["\']\\s*\\))'),
    ],
    excludePatterns: [
      // Superglobals used but with allowed_classes option
      re('unserialize\\s*\\([^)]*,\\s*\\[\\s*["\']allowed_classes["\']\\s*=>\\s*(?:false|\\[\\])'),
    ],
    recommendation:
      'Never unserialize() user input. Use json_decode() for data interchange. If serialization is required, use the allowed_classes option set to false or a strict allow-list, and sign data with HMAC.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },

  // 9 ─ .NET BinaryFormatter
  {
    id: 'SAST-TP-DESER-CSHARP-BINARYFORMATTER',
    name: '.NET: Unsafe Deserialization via BinaryFormatter',
    description:
      'BinaryFormatter.Deserialize() on untrusted data is a well-known RCE vector. Microsoft recommends removing it entirely.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['csharp'],
    patterns: [
      re('BinaryFormatter\\s*\\.\\s*Deserialize\\s*\\('),
      re('new\\s+BinaryFormatter\\s*\\(\\s*\\)\\s*\\.\\s*Deserialize\\s*\\('),
      re('BinaryFormatter\\s+\\w+\\s*=\\s*new\\s+BinaryFormatter'),
    ],
    excludePatterns: [
      // BinaryFormatter with SerializationBinder or SurrogateSelector (mitigates risk)
      re('SerializationBinder'),
      re('SurrogateSelector'),
      // Null reference (comment / documentation)
      re('BinaryFormatter\\s*\\w*\\s*=\\s*null'),
    ],
    recommendation:
      'Remove all BinaryFormatter usage. Migrate to System.Text.Json or Newtonsoft.Json with TypeNameHandling=TypeNameHandling.None. Microsoft has deprecated BinaryFormatter as of .NET 5+.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },

  // 10 ─ .NET other unsafe deserializers
  {
    id: 'SAST-TP-DESER-CSHARP-OTHER',
    name: '.NET: Unsafe Deserialization via LosFormatter / JavaScriptSerializer / TypeNameHandling',
    description:
      'LosFormatter, JavaScriptSerializer with SimpleTypeResolver, NetDataContractSerializer, or Json.NET with TypeNameHandling=All can all be exploited for RCE.',
    severity: 'high',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['csharp'],
    patterns: [
      re('LosFormatter\\s*\\.\\s*Deserialize\\s*\\('),
      re('new\\s+JavaScriptSerializer\\s*\\(\\s*new\\s+SimpleTypeResolver\\s*\\('),
      re('TypeNameHandling\\s*=\\s*TypeNameHandling\\.(?:All|Objects|Auto)'),
      re('NetDataContractSerializer'),
      re('SoapFormatter'),
      re('ObjectStateFormatter'),
    ],
    excludePatterns: [
      re('TypeNameHandling\\s*=\\s*TypeNameHandling\\.None'),
    ],
    recommendation:
      'Replace LosFormatter/ObjectStateFormatter with safe alternatives. Set TypeNameHandling=TypeNameHandling.None in Json.NET. Use System.Text.Json which does not support polymorphic deserialization by default.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'deserialization',
  },

  // 11 ─ Ruby Marshal.load / YAML.load
  {
    id: 'SAST-TP-DESER-RUBY-MARSHAL',
    name: 'Ruby: Unsafe Deserialization via Marshal.load / YAML.load',
    description:
      'Marshal.load() and YAML.load() can instantiate arbitrary Ruby objects, enabling RCE through gadget chains.',
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    languages: ['ruby'],
    patterns: [
      re('Marshal\\.load\\s*\\('),
      re('Marshal\\.restore\\s*\\('),
      re('YAML\\.load\\s*\\('),
    ],
    excludePatterns: [
      re('YAML\\.safe_load\\s*\\('),
      re('YAML\\.load\\s*\\([^,)]*,\\s*(?:permitted_classes|safe_load)'),
    ],
    recommendation:
      'Use YAML.safe_load() instead of YAML.load(). Never call Marshal.load() on data from untrusted sources — use JSON.parse() instead.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'deserialization',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // SERVER-SIDE TEMPLATE INJECTION  (CWE-1336 / CWE-94)
  // ═══════════════════════════════════════════════════════════════════════════

  // 12 ─ Jinja2 render_template_string with variable
  {
    id: 'SAST-TP-SSTI-JINJA2-RENDER',
    name: 'Python: SSTI via Jinja2 render_template_string()',
    description:
      'render_template_string() called with user-controlled input allows attackers to execute arbitrary Python expressions embedded in Jinja2 templates ({{ config }}, {{ self.__init__.__globals__ }}).',
    severity: 'critical',
    cweId: 'CWE-1336',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['python'],
    patterns: [
      re('render_template_string\\s*\\(\\s*(?:request\\.|req\\.|flask\\.request)'),
      re('render_template_string\\s*\\(\\s*(?:f["\']|["\'].*%.*["\'])'),
    ],
    excludePatterns: [
      // render_template_string called with a static string literal (no user input)
      re('render_template_string\\s*\\(\\s*["\'][^"\']*["\']\\s*\\)'),
      // SandboxedEnvironment usage
      re('SandboxedEnvironment'),
    ],
    recommendation:
      'Never pass user input directly to render_template_string(). Use render_template() with static template files. If dynamic templates are needed, use a sandboxed environment (Jinja2 SandboxedEnvironment) or a logic-less template language like Mustache.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'ssti',
  },

  // 13 ─ Jinja2 Template() with user input
  {
    id: 'SAST-TP-SSTI-JINJA2-TEMPLATE',
    name: 'Python: SSTI via Jinja2 Template() Constructor',
    description:
      'Creating a Jinja2 Template() object from user-controlled input is equivalent to render_template_string() and allows full SSTI.',
    severity: 'critical',
    cweId: 'CWE-1336',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['python'],
    patterns: [
      re('jinja2\\.Template\\s*\\(\\s*(?:request\\.|req\\.|flask\\.request)'),
      re('Template\\s*\\(\\s*(?:request\\.|req\\.|flask\\.request)'),
    ],
    excludePatterns: [
      // Template() called with a static string literal
      re('Template\\s*\\(\\s*["\'][^"\']*["\']\\s*\\)'),
      // Import from jinja2 but used with SandboxedEnvironment
      re('SandboxedEnvironment'),
    ],
    recommendation:
      'Do not construct Jinja2 Template objects from user input. Use static template files loaded via the Jinja2 Environment loader.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'ssti',
  },

  // 14 ─ Spring SpEL SpelExpressionParser
  {
    id: 'SAST-TP-SSTI-SPRING-SPEL',
    name: 'Java: Expression Language Injection via Spring SpEL',
    description:
      'SpelExpressionParser().parseExpression() with user-controlled input can execute arbitrary Java code through SpEL expressions like T(java.lang.Runtime).getRuntime().exec().',
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['java'],
    patterns: [
      re('SpelExpressionParser\\s*\\(\\s*\\)\\s*\\.\\s*parseExpression\\s*\\('),
      re('new\\s+SpelExpressionParser\\s*\\(\\s*\\)\\s*\\.\\s*parseExpression\\s*\\('),
      re('ExpressionParser\\s+\\w+\\s*=\\s*new\\s+SpelExpressionParser'),
    ],
    excludePatterns: [
      // When the expression is a quoted string literal (static), it's safe
      re('parseExpression\\s*\\(\\s*"[^"]*"\\s*\\)'),
    ],
    recommendation:
      'Avoid SpEL with user input. Use a SimpleEvaluationContext instead of the default StandardEvaluationContext to restrict what expressions can access. Prefer message-format templates without expression evaluation.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'ssti',
  },

  // 15 ─ Freemarker Template.process with user input
  {
    id: 'SAST-TP-SSTI-FREEMARKER',
    name: 'Java: SSTI via Freemarker Template.process()',
    description:
      'FreeMarker Template.process() with user-controlled template content can lead to RCE via the built-in "new" directive that creates arbitrary Java objects.',
    severity: 'high',
    cweId: 'CWE-1336',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['java'],
    patterns: [
      re('new\\s+Template\\s*\\([^)]*new\\s+StringReader'),
      re('\\.process\\s*\\([^)]*,\\s*new\\s+StringWriter'),
    ],
    excludePatterns: [
      // Template loaded from classpath via Configuration (safe)
      re('cfg\\.getTemplate\\s*\\('),
      re('configuration\\.getTemplate\\s*\\('),
      // Disabled new built-in
      re('SUPPRESS_METHOD|ALLOWS_NOTHING|SAFER_RESOLVER'),
    ],
    recommendation:
      'Never construct FreeMarker Template objects from user input. Load templates from the classpath using Configuration.getTemplate(). Disable the new built-in with cfg.setNewBuiltinClassResolver(TemplateClassResolver.SUPPRESS_METHOD).',
    cvssScore: 8.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'ssti',
  },

  // 16 ─ Velocity / Handlebars / Twig / ERB / Pug template injection
  {
    id: 'SAST-TP-SSTI-MULTI',
    name: 'Server-Side Template Injection (Multi-Engine)',
    description:
      'User input rendered through a server-side template engine (Velocity, Handlebars, Twig, ERB, Pug) without sandboxing can lead to RCE or information disclosure.',
    severity: 'high',
    cweId: 'CWE-1336',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['java', 'javascript', 'typescript', 'php', 'ruby', 'python'],
    patterns: [
      // Velocity (Java)
      re('Velocity\\.evaluate\\s*\\('),
      re('VelocityContext\\s*\\(\\s*\\)\\s*;.*\\.evaluate\\s*\\('),
      // Handlebars (JS) — compiling user input
      re('Handlebars\\.compile\\s*\\(\\s*(?:req\\.|request\\.)'),
      // Twig (PHP)
      re('new\\s+Twig\\\\\\\\Environment\\s*\\(\\s*new\\s+Twig\\\\\\\\Loader\\\\\\\\ArrayLoader'),
      re('\\\\Twig\\\\Environment.*render\\s*\\(.*\\$_(?:GET|POST|REQUEST)'),
      // ERB (Ruby)
      re('ERB\\.new\\s*\\(\\s*(?:params|request)'),
      // Pug (JS)
      re('pug\\.compile\\s*\\(\\s*(?:req\\.|request\\.)'),
    ],
    excludePatterns: [
      // Handlebars.compile with a static string (safe inline template)
      re('Handlebars\\.compile\\s*\\(\\s*["\'][^"\']*["\']'),
      // ERB.new with a static string
      re('ERB\\.new\\s*\\(\\s*["\'][^"\']*["\']'),
      // Pug compile from a file, not user input
      re('pug\\.compileFile\\s*\\('),
      // Velocity evaluate with static template string
      re('Velocity\\.evaluate\\s*\\([^,]*,\\s*"[^"]*"'),
    ],
    recommendation:
      'Always load templates from files, never from user input. If user input must be rendered, use a logic-less template engine (Mustache, Handlebars in strict mode) that does not evaluate code expressions. Enable sandboxing where available.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'ssti',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // JNDI / LOG4SHELL  (CWE-917)
  // ═══════════════════════════════════════════════════════════════════════════

  // 17 ─ ${jndi: pattern in strings / log configs
  {
    id: 'SAST-TP-JNDI-LOG4SHELL-PATTERN',
    name: 'Log4Shell: JNDI Lookup Injection Pattern',
    description:
      'The pattern ${jndi:...} appearing in log messages, configuration files, or string formatting allows an attacker who controls the input to trigger a JNDI lookup and potentially execute arbitrary code.',
    severity: 'critical',
    cweId: 'CWE-917',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['all'],
    patterns: [
      re('\\$\\{\\s*(?:jndi|java|lower|upper|env|sys|ctx|date|main|marker|log4j)\\s*:'),
      re('\\$\\{\\s*jndi\\s*:'),
    ],
    excludePatterns: [
      // Escaped literal (e.g., in documentation showing the attack pattern)
      re('\\\\\\$\\{jndi'),
      // Comment line explaining the vulnerability (text after //)
      re('(?:CVE-2021-44228|CVE-2021-45046|Log4Shell)'),
    ],
    recommendation:
      'Upgrade Log4j to 2.17.1+ (2.12.4 for Java 7, 2.3.2 for Java 6). Set log4j2.formatMsgNoLookups=true. Remove the JndiLookup class from the classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class.',
    cvssScore: 10.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    category: 'jndi',
  },

  // 18 ─ InitialContext().lookup( + variable
  {
    id: 'SAST-TP-JNDI-LOOKUP-VARIABLE',
    name: 'Java: JNDI Lookup with User-Controlled Name',
    description:
      'InitialContext.lookup() called with a user-controlled name can be exploited similarly to Log4Shell — an attacker who controls the lookup name can point it at a malicious LDAP/RMI server.',
    severity: 'critical',
    cweId: 'CWE-917',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['java'],
    patterns: [
      re('new\\s+InitialContext\\s*\\(\\s*\\)\\s*\\.\\s*lookup\\s*\\('),
      re('InitialContext\\s*\\(\\s*\\)\\s*\\.\\s*lookup\\s*\\('),
      re('\\.lookup\\s*\\(\\s*(?:request\\.|req\\.|@RequestParam|@PathVariable)'),
    ],
    excludePatterns: [
      // lookup("java:comp/env/...") is safe — it's a local ENC lookup
      re('lookup\\s*\\(\\s*"java:'),
    ],
    recommendation:
      'Never pass user input to InitialContext.lookup(). If dynamic JNDI lookups are required, maintain a strict allow-list of permitted JNDI names and validate against it before calling lookup().',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'jndi',
  },

  // 19 ─ Log4j vulnerable version detection in build files
  {
    id: 'SAST-TP-JNDI-LOG4J-VERSION',
    name: 'Log4Shell: Potentially Vulnerable Log4j Version',
    description:
      'Log4j versions 2.0-beta9 through 2.17.0 (excluding 2.12.4, 2.3.2) contain the critical JNDI lookup vulnerability (CVE-2021-44228 / CVE-2021-45046).',
    severity: 'critical',
    cweId: 'CWE-917',
    owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
    languages: ['java', 'xml', 'yaml'],
    patterns: [
      re('log4j.*(?:2\\.(?:[0-9]|1[0-6])\\.)'),
      re('log4j-core.*2\\.(?:1[0-7])\\.0'),
      re('org\\.apache\\.logging\\.log4j.*2\\.(?:[0-9]|1[0-7])\\.'),
    ],
    excludePatterns: [
      re('log4j.*2\\.(?:1[2-9]\\.|2[0-9]+\\.)'),  // 2.12+ or 2.20+ (newer)
      re('log4j.*2\\.17\\.[1-9]'),                  // 2.17.1+ (patched)
      re('log4j.*2\\.3\\.[2-9]'),                   // 2.3.2+ (patched backport)
      re('log4j.*2\\.12\\.[4-9]'),                  // 2.12.4+ (patched backport)
    ],
    recommendation:
      'Upgrade Log4j to 2.17.1+ (2.12.4 for Java 7, 2.3.2 for Java 6). Verify the fix with a vulnerability scanner. Check all transitive dependencies as well.',
    cvssScore: 10.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    category: 'jndi',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // JWT FLAWS  (CWE-347)
  // ═══════════════════════════════════════════════════════════════════════════

  // 20 ─ algorithms: ['none'] / alg:none accepted
  {
    id: 'SAST-TP-JWT-NONE-ALG',
    name: 'JWT: "none" Algorithm Accepted',
    description:
      'The JWT library is configured to accept tokens signed with the "none" algorithm. An attacker can forge tokens by setting alg:none and providing an empty signature.',
    severity: 'high',
    cweId: 'CWE-347',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    patterns: [
      re('algorithms\\s*:\\s*\\[\\s*["\']none["\']'),
      re('algorithms\\s*:\\s*\\[[^\\]]*["\']none["\']'),
      re('alg\\s*:\\s*["\']none["\']'),
    ],
    excludePatterns: [
      // In test files only
    ],
    recommendation:
      'Explicitly list allowed algorithms (e.g., algorithms: ["RS256", "ES256"]). Never include "none". Most JWT libraries reject "none" by default — this usually means someone explicitly enabled it (a critical misconfiguration).',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'jwt',
  },

  // 21 ─ jwt.decode() without verify()
  {
    id: 'SAST-TP-JWT-DECODE-NOVERIFY',
    name: 'JWT: decode() Used Without verify()',
    description:
      'jwt.decode() decodes the token WITHOUT verifying the signature. Any data in a JWT decoded this way is attacker-controlled. The token must be verified with jwt.verify() before use.',
    severity: 'high',
    cweId: 'CWE-347',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript'],
    patterns: [
      re('jwt\\.decode\\s*\\(\\s*[^)]+\\)'),
    ],
    excludePatterns: [
      // Exclude lines where .verify( is called nearby (within the same expression or on the result)
      re('\\.verify\\s*\\('),
      // JWT decode for inspection only is OK in debug/log contexts
      re('console\\.(?:log|info|debug)'),
      re('logger\\.'),
    ],
    recommendation:
      'Always use jwt.verify(token, secretOrPublicKey, options) to validate the token signature. jwt.decode() should only be used for debugging/inspection of trusted tokens, never for authorization decisions.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'jwt',
  },

  // 22 ─ Hardcoded HMAC secret in JWT context
  {
    id: 'SAST-TP-JWT-HARDCODED-SECRET',
    name: 'JWT: Hardcoded HMAC Secret',
    description:
      'JWT signing/verification uses a hardcoded string literal as the HMAC secret. Anyone with access to the source code can forge valid tokens.',
    severity: 'high',
    cweId: 'CWE-347',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript', 'python', 'java'],
    patterns: [
      re('jwt\\.sign\\s*\\([^,]+,\\s*["\'][^"\']{4,}["\']'),
      re('jwt\\.verify\\s*\\([^,]+,\\s*["\'][^"\']{4,}["\']'),
      re('JWT\\.sign\\s*\\([^,]+,\\s*["\'][^"\']{4,}["\']'),
      re('\\.sign\\s*\\([^,]+,\\s*["\'][^"\']{8,}["\']'),
    ],
    excludePatterns: [
      // Exclude references to env vars / config
      re('(?:process\\.env|os\\.environ|System\\.getenv|os\\.Getenv|config\\.|settings\\.)'),
      re('["\']\\s*[+*]\\s*'), // dynamically constructed
    ],
    recommendation:
      'Store JWT secrets in environment variables or a secrets manager. Rotate exposed secrets immediately. Use RS256/ES256 with key files instead of HMAC shared secrets for multi-service architectures.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'jwt',
  },

  // 23 ─ kid/jku/x5u from untrusted source
  {
    id: 'SAST-TP-JWT-KID-INJECTION',
    name: 'JWT: Untrusted Key Identifier (kid/jku/x5u)',
    description:
      'Using the JWT header "kid" (key ID), "jku" (JWK Set URL), or "x5u" (X.509 URL) from an untrusted source can lead to key confusion attacks, path traversal in key files, or SSRF to fetch attacker-controlled keys.',
    severity: 'high',
    cweId: 'CWE-347',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    patterns: [
      re('\\.header\\s*\\(\\s*["\']kid["\']'),
      re('token\\.header\\s*\\[\\s*["\']kid["\']\\s*\\]'),
      re('decoded\\.header\\.kid'),
      re('kid\\s*=\\s*.*req\\.'),
      // jku SSRF
      re('\\.header\\s*\\(\\s*["\']jku["\']'),
      re('jku.*https?://'),
      // x5u
      re('x5u.*https?://'),
    ],
    excludePatterns: [
      // kid from a hard-coded map is fine
      re('kid\\s*=\\s*["\'][^"\']*["\']'),
      re('KidLookup\\b'),
    ],
    recommendation:
      'Do not use kid/jku/x5u from untrusted tokens without strict validation. If kid is used for key selection, maintain a server-side key map and never use the kid value directly in file paths. Disable jku/x5u unless absolutely required.',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'jwt',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // NOSQL INJECTION  (CWE-943)
  // ═══════════════════════════════════════════════════════════════════════════

  // 24 ─ MongoDB $where + user-controlled input
  {
    id: 'SAST-TP-NOSQL-MONGO-WHERE',
    name: 'MongoDB NoSQL Injection via $where',
    description:
      'MongoDB $where clause with user-controlled input allows JavaScript code injection. An attacker can inject arbitrary JavaScript that executes inside the database.',
    severity: 'critical',
    cweId: 'CWE-943',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript', 'python'],
    patterns: [
      re('\\$where\\s*:\\s*(?:req\\.|request\\.|params\\.|body\\.)'),
      re('\\{\\s*\\$where\\s*:'),
      re('\\$where\\s*:\\s*`'),
      re('\\$where\\s*:\\s*function'),
    ],
    excludePatterns: [
      // Hardcoded string $where is less risky
      re('\\$where\\s*:\\s*["\'][^"\']*["\']'),
    ],
    recommendation:
      'Never use $where with user input. Use MongoDB aggregation operators ($expr, $regex, $match) for dynamic queries. Validate and sanitize all query parameters with a schema validation library (Joi, Zod, mongoose schemas).',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'nosql',
  },

  // 25 ─ MongoDB find(req.body) — direct user input to query
  {
    id: 'SAST-TP-NOSQL-MONGO-FIND',
    name: 'MongoDB NoSQL Injection via Unsanitized Query',
    description:
      'Passing user input directly to find()/findOne()/update() without sanitization allows NoSQL injection. Attackers can inject operators like $ne, $gt, $regex to bypass authentication or extract data.',
    severity: 'critical',
    cweId: 'CWE-943',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript', 'python'],
    patterns: [
      re('\\.find\\s*\\(\\s*(?:req\\.body|req\\.query|req\\.params|request\\.json|request\\.args)\\s*\\)'),
      re('\\.findOne\\s*\\(\\s*(?:req\\.body|req\\.query|req\\.params|request\\.json|request\\.args)\\s*\\)'),
      re('\\.update(?:One|Many)?\\s*\\(\\s*(?:req\\.body)'),
      re('\\.delete(?:One|Many)?\\s*\\(\\s*(?:req\\.body)'),
    ],
    excludePatterns: [
      // If there's a sanitize/validate function call first
      re('sanitize|validate|filter|pick\\s*\\('),
    ],
    recommendation:
      'Never pass req.body (or any raw user input) directly to MongoDB queries. Use mongoose schemas with strict validation, or explicitly pick allowed fields. Strip $-prefixed keys from user input objects (mongo-sanitize or express-mongo-sanitize).',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'nosql',
  },

  // 26 ─ MongoDB $regex from input
  {
    id: 'SAST-TP-NOSQL-MONGO-REGEX',
    name: 'MongoDB NoSQL Injection via $regex',
    description:
      'User input passed to MongoDB $regex operator can be used for blind data exfiltration by timing the response of different regex patterns character by character.',
    severity: 'high',
    cweId: 'CWE-943',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript', 'python'],
    patterns: [
      re('\\$regex\\s*:\\s*(?:req\\.|request\\.|params\\.|body\\.)'),
      re('\\$regex\\s*:\\s*new\\s+RegExp\\s*\\('),
      re('\\$regex\\s*:\\s*`'),
    ],
    excludePatterns: [
      re('\\$regex\\s*:\\s*["\'][^"\']*["\']'), // hardcoded regex string
    ],
    recommendation:
      'Escape user input before passing to $regex (escape-string-regexp). Prefer exact-match queries. If regex search is required, set a timeout on the query and rate-limit the endpoint.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'nosql',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // GRAPHQL  (CWE-200,  CWE-770)
  // ═══════════════════════════════════════════════════════════════════════════

  // 27 ─ GraphQL introspection enabled in production
  {
    id: 'SAST-TP-GRAPHQL-INTROSPECTION',
    name: 'GraphQL: Introspection Enabled',
    description:
      'GraphQL introspection is enabled in what appears to be a production configuration. Introspection exposes the entire schema to unauthenticated users, aiding attackers in crafting targeted queries.',
    severity: 'medium',
    cweId: 'CWE-200',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    patterns: [
      re('introspection\\s*:\\s*true'),
      re('graphiql\\s*:\\s*true'),
      re('graphqlHTTP\\s*\\(\\s*\\{[^}]*graphiql\\s*:\\s*true'),
      re('playground\\s*:\\s*true'),
    ],
    excludePatterns: [
      // Dev-only guard
      re('(?:NODE_ENV|ENVIRONMENT|DEBUG|IS_DEV|isDevelopment|development)\\s*(?:!==?\\s*["\']production["\']|===?\\s*["\']development["\'])'),
      re('if\\s*\\(\\s*(?:process\\.env\\.NODE_ENV|env)\\s*!==\\s*["\']production["\']'),
    ],
    recommendation:
      'Disable GraphQL introspection in production by setting introspection: false (Apollo Server) or using a production-only plugin. If introspection is needed for monitoring, require authentication and consider per-IP allow-listing.',
    cvssScore: 6.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    category: 'graphql',
  },

  // 28 ─ No depth/complexity limit on GraphQL queries
  {
    id: 'SAST-TP-GRAPHQL-NO-LIMITS',
    name: 'GraphQL: Missing Query Depth / Complexity Limits',
    description:
      'The GraphQL server is configured without depth or complexity limits (or uses very high defaults). Malicious nested/alias queries can cause denial of service.',
    severity: 'medium',
    cweId: 'CWE-770',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    patterns: [
      // Absence of depth/complexity plugins or settings
      re('ApolloServer\\s*\\(\\s*\\{[^}]{0,500}\\}'),
      re('new\\s+ApolloServer\\s*\\(\\s*\\{'),
    ],
    excludePatterns: [
      re('(?:validationRules|validationRules|depthLimit|complexity|maxDepth|queryDepth)\\s*[=:}]'),
      re('graphql-depth-limit'),
      re('graphql-query-complexity'),
      re('graphql-cost-analysis'),
    ],
    recommendation:
      'Add query depth limiting (graphql-depth-limit, max_depth in Graphene, or maxQueryDepth in Apollo). Add query complexity analysis (graphql-query-complexity). Set reasonable limits: depth 5-10, complexity 1000-5000 depending on your schema.',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
    category: 'graphql',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // GO-SPECIFIC  (gosec-inspired rules)
  // ═══════════════════════════════════════════════════════════════════════════

  // 29 ─ Go fmt.Sprintf → SQL
  {
    id: 'SAST-TP-GO-SQLI-SPRINTF',
    name: 'Go: SQL Injection via fmt.Sprintf in DB Query',
    description:
      'Using fmt.Sprintf() to build SQL queries passed to db.Query/db.Exec/db.QueryRow allows SQL injection if any format arguments come from user input.',
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['go'],
    patterns: [
      re('fmt\\.Sprintf\\s*\\(\\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)\\b'),
      re('fmt\\.Sprintf\\s*\\(\\s*["\'][^"\']*(?:FROM|WHERE)\\b.*\\)\\s*\\)\\s*;?\\s*(?:db|DB|database|sqlDB)\\.(?:Query|Exec|QueryRow)'),
    ],
    excludePatterns: [
      // fmt.Sprintf that builds column/table names without user input
    ],
    recommendation:
      'Use placeholders with db.Query("SELECT ... WHERE id = $1", userInput). Never use fmt.Sprintf to inject values into SQL. For dynamic column/table names, use a strict allow-list.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'go-security',
  },

  // 30 ─ Go exec.Command + user input
  {
    id: 'SAST-TP-GO-CMDI-EXEC',
    name: 'Go: Command Injection via exec.Command with User Input',
    description:
      'Constructing an exec.Command with user-controlled input in the command name or arguments can lead to arbitrary command execution.',
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['go'],
    patterns: [
      re('exec\\.Command\\s*\\(\\s*(?:r\\.(?:URL\\.Query|Form|PostForm)|c\\.(?:Query|Param|FormValue|PostForm))'),
      re('exec\\.Command\\s*\\(\\s*[^,)]*fmt\\.Sprintf'),
      // exec.Command called with variable built from HTTP request
      re('exec\\.Command\\s*\\(\\s*\\w+\\s*,?\\s*.*(?:r\\.|c\\.|req\\.)'),
    ],
    excludePatterns: [
      // Static string commands
      re('exec\\.Command\\s*\\(\\s*"[^"]*"\\s*,\\s*"[^"]*"'),
    ],
    recommendation:
      'Use exec.Command with only hardcoded command names. Pass arguments as separate array elements. Avoid shell invocation — exec.Command does not invoke the shell by default. Sanitize user input before using in arguments.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'go-security',
  },

  // 31 ─ Go math/rand for tokens/auth
  {
    id: 'SAST-TP-GO-WEAK-RAND',
    name: 'Go: Weak Random Generator Used for Security',
    description:
      'math/rand is not cryptographically secure. Using it for tokens, session IDs, passwords, or cryptographic keys produces predictable values.',
    severity: 'high',
    cweId: 'CWE-338',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['go'],
    patterns: [
      re('math/rand'),
      re('rand\\.(?:Intn?|Float|Read|Perm|Shuffle|ExpFloat64|NormFloat64)\\s*\\('),
    ],
    excludePatterns: [
      // crypto/rand import means they're using secure rand
      re('crypto/rand'),
      // Exclude if crypto/rand is imported in same file (approx check)
    ],
    recommendation:
      'Use crypto/rand for security-sensitive random values. Replace rand.Intn(n) with crypto/rand.Int(rand.Reader, max). For random strings, use crypto/rand.Read to fill a byte slice and encode with base64.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'go-security',
  },

  // 32 ─ Go http.Get(userURL) SSRF
  {
    id: 'SAST-TP-GO-SSRF',
    name: 'Go: SSRF via http.Get with User-Controlled URL',
    description:
      'Passing a user-controlled URL to http.Get(), http.Post(), or any http.Client method allows attackers to make requests to internal services.',
    severity: 'high',
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
    languages: ['go'],
    patterns: [
      re('http\\.Get\\s*\\(\\s*(?:r\\.(?:URL\\.Query|Form|PostForm)|c\\.(?:Query|Param|FormValue|PostForm))'),
      re('http\\.Post(?:Form)?\\s*\\(\\s*[^,]*,\\s*[^,]*,\\s*(?:r\\.|c\\.)'),
      re('http\\.Client\\{\\}\\s*\\.\\s*(?:Get|Post|Do)\\s*\\(\\s*.*(?:r\\.|c\\.|req\\.)'),
      re('\\.(?:Get|Post|Do)\\s*\\(\\s*.*(?:r\\.URL|r\\.Form|c\\.Query|c\\.Param)'),
    ],
    excludePatterns: [
      // With URL parsing and host validation
      re('url\\.Parse|isValidURL|ValidateHost|allowlist|allowedHost'),
    ],
    recommendation:
      'Validate URLs against an allow-list of permitted hosts. Parse the URL with url.Parse and check the Host field before making the request. Block internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8).',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    category: 'go-security',
  },

  // 33 ─ Go tls.Config InsecureSkipVerify: true
  {
    id: 'SAST-TP-GO-TLS-SKIP',
    name: 'Go: TLS Certificate Verification Disabled',
    description:
      'tls.Config{InsecureSkipVerify: true} disables TLS certificate validation, making HTTPS connections vulnerable to man-in-the-middle attacks.',
    severity: 'medium',
    cweId: 'CWE-295',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['go'],
    patterns: [
      re('InsecureSkipVerify\\s*:\\s*true'),
      re('tls\\.Config\\s*\\{[^}]*InsecureSkipVerify\\s*:\\s*true'),
    ],
    excludePatterns: [
      re('InsecureSkipVerify\\s*:\\s*false'),
      // Exclude commented-out code
    ],
    recommendation:
      'Never set InsecureSkipVerify: true in production. For development, use properly-signed certificates (Let\'s Encrypt, mkcert for localhost). If you must use self-signed certs, add the CA explicitly to the system trust store rather than disabling verification.',
    cvssScore: 5.9,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'go-security',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // RUST-SPECIFIC
  // ═══════════════════════════════════════════════════════════════════════════

  // 34 ─ Rust Command::new + user input
  {
    id: 'SAST-TP-RUST-CMDI',
    name: 'Rust: Command Injection via std::process::Command',
    description:
      'std::process::Command::new() with user-controlled input as the command name or unsanitized arguments can execute arbitrary system commands.',
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['rust'],
    patterns: [
      re('Command::new\\s*\\(\\s*(?:req|request|params|input|body|query|user)\\w*'),
      re('Command::new\\s*\\(\\s*[^)]*\\.(?:to_str|as_str|to_string)\\s*\\('),
      re('\\.arg\\s*\\(\\s*(?:req|request|params|input|body|user)\\w*'),
      re('Command::new\\s*\\(\\s*[^)]*format!'),
    ],
    excludePatterns: [
      // Hardcoded string
      re('Command::new\\s*\\(\\s*"[^"]*"'),
    ],
    recommendation:
      'Never use user input as the command name in Command::new(). Use a fixed command and pass sanitized arguments via .arg(). Avoid shell interpretation — Rust\'s Command does not invoke the shell by default.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'rust-security',
  },

  // 35 ─ Rust unsafe block around FFI with external data
  {
    id: 'SAST-TP-RUST-UNSAFE-FFI',
    name: 'Rust: Unsafe FFI with Untrusted Data',
    description:
      'An unsafe block passes data from an external (user-controlled) source to an FFI function call. Unsafe blocks disable Rust\'s memory safety guarantees and FFI functions are especially dangerous.',
    severity: 'high',
    cweId: 'CWE-242',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['rust'],
    patterns: [
      re('unsafe\\s*\\{[^}]{0,300}(?:req|request|input|body|user|stdin|read|recv)\\w*[^}]{0,300}\\}'),
      re('unsafe\\s*\\{[^}]{0,100}(?:libc|ffi|extern\\s+"C")'),
    ],
    excludePatterns: [
      // Known-safe FFI patterns
      re('unsafe\\s*\\{[^}]{0,50}(?:as_ptr|from_raw_parts|transmute)\\s*\\('),
    ],
    recommendation:
      'Wrap all unsafe FFI calls in safe abstractions that validate inputs before entering the unsafe block. Use bound-checked slices. Validate all data crossing the FFI boundary. Consider using safer FFI libraries (jni-rs, wasm-bindgen, pyo3) that handle many safety concerns.',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'rust-security',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // CI / SUPPLY CHAIN  (GitHub Actions)
  // ═══════════════════════════════════════════════════════════════════════════

  // 36 ─ GitHub Actions pull_request_target + checkout of PR ref
  {
    id: 'SAST-TP-CI-PR-TARGET-CHECKOUT',
    name: 'GitHub Actions: pull_request_target with PR Checkout',
    description:
      'pull_request_target runs in the context of the BASE repository (with access to secrets) but checking out the PR ref gives the attacker\'s code access to those secrets. This is the most dangerous Actions misconfiguration.',
    severity: 'critical',
    cweId: 'CWE-269',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['yaml'],
    patterns: [
      re('pull_request_target'),
    ],
    excludePatterns: [
      // Safe when NOT checking out PR code — only running trusted workflows
      re('ref\\s*:\\s*(?:refs/heads/(?:main|master|develop|release)|\\${{\\s*(?:github\\.event\\.repository\\.default_branch|github\\.ref_name)\\s*}})'),
    ],
    recommendation:
      'Do not use pull_request_target with actions/checkout of the PR ref (ref: ${{ github.event.pull_request.head.sha }}). Use pull_request instead (which runs without secret access). If pull_request_target is required, only run trusted, script-less actions and never check out PR code.',
    cvssScore: 9.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    category: 'ci-cd',
  },

  // 37 ─ GitHub Actions ${{ github.event.* }} in run: (script injection)
  {
    id: 'SAST-TP-CI-SCRIPT-INJECTION',
    name: 'GitHub Actions: Script Injection via Untrusted Event Data',
    description:
      'Using ${{ github.event.* }} directly in a run: block allows attackers to inject shell commands through pull request titles, issue comments, commit messages, or other event-controlled data.',
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['yaml'],
    patterns: [
      re('run\\s*:\\s*\\|?\\s*[^\\n]*\\$\\{\\{\\s*github\\.event\\.'),
      re('run\\s*:\\s*\\|?\\s*[^\\n]*\\$\\{\\{\\s*github\\.event\\.(?:pull_request|issue_comment|discussion|review|check_run|check_suite|deployment|release|push|workflow_dispatch\\.inputs)'),
    ],
    excludePatterns: [
      // Safe: using env context or intermediate variables with proper quoting
      re('\\$\\{\\{\\s*env\\.'),
      re('\\$\\{\\{\\s*(?:steps|needs|matrix|vars)\\.'),
    ],
    recommendation:
      'Never use ${{ github.event.* }} directly in run: blocks. Instead, assign event values to environment variables first, then reference them as shell variables. Use actions/github-script for JavaScript processing of event data.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    category: 'ci-cd',
  },

  // 38 ─ Unpinned GitHub Actions (uses: ...@main)
  {
    id: 'SAST-TP-CI-UNPINNED-ACTIONS',
    name: 'GitHub Actions: Unpinned Action Version',
    description:
      'Actions referenced by branch name (e.g., @main, @master) rather than a pinned commit SHA allow supply-chain attacks if the action repository is compromised.',
    severity: 'medium',
    cweId: 'CWE-1104',
    owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
    languages: ['yaml'],
    patterns: [
      re('uses\\s*:\\s*[^@\\s]+@(?:main|master|develop|latest|v\\d+)\\s*$', 'm'),
      re('uses\\s*:\\s*[^@\\s]+@(?:main|master|develop|latest)\\b'),
    ],
    excludePatterns: [
      // Pinned by commit SHA
      re('uses\\s*:\\s*[^@\\s]+@[0-9a-f]{40}\\b'),
      // GitHub's own actions pinned to a tag — lower risk (but ideally pin SHA)
      re('uses\\s*:\\s*actions/'),
      // Docker actions reference image tags, not branches
      re('uses\\s*:\\s*docker://'),
    ],
    recommendation:
      'Pin all GitHub Actions to a full-length commit SHA: uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683. Use tools like step-security/secure-workflows or Renovate with pinDigests to automate this.',
    cvssScore: 5.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L',
    category: 'ci-cd',
  },
];
