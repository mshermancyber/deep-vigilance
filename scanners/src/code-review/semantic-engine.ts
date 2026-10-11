// ============================================================
// Semantic Code Review Engine
// Deep semantic analysis across 30+ languages
// Null dereferences, race conditions, logic errors, memory leaks,
// integer overflow, auth flaws, business logic issues, and more.
// ============================================================

import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger.js';

// ---- Types ----

export interface SemanticRule {
  id: string;
  name: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  languages: string[];
  description: string;
  cweId: string;
  owaspCategory: string;
  cvssScore: number;
  cvssVector: string;
  patterns: RegExp[];       // Primary detection patterns
  contextPatterns?: RegExp[]; // Context that increases confidence
  excludePatterns?: RegExp[]; // Patterns that indicate false positives
  languagePatterns?: Record<string, RegExp[]>;       // Language-specific detection patterns (merged with base)
  languageExcludePatterns?: Record<string, RegExp[]>; // Language-specific exclude patterns (merged with base)
  languageContextPatterns?: Record<string, RegExp[]>; // Language-specific confidence boosters
  recommendation: string;
  aiSummary?: string;
}

export interface SemanticFinding {
  ruleId: string;
  ruleName: string;
  category: string;
  findingType: 'semantic' | 'security' | 'quality' | 'performance' | 'logic' | 'architecture';
  title: string;
  description: string;
  severity: string;
  severityRank: number;
  confidenceScore: number;
  falsePositiveProbability: number;
  filePath: string;
  lineNumber: number;
  lineRange: string;
  columnNumber?: number;
  functionName?: string;
  className?: string;
  codeSnippet: string;
  contextSnippet: string;
  cweId: string;
  owaspCategory: string;
  cvssScore: number;
  cvssVector: string;
  recommendation: string;
  language: string;
  aiSummary?: string;
  rootCause?: string;
  securityImpact?: string;
  exploitabilityAssessment?: string;
  secureCodeExample?: string;
}

// ---- Constants ----

const SEVERITY_RANK: Record<string, number> = {
  critical: 1, high: 2, medium: 3, low: 4, info: 5,
};

const FILE_EXT_LANGUAGE: Record<string, string> = {
  '.c': 'c', '.h': 'c',
  '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp', '.hxx': 'cpp',
  '.cs': 'csharp',
  '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin', '.scala': 'scala',
  '.py': 'python', '.pyi': 'python',
  '.go': 'go',
  '.rs': 'rust',
  '.swift': 'swift', '.m': 'objective-c', '.mm': 'objective-c',
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript',
  '.jsx': 'javascript',
  '.php': 'php', '.phtml': 'php',
  '.rb': 'ruby',
  '.pl': 'perl', '.pm': 'perl',
  '.sh': 'bash', '.bash': 'bash',
  '.ps1': 'powershell', '.psm1': 'powershell',
  '.sql': 'sql',
  '.tf': 'terraform', '.tfvars': 'terraform',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.json': 'json',
  'Dockerfile': 'dockerfile', '.dockerfile': 'dockerfile',
  'helm': 'helm',
  '.ansible': 'ansible',
};

const IGNORED_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv', 'vendor',
  '.next', '.nuxt', 'dist', 'build', 'target', '.idea', '.vscode',
  'coverage', '.nyc_output', 'bower_components', '.tox', '.eggs',
  'Pods', 'Carthage', '.build', 'bin', 'obj', 'Debug', 'Release',
]);

// ---- Semantic Analysis Rules ----

const SEMANTIC_RULES: SemanticRule[] = [
  // ============ NULL / NIL DEREFERENCES ============
  {
    id: 'SEM-NULL-001',
    name: 'Potential Null Pointer Dereference',
    category: 'null-safety',
    severity: 'high',
    languages: ['c', 'cpp', 'java', 'csharp', 'kotlin', 'swift', 'go', 'typescript', 'rust'],
    description: 'Variable accessed without null check after being assigned or compared',
    cweId: 'CWE-476',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    patterns: [
      // Java/C#: method called on potentially null
      /(\w+)\s*!=\s*null[\s\S]{0,100}\1\.\w+\(/,
      // C/C++: dereference after null check
      /if\s*\(\s*\w+\s*!=\s*(?:NULL|nullptr)\s*\)[\s\S]{0,200}\*\w+/,
      // Go: nil check followed by dereference
      /if\s+\w+\s*!=\s*nil\s*\{[\s\S]{0,200}\w+\.\w+/,
      // Kotlin: force unwrap
      /(\w+)!!/,
    ],
    contextPatterns: [
      /(?:null|nil|nullptr|None)/i,
      /Optional/,
      /\?\./,
    ],
    languageExcludePatterns: {
      java: [
        /Optional\.\w+/,
        /Objects\.requireNonNull/,
        /assertNotNull/,
        /@NonNull|@Nonnull|@NotNull/,
        /!=\s*null\s*\)\s*\{/,
        /@Test\b|@Before\b|@After\b/,
        /[/\\]test[s]?[/\\]/,
      ],
      kotlin: [
        /\?\./,
        /\?:/,
        /\blet\s*\{/,
        /\?.let\s*\{/,
      ],
      typescript: [
        /\?\./,
        /\?\?/,
        /!\./,
        /as\s+\w+/,
        /[/\\]test[s]?[/\\]/,
        /\.spec\.\w+$/,
      ],
      go: [
        /if\s+err\s*!=\s*nil/,
        /if\s+\w+\s*==\s*nil\s*\{\s*return/,
      ],
    },
    recommendation: 'Always check for null/nil before dereferencing. Use Optional types (Java), ?. operator (TS/Swift/Kotlin), Option<T> (Rust), or guard clauses.',
  },

  // ============ RACE CONDITIONS ============
  {
    id: 'SEM-RACE-001',
    name: 'Potential Race Condition',
    category: 'concurrency',
    severity: 'high',
    languages: ['java', 'csharp', 'go', 'python', 'javascript', 'typescript', 'rust', 'cpp'],
    description: 'Shared mutable state accessed without proper synchronization',
    cweId: 'CWE-362',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 7.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
    patterns: [
      // Go: goroutine with shared variable
      /go\s+func\s*\([^)]*\)[\s\S]{0,100}\{[\s\S]{0,300}(?:shared|global|cache|state)\w*/,
      // Java: unsynchronized access
      /(?:public|private)\s+(?:static\s+)?\w+\s+\w+\s*;[\s\S]{0,100}(?:synchronized|volatile|Atomic|Lock)/,
      // Python: threading without lock
      /threading\.Thread[\s\S]{0,200}(?:Lock|RLock|Semaphore)/,
      // JS/TS: async without await on shared state
      /async\s+function[\s\S]{0,200}(?:\.push\(|\.pop\(|\.splice\(|=\s*\{)/,
      // General: shared counter increment without atomic
      /(\w+)\s*=\s*\1\s*\+\s*1[\s\S]{0,50}(?:mutex|lock|atomic|synchronized)/,
    ],
    contextPatterns: [
      /(?:goroutine|thread|async|concurrent|parallel)/i,
      /(?:sync\.Mutex|sync\.RWMutex|ReentrantLock|lock\(\))/,
    ],
    recommendation: 'Use proper synchronization primitives: mutexes, locks, atomic operations, channels (Go), or concurrent data structures.',
  },

  // ============ MEMORY LEAKS ============
  {
    id: 'SEM-MEM-001',
    name: 'Potential Memory Leak',
    category: 'memory',
    severity: 'high',
    languages: ['c', 'cpp', 'objective-c', 'java', 'csharp'],
    description: 'Dynamically allocated memory not freed, or resources not closed',
    cweId: 'CWE-401',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 6.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    patterns: [
      // C/C++: malloc/new without free/delete
      /(?:malloc|calloc|realloc)\s*\([^)]+\)(?![\s\S]{0,500}free\s*\(\w+\))/,
      /new\s+\w+\s*\[[^\]]*\](?![\s\S]{0,500}delete\s*\[\s*\])/,
      // Java: unclosed resources (only specific I/O types, not collections)
      /new\s+(?:FileInputStream|FileOutputStream|BufferedReader|BufferedWriter|Connection|PreparedStatement|ResultSet)\s*\((?![\s\S]{0,300}(?:try\s*\(|\.close\(\)|finally))/,
      // C#: IDisposable not in using
      /new\s+(?:SqlConnection|FileStream|StreamReader|HttpClient)\s*\((?![\s\S]{0,200}using\b)/,
    ],
    excludePatterns: [
      /try\s*\(\s*\w+\s+\w+\s*=\s*new\b/,
      /try\s*\{[\s\S]{0,50}new\b/,
      /using\s*\(\s*(?:var|new)\b/,
      /\bdefer\s/,
      /\.close\s*\(\)/,
      /\btest_|\bTest\b|@Test\b|@Before|@After|setUp|tearDown/,
    ],
    contextPatterns: [
      /(?:free|delete|dispose|close|using|try-with-resources|defer)/,
      /(?:weak|WeakReference|WeakPtr)/,
    ],
    languageExcludePatterns: {
      java: [
        /try\s*\(/,
        /@Bean\b/,
        /@Autowired\b/,
        /@Component\b|@Service\b|@Repository\b|@Controller\b/,
        /@Resource\b/,
        /\breturn\s+new\b/,
        /=\s*new\s+\w+[\s\S]{0,50}\.close\s*\(\)/,
        /(?:AutoCloseable|Closeable)\b/,
        /[/\\]test[s]?[/\\]/,
        /\bfinal\s+\w+\s+\w+\s*=\s*new\b/,
        /\bprivate\s+(?:static\s+)?final\b/,
      ],
      csharp: [
        /\busing\s+var\b/,
        /\busing\s*\(/,
        /IDisposable/,
        /\.Dispose\s*\(\)/,
      ],
    },
    recommendation: 'Always free/delete allocated memory. Use RAII (C++), try-with-resources (Java), using (C#), defer (Go), or drop (Rust).',
  },

  // ============ INTEGER OVERFLOW ============
  {
    id: 'SEM-INT-001',
    name: 'Potential Integer Overflow',
    category: 'numeric',
    severity: 'high',
    languages: ['c', 'cpp', 'java', 'csharp', 'go', 'rust', 'solidity', 'javascript', 'typescript'],
    description: 'Arithmetic operation may overflow without bounds checking',
    cweId: 'CWE-190',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    patterns: [
      // Arithmetic on user-controlled input
      /(?:req\.|request\.|params\.|input\.|user\.)\w+\s*\+\s*\d+/,
      // Cast from larger to smaller type
      /\(u?int(?:8|16|32)\)\s*\w+/,
      // Multiplication without checked
      /(\w+)\s*\*\s*(\w+)(?![\s\S]{0,100}(?:checked|overflow|saturating))/,
      // Array index calculation
      /\[\s*\w+\s*\+\s*\w+\s*\]/,
      // Size calculation
      /(?:malloc|calloc|alloca)\s*\(\s*\w+\s*\*\s*\w+\s*\)/,
    ],
    contextPatterns: [
      /(?:SafeMath|checked|wrapping|saturating|overflow)/,
      /(?:BigInteger|BigInt|SafeInt)/,
    ],
    languageExcludePatterns: {
      javascript: [
        /\[\s*\w+\s*\+\s*(?:1|2)\s*\]/,
        /\.length\s*[\-+]\s*\d+/,
        /\[\s*(?:i|j|k|idx|index|offset)\s*\+\s*\w+\s*\]/,
        /(?:Math\.|parseInt|parseFloat|Number\()/,
        /\bcss\b|\bstyle\b|\bwidth\b|\bheight\b|\bpadding\b|\bmargin\b/i,
        /\bpx\b|\bem\b|\brem\b/,
        /[/\\]test[s]?[/\\]/,
      ],
      typescript: [
        /\[\s*\w+\s*\+\s*(?:1|2)\s*\]/,
        /\.length\s*[\-+]\s*\d+/,
        /\[\s*(?:i|j|k|idx|index|offset)\s*\+\s*\w+\s*\]/,
        /(?:Math\.|parseInt|parseFloat|Number\()/,
        /\bcss\b|\bstyle\b|\bwidth\b|\bheight\b|\bpadding\b|\bmargin\b/i,
        /[/\\]test[s]?[/\\]/,
      ],
      java: [
        /\[\s*(?:i|j|k)\s*\+\s*(?:1|2)\s*\]/,
        /\.size\s*\(\)\s*[\-+]\s*\d+/,
        /\.length\s*[\-+]\s*\d+/,
        /@Test\b/,
        /[/\\]test[s]?[/\\]/,
      ],
    },
    recommendation: 'Use checked arithmetic operations. Validate input ranges. Use safe math libraries: SafeMath (Solidity), checked (C#), saturating_ (Rust).',
  },

  // ============ LOGIC ERRORS ============
  {
    id: 'SEM-LOGIC-001',
    name: 'Suspicious Logic — Always True/False Condition',
    category: 'logic',
    severity: 'medium',
    languages: ['all'],
    description: 'Condition that always evaluates to the same value',
    cweId: 'CWE-570',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 5.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
    patterns: [
      /if\s*\(\s*true\s*\)/,
      /if\s*\(\s*false\s*\)/,
      /while\s*\(\s*true\s*\)\s*\{[\s\S]{0,50}\}/,
      /(?<![.\w])(\w+)\s*==\s*\1\b(?!\s*\()/,
      /(?<![.\w])(\w+)\s*!=\s*\1\b(?!\s*\()/,
      /if\s*\(\s*(?:0|1)\s*\)/,
      /(?:&&|\|\|)\s*(?:true|false)\s*(?:&&|\|\|)/,
    ],
    excludePatterns: [
      /\bdef\s+test_/,
      /\bclass\s+\w+Test/,
      /assert\w*\s*\(/,
      /\.assertEqual\s*\(/,
      /\b(?:self|this)\.\w+\s*==\s*(?:self|this)\.\w+/,
      /==\s*(?:None|null|nil|undefined)\b/,
      /!=\s*(?:None|null|nil|undefined)\b/,
      /^\s*(?:#|\/\/|\*|\/\*)\s*.*(==|!=)/,
      /(?:since|because|note|comment|explanation|SQL)\b[\s\S]{0,50}(?:==|!=)/i,
    ],
    recommendation: 'Review the condition logic. Remove impossible branches. Use static analysis to verify control flow.',
  },

  {
    id: 'SEM-LOGIC-002',
    name: 'Assignment in Conditional Expression',
    category: 'logic',
    severity: 'medium',
    languages: ['c', 'cpp', 'java', 'csharp', 'javascript', 'typescript'],
    description: 'Assignment operator used where equality comparison likely intended',
    cweId: 'CWE-481',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 5.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
    patterns: [
      /if\s*\(\s*\w+\s*=[^=!>]/,
      /while\s*\(\s*\w+\s*=[^=!>]/,
    ],
    excludePatterns: [
      /if\s*\(\s*\(\s*\w+\s*=\s*\w+/,
      /while\s*\(\s*\(\s*\w+\s*=\s*\w+/,
      /if\s*\(\s*\w+\s*=\s*await\b/,
      /while\s*\(\s*\w+\s*=\s*await\b/,
      /=>\s*\{/,
      /:\s*\w+\s*=/,
    ],
    languageExcludePatterns: {
      javascript: [
        /while\s*\(\s*\w+\s*=\s*\w+\.exec\s*\(/,
        /if\s*\(\s*\w+\s*=\s*\w+\.exec\s*\(/,
        /while\s*\(\s*\w+\s*=\s*\w+\.match\s*\(/,
        /if\s*\(\s*\w+\s*=\s*\w+\.match\s*\(/,
        /while\s*\(\s*\w+\s*=\s*\w+\.next\s*\(/,
        /if\s*\(\s*\w+\s*=\s*\w+\.shift\s*\(/,
        /[/\\]test[s]?[/\\]/,
      ],
      typescript: [
        /while\s*\(\s*\w+\s*=\s*\w+\.exec\s*\(/,
        /if\s*\(\s*\w+\s*=\s*\w+\.exec\s*\(/,
        /while\s*\(\s*\w+\s*=\s*\w+\.match\s*\(/,
        /if\s*\(\s*\w+\s*=\s*\w+\.match\s*\(/,
        /[/\\]test[s]?[/\\]/,
      ],
      c: [
        /while\s*\(\s*\w+\s*=\s*\w+\s*\(/,
        /if\s*\(\s*\w+\s*=\s*(?:fgets|fread|read|recv)\s*\(/,
      ],
      cpp: [
        /while\s*\(\s*\w+\s*=\s*\w+\s*\(/,
        /if\s*\(\s*\w+\s*=\s*(?:fgets|fread|read|recv)\s*\(/,
        /while\s*\(\s*(?:std::)?getline\s*\(/,
      ],
    },
    recommendation: 'Use == or === for comparison. If assignment is intentional, wrap in extra parentheses and add a comment.',
  },

  // ============ OFF-BY-ONE ERRORS ============
  {
    id: 'SEM-OBO-001',
    name: 'Potential Off-By-One Error',
    category: 'logic',
    severity: 'medium',
    languages: ['all'],
    description: 'Loop boundary or array index looks off by one',
    cweId: 'CWE-193',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 5.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
    patterns: [
      /for\s*\(\s*(?:let|var|int|size_t|auto)\s+\w+\s*=\s*0\s*;\s*\w+\s*<=\s*\w+\.length/,
      /for\s*\(\s*(?:let|var|int|size_t|auto)\s+\w+\s*=\s*1\s*;\s*\w+\s*<\s*\w+\.length/,
      /\.substring?\s*\(\s*\d+\s*,\s*\w+\.length\s*-\s*1\s*\)/,
      /\[\s*\w+\.length\s*\]/,
      /<\s*\w+\.length\s*-\s*1\s*;/,
    ],
    languageExcludePatterns: {
      javascript: [
        /\.at\s*\(\s*-1\s*\)/,
        /\.slice\s*\(/,
        /\.splice\s*\(/,
        /Array\.from\s*\(/,
        /\.forEach\s*\(/,
        /\.map\s*\(/,
        /\.filter\s*\(/,
        /[/\\]test[s]?[/\\]/,
      ],
      typescript: [
        /\.at\s*\(\s*-1\s*\)/,
        /\.slice\s*\(/,
        /\.forEach\s*\(/,
        /\.map\s*\(/,
        /\.filter\s*\(/,
        /[/\\]test[s]?[/\\]/,
      ],
      java: [
        /\.subList\s*\(/,
        /\.iterator\s*\(\)/,
        /for\s*\(\s*\w+\s+\w+\s*:\s*\w+\)/,
        /[/\\]test[s]?[/\\]/,
      ],
      python: [
        /\brange\s*\(\s*len\s*\(/,
        /\bfor\s+\w+\s+in\s+/,
        /\benumerate\s*\(/,
      ],
    },
    recommendation: 'Review loop boundaries. Use zero-based indexing consistently. Consider using for-each or range-based loops.',
  },

  // ============ UNSAFE CASTING ============
  {
    id: 'SEM-CAST-001',
    name: 'Unsafe Type Cast',
    category: 'type-safety',
    severity: 'medium',
    languages: ['java', 'csharp', 'c', 'cpp', 'kotlin'],
    description: 'Type cast without proper checking may cause ClassCastException or undefined behavior',
    cweId: 'CWE-704',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 5.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L',
    patterns: [
      /\(\s*\w+\s*\)\s*\w+(?!\s+instanceof)/,
      /reinterpret_cast\s*</,
      /static_cast\s*<[^>]*>\s*\(\s*\w+\s*\)/,
      /\.cast\s*\(\s*\w+::class\s*\)/,
      /as!\s+\w+/,
    ],
    languageExcludePatterns: {
      java: [
        /\(\s*(?:int|long|short|byte|char|float|double|boolean)\s*\)/,
        /\(\s*(?:String|Object|Integer|Long|Double|Boolean|Number)\s*\)\s*(?:this|super|null)\b/,
        /instanceof\s+\w+[\s\S]{0,100}\(\s*\w+\s*\)/,
        /\(\s*(?:Map|List|Set|Collection|Iterable|Iterator|Comparable|Serializable)\s*(?:<[^>]*>)?\s*\)/,
        /\(\s*\w+(?:<[^>]*>)?\s*\)\s*(?:get|remove|poll|peek|pop|next|clone)\s*\(/,
        /@SuppressWarnings\s*\(\s*"unchecked"\s*\)/,
        /@Override/,
        /\breturn\s+\(\s*\w+\s*\)/,
        /\btest\w*\s*\(/i,
        /[/\\]test[s]?[/\\]/,
      ],
      csharp: [
        /\(\s*(?:int|long|short|byte|char|float|double|bool|string|object)\s*\)/,
        /\bas\s+\w+/,
        /is\s+\w+\s+\w+/,
      ],
    },
    recommendation: 'Use instanceof/type checks before casting. Prefer pattern matching (Java 16+, C# 7+). Use safe cast (as?) in Kotlin.',
  },

  // ============ EXCEPTION HANDLING ============
  {
    id: 'SEM-EXC-001',
    name: 'Empty or Overly Broad Exception Handler',
    category: 'error-handling',
    severity: 'medium',
    languages: ['java', 'csharp', 'python', 'javascript', 'typescript', 'php', 'ruby', 'cpp'],
    description: 'Exception caught but silently ignored, or catching overly broad exception types',
    cweId: 'CWE-390',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 4.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
    patterns: [
      /catch\s*\(\s*\w+\s+\w+\s*\)\s*\{[\s\n\r]*\}/,
      /catch\s*\(\s*Exception\s+\w+\s*\)/,
      /except\s*:\s*\n\s*pass/,
      /catch\s*\{[\s\n\r]*\}/,
      /rescue\s*=>\s*\w+\s*\n\s*end/,
      /catch\s*\(\s*\.\.\.\s*\)\s*\{\s*\}/,
    ],
    languageExcludePatterns: {
      java: [
        /@ExceptionHandler\b/,
        /@ControllerAdvice\b/,
        /catch\s*\(\s*Exception\s+\w+\s*\)\s*\{[\s\S]{0,100}(?:log|LOG|logger|LOGGER)\./,
        /catch\s*\(\s*Exception\s+\w+\s*\)\s*\{[\s\S]{0,100}(?:throw|return)/,
        /@Override\s+[\s\S]{0,50}catch/,
        /[/\\]test[s]?[/\\]/,
        /@Test\b/,
      ],
      python: [
        /except\s+\w+Error\b/,
        /except\s+\w+Exception\b/,
        /except\s+\(\w+,\s*\w+\)/,
        /logging\.\w+\s*\(/,
        /logger\.\w+\s*\(/,
      ],
      javascript: [
        /catch\s*\(\s*\w+\s*\)\s*\{[\s\S]{0,100}(?:console\.|log|throw|return)/,
        /\.catch\s*\(/,
        /[/\\]test[s]?[/\\]/,
      ],
      typescript: [
        /catch\s*\(\s*\w+\s*(?::\s*\w+)?\s*\)\s*\{[\s\S]{0,100}(?:console\.|log|throw|return)/,
        /\.catch\s*\(/,
        /[/\\]test[s]?[/\\]/,
      ],
    },
    recommendation: 'Catch specific exception types. Log exceptions with context. Never swallow exceptions silently. Add proper error recovery.',
  },

  // ============ AUTHENTICATION FLAWS ============
  {
    id: 'SEM-AUTH-001',
    name: 'Missing Authorization Check',
    category: 'authentication',
    severity: 'critical',
    languages: ['java', 'csharp', 'python', 'javascript', 'typescript', 'php', 'ruby', 'go', 'kotlin'],
    description: 'Endpoint or function performs sensitive operation without authorization verification',
    cweId: 'CWE-862',
    owaspCategory: 'A01:2021 - Broken Access Control',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    patterns: [
      /(?:@PostMapping|@GetMapping|@RequestMapping)[\s\S]{0,200}(?!.*@PreAuthorize)/,
      /(?:app\.(?:post|put|delete|patch)\s*\(\s*["'][^"']+["'][\s\S]{0,200}(?!.*auth|token|session|permission))/i,
      /router\.(?:post|put|delete)\s*\(\s*["'][^"']+["'][\s\S]{0,200}(?!.*middleware|auth|guard)/,
    ],
    excludePatterns: [
      /_auth_check|verify_token|check_permission|require_auth|login_required|Depends\s*\(/i,
      /auth|guard|middleware|@PreAuthorize|@Secured|@RolesAllowed/i,
      /@router\.get\s*\(\s*["']\/(?:health|status|ping|metrics|docs|openapi)/i,
      /def\s+(?:get_|list_|fetch_|read_)\w+/,
    ],
    languageExcludePatterns: {
      java: [
        /@Secured\b/,
        /@PreAuthorize\b/,
        /@RolesAllowed\b/,
        /@WithMockUser\b/,
        /SecurityContext/,
        /WebSecurityConfigurerAdapter/,
        /HttpSecurity/,
        /@Configuration\b/,
        /@GetMapping\b/,
        /[/\\]test[s]?[/\\]/,
        /@Test\b/,
        /@SpringBootTest\b/,
        /actuator/i,
      ],
      python: [
        /login_required/,
        /permission_required/,
        /@permission_classes/,
        /IsAuthenticated/,
        /has_perm\s*\(/,
      ],
      javascript: [
        /passport\./,
        /jwt\./,
        /requireAuth/i,
        /isAuthenticated/i,
      ],
    },
    recommendation: 'Add authorization middleware/guard to all sensitive endpoints. Use declarative authorization (@PreAuthorize, @RequirePermission). Implement deny-by-default.',
  },

  {
    id: 'SEM-AUTH-002',
    name: 'Broken Object-Level Authorization',
    category: 'authentication',
    severity: 'critical',
    languages: ['java', 'csharp', 'python', 'javascript', 'typescript', 'php', 'ruby', 'go'],
    description: 'Resource ID accepted without verifying ownership or access rights',
    cweId: 'CWE-639',
    owaspCategory: 'A01:2021 - Broken Access Control',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    patterns: [
      /req\.(?:params|query|body)\.(?:id|userId|accountId|orderId)/i,
      /@PathVariable\s*(?:\w+\s+)?(?:id|userId|accountId)/i,
      /request\.args\.get\s*\(\s*["'](?:id|user_id)["']/,
      /\.findById\s*\(\s*req\./,
      /SELECT.*WHERE\s+id\s*=\s*\$\d+(?!.*AND\s+org_id)/i,
    ],
    recommendation: 'Verify resource ownership before access. Add organization/project context to all queries. Use indirect object references.',
  },

  // ============ BUSINESS LOGIC FLAWS ============
  {
    id: 'SEM-BIZ-001',
    name: 'Missing Input Validation on Business-Critical Data',
    category: 'business-logic',
    severity: 'high',
    languages: ['all'],
    description: 'Business-critical input accepted without validation (price, quantity, amount, role)',
    cweId: 'CWE-20',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H',
    patterns: [
      /(?:price|amount|quantity|balance|role|permission|status)\s*=\s*req\.(?:body|query|params)/i,
      /(?:setPrice|setAmount|setQuantity|setRole)\s*\(\s*req\./i,
      /(?:price|amount|quantity)\s*:\s*req\./i,
      /\$\w+\s*=\s*\$_(?:POST|GET|REQUEST)\s*\[\s*["'](?:price|amount|role)/i,
    ],
    recommendation: 'Validate all business-critical inputs. Use allowlists for roles/statuses. Validate value ranges. Server-side validation is mandatory.',
  },

  // ============ TRUST BOUNDARY ============
  {
    id: 'SEM-TRUST-001',
    name: 'Trust Boundary Violation',
    category: 'trust-boundary',
    severity: 'high',
    languages: ['java', 'csharp', 'python', 'javascript', 'typescript', 'php', 'ruby', 'go'],
    description: 'Data crossing trust boundary without validation or sanitization',
    cweId: 'CWE-501',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    patterns: [
      /req\.(?:body|query|params)\.\w+\s*(?:;|\n|\}|\))/,
      /session\.(?:set|put)\s*\(\s*["']\w+["']\s*,\s*req\./i,
      /cookie\s*\[\s*["']\w+["']\s*\]\s*=\s*req\./i,
      /localStorage\.setItem\s*\(\s*["']\w+["']\s*,\s*req\./i,
    ],
    recommendation: 'Validate and sanitize all data crossing trust boundaries. Never trust client-side data. Implement server-side validation.',
  },

  // ============ UNREACHABLE CODE ============
  {
    id: 'SEM-DEAD-001',
    name: 'Unreachable Code Detected',
    category: 'quality',
    severity: 'low',
    languages: ['all'],
    description: 'Code that can never be executed',
    cweId: 'CWE-561',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 2.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    patterns: [
      /return\s+\w+\s*;\s*\n\s*(?![\s})\]]*(?:$|\/\/|\/\*|else|catch|finally|case|default))\w+\s*[^;]*;/,
      /throw\s+new\s+\w+\s*\([^)]*\)\s*;\s*\n\s*(?![\s})\]]*(?:$|\/\/|\/\*|else|catch|finally|case|default))\w+/,
    ],
    excludePatterns: [
      /\.min\./,
      /-bundle\./,
      /\.bundle\./,
      /vendor[/\\]/,
      /\bif\s*\([\s\S]{0,200}(?:return|throw)\b/,
      /\bswitch\s*\(/,
      /\bcase\s+/,
    ],
    recommendation: 'Remove unreachable code. It adds confusion and may hide bugs.',
  },

  // ============ RESOURCE LEAKS ============
  {
    id: 'SEM-RES-001',
    name: 'Resource Leak — Unclosed Handle',
    category: 'resource',
    severity: 'medium',
    languages: ['python', 'java', 'csharp', 'javascript', 'typescript', 'go', 'php'],
    description: 'File handle, socket, or database connection not properly closed',
    cweId: 'CWE-404',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 5.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
    patterns: [
      /\.(?:open|connect|acquire)\s*\((?![\s\S]{0,300}(?:close|disconnect|release|\.close\(\))\s*)/,
      /new\s+(?:Socket|HttpClient|WebSocket)\s*\(/,
      /socket\.socket\s*\(/,
      /\.createConnection\s*\(/,
    ],
    excludePatterns: [
      /def\s+_?(?:connect|get_conn|create_pool|init_db)\b/,
      /return\s+(?:conn|connection|pool|client|db)\b/,
      /with\s+[\w.]+\.open\s*\(/,
      /with\s+\w+\.\w+\s*\(/,
      /with\s+\w+\s+as\s/,
      /async\s+with\s/,
      /try[\s\S]{0,200}finally[\s\S]{0,100}\.close\(\)/,
      /\.connect\s*\(\s*\w+[\s\S]{0,30}(?:signal|handler|callback|listener|slot|receiver|on_|dispatch)/,
      /(?:signal|Signal|signals|event|Event)\s*[\.\(][\s\S]{0,50}\.connect\s*\(/,
      /\.connect\s*\(\s*(?:self\.\w+|lambda|on_\w+|handle_\w+|func)\s*[,)]/,
      /\w+(?:_finished|_changed|_saved|_deleted|_sent|_received|_started|_ready|_init|_update)\.connect\s*\(/,
      /(?:pre_save|post_save|pre_delete|post_delete|pre_init|post_init|pre_migrate|post_migrate|request_started|request_finished|setting_changed|connection_created|got_request_exception)\.connect\s*\(/,
      /\.disconnect\s*\(/,
      /addEventListener\s*\(/,
      /\.on\s*\(\s*['"`]/,
      /\bdef\s+(?:test_|ready\b)/,
      /\bclass\s+\w+(?:Test|Config|Apps?)\b/,
      /\bdef\s+__(?:enter|exit)__\b/,
      /os\.open\s*\(/,
      /window\.open\s*\(/,
      /super\(\)\.open\s*\(/,
      /[/\\]tests?[/\\]/,
      /return\s+super\(\)\./,
    ],
    languageExcludePatterns: {
      python: [
        /with\s+(?:open|io\.open)\s*\(/,
        /with\s+[\w.]+\s+as\s+\w+\s*:/,
        /contextmanager/,
        /@contextmanager/,
        /def\s+__(?:enter|exit|del)__/,
        /\.close\s*\(\)/,
        /atexit\.register/,
      ],
      java: [
        /try\s*\(/,
        /@Bean\b/,
        /@Autowired\b/,
        /(?:AutoCloseable|Closeable)\b/,
        /\.close\s*\(\)/,
        /finally\s*\{/,
        /[/\\]test[s]?[/\\]/,
      ],
      go: [
        /defer\s+\w+\.Close\s*\(\)/,
        /defer\s+func\s*\(\)/,
        /defer\s+\w+\(/,
      ],
      javascript: [
        /\.on\s*\(\s*['"](?:close|end|finish|error)['"]/,
        /\.destroy\s*\(\)/,
        /\.end\s*\(\)/,
        /process\.on\s*\(/,
        /\.pipe\s*\(/,
        /[/\\]test[s]?[/\\]/,
        /\.(?:spec|test)\.\w+$/,
      ],
      typescript: [
        /\.on\s*\(\s*['"](?:close|end|finish|error)['"]/,
        /\.destroy\s*\(\)/,
        /\.end\s*\(\)/,
        /using\s+/,
        /[/\\]test[s]?[/\\]/,
        /\.(?:spec|test)\.\w+$/,
      ],
    },
    recommendation: 'Use context managers (Python with), try-with-resources (Java), using (C#), defer (Go). Always close resources.',
  },

  // ============ INFINITE LOOP RISK ============
  {
    id: 'SEM-LOOP-001',
    name: 'Potential Infinite Loop',
    category: 'logic',
    severity: 'medium',
    languages: ['all'],
    description: 'Loop condition that may never become false',
    cweId: 'CWE-835',
    owaspCategory: 'A04:2021 - Insecure Design',
    cvssScore: 5.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
    patterns: [
      /while\s*\(\s*1\s*\)/,
      /while\s*\(\s*true\s*\)(?![\s\S]{0,500}break)/,
      /for\s*\(\s*;\s*;\s*\)(?![\s\S]{0,500}break)/,
      /while\s*True\s*:(?![\s\S]{0,500}(?:break|return|yield|raise))/,
    ],
    excludePatterns: [
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,500}(?:await|return|page\s*[+=]|offset\s*[+=])/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,500}(?:receive_|recv|accept|listen|sleep)/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,500}(?:yield\b|yield\s+from\b)/,
      /def\s+\w+\s*\([^)]*\)\s*(?:->[\s\S]{0,30})?:\s*[\s\S]{0,100}while\s*True/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,200}(?:try|except|catch)\b/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,200}input\s*\(/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,200}(?:imap|next\s*\(|__next__|\.get\s*\()/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,200}(?:shouldStop|is_set|\.wait\s*\()/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,200}(?:\.decode\s*\(|StopIteration)/,
      /page\s*=\s*\d+[\s\S]{0,100}while\s*True/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,300}(?:page\s*\+|page\s*=\s*page|offset\s*\+|cursor)/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,300}(?:callback_count|run_on_commit)/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,300}(?:escaped|token|parse|sqlparse)/,
      /while\s*(?:True|\(\s*true\s*\))[\s\S]{0,300}(?:_catalog|translation|fallback)/,
      /def\s+(?:tick|run_forever|serve_forever|main_loop|event_loop)\s*\(/,
      /\bdef\s+test_/,
      /\bclass\s+\w+Test/,
      /[/\\]tests?[/\\]/,
      /[/\\]scripts[/\\]/,
    ],
    languageExcludePatterns: {
      python: [
        /async\s+def\s+\w+[\s\S]{0,200}while\s*True/,
        /asyncio\.\w+/,
        /\bawait\b/,
        /signal\.signal\s*\(/,
      ],
      javascript: [
        /while\s*\(\s*true\s*\)[\s\S]{0,200}(?:await|setTimeout|setInterval|requestAnimationFrame)/,
        /while\s*\(\s*true\s*\)[\s\S]{0,200}\.read\s*\(/,
        /new\s+Promise/,
        /[/\\]test[s]?[/\\]/,
      ],
      typescript: [
        /while\s*\(\s*true\s*\)[\s\S]{0,200}(?:await|setTimeout|setInterval)/,
        /while\s*\(\s*true\s*\)[\s\S]{0,200}\.read\s*\(/,
        /[/\\]test[s]?[/\\]/,
      ],
      go: [
        /for\s*\{[\s\S]{0,200}(?:select\s*\{|<-|time\.Sleep)/,
        /for\s*\{[\s\S]{0,200}(?:ctx\.Done|context\.)/,
      ],
      java: [
        /while\s*\(\s*true\s*\)[\s\S]{0,200}(?:Thread\.sleep|wait\s*\(|take\s*\(|poll\s*\()/,
        /while\s*\(\s*true\s*\)[\s\S]{0,200}(?:\.accept\s*\(|ServerSocket)/,
        /[/\\]test[s]?[/\\]/,
        /@Test\b/,
      ],
    },
    recommendation: 'Ensure loop has a termination condition that eventually becomes false. Add maximum iteration counters for safety.',
  },
];

// ---- Engine ----

export function getLanguage(filePath: string): string | null {
  const basename = path.basename(filePath);
  const ext = path.extname(filePath);

  if (FILE_EXT_LANGUAGE[basename]) return FILE_EXT_LANGUAGE[basename]!;
  if (FILE_EXT_LANGUAGE[ext]) return FILE_EXT_LANGUAGE[ext]!;

  // Dockerfile detection
  if (/^Dockerfile(\..+)?$/.test(basename)) return 'dockerfile';

  return null;
}

export function shouldAnalyzeFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const parts = normalized.split('/');

  for (const part of parts) {
    if (IGNORED_DIRS.has(part)) return false;
  }

  // Skip binary extensions
  const binaryExts = ['.exe', '.dll', '.so', '.dylib', '.bin', '.zip', '.tar', '.gz',
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.ttf', '.eot', '.pdf'];
  const ext = path.extname(filePath).toLowerCase();
  if (binaryExts.includes(ext)) return false;

  // Skip generated/minified/bundled files
  if (normalized.includes('.generated.') || normalized.includes('.min.') ||
      normalized.endsWith('-lock.json') || normalized.endsWith('.lock') ||
      normalized.includes('-bundle.') || normalized.includes('.bundle.') ||
      normalized.includes('.chunk.') || normalized.includes('.packed.') ||
      /\bvendor[/\\]/.test(normalized) || /\bthird[_-]?party[/\\]/.test(normalized)) {
    return false;
  }
  const basename = path.basename(filePath);
  if (/\.min\.\w+$/.test(basename) || /[-.]bundle\.\w+$/.test(basename)) {
    return false;
  }

  return true;
}

export function analyzeFileSemantic(
  filePath: string,
  content: string,
  language: string,
): SemanticFinding[] {
  const findings: SemanticFinding[] = [];
  const lines = content.split('\n');

  const applicableRules = SEMANTIC_RULES.filter(
    r => r.languages.includes('all') || r.languages.includes(language),
  );

  for (const rule of applicableRules) {
    const langPatterns = rule.languagePatterns?.[language];
    const allPatterns = langPatterns ? [...rule.patterns, ...langPatterns] : rule.patterns;

    for (const pattern of allPatterns) {
      pattern.lastIndex = 0;

      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx]!;
        pattern.lastIndex = 0;

        // Also check multi-line context (up to 5 lines)
        const context = lines.slice(lineIdx, Math.min(lines.length, lineIdx + 5)).join('\n');

        let match: RegExpExecArray | null;
        const testTarget = pattern.flags.includes('s') ? context : line;
        pattern.lastIndex = 0;
        match = pattern.exec(testTarget);

        if (!match) continue;

        // Check exclude patterns against wider context (10 lines) so
        // multi-line excludes can see surrounding code
        const excludeContext = lines.slice(lineIdx, Math.min(lines.length, lineIdx + 10)).join('\n');
        const langExcludes = rule.languageExcludePatterns?.[language];
        const allExcludes = langExcludes
          ? [...(rule.excludePatterns || []), ...langExcludes]
          : rule.excludePatterns;
        if (allExcludes) {
          let isExcluded = false;
          for (const exclude of allExcludes) {
            exclude.lastIndex = 0;
            if (exclude.test(excludeContext)) {
              isExcluded = true;
              break;
            }
          }
          if (isExcluded) continue;
        }

        // Calculate confidence based on context patterns
        let confidenceScore = 0.55; // Base confidence
        const langCtx = rule.languageContextPatterns?.[language];
        const allContextPatterns = langCtx
          ? [...(rule.contextPatterns || []), ...langCtx]
          : rule.contextPatterns;
        if (allContextPatterns) {
          const contextMatch = allContextPatterns.filter(p => {
            p.lastIndex = 0;
            return p.test(context);
          }).length;
          confidenceScore += contextMatch * 0.15;
        }
        confidenceScore = Math.min(0.98, confidenceScore);

        // Calculate false positive probability
        const falsePositiveProb = +(1 - confidenceScore).toFixed(2);

        const contextStart = Math.max(0, lineIdx - 3);
        const contextEnd = Math.min(lines.length, lineIdx + 5);
        const contextSnippet = lines.slice(contextStart, contextEnd).join('\n');
        const codeSnippet = contextSnippet.slice(0, 500);

        // Extract function name
        let functionName: string | undefined;
        const funcMatch = context.match(/(?:func|function|def|fn|public\s+\w+\s+)\s*(\w+)\s*\(/);
        if (funcMatch) functionName = funcMatch[1];

        // Extract class name
        let className: string | undefined;
        const classMatch = context.match(/class\s+(\w+)/);
        if (classMatch) className = classMatch[1];

        // AI summary
        const aiSummary = buildAISummary(rule, language, match[0]);

        // Security impact
        const securityImpact = buildSecurityImpact(rule);

        // Exploitability
        const exploitabilityAssessment = buildExploitability(rule);

        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          findingType: mapCategoryToFindingType(rule.category),
          title: `${rule.name} in ${path.basename(filePath)}`,
          description: rule.description,
          severity: rule.severity,
          severityRank: SEVERITY_RANK[rule.severity] || 3,
          confidenceScore: +confidenceScore.toFixed(2),
          falsePositiveProbability: falsePositiveProb,
          filePath,
          lineNumber: lineIdx + 1,
          lineRange: `${contextStart + 1}-${contextEnd}`,
          functionName,
          className,
          codeSnippet,
          contextSnippet: contextSnippet.slice(0, 300),
          cweId: rule.cweId,
          owaspCategory: rule.owaspCategory,
          cvssScore: rule.cvssScore,
          cvssVector: rule.cvssVector,
          recommendation: rule.recommendation,
          language,
          aiSummary,
          rootCause: `The code at line ${lineIdx + 1} contains a pattern matching ${rule.name.toLowerCase()}.`,
          securityImpact,
          exploitabilityAssessment,
          secureCodeExample: buildSecureExample(rule, language),
        });
      }
    }
  }

  return findings;
}

// ---- Helper Functions ----

function mapCategoryToFindingType(category: string): SemanticFinding['findingType'] {
  const mapping: Record<string, SemanticFinding['findingType']> = {
    'null-safety': 'semantic',
    'concurrency': 'performance',
    'memory': 'quality',
    'numeric': 'semantic',
    'logic': 'logic',
    'type-safety': 'semantic',
    'error-handling': 'quality',
    'authentication': 'security',
    'business-logic': 'logic',
    'trust-boundary': 'security',
    'quality': 'quality',
    'resource': 'quality',
  };
  return mapping[category] || 'semantic';
}

function buildAISummary(rule: SemanticRule, language: string, match: string): string {
  const snippets: Record<string, string> = {
    'null-safety': `The code at this location dereferences a value that may be null/nil. In ${language}, this could lead to a NullPointerException/panic at runtime.`,
    'concurrency': `A shared mutable state is accessed from concurrent execution contexts without visible synchronization. This is a classic data race pattern.`,
    'memory': `Dynamically allocated memory or resource handle appears to lack a corresponding deallocation/close call, potentially causing a memory/resource leak over time.`,
    'numeric': `An arithmetic operation involving user-controlled or unbounded values could overflow the target type, leading to unexpected behavior or security bypass.`,
    'logic': `The conditional expression contains a logic pattern that may not behave as expected. Review the boolean logic carefully.`,
    'authentication': `A sensitive operation is performed without verifying the caller's authorization. This could allow unauthorized access to protected resources.`,
    'business-logic': `Business-critical input is accepted from an untrusted source without validation, potentially allowing manipulation of business rules.`,
    'trust-boundary': `Data is crossing a trust boundary from an untrusted source to a trusted context without proper validation.`,
  };

  for (const [key, summary] of Object.entries(snippets)) {
    if (rule.category.includes(key) || rule.id.toLowerCase().includes(key)) {
      return summary;
    }
  }

  return `The pattern "${match.slice(0, 80)}" matches a known ${rule.category} anti-pattern that could lead to ${rule.severity}-severity issues.`;
}

function buildSecurityImpact(rule: SemanticRule): string {
  if (rule.severity === 'critical') {
    return 'This finding could allow an unauthenticated attacker to compromise the system, access sensitive data, or execute arbitrary code. Immediate remediation is strongly recommended.';
  }
  if (rule.severity === 'high') {
    return 'This finding could allow an attacker to bypass security controls, access unauthorized data, or cause denial of service. Prioritize remediation within the current sprint.';
  }
  if (rule.severity === 'medium') {
    return 'This finding may contribute to a larger attack chain or degrade system reliability. Remediate within the current development cycle.';
  }
  return 'This finding has limited security impact but should be addressed to maintain code quality standards.';
}

function buildExploitability(rule: SemanticRule): string {
  if (rule.cweId.startsWith('CWE-8') || rule.cweId.startsWith('CWE-9')) {
    return 'High exploitability — these vulnerability classes are commonly exploited in the wild. Automated tools exist to detect and exploit this pattern.';
  }
  if (['CWE-476', 'CWE-190', 'CWE-362', 'CWE-401'].includes(rule.cweId)) {
    return 'Medium exploitability — exploitation typically requires specific conditions but can lead to serious impact when triggered.';
  }
  return 'Lower direct exploitability — this is more of a code quality or defense-in-depth issue, but could contribute to a larger vulnerability chain.';
}

function buildSecureExample(rule: SemanticRule, language: string): string {
  const examples: Record<string, Record<string, string>> = {
    'null-safety': {
      java: 'if (value != null) {\n    value.doSomething();\n} else {\n    // Handle null case\n}',
      typescript: 'const result = value?.doSomething() ?? defaultValue;',
      go: 'if value != nil {\n    value.DoSomething()\n} else {\n    // Handle nil case\n}',
      python: 'if value is not None:\n    value.do_something()\nelse:\n    # Handle None case',
      default: '// Check for null/nil before dereferencing\nif (value != null) {\n    value.method();\n}',
    },
    'concurrency': {
      java: 'private final ReentrantLock lock = new ReentrantLock();\nlock.lock();\ntry {\n    // Critical section\n} finally {\n    lock.unlock();\n}',
      go: 'var mu sync.Mutex\nmu.Lock()\ndefer mu.Unlock()\n// Critical section',
      typescript: 'const mutex = new Mutex();\nawait mutex.acquire();\ntry {\n    // Critical section\n} finally {\n    mutex.release();\n}',
      default: '// Use proper synchronization\nmutex.lock();\ntry {\n    // Critical section\n} finally {\n    mutex.unlock();\n}',
    },
    'memory': {
      cpp: 'std::unique_ptr<Resource> res = std::make_unique<Resource>();\n// Automatically freed when out of scope',
      java: 'try (var resource = new Resource()) {\n    // Use resource\n} // Auto-closed',
      python: 'with open("file.txt") as f:\n    # Use file\n# Auto-closed',
      default: '// Use RAII or try-with-resources to ensure cleanup\n// Let the language manage resource lifecycle',
    },
  };

  const langExamples = examples[rule.category];
  if (langExamples) {
    return langExamples[language] || langExamples.default || 'See recommendation for language-specific secure implementation.';
  }

  return `// Secure alternative to ${rule.name.toLowerCase()}:\n// Follow best practices: ${rule.recommendation}`;
}

// ---- Batch Analysis ----

export function analyzeDirectorySemantic(
  targetPath: string,
  progressCallback?: (progress: number) => void,
): SemanticFinding[] {
  const allFindings: SemanticFinding[] = [];
  let filesProcessed = 0;

  function collectFiles(dir: string): string[] {
    const files: string[] = [];
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
            files.push(...collectFiles(fullPath));
          }
        } else if (entry.isFile() && shouldAnalyzeFile(fullPath)) {
          files.push(fullPath);
        }
      }
    } catch {
      // Skip permission errors
    }
    return files;
  }

  const files = collectFiles(targetPath);
  const totalFiles = files.length;

  for (const file of files) {
    const language = getLanguage(file);
    if (!language) continue;

    try {
      const content = fs.readFileSync(file, 'utf-8');
      const findings = analyzeFileSemantic(file, content, language);
      allFindings.push(...findings);
    } catch {
      // Skip binary/unreadable files
    }

    filesProcessed++;
    if (progressCallback && totalFiles > 0) {
      progressCallback(Math.floor((filesProcessed / totalFiles) * 100));
    }
  }

  return allFindings;
}

export function getSemanticRules(): SemanticRule[] {
  return SEMANTIC_RULES;
}

export function getRuleById(id: string): SemanticRule | undefined {
  return SEMANTIC_RULES.find(r => r.id === id);
}
