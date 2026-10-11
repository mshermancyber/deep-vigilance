// ============================================================
// Reachability Engine (M25 - Interprocedural Analysis)
// Real call graph construction, framework entry point
// detection, BFS reachability, taint flow tracing, scoring
// ============================================================

import { logger } from '../utils/logger.js';
import type { IRNode } from './ast-engine.js';

// ---------------------------------------------------------------------------
// Types & Interfaces
// ---------------------------------------------------------------------------

/** The nature of a call edge between two functions */
export type CallType = 'direct' | 'virtual' | 'dynamic' | 'callback';

/** Supported web frameworks for entry point detection */
export type FrameworkType =
  | 'spring'
  | 'express'
  | 'django'
  | 'aspnet'
  | 'go-http'
  | 'lambda'
  | 'unknown';

/**
 * A vertex in the call graph.
 *
 * - `callees` is a Map from callee function name to the type of call.
 * - `callers` is a simple array (call type is captured in the callee's Map,
 *   so reverse edges don't duplicate it).
 * - `distance` is the number of call-chain hops from the nearest entry point
 *   (-1 means unreachable, 0 means entry point itself).
 * - `importSource` records the module from which this function was imported
 *   (empty string = defined in the current module).
 */
export interface CallGraphNode {
  functionName: string;
  filePath: string;
  lineNumber: number;
  callees: Map<string, CallType>;
  callers: string[];
  isEntryPoint: boolean;
  isReachable: boolean;
  distance: number;
  importSource: string;
  metadata?: Record<string, unknown>;
}

/** Parsed import statement */
export interface ImportRecord {
  sourcePath: string;
  localNames: string[];
  isDefault: boolean;
  isNamespace: boolean;
  lineNumber: number;
}

/** Result of computed reachability analysis */
export interface ReachabilityResult {
  entryPoints: string[];
  totalFunctions: number;
  reachableFunctions: number;
  deadFunctions: string[];
  reachabilityMap: Map<string, { isReachable: boolean; distance: number }>;
  averageDistance: number;
  maxDistance: number;
}

/** A discovered taint flow from a source function to a sink function */
export interface TaintFlow {
  sourceFunction: string;
  sinkFunction: string;
  path: string[];
  pathHops: number;
  sanitizersOnPath: string[];
  sanitizerBreak: boolean;
  riskScore: number;
  callTypesOnPath: CallType[];
}

/** Input shape for exploitability scoring */
export interface ExploitabilityInput {
  cvssScore: number;
  cweId?: string;
  severity?: string;
}

/** Reachability snapshot for a single finding */
export interface FindingReachability {
  isReachable: boolean;
  distance: number;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Returned by the function-def collection phase */
interface FnDefInfo {
  name: string;
  filePath: string;
  lineNumber: number;
  importSource: string;
}

/**
 * Walk the AST and collect every FunctionDef node along with its metadata.
 */
function collectFunctionDefs(nodes: IRNode[], basePath: string): FnDefInfo[] {
  const defs: FnDefInfo[] = [];
  const seen = new Set<string>();

  function walk(node: IRNode): void {
    if (node.type === 'FunctionDef' && node.name) {
      if (!seen.has(node.name)) {
        seen.add(node.name);
        const src = (node.metadata?.importSource as string) || '';
        defs.push({
          name: node.name,
          filePath: basePath,
          lineNumber: node.lineNumber,
          importSource: src,
        });
      }
    }
    for (const child of node.children) {
      walk(child);
    }
  }

  for (const n of nodes) walk(n);
  return defs;
}

/**
 * Walk the AST and collect every Import node.
 */
function collectImports(nodes: IRNode[]): ImportRecord[] {
  const records: ImportRecord[] = [];

  function walk(node: IRNode): void {
    if (node.type === 'Import' && node.name) {
      const rawNames = (node.metadata?.importedNames as string[]) ?? [];
      const names = rawNames.length > 0
        ? rawNames
        : (node.children
            .filter(c => c.type === 'Literal' && c.name)
            .map(c => c.name!));

      const isDefault = (node.metadata?.isDefault as boolean) ?? false;
      const isNamespace = (node.metadata?.isNamespace as boolean) ?? false;

      records.push({
        sourcePath: node.name,
        localNames: isDefault
          ? names.length > 0 ? [names[0]!] : []
          : names,
        isDefault,
        isNamespace,
        lineNumber: node.lineNumber,
      });
    }
    for (const child of node.children) walk(child);
  }

  for (const n of nodes) walk(n);
  return records;
}

/**
 * Given an IR node (typically a CallExpr), determine which function name(s)
 * it might be invoking. Handles dotted names, imported symbols, and
 * ambiguous call targets.
 */
function resolveCalleeNames(
  node: IRNode,
  available: Set<string>,
  imports: ImportRecord[],
): string[] {
  const rawName = node.name ?? '';
  if (!rawName) return [];

  // Build a local-name → original-name map from imports
  const importedLocal = new Map<string, string>();
  for (const imp of imports) {
    for (const ln of imp.localNames) {
      importedLocal.set(ln, ln);
    }
  }

  // Strip leading `new ` for constructor calls
  const cleaned = rawName.replace(/^new\s+/, '');
  const candidates: string[] = [];

  // Full name (e.g. "foo.bar")
  if (available.has(cleaned)) {
    candidates.push(cleaned);
    return candidates;
  }

  // Member expression: check the base (e.g. "obj" from "obj.method")
  let dotBase = '';
  let dotMethod = '';
  const dotIdx = cleaned.indexOf('.');
  if (dotIdx > 0) {
    dotBase = cleaned.substring(0, dotIdx);
    dotMethod = cleaned.substring(dotIdx + 1);

    if (available.has(dotBase)) {
      candidates.push(dotBase);
    }
    if (available.has(dotMethod) && !candidates.includes(dotMethod)) {
      candidates.push(dotMethod);
    }
  }

  // Direct match
  if (available.has(cleaned) && !candidates.includes(cleaned)) {
    candidates.push(cleaned);
  }

  // Check if name is a locally imported symbol
  if (importedLocal.has(cleaned)) {
    // If the original name differs, try it
    const orig = importedLocal.get(cleaned)!;
    if (orig !== cleaned && available.has(orig) && !candidates.includes(orig)) {
      candidates.push(orig);
    }
  }

  // If this is a method call on a parameter (virtual dispatch)
  if (dotIdx > 0 && dotBase && dotMethod) {
    // Check if base looks like a parameter (lowercase / ctx, req, etc.)
    const paramLike = /^[a-z][a-zA-Z0-9]*$/.test(dotBase) && !available.has(dotBase);
    if (paramLike) {
      // We can't resolve it; add a placeholder with 'virtual' hint
      candidates.push(`__virtual__${dotMethod}`);
    }
  }

  return candidates;
}

/**
 * Determine the call type for a CallExpr node.
 */
function classifyCall(node: IRNode, graph: Map<string, CallGraphNode>): CallType {
  const rawName = node.name ?? '';

  // Dynamic call patterns: computed member access, call/apply, dynamic imports
  if (/\[/.test(rawName) || rawName.includes('?.(')) {
    return 'dynamic';
  }
  if (/\.(call|apply|bind)\s*$/.test(rawName)) {
    return 'dynamic';
  }

  // Virtual / interface: member expression where receiver is not a known function
  const dotIdx = rawName.indexOf('.');
  if (dotIdx > 0) {
    const base = rawName.substring(0, dotIdx);
    if (!graph.has(base) && !/^[A-Z]/.test(base)) {
      return 'virtual';
    }
    // Static method on a known class
    if (/^[A-Z]/.test(base) && graph.has(base)) {
      return 'virtual';
    }
  }

  // Callback: if any child is a FunctionDef/ArrowFunc node
  const hasInlineFunc = node.children.some(
    c => c.type === 'FunctionDef' || c.type === 'ArrowFunc',
  );
  if (hasInlineFunc) {
    return 'callback';
  }

  return 'direct';
}

/**
 * Find the enclosing function for a given AST node by line-number proximity.
 * Since AST nodes may be spread across multiple files, we look for the nearest
 * FunctionDef whose line number is <= the node's line number within the same
 * file path.
 */
function findEnclosingFunction(
  node: IRNode,
  graph: Map<string, CallGraphNode>,
  filePath: string,
): string | null {
  let bestName: string | null = null;
  let bestDelta = Infinity;

  for (const [name, gn] of graph) {
    if (gn.filePath !== filePath) continue;
    if (gn.lineNumber <= node.lineNumber) {
      const delta = node.lineNumber - gn.lineNumber;
      if (delta < bestDelta) {
        bestDelta = delta;
        bestName = name;
      }
    }
  }
  return bestName;
}

/**
 * Add a directed edge from `caller` to `callee` in the graph.
 */
function addEdge(
  graph: Map<string, CallGraphNode>,
  caller: string,
  callee: string,
  callType: CallType,
): void {
  const callerNode = graph.get(caller);
  const calleeNode = graph.get(callee);
  if (!callerNode || !calleeNode) return;

  // Add callee to caller's callees (keep the strongest call type)
  const existing = callerNode.callees.get(callee);
  if (!existing) {
    callerNode.callees.set(callee, callType);
  } else {
    // Upgrade: dynamic < callback < virtual < direct
    const rank: Record<CallType, number> = {
      dynamic: 0,
      callback: 1,
      virtual: 2,
      direct: 3,
    };
    if (rank[callType] > rank[existing]) {
      callerNode.callees.set(callee, callType);
    }
  }

  // Add caller to callee's callers (deduplicate)
  if (!calleeNode.callers.includes(caller)) {
    calleeNode.callers.push(caller);
  }
}

// ---------------------------------------------------------------------------
// 1. buildCallGraphFromAST
// ---------------------------------------------------------------------------

/**
 * Construct a real directed call graph from an array of AST IR nodes.
 *
 * Process:
 *  1. Registers every `FunctionDef` as a vertex.
 *  2. Parses `Import` nodes to build a module-import index.
 *  3. Walks every `CallExpr`, resolves the callee name(s), determines the
 *     call type (direct / virtual / dynamic / callback), and adds a directed
 *     edge from the enclosing function to the callee.
 *  4. Resolves cross-file calls by checking import aliases.
 *
 * Returns a Map from function name to `CallGraphNode`.
 */
export function buildCallGraphFromAST(
  astNodes: IRNode[],
  filePath: string = '',
): Map<string, CallGraphNode> {
  const graph = new Map<string, CallGraphNode>();

  // --------------------------------------------------
  // Phase 1: Register FunctionDef vertices
  // --------------------------------------------------
  const defs = collectFunctionDefs(astNodes, filePath);
  for (const fn of defs) {
    graph.set(fn.name, {
      functionName: fn.name,
      filePath: fn.filePath,
      lineNumber: fn.lineNumber,
      callees: new Map(),
      callers: [],
      isEntryPoint: false,
      isReachable: false,
      distance: -1,
      importSource: fn.importSource,
    });
  }

  // --------------------------------------------------
  // Phase 2: Collect import records
  // --------------------------------------------------
  const imports = collectImports(astNodes);

  // Available function names for call resolution
  const availableNames = new Set(graph.keys());

  // --------------------------------------------------
  // Phase 3: Walk CallExpr nodes recursively and add edges
  // --------------------------------------------------
  function walkCallExprs(nodes: IRNode[]): void {
    for (const node of nodes) {
      if (node.type === 'CallExpr' && node.name) {
        // Find the enclosing function for this call
        const enclosingFn = findEnclosingFunction(node, graph, filePath);
        if (!enclosingFn) continue;

        // Resolve what function(s) this call might refer to
        const candidates = resolveCalleeNames(node, availableNames, imports);

        for (const callee of candidates) {
          // Strip virtual prefix used for unresolvable method calls
          const cleanCallee = callee.startsWith('__virtual__')
            ? callee.replace('__virtual__', '')
            : callee;

          // Only add edge if the callee is in our graph
          if (graph.has(cleanCallee)) {
            const callType = classifyCall(node, graph);
            addEdge(graph, enclosingFn, cleanCallee, callType);
          }
        }
      }

      // Recurse into children to find nested CallExpr nodes
      walkCallExprs(node.children);
    }
  }

  walkCallExprs(astNodes);

  // --------------------------------------------------
  // Phase 4: Resolve cross-file import-based calls
  // --------------------------------------------------
  resolveCrossFileCalls(graph, imports, availableNames);

  logger.debug({ functions: graph.size, filePath }, 'Call graph built from AST');
  return graph;
}

/**
 * Augment the call graph by linking imported symbols to functions that are
 * available in the graph under their original names.
 */
function resolveCrossFileCalls(
  graph: Map<string, CallGraphNode>,
  imports: ImportRecord[],
  available: Set<string>,
): void {
  // For each import, if the import source name appears as a function in the
  // graph AND the local alias also exists, we can merge / annotate.
  for (const [funcName, node] of graph) {
    // If a function was imported from another file, find imports that
    // reference it via alias
    for (const imp of imports) {
      if (node.importSource && imp.sourcePath.includes(node.importSource)) {
        // The function's origin matches this import's source
        // Mark the node with cross-file reachability info
        if (!node.metadata?.crossFileResolved) {
          node.metadata = {
            ...(node.metadata || {}),
            crossFileResolved: true,
            importSource: imp.sourcePath,
          };
        }
      }
    }
  }

  // Second pass: for functions that have callers but the callers are not
  // in the graph (i.e., calls from outside the analyzed files), try to link
  // via import-dependency heuristics
  for (const [, node] of graph) {
    if (node.callers.length === 0 && !node.isEntryPoint) {
      // Check if any import statement suggests this function is called
      // from another file
      for (const imp of imports) {
        if (imp.localNames.includes(node.functionName)) {
          // The function is exported/imported, so consider it potentially
          // reachable from outside
          node.callers.push(`<external:${imp.sourcePath}>`);
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// 2. identifyEntryPoints
// ---------------------------------------------------------------------------

/**
 * Scan the AST and call graph for framework-specific HTTP / gRPC / event
 * entry points.
 *
 * For each supported framework, specific patterns are matched:
 *
 * - **Spring**: `@RestController`, `@Controller`, `@GetMapping`, `@PostMapping`,
 *   `@RequestMapping`, `@PutMapping`, `@DeleteMapping`, `@PatchMapping`
 * - **Express**: `app.get()`, `app.post()`, `app.put()`, `app.delete()`,
 *   `app.patch()`, `app.all()`, `app.use()`, `router.get()`, `router.post()`,
 *   etc.  The handler function name is extracted from the last argument.
 * - **Django**: functions or methods referenced in `urlpatterns` lists
 *   containing `path()` / `re_path()` calls.
 * - **ASP.NET**: `[HttpGet]`, `[HttpPost]`, `[HttpPut]`, `[HttpDelete]`,
 *   `[HttpPatch]`, `[ApiController]` on methods / classes.
 * - **Go net/http**: `http.HandleFunc()`, `http.Handle()`, `mux.HandleFunc()`,
 *   `mux.Handle()`, `r.HandleFunc()`, `r.Handle()`, `r.GET()`, `r.POST()`,
 *   etc. (Gin / Echo).
 * - **AWS Lambda**: functions named `handler` or `lambda_handler`, or
 *   `exports.handler =`, `module.exports.handler =`.
 *
 * @param callGraph   The call graph (to validate function names exist).
 * @param framework   The framework to detect (or `unknown` for heuristic).
 * @param astNodes    The raw AST nodes (required for annotation scanning).
 * @param filePath    The source file path (for logging / attribution).
 * @returns           Array of function names that are entry points.
 */
export function identifyEntryPoints(
  callGraph: Map<string, CallGraphNode>,
  framework: FrameworkType,
  astNodes: IRNode[],
  filePath: string = '',
): string[] {
  const entryPoints: string[] = [];
  const graphNames = new Set(callGraph.keys());

  switch (framework) {
    // ----------------------------------------------------------
    case 'spring': {
      const entryClasses = new Set<string>();

      for (const node of astNodes) {
        if (node.type === 'ClassDef' && node.name) {
          const anns = extractAnnotations(node);
          if (anns.some(a => /RestController|Controller/.test(a))) {
            entryClasses.add(node.name);
            // All methods in this class become entry points
            for (const child of node.children) {
              if (child.type === 'FunctionDef' && child.name) {
                addEntry(callGraph, child.name, entryPoints);
              }
            }
          }
        }
      }

      // Also look for annotated methods directly (standalone @RequestMapping etc.)
      for (const node of astNodes) {
        if (node.type === 'FunctionDef' && node.name) {
          const anns = extractAnnotations(node);
          if (anns.some(a => /GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping/.test(a))) {
            addEntry(callGraph, node.name, entryPoints);
          }
        }
      }
      break;
    }

    // ----------------------------------------------------------
    case 'express': {
      // Express: app.get('/path', handlerFn) or router.post('/path', handlerFn)
      // The handler is the last (non-string) argument
      for (const node of astNodes) {
        if (node.type !== 'CallExpr' || !node.name) continue;
        // Match patterns: app.get, app.post, router.get, etc.
        if (/^(app|router|route)\.[a-zA-Z]+$/.test(node.name)) {
          const method = node.name.split('.')[1];
          if (!method) continue;
          const httpMethods = new Set([
            'get', 'post', 'put', 'delete', 'patch', 'all', 'use',
          ]);
          if (!httpMethods.has(method)) continue;

          // Extract handler names from arguments
          for (const child of node.children) {
            if (child.type === 'Literal' && typeof child.value === 'string') continue; // skip path strings
            if (child.type === 'FunctionDef' && child.name) {
              addEntry(callGraph, child.name, entryPoints);
            }
            // Named function reference passed as argument
            if ((child.type as string) === 'Identifier' && child.name && graphNames.has(child.name)) {
              addEntry(callGraph, child.name, entryPoints);
            }
            if (child.type === 'Literal' && child.name && graphNames.has(child.name)) {
              addEntry(callGraph, child.name, entryPoints);
            }
          }
        }
      }
      break;
    }

    // ----------------------------------------------------------
    case 'django': {
      // Django: urlpatterns = [path('...', view_func), ...]
      // Find lists assigned to urlpatterns
      // or @app.route('...') decorators
      let inUrlpatterns = false;

      for (const node of astNodes) {
        if (node.type === 'Assign' && node.name === 'urlpatterns') {
          inUrlpatterns = true;
          // Walk children to find path() / re_path() calls
          for (const child of node.children) {
            if (child.type === 'CallExpr' && child.name) {
              if (/^(path|re_path)$/.test(child.name)) {
                // Second argument is the view function
                const viewArg = child.children[1];
                if (viewArg) {
                  // It might be a named reference
                  const viewName = viewArg.name || viewArg.value || '';
                  if (viewName && graphNames.has(viewName)) {
                    addEntry(callGraph, viewName, entryPoints);
                  }
                  // Or a dotted string "module.views.index"
                  if (viewName && viewName.includes('.')) {
                    const lastPart = viewName.split('.').pop()!;
                    if (graphNames.has(lastPart)) {
                      addEntry(callGraph, lastPart, entryPoints);
                    }
                  }
                }
              }
            }
          }
        }
      }

      // Python decorator pattern: @app.route('/path')
      for (const node of astNodes) {
        if (node.type === 'FunctionDef' && node.name) {
          const decos = (node.metadata?.decorators as string[]) ?? [];
          if (decos.some(d => /\.route\(/.test(d) || /\.add_url_rule/.test(d))) {
            addEntry(callGraph, node.name, entryPoints);
          }
        }
      }
      break;
    }

    // ----------------------------------------------------------
    case 'aspnet': {
      // ASP.NET: [HttpPost], [HttpGet], [ApiController] on classes/methods
      for (const node of astNodes) {
        if (node.type === 'ClassDef' && node.name) {
          const clsAnns = extractAnnotations(node);
          if (clsAnns.some(a => /ApiController|Route/.test(a))) {
            // Controller class: all public methods are potential entry points
            for (const child of node.children) {
              if (child.type === 'FunctionDef' && child.name) {
                const methAnns = extractAnnotations(child);
                if (methAnns.length === 0 || methAnns.some(a => /HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route|AcceptVerbs/.test(a))) {
                  addEntry(callGraph, child.name, entryPoints);
                }
              }
            }
          }
        }
        // Standalone method with [HttpXxx]
        if (node.type === 'FunctionDef' && node.name) {
          const anns = extractAnnotations(node);
          if (anns.some(a => /HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch/.test(a))) {
            addEntry(callGraph, node.name, entryPoints);
          }
        }
      }
      break;
    }

    // ----------------------------------------------------------
    case 'go-http': {
      // Go net/http: http.HandleFunc("/path", handler)
      // Gin: r.GET("/path", handler), r.POST(...)
      // Echo: e.GET("/path", handler)
      for (const node of astNodes) {
        if (node.type !== 'CallExpr' || !node.name) continue;

        const isHttpHandler = /^(http|mux|r|e|router|gin)\.(HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/.test(node.name);
        const isGenericHandler = /\.(HandleFunc|Handle)$/.test(node.name);

        if (isHttpHandler || isGenericHandler) {
          // The handler is typically the last argument
          for (let i = node.children.length - 1; i >= 0; i--) {
            const child = node.children[i]!;
            // Named function reference
            const name = child.name || child.value || '';
            if (name && graphNames.has(name)) {
              addEntry(callGraph, name, entryPoints);
              break;
            }
            // Inline function definition (anonymous)
            if ((child.type === 'FunctionDef' || child.type === 'ArrowFunc') && child.name) {
              addEntry(callGraph, child.name, entryPoints);
              break;
            }
          }
        }
      }
      break;
    }

    // ----------------------------------------------------------
    case 'lambda': {
      // AWS Lambda: handler function, lambda_handler, exports.handler
      for (const [name, node] of callGraph) {
        if (name === 'handler' || name === 'lambda_handler' || name.endsWith('.handler')) {
          node.isEntryPoint = true;
          entryPoints.push(name);
        }
      }
      // Also check for `module.exports = { handler: ... }` or `exports.handler = ...`
      for (const node of astNodes) {
        if (node.type === 'Assign' && node.name) {
          if (/exports\.handler|module\.exports\.handler/.test(node.name)) {
            // The right-hand side might be a function name
            for (const child of node.children) {
              const refName = child.name || child.value || '';
              if (refName && graphNames.has(refName)) {
                addEntry(callGraph, refName, entryPoints);
              }
            }
          }
        }
      }
      break;
    }

    // ----------------------------------------------------------
    case 'unknown':
    default: {
      // Heuristic: common entry point names
      const heuristicNames = [
        'main', 'handler', 'lambda_handler', 'handleRequest',
        'handle', 'serve', 'start', 'run', 'init', 'bootstrap',
        'onRequest', 'onEvent', 'onMessage',
      ];
      for (const name of heuristicNames) {
        if (graphNames.has(name)) {
          addEntry(callGraph, name, entryPoints);
        }
      }
      break;
    }
  }

  // Mark all identified entry points in the call graph
  for (const ep of entryPoints) {
    const node = callGraph.get(ep);
    if (node) {
      node.isEntryPoint = true;
    }
  }

  logger.debug({ entryPoints, framework, filePath }, 'Entry points identified');
  return entryPoints;
}

/**
 * Register a function as an entry point, deduplicating.
 */
function addEntry(
  callGraph: Map<string, CallGraphNode>,
  funcName: string,
  accumulator: string[],
): void {
  if (!accumulator.includes(funcName) && callGraph.has(funcName)) {
    accumulator.push(funcName);
  }
}

/**
 * Extract annotation / decorator strings from an IR node's metadata.
 */
function extractAnnotations(node: IRNode): string[] {
  const results: string[] = [];

  // Check metadata.annotation (C# / Java style)
  const ann = node.metadata?.annotation as string | undefined;
  if (ann) {
    results.push(ann);
  }

  // Check metadata.annotations (array form)
  const anns = node.metadata?.annotations as string[] | undefined;
  if (anns) {
    for (const a of anns) results.push(a);
  }

  // Check metadata.decorator (TS/Python style)
  const dec = node.metadata?.decorator as string | undefined;
  if (dec) {
    results.push(dec);
  }

  // Check metadata.decorators (array form)
  const decs = node.metadata?.decorators as string[] | undefined;
  if (decs) {
    for (const d of decs) results.push(d);
  }

  // Also scan the function name for annotation patterns like @GetMapping
  if (node.name) {
    const matches = node.name.match(/@\w+/g);
    if (matches) results.push(...matches);
  }

  return results;
}

// ---------------------------------------------------------------------------
// 3. computeReachability
// ---------------------------------------------------------------------------

/**
 * Run real BFS from all identified entry points through the call graph to
 * determine which functions are reachable.
 *
 * For each function discovered during BFS, `distance` is set to the number
 * of call-chain hops from the nearest entry point (0 for entry points
 * themselves).  Functions not visited are marked unreachable (distance -1).
 *
 * Returns a `ReachabilityResult` with reachability map, dead function list,
 * and summary statistics.
 */
export function computeReachability(
  callGraph: Map<string, CallGraphNode>,
  entryPoints: string[],
): ReachabilityResult {
  // Initialize / reset reachability state
  for (const [, node] of callGraph) {
    node.isReachable = false;
    node.distance = -1;
  }

  // BFS queue: [functionName, distance]
  const queue: Array<[string, number]> = [];
  const visited = new Set<string>();

  // Seed queue with all entry points (distance 0)
  for (const ep of entryPoints) {
    if (callGraph.has(ep)) {
      queue.push([ep, 0]);
      visited.add(ep);
    }
  }

  // BFS traversal -- real graph exploration, no hardcoded paths
  while (queue.length > 0) {
    const [current, dist] = queue.shift()!;
    const node = callGraph.get(current);
    if (!node) continue;

    node.isReachable = true;
    node.distance = dist;

    for (const calleeName of node.callees.keys()) {
      if (!visited.has(calleeName) && callGraph.has(calleeName)) {
        visited.add(calleeName);
        queue.push([calleeName, dist + 1]);
      }
    }
  }

  // Collect results
  const reachabilityMap = new Map<string, { isReachable: boolean; distance: number }>();
  const deadFunctions: string[] = [];
  let totalDistance = 0;
  let reachableCount = 0;
  let maxDistance = 0;

  for (const [name, node] of callGraph) {
    const info = { isReachable: node.isReachable, distance: node.distance };
    reachabilityMap.set(name, info);

    if (!node.isReachable) {
      deadFunctions.push(name);
    } else {
      totalDistance += node.distance;
      reachableCount++;
      if (node.distance > maxDistance) maxDistance = node.distance;
    }
  }

  const totalFunctions = callGraph.size;
  const averageDistance = reachableCount > 0
    ? Math.round((totalDistance / reachableCount) * 100) / 100
    : 0;

  logger.debug({
    totalFunctions,
    reachableFunctions: reachableCount,
    deadFunctions: deadFunctions.length,
    averageDistance,
    maxDistance,
  }, 'Reachability analysis complete');

  return {
    entryPoints: [...entryPoints],
    totalFunctions,
    reachableFunctions: reachableCount,
    deadFunctions,
    reachabilityMap,
    averageDistance,
    maxDistance,
  };
}

// ---------------------------------------------------------------------------
// 4. traceSourceToSink
// ---------------------------------------------------------------------------

/**
 * For each source-to-sink pair, find all connecting paths through the call
 * graph using BFS / limited DFS.  Checks whether any sanitizer function
 * appears on each path and computes a risk score.
 *
 * Path scoring formula:
 *   riskScore = likelihood * impact * (1 - maxSanitizerStrength)
 *
 * Where:
 *   - likelihood   starts at 1.0, decays with path length and call-type
 *                   uncertainty (virtual/dynamic calls reduce confidence)
 *   - impact       based on sink severity (default 1.0)
 *   - sanitizerStrength  max sanitizer reduction on the path (0-1)
 *
 * @param callGraph   The full call graph.
 * @param sources     Array of source function names (taint origins).
 * @param sinks       Array of sink function names (dangerous operations).
 * @param sanitizers  Array of sanitizer function names (mitigation points).
 * @returns           Array of TaintFlow objects, one per discovered path.
 */
export function traceSourceToSink(
  callGraph: Map<string, CallGraphNode>,
  sources: string[],
  sinks: string[],
  sanitizers: string[],
): TaintFlow[] {
  const flows: TaintFlow[] = [];
  const sanitizerSet = new Set(sanitizers);
  const sinkSet = new Set(sinks);

  // Pre-compute adjacency list for fast iteration
  const adjacency = new Map<string, string[]>();
  for (const [name, node] of callGraph) {
    adjacency.set(name, [...node.callees.keys()]);
  }

  const MAX_PATHS_PER_PAIR = 5;
  const MAX_BFS_DEPTH = 20;

  let flowId = 0;

  for (const source of sources) {
    if (!callGraph.has(source)) continue;

    for (const sink of sinks) {
      if (!callGraph.has(sink)) continue;
      if (source === sink) {
        // Source and sink in the same function
        const callTypes: CallType[] = [];
        const sanitizersOnPath = sanitizerSet.has(source) ? [source] : [];
        const riskScore = computePathRisk(
          1,                     // likelihood (same function = full)
          1.0,                   // impact
          sanitizersOnPath,
          callTypes,
          0,                     // pathHops = 0 (same function)
        );

        flows.push({
          sourceFunction: source,
          sinkFunction: sink,
          path: [source],
          pathHops: 0,
          sanitizersOnPath,
          sanitizerBreak: sanitizersOnPath.length > 0,
          riskScore,
          callTypesOnPath: callTypes,
        });
        flowId++;
        continue;
      }

      // BFS from source to sink, collecting up to MAX_PATHS_PER_PAIR paths
      const foundPaths = bfsFindPaths(
        source,
        sink,
        adjacency,
        MAX_PATHS_PER_PAIR,
        MAX_BFS_DEPTH,
      );

      for (const path of foundPaths) {
        const pathHops = path.length - 1;
        const sanitizersOnPath = path.filter(fn => sanitizerSet.has(fn));
        const callTypesOnPath = extractCallTypesOnPath(path, callGraph);

        // Compute likelihood based on path length and call-type uncertainty
        const likelihood = computePathLikelihood(pathHops, callTypesOnPath);

        // Compute sanitizer strength (max reduction on this path)
        const maxSanitizerStrength = sanitizersOnPath.length > 0
          ? Math.min(0.95, sanitizersOnPath.length * 0.3)
          : 0;

        const riskScore = computePathRisk(
          likelihood,
          1.0,  // impact (default; caller can adjust)
          sanitizersOnPath,
          callTypesOnPath,
          pathHops,
        );

        flows.push({
          sourceFunction: source,
          sinkFunction: sink,
          path,
          pathHops,
          sanitizersOnPath,
          sanitizerBreak: maxSanitizerStrength >= 0.8,
          riskScore,
          callTypesOnPath,
        });
        flowId++;
      }

      // If BFS found no paths but both source and sink exist in the graph,
      // check if they are connected via transitive closure over callers/callees
      if (foundPaths.length === 0) {
        const transitivePath = findTransitivePath(source, sink, adjacency, MAX_BFS_DEPTH);
        if (transitivePath) {
          const pathHops = transitivePath.length - 1;
          const sanitizersOnPath = transitivePath.filter(fn => sanitizerSet.has(fn));
          const callTypesOnPath = extractCallTypesOnPath(transitivePath, callGraph);
          const likelihood = computePathLikelihood(pathHops, callTypesOnPath);
          const maxSanitizerStrength = sanitizersOnPath.length > 0
            ? Math.min(0.95, sanitizersOnPath.length * 0.3)
            : 0;

          const riskScore = computePathRisk(likelihood, 1.0, sanitizersOnPath, callTypesOnPath, pathHops);

          flows.push({
            sourceFunction: source,
            sinkFunction: sink,
            path: transitivePath,
            pathHops,
            sanitizersOnPath,
            sanitizerBreak: maxSanitizerStrength >= 0.8,
            riskScore,
            callTypesOnPath,
          });
          flowId++;
        }
      }
    }
  }

  // Sort by risk score descending (highest-risk flows first)
  flows.sort((a, b) => b.riskScore - a.riskScore);

  logger.debug({ totalFlows: flows.length, sources: sources.length, sinks: sinks.length }, 'Taint flow tracing complete');
  return flows;
}

/**
 * BFS from source to sink, returning up to `maxPaths` distinct paths.
 *
 * Uses a standard BFS with path reconstruction.  To collect multiple paths
 * we allow revisiting nodes on different paths (but not reusing the same
 * full path).
 */
function bfsFindPaths(
  source: string,
  sink: string,
  adjacency: Map<string, string[]>,
  maxPaths: number,
  maxDepth: number,
): string[][] {
  const paths: string[][] = [];
  const visitedEdges = new Set<string>();

  // Each queue entry: [currentNode, pathSoFar]
  const queue: Array<[string, string[]]> = [[source, [source]]];
  const visitedNodesOnThisBranch = new Set<string>();
  visitedNodesOnThisBranch.add(source);

  while (queue.length > 0 && paths.length < maxPaths) {
    const [current, path] = queue.shift()!;

    if (path.length - 1 > maxDepth) continue;

    if (current === sink && path.length > 1) {
      paths.push([...path]);
      continue;
    }

    const neighbors = adjacency.get(current) ?? [];
    for (const next of neighbors) {
      // Skip if adding this would create a cycle within the current branch
      if (path.includes(next)) continue;

      // Track edge to avoid revisiting the same edge in other paths
      const edgeKey = `${current}->${next}`;
      if (visitedEdges.has(edgeKey) && paths.length > 0) continue;

      visitedEdges.add(edgeKey);
      queue.push([next, [...path, next]]);
    }
  }

  return paths;
}

/**
 * Fallback: find a single transitive path using a simpler BFS (without
 * edge-dedup constraints).  This catches cases where the stricter BFS
 * above fails due to cycle pruning.
 */
function findTransitivePath(
  source: string,
  sink: string,
  adjacency: Map<string, string[]>,
  maxDepth: number,
): string[] | null {
  const visited = new Set<string>();
  const predecessors = new Map<string, string | null>();
  const queue: string[] = [source];
  visited.add(source);
  predecessors.set(source, null);

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (current === sink) break;
    const distance = computeDistanceFromPredecessors(predecessors, source, current);
    if (distance > maxDepth) continue;

    const neighbors = adjacency.get(current) ?? [];
    for (const next of neighbors) {
      if (!visited.has(next)) {
        visited.add(next);
        predecessors.set(next, current);
        queue.push(next);
      }
    }
  }

  if (!visited.has(sink)) return null;

  // Reconstruct path
  const path: string[] = [];
  let cursor: string | null = sink;
  while (cursor !== null) {
    path.unshift(cursor);
    cursor = predecessors.get(cursor) ?? null;
  }
  return path.length >= 2 ? path : null;
}

/**
 * Count how many predecessors we need to traverse to compute distance.
 */
function computeDistanceFromPredecessors(
  predecessors: Map<string, string | null>,
  source: string,
  target: string,
): number {
  let dist = 0;
  let cursor: string | null = target;
  while (cursor !== null && cursor !== source) {
    dist++;
    cursor = predecessors.get(cursor) ?? null;
  }
  return cursor === source ? dist : Infinity;
}

/**
 * Extract the call types along a path from the call graph.
 */
function extractCallTypesOnPath(
  path: string[],
  callGraph: Map<string, CallGraphNode>,
): CallType[] {
  const types: CallType[] = [];
  for (let i = 0; i < path.length - 1; i++) {
    const caller = callGraph.get(path[i]!);
    const callee = path[i + 1]!;
    if (caller && caller.callees.has(callee)) {
      types.push(caller.callees.get(callee)!);
    } else {
      types.push('direct');
    }
  }
  return types;
}

/**
 * Compute the likelihood that a path is actually exploitable.
 *
 * Factors:
 *  - Path length: more hops = less likely to be exploitable in practice
 *  - Call type uncertainty: virtual/dynamic calls are harder to trace
 */
function computePathLikelihood(hops: number, callTypes: CallType[]): number {
  // Base likelihood
  let likelihood = 1.0;

  // Path length penalty
  if (hops === 0) {
    likelihood = 1.0;
  } else if (hops <= 2) {
    likelihood = 0.95;
  } else if (hops <= 5) {
    likelihood = 0.85;
  } else if (hops <= 10) {
    likelihood = 0.65;
  } else {
    likelihood = 0.40;
  }

  // Call-type uncertainty penalties
  for (const ct of callTypes) {
    switch (ct) {
      case 'virtual':
        likelihood *= 0.85;  // Virtual dispatch reduces confidence
        break;
      case 'dynamic':
        likelihood *= 0.70;  // Dynamic calls are hard to track
        break;
      case 'callback':
        likelihood *= 0.90;  // Callbacks are moderately uncertain
        break;
      case 'direct':
        // No penalty for direct calls
        break;
    }
  }

  return Math.max(0.01, likelihood);
}

/**
 * Compute the risk score for a taint flow path.
 *
 * Formula: riskScore = likelihood * impact * (1 - sanitizerStrength)
 *
 * Where:
 *  - likelihood:       0.01 - 1.0 (how likely the path is real)
 *  - impact:           0.1 - 1.0 (severity of the sink)
 *  - sanitizerStrength: 0 - 0.95 (effectiveness of sanitizers on path)
 */
function computePathRisk(
  likelihood: number,
  impact: number,
  sanitizersOnPath: string[],
  callTypes: CallType[],
  hops: number,
): number {
  // Compute sanitizer strength: each sanitizer provides some protection
  // Stacking sanitizers: 1st = 0.5, 2nd adds 0.25, 3rd adds 0.15, etc.
  let sanitizerStrength = 0;
  if (sanitizersOnPath.length > 0) {
    const strengths = [0.5, 0.25, 0.15, 0.08, 0.02];
    for (let i = 0; i < sanitizersOnPath.length && i < strengths.length; i++) {
      sanitizerStrength += strengths[i]!;
    }
    sanitizerStrength = Math.min(0.95, sanitizerStrength);
  }

  // Base risk
  let risk = likelihood * impact * (1 - sanitizerStrength);

  // Additional penalty for very long paths
  if (hops > 12) risk *= 0.85;
  if (hops > 20) risk *= 0.70;

  return Math.round(risk * 1000) / 1000;
}

// ---------------------------------------------------------------------------
// 5. computeExploitabilityScore
// ---------------------------------------------------------------------------

/**
 * Compute an adjusted exploitability score (0-10) for a security finding
 * based on:
 *
 *   1. **Base CVSS** score from the finding itself.
 *   2. **Reachability penalty**: unreachable functions get score 0.
 *      Reachable functions get reduced score proportional to their distance
 *      from the nearest entry point (more hops = harder to exploit).
 *   3. **WAF reduction**: if a WAF is detected, the score is reduced
 *      because some attack payloads are blocked at the network layer.
 *   4. **Auth multiplier**: if authentication is required to reach the
 *      vulnerable code, the score is reduced because exploitation requires
 *      valid credentials.
 *
 * Scoring formula:
 * ```
 * if not reachable => 0
 * score = baseCVSS
 * score *= reachabilityMultiplier(distance)   // 0.55 - 1.0
 * if wafDetected  => score *= 0.75
 * if authRequired  => score *= 0.85
 * return clamp(score, 0, 10)
 * ```
 *
 * @param finding       The security finding (must include `cvssScore`).
 * @param reachability  Reachability info for the vulnerable function.
 * @param wafDetected   Whether a WAF is present in the deployment.
 * @param authRequired  Whether auth is required to trigger this path.
 * @returns             Adjusted exploitability score (0-10).
 */
export function computeExploitabilityScore(
  finding: ExploitabilityInput,
  reachability: FindingReachability,
  wafDetected: boolean,
  authRequired: boolean,
): number {
  if (!reachability.isReachable) {
    return 0;
  }

  let score = finding.cvssScore;

  // ---- Reachability distance penalty ----
  // Functions directly callable from an entry point (distance 0) get full score.
  // Each additional hop reduces confidence that an attacker can reach the
  // vulnerable code path in practice.
  const reachabilityMultiplier = computeReachabilityMultiplier(reachability.distance);
  score *= reachabilityMultiplier;

  // ---- WAF reduction ----
  // A Web Application Firewall blocks many exploit attempts at the network
  // layer, especially for well-known attack patterns.
  if (wafDetected) {
    score *= 0.75;
  }

  // ---- Auth multiplier ----
  // Authentication-required endpoints are harder to exploit because the
  // attacker must first compromise valid credentials.
  if (authRequired) {
    score *= 0.85;
  }

  // ---- Clamp to [0, 10] and round to 1 decimal ----
  const clamped = Math.max(0, Math.min(10, score));
  return Math.round(clamped * 10) / 10;
}

/**
 * Compute the reachability multiplier based on distance from nearest entry
 * point.
 *
 * - distance 0 (entry point itself):      1.00
 * - distance 1 (directly called):         0.95
 * - distance 2:                           0.88
 * - distance 3:                           0.80
 * - distance 4:                           0.72
 * - distance 5:                           0.65
 * - distance 6-8:                         0.60
 * - distance 9+:                          0.55
 */
function computeReachabilityMultiplier(distance: number): number {
  if (distance <= 0) return 1.0;
  if (distance === 1) return 0.95;
  if (distance === 2) return 0.88;
  if (distance === 3) return 0.80;
  if (distance === 4) return 0.72;
  if (distance === 5) return 0.65;
  if (distance <= 8) return 0.60;
  return 0.55;
}
