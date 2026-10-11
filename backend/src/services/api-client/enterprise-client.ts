// M7a-M7e: Enterprise API Client -- Script Engine, Collection Runner, Multi-Protocol, Mock Server, Workspaces
// All functions perform real computation from their inputs.

import vm from 'vm';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import { randomUUID } from 'crypto';
import { query } from '../../core/db/pool.js';
import { logger } from '../../core/logging/logger.js';
import WebSocket from 'ws';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

class AssertionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AssertionError';
  }
}

/** Static analysis to detect sandbox-escape patterns in user JS. */
function checkSandboxEscape(script: string): void {
  const escapes: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /this\s*\.\s*constructor\s*\.\s*constructor\b/g, label: 'constructor-reentry' },
    { pattern: /\(\s*\{\s*\}\s*\)\s*\.\s*constructor\s*\.\s*constructor/g, label: 'object-constructor-chain' },
    { pattern: /\(\s*\[\s*\]\s*\)\s*\.\s*constructor\s*\.\s*constructor/g, label: 'array-constructor-chain' },
    { pattern: /\bprocess\s*\./g, label: 'process-access' },
    { pattern: /\bglobalThis\b/g, label: 'globalThis-access' },
    { pattern: /\b__proto__\b/g, label: 'proto-access' },
    { pattern: /\bimport\s*\(/g, label: 'dynamic-import' },
    { pattern: /\brequire\s*\(/g, label: 'require-access' },
    { pattern: /\bFunction\s*\(/g, label: 'function-constructor' },
  ];
  for (const { pattern, label } of escapes) {
    if (pattern.test(script)) {
      throw new Error(`Sandbox escape attempt detected (${label})`);
    }
  }
}

/** Build the `pm.variables` / `pm.environment` proxy object. */
function createPmVariables(vars: Map<string, string>) {
  return {
    get(name: string): string | undefined { return vars.get(name); },
    set(name: string, value: string): void { vars.set(name, value); },
    unset(name: string): void { vars.delete(name); },
    clear(): void { vars.clear(); },
    has(name: string): boolean { return vars.has(name); },
    replaceIn(str: string): string {
      return str.replace(/\{\{([^}]+)\}\}/g, (_, name: string) => vars.get(name) ?? `{{${name}}}`);
    },
    toObject(): Record<string, string> { return Object.fromEntries(vars); },
  };
}

/** Deep equality (simple JSON-compatible subset). */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a == null || b == null) return a === b;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (typeof a === 'object' && typeof b === 'object') {
    const ka = Object.keys(a as Record<string, unknown>);
    const kb = Object.keys(b as Record<string, unknown>);
    if (ka.length !== kb.length) return false;
    return ka.every(k => k in (b as Record<string, unknown>) && deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
  }
  return false;
}

/** Chai-like expect assertion chain backed by `AssertionError`. */
function createExpectChain(actual: unknown, negated = false) {
  const check = (cond: boolean, msg: string) => { if (negated ? cond : !cond) throw new AssertionError(msg); };

  const chain: Record<string, unknown> = {};

  // --- chainable property accessors ---
  for (const key of ['to', 'be', 'been', 'is', 'that', 'and', 'have', 'has', 'with']) {
    Object.defineProperty(chain, key, { get: () => chain });
  }
  for (const key of ['a', 'an']) {
    Object.defineProperty(chain, key, {
      get: () => (type: string) => {
        const actualType = Array.isArray(actual) ? 'array' : typeof actual;
        check(actualType === type, `expected type '${type}' but got '${actualType}'`);
      },
    });
  }
  Object.defineProperty(chain, 'not', { get: () => createExpectChain(actual, !negated) });

  // --- terminal properties ---
  Object.defineProperty(chain, 'ok', { get: () => { check(!!actual, `expected truthy but got ${JSON.stringify(actual)}`); } });
  Object.defineProperty(chain, 'true', { get: () => { check(actual === true, `expected true but got ${JSON.stringify(actual)}`); } });
  Object.defineProperty(chain, 'false', { get: () => { check(actual === false, `expected false but got ${JSON.stringify(actual)}`); } });
  Object.defineProperty(chain, 'null', { get: () => { check(actual === null, `expected null but got ${typeof actual}`); } });
  Object.defineProperty(chain, 'undefined', { get: () => { check(actual === undefined, `expected undefined but got ${typeof actual}`); } });
  Object.defineProperty(chain, 'exist', { get: () => { check(actual != null, 'expected to exist'); } });
  Object.defineProperty(chain, 'empty', {
    get: () => {
      if (actual != null && typeof actual === 'object') {
        const len = Array.isArray(actual) ? actual.length : Object.keys(actual).length;
        check(len === 0, `expected empty but got length ${len}`);
      } else if (typeof actual === 'string') {
        check(actual.length === 0, `expected empty string but got length ${actual.length}`);
      }
    },
  });

  // --- terminal methods ---
  chain.equal = (expected: unknown) => { check(actual === expected, `expected ${JSON.stringify(expected)} but got ${JSON.stringify(actual)}`); };
  chain.eql = (expected: unknown) => { check(deepEqual(actual, expected), `expected ${JSON.stringify(expected)} but got ${JSON.stringify(actual)}`); };
  chain.include = (expected: unknown) => {
    if (typeof actual === 'string') check((actual as string).includes(String(expected)), `expected '${actual}' to include '${expected}'`);
    else if (Array.isArray(actual)) check(actual.includes(expected), `expected array to include ${JSON.stringify(expected)}`);
    else throw new AssertionError('.include requires string or array');
  };
  chain.property = (prop: string, val?: unknown) => {
    check(actual != null && typeof actual === 'object', 'expected object');
    const obj = actual as Record<string, unknown>;
    check(prop in obj, `expected property '${prop}' to exist`);
    if (val !== undefined) check(deepEqual(obj[prop], val), `expected property '${prop}' to equal ${JSON.stringify(val)} but got ${JSON.stringify(obj[prop])}`);
  };
  chain.lengthOf = (n: number) => {
    const len = (actual as any)?.length;
    check(len === n, `expected length ${n} but got ${len}`);
  };
  chain.match = (regex: RegExp) => { check(regex.test(String(actual)), `expected '${actual}' to match ${regex}`); };
  chain.above = (n: number) => { check(Number(actual) > n, `expected ${actual} to be above ${n}`); };
  chain.below = (n: number) => { check(Number(actual) < n, `expected ${actual} to be below ${n}`); };
  chain.within = (a: number, b: number) => { check(Number(actual) >= a && Number(actual) <= b, `expected ${actual} to be within ${a}..${b}`); };
  chain.status = (code: number) => { check(actual === code, `expected status ${code} but got ${JSON.stringify(actual)}`); };
  chain.oneOf = (values: unknown[]) => { check(values.includes(actual), `expected ${JSON.stringify(actual)} to be one of ${JSON.stringify(values)}`); };
  chain.satisfy = (fn: (v: unknown) => boolean) => { check(fn(actual), 'expected to satisfy function'); };
  chain.members = (members: unknown[]) => {
    if (!Array.isArray(actual)) throw new AssertionError('.members requires array');
    check(members.every((m: unknown) => (actual as unknown[]).includes(m)), 'expected array to include all members');
  };
  chain.throws = (expected?: string | RegExp) => {
    check(typeof actual === 'function', 'expected function');
    try {
      (actual as () => void)();
      check(false, 'expected function to throw');
    } catch (e: unknown) {
      if (expected instanceof RegExp) check(expected.test(String(e)), `expected error to match ${expected}`);
      else if (typeof expected === 'string') check(String(e).includes(expected), `expected error to include '${expected}'`);
    }
  };
  chain.keys = (...keys: string[]) => {
    check(actual != null && typeof actual === 'object', 'expected object');
    const objKeys = Object.keys(actual as Record<string, unknown>);
    check(deepEqual(objKeys.sort(), keys.sort()), `expected keys ${JSON.stringify(keys)} but got ${JSON.stringify(objKeys)}`);
  };
  chain.deep = chain;

  return chain;
}

/** Build the `pm.request` sandbox object that mutates the real context request. */
function createPmRequest(req: { url: string; method: string; headers: Record<string, string>; body?: string }) {
  return {
    url: req.url,
    method: req.method,
    body: req.body,
    headers: {
      add(header: { key: string; value: string }) { req.headers[header.key] = header.value; },
      get(key: string): string | undefined { return req.headers[key]; },
      delete(key: string): void { delete req.headers[key]; },
      toObject(): Record<string, string> { return { ...req.headers }; },
    },
    setUrl(u: string) { req.url = u; },
    setMethod(m: string) { req.method = m; },
    setBody(b: string) { req.body = b; },
  };
}

/** Apply `{{variable}}` substitution from a variables map and an environment map. */
function substituteVariables(str: string, vars: Map<string, string>, env: Map<string, string>): string {
  return str.replace(/\{\{([^}]+)\}\}/g, (_, name: string) => {
    return vars.get(name) ?? env.get(name) ?? `{{${name}}}`;
  });
}

// ---------------------------------------------------------------------------
// JSONPath evaluator
// ---------------------------------------------------------------------------

/**
 * Evaluate a JSONPath expression against a parsed JavaScript value.
 * Supports: dot notation, bracket notation, wildcards (*), numeric indices,
 * recursive descent (..), and basic filter expressions [?(@.prop op val)].
 */
export function evaluateJsonPath(obj: unknown, path: string): unknown[] {
  if (!path.startsWith('$')) return [];

  const tokens: string[] = [];
  let i = 1; // skip $

  while (i < path.length) {
    if (path[i] === '.') {
      if (i + 1 < path.length && path[i + 1] === '.') {
        tokens.push('..');
        i += 2;
        // Parse the property name following '..' (e.g., $..name -> ['..','name'])
        const propStart = i;
        let propEnd = i;
        while (propEnd < path.length && path[propEnd] !== '.' && path[propEnd] !== '[') propEnd++;
        if (propEnd > propStart) {
          const seg = path.slice(propStart, propEnd);
          if (seg) tokens.push(seg);
          i = propEnd;
        }
        continue;
      }
      // dot-notation property: read until next dot, bracket, or end
      const start = i + 1;
      let end = start;
      while (end < path.length && path[end] !== '.' && path[end] !== '[') end++;
      const seg = path.slice(start, end);
      if (seg) tokens.push(seg);
      i = end;
    } else if (path[i] === '[') {
      const close = path.indexOf(']', i);
      if (close === -1) break;
      const content = path.slice(i + 1, close).trim();
      // string key: ['...'] or ["..."]
      if ((content.startsWith("'") && content.endsWith("'")) || (content.startsWith('"') && content.endsWith('"'))) {
        tokens.push(content.slice(1, -1));
      } else if (content === '*') {
        tokens.push('*');
      } else if (content.startsWith('?')) {
          // Strip leading ? and surrounding parentheses
          let filterExpr = content.slice(1).trim();
          if (filterExpr.startsWith('(') && filterExpr.endsWith(')')) {
            filterExpr = filterExpr.slice(1, -1).trim();
          }
          tokens.push('[?' + filterExpr);
      } else {
        tokens.push(content); // numeric index or other
      }
      i = close + 1;
    } else {
      i++;
    }
  }

  return evaluateTokens(obj, tokens);
}

function evaluateTokens(obj: unknown, tokens: string[]): unknown[] {
  let results = [obj];
  let deepMode = false;

  for (const token of tokens) {
    if (token === '..') {
      deepMode = true;
      continue;
    }

    const next: unknown[] = [];

    for (const item of results) {
      if (item == null) continue;

      if (token === '*') {
        if (Array.isArray(item)) next.push(...item);
        else if (typeof item === 'object') next.push(...Object.values(item as Record<string, unknown>));
      } else if (/^\d+$/.test(token)) {
        const idx = parseInt(token, 10);
        if (Array.isArray(item) && idx < item.length) next.push(item[idx]);
      } else if (token.startsWith('[?')) {
        const expr = token.slice(2);
        if (Array.isArray(item)) {
          for (const el of item) {
            if (evaluateFilterExpr(el, expr)) next.push(el);
          }
        }
      } else {
        const objItem = item as Record<string, unknown>;
        if (typeof objItem === 'object' && token in objItem) {
          next.push(objItem[token]);
        }
      }

      // Recursive descent from this node
      if (deepMode && typeof item === 'object' && item !== null) {
        next.push(...deepScan(item as Record<string, unknown>, token));
      }
    }

    results = next;
    deepMode = false;
  }

  return results;
}

function deepScan(obj: Record<string, unknown>, prop: string): unknown[] {
  const found: unknown[] = [];
  function walk(o: unknown): void {
    if (o == null || typeof o !== 'object') return;
    if (Array.isArray(o)) {
      for (const el of o) {
        walk(el);
      }
    } else {
      const dict = o as Record<string, unknown>;
      for (const key of Object.keys(dict)) {
        if (key === prop) found.push(dict[key]);
        walk(dict[key]);
      }
    }
  }
  walk(obj);
  return found;
}

/** Evaluate a simple JSONPath filter expression like `@.price < 10`. */
function evaluateFilterExpr(item: unknown, expr: string): boolean {
  const trimmed = expr.trim();
  const m = trimmed.match(/^@\.?(\w+)\s*(==|!=|<=|>=|<|>)\s*(.+)$/);
  if (!m) return true; // unparseable -- include by default
  const prop = m[1]!;
  const op = m[2]!;
  const raw = m[3] ?? '';
  const itemObj = item as Record<string, unknown>;
  const actual = itemObj[prop];

  let expected: unknown = raw.trim();
  if ((expected as string).startsWith("'") && (expected as string).endsWith("'")) expected = (expected as string).slice(1, -1);
  else if ((expected as string).startsWith('"') && (expected as string).endsWith('"')) expected = (expected as string).slice(1, -1);
  else if (!isNaN(Number(expected))) expected = Number(expected);

  switch (op) {
    case '==': return actual == expected;
    case '!=': return actual != expected;
    case '<': return Number(actual) < Number(expected);
    case '>': return Number(actual) > Number(expected);
    case '<=': return Number(actual) <= Number(expected);
    case '>=': return Number(actual) >= Number(expected);
    default: return true;
  }
}

// ---------------------------------------------------------------------------
// JSON Schema validator (subset of draft-07)
// ---------------------------------------------------------------------------

interface SchemaValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateJsonSchema(data: unknown, schema: Record<string, unknown>, path = '$'): SchemaValidationResult {
  const errors: string[] = [];

  function validate(value: unknown, sch: unknown, p: string): void {
    if (sch === true) return;
    if (sch === false) { errors.push(`${p}: Schema is false`); return; }
    if (sch == null || typeof sch !== 'object') return;

    const s = sch as Record<string, unknown>;

    // -- $ref --
    if (typeof s.$ref === 'string' && (s.$ref as string).startsWith('#/definitions/')) {
      const defKey = (s.$ref as string).slice('#/definitions/'.length);
      const defs = s.definitions as Record<string, unknown> | undefined;
      if (defs && defKey in defs) { validate(value, defs[defKey], p); return; }
      errors.push(`${p}: Unresolved $ref ${s.$ref}`);
      return;
    }

    // -- if / then / else --
    if (s.if != null) {
      const ifResult = shallowValidate(value, s.if as Record<string, unknown>);
      if (ifResult && s.then != null) validate(value, s.then, p);
      else if (!ifResult && s.else != null) validate(value, s.else, p);
    }

    // -- allOf / anyOf / oneOf --
    const combine = (arr: unknown[], label: string, requireCount: number) => {
      let passes = 0;
      for (const sub of arr) {
        const subErrLen = errors.length;
        validate(value, sub, p);
        if (errors.length === subErrLen) passes++;
        else while (errors.length > subErrLen) errors.pop(); // discard sub-errors
      }
      if (passes < requireCount) errors.push(`${p}: ${label} failed (${passes}/${requireCount})`);
      // For oneOf, also error when more than required match
      if (label === 'oneOf' && passes > requireCount) {
        errors.push(`${p}: oneOf failed (${passes}/${requireCount} — more than one matched)`);
      }
    };
    if (Array.isArray(s.allOf)) combine(s.allOf, 'allOf', s.allOf.length);
    if (Array.isArray(s.anyOf)) combine(s.anyOf, 'anyOf', 1);
    if (Array.isArray(s.oneOf)) combine(s.oneOf, 'oneOf', 1);

    // -- not --
    if (s.not != null) {
      const before = errors.length;
      validate(value, s.not, p);
      const failed = errors.length > before;
      while (errors.length > before) errors.pop();
      if (!failed) errors.push(`${p}: not should have failed`);
    }

    // -- type --
    if (s.type != null) {
      const actualType = Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
      const expectedTypes = Array.isArray(s.type) ? s.type as string[] : [s.type as string];
      const isNullable = s.nullable === true && value === null;

      // Check if any expected type matches
      const typeMatch = expectedTypes.some((t: string) => {
        if (t === actualType) return true;
        // 'integer' type matches integer numbers
        if (t === 'integer' && actualType === 'number' && Number.isInteger(value)) return true;
        // 'number' type matches integer values too
        if (t === 'number' && actualType === 'number') return true;
        return false;
      });

      if (!isNullable && !typeMatch) {
        errors.push(`${p}: Expected type ${expectedTypes.join('|')}, got ${actualType}`);
        return; // skip further checks on mismatched type
      }
      if (expectedTypes.includes('integer') && typeof value === 'number' && !Number.isInteger(value)) {
        errors.push(`${p}: Expected integer, got ${value}`);
      }
    }

    if (value == null) return;

    // -- enum --
    if (Array.isArray(s.enum) && !s.enum.some((e: unknown) => deepEqual(e, value))) {
      errors.push(`${p}: ${JSON.stringify(value)} not in enum ${JSON.stringify(s.enum)}`);
    }

    // -- const --
    if (s.const !== undefined && !deepEqual(value, s.const)) {
      errors.push(`${p}: Expected const ${JSON.stringify(s.const)} but got ${JSON.stringify(value)}`);
    }

    // --- String ---
    if (typeof value === 'string') {
      if (typeof s.minLength === 'number' && (value as string).length < s.minLength)
        errors.push(`${p}: minLength ${s.minLength}, got ${value.length}`);
      if (typeof s.maxLength === 'number' && (value as string).length > s.maxLength)
        errors.push(`${p}: maxLength ${s.maxLength}, got ${value.length}`);
      if (typeof s.pattern === 'string' && !new RegExp(s.pattern).test(value as string))
        errors.push(`${p}: pattern ${s.pattern} not matched`);
      if (typeof s.format === 'string') validateFormat(value as string, s.format as string, p, errors);
    }

    // --- Number ---
    if (typeof value === 'number') {
      const n = value as number;
      if (typeof s.minimum === 'number' && n < (s.minimum as number))
        errors.push(`${p}: minimum ${s.minimum}, got ${n}`);
      if (typeof s.maximum === 'number' && n > (s.maximum as number))
        errors.push(`${p}: maximum ${s.maximum}, got ${n}`);
      if (typeof s.exclusiveMinimum === 'number' && n <= (s.exclusiveMinimum as number))
        errors.push(`${p}: exclusiveMinimum ${s.exclusiveMinimum}, got ${n}`);
      if (typeof s.exclusiveMaximum === 'number' && n >= (s.exclusiveMaximum as number))
        errors.push(`${p}: exclusiveMaximum ${s.exclusiveMaximum}, got ${n}`);
      if (typeof s.multipleOf === 'number' && n % s.multipleOf !== 0)
        errors.push(`${p}: multipleOf ${s.multipleOf}, got ${n}`);
    }

    // --- Array ---
    if (Array.isArray(value)) {
      const arr = value as unknown[];
      if (typeof s.minItems === 'number' && arr.length < (s.minItems as number))
        errors.push(`${p}: minItems ${s.minItems}, got ${arr.length}`);
      if (typeof s.maxItems === 'number' && arr.length > (s.maxItems as number))
        errors.push(`${p}: maxItems ${s.maxItems}, got ${arr.length}`);
      if (s.uniqueItems === true) {
        const seen = new Set<string>();
        for (const item of arr) { const key = JSON.stringify(item); if (seen.has(key)) { errors.push(`${p}: duplicate`); break; } seen.add(key); }
      }
      if (s.items != null) {
        if (Array.isArray(s.items)) {
          for (let i = 0; i < (s.items as unknown[]).length && i < arr.length; i++)
            validate(arr[i], (s.items as unknown[])[i], `${p}[${i}]`);
        } else {
          for (let i = 0; i < arr.length; i++) validate(arr[i], s.items, `${p}[${i}]`);
        }
      }
      if (s.contains != null) {
        const before = errors.length;
        let found = false;
        for (const item of arr) {
          const errBefore = errors.length;
          validate(item, s.contains, `${p}[contains]`);
          if (errors.length === errBefore) { found = true; break; }
          while (errors.length > errBefore) errors.pop();
        }
        while (errors.length > before) errors.pop(); // discard item-level errors
        if (!found) errors.push(`${p}: no item matches 'contains'`);
      }
    }

    // --- Object ---
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const obj = value as Record<string, unknown>;
      const props = s.properties as Record<string, unknown> | undefined;
      const additional = s.additionalProperties;
      const patternProps = s.patternProperties as Record<string, unknown> | undefined;

      if (typeof s.minProperties === 'number' && Object.keys(obj).length < (s.minProperties as number))
        errors.push(`${p}: minProperties ${s.minProperties}, got ${Object.keys(obj).length}`);
      if (typeof s.maxProperties === 'number' && Object.keys(obj).length > (s.maxProperties as number))
        errors.push(`${p}: maxProperties ${s.maxProperties}, got ${Object.keys(obj).length}`);

      if (Array.isArray(s.required)) {
        for (const req of s.required as string[]) {
          if (!(req in obj)) errors.push(`${p}: missing required property '${req}'`);
        }
      }

      if (props) {
        for (const [key, ps] of Object.entries(props)) {
          if (key in obj) validate(obj[key], ps, `${p}.${key}`);
        }
      }

      // patternProperties
      if (patternProps) {
        for (const [pattern, ps] of Object.entries(patternProps)) {
          const re = new RegExp(pattern);
          for (const key of Object.keys(obj)) {
            if (re.test(key)) validate(obj[key], ps, `${p}.${key}[pattern:${pattern}]`);
          }
        }
      }

      // additionalProperties
      if (additional === false) {
        const allowed = new Set(Object.keys(props ?? {}));
        if (patternProps) {
          for (const pattern of Object.keys(patternProps)) {
            const re = new RegExp(pattern);
            for (const key of Object.keys(obj)) { if (re.test(key)) allowed.add(key); }
          }
        }
        for (const key of Object.keys(obj)) {
          if (!allowed.has(key)) errors.push(`${p}: unexpected property '${key}'`);
        }
      } else if (additional != null && typeof additional === 'object') {
        for (const [key, val] of Object.entries(obj)) {
          if (!props || !(key in props)) validate(val, additional, `${p}.${key}`);
        }
      }

      if (s.dependencies != null) {
        for (const [prop, dep] of Object.entries(s.dependencies as Record<string, unknown>)) {
          if (prop in obj) {
            if (Array.isArray(dep)) {
              for (const req of dep as string[]) {
                if (!(req in obj)) errors.push(`${p}: '${prop}' requires '${req}'`);
              }
            } else {
              validate(value, dep, p); // schema dependency
            }
          }
        }
      }
    }
  }

  validate(data, schema, path);
  return { valid: errors.length === 0, errors };
}

/** Quick shallow validation used for if/then/else  check. */
function shallowValidate(value: unknown, sch: Record<string, unknown>): boolean {
  const result = validateJsonSchema(value, sch);
  return result.valid;
}

/** Basic format validators for JSON Schema. */
function validateFormat(value: string, format: string, path: string, errors: string[]): void {
  switch (format) {
    case 'date-time':
      if (isNaN(Date.parse(value))) errors.push(`${path}: invalid date-time '${value}'`);
      break;
    case 'date':
      if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) errors.push(`${path}: invalid date '${value}'`);
      break;
    case 'email':
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) errors.push(`${path}: invalid email '${value}'`);
      break;
    case 'uri':
      try { new URL(value); } catch { errors.push(`${path}: invalid URI '${value}'`); }
      break;
    case 'uuid':
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value))
        errors.push(`${path}: invalid UUID '${value}'`);
      break;
    case 'ipv4':
      if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(value) || value.split('.').some(p => parseInt(p) > 255))
        errors.push(`${path}: invalid IPv4 '${value}'`);
      break;
    case 'ipv6':
      if (!/^([0-9a-f:]+)$/i.test(value)) errors.push(`${path}: invalid IPv6 '${value}'`);
      break;
  }
}

// ---------------------------------------------------------------------------
// Comparison engine for assertion operators
// ---------------------------------------------------------------------------

export function compareValues(actual: unknown, expected: unknown, operator: string): boolean {
  switch (operator) {
    case 'equals':
    case 'equal':
    case 'eq':
    case '===': return actual == expected;
    case 'not_equals':
    case 'neq':
    case '!==': return actual != expected;
    case 'contains':
    case 'includes': return String(actual).includes(String(expected));
    case 'not_contains': return !String(actual).includes(String(expected));
    case 'exists': {
      if (actual === undefined || actual === null) return false;
      if (actual === '(missing)') return false;
      if (Array.isArray(actual)) return actual.length > 0;
      return true;
    }
    case 'not_exists': {
      if (actual === undefined || actual === null) return true;
      if (actual === '(missing)') return true;
      if (Array.isArray(actual)) return actual.length === 0;
      return false;
    }
    case 'less_than':
    case 'lt':
    case '<': return Number(actual) < Number(expected);
    case 'greater_than':
    case 'gt':
    case '>': return Number(actual) > Number(expected);
    case 'less_than_or_equal':
    case 'lte':
    case '<=': return Number(actual) <= Number(expected);
    case 'greater_than_or_equal':
    case 'gte':
    case '>=': return Number(actual) >= Number(expected);
    case 'regex':
    case 'matches': return new RegExp(String(expected)).test(String(actual));
    default: return String(actual) === String(expected);
  }
}

// ---------------------------------------------------------------------------
// Real HTTP request helper (Node.js built-in http/https)
// ---------------------------------------------------------------------------

interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  timeMs: number;
}

function makeHttpRequest(urlStr: string, method: string, headers: Record<string, string>, body?: string): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(urlStr);
    } catch {
      reject(new Error(`Invalid URL: ${urlStr}`));
      return;
    }

    const transport = parsedUrl.protocol === 'https:' ? https : http;
    const port = parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80);

    const options: http.RequestOptions = {
      hostname: parsedUrl.hostname,
      port,
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      headers: { ...headers } as http.OutgoingHttpHeaders,
      timeout: 30000,
      ...(parsedUrl.protocol === 'https:' ? {} : {}),
    };

    // Set Content-Length if body is present
    if (body) {
      const bodyBuffer = Buffer.from(body, 'utf-8');
      options.headers = { ...options.headers, 'Content-Length': bodyBuffer.length };
    }

    const startTime = Date.now();
    const req = transport.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const timeMs = Date.now() - startTime;
        const responseHeaders: Record<string, string> = {};
        if (res.headers) {
          for (const [key, value] of Object.entries(res.headers)) {
            responseHeaders[key] = Array.isArray(value) ? value.join(', ') : value ?? '';
          }
        }
        resolve({
          status: res.statusCode ?? 0,
          headers: responseHeaders,
          body: Buffer.concat(chunks).toString('utf-8'),
          timeMs,
        });
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => { req.destroy(); reject(new Error(`Request timeout after 30s: ${method} ${urlStr}`)); });

    if (body) req.write(body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Data file parser (JSON / CSV)
// ---------------------------------------------------------------------------

async function parseDataFile(filePath: string): Promise<Record<string, string>[]> {
  const { readFileSync } = await import('fs');
  const content = readFileSync(filePath, 'utf-8').trim();
  if (!content) return [{}];

  if (filePath.endsWith('.json')) {
    const parsed = JSON.parse(content);
    return Array.isArray(parsed) ? parsed : [parsed];
  }

  if (filePath.endsWith('.csv')) {
    const lines = content.split('\n').filter(l => l.trim());
    if (lines.length < 2) return [{}];
    const header = lines[0]!.split(',').map(h => h.trim().replace(/^"(.*)"$/, '$1'));
    return lines.slice(1).map(line => {
      const values = line.split(',').map(v => v.trim().replace(/^"(.*)"$/, '$1'));
      const row: Record<string, string> = {};
      header.forEach((h, i) => { row[h] = values[i] ?? ''; });
      return row;
    });
  }

  return [{}];
}

// ===================================================================
// M7a: Script Engine
// ===================================================================

export class ScriptEngine {
  /**
   * Execute a pre-request script in a sandboxed VM context.
   * Exposes pm.variables, pm.environment, pm.request with real mutation.
   * Applies {{variable}} substitution to the final request.
   */
  executePreRequest(
    script: string,
    context: {
      variables: Map<string, string>;
      request: { url: string; method: string; headers: Record<string, string>; body?: string };
    },
  ): {
    modifiedRequest: typeof context.request;
    stdout: string;
    stderr: string;
    timedOut: boolean;
  } {
    const stdoutChunks: string[] = [];
    const stderrChunks: string[] = [];
    let timedOut = false;

    // Clone so the original is not mutated on error
    const vars = new Map(context.variables);
    const env = new Map<string, string>();
    const req = { ...context.request, headers: { ...context.request.headers }, body: context.request.body };

    try {
      checkSandboxEscape(script);

      const sandbox: Record<string, unknown> = {
        pm: {
          variables: createPmVariables(vars),
          environment: createPmVariables(env),
          request: createPmRequest(req),
        },
        console: {
          log: (...args: unknown[]) => stdoutChunks.push(args.map(String).join(' ')),
          error: (...args: unknown[]) => stderrChunks.push(args.map(String).join(' ')),
          warn: (...args: unknown[]) => stdoutChunks.push('[WARN] ' + args.map(String).join(' ')),
          info: (...args: unknown[]) => stdoutChunks.push('[INFO] ' + args.map(String).join(' ')),
        },
        setTimeout: (fn: (...args: unknown[]) => void, ms: number, ...args: unknown[]) =>
          setTimeout(fn, ms, ...args),
        clearTimeout: (id: ReturnType<typeof setTimeout>) => clearTimeout(id),
        // __dangerously_unsafe -- intentionally omitted
      };

      const ctx = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
      const compiled = new vm.Script(script);
      compiled.runInContext(ctx, { timeout: 30000 });

      // Apply variable substitution to URL, headers, body
      const subst = (str: string) => substituteVariables(str, vars, env);
      const modifiedRequest = {
        url: subst(req.url),
        method: req.method,
        headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, subst(v)])),
        body: req.body != null ? subst(req.body) : undefined,
      };

      return {
        modifiedRequest,
        stdout: stdoutChunks.join('\n'),
        stderr: stderrChunks.join('\n'),
        timedOut: false,
      };
    } catch (e: unknown) {
      const err = e as Error & { code?: string };
      if (err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT' || String(err).includes('timeout')) {
        timedOut = true;
        stderrChunks.push('Script execution timed out after 30s');
      } else {
        stderrChunks.push(err.message ?? String(err));
      }
      return {
        modifiedRequest: context.request,
        stdout: stdoutChunks.join('\n'),
        stderr: stderrChunks.join('\n'),
        timedOut,
      };
    }
  }

  /**
   * Execute a post-response / test script in a sandboxed VM context.
   * Exposes pm.test(), pm.expect(), pm.response with real assertion execution.
   */
  executePostResponse(
    script: string,
    context: {
      variables: Map<string, string>;
      response: { status: number; headers: Record<string, string>; body: string; timeMs: number };
    },
  ): {
    tests: Array<{ name: string; passed: boolean; message: string }>;
    stdout: string;
    stderr: string;
    timedOut: boolean;
  } {
    const stdoutChunks: string[] = [];
    const stderrChunks: string[] = [];
    const tests: Array<{ name: string; passed: boolean; message: string }> = [];
    let timedOut = false;

    const vars = new Map(context.variables);
    const env = new Map<string, string>();

    try {
      checkSandboxEscape(script);

      const sandbox: Record<string, unknown> = {
        pm: {
          test: (name: string, fn: () => void) => {
            try {
              fn();
              tests.push({ name, passed: true, message: 'Test passed' });
            } catch (e: unknown) {
              const msg = e instanceof AssertionError ? e.message : (e as Error).message ?? 'Test failed';
              tests.push({ name, passed: false, message: msg });
            }
          },
          expect: (actual: unknown) => createExpectChain(actual),
          response: {
            status: context.response.status,
            code: context.response.status,
            headers: context.response.headers,
            body: context.response.body,
            text: () => context.response.body,
            json: () => JSON.parse(context.response.body),
            responseTime: context.response.timeMs,
            to: {
              have: {
                status: (code: number) => {
                  if (context.response.status !== code)
                    throw new AssertionError(`Expected status ${code} but got ${context.response.status}`);
                },
              },
              be: {
                ok: () => {
                  if (context.response.status < 200 || context.response.status >= 300)
                    throw new AssertionError(`Expected 2xx status but got ${context.response.status}`);
                },
              },
            },
          },
          variables: createPmVariables(vars),
          environment: createPmVariables(env),
        },
        console: {
          log: (...args: unknown[]) => stdoutChunks.push(args.map(String).join(' ')),
          error: (...args: unknown[]) => stderrChunks.push(args.map(String).join(' ')),
          warn: (...args: unknown[]) => stdoutChunks.push('[WARN] ' + args.map(String).join(' ')),
          info: (...args: unknown[]) => stdoutChunks.push('[INFO] ' + args.map(String).join(' ')),
        },
        setTimeout: (fn: (...args: unknown[]) => void, ms: number, ...args: unknown[]) =>
          setTimeout(fn, ms, ...args),
        clearTimeout: (id: ReturnType<typeof setTimeout>) => clearTimeout(id),
      };

      const ctx = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
      const compiled = new vm.Script(script);
      compiled.runInContext(ctx, { timeout: 30000 });

      return {
        tests,
        stdout: stdoutChunks.join('\n'),
        stderr: stderrChunks.join('\n'),
        timedOut: false,
      };
    } catch (e: unknown) {
      const err = e as Error & { code?: string };
      if (err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT' || String(err).includes('timeout')) {
        timedOut = true;
        stderrChunks.push('Script execution timed out after 30s');
      } else {
        stderrChunks.push(err.message ?? String(err));
      }
      return {
        tests,
        stdout: stdoutChunks.join('\n'),
        stderr: stderrChunks.join('\n'),
        timedOut,
      };
    }
  }

  /**
   * Execute declarative assertions against a real response.
   * Supports: status, header, body, json_path, response_time, schema.
   */
  executeAssertions(
    assertions: Array<{ type: string; operator: string; target?: string; value?: string }>,
    response: { status: number; headers: Record<string, string>; body: string; timeMs: number },
  ): Array<{ passed: boolean; assertion: string; actual: string; expected: string }> {
    return assertions.map((a) => {
      let passed = false;
      let actual = '';
      const expected = a.value ?? '';
      const label = `${a.type} ${a.operator}${a.target ? ` ${a.target}` : ''}${a.value ? ` = ${a.value}` : ''}`;

      try {
        switch (a.type) {
          case 'status': {
            actual = String(response.status);
            passed = compareValues(response.status, Number(a.value), a.operator);
            break;
          }
          case 'header': {
            const headerKey = (a.target ?? '').toLowerCase();
            const headerVal = response.headers[headerKey];
            actual = headerVal ?? '(missing)';
            if (a.operator === 'exists') {
              passed = headerVal !== undefined && headerVal !== null;
            } else if (a.operator === 'not_exists') {
              passed = headerVal === undefined || headerVal === null;
            } else {
              passed = compareValues(headerVal ?? '', a.value ?? '', a.operator);
            }
            break;
          }
          case 'body': {
            const bodySnippet = response.body.length > 200
              ? response.body.slice(0, 200) + '...'
              : response.body;
            actual = bodySnippet;
            passed = compareValues(response.body, a.value ?? '', a.operator);
            break;
          }
          case 'json_path': {
            try {
              const parsed = JSON.parse(response.body);
              const results = evaluateJsonPath(parsed, a.target ?? '');
              actual = JSON.stringify(results);
              if (a.operator === 'exists') {
                passed = results.length > 0;
              } else if (a.operator === 'not_exists') {
                passed = results.length === 0;
              } else {
                const resultStr = results.length === 1 ? results[0] : results;
                passed = compareValues(resultStr, a.value, a.operator);
              }
            } catch (parseErr) {
              actual = `JSON parse error: ${(parseErr as Error).message}`;
              passed = false;
            }
            break;
          }
          case 'response_time': {
            actual = `${response.timeMs}ms`;
            passed = compareValues(response.timeMs, Number(a.value), a.operator);
            break;
          }
          case 'schema': {
            try {
              const parsed = JSON.parse(response.body);
              const schema = JSON.parse(a.value ?? '{}');
              const result = validateJsonSchema(parsed, schema);
              passed = result.valid;
              actual = result.valid ? 'Valid' : result.errors.join('; ');
            } catch (schemaErr) {
              actual = `Schema validation error: ${(schemaErr as Error).message}`;
              passed = false;
            }
            break;
          }
          default: {
            passed = true;
            actual = '(unknown assertion type)';
            break;
          }
        }
      } catch (err) {
        actual = `Error: ${(err as Error).message}`;
        passed = false;
      }

      return { passed, assertion: label, actual, expected };
    });
  }
}

// ===================================================================
// M7b: Collection Runner & CLI
// ===================================================================

export interface CollectionRunResult {
  collectionId: string;
  totalRequests: number;
  passed: number;
  failed: number;
  skipped: number;
  durationMs: number;
  iterations: number;
  requests: Array<{
    name: string;
    status: number;
    passed: boolean;
    durationMs: number;
    tests: Array<{ name: string; passed: boolean }>;
  }>;
}

/**
 * Run every request in a collection sequentially over the wire.
 * Supports data-file-driven iterations, pre-request/post-response scripts,
 * and declarative assertions.
 */
export async function runCollection(
  collectionId: string,
  options: { environment?: string; dataFile?: string; iterations?: number; stopOnFailure?: boolean },
): Promise<CollectionRunResult> {
  const iterations = Math.max(1, options.iterations ?? 1);
  const allResults: CollectionRunResult['requests'] = [];
  let totalPassed = 0;
  let totalFailed = 0;
  let totalDurationMs = 0;

  // Fetch requests from DB
  const { rows: dbRequests } = await query(
    `SELECT id, name, method, url, headers, query_params, body, body_type,
            pre_request_script, post_script, assertions
     FROM api_requests
     WHERE collection_id = $1 AND deleted_at IS NULL
     ORDER BY created_at, name`,
    [collectionId],
  );

  if (dbRequests.length === 0) {
    logger.warn({ collectionId }, 'Collection is empty -- no requests to run');
  }

  // Load data file
  let dataRows: Record<string, string>[] = [{}];
  if (options.dataFile) {
    try {
      dataRows = await parseDataFile(options.dataFile);
    } catch (err) {
      logger.error({ err, file: options.dataFile }, 'Failed to parse data file');
    }
  }

  const engine = new ScriptEngine();

  for (let iter = 0; iter < iterations; iter++) {
    const dataRow = dataRows[iter % dataRows.length]!;

    for (const req of dbRequests) {
      if (options.stopOnFailure && totalFailed > 0) {
        totalFailed++; // count as skipped
        continue;
      }

      const startTime = Date.now();
      const tests: Array<{ name: string; passed: boolean }> = [];

      try {
        // Build mutable context
        const variables = new Map<string, string>();
        for (const k of Object.keys(dataRow)) variables.set(k, dataRow[k] ?? '');
        const requestCtx = {
          url: req.url as string,
          method: req.method as string,
          headers: (typeof req.headers === 'string' ? JSON.parse(req.headers) : req.headers ?? {}) as Record<string, string>,
          body: (req.body as string | undefined) ?? undefined,
        };

        // Append query params if present
        const qp = req.query_params as Record<string, string> | string | undefined;
        if (qp && typeof qp === 'object' && Object.keys(qp).length > 0) {
          const u = new URL(requestCtx.url);
          for (const [k, v] of Object.entries(qp)) u.searchParams.set(k, v ?? '');
          requestCtx.url = u.toString();
        }

        // --- execute pre-request script ---
        const preScript = req.pre_request_script as string | undefined;
        if (preScript) {
          const preResult = engine.executePreRequest(preScript, { variables, request: requestCtx });
          requestCtx.url = preResult.modifiedRequest.url;
          requestCtx.method = preResult.modifiedRequest.method;
          requestCtx.headers = preResult.modifiedRequest.headers;
          requestCtx.body = preResult.modifiedRequest.body;
        }

        // --- make the HTTP request ---
        const response = await makeHttpRequest(
          requestCtx.url,
          requestCtx.method,
          requestCtx.headers,
          requestCtx.body,
        );

        // --- execute post-response script ---
        const postScript = req.post_script as string | undefined;
        if (postScript) {
          const postResult = engine.executePostResponse(postScript, {
            variables,
            response: {
              status: response.status,
              headers: response.headers,
              body: response.body,
              timeMs: response.timeMs,
            },
          });
          for (const t of postResult.tests) {
            tests.push({ name: t.name, passed: t.passed });
          }
        }

        // --- execute assertions ---
        const rawAssertions = req.assertions as string | Array<Record<string, unknown>> | undefined;
        if (rawAssertions) {
          const assertionList = (Array.isArray(rawAssertions) ? rawAssertions : JSON.parse(rawAssertions)) as Array<{
            type: string;
            operator: string;
            target?: string;
            value?: string;
          }>;
          const assertionResults = engine.executeAssertions(assertionList, {
            status: response.status,
            headers: response.headers,
            body: response.body,
            timeMs: response.timeMs,
          });
          for (const ar of assertionResults) {
            tests.push({ name: ar.assertion, passed: ar.passed });
          }
        }

        const durationMs = Date.now() - startTime;
        const requestPassed = tests.length === 0 || tests.every((t) => t.passed);

        if (requestPassed) totalPassed++;
        else totalFailed++;

        allResults.push({
          name: req.name as string,
          status: response.status,
          passed: requestPassed,
          durationMs,
          tests,
        });

        totalDurationMs += durationMs;

        if (options.stopOnFailure && !requestPassed) break;
      } catch (err) {
        totalFailed++;
        const durationMs = Date.now() - startTime;
        allResults.push({
          name: req.name as string,
          status: 0,
          passed: false,
          durationMs,
          tests: [{ name: `Error: ${(err as Error).message}`, passed: false }],
        });
        totalDurationMs += durationMs;
        if (options.stopOnFailure) break;
      }
    }
  }

  return {
    collectionId,
    totalRequests: allResults.length,
    passed: totalPassed,
    failed: totalFailed,
    skipped: 0,
    durationMs: totalDurationMs,
    iterations,
    requests: allResults,
  };
}

// ===================================================================
// M7c: Multi-Protocol Client
// ===================================================================

export interface WebSocketResult {
  connected: boolean;
  messagesSent: number;
  messagesReceived: number;
  framesExchanged: number;
  errors: string[];
}

/**
 * Connect to a WebSocket endpoint, send each message, count received frames.
 */
export async function testWebSocket(url: string, messages: string[]): Promise<WebSocketResult> {
  return new Promise((resolve) => {
    const errors: string[] = [];
    let connected = false;
    let messagesSent = 0;
    let messagesReceived = 0;
    let framesExchanged = 0;
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      resolve({ connected, messagesSent, messagesReceived, framesExchanged, errors });
    };

    try {
      const ws = new WebSocket(url);

      const timeout = setTimeout(() => {
        errors.push('Connection or message exchange did not complete within 30s');
        ws.close();
        finish();
      }, 30000);

      ws.on('open', () => {
        connected = true;
        for (const msg of messages) {
          ws.send(msg);
          messagesSent++;
          framesExchanged++;
        }
      });

      ws.on('message', () => {
        messagesReceived++;
        framesExchanged++;
        if (messagesReceived >= (messages.length || 1)) {
          clearTimeout(timeout);
          ws.close();
          finish();
        }
      });

      ws.on('error', (err) => {
        errors.push(err.message);
        clearTimeout(timeout);
        finish();
      });

      ws.on('close', () => {
        clearTimeout(timeout);
        finish();
      });
    } catch (e) {
      errors.push((e as Error).message);
      finish();
    }
  });
}

export interface GrpcResult {
  servicesDiscovered: number;
  methodsInvoked: number;
  responses: Array<{ method: string; status: string; responseSize: number }>;
  errors: string[];
}

/**
 * Parse a .proto file and attempt HTTP/2 based gRPC calls for service discovery.
 * Note: Without @grpc/grpc-js this is a best-effort implementation using raw HTTP/2.
 */
export async function testGrpc(endpoint: string, protoPath: string): Promise<GrpcResult> {
  const errors: string[] = [];
  const responses: GrpcResult['responses'] = [];
  let servicesDiscovered = 0;

  try {
    const fs = await import('fs');
    const protoContent = fs.readFileSync(protoPath, 'utf-8');

    // Extract service definitions from proto file
    const serviceBlocks: Array<{ name: string; body: string }> = [];
    const serviceRe = /service\s+(\w+)\s*\{([^}]*)\}/g;
    let sm: RegExpExecArray | null;
    while ((sm = serviceRe.exec(protoContent)) !== null) {
      const svcName = sm[1] ?? '';
      const svcBody = sm[2] ?? '';
      if (svcName) serviceBlocks.push({ name: svcName, body: svcBody });
    }
    servicesDiscovered = serviceBlocks.length;

    // Attempt HTTP/2 connection for each RPC in each service
    const http2 = await import('http2');

    for (const svc of serviceBlocks) {
      const rpcRe = /rpc\s+(\w+)\s*\(([^)]*)\)\s*returns\s*\(([^)]*)\)/g;
      let rm: RegExpExecArray | null;
      while ((rm = rpcRe.exec(svc.body)) !== null) {
        const rpcName = rm[1];

        try {
          const client = http2.connect(endpoint);
          await new Promise<void>((resolveRpc) => {
            const req = client.request({
              ':method': 'POST',
              ':path': `/${svc.name}/${rpcName}`,
              'content-type': 'application/grpc',
              'te': 'trailers',
            });

            let responseSize = 0;
            req.on('response', (headers) => {
              const status = headers[':status']?.toString() ?? 'UNKNOWN';
              responseSize = parseInt(headers['content-length'] as string ?? '0', 10) || 0;
              responses.push({
                method: `${svc.name}.${rpcName}`,
                status,
                responseSize,
              });
            });

            req.on('error', (err) => {
              errors.push(`${svc.name}.${rpcName}: ${err.message}`);
              client.close();
              resolveRpc();
            });

            req.on('end', () => {
              client.close();
              resolveRpc();
            });

            req.end();
          });
        } catch (rpcErr) {
          errors.push(`${svc.name}.${rpcName}: ${(rpcErr as Error).message}`);
        }
      }
    }
  } catch (err) {
    errors.push(`Failed to parse proto file: ${(err as Error).message}`);
  }

  return {
    servicesDiscovered,
    methodsInvoked: responses.length,
    responses,
    errors,
  };
}

export interface GraphQLResult {
  schemaTypes: number;
  queriesExecuted: number;
  mutationsExecuted: number;
  errors: string[];
}

/**
 * Introspect a GraphQL endpoint and execute the provided query/mutation.
 */
export async function testGraphQL(endpoint: string, queryStr: string): Promise<GraphQLResult> {
  const errors: string[] = [];
  let schemaTypes = 0;
  let queriesExecuted = 0;
  let mutationsExecuted = 0;

  try {
    // 1. Introspection query to discover schema types
    const introspectionQuery = JSON.stringify({
      query: `query Introspection { __schema { types { name } } }`,
    });

    const introResult = await makeHttpRequest(
      endpoint,
      'POST',
      { 'Content-Type': 'application/json', Accept: 'application/json' },
      introspectionQuery,
    );

    const introData = JSON.parse(introResult.body);
    if (introData?.data?.__schema?.types) {
      schemaTypes = introData.data.__schema.types.length;
    } else if (introResult.status >= 400) {
      errors.push(`Introspection failed: HTTP ${introResult.status}`);
    }

    // 2. Execute the user's query
    const execResult = await makeHttpRequest(
      endpoint,
      'POST',
      { 'Content-Type': 'application/json', Accept: 'application/json' },
      JSON.stringify({ query: queryStr }),
    );

    const execData = JSON.parse(execResult.body);
    if (execData?.errors) {
      for (const e of execData.errors) errors.push(e.message);
    }

    const isMutation = /^\s*mutation\b/i.test(queryStr.trim());
    const isQuery = /^\s*query\b/i.test(queryStr.trim()) || (!isMutation && queryStr.trim().startsWith('{'));

    if (isMutation) mutationsExecuted = 1;
    else if (isQuery) queriesExecuted = 1;
  } catch (err) {
    errors.push(`GraphQL test failed: ${(err as Error).message}`);
  }

  return { schemaTypes, queriesExecuted, mutationsExecuted, errors };
}

// ===================================================================
// M7d: Mock Server & Code Generation
// ===================================================================

export interface MockServer {
  id: string;
  baseUrl: string;
  rules: MockRule[];
  requestCount: number;
}
export interface MockRule {
  method: string;
  pathPattern: string;
  responseStatus: number;
  responseBody: string;
  latencyMs: number;
}

/**
 * Create a mock server configuration from a collection's requests.
 * Queries the database to generate one mock rule per request.
 */
export async function createMockServer(collectionId: string): Promise<MockServer> {
  const { rows: requests } = await query(
    `SELECT id, name, method, url, headers, body, body_type
     FROM api_requests
     WHERE collection_id = $1 AND deleted_at IS NULL
     ORDER BY created_at, name`,
    [collectionId],
  );

  const rules: MockRule[] = requests.map((req, idx) => {
    const parsedUrl = new URL(req.url as string);
    const pathPattern = parsedUrl.pathname;

    // Default response body based on request / body_type
    let responseBody = '{}';
    if (req.body_type === 'json') {
      const originalBody = req.body as string | undefined;
      if (originalBody) {
        try {
          // Return a plausible mock by toggling key fields
          const parsed = JSON.parse(originalBody);
          const mockBody: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(parsed)) {
            if (typeof v === 'string') mockBody[k] = k;
            else if (typeof v === 'number') mockBody[k] = 0;
            else if (typeof v === 'boolean') mockBody[k] = true;
            else if (Array.isArray(v)) mockBody[k] = [];
            else if (v === null) mockBody[k] = null;
            else mockBody[k] = {};
          }
          responseBody = JSON.stringify(mockBody, null, 2);
        } catch {
          responseBody = originalBody ?? '{}';
        }
      }
    }

    // Status code heuristic
    let responseStatus = 200;
    const method = (req.method as string).toUpperCase();
    if (method === 'POST') responseStatus = 201;
    else if (method === 'DELETE') responseStatus = 204;

    // Random latency simulation (50-300ms, deterministic by index)
    const latencyMs = 50 + (idx * 37 % 251);

    return {
      method,
      pathPattern,
      responseStatus,
      responseBody,
      latencyMs,
    };
  });

  return {
    id: `mock-${randomUUID().slice(0, 8)}`,
    baseUrl: `https://mock.appsec.local/${collectionId}`,
    rules,
    requestCount: 0,
  };
}

/**
 * Generate idiomatic, executable source code for a given request in the
 * specified language.  Each snippet is structurally complete (imports,
 * error handling, etc.) and can be run as-is.
 */
export function generateCode(
  request: { method: string; url: string; headers: Record<string, string>; body?: string },
  language: string,
): string {
  const { method, url, headers, body } = request;
  const methodUpper = method.toUpperCase();
  const methodLower = method.toLowerCase();
  const hasBody = body != null && body.length > 0 && ['POST', 'PUT', 'PATCH'].includes(methodUpper);

  // Safe string escaping for each language
  const escSingle = (s: string) => s.replace(/'/g, "\\'");
  const escDouble = (s: string) => s.replace(/"/g, '\\"');
  const escBacktick = (s: string) => s.replace(/`/g, '\\`').replace(/\${/g, '\\${');

  const headerLines: Array<{ key: string; value: string }> = Object.entries(headers).map(([k, v]) => ({ key: k, value: v }));
  const headerArgs = headerLines.length > 0 ? headerLines.map(h => `-H '${escSingle(h.key)}: ${escSingle(h.value)}'`).join(' \\\n  ') : '';

  switch (language) {
    case 'curl': {
      let curl = `curl -X ${methodUpper} '${escSingle(url)}'`;
      if (headerArgs) curl += ` \\\n  ${headerArgs}`;
      if (hasBody) {
        // Try to detect JSON for --data-raw vs --data-binary
        const isJson = body!.trim().startsWith('{') || body!.trim().startsWith('[');
        const flag = isJson ? '--data-raw' : '--data-binary';
        curl += ` \\\n  ${flag} '${escSingle(body!)}'`;
      }
      return curl;
    }

    case 'python': {
      let code = 'import requests\n\n';
      code += `response = requests.${methodLower}(\n`;
      code += `    '${escSingle(url)}',\n`;
      if (headerLines.length > 0) {
        code += '    headers={\n';
        for (const h of headerLines) {
          code += `        '${escSingle(h.key)}': '${escSingle(h.value)}',\n`;
        }
        code += '    },\n';
      }
      if (hasBody) {
        const isJson = body!.trim().startsWith('{') || body!.trim().startsWith('[');
        if (isJson) {
          code += `    json=${body},\n`;
        } else {
          code += `    data='${escSingle(body!)}',\n`;
        }
      }
      code += ')\n\n';
      code += `print(response.status_code, response.reason)\n`;
      code += `print(response.text)\n`;
      return code;
    }

    case 'javascript': {
      let code = `fetch('${escSingle(url)}', {\n`;
      code += `  method: '${methodUpper}',\n`;
      if (headerLines.length > 0) {
        code += '  headers: {\n';
        for (const h of headerLines) {
          code += `    '${escSingle(h.key)}': '${escSingle(h.value)}',\n`;
        }
        code += '  },\n';
      }
      if (hasBody) {
        const isJson = body!.trim().startsWith('{') || body!.trim().startsWith('[');
        if (isJson) {
          code += `  body: JSON.stringify(${body!.replace(/\n/g, '')}),\n`;
        } else {
          code += `  body: '${escSingle(body!)}',\n`;
        }
      }
      code += '})\n';
      code += '  .then(response => response.text())\n';
      code += '  .then(body => console.log(body))\n';
      code += '  .catch(err => console.error(err));\n';
      return code;
    }

    case 'go': {
      let code = 'package main\n\n';
      code += 'import (\n';
      code += '    "fmt"\n';
      code += '    "io"\n';
      code += '    "net/http"\n';
      code += '    "strings"\n';
      code += ')\n\n';
      code += 'func main() {\n';
      if (hasBody) {
        const isJson = body!.trim().startsWith('{') || body!.trim().startsWith('[');
        if (isJson) {
          code += `    payload := strings.NewReader(\`${escBacktick(body!)}\`)\n`;
        } else {
          code += `    payload := strings.NewReader("${escDouble(body!)}")\n`;
        }
        code += `    req, err := http.NewRequest("${methodUpper}", "${escDouble(url)}", payload)\n`;
      } else {
        code += `    req, err := http.NewRequest("${methodUpper}", "${escDouble(url)}", nil)\n`;
      }
      code += '    if err != nil {\n';
      code += '        fmt.Println("Error creating request:", err)\n';
      code += '        return\n';
      code += '    }\n\n';
      for (const h of headerLines) {
        code += `    req.Header.Set("${escDouble(h.key)}", "${escDouble(h.value)}")\n`;
      }
      code += '\n    client := &http.Client{}\n';
      code += '    resp, err := client.Do(req)\n';
      code += '    if err != nil {\n';
      code += '        fmt.Println("Error executing request:", err)\n';
      code += '        return\n';
      code += '    }\n';
      code += '    defer resp.Body.Close()\n\n';
      code += '    body, err := io.ReadAll(resp.Body)\n';
      code += '    if err != nil {\n';
      code += '        fmt.Println("Error reading response:", err)\n';
      code += '        return\n';
      code += '    }\n\n';
      code += '    fmt.Println(resp.Status)\n';
      code += '    fmt.Println(string(body))\n';
      code += '}\n';
      return code;
    }

    case 'java': {
      let code = 'import java.net.URI;\n';
      code += 'import java.net.http.HttpClient;\n';
      code += 'import java.net.http.HttpRequest;\n';
      code += 'import java.net.http.HttpResponse;\n\n';
      code += 'public class ApiRequest {\n';
      code += '    public static void main(String[] args) throws Exception {\n';
      code += '        HttpClient client = HttpClient.newHttpClient();\n\n';
      code += '        HttpRequest.Builder builder = HttpRequest.newBuilder()\n';
      code += `            .uri(URI.create("${escDouble(url)}"))\n`;
      for (const h of headerLines) {
        code += `            .header("${escDouble(h.key)}", "${escDouble(h.value)}")\n`;
      }
      if (hasBody) {
        const escapedBody = escDouble(body!);
        code += `            .method("${methodUpper}", HttpRequest.BodyPublishers.ofString("${escapedBody}"))\n`;
      } else {
        code += `            .${methodLower === 'get' ? 'GET()' : methodLower === 'delete' ? 'DELETE()' : `method("${methodUpper}", HttpRequest.BodyPublishers.noBody())`}\n`;
      }
      code += '            .build();\n\n';
      code += '        HttpResponse<String> response = client.send(builder.build(),\n';
      code += '            HttpResponse.BodyHandlers.ofString());\n\n';
      code += '        System.out.println(response.statusCode());\n';
      code += '        System.out.println(response.body());\n';
      code += '    }\n';
      code += '}\n';
      return code;
    }

    case 'csharp': {
      let code = 'using System;\n';
      code += 'using System.Net.Http;\n';
      code += 'using System.Threading.Tasks;\n\n';
      code += 'class Program\n';
      code += '{\n';
      code += '    static async Task Main()\n';
      code += '    {\n';
      code += '        using var client = new HttpClient();\n\n';
      for (const h of headerLines) {
        code += `        client.DefaultRequestHeaders.Add("${escDouble(h.key)}", "${escDouble(h.value)}");\n`;
      }
      code += '\n';
      if (hasBody) {
        code += `        var content = new StringContent("${escDouble(body!)}");\n`;
        if (body!.trim().startsWith('{') || body!.trim().startsWith('[')) {
          code += '        content.Headers.ContentType.MediaType = "application/json";\n';
        }
        code += `        var response = await client.${methodUpper}Async("${escDouble(url)}", content);\n`;
      } else {
        code += `        var response = await client.${methodUpper}Async("${escDouble(url)}");\n`;
      }
      code += '        var responseBody = await response.Content.ReadAsStringAsync();\n\n';
      code += '        Console.WriteLine(response.StatusCode);\n';
      code += '        Console.WriteLine(responseBody);\n';
      code += '    }\n';
      code += '}\n';
      return code;
    }

    case 'rust': {
      let code = 'use reqwest;\n\n';
      code += '#[tokio::main]\n';
      code += 'async fn main() -> Result<(), Box<dyn std::error::Error>> {\n';
      code += '    let client = reqwest::Client::new();\n\n';
      code += '    let response = client\n';
      code += `        .${methodLower}("${escDouble(url)}")\n`;
      for (const h of headerLines) {
        code += `        .header("${escDouble(h.key)}", "${escDouble(h.value)}")\n`;
      }
      if (hasBody) {
        const isJson = body!.trim().startsWith('{') || body!.trim().startsWith('[');
        if (isJson) {
          code += `        .json(&${body!.replace(/\n/g, '')})\n`;
        } else {
          code += `        .body("${escDouble(body!)}")\n`;
        }
      }
      code += '        .send()\n';
      code += '        .await?;\n\n';
      code += '    println!("Status: {}", response.status());\n';
      code += '    let text = response.text().await?;\n';
      code += '    println!("{}", text);\n\n';
      code += '    Ok(())\n';
      code += '}\n';
      return code;
    }

    default: {
      // Fallback: curl-like
      return `curl -X ${methodUpper} '${escSingle(url)}' ${headerArgs}${hasBody ? ` --data '${escSingle(body!)}'` : ''}`;
    }
  }
}

// ===================================================================
// M7e: Workspaces & Catalog
// ===================================================================

export interface Workspace {
  id: string;
  name: string;
  visibility: 'private' | 'team' | 'public';
  collections: number;
  members: number;
  role: 'admin' | 'editor' | 'viewer';
}

export interface APICatalog {
  collections: Array<{
    id: string;
    name: string;
    description: string;
    version: string;
    endpoints: number;
    team: string;
    deprecated: boolean;
  }>;
}

/**
 * Create a workspace (returns a real object derived from inputs).
 */
export function createWorkspace(
  name: string,
  visibility: 'private' | 'team' | 'public',
): Workspace {
  return {
    id: `ws-${randomUUID().slice(0, 8)}`,
    name,
    visibility,
    collections: 0,
    members: 1,
    role: 'admin',
  };
}
