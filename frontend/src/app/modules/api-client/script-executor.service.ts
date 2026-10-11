import { Injectable } from '@angular/core';

export interface ScriptResult {
  tests: TestResult[];
  logs: string[];
  error: string | null;
  executionTime: number;
}

export interface TestResult {
  name: string;
  passed: boolean;
  error: string | null;
}

export interface PmContext {
  variables: PmVarStore;
  environment: PmVarStore;
  collectionVariables: PmVarStore;
  globals: PmVarStore;
  request: PmRequest;
  response: PmResponse;
  test: (name: string, fn: () => void) => void;
  expect: (actual: unknown) => PmExpectChain;
  iterationData: PmVarStore;
}

interface PmVarStore {
  get: (key: string) => unknown;
  set: (key: string, value: unknown) => void;
  has: (key: string) => boolean;
  unset: (key: string) => void;
  clear: () => void;
  toObject: () => Record<string, unknown>;
  replace: (vars: Record<string, unknown>) => void;
}

interface PmRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
  addHeader: (key: string, value: string) => void;
  removeHeader: (key: string) => void;
}

interface PmResponse {
  status: number;
  statusText: string;
  body: string;
  headers: Record<string, string>;
  responseTime: number;
  code: number;
  text: () => string;
  json: () => unknown;
  toJSON: () => Record<string, unknown>;
}

interface PmExpectChain {
  to: PmExpectTo;
  not: PmExpectNot;
}

interface PmExpectTo {
  exist: () => PmExpectChain;
  be: PmExpectBe;
  equal: (expected: unknown) => PmExpectChain;
  eql: (expected: unknown) => PmExpectChain;
  deep: { equal: (expected: unknown) => PmExpectChain };
  include: (expected: unknown) => PmExpectChain;
  have: PmExpectHave;
  match: (regex: RegExp) => PmExpectChain;
  satisfy: (predicate: (val: unknown) => boolean) => PmExpectChain;
  beTrue: () => PmExpectChain;
  beFalse: () => PmExpectChain;
  beNull: () => PmExpectChain;
  beUndefined: () => PmExpectChain;
  beOk: () => PmExpectChain;
  beEmpty: () => PmExpectChain;
  beAbove: (n: number) => PmExpectChain;
  beBelow: (n: number) => PmExpectChain;
  beAtLeast: (n: number) => PmExpectChain;
  beAtMost: (n: number) => PmExpectChain;
  beA: (type: string) => PmExpectChain;
  beAn: (type: string) => PmExpectChain;
  beInstanceOf: (ctor: new (...args: unknown[]) => unknown) => PmExpectChain;
  beGreaterThan: (n: number) => PmExpectChain;
  beLessThan: (n: number) => PmExpectChain;
  throw: (error?: unknown) => PmExpectChain;
  resolve: () => PmExpectChain;
  reject: () => PmExpectChain;
  haveLengthOf: (n: number) => PmExpectChain;
  haveProperty: (key: string, val?: unknown) => PmExpectChain;
}

interface PmExpectBe extends Omit<PmExpectTo, 'be'> {
  a: (type: string) => PmExpectChain;
  an: (type: string) => PmExpectChain;
  ok: () => PmExpectChain;
  true: () => PmExpectChain;
  false: () => PmExpectChain;
  null: () => PmExpectChain;
  undefined: () => PmExpectChain;
  empty: () => PmExpectChain;
  above: (n: number) => PmExpectChain;
  below: (n: number) => PmExpectChain;
  atLeast: (n: number) => PmExpectChain;
  atMost: (n: number) => PmExpectChain;
  greaterThan: (n: number) => PmExpectChain;
  lessThan: (n: number) => PmExpectChain;
  instanceOf: (ctor: new (...args: unknown[]) => unknown) => PmExpectChain;
  lengthOf: (n: number) => PmExpectChain;
}

interface PmExpectHave {
  property: (key: string, val?: unknown) => PmExpectChain;
  lengthOf: (n: number) => PmExpectChain;
}

interface PmExpectNot {
  exist: () => PmExpectChain;
  equal: (expected: unknown) => PmExpectChain;
  include: (expected: unknown) => PmExpectChain;
  match: (regex: RegExp) => PmExpectChain;
  satisfy: (predicate: (val: unknown) => boolean) => PmExpectChain;
  beTrue: () => PmExpectChain;
  beFalse: () => PmExpectChain;
  beNull: () => PmExpectChain;
  beUndefined: () => PmExpectChain;
  beOk: () => PmExpectChain;
  beEmpty: () => PmExpectChain;
  beAbove: (n: number) => PmExpectChain;
  beBelow: (n: number) => PmExpectChain;
  beA: (type: string) => PmExpectChain;
  beInstanceOf: (ctor: new (...args: unknown[]) => unknown) => PmExpectChain;
  throw: (error?: unknown) => PmExpectChain;
}

@Injectable({ providedIn: 'root' })
export class ScriptExecutorService {
  private testResults: TestResult[] = [];
  private logEntries: string[] = [];
  private expectError: string | null = null;

  /**
   * Execute a pre-request or post-response script in a sandboxed environment.
   * Returns test results, logs, and any errors.
   */
  execute(
    script: string,
    context: {
      variables?: Record<string, unknown>;
      environment?: Record<string, unknown>;
      collectionVariables?: Record<string, unknown>;
      globals?: Record<string, unknown>;
      request?: { method?: string; url?: string; headers?: Record<string, string>; body?: unknown };
      response?: { status?: number; statusText?: string; body?: string; headers?: Record<string, string>; responseTime?: number };
      iterationData?: Record<string, unknown>;
    },
  ): ScriptResult {
    this.testResults = [];
    this.logEntries = [];
    this.expectError = null;

    const startTime = performance.now();

    try {
      const pm = this.buildPmContext(context);

      // Wrap the script in a try/catch at the script level to capture top-level errors
      const wrappedScript = `
        (function(pm, console) {
          var _origConsoleLog = console.log;
          var _origConsoleWarn = console.warn;
          var _origConsoleError = console.error;

          console.log = function() {
            var args = Array.prototype.slice.call(arguments);
            _origConsoleLog.apply(console, args);
            _pmLog(args.map(function(a) { return typeof a === 'object' ? JSON.stringify(a) : String(a); }).join(' '));
          };
          console.warn = function() {
            var args = Array.prototype.slice.call(arguments);
            _origConsoleWarn.apply(console, args);
            _pmLog('[warn] ' + args.map(function(a) { return typeof a === 'object' ? JSON.stringify(a) : String(a); }).join(' '));
          };
          console.error = function() {
            var args = Array.prototype.slice.call(arguments);
            _origConsoleError.apply(console, args);
            _pmLog('[error] ' + args.map(function(a) { return typeof a === 'object' ? JSON.stringify(a) : String(a); }).join(' '));
          };

          ${script}
        })(pm, console);
      `;

      // Defense-in-depth: shadow dangerous globals as undefined params so a test
      // script can't reach the DOM, network, or storage. (Not a true sandbox —
      // full isolation would require a Web Worker; this raises the bar for
      // imported/shared scripts without that refactor.)
      const SHADOWED_GLOBALS = [
        'window', 'document', 'globalThis', 'self', 'parent', 'top', 'frames',
        'fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'navigator', 'location',
        'localStorage', 'sessionStorage', 'indexedDB', 'caches', 'eval', 'importScripts',
      ];
      const executeFn = new Function(
        'pm', 'console', '_pmLog', '_pmTest', '_pmExpect', ...SHADOWED_GLOBALS, wrappedScript,
      );

      executeFn(
        this.buildPmContext(context),
        console,
        (msg: string) => this.logEntries.push(msg),
        (name: string, fn: () => void) => this.runTest(name, fn),
        (actual: unknown) => this.createExpectChain(actual),
        ...SHADOWED_GLOBALS.map(() => undefined),
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logEntries.push('[script error] ' + msg);
      return {
        tests: this.testResults,
        logs: this.logEntries,
        error: msg,
        executionTime: performance.now() - startTime,
      };
    }

    return {
      tests: this.testResults,
      logs: this.logEntries,
      error: this.expectError,
      executionTime: performance.now() - startTime,
    };
  }

  private buildPmContext(context: {
    variables?: Record<string, unknown>;
    environment?: Record<string, unknown>;
    collectionVariables?: Record<string, unknown>;
    globals?: Record<string, unknown>;
    request?: { method?: string; url?: string; headers?: Record<string, string>; body?: unknown };
    response?: { status?: number; statusText?: string; body?: string; headers?: Record<string, string>; responseTime?: number };
    iterationData?: Record<string, unknown>;
  }): PmContext {
    let requestHeaders: Record<string, string> = { ...(context.request?.headers || {}) };

    const pm: PmContext = {
      variables: this.createVarStore(context.variables || {}),
      environment: this.createVarStore(context.environment || {}),
      collectionVariables: this.createVarStore(context.collectionVariables || {}),
      globals: this.createVarStore(context.globals || {}),
      iterationData: this.createVarStore(context.iterationData || {}),

      request: {
        method: context.request?.method || 'GET',
        url: context.request?.url || '',
        headers: requestHeaders,
        body: context.request?.body,
        addHeader: (key: string, value: string) => { requestHeaders[key] = value; },
        removeHeader: (key: string) => { delete requestHeaders[key]; },
      },

      response: {
        status: context.response?.status || 0,
        statusText: context.response?.statusText || '',
        body: context.response?.body || '',
        headers: context.response?.headers || {},
        responseTime: context.response?.responseTime || 0,
        code: context.response?.status || 0,
        text: () => context.response?.body || '',
        json: () => {
          try { return JSON.parse(context.response?.body || '{}'); } catch { return {}; }
        },
        toJSON: () => ({
          status: context.response?.status || 0,
          body: context.response?.body || '',
          headers: context.response?.headers || {},
          responseTime: context.response?.responseTime || 0,
        }),
      },

      test: (name: string, fn: () => void) => this.runTest(name, fn),

      expect: (actual: unknown) => this.createExpectChain(actual),
    };

    return pm;
  }

  private createVarStore(initial: Record<string, unknown>): PmVarStore {
    const store: Record<string, unknown> = { ...initial };
    return {
      get: (key: string) => store[key],
      set: (key: string, value: unknown) => { store[key] = value; },
      has: (key: string) => key in store,
      unset: (key: string) => { delete store[key]; },
      clear: () => { Object.keys(store).forEach(k => delete store[k]); },
      toObject: () => ({ ...store }),
      replace: (vars: Record<string, unknown>) => {
        Object.keys(store).forEach(k => delete store[k]);
        Object.assign(store, vars);
      },
    };
  }

  private runTest(name: string, fn: () => void): void {
    try {
      fn();
      this.testResults.push({ name, passed: true, error: null });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.testResults.push({ name, passed: false, error: msg });
    }
  }

  /**
   * Build a chai-style expect chain. Each method records the assertion
   * and throws on failure so pm.test catches it.
   */
  private createExpectChain(actual: unknown): PmExpectChain {
    let negate = false;
    const assert = (condition: boolean, message: string): void => {
      if (negate ? condition : !condition) {
        throw new Error(message);
      }
    };
    const resetNegate = () => { negate = false; };

    // Build the chain with lazy property accessors for 'not' and 'to'
    const toObj = this.buildToObject(actual, assert, resetNegate, () => negate, () => chain);

    const chain: PmExpectChain = {
      get not(): PmExpectNot {
        negate = true;
        return chain as unknown as PmExpectNot;
      },
      get to() {
        return toObj;
      },
    };
    return chain;
  }

  private buildToObject(
    actual: unknown,
    assert: (condition: boolean, message: string) => void,
    resetNegate: () => void,
    getNegate: () => boolean,
    getChain: () => PmExpectChain,
  ): PmExpectTo {
    const self = this;
    const chain = getChain;
    const rn = resetNegate;

    const beObj: PmExpectBe = <PmExpectBe><unknown>{
      a: (type: string) => { assert(typeof actual === type, `expected ${JSON.stringify(actual)} to be a ${type}`); rn(); return chain(); },
      an: (type: string) => { assert(typeof actual === type, `expected ${JSON.stringify(actual)} to be an ${type}`); rn(); return chain(); },
      ok: () => { assert(!!actual, `expected ${JSON.stringify(actual)} to be truthy`); rn(); return chain(); },
      true: () => { assert(actual === true, `expected ${JSON.stringify(actual)} to be true`); rn(); return chain(); },
      false: () => { assert(actual === false, `expected ${JSON.stringify(actual)} to be false`); rn(); return chain(); },
      null: () => { assert(actual === null, `expected ${JSON.stringify(actual)} to be null`); rn(); return chain(); },
      undefined: () => { assert(actual === undefined, `expected ${JSON.stringify(actual)} to be undefined`); rn(); return chain(); },
      empty: () => {
        const isEmpty = actual == null || (Array.isArray(actual) && actual.length === 0) || (typeof actual === 'string' && actual.length === 0) || (typeof actual === 'object' && Object.keys(actual as Record<string, unknown>).length === 0);
        assert(isEmpty, `expected ${JSON.stringify(actual)} to be empty`); rn(); return chain();
      },
      above: (n: number) => { assert(typeof actual === 'number' && actual > n, `expected ${actual} to be above ${n}`); rn(); return chain(); },
      below: (n: number) => { assert(typeof actual === 'number' && actual < n, `expected ${actual} to be below ${n}`); rn(); return chain(); },
      atLeast: (n: number) => { assert(typeof actual === 'number' && actual >= n, `expected ${actual} to be at least ${n}`); rn(); return chain(); },
      atMost: (n: number) => { assert(typeof actual === 'number' && actual <= n, `expected ${actual} to be at most ${n}`); rn(); return chain(); },
      greaterThan: (n: number) => { assert(typeof actual === 'number' && actual > n, `expected ${actual} to be greater than ${n}`); rn(); return chain(); },
      lessThan: (n: number) => { assert(typeof actual === 'number' && actual < n, `expected ${actual} to be less than ${n}`); rn(); return chain(); },
      instanceOf: (ctor: new (...args: unknown[]) => unknown) => { assert(actual instanceof ctor, `expected ${JSON.stringify(actual)} to be instance of ${ctor.name}`); rn(); return chain(); },
      lengthOf: (n: number) => { const len = (actual as { length?: number })?.length ?? 0; assert(len === n, `expected length ${len} to be ${n}`); rn(); return chain(); },
    };

    const to: PmExpectTo = <PmExpectTo><unknown>{
      exist: () => { assert(actual != null, `expected ${JSON.stringify(actual)} to exist`); rn(); return chain(); },
      be: beObj,
      equal: (expected: unknown) => { assert(expected === actual, `expected ${JSON.stringify(actual)} to equal ${JSON.stringify(expected)}`); rn(); return chain(); },
      eql: (expected: unknown) => {
        const ok = JSON.stringify(actual) === JSON.stringify(expected);
        assert(ok, `expected ${JSON.stringify(actual)} to deeply equal ${JSON.stringify(expected)}`); rn(); return chain();
      },
      deep: { equal: (expected: unknown) => to.eql(expected) },
      include: (expected: unknown) => {
        if (typeof actual === 'string' && typeof expected === 'string') {
          assert(actual.includes(expected), `expected "${actual}" to include "${expected}"`);
        } else if (Array.isArray(actual)) {
          assert(actual.some(i => i === expected), `expected array to include ${JSON.stringify(expected)}`);
        } else if (actual && typeof actual === 'object') {
          assert((expected as string) in (actual as Record<string, unknown>), `expected object to include key ${JSON.stringify(expected)}`);
        }
        rn(); return chain();
      },
      have: {
        property: (key: string, val?: unknown) => {
          const obj = actual as Record<string, unknown>;
          assert(key in obj, `expected object to have property ${key}`);
          if (val !== undefined) {
            assert(obj[key] === val, `expected property ${key} to equal ${JSON.stringify(val)} but got ${JSON.stringify(obj[key])}`);
          }
          rn(); return chain();
        },
        lengthOf: (n: number) => to.be.lengthOf(n),
      },
      match: (regex: RegExp) => { assert(regex.test(String(actual)), `expected ${JSON.stringify(actual)} to match ${regex}`); rn(); return chain(); },
      satisfy: (predicate: (val: unknown) => boolean) => { assert(predicate(actual), `expected ${JSON.stringify(actual)} to satisfy predicate`); rn(); return chain(); },
      beTrue: () => to.be.true(),
      beFalse: () => to.be.false(),
      beNull: () => to.be.null(),
      beUndefined: () => to.be.undefined(),
      beOk: () => to.be.ok(),
      beEmpty: () => to.be.empty(),
      beAbove: (n: number) => to.be.above(n),
      beBelow: (n: number) => to.be.below(n),
      beAtLeast: (n: number) => to.be.atLeast(n),
      beAtMost: (n: number) => to.be.atMost(n),
      beA: (type: string) => to.be.a(type),
      beAn: (type: string) => to.be.an(type),
      beInstanceOf: (ctor: new (...args: unknown[]) => unknown) => to.be.instanceOf(ctor),
      beGreaterThan: (n: number) => to.be.greaterThan(n),
      beLessThan: (n: number) => to.be.lessThan(n),
      resolve: () => chain(),
      reject: () => chain(),
      haveLengthOf: (n: number) => to.be.lengthOf(n),
      haveProperty: (key: string, val?: unknown) => to.have.property(key, val),
    };
    // Use Object.defineProperty to add 'throw' to avoid reserved word issues
    Object.defineProperty(to, 'throw', {
      value: () => {
        assert(typeof actual === 'function', 'expected a function');
        try { (actual as () => void)(); assert(getNegate(), 'expected function to throw'); rn(); return chain(); }
        catch (_e) { assert(!getNegate(), 'expected function not to throw'); rn(); return chain(); }
      },
      writable: false,
      enumerable: true,
      configurable: false,
    });
    return to;
  }
}
