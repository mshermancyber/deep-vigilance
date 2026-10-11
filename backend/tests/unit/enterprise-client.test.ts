// Enterprise API Client — Comprehensive Tests (M7a-M7e)
// Tests that every function produces real results from real inputs,
// with no hardcoded or stubbed return values.

import { describe, it, expect, vi } from 'vitest';

// Mock DB pool and logger to avoid environment config validation at import time.
// The enterprise-client.ts imports pool.ts -> logger.ts -> config/index.ts which
// validates env vars (DB_PASSWORD, REDIS_PASSWORD, etc.) and exits if missing.
vi.mock('../../src/core/db/pool.js', () => ({
  query: vi.fn(),
}));
vi.mock('../../src/core/logging/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

import {
  ScriptEngine,
  evaluateJsonPath,
  validateJsonSchema,
  compareValues,
  generateCode,
  createWorkspace,
} from '../../src/services/api-client/enterprise-client.js';

// ===================================================================
// Helper: fake response factory for assertions
// ===================================================================

function makeResponse(overrides: Partial<{
  status: number;
  headers: Record<string, string>;
  body: string;
  timeMs: number;
}> = {}) {
  return {
    status: 200,
    headers: { 'content-type': 'application/json', 'x-request-id': 'abc-123' },
    body: JSON.stringify({ name: 'Alice', age: 30, roles: ['admin', 'user'], metadata: { region: 'us-east' } }),
    timeMs: 150,
    ...overrides,
  };
}

// ===================================================================
// M7a: Script Engine
// ===================================================================

describe('ScriptEngine — executePostResponse', () => {
  const engine = new ScriptEngine();

  it('executes a script with pm.test() and reports passing tests', () => {
    const script = `
      pm.test("status is 200", () => {
        pm.expect(pm.response.status).to.equal(200);
      });
      pm.test("body has name", () => {
        const json = pm.response.json();
        pm.expect(json).to.have.property('name');
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(2);
    expect(result.tests[0]!.name).toBe('status is 200');
    expect(result.tests[0]!.passed).toBe(true);
    expect(result.tests[1]!.name).toBe('body has name');
    expect(result.tests[1]!.passed).toBe(true);
    expect(result.timedOut).toBe(false);
  });

  it('reports assertion failures from pm.expect()', () => {
    const script = `
      pm.test("status is 404", () => {
        pm.expect(pm.response.status).to.equal(404);
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse({ status: 200 }),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.name).toBe('status is 404');
    expect(result.tests[0]!.passed).toBe(false);
    expect(result.tests[0]!.message).toContain('expected 404 but got 200');
  });

  it('provides pm.response.json() with parsed body', () => {
    const script = `
      pm.test("json parse works", () => {
        const json = pm.response.json();
        pm.expect(json.name).to.eql("Alice");
        pm.expect(json.age).to.eql(30);
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(true);
  });

  it('provides pm.response.to.have.status() and pm.response.to.be.ok()', () => {
    const script = `
      pm.test("status helpers", () => {
        pm.response.to.have.status(200);
        pm.response.to.be.ok();
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(true);
  });

  it('pm.response.to.have.status() fails on mismatch', () => {
    const script = `
      pm.test("wrong status", () => {
        pm.response.to.have.status(500);
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse({ status: 200 }),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(false);
    expect(result.tests[0]!.message).toContain('Expected status 500 but got 200');
  });

  it('pm.response.to.be.ok() fails on error status', () => {
    const script = `
      pm.test("not ok", () => {
        pm.response.to.be.ok();
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse({ status: 500 }),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(false);
  });

  it('pm.expect() chain supports .not negation', () => {
    const script = `
      pm.test("not equal", () => {
        pm.expect(1 + 1).not.to.equal(3);
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(true);
  });

  it('pm.expect() chain supports .eql deep equality', () => {
    const script = `
      pm.test("deep equal", () => {
        pm.expect({a: 1, b: 2}).to.eql({a: 1, b: 2});
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(true);
  });

  it('pm.expect().to.include works on strings', () => {
    const script = `
      pm.test("includes", () => {
        pm.expect("hello world").to.include("world");
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(true);
  });

  it('pm.expect().to.have.property() works', () => {
    const script = `
      pm.test("has property", () => {
        pm.expect({x: 10}).to.have.property("x", 10);
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(true);
  });

  it('handles multiple pm.test() calls from a single script', () => {
    const script = `
      pm.test("test A", () => { pm.expect(1).to.eql(1); });
      pm.test("test B", () => { pm.expect(2).to.eql(2); });
      pm.test("test C", () => { pm.expect(3).to.eql(4); });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(3);
    expect(result.tests[0]!.passed).toBe(true);
    expect(result.tests[1]!.passed).toBe(true);
    expect(result.tests[2]!.passed).toBe(false);
  });

  it('handles scripts with no pm.test() calls', () => {
    const script = 'console.log("no tests here");';
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(0);
    expect(result.stdout).toContain('no tests here');
  });

  it('captures console output from scripts', () => {
    const script = `
      console.log("hello from sandbox");
      console.warn("warning message");
      console.error("error message");
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.stdout).toContain('hello from sandbox');
    expect(result.stdout).toContain('[WARN] warning message');
    expect(result.stderr).toContain('error message');
  });

  it('rejects sandbox escape attempts (constructor reentry)', () => {
    const script = 'this.constructor.constructor("return process")()';
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(0);
    expect(result.stderr).toContain('Sandbox escape attempt detected');
  });

  it('rejects sandbox escape attempts (process access)', () => {
    const script = 'process.env';
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.stderr).toContain('Sandbox escape attempt detected');
  });

  it('rejects sandbox escape attempts (globalThis)', () => {
    const script = 'globalThis.fetch("http://evil.com")';
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.stderr).toContain('Sandbox escape attempt detected');
  });

  it('pm.response.text() returns the body string', () => {
    const script = `
      pm.test("text works", () => {
        const t = pm.response.text();
        pm.expect(t).to.include("Alice");
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(true);
  });

  it('pm.variables.set/get works inside scripts', () => {
    const vars = new Map<string, string>([['existing', 'hello']]);
    const script = `
      pm.test("variable access", () => {
        pm.expect(pm.variables.get("existing")).to.eql("hello");
      });
      pm.variables.set("newvar", "world");
    `;
    const result = engine.executePostResponse(script, {
      variables: vars,
      response: makeResponse(),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(true);
  });

  it('response time is exposed via pm.response.responseTime', () => {
    const script = `
      pm.test("response time", () => {
        pm.expect(pm.response.responseTime).to.be.below(1000);
      });
    `;
    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: makeResponse({ timeMs: 150 }),
    });

    expect(result.tests).toHaveLength(1);
    expect(result.tests[0]!.passed).toBe(true);
  });
});

// ===================================================================
// executeAssertions — REAL evaluation of each assertion type
// ===================================================================

describe('ScriptEngine — executeAssertions', () => {
  const engine = new ScriptEngine();

  // --- status ---
  it('status assertion: passes when response status matches', () => {
    const results = engine.executeAssertions(
      [{ type: 'status', operator: 'equals', value: '200' }],
      makeResponse({ status: 200 }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
    expect(results[0]!.actual).toBe('200');
  });

  it('status assertion: fails when response status differs', () => {
    const results = engine.executeAssertions(
      [{ type: 'status', operator: 'equals', value: '404' }],
      makeResponse({ status: 200 }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
  });

  // --- header ---
  it('header assertion: passes on exists', () => {
    const results = engine.executeAssertions(
      [{ type: 'header', operator: 'exists', target: 'content-type' }],
      makeResponse({ headers: { 'content-type': 'application/json' } }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
    expect(results[0]!.actual).toBe('application/json');
  });

  it('header assertion: fails on not_exists when header present', () => {
    const results = engine.executeAssertions(
      [{ type: 'header', operator: 'not_exists', target: 'content-type' }],
      makeResponse({ headers: { 'content-type': 'application/json' } }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
  });

  it('header assertion: passes on not_exists when header missing', () => {
    const results = engine.executeAssertions(
      [{ type: 'header', operator: 'not_exists', target: 'x-missing' }],
      makeResponse({ headers: { 'content-type': 'application/json' } }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
    expect(results[0]!.actual).toBe('(missing)');
  });

  it('header assertion: passes on equals', () => {
    const results = engine.executeAssertions(
      [{ type: 'header', operator: 'equals', target: 'content-type', value: 'application/json' }],
      makeResponse({ headers: { 'content-type': 'application/json' } }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  it('header assertion: fails on equals with wrong value', () => {
    const results = engine.executeAssertions(
      [{ type: 'header', operator: 'equals', target: 'content-type', value: 'text/html' }],
      makeResponse({ headers: { 'content-type': 'application/json' } }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
  });

  // --- body ---
  it('body assertion: passes on contains', () => {
    const results = engine.executeAssertions(
      [{ type: 'body', operator: 'contains', value: 'Alice' }],
      makeResponse({ body: '{"name":"Alice","age":30}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  it('body assertion: fails on contains when body does not match', () => {
    const results = engine.executeAssertions(
      [{ type: 'body', operator: 'contains', value: 'Bob' }],
      makeResponse({ body: '{"name":"Alice","age":30}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
  });

  it('body assertion: passes on regex', () => {
    const results = engine.executeAssertions(
      [{ type: 'body', operator: 'regex', value: '\\"age\\":\\d+' }],
      makeResponse({ body: '{"name":"Alice","age":30}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  it('body assertion: fails on regex when pattern does not match', () => {
    const results = engine.executeAssertions(
      [{ type: 'body', operator: 'regex', value: '\\"ssn\\":' }],
      makeResponse({ body: '{"name":"Alice"}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
  });

  // --- json_path ---
  it('json_path assertion: finds value by dot notation', () => {
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'equals', target: '$.name', value: 'Alice' }],
      makeResponse({ body: '{"name":"Alice","age":30}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
    expect(results[0]!.actual).toContain('Alice');
  });

  it('json_path assertion: finds nested value by dot notation', () => {
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'equals', target: '$.metadata.region', value: 'us-east' }],
      makeResponse(),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  it('json_path assertion: finds array element by bracket index', () => {
    const body = JSON.stringify({ items: [10, 20, 30] });
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'equals', target: '$.items[0]', value: '10' }],
      makeResponse({ body }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  it('json_path assertion: bracket notation for object keys', () => {
    const body = JSON.stringify({ 'some-key': 'value' });
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'equals', target: "$['some-key']", value: 'value' }],
      makeResponse({ body }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  it('json_path assertion: wildcard returns all array elements', () => {
    const body = JSON.stringify([1, 2, 3]);
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'equals', target: '$[*]', value: '' }],
      makeResponse({ body }),
    );
    // With wildcard, results is array [1,2,3], so compareValues compares array === '' which fails
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('1');
    expect(results[0]!.actual).toContain('2');
    expect(results[0]!.actual).toContain('3');
  });

  it('json_path assertion: exists passes when path matches', () => {
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'exists', target: '$.name' }],
      makeResponse({ body: '{"name":"Alice"}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  it('json_path assertion: exists fails when path has no match', () => {
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'exists', target: '$.nonexistent' }],
      makeResponse({ body: '{"name":"Alice"}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
  });

  it('json_path assertion: not_exists passes when path has no match', () => {
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'not_exists', target: '$.nonexistent' }],
      makeResponse({ body: '{"name":"Alice"}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  it('json_path assertion: handles invalid JSON body gracefully', () => {
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'exists', target: '$.name' }],
      makeResponse({ body: 'not-json' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('JSON parse error');
  });

  it('json_path assertion: supports recursive descent (..)', () => {
    const body = JSON.stringify({ a: { b: { c: 1 } } });
    const results = engine.executeAssertions(
      [{ type: 'json_path', operator: 'exists', target: '$..c' }],
      makeResponse({ body }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  // --- response_time ---
  it('response_time assertion: less_than passes when under threshold', () => {
    const results = engine.executeAssertions(
      [{ type: 'response_time', operator: 'less_than', value: '1000' }],
      makeResponse({ timeMs: 150 }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
    expect(results[0]!.actual).toBe('150ms');
  });

  it('response_time assertion: less_than fails when over threshold', () => {
    const results = engine.executeAssertions(
      [{ type: 'response_time', operator: 'less_than', value: '100' }],
      makeResponse({ timeMs: 150 }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
  });

  it('response_time assertion: greater_than passes when over threshold', () => {
    const results = engine.executeAssertions(
      [{ type: 'response_time', operator: 'greater_than', value: '50' }],
      makeResponse({ timeMs: 150 }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });

  // --- schema ---
  it('schema assertion: passes when JSON matches schema', () => {
    const schema = JSON.stringify({
      type: 'object',
      properties: {
        name: { type: 'string' },
        age: { type: 'number' },
      },
      required: ['name', 'age'],
    });
    const results = engine.executeAssertions(
      [{ type: 'schema', operator: 'valid', value: schema }],
      makeResponse({ body: '{"name":"Alice","age":30}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
    expect(results[0]!.actual).toBe('Valid');
  });

  it('schema assertion: fails when JSON does not match schema', () => {
    const schema = JSON.stringify({
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email' },
      },
      required: ['email'],
    });
    const results = engine.executeAssertions(
      [{ type: 'schema', operator: 'valid', value: schema }],
      makeResponse({ body: '{"name":"Alice","age":30}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('missing required');
  });

  it('schema assertion: validates string minLength', () => {
    const schema = JSON.stringify({
      type: 'object',
      properties: { name: { type: 'string', minLength: 10 } },
    });
    const results = engine.executeAssertions(
      [{ type: 'schema', operator: 'valid', value: schema }],
      makeResponse({ body: '{"name":"Alice"}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('minLength');
  });

  it('schema assertion: validates numeric multipleOf', () => {
    const schema = JSON.stringify({
      type: 'object',
      properties: { count: { type: 'number', multipleOf: 5 } },
    });
    const results = engine.executeAssertions(
      [{ type: 'schema', operator: 'valid', value: schema }],
      makeResponse({ body: '{"count":7}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('multipleOf');
  });

  it('schema assertion: validates enum constraint', () => {
    const schema = JSON.stringify({
      type: 'object',
      properties: { role: { type: 'string', enum: ['admin', 'user'] } },
    });
    const results = engine.executeAssertions(
      [{ type: 'schema', operator: 'valid', value: schema }],
      makeResponse({ body: '{"role":"superuser"}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('not in enum');
  });

  it('schema assertion: validates array minItems', () => {
    const schema = JSON.stringify({
      type: 'object',
      properties: { tags: { type: 'array', minItems: 3 } },
    });
    const results = engine.executeAssertions(
      [{ type: 'schema', operator: 'valid', value: schema }],
      makeResponse({ body: '{"tags":["a","b"]}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('minItems');
  });

  it('schema assertion: validates additionalProperties: false', () => {
    const schema = JSON.stringify({
      type: 'object',
      properties: { name: { type: 'string' } },
      additionalProperties: false,
    });
    const results = engine.executeAssertions(
      [{ type: 'schema', operator: 'valid', value: schema }],
      makeResponse({ body: '{"name":"Alice","extra":"should not be here"}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('unexpected property');
  });

  it('schema assertion: validates date-time format', () => {
    const schema = JSON.stringify({
      type: 'object',
      properties: { ts: { type: 'string', format: 'date-time' } },
    });
    const results = engine.executeAssertions(
      [{ type: 'schema', operator: 'valid', value: schema }],
      makeResponse({ body: '{"ts":"not-a-date"}' }),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('invalid date-time');
  });

  it('schema assertion: handles invalid schema JSON gracefully', () => {
    const results = engine.executeAssertions(
      [{ type: 'schema', operator: 'valid', value: 'not-json' }],
      makeResponse(),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.actual).toContain('Schema validation error');
  });

  // --- multiple assertions ---
  it('processes multiple assertion types in one call', () => {
    const results = engine.executeAssertions(
      [
        { type: 'status', operator: 'equals', value: '200' },
        { type: 'header', operator: 'exists', target: 'content-type' },
        { type: 'response_time', operator: 'less_than', value: '500' },
        { type: 'json_path', operator: 'exists', target: '$.name' },
      ],
      makeResponse(),
    );

    expect(results).toHaveLength(4);
    expect(results[0]!.passed).toBe(true);
    expect(results[1]!.passed).toBe(true);
    expect(results[2]!.passed).toBe(true);
    expect(results[3]!.passed).toBe(true);
  });

  it('produces correct assertion labels', () => {
    const results = engine.executeAssertions(
      [{ type: 'status', operator: 'equals', value: '200' }],
      makeResponse(),
    );
    expect(results[0]!.assertion).toContain('status');
    expect(results[0]!.assertion).toContain('equals');
    expect(results[0]!.assertion).toContain('200');
  });

  it('unknown assertion type does not throw and returns passed=true', () => {
    const results = engine.executeAssertions(
      [{ type: 'unknown_type', operator: 'foo', value: 'bar' }],
      makeResponse(),
    );
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(true);
  });
});

// ===================================================================
// compareValues — unit tests
// ===================================================================

describe('compareValues', () => {
  it('equals: strict equality', () => {
    expect(compareValues(42, 42, 'equals')).toBe(true);
    expect(compareValues(42, 43, 'equals')).toBe(false);
    expect(compareValues('hello', 'hello', 'eq')).toBe(true);
    expect(compareValues(1, 1, '===')).toBe(true);
  });

  it('not_equals: strict inequality', () => {
    expect(compareValues(42, 43, 'not_equals')).toBe(true);
    expect(compareValues(42, 42, 'neq')).toBe(false);
    expect(compareValues('a', 'b', '!==')).toBe(true);
  });

  it('contains / includes', () => {
    expect(compareValues('hello world', 'world', 'contains')).toBe(true);
    expect(compareValues('hello world', 'xyz', 'contains')).toBe(false);
    expect(compareValues('hello world', 'hello', 'includes')).toBe(true);
  });

  it('not_contains', () => {
    expect(compareValues('hello world', 'xyz', 'not_contains')).toBe(true);
    expect(compareValues('hello world', 'world', 'not_contains')).toBe(false);
  });

  it('exists: truthy values', () => {
    expect(compareValues('present', null, 'exists')).toBe(true);
    expect(compareValues(0, null, 'exists')).toBe(true);
    expect(compareValues(false, null, 'exists')).toBe(true);
    expect(compareValues('(missing)', null, 'exists')).toBe(false);
  });

  it('exists: falsy/empty values', () => {
    expect(compareValues(undefined, null, 'exists')).toBe(false);
    expect(compareValues(null, null, 'exists')).toBe(false);
  });

  it('not_exists', () => {
    expect(compareValues(undefined, null, 'not_exists')).toBe(true);
    expect(compareValues(null, null, 'not_exists')).toBe(true);
    expect(compareValues('(missing)', null, 'not_exists')).toBe(true);
    expect(compareValues('hello', null, 'not_exists')).toBe(false);
  });

  it('less_than / greater_than / comparison operators', () => {
    expect(compareValues(5, 10, 'less_than')).toBe(true);
    expect(compareValues(10, 5, 'less_than')).toBe(false);
    expect(compareValues(5, 5, 'lt')).toBe(false);
    expect(compareValues(10, 5, 'greater_than')).toBe(true);
    expect(compareValues(5, 10, 'greater_than')).toBe(false);
    expect(compareValues(5, 5, 'gt')).toBe(false);
    expect(compareValues(5, 10, '<')).toBe(true);
    expect(compareValues(10, 5, '>')).toBe(true);
    expect(compareValues(5, 5, '<=')).toBe(true);
    expect(compareValues(5, 5, '>=')).toBe(true);
  });

  it('regex / matches', () => {
    expect(compareValues('hello 123 world', '\\d+', 'regex')).toBe(true);
    expect(compareValues('hello world', '\\d+', 'matches')).toBe(false);
    expect(compareValues('abc-123', '^[a-z]+-\\d+$', 'regex')).toBe(true);
  });

  it('default fallback uses string comparison', () => {
    expect(compareValues('hello', 'hello', 'unknown_op')).toBe(true);
    expect(compareValues('hello', 'world', 'unknown_op')).toBe(false);
  });
});

// ===================================================================
// evaluateJsonPath — unit tests
// ===================================================================

describe('evaluateJsonPath', () => {
  const data = {
    store: {
      book: [
        { title: 'Book A', price: 10, author: { name: 'Author 1' } },
        { title: 'Book B', price: 15, author: { name: 'Author 2' } },
        { title: 'Book C', price: 20, author: { name: 'Author 3' } },
      ],
      name: 'My Store',
    },
  };

  it('returns empty array for paths not starting with $', () => {
    expect(evaluateJsonPath(data, 'store.book')).toEqual([]);
  });

  it('resolves simple dot notation', () => {
    const result = evaluateJsonPath(data, '$.store.name');
    expect(result).toEqual(['My Store']);
  });

  it('resolves nested dot notation', () => {
    const result = evaluateJsonPath(data, '$.store.book[0].title');
    expect(result).toEqual(['Book A']);
  });

  it('resolves array index with bracket notation', () => {
    const result = evaluateJsonPath(data, '$.store.book[1]');
    expect(result).toEqual([{ title: 'Book B', price: 15, author: { name: 'Author 2' } }]);
  });

  it('resolves bracket notation with string key', () => {
    const result = evaluateJsonPath(data, "$['store']['name']");
    expect(result).toEqual(['My Store']);
  });

  it('wildcard returns all array elements', () => {
    const result = evaluateJsonPath(data, '$.store.book[*].title');
    expect(result).toEqual(['Book A', 'Book B', 'Book C']);
  });

  it('wildcard on object returns all values', () => {
    const result = evaluateJsonPath(data, '$.store.book[0].author[*]');
    expect(result).toEqual(['Author 1']);
  });

  it('recursive descent finds nested values', () => {
    const result = evaluateJsonPath(data, '$..author.name');
    // Recursive descent finds all 'name' properties nested under 'author' objects,
    // plus any other 'name' properties encountered during the walk.
    expect(result).toContain('Author 1');
    expect(result).toContain('Author 2');
    expect(result).toContain('Author 3');
    expect(result.length).toBeGreaterThanOrEqual(3);
  });

  it('recursive descent with top-level prop', () => {
    const result = evaluateJsonPath(data, '$..name');
    expect(result.length).toBeGreaterThanOrEqual(3);
    expect(result.some(r => r === 'My Store' || (typeof r === 'object' && r !== null))).toBe(true);
  });

  it('recursive descent works via intermediate paths', () => {
    const result = evaluateJsonPath(data, '$.store.book[0].author.name');
    expect(result).toEqual(['Author 1']);
  });

  it('handles filter expressions with numeric comparison', () => {
    const result = evaluateJsonPath(data, '$.store.book[?(@.price < 15)]');
    expect(result).toHaveLength(1);
    expect((result[0] as any).title).toBe('Book A');
  });

  it('handles filter expressions with string comparison', () => {
    const result = evaluateJsonPath(data, "$.store.book[?(@.title == 'Book B')]");
    expect(result).toHaveLength(1);
    expect((result[0] as any).price).toBe(15);
  });

  it('handles filter greater-than-or-equal', () => {
    const result = evaluateJsonPath(data, '$.store.book[?(@.price >= 15)]');
    // After regex fix: >= is properly parsed; books with price 15 and 20 match
    expect(result).toHaveLength(2);
    const titles = result.map(r => (r as any).title);
    expect(titles).toContain('Book B');
    expect(titles).toContain('Book C');
  });

  it('handles filter not-equals', () => {
    const result = evaluateJsonPath(data, '$.store.book[?(@.price != 15)]');
    expect(result).toHaveLength(2);
  });

  it('returns empty for non-existent path', () => {
    const result = evaluateJsonPath(data, '$.store.nonexistent');
    expect(result).toEqual([]);
  });

  it('handles simple top-level value', () => {
    const result = evaluateJsonPath('hello', '$');
    expect(result).toEqual(['hello']);
  });

  it('handles primitive root lookup', () => {
    const result = evaluateJsonPath(42, '$');
    expect(result).toEqual([42]);
  });
});

// ===================================================================
// validateJsonSchema — unit tests
// ===================================================================

describe('validateJsonSchema', () => {
  it('validates a simple object schema', () => {
    const result = validateJsonSchema(
      { name: 'Alice', age: 30 },
      { type: 'object', properties: { name: { type: 'string' }, age: { type: 'number' } }, required: ['name'] },
    );
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('fails on missing required property', () => {
    const result = validateJsonSchema(
      { age: 30 },
      { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes('missing required'))).toBe(true);
  });

  it('fails on wrong type', () => {
    const result = validateJsonSchema(
      { name: 42 },
      { type: 'object', properties: { name: { type: 'string' } } },
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes('Expected type'))).toBe(true);
  });

  it('validates nested objects', () => {
    const result = validateJsonSchema(
      { user: { name: 'Alice' } },
      {
        type: 'object',
        properties: {
          user: {
            type: 'object',
            properties: { name: { type: 'string' } },
            required: ['name'],
          },
        },
        required: ['user'],
      },
    );
    expect(result.valid).toBe(true);
  });

  it('validates array items', () => {
    const result = validateJsonSchema(
      [1, 2, 3],
      { type: 'array', items: { type: 'number' } },
    );
    expect(result.valid).toBe(true);
  });

  it('fails on array item type mismatch', () => {
    const result = validateJsonSchema(
      [1, 'two', 3],
      { type: 'array', items: { type: 'number' } },
    );
    expect(result.valid).toBe(false);
  });

  it('validates enum', () => {
    const result = validateJsonSchema(
      'admin',
      { type: 'string', enum: ['admin', 'user'] },
    );
    expect(result.valid).toBe(true);
  });

  it('fails on enum mismatch', () => {
    const result = validateJsonSchema(
      'superuser',
      { type: 'string', enum: ['admin', 'user'] },
    );
    expect(result.valid).toBe(false);
  });

  it('validates const', () => {
    const result = validateJsonSchema('hello', { const: 'hello' });
    expect(result.valid).toBe(true);
  });

  it('fails on const mismatch', () => {
    const result = validateJsonSchema('world', { const: 'hello' });
    expect(result.valid).toBe(false);
  });

  it('validates string pattern', () => {
    const result = validateJsonSchema(
      'abc-123',
      { type: 'string', pattern: '^[a-z]+-\\d+$' },
    );
    expect(result.valid).toBe(true);
  });

  it('fails on pattern mismatch', () => {
    const result = validateJsonSchema(
      'ABC',
      { type: 'string', pattern: '^[a-z]+$' },
    );
    expect(result.valid).toBe(false);
  });

  it('validates minLength / maxLength', () => {
    const result = validateJsonSchema(
      'hello',
      { type: 'string', minLength: 2, maxLength: 10 },
    );
    expect(result.valid).toBe(true);
  });

  it('fails on minLength', () => {
    const result = validateJsonSchema('a', { type: 'string', minLength: 2 });
    expect(result.valid).toBe(false);
  });

  it('validates number bounds', () => {
    const result = validateJsonSchema(5, { type: 'number', minimum: 0, maximum: 10 });
    expect(result.valid).toBe(true);
  });

  it('fails on exceeding maximum', () => {
    const result = validateJsonSchema(15, { type: 'number', maximum: 10 });
    expect(result.valid).toBe(false);
  });

  it('validates array minItems', () => {
    const result = validateJsonSchema([1, 2], { type: 'array', minItems: 2 });
    expect(result.valid).toBe(true);
  });

  it('fails on array minItems', () => {
    const result = validateJsonSchema([1], { type: 'array', minItems: 2 });
    expect(result.valid).toBe(false);
  });

  it('validates additionalProperties: false', () => {
    const result = validateJsonSchema(
      { name: 'Alice' },
      { type: 'object', properties: { name: { type: 'string' } }, additionalProperties: false },
    );
    expect(result.valid).toBe(true);
  });

  it('fails on additionalProperties: false with extra key', () => {
    const result = validateJsonSchema(
      { name: 'Alice', extra: 'bad' },
      { type: 'object', properties: { name: { type: 'string' } }, additionalProperties: false },
    );
    expect(result.valid).toBe(false);
  });

  it('validates allOf', () => {
    const result = validateJsonSchema(
      { name: 'Alice', age: 30 },
      {
        allOf: [
          { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
          { type: 'object', properties: { age: { type: 'number' } }, required: ['age'] },
        ],
      },
    );
    expect(result.valid).toBe(true);
  });

  it('fails on allOf when one sub-schema fails', () => {
    const result = validateJsonSchema(
      { name: 'Alice' },
      {
        allOf: [
          { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
          { type: 'object', properties: { age: { type: 'number' } }, required: ['age'] },
        ],
      },
    );
    expect(result.valid).toBe(false);
  });

  it('validates anyOf', () => {
    const result = validateJsonSchema(
      'hello',
      { anyOf: [{ type: 'string' }, { type: 'number' }] },
    );
    expect(result.valid).toBe(true);
  });

  it('validates oneOf', () => {
    const result = validateJsonSchema(
      'hello',
      { oneOf: [{ type: 'string' }, { type: 'number' }] },
    );
    expect(result.valid).toBe(true);
  });

  it('fails on oneOf when multiple match', () => {
    const result = validateJsonSchema(
      42,
      { oneOf: [{ type: 'number' }, { type: 'integer' }] },
    );
    expect(result.valid).toBe(false);
  });

  it('validates if/then/else', () => {
    const result = validateJsonSchema(
      { type: 'book', pages: 200 },
      {
        if: { properties: { type: { const: 'book' } } },
        then: { properties: { pages: { type: 'number', minimum: 1 } }, required: ['pages'] },
      },
    );
    expect(result.valid).toBe(true);
  });

  it('handles $ref to definitions', () => {
    const result = validateJsonSchema(
      { user: { name: 'Alice' } },
      {
        $ref: '#/definitions/WithUser',
        definitions: {
          WithUser: {
            type: 'object',
            properties: { user: { type: 'object', properties: { name: { type: 'string' } } } },
          },
        },
      },
    );
    expect(result.valid).toBe(true);
  });

  it('fails on non-nullable null for object type', () => {
    const result = validateJsonSchema(
      null,
      { type: 'object', properties: { name: { type: 'string' } } },
    );
    expect(result.valid).toBe(false);
  });

  it('passes on nullable null', () => {
    const result = validateJsonSchema(
      null,
      { type: 'object', nullable: true, properties: { name: { type: 'string' } } },
    );
    expect(result.valid).toBe(true);
  });
});

// ===================================================================
// generateCode — produces real, runnable code per language
// ===================================================================

describe('generateCode', () => {
  const request = {
    method: 'GET',
    url: 'https://api.example.com/users',
    headers: { Authorization: 'Bearer token123', Accept: 'application/json' },
  };

  const postRequest = {
    method: 'POST',
    url: 'https://api.example.com/users',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Alice', age: 30 }),
  };

  it('generates curl command', () => {
    const code = generateCode(request, 'curl');
    expect(code).toContain('curl');
    expect(code).toContain('GET');
    expect(code).toContain('api.example.com');
    expect(code).toContain('Authorization');
  });

  it('generates Python code', () => {
    const code = generateCode(request, 'python');
    expect(code).toContain('import requests');
    expect(code).toContain('requests.get');
    expect(code).toContain('api.example.com');
  });

  it('generates JavaScript fetch code', () => {
    const code = generateCode(request, 'javascript');
    expect(code).toContain('fetch(');
    expect(code).toContain('method');
    expect(code).toContain('Authorization');
  });

  it('generates Go code', () => {
    const code = generateCode(request, 'go');
    expect(code).toContain('package main');
    expect(code).toContain('http.NewRequest');
  });

  it('generates Java code', () => {
    const code = generateCode(request, 'java');
    expect(code).toContain('import java.net.http.HttpClient');
    expect(code).toContain('HttpRequest');
  });

  it('generates C# code', () => {
    const code = generateCode(request, 'csharp');
    expect(code).toContain('using System.Net.Http');
    expect(code).toContain('HttpClient');
  });

  it('generates Rust code', () => {
    const code = generateCode(request, 'rust');
    expect(code).toContain('use reqwest');
    expect(code).toContain('.get(');
  });

  it('includes body in POST code generation (Python)', () => {
    const code = generateCode(postRequest, 'python');
    expect(code).toContain('requests.post');
    expect(code).toContain('Alice');
  });

  it('includes body in POST (JavaScript)', () => {
    const code = generateCode(postRequest, 'javascript');
    expect(code).toContain('method:');
    expect(code).toContain('body:');
  });

  it('uses --data-raw for JSON body in curl', () => {
    const code = generateCode(postRequest, 'curl');
    expect(code).toContain('--data-raw');
    expect(code).toContain('Alice');
  });

  it('falls back to curl for unknown language', () => {
    const code = generateCode(request, 'unknown');
    expect(code).toContain('curl');
  });
});

// ===================================================================
// createWorkspace
// ===================================================================

describe('createWorkspace', () => {
  it('returns a real object derived from inputs', () => {
    const ws = createWorkspace('My Workspace', 'team');
    expect(ws.name).toBe('My Workspace');
    expect(ws.visibility).toBe('team');
    expect(ws.id).toMatch(/^ws-/);
    expect(ws.collections).toBe(0);
    expect(ws.members).toBe(1);
    expect(ws.role).toBe('admin');
  });

  it('accepts private visibility', () => {
    const ws = createWorkspace('Private', 'private');
    expect(ws.visibility).toBe('private');
  });

  it('accepts public visibility', () => {
    const ws = createWorkspace('Public', 'public');
    expect(ws.visibility).toBe('public');
  });
});

// ===================================================================
// Integration: real response data through the full pipeline
// ===================================================================

describe('Full pipeline — script + assertions with real response data', () => {
  const engine = new ScriptEngine();

  it('post-response script assertions reflect actual response data', () => {
    // A script that should pass with a 200 JSON response
    const script = `
      pm.test("status is 200", () => {
        pm.response.to.have.status(200);
      });
      pm.test("body is valid JSON", () => {
        const json = pm.response.json();
        pm.expect(json).to.have.property("name");
        pm.expect(json.name).to.be.a("string");
      });
      pm.test("fast response", () => {
        pm.expect(pm.response.responseTime).to.be.below(1000);
      });
    `;

    const result = engine.executePostResponse(script, {
      variables: new Map(),
      response: {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'Alice', role: 'admin' }),
        timeMs: 45,
      },
    });

    expect(result.tests).toHaveLength(3);
    expect(result.tests.every((t) => t.passed)).toBe(true);
  });

  it('declarative assertions reflect actual response data — all pass', () => {
    const response = {
      status: 201,
      headers: {
        'content-type': 'application/json',
        'x-request-id': 'req-abc-123',
        'location': '/api/users/42',
      },
      body: JSON.stringify({ id: 42, name: 'Bob', email: 'bob@example.com', createdAt: '2026-01-15T10:00:00Z' }),
      timeMs: 320,
    };

    const results = engine.executeAssertions(
      [
        { type: 'status', operator: 'equals', value: '201' },
        { type: 'header', operator: 'exists', target: 'x-request-id' },
        { type: 'header', operator: 'equals', target: 'content-type', value: 'application/json' },
        { type: 'json_path', operator: 'equals', target: '$.id', value: '42' },
        { type: 'json_path', operator: 'exists', target: '$.email' },
        { type: 'response_time', operator: 'less_than', value: '1000' },
        {
          type: 'schema', operator: 'valid', value: JSON.stringify({
            type: 'object',
            properties: {
              id: { type: 'number' },
              name: { type: 'string' },
              email: { type: 'string', format: 'email' },
            },
            required: ['id', 'name', 'email'],
          }),
        },
      ],
      response,
    );

    expect(results).toHaveLength(7);
    for (const r of results) {
      expect(r.passed, `Assertion "${r.assertion}" should pass but failed: actual=${r.actual}, expected=${r.expected}`).toBe(true);
    }
  });

  it('declarative assertions fail when response data changes', () => {
    // Same assertions as above, but response is different
    const response = {
      status: 404,
      headers: { 'content-type': 'text/html' },
      body: '<html>Not Found</html>',
      timeMs: 5000,
    };

    const results = engine.executeAssertions(
      [
        { type: 'status', operator: 'equals', value: '200' },
        { type: 'header', operator: 'exists', target: 'x-request-id' },
        { type: 'json_path', operator: 'exists', target: '$.id' },
        { type: 'response_time', operator: 'less_than', value: '1000' },
      ],
      response,
    );

    // status fails (404 vs 200)
    expect(results[0]!.passed).toBe(false);
    // header x-request-id missing
    expect(results[1]!.passed).toBe(false);
    // json_path $.id fails on HTML body
    expect(results[2]!.passed).toBe(false);
    // response_time fails (5000 > 1000)
    expect(results[3]!.passed).toBe(false);
  });
});
