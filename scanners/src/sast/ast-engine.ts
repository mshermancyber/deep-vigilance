// ============================================================
// AST-Based Analysis Engine
// Tree-sitter-like AST parsing, unified IR, CFG, call graph
// ============================================================

import { logger } from '../utils/logger.js';
import * as crypto from 'crypto';
import * as path from 'path';
import { isTreeSitterSupported, parseWithTreeSitter } from './tree-sitter-parser.js';

// ============================================================
// SECTION 1 -- Exported Types
// ============================================================

export type IRNodeType =
  'FunctionDef' | 'CallExpr' | 'BinaryOp' | 'IfStmt' | 'Assign' |
  'Import' | 'Literal' | 'Parameter' | 'Return' | 'ClassDef' |
  'VariableDecl' | 'ForStmt' | 'WhileStmt' | 'DoWhileStmt' | 'TryStmt' | 'ThrowStmt' |
  'SwitchStmt' | 'ArrayAccess' | 'MemberAccess' | 'UnaryOp' | 'TernaryExpr' |
  'TemplateExpr' | 'ArrowFunc' | 'SpreadElement' | 'AwaitExpr' | 'YieldExpr';

export interface IRNode {
  type: IRNodeType;
  name?: string;
  value?: string;
  children: IRNode[];
  lineNumber: number;
  columnNumber: number;
  language: string;
  metadata: Record<string, unknown>;
}

export interface CallGraphNode {
  functionName: string;
  filePath: string;
  lineNumber: number;
  callees: string[];
  callers: string[];
  isEntryPoint: boolean;
  isReachable: boolean;
}

export interface CFGBasicBlock {
  id: number;
  statements: IRNode[];
  successors: number[];
  predecessors: number[];
  isEntry: boolean;
  isExit: boolean;
}

export interface TaintSource {
  type: string;
  node: IRNode;
  description: string;
}

export interface TaintSink {
  type: string;
  node: IRNode;
  description: string;
  severity: string;
}

export interface TaintPath {
  source: TaintSource;
  sink: TaintSink;
  nodes: IRNode[];
  sanitizers: string[];
  taintBroken: boolean;
  pathLength: number;
  reachabilityScore: number;
}

// ============================================================
// SECTION 2 -- Internal Types
// ============================================================

interface Pos { line: number; column: number; }

interface SourceLocation {
  start: Pos & { offset: number };
  end: Pos & { offset: number };
}

type ASTNode = Record<string, unknown> & {
  type: string;
  loc: SourceLocation;
};

type TokenType =
  'Keyword' | 'Identifier' | 'Number' | 'String'
  | 'Template' | 'Regex' | 'Punctuator' | 'Comment' | 'EOF';

interface Token {
  type: TokenType;
  value: string;
  start: number;
  end: number;
  line: number;
  column: number;
}

// ============================================================
// SECTION 3 -- Tokenizer
// ============================================================

const KEYWORDS = new Set([
  'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger',
  'default', 'delete', 'do', 'else', 'export', 'extends', 'finally',
  'for', 'function', 'if', 'import', 'in', 'instanceof', 'let', 'new',
  'of', 'return', 'static', 'super', 'switch', 'this', 'throw', 'try',
  'typeof', 'var', 'void', 'while', 'with', 'yield', 'async', 'await',
  'from', 'as', 'implements', 'interface', 'declare', 'module',
  'namespace', 'type', 'abstract', 'readonly', 'enum', 'constructor',
  'get', 'set', 'private', 'protected', 'public', 'satisfies',
  'keyof', 'infer', 'never', 'unknown', 'any', 'boolean', 'number',
  'string', 'symbol', 'bigint', 'undefined', 'null', 'true', 'false',
]);

const MULTI_PUNCT = [
  '===', '!==', '<=', '>=', '&&', '||', '??', '?.', '**',
  '<<', '>>', '>>>', '+=', '-=', '*=', '/=', '%=', '**=',
  '<<=', '>>=', '>>>=', '&=', '^=', '|=', '&&=', '||=',
  '??=', '++', '--',
];

class Tokenizer {
  private s: string;
  pos = 0;
  line = 1;
  col = 1;

  constructor(source: string) { this.s = source; }

  private ch(n = 0): string { return this.s[this.pos + n] || '\0'; }

  private skip(n = 1): void {
    for (let i = 0; i < n; i++) {
      if (this.ch() === '\n') { this.line++; this.col = 0; }
      this.pos++; this.col++;
    }
  }

  private isRegexStart(): boolean {
    let i = this.pos - 1;
    while (i >= 0 && /\s/.test(this.s[i])) i--;
    if (i < 0) return true;
    return '(,=?!:;+-*/%&|^~<>{[!'.includes(this.s[i]!);
  }

  skipWs(): void {
    while (this.pos < this.s.length) {
      const c = this.ch();
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { this.skip(); }
      else if (c === '/' && this.ch(1) === '/') { while (this.pos < this.s.length && this.ch() !== '\n') this.skip(); }
      else if (c === '/' && this.ch(1) === '*') {
        this.skip(2);
        while (this.pos < this.s.length) {
          if (this.ch() === '*' && this.ch(1) === '/') { this.skip(2); break; }
          this.skip();
        }
      } else break;
    }
  }

  next(): Token {
    this.skipWs();
    if (this.pos >= this.s.length) return { type: 'EOF', value: '', start: this.pos, end: this.pos, line: this.line, column: this.col };

    const sl = this.line, sc = this.col;
    const c = this.ch();

    // String
    if (c === "'" || c === '"') return this.readStr(c);
    if (c === '`') return this.readTmpl();

    // Regex (heuristic)
    if (c === '/' && this.isRegexStart()) return this.readRgx();

    // Number
    if (/[0-9]/.test(c)) return this.readNum();

    // Identifier / keyword
    if (/[a-zA-Z_$]/.test(c)) return this.readIdent();
    if (c === '#') return this.readIdent();

    // Multi-char punctuator (longest first)
    const three = this.s.slice(this.pos, this.pos + 3);
    for (const p of MULTI_PUNCT) {
      if (three.startsWith(p) || this.s.startsWith(p, this.pos)) {
        this.skip(p.length);
        return { type: 'Punctuator', value: p, start: this.pos - p.length, end: this.pos, line: sl, column: sc };
      }
    }

    // Single punctuator
    if ('(){}[].,;:?=+-*/%^~!<>&|@#'.includes(c)) { this.skip(); return { type: 'Punctuator', value: c, start: this.pos - 1, end: this.pos, line: sl, column: sc }; }

    this.skip();
    return { type: 'Identifier', value: c, start: this.pos - 1, end: this.pos, line: sl, column: sc };
  }

  peek(): Token {
    const saved = { pos: this.pos, line: this.line, col: this.col };
    const t = this.next();
    this.pos = saved.pos; this.line = saved.line; this.col = saved.col;
    return t;
  }

  private readStr(q: string): Token {
    const st = this.pos; const sl = this.line, sc = this.col; this.skip();
    while (this.pos < this.s.length) {
      if (this.ch() === '\\') { this.skip(2); continue; }
      if (this.ch() === q) { this.skip(); break; }
      if (this.ch() === '\n') break;
      this.skip();
    }
    return { type: 'String', value: this.s.slice(st, this.pos), start: st, end: this.pos, line: sl, column: sc };
  }

  private readTmpl(): Token {
    const st = this.pos; const sl = this.line, sc = this.col; this.skip();
    let depth = 0;
    while (this.pos < this.s.length) {
      if (this.ch() === '\\') { this.skip(2); continue; }
      if (this.ch() === '$' && this.ch(1) === '{') { depth++; this.skip(2); continue; }
      if (this.ch() === '}') { if (depth > 0) depth--; this.skip(); continue; }
      if (this.ch() === '`' && depth === 0) { this.skip(); break; }
      this.skip();
    }
    return { type: 'Template', value: this.s.slice(st, this.pos), start: st, end: this.pos, line: sl, column: sc };
  }

  private readNum(): Token {
    const st = this.pos; const sl = this.line, sc = this.col;
    if (this.ch() === '0' && /[xXbBoO]/.test(this.ch(1))) {
      const base = this.ch(1).toLowerCase();
      this.skip(2);
      const re = base === 'x' ? /[0-9a-fA-F_]/ : base === 'b' ? /[01_]/ : /[0-7_]/;
      while (re.test(this.ch())) this.skip();
    } else {
      while (/[0-9_]/.test(this.ch())) this.skip();
      if (this.ch() === '.') { this.skip(); while (/[0-9_]/.test(this.ch())) this.skip(); }
      if (/[eE]/.test(this.ch())) { this.skip(); if (/[+-]/.test(this.ch())) this.skip(); while (/[0-9_]/.test(this.ch())) this.skip(); }
    }
    if (this.ch() === 'n') this.skip();
    return { type: 'Number', value: this.s.slice(st, this.pos), start: st, end: this.pos, line: sl, column: sc };
  }

  private readIdent(): Token {
    const st = this.pos; const sl = this.line, sc = this.col;
    while (/[a-zA-Z0-9_$#]/.test(this.ch())) this.skip();
    const w = this.s.slice(st, this.pos);
    return { type: KEYWORDS.has(w) ? 'Keyword' : 'Identifier', value: w, start: st, end: this.pos, line: sl, column: sc };
  }

  private readRgx(): Token {
    const st = this.pos; const sl = this.line, sc = this.col; this.skip();
    let inCls = false;
    while (this.pos < this.s.length) {
      if (this.ch() === '\\') { this.skip(2); continue; }
      if (this.ch() === '[') inCls = true;
      if (this.ch() === ']') inCls = false;
      if (this.ch() === '/' && !inCls) { this.skip(); break; }
      if (this.ch() === '\n') break;
      this.skip();
    }
    while (/[gimsuyd]/.test(this.ch())) this.skip();
    return { type: 'Regex', value: this.s.slice(st, this.pos), start: st, end: this.pos, line: sl, column: sc };
  }
}

// ============================================================
// SECTION 4 -- JS/TS Recursive Descent Parser
// ============================================================

function mkNode(type: string, loc: SourceLocation, extra: Record<string, unknown> = {}): ASTNode {
  return { type, loc, ...extra };
}

const BINARY_PREC: Record<string, number> = {
  ',': 1, '=': 2, '+=': 2, '-=': 2, '*=': 2, '/=': 2, '%=': 2,
  '**=': 2, '<<=': 2, '>>=': 2, '>>>=': 2, '&=': 2, '^=': 2,
  '|=': 2, '&&=': 2, '||=': 2, '??=': 2,
  '??': 3, '||': 4, '&&': 5,
  '|': 6, '^': 7, '&': 8,
  '===': 9, '!==': 9, '==': 9, '!=': 9,
  '<': 10, '>': 10, '<=': 10, '>=': 10, 'instanceof': 10, 'in': 10,
  '<<': 11, '>>': 11, '>>>': 11,
  '+': 12, '-': 12,
  '*': 13, '/': 13, '%': 13,
  '**': 14,
};

const UNARY_PREC = 15;
const CALL_PREC = 16;

interface PosData { line: number; column: number; offset: number; }

function srcLoc(t: Token): SourceLocation {
  return { start: { line: t.line, column: t.column, offset: t.start }, end: { line: t.line, column: t.column, offset: t.end } };
}

function isToken(a: Token | ASTNode): a is Token {
  return typeof (a as Token).start === 'number';
}

function getStartPos(a: Token | ASTNode): PosData {
  if (isToken(a)) return { line: a.line, column: a.column, offset: a.start };
  return (a as ASTNode).loc.start;
}

function getEndPos(a: Token | ASTNode): PosData {
  if (isToken(a)) return { line: a.line, column: a.column, offset: a.end };
  return (a as ASTNode).loc.end;
}

function rangeLoc(s: Token | ASTNode, e: Token | ASTNode): SourceLocation {
  return { start: getStartPos(s), end: getEndPos(e) };
}

function rangePos(s: PosData, e: PosData): SourceLocation {
  return { start: { line: s.line, column: s.column, offset: s.offset }, end: { line: e.line, column: e.column, offset: e.offset } };
}

class Parser {
  private tk: Tokenizer;
  private tok: Token;

  constructor(s: string) { this.tk = new Tokenizer(s); this.tok = this.tk.next(); }

  private val(): string { return this.tok.value; }
  private typ(): TokenType { return this.tok.type; }
  // Legacy v/t getters removed — always use val()/typ() to prevent TS narrowing issues

  private adv(): Token { const p = this.tok; this.tok = this.tk.next(); return p; }
  private match(v: string): boolean { if (this.val() ===v) { this.adv(); return true; } return false; }
  private expect(v: string): void { if (this.val() ===v) this.adv(); }

  parseProgram(): ASTNode {
    const st = this.tok;
    const body: ASTNode[] = [];
    while (this.typ() !=='EOF') { const s = this.parseStmtItem(); if (s) body.push(s); else this.adv(); }
    return mkNode('Program', rangeLoc(st, this.tok), { body });
  }

  private parseStmtItem(): ASTNode | null {
    const v = this.val();
    if (v === 'function') return this.parseFn(false);
    if (v === 'async' && this.tk.peek().value === 'function') { this.adv(); return this.parseFn(true); }
    if (v === 'class') return this.parseCls();
    if (v === 'const' || v === 'let' || v === 'var') return this.parseVar();
    if (v === 'import') return this.parseImp();
    if (v === 'export') return this.parseExp();
    if (v === 'if') return this.parseIf();
    if (v === 'for') return this.parseFor();
    if (v === 'while') return this.parseWhile();
    if (v === 'do') return this.parseDo();
    if (v === 'switch') return this.parseSwitch();
    if (v === 'try') return this.parseTry();
    if (v === 'return') return this.parseRet();
    if (v === 'throw') return this.parseThrow();
    if (v === 'break' || v === 'continue') return this.parseBrk();
    if (v === 'debugger') { this.adv(); return mkNode('DebuggerStatement', srcLoc(this.tok), {}); }
    if (v === ';') { this.adv(); return mkNode('EmptyStatement', srcLoc(this.tok), {}); }
    if (v === '{') return this.parseBlock();
    return this.parseExprStmt();
  }

  private parseBlock(): ASTNode {
    const st = this.adv();
    const body: ASTNode[] = [];
    while (this.val() !=='}' && this.typ() !=='EOF') { const s = this.parseStmtItem(); if (s) body.push(s); else this.adv(); }
    const ed = this.tok;
    if (this.val() ==='}') this.adv();
    return mkNode('BlockStatement', rangeLoc(st, ed), { body });
  }

  private parseFn(async = false): ASTNode {
    const st = this.adv();
    const gen = this.val() ==='*'; if (gen) this.adv();
    const name = this.typ() ==='Identifier' ? this.adv().value : '';
    const params = this.parseParams();
    const body = this.parseBlock();
    return mkNode('FunctionDeclaration', rangeLoc(st, body), { name, params, body: body.body, async, generator: gen });
  }

  private parseFnExpr(): ASTNode {
    const st = this.adv();
    const gen = this.val() ==='*'; if (gen) this.adv();
    const name = this.typ() ==='Identifier' ? this.adv().value : '';
    const params = this.parseParams();
    const body = this.parseBlock();
    return mkNode('FunctionExpression', rangeLoc(st, body), { name, params, body: body.body, generator: gen });
  }

  private parseCls(): ASTNode {
    const st = this.adv();
    const name = this.typ() ==='Identifier' ? this.adv().value : '';
    let sup = '';
    if (this.val() ==='extends') { this.adv(); sup = this.typ() ==='Identifier' ? this.adv().value : ''; }
    const members: ASTNode[] = [];
    if (this.val() ==='{') {
      this.adv();
      while (this.val() !=='}' && this.typ() !=='EOF') {
        const v = this.val();
        if (v === 'static' || v === 'get' || v === 'set') this.adv();
        if (v === ';' || v === '}' || this.typ() ==='EOF') { if (v === ';') this.adv(); continue; }
        const mn = (this.typ() ==='Identifier' || this.typ() ==='Keyword') ? this.adv().value : 'unknown';
        const mp = this.val() ==='(' ? this.parseParams() : [];
        let mb: ASTNode[] = [];
        if (this.val() ==='{') { const blk = this.parseBlock(); mb = blk.body as ASTNode[]; }
        members.push(mkNode('MethodDefinition', srcLoc(this.tok), { name: mn, params: mp, body: mb }));
        while (this.val() !=='}' && this.val() !==';' && this.typ() !=='EOF') this.adv();
        if (this.val() ===';') this.adv();
      }
      if (this.val() ==='}') this.adv();
    }
    return mkNode('ClassDeclaration', rangeLoc(st, this.tok), { name, superClass: sup, members });
  }

  private parseVar(): ASTNode {
    const st = this.adv(); const kind = st.value;
    const decls: Array<{ id: string; init: ASTNode | null }> = [];
    do {
      if (this.typ() ==='Identifier') {
        const id = this.adv().value;
        let init: ASTNode | null = null;
        if (this.val() ==='=') { this.adv(); init = this.parseExpr(); }
        decls.push({ id, init });
      }
      if (this.val() ===',') this.adv(); else break;
    } while (this.typ() !=='EOF');
    this.match(';');
    return mkNode('VariableDeclaration', rangeLoc(st, this.tok), { kind, declarations: decls });
  }

  private parseIf(): ASTNode {
    const st = this.adv(); this.expect('(');
    const test = this.parseExpr();
    this.expect(')');
    const cons = this.parseStmtItem() || mkNode('EmptyStatement', srcLoc(this.tok), {});
    let alt: ASTNode | null = null;
    if (this.val() ==='else') { this.adv(); alt = this.parseStmtItem(); }
    return mkNode('IfStatement', rangeLoc(st, this.tok), { test, consequent: cons, alternate: alt });
  }

  private parseFor(): ASTNode {
    const st = this.adv(); this.expect('(');
    const init = this.val() ===';' ? null : this.parseStmtItem();
    this.expect(';');
    const test = this.val() ===';' ? null : this.parseExpr();
    this.expect(';');
    const upd = this.val() ===')' ? null : this.parseExpr();
    this.expect(')');
    const body = this.parseStmtItem() || mkNode('EmptyStatement', srcLoc(this.tok), {});
    return mkNode('ForStatement', rangeLoc(st, this.tok), { init, test, update: upd, body });
  }

  private parseWhile(): ASTNode {
    const st = this.adv(); this.expect('(');
    const test = this.parseExpr();
    this.expect(')');
    const body = this.parseStmtItem() || mkNode('EmptyStatement', srcLoc(this.tok), {});
    return mkNode('WhileStatement', rangeLoc(st, this.tok), { test, body });
  }

  private parseDo(): ASTNode {
    const st = this.adv();
    const body = this.parseStmtItem() || mkNode('EmptyStatement', srcLoc(this.tok), {});
    if (this.val() ==='while') this.adv();
    this.expect('(');
    const test = this.parseExpr();
    this.expect(')');
    return mkNode('DoWhileStatement', rangeLoc(st, this.tok), { body, test });
  }

  private parseSwitch(): ASTNode {
    const st = this.adv(); this.expect('(');
    const disc = this.parseExpr();
    this.expect(')'); this.expect('{');
    const cases: ASTNode[] = [];
    while (this.val() !=='}' && this.typ() !=='EOF') {
      if (this.val() ==='case' || this.val() ==='default') {
        const cs = this.adv();
        const t = cs.value === 'default' ? null : this.parseExpr();
        this.expect(':');
        const cons: ASTNode[] = [];
        while (this.val() !=='case' && this.val() !=='default' && this.val() !=='}' && this.typ() !=='EOF') {
          const s = this.parseStmtItem(); if (s) cons.push(s); else this.adv();
        }
        cases.push(mkNode('SwitchCase', rangeLoc(cs, this.tok), { test: t, consequent: cons }));
      } else this.adv();
    }
    if (this.val() ==='}') this.adv();
    return mkNode('SwitchStatement', rangeLoc(st, this.tok), { discriminant: disc, cases });
  }

  private parseTry(): ASTNode {
    const st = this.adv();
    const block = this.parseBlock();
    let handler: ASTNode | null = null, finalizer: ASTNode | null = null;
    if (this.val() ==='catch') {
      this.adv();
      let param: ASTNode | null = null;
      if (this.val() ==='(') { this.adv(); if (this.typ() ==='Identifier') param = mkNode('Identifier', srcLoc(this.tok), { name: this.adv().value }); this.expect(')'); }
      const cb = this.parseBlock();
      handler = mkNode('CatchClause', srcLoc(this.tok), { param, body: cb.body });
    }
    if (this.val() ==='finally') { this.adv(); const fb = this.parseBlock(); finalizer = mkNode('FinallyClause', srcLoc(this.tok), { body: fb.body }); }
    return mkNode('TryStatement', rangeLoc(st, this.tok), { block: block.body, handler, finalizer });
  }

  private parseRet(): ASTNode {
    const st = this.adv();
    let arg: ASTNode | null = null;
    if (this.val() !==';' && this.val() !=='}' && this.typ() !=='EOF') arg = this.parseExpr();
    this.match(';');
    return mkNode('ReturnStatement', rangeLoc(st, this.tok), { argument: arg });
  }

  private parseThrow(): ASTNode {
    const st = this.adv();
    const arg = this.parseExpr();
    this.match(';');
    return mkNode('ThrowStatement', rangeLoc(st, this.tok), { argument: arg });
  }

  private parseBrk(): ASTNode {
    const st = this.adv();
    let label = '';
    if (this.typ() ==='Identifier') label = this.adv().value;
    this.match(';');
    return mkNode(st.value === 'break' ? 'BreakStatement' : 'ContinueStatement', rangeLoc(st, this.tok), { label });
  }

  private parseImp(): ASTNode {
    const st = this.adv();
    const specs: ASTNode[] = [];
    let source = '';

    if (this.val() ==='{') {
      this.adv();
      while (this.val() !=='}' && this.typ() !=='EOF') {
        if (this.typ() ==='Identifier') {
          const l = this.adv().value;
          let im = l;
          if (this.val() ==='as') { this.adv(); im = this.adv().value; }
          specs.push(mkNode('ImportSpecifier', srcLoc(this.tok), { local: l, imported: im }));
        }
        if (this.val() ===',') this.adv();
      }
      if (this.val() ==='}') this.adv();
    } else if (this.typ() ==='Identifier') {
      specs.push(mkNode('ImportDefaultSpecifier', srcLoc(this.tok), { local: this.adv().value }));
      if (this.val() ===',') {
        this.adv();
        if (this.val() ==='*') { this.adv(); if (this.val() ==='as') { this.adv(); specs.push(mkNode('ImportNamespaceSpecifier', srcLoc(this.tok), { local: this.adv().value })); } }
      }
    } else if (this.val() ==='*') {
      this.adv();
      if (this.val() ==='as') { this.adv(); specs.push(mkNode('ImportNamespaceSpecifier', srcLoc(this.tok), { local: this.adv().value })); }
    }

    if (this.val() ==='from') { this.adv(); if (this.typ() ==='String') source = this.adv().value; }
    if (this.val() ==='(' && source === '' && specs.length === 0) {
      this.adv();
      if (this.typ() ==='String') source = this.adv().value;
      if (this.val() ===')') this.adv();
      return mkNode('ImportExpression', rangeLoc(st, this.tok), { source });
    }
    this.match(';');
    return mkNode('ImportDeclaration', rangeLoc(st, this.tok), { specifiers: specs, source });
  }

  private parseExp(): ASTNode {
    const st = this.adv();
    if (this.val() ==='default') { this.adv(); const d = this.parseStmtItem(); return mkNode('ExportDefaultDeclaration', rangeLoc(st, this.tok), { declaration: d }); }
    if (this.val() ==='{') {
      this.adv(); const specs: ASTNode[] = [];
      while (this.val() !=='}' && this.typ() !=='EOF') {
        if (this.typ() ==='Identifier') { const l = this.adv().value; let e = l; if (this.val() ==='as') { this.adv(); e = this.adv().value; } specs.push(mkNode('ExportSpecifier', srcLoc(this.tok), { local: l, exported: e })); }
        if (this.val() ===',') this.adv();
      }
      if (this.val() ==='}') this.adv();
      this.match(';');
      return mkNode('ExportNamedDeclaration', rangeLoc(st, this.tok), { specifiers: specs });
    }
    if (this.val() ==='*') { this.adv(); let e = ''; if (this.val() ==='as') { this.adv(); e = this.adv().value; } return mkNode('ExportAllDeclaration', rangeLoc(st, this.tok), { exported: e }); }
    const d = this.parseStmtItem();
    return mkNode('ExportNamedDeclaration', rangeLoc(st, this.tok), { declaration: d });
  }

  // -- Expressions --

  private parseParams(): ASTNode[] {
    const params: ASTNode[] = [];
    if (this.val() ==='(') {
      this.adv();
      while (this.val() !==')' && this.typ() !=='EOF') {
        if (this.val() ==='...') { this.adv(); const n = this.typ() ==='Identifier' ? this.adv().value : 'rest'; params.push(mkNode('Parameter', srcLoc(this.tok), { name: n, rest: true })); }
        else if (this.typ() ==='Identifier') {
          const n = this.adv().value;
          let def: ASTNode | null = null;
          if (this.val() ==='=') { this.adv(); def = this.parseExpr(); }
          if (this.val() ===':') { this.adv(); while (this.typ() ==='Identifier' || this.val() ==='.' || this.val() ==='[' || this.val() ==='|' || this.val() ==='&') { this.adv(); } }
          params.push(mkNode('Parameter', srcLoc(this.tok), { name: n, default: def }));
        } else if (this.val() ==='{' || this.val() ==='[') {
          const opn = this.adv().value;
          const cls = opn === '{' ? '}' : ']';
          let d = 1;
          while (d > 0 && this.typ() !=='EOF') { if (this.val() ===opn) d++; if (this.val() ===cls) d--; this.adv(); }
          params.push(mkNode('Parameter', srcLoc(this.tok), { name: 'destructured', destructured: true }));
        }
        if (this.val() ===',') this.adv(); else break;
      }
      if (this.val() ===')') this.adv();
    }
    return params;
  }

  private parseExpr(prec = 0): ASTNode | null {
    if (this.typ() ==='EOF' || this.val() ===';' || this.val() ===')' || this.val() ===']' || this.val() ==='}' || this.val() ===':') return null;
    let left = this.parsePrefix();
    if (!left) return null;

    while (this.typ() !=='EOF') {
      const v = this.val();

      // Postfix ++/--
      if (v === '++' || v === '--') { this.adv(); left = mkNode('UpdateExpression', rangeLoc(left, this.tok), { operator: v, argument: left, prefix: false }); continue; }

      // Ternary ?:
      if (v === '?' && BINARY_PREC[v] === undefined) {
        if (prec <= 2) { this.adv(); const cons = this.parseExpr(2); this.expect(':'); const alt = this.parseExpr(2); left = mkNode('ConditionalExpression', rangeLoc(left, this.tok), { test: left, consequent: cons, alternate: alt }); continue; }
        break;
      }

      // Binary
      const bp = BINARY_PREC[v];
      if (bp !== undefined) {
        if (bp < prec) break;
        if (v === '=' || v.endsWith('=')) { this.adv(); const r = this.parseExpr(2); left = mkNode('AssignmentExpression', rangeLoc(left, this.tok), { operator: v, left, right: r }); continue; }
        if (v === ',') { this.adv(); const r = this.parseExpr(1); left = mkNode('SequenceExpression', rangeLoc(left, this.tok), { expressions: [left, r] }); continue; }
        this.adv();
        const right = this.parseExpr(bp + 1);
        left = mkNode(v === '&&' || v === '||' || v === '??' ? 'LogicalExpression' : 'BinaryExpression', rangeLoc(left, this.tok), { operator: v, left, right });
        continue;
      }

      // Call ()
      if (v === '(') { const args = this.parseArgs(); left = mkNode('CallExpression', rangeLoc(left, this.tok), { callee: left, arguments: args }); continue; }

      // Member access . [ ?.
      if (v === '.') { this.adv(); const prop = this.typ() ==='Identifier' || this.typ() ==='Keyword' ? this.adv().value : ''; left = mkNode('MemberExpression', rangeLoc(left, this.tok), { object: left, property: prop, computed: false }); continue; }
      if (v === '?.' && this.tk.peek().type === 'Identifier') { this.adv(); const prop = this.adv().value; left = mkNode('OptionalMemberExpression', rangeLoc(left, this.tok), { object: left, property: prop }); continue; }
      if (v === '[') { this.adv(); const prop = this.parseExpr(); if (this.val() ===']') this.adv(); left = mkNode('MemberExpression', rangeLoc(left, this.tok), { object: left, property: prop, computed: true }); continue; }

      break;
    }
    return left;
  }

  private parseExprStmt(): ASTNode | null {
    const e = this.parseExpr();
    this.match(';');
    while (this.val() ===';') this.adv();
    return e;
  }

  private parsePrefix(): ASTNode | null {
    const tok = this.tok;
    if (this.typ() ==='Number') return mkNode('Literal', srcLoc(this.adv()), { value: tok.value, literalType: 'number' });
    if (this.typ() ==='String') return mkNode('Literal', srcLoc(this.adv()), { value: tok.value, literalType: 'string' });
    if (this.typ() ==='Regex') return mkNode('Literal', srcLoc(this.adv()), { value: tok.value, literalType: 'regex' });
    if (this.typ() ==='Template') { this.adv(); return mkNode('TemplateLiteral', srcLoc(tok), { quasis: [tok.value], expressions: [] }); }
    if (tok.value === 'null') { this.adv(); return mkNode('Literal', srcLoc(tok), { value: 'null', literalType: 'null' }); }
    if (tok.value === 'true' || tok.value === 'false') { this.adv(); return mkNode('Literal', srcLoc(tok), { value: tok.value, literalType: 'boolean' }); }
    if (tok.value === 'undefined') { this.adv(); return mkNode('Identifier', srcLoc(tok), { name: 'undefined' }); }
    if (tok.value === 'this') { this.adv(); return mkNode('ThisExpression', srcLoc(tok), {}); }
    if (tok.value === 'super') { this.adv(); return mkNode('SuperExpression', srcLoc(tok), {}); }
    if (this.typ() ==='Identifier') { this.adv(); return mkNode('Identifier', srcLoc(tok), { name: tok.value }); }

    if (tok.value === '(') {
      this.adv();
      if (this.val() ===')') { this.adv(); return mkNode('SequenceExpression', srcLoc(tok), { expressions: [] }); }
      const e = this.parseExpr();
      this.expect(')');
      if (this.val() ==='=>') return this.parseArrowFn([e!], tok);
      return e;
    }

    if (tok.value === '{') return this.parseObj();
    if (tok.value === '[') return this.parseArr();

    // Unary
    if (['+', '-', '!', '~', 'typeof', 'void', 'delete', 'await'].includes(tok.value)) {
      this.adv();
      const op = this.parseExpr(UNARY_PREC);
      return mkNode('UnaryExpression', rangeLoc(tok, this.tok), { operator: tok.value, prefix: true, argument: op });
    }

    // Prefix ++/--
    if (tok.value === '++' || tok.value === '--') { this.adv(); const op = this.parseExpr(UNARY_PREC); return mkNode('UpdateExpression', rangeLoc(tok, this.tok), { operator: tok.value, prefix: true, argument: op }); }

    // Spread
    if (tok.value === '...') { this.adv(); const a = this.parseExpr(); return mkNode('SpreadElement', rangeLoc(tok, this.tok), { argument: a }); }

    // new
    if (tok.value === 'new') { this.adv(); const callee = this.parseExpr(CALL_PREC); const args = this.val() ==='(' ? this.parseArgs() : []; return mkNode('NewExpression', rangeLoc(tok, this.tok), { callee, arguments: args }); }

    // yield
    if (tok.value === 'yield') {
      this.adv();
      const del = this.val() ==='*'; if (del) this.adv();
      return mkNode('YieldExpression', rangeLoc(tok, this.tok), { argument: this.parseExpr(), delegate: del });
    }

    // Arrow: ident => ...
    if (tok.type === 'Identifier' && this.val() ==='=>') return this.parseArrowFn([mkNode('Identifier', srcLoc(tok), { name: tok.value })], tok);

    // async () => ...
    if (tok.value === 'async') {
      const p = this.tk.peek();
      if (p.type === 'Punctuator' && p.value === '(') {
        this.adv();
        const params = this.parseParams();
        if (this.val() ==='=>') return this.parseArrowFn(params, tok);
      } else if (p.type === 'Identifier') {
        this.adv();
        const id = mkNode('Identifier', srcLoc(this.tk.next()), { name: p.value }); // consume ident
        if (this.val() ==='=>') return this.parseArrowFn([id], tok);
      }
    }

    // class expression
    if (tok.value === 'class') return this.parseCls();
    // function expression
    if (tok.value === 'function') return this.parseFnExpr();

    // import()
    if (tok.value === 'import' && this.tk.peek().value === '(') { this.adv(); this.adv(); const src = this.parseExpr(); this.expect(')'); return mkNode('ImportExpression', rangeLoc(tok, this.tok), { source: src }); }

    return null;
  }

  private parseArrowFn(params: ASTNode[], st: Token): ASTNode {
    this.adv();
    let body: ASTNode | ASTNode[];
    if (this.val() ==='{') {
      const blk = this.parseBlock();
      body = blk.body as ASTNode[];
    } else {
      body = [this.parseExpr()!];
    }
    return mkNode('ArrowFunctionExpression', rangeLoc(st, this.tok), { params, body, expression: !Array.isArray(body) || body.length <= 1 });
  }

  private parseArgs(): ASTNode[] {
    const args: ASTNode[] = [];
    if (this.val() ==='(') this.adv();
    while (this.val() !==')' && this.typ() !=='EOF') {
      if (this.val() ===',') { this.adv(); continue; }
      const a = this.parseExpr(); if (a) args.push(a); else this.adv();
    }
    if (this.val() ===')') this.adv();
    return args;
  }

  private parseObj(): ASTNode {
    const st = this.adv();
    const props: ASTNode[] = [];
    while (this.val() !=='}' && this.typ() !=='EOF') {
      const v = this.val();
      if (v === '...') { this.adv(); props.push(mkNode('SpreadElement', rangeLoc(st, this.tok), { argument: this.parseExpr() })); }
      else if (v === 'get' || v === 'set') {
        const acc = this.adv().value;
        const key = this.adv().value;
        const prm = this.val() ==='(' ? this.parseParams() : [];
        const blk = this.val() ==='{' ? this.parseBlock() : null;
        props.push(mkNode('Property', srcLoc(this.tok), { key, accessor: acc, value: mkNode('FunctionExpression', srcLoc(this.tok), { params: prm, body: blk?.body || [] }) }));
      } else if ((this.typ() ==='Identifier' || this.typ() ==='String' || this.typ() ==='Number') && this.val() !=='[') {
        const kt = this.adv();
        let key = kt.value;
        if (this.val() ===':') { this.adv(); props.push(mkNode('Property', rangeLoc(kt, this.tok), { key, value: this.parseExpr() })); }
        else if (this.val() ==='(') { const prm = this.parseParams(); const blk = this.val() ==='{' ? this.parseBlock() : null; props.push(mkNode('Property', srcLoc(this.tok), { key, value: mkNode('FunctionExpression', srcLoc(this.tok), { params: prm, body: blk?.body || [] }) })); }
        else if (this.val() ===',' || this.val() ==='}') props.push(mkNode('Property', srcLoc(kt), { key, value: mkNode('Identifier', srcLoc(kt), { name: key }), shorthand: true }));
        else if (this.val() ==='=') { this.adv(); props.push(mkNode('Property', srcLoc(this.tok), { key, value: this.parseExpr(), shorthand: true })); }
        else this.adv();
      } else if (v === '[') {
        this.adv(); const ke = this.parseExpr(); if (this.val() ===']') this.adv();
        if (this.val() ===':') { this.adv(); props.push(mkNode('Property', srcLoc(this.tok), { key: ke, value: this.parseExpr(), computed: true })); }
      } else this.adv();
      if (this.val() ===',') this.adv();
    }
    if (this.val() ==='}') this.adv();
    return mkNode('ObjectExpression', rangeLoc(st, this.tok), { properties: props });
  }

  private parseArr(): ASTNode {
    const st = this.adv();
    const els: ASTNode[] = [];
    while (this.val() !==']' && this.typ() !=='EOF') {
      if (this.val() ===',') { this.adv(); continue; }
      if (this.val() ==='...') { this.adv(); els.push(mkNode('SpreadElement', srcLoc(this.tok), { argument: this.parseExpr() })); }
      else { const e = this.parseExpr(); if (e) els.push(e); else this.adv(); }
      if (this.val() ===',') this.adv();
    }
    if (this.val() ===']') this.adv();
    return mkNode('ArrayExpression', rangeLoc(st, this.tok), { elements: els });
  }

  static parse(source: string): ASTNode { return new Parser(source).parseProgram(); }
}

// ============================================================
// SECTION 5 -- TypeScript Compiler API Bridge
// ============================================================

let tsModule: typeof import('typescript') | null = null;

function tryLoadTS(): boolean {
  if (tsModule !== null) return true;
  try { tsModule = require('typescript'); return true; }
  catch { return false; }
}

function parseWithTSC(source: string): ASTNode | null {
  tryLoadTS();
  if (tsModule === null) return null;
  const sf = tsModule.createSourceFile('input.ts', source, tsModule.ScriptTarget.Latest, true);
  return convertTSCNode(sf, tsModule);
}

function convertTSCNode(node: import('typescript').Node, ts: typeof import('typescript')): ASTNode {
  const sf = node.getSourceFile();
  const loc: SourceLocation = {
    start: { line: ts.getLineAndCharacterOfPosition(sf, node.pos).line + 1, column: ts.getLineAndCharacterOfPosition(sf, node.pos).character, offset: node.pos },
    end: { line: ts.getLineAndCharacterOfPosition(sf, node.end).line + 1, column: ts.getLineAndCharacterOfPosition(sf, node.end).character, offset: node.end },
  };
  const children: ASTNode[] = [];
  ts.forEachChild(node, (child: import('typescript').Node) => { const c = convertTSCNode(child, ts); if (c) children.push(c); });
  const kind = ts.SyntaxKind[node.kind];
  const result: ASTNode = mkNode('TSCNode', loc, { kind, children });
  if (ts.isIdentifier(node)) result.name = node.text;
  if (ts.isStringLiteral(node) || ts.isNumericLiteral(node)) result.value = node.text;
  return result;
}

// ============================================================
// SECTION 6 -- Language-Specific Parsers
// ============================================================

function ir(
  type: IRNodeType, line: number, col: number, lang: string,
  name?: string, val?: string, children: IRNode[] = [],
  meta: Record<string, unknown> = {},
): IRNode {
  return { type, name, value: val, children, lineNumber: line, columnNumber: col, language: lang, metadata: meta };
}

function parsePythonToIR(source: string, lang: string): IRNode[] {
  const nodes: IRNode[] = [];
  const lines = source.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i]!.trimEnd();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    const indent = lines[i]!.length - lines[i]!.trimStart().length;

    if (trimmed.match(/^@\w+/)) { nodes.push(ir('VariableDecl', i + 1, indent, lang, trimmed.match(/^@(\w+)/)![1], undefined, [], { decorator: true })); continue; }
    const cm = trimmed.match(/^class\s+(\w+)\s*(?:\(([^)]*)\))?\s*:/);
    if (cm) { nodes.push(ir('ClassDef', i + 1, indent, lang, cm[1], undefined, [], { bases: cm[2] ? cm[2].split(',').map(b => b.trim()).filter(Boolean) : [] })); continue; }
    const fm = trimmed.match(/^(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)/);
    if (fm) { nodes.push(ir('FunctionDef', i + 1, indent + (trimmed.startsWith('async') ? 6 : 0), lang, fm[1], undefined, [], { params: fm[2]?.split(',').map(p => p.trim()).filter(Boolean) || [], async: trimmed.startsWith('async'), indent })); continue; }
    const im = trimmed.match(/^(?:from\s+(\S+)\s+)?import\s+(.+)/);
    if (im) { nodes.push(ir('Import', i + 1, indent, lang, trimmed, undefined, [], { source: im[1] || '', symbols: im[2]?.split(',').map(s => s.trim()) || [] })); continue; }
    const am = trimmed.match(/^(\w+(?:\.\w+)*)\s*=\s*(.+)/);
    if (am && indent === 0) { nodes.push(ir('Assign', i + 1, indent, lang, am[1], undefined, [], { value: am[2]!.substring(0, 80) })); continue; }
    if (trimmed.match(/^(?:if|elif|else)\b/)) { nodes.push(ir('IfStmt', i + 1, indent, lang, trimmed)); continue; }
    if (trimmed.match(/^(?:for|while)\b/)) { nodes.push(ir('ForStmt', i + 1, indent, lang, trimmed, undefined, [], { loopType: trimmed.startsWith('for') ? 'for' : 'while' })); continue; }
    if (trimmed.startsWith('return') || trimmed.startsWith('yield')) { nodes.push(ir('Return', i + 1, indent, lang, trimmed)); continue; }
  }
  return nodes;
}

function parseBraceLang(source: string, lang: string): IRNode[] {
  const nodes: IRNode[] = [];
  for (let i = 0; i < source.split('\n').length; i++) {
    const line = source.split('\n')[i]!.trim();
    if (line.startsWith('import ')) {
      const p = line.match(/^import\s+(?:static\s+)?([\w.*]+)\s*;/);
      if (p) nodes.push(ir('Import', i + 1, 0, lang, p[1]));
      continue;
    }
    if (line.startsWith('@')) { const a = line.match(/^@(\w+)/); if (a) nodes.push(ir('VariableDecl', i + 1, 0, lang, a[1], undefined, [], { annotation: true })); continue; }
    const cm = line.match(/(?:public|private|protected|abstract|final|static)*\s*(?:class|interface|enum|record|struct)\s+(\w+)/);
    if (cm) { nodes.push(ir('ClassDef', i + 1, 0, lang, cm[1])); continue; }
    const mm = line.match(/(?:public|private|protected|static|final|abstract|\s)+[\w<>[\].,?]+\s+(\w+)\s*\(([^)]*)\)\s*(?:\{|throws|;)/);
    if (mm) { nodes.push(ir('FunctionDef', i + 1, 0, lang, mm[1], undefined, [], { params: mm[2]?.split(',').map(p => p.trim()).filter(Boolean) || [] })); continue; }
    const cl = line.match(/(\w+(?:\.\w+)*)\s*\(/);
    if (cl) nodes.push(ir('CallExpr', i + 1, 0, lang, cl[1]));
  }
  return nodes;
}

function parseGoToIR(source: string, lang: string): IRNode[] {
  const nodes: IRNode[] = [];
  for (let i = 0; i < source.split('\n').length; i++) {
    const line = source.split('\n')[i]!.trim();
    if (line.startsWith('package ')) { nodes.push(ir('Import', i + 1, 0, lang, 'package ' + (line.split(/\s+/)[1] || ''))); continue; }
    const imp = line.match(/^import\s+(?:"([^"]+)"|(\w+)\s+"([^"]+)")/);
    if (imp) { nodes.push(ir('Import', i + 1, 0, lang, imp[1] || imp[3] || '')); continue; }
    if (line.match(/^type\s+(\w+)\s+(?:struct|interface)\b/)) { const t = line.match(/^type\s+(\w+)/); if (t) nodes.push(ir('ClassDef', i + 1, 0, lang, t[1])); continue; }
    const fm = line.match(/^func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(([^)]*)\)/);
    if (fm) { nodes.push(ir('FunctionDef', i + 1, 0, lang, fm[1], undefined, [], { params: fm[2]?.split(',').map(p => p.trim()).filter(Boolean) || [], isEntry: fm[1] === 'main' || fm[1] === 'init' })); continue; }
    if (line.includes('go ') && line.includes('(')) { nodes.push(ir('CallExpr', i + 1, 0, lang, 'go ' + line)); continue; }
    if (line.startsWith('defer ')) { nodes.push(ir('CallExpr', i + 1, 0, lang, line.substring(6))); continue; }
  }
  return nodes;
}

function parseRustToIR(source: string, lang: string): IRNode[] {
  const nodes: IRNode[] = [];
  for (let i = 0; i < source.split('\n').length; i++) {
    const line = source.split('\n')[i]!.trim();
    if (line.startsWith('use ')) { nodes.push(ir('Import', i + 1, 0, lang, line)); continue; }
    const dm = line.match(/^(?:pub\s+)?(?:struct|enum|trait|impl)\s+(\w+)/);
    if (dm) { nodes.push(ir('ClassDef', i + 1, 0, lang, dm[1], undefined, [], { declType: line.includes('trait') ? 'trait' : line.includes('impl') ? 'impl' : line.includes('enum') ? 'enum' : 'struct' })); continue; }
    const fm = line.match(/^(?:pub\s+)?(?:unsafe\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]+>)?\s*\(([^)]*)\)/);
    if (fm) { nodes.push(ir('FunctionDef', i + 1, 0, lang, fm[1], undefined, [], { params: (fm[2] || '').split(',').map(p => p.trim()).filter(Boolean) })); continue; }
  }
  return nodes;
}

function parsePHPToIR(source: string, lang: string): IRNode[] {
  const nodes: IRNode[] = [];
  for (let i = 0; i < source.split('\n').length; i++) {
    const line = source.split('\n')[i]!.trim();
    if (!line || line.startsWith('//') || line.startsWith('#')) continue;
    if (line.startsWith('<?php')) { nodes.push(ir('Import', i + 1, 0, lang, '<?php')); continue; }
    if (line.startsWith('namespace ')) { nodes.push(ir('Import', i + 1, 0, lang, line)); continue; }
    if (line.startsWith('use ') && line.endsWith(';')) { nodes.push(ir('Import', i + 1, 0, lang, line)); continue; }
    const cm = line.match(/(?:abstract\s+|final\s+)?class\s+(\w+)/);
    if (cm) { nodes.push(ir('ClassDef', i + 1, 0, lang, cm[1])); continue; }
    const im = line.match(/(?:interface|trait)\s+(\w+)/);
    if (im) { nodes.push(ir('ClassDef', i + 1, 0, lang, im[1], undefined, [], { declType: line.includes('interface') ? 'interface' : 'trait' })); continue; }
    const fm = line.match(/function\s+(\w+)\s*\(([^)]*)\)/);
    if (fm) { nodes.push(ir('FunctionDef', i + 1, 0, lang, fm[1], undefined, [], { params: fm[2]?.split(',').map(p => p.trim()).filter(Boolean) || [] })); continue; }
  }
  return nodes;
}

function parseRubyToIR(source: string, lang: string): IRNode[] {
  const nodes: IRNode[] = [];
  for (let i = 0; i < source.split('\n').length; i++) {
    const line = source.split('\n')[i]!.trim();
    if (line.startsWith('#')) continue;
    const rm = line.match(/^(?:require|require_relative|include|load)\s+['"]([^'"]+)['"]/);
    if (rm) { nodes.push(ir('Import', i + 1, 0, lang, rm[1])); continue; }
    const mm = line.match(/^module\s+(\w+)/);
    if (mm) { nodes.push(ir('ClassDef', i + 1, 0, lang, mm[1], undefined, [], { declType: 'module' })); continue; }
    const cm = line.match(/^class\s+(\w+)/);
    if (cm) { nodes.push(ir('ClassDef', i + 1, 0, lang, cm[1])); continue; }
    const dm = line.match(/^def\s+(?:self\.)?(\w+(?:[?!])?)\s*(?:\(([^)]*)\))?/);
    if (dm) { nodes.push(ir('FunctionDef', i + 1, 0, lang, dm[1], undefined, [], { params: (dm[2] || '').split(',').map(p => p.trim()).filter(Boolean) })); continue; }
  }
  return nodes;
}

function parseJSONToIR(source: string, lang: string): IRNode[] {
  try { const p = JSON.parse(source); if (typeof p === 'object' && p !== null) return [ir('Literal', 1, 0, lang, undefined, 'json-object', [], { keys: Object.keys(p) })]; } catch { /* ignore */ }
  return [];
}

function parseYAMLToIR(source: string, lang: string): IRNode[] {
  const keys: string[] = [];
  for (const l of source.split('\n')) { const m = l.match(/^(\w[\w-]*)\s*:/); if (m) keys.push(m[1]!); }
  return keys.length > 0 ? [ir('Literal', 1, 0, lang, undefined, 'yaml-doc', [], { keys })] : [];
}

function parseTOMLToIR(source: string, lang: string): IRNode[] {
  const nodes: IRNode[] = [];
  for (const l of source.split('\n')) {
    const tm = l.match(/^\[([^\]]+)\]/);
    if (tm) { nodes.push(ir('Literal', 1, 0, lang, tm[1], 'section', [])); continue; }
    const km = l.match(/^(\w[\w._-]*)\s*=/);
    if (km) nodes.push(ir('Literal', 1, 0, lang, km[1]));
  }
  return nodes;
}

// ============================================================
// SECTION 7 -- AST to IR Conversion
// ============================================================

function calleeName(n: ASTNode): string {
  if (!n) return 'unknown';
  if (n.type === 'Identifier') return String(n.name ?? '');
  if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') {
    const obj = calleeName(n.object as ASTNode);
    const prop = n.property as ASTNode | string;
    const pn = typeof prop === 'string' ? prop : String((prop as ASTNode).name ?? '');
    return obj ? `${obj}.${pn}` : pn;
  }
  if (n.type === 'CallExpression') return `${calleeName(n.callee as ASTNode)}()`;
  return 'expr';
}

function astToIR(node: ASTNode, lang: string): IRNode[] {
  const out: IRNode[] = [];
  walk(node, lang, out, 0);
  return out;
}

function walk(node: ASTNode, lang: string, out: IRNode[], depth: number): void {
  if (depth > 200 || !node || !node.type) return;
  const l = node.loc.start.line, c = node.loc.start.column;
  let n: IRNode | null = null;

  const t = node.type;

  if (t === 'FunctionDeclaration') {
    const name = String(node.name ?? 'anonymous');
    const params = ((node.params as ASTNode[]) || []).map((p: ASTNode) => ir('Parameter', p.loc.start.line, p.loc.start.column, lang, String(p.name ?? '')));
    n = ir('FunctionDef', l, c, lang, name, undefined, params, { async: !!node.async, generator: !!node.generator });
    for (const ch of (node.body as ASTNode[]) || []) walk(ch, lang, out, depth + 1);
  } else if (t === 'ArrowFunctionExpression' || t === 'FunctionExpression') {
    const name = String(node.name ?? (t === 'ArrowFunctionExpression' ? 'arrow' : 'anonymous_func'));
    const params = ((node.params as ASTNode[]) || []).map((p: ASTNode) => ir('Parameter', p.loc.start.line, p.loc.start.column, lang, String(p.name ?? '')));
    n = ir('ArrowFunc', l, c, lang, name, undefined, params);
    for (const ch of (node.body as ASTNode[]) || []) walk(ch, lang, out, depth + 1);
  } else if (t === 'CallExpression') {
    const cal = node.callee as ASTNode;
    n = ir('CallExpr', l, c, lang, calleeName(cal));
  } else if (t === 'BinaryExpression' || t === 'LogicalExpression') {
    n = ir('BinaryOp', l, c, lang, undefined, String(node.operator ?? ''), [toIR(node.left as ASTNode, lang), toIR(node.right as ASTNode, lang)], { operator: node.operator });
  } else if (t === 'UnaryExpression' || t === 'UpdateExpression') {
    n = ir('UnaryOp', l, c, lang, undefined, String(node.operator ?? ''), [toIR(node.argument as ASTNode, lang)], { prefix: !!node.prefix });
  } else if (t === 'ConditionalExpression') {
    n = ir('TernaryExpr', l, c, lang, undefined, undefined, [toIR(node.test as ASTNode, lang), toIR(node.consequent as ASTNode, lang), toIR(node.alternate as ASTNode, lang)]);
  } else if (t === 'IfStatement') {
    n = ir('IfStmt', l, c, lang, undefined, undefined, [toIR(node.test as ASTNode, lang)]);
    walk(node.consequent as ASTNode, lang, out, depth + 1);
    walk(node.alternate as ASTNode, lang, out, depth + 1);
  } else if (t === 'VariableDeclaration') {
    for (const d of (node.declarations as Array<Record<string, unknown>>) || []) {
      out.push(ir('VariableDecl', l, c, lang, String(d.id ?? ''), undefined, [], { kind: node.kind }));
      if (d.init) walk(d.init as ASTNode, lang, out, depth + 1);
    }
    n = null;
  } else if (t === 'AssignmentExpression') {
    n = ir('Assign', l, c, lang, calleeName(node.left as ASTNode), undefined, [], { operator: String(node.operator ?? '=') });
  } else if (t === 'ForStatement' || t === 'WhileStatement') {
    n = ir('ForStmt', l, c, lang, undefined, t);
    walk(node.body as ASTNode, lang, out, depth + 1);
  } else if (t === 'DoWhileStatement') {
    n = ir('DoWhileStmt', l, c, lang);
  } else if (t === 'SwitchStatement') {
    n = ir('SwitchStmt', l, c, lang);
  } else if (t === 'TryStatement') {
    n = ir('TryStmt', l, c, lang);
  } else if (t === 'ReturnStatement') {
    n = ir('Return', l, c, lang, undefined, undefined, node.argument ? [toIR(node.argument as ASTNode, lang)] : []);
    if (node.argument) walk(node.argument as ASTNode, lang, out, depth + 1);
  } else if (t === 'ThrowStatement') {
    n = ir('ThrowStmt', l, c, lang);
  } else if (t === 'ImportDeclaration' || t === 'ImportExpression') {
    n = ir('Import', l, c, lang, undefined, String(node.source ?? ''), [], { importType: t });
  } else if (t === 'ClassDeclaration') {
    n = ir('ClassDef', l, c, lang, String(node.name ?? ''), undefined, [], { superClass: String(node.superClass ?? '') });
  } else if (t === 'MemberExpression' || t === 'OptionalMemberExpression') {
    const prop = node.property as ASTNode | string;
    n = ir('MemberAccess', l, c, lang, typeof prop === 'string' ? prop : String((prop as ASTNode).name ?? ''));
  } else if (t === 'ArrayExpression') {
    n = ir('Literal', l, c, lang, undefined, 'array', [], { elementCount: ((node.elements as ASTNode[]) || []).length });
  } else if (t === 'ObjectExpression') {
    n = ir('Literal', l, c, lang, undefined, 'object', [], { propertyCount: ((node.properties as ASTNode[]) || []).length });
  } else if (t === 'SpreadElement') {
    n = ir('SpreadElement', l, c, lang);
  } else if (t === 'AwaitExpression') {
    n = ir('AwaitExpr', l, c, lang);
  } else if (t === 'YieldExpression') {
    n = ir('YieldExpr', l, c, lang);
  } else if (t === 'TemplateLiteral') {
    n = ir('TemplateExpr', l, c, lang, undefined, String(node.value ?? (node.quasis as any)?.[0] ?? ''));
  }

  if (n) out.push(n);

  // Walk children recursively for unhandled node types
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'type') continue;
    const val = node[key];
    if (Array.isArray(val)) { for (const item of val) { if (typeof item === 'object' && item !== null && (item as ASTNode).type) walk(item as ASTNode, lang, out, depth + 1); } }
    else if (typeof val === 'object' && val !== null && (val as ASTNode).type) walk(val as ASTNode, lang, out, depth + 1);
  }
}

function toIR(node: ASTNode | null, lang: string): IRNode {
  if (!node) return ir('Literal', 0, 0, lang, 'nil');
  const l = node.loc.start.line, c = node.loc.start.column;
  if (node.type === 'Literal') return ir('Literal', l, c, lang, undefined, String(node.value ?? ''));
  if (node.type === 'Identifier') return ir('Literal', l, c, lang, String(node.name ?? ''));
  if (node.type === 'CallExpression') return ir('CallExpr', l, c, lang, calleeName(node.callee as ASTNode));
  return ir('Literal', l, c, lang, node.type);
}

// ============================================================
// SECTION 8 -- Call Graph
// ============================================================

const ENTRY_NAMES = new Set([
  'main', 'init', 'start', 'run', 'handle', 'serve', 'controller',
  'handler', 'router', 'index', 'app', 'bootstrap', 'lambda_handler',
  'middleware', 'setup', 'configure', 'onRequest', 'onEvent',
]);

export function buildCallGraph(irNodes: IRNode[]): Map<string, CallGraphNode> {
  const graph = new Map<string, CallGraphNode>();

  // Register functions
  for (const node of irNodes) {
    if (node.type === 'FunctionDef' && node.name && !graph.has(node.name)) {
      graph.set(node.name, {
        functionName: node.name, filePath: '', lineNumber: node.lineNumber,
        callees: [], callers: [],
        isEntryPoint: [...ENTRY_NAMES].some(n => node.name!.toLowerCase().includes(n)),
        isReachable: true,
      });
    }
  }

  // Resolve call relationships
  let lastFunc = '';
  const funcsByLine = [...graph.entries()].map(([n, g]) => ({ n, l: g.lineNumber })).sort((a, b) => b.l - a.l);

  for (const node of irNodes) {
    if (node.type === 'CallExpr' && node.name) {
      // Find enclosing function
      for (const fn of funcsByLine) { if (fn.l <= node.lineNumber) { lastFunc = fn.n; break; } }

      const parts = node.name.split('.');
      const direct = parts[0];
      const method = parts.length > 1 ? parts[1] : undefined;
      let resolved = '';

      if (graph.has(node.name)) resolved = node.name;
      else if (graph.has(direct)) resolved = direct;
      else if (method && graph.has(method)) resolved = method;

      if (resolved && lastFunc) {
        const callee = graph.get(resolved);
        const caller = graph.get(lastFunc);
        if (callee && caller) {
          if (!caller.callees.includes(resolved)) caller.callees.push(resolved);
          if (!callee.callers.includes(lastFunc)) callee.callers.push(lastFunc);
        }
      }
    }
  }

  // Compute reachability
  const visited = new Set<string>();
  const queue = [...graph.values()].filter(n => n.isEntryPoint).map(n => n.functionName);
  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (visited.has(cur)) continue;
    visited.add(cur);
    const gn = graph.get(cur);
    if (gn) { gn.isReachable = true; for (const c of gn.callees) { if (!visited.has(c)) queue.push(c); } }
  }
  for (const [, gn] of graph) { if (!visited.has(gn.functionName)) gn.isReachable = false; }

  return graph;
}

// ============================================================
// SECTION 9 -- CFG Construction
// ============================================================

export function buildCFG(irNodes: IRNode[]): CFGBasicBlock[] {
  const blocks: CFGBasicBlock[] = [];
  if (irNodes.length === 0) return blocks;

  let nextId = 0;
  const entry: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [], isEntry: true, isExit: false };
  blocks.push(entry);

  let cur: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [entry.id], isEntry: false, isExit: false };
  blocks.push(cur);
  entry.successors.push(cur.id);

  for (const node of irNodes) {
    if (node.type === 'IfStmt') {
      cur.statements.push(node);
      const branch: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [cur.id], isEntry: false, isExit: false };
      cur.successors.push(branch.id);
      blocks.push(branch);
      const merge: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [], isEntry: false, isExit: false };
      branch.successors.push(merge.id);
      blocks.push(merge);
      cur = merge;
    } else if (node.type === 'ForStmt' || node.type === 'WhileStmt' || node.type === 'DoWhileStmt') {
      cur.statements.push(node);
      const lb: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [cur.id], isEntry: false, isExit: false };
      cur.successors.push(lb.id);
      blocks.push(lb);
      const lx: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [lb.id], isEntry: false, isExit: false };
      lb.successors.push(lx.id, cur.id);
      blocks.push(lx);
      cur = lx;
    } else if (node.type === 'TryStmt') {
      cur.statements.push(node);
      const tb: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [cur.id], isEntry: false, isExit: false };
      const hb: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [cur.id], isEntry: false, isExit: false };
      cur.successors.push(tb.id, hb.id);
      blocks.push(tb, hb);
      const tm: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [tb.id, hb.id], isEntry: false, isExit: false };
      tb.successors.push(tm.id); hb.successors.push(tm.id);
      blocks.push(tm);
      cur = tm;
    } else if (node.type === 'SwitchStmt') {
      cur.statements.push(node);
      const sm: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [cur.id], isEntry: false, isExit: false };
      cur.successors.push(sm.id);
      blocks.push(sm);
      cur = sm;
    } else if (node.type === 'Return' || node.type === 'ThrowStmt') {
      cur.statements.push(node);
      const nb: CFGBasicBlock = { id: nextId++, statements: [], successors: [], predecessors: [], isEntry: false, isExit: true };
      blocks.push(nb);
      cur.isExit = true;
      cur = nb;
    } else {
      cur.statements.push(node);
    }
  }

  if (!cur.isExit && cur.statements.length > 0) cur.isExit = true;
  if (blocks.length === 1) blocks[0]!.isExit = true;

  // Dominator analysis
  if (blocks.length > 0) {
    const entryId = blocks.find(b => b.isEntry)?.id;
    if (entryId !== undefined) {
      const dom = new Map<number, Set<number>>();
      for (const b of blocks) dom.set(b.id, new Set(blocks.map(x => x.id)));
      dom.set(entryId, new Set([entryId]));
      let changed = true;
      while (changed) {
        changed = false;
        for (const b of blocks) {
          if (b.id === entryId || b.predecessors.length === 0) continue;
          const pd = b.predecessors.map(p => dom.get(p)).filter((d): d is Set<number> => d !== undefined);
          if (pd.length === 0) continue;
          let nd = new Set(pd[0]!);
          for (let i = 1; i < pd.length; i++) nd = new Set([...nd].filter(x => pd[i]!.has(x)));
          nd.add(b.id);
          const od = dom.get(b.id);
          if (od && !(nd.size === od.size && [...nd].every(x => od.has(x)))) { dom.set(b.id, nd); changed = true; }
        }
      }
    }
  }

  return blocks;
}

// ============================================================
// SECTION 10 -- Taint Tracking
// ============================================================

const SRC_PATTERNS: Array<{ re: RegExp; type: string; desc: string }> = [
  { re: /req\.(body|query|params|headers|cookies)/, type: 'HTTP', desc: 'HTTP request data' },
  { re: /request\.(args|form|json|data|query)/, type: 'HTTP', desc: 'HTTP request data' },
  { re: /@RequestBody|@RequestParam|@PathVariable/, type: 'HTTP', desc: 'HTTP annotated param' },
  { re: /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/, type: 'HTTP', desc: 'PHP superglobal' },
  { re: /c\.(Query|Param|PostForm|FormValue)/, type: 'HTTP', desc: 'Gin input' },
  { re: /ctx\.(Query|Param|PostForm|FormValue)/, type: 'HTTP', desc: 'Context input' },
  { re: /readFile(?:Sync)?|file_get_contents|fopen|fs\.readFile/, type: 'File', desc: 'File read' },
  { re: /process\.env|process\.argv|Deno\.env/, type: 'Env', desc: 'Environment variable' },
  { re: /os\.(Getenv|Environ|Args)/, type: 'Env', desc: 'Go env var' },
  { re: /getElementById|querySelector|innerHTML|outerHTML/, type: 'DOM', desc: 'DOM input' },
  { re: /window\.location|document\.cookie|document\.referrer/, type: 'DOM', desc: 'Browser DOM input' },
  { re: /req\.formFile|multipart\.Form/, type: 'File', desc: 'File upload' },
];

const SNK_PATTERNS: Array<{ re: RegExp; type: string; sev: string }> = [
  { re: /(execute|query|raw|exec|queryRaw|findRaw)\s*\(/, type: 'SQL', sev: 'critical' },
  { re: /(exec|spawn|system|popen|shell_exec|execSync)\s*\(/, type: 'Command', sev: 'critical' },
  { re: /(eval|Function\(|setTimeout|setInterval)\s*\(/, type: 'Code', sev: 'critical' },
  { re: /writeFile(?:Sync)?|fwrite|file_put_contents|fs\.writeFile/, type: 'FileWrite', sev: 'high' },
  { re: /render|send\(|json\(|html\(|sendFile/, type: 'HTTP Response', sev: 'medium' },
  { re: /(fetch|axios|http\.(Get|Post)|request\.(get|post)|curl_exec)\s*\(/, type: 'HTTP Request', sev: 'high' },
  { re: /innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML/, type: 'XSS', sev: 'critical' },
  { re: /log\.(info|warn|error|debug)|console\.(log|error|warn)/, type: 'Log', sev: 'low' },
];

const SAN_RE = [/sanitize/i, /escape/i, /validate/i, /clean/i, /scrub/i, /filter/i,
  /purify/i, /encode/i, /htmlspecialchars/i, /escapeHtml/i, /DOMPurify/i,
  /sanitizeHtml/i, /validator/i, /PreparedStatement/i, /parameterize/i,
  /bindParam/i, /quote/i, /stripTags/i, /crypto/i, /encrypt/i];

export function identifySources(irNodes: IRNode[]): TaintSource[] {
  const sources: TaintSource[] = [];
  const seen = new Set<string>();
  for (const node of irNodes) {
    const name = node.name || '';
    for (const sp of SRC_PATTERNS) {
      if (sp.re.test(name)) {
        const key = `${sp.type}:${node.lineNumber}`;
        if (!seen.has(key)) { seen.add(key); sources.push({ type: sp.type, node, description: `${sp.desc} at line ${node.lineNumber}` }); }
        break;
      }
    }
  }
  return sources;
}

export function identifySinks(irNodes: IRNode[]): TaintSink[] {
  const sinks: TaintSink[] = [];
  const seen = new Set<string>();
  for (const node of irNodes) {
    const name = node.name || '';
    for (const sp of SNK_PATTERNS) {
      if (sp.re.test(name)) {
        const key = `${sp.type}:${node.lineNumber}`;
        if (!seen.has(key)) { seen.add(key); sinks.push({ type: sp.type, node, description: `${sp.type} sink at line ${node.lineNumber}`, severity: sp.sev }); }
        break;
      }
    }
  }
  return sinks;
}

function findEnclosingFunc(node: IRNode, allNodes: IRNode[]): string | null {
  let closest: string | null = null, closestLine = 0;
  for (const n of allNodes) {
    if (n.type === 'FunctionDef' && n.name && n.lineNumber <= node.lineNumber && n.lineNumber > closestLine) {
      closest = n.name; closestLine = n.lineNumber;
    }
  }
  return closest;
}

function pathExists(from: string, to: string, cg: Map<string, CallGraphNode>): boolean {
  const visited = new Set<string>();
  const q = [from];
  while (q.length) {
    const cur = q.shift()!;
    if (cur === to) return true;
    if (visited.has(cur)) continue;
    visited.add(cur);
    const n = cg.get(cur);
    if (n) for (const c of n.callees) { if (!visited.has(c)) q.push(c); }
  }
  return false;
}

export function traceDataflow(
  sources: TaintSource[], sinks: TaintSink[],
  allNodes: IRNode[], callGraph: Map<string, CallGraphNode>,
): TaintPath[] {
  const paths: TaintPath[] = [];
  if (sources.length === 0 || sinks.length === 0) return paths;

  for (const src of sources) {
    for (const snk of sinks) {
      const between = allNodes.filter(n => n.lineNumber >= src.node.lineNumber && n.lineNumber <= snk.node.lineNumber);

      const sanitizers: string[] = [];
      for (const n of between) { const nn = n.name || ''; if (SAN_RE.some(r => r.test(nn)) && !sanitizers.includes(nn)) sanitizers.push(nn); }

      const srcFunc = findEnclosingFunc(src.node, allNodes);
      const snkFunc = findEnclosingFunc(snk.node, allNodes);
      let reach = 1.0;

      if (srcFunc && snkFunc && srcFunc !== snkFunc) {
        const sc = callGraph.get(srcFunc), sk = callGraph.get(snkFunc);
        if (sc && sk) {
          if (sc.isReachable && sk.isReachable) reach = pathExists(srcFunc, snkFunc, callGraph) ? 1.0 : 0.5;
          else reach = 0.0;
        }
      }

      const taintBroken = sanitizers.length > 0;
      paths.push({
        source: src, sink: snk, nodes: between, sanitizers, taintBroken,
        pathLength: between.length,
        reachabilityScore: taintBroken ? Math.min(reach, 0.3) : reach,
      });
    }
  }

  // Deduplicate and sort
  const seen = new Set<string>();
  return paths.filter(p => {
    const key = `${p.source.type}:${p.source.node.lineNumber}->${p.sink.type}:${p.sink.node.lineNumber}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => (b.reachabilityScore * (b.sink.severity === 'critical' ? 10 : b.sink.severity === 'high' ? 5 : 1)) -
    (a.reachabilityScore * (a.sink.severity === 'critical' ? 10 : a.sink.severity === 'high' ? 5 : 1)));
}

// ============================================================
// SECTION 11 -- Language Detection & Dispatcher
// ============================================================

const LANG_ALIASES: Record<string, string> = {
  js: 'javascript', ts: 'typescript', jsx: 'javascript', tsx: 'typescript',
  py: 'python', cs: 'csharp', 'c#': 'csharp',
  golang: 'go', rs: 'rust', rb: 'ruby', kt: 'kotlin',
  yml: 'yaml',
};

const EXT_MAP: Record<string, string> = {
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.py': 'python', '.java': 'java', '.cs': 'csharp', '.go': 'go', '.rs': 'rust',
  '.php': 'php', '.rb': 'ruby', '.kt': 'kotlin', '.kts': 'kotlin',
  '.scala': 'scala', '.swift': 'swift',
  '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json', '.toml': 'toml',
};

function normalizeLang(language: string): string {
  return LANG_ALIASES[language.toLowerCase()] || language.toLowerCase();
}

function detectLang(filePath: string): string {
  return EXT_MAP[path.extname(filePath).toLowerCase()] || 'unknown';
}

// ============================================================
// SECTION 12 -- Caching
// ============================================================

interface CacheEntry { hash: string; data: IRNode[]; ts: number; }
const cache = new Map<string, CacheEntry>();
const MAX_CACHE = 500;
const CACHE_TTL = 5 * 60 * 1000;

function cacheKey(source: string, lang: string, fp: string): string {
  return `${lang}:${fp}:${crypto.createHash('sha256').update(source).digest('hex').substring(0, 16)}`;
}

function cacheGet(source: string, lang: string, fp: string): IRNode[] | null {
  const k = cacheKey(source, lang, fp);
  const e = cache.get(k);
  if (e && Date.now() - e.ts < CACHE_TTL) return e.data;
  if (e) cache.delete(k);
  return null;
}

function cacheSet(source: string, lang: string, fp: string, data: IRNode[]): void {
  if (cache.size >= MAX_CACHE) {
    let oldK = '', oldT = Infinity;
    for (const [k, v] of cache) { if (v.ts < oldT) { oldT = v.ts; oldK = k; } }
    if (oldK) cache.delete(oldK);
  }
  const k = cacheKey(source, lang, fp);
  cache.set(k, { hash: k, data, ts: Date.now() });
}

export function clearParseCache(): void { cache.clear(); }

// ============================================================
// SECTION 13 -- Public API
// ============================================================

const SUPPORTED = new Set([
  'javascript', 'typescript', 'python', 'java', 'csharp', 'go', 'rust',
  'php', 'ruby', 'kotlin', 'scala', 'swift', 'yaml', 'json', 'toml',
]);

export function supportsASTAnalysis(language: string): boolean {
  return SUPPORTED.has(normalizeLang(language));
}

export function parseToIR(sourceCode: string, language: string, filePath: string): IRNode[] {
  if (!sourceCode || sourceCode.trim().length === 0) return [];
  const lang = normalizeLang(language || detectLang(filePath));

  const cached = cacheGet(sourceCode, lang, filePath);
  if (cached) return cached;

  let irNodes: IRNode[];

  try {
    switch (lang) {
      case 'javascript':
      case 'typescript': {
        let ast: ASTNode | null = null;
        if (lang === 'typescript') ast = parseWithTSC(sourceCode);
        if (!ast) ast = Parser.parse(sourceCode);
        irNodes = ast ? astToIR(ast, lang) : [];
        break;
      }
      case 'json': irNodes = parseJSONToIR(sourceCode, lang); break;
      case 'yaml': irNodes = parseYAMLToIR(sourceCode, lang); break;
      case 'toml': irNodes = parseTOMLToIR(sourceCode, lang); break;
      default: {
        // For all other languages, attempt tree-sitter first with regex fallback
        if (isTreeSitterSupported(lang)) {
          irNodes = parseToIRWithTreeSitter(sourceCode, lang);
        } else {
          logger.warn(`No dedicated parser for "${lang}", using generic parser`);
          try { irNodes = astToIR(Parser.parse(sourceCode), lang); }
          catch { irNodes = []; }
        }
        break;
      }
    }
  } catch (error) {
    logger.error({ error, language: lang, filePath }, 'AST parsing error');
    irNodes = [];
  }

  cacheSet(sourceCode, lang, filePath, irNodes);
  return irNodes;
}

// Tree-sitter cache: stores parsed results from async parsing
const treeSitterCache = new Map<string, IRNode[]>();

function parseToIRWithTreeSitter(sourceCode: string, lang: string): IRNode[] {
  const key = crypto.createHash('md5').update(sourceCode).digest('hex') + ':' + lang;
  const cached = treeSitterCache.get(key);
  if (cached) return cached;

  // Fire async parse and cache result; return regex fallback synchronously
  parseWithTreeSitter(sourceCode, lang).then(nodes => {
    if (nodes && nodes.length > 0) {
      treeSitterCache.set(key, nodes);
      if (treeSitterCache.size > 2000) {
        const first = treeSitterCache.keys().next().value;
        if (first) treeSitterCache.delete(first);
      }
    }
  }).catch(() => { /* fallback to regex */ });

  // Synchronous regex fallback while tree-sitter loads/parses
  switch (lang) {
    case 'python': return parsePythonToIR(sourceCode, lang);
    case 'java': case 'csharp': case 'kotlin': case 'scala': return parseBraceLang(sourceCode, lang);
    case 'go': return parseGoToIR(sourceCode, lang);
    case 'rust': return parseRustToIR(sourceCode, lang);
    case 'php': return parsePHPToIR(sourceCode, lang);
    case 'ruby': return parseRubyToIR(sourceCode, lang);
    case 'c': case 'cpp': return parseBraceLang(sourceCode, lang);
    default: return [];
  }
}

export async function parseToIRAsync(sourceCode: string, language: string, filePath: string): Promise<IRNode[]> {
  if (!sourceCode || sourceCode.trim().length === 0) return [];
  const lang = normalizeLang(language || detectLang(filePath));

  const cached = cacheGet(sourceCode, lang, filePath);
  if (cached) return cached;

  if (lang === 'javascript' || lang === 'typescript' || lang === 'json' || lang === 'yaml' || lang === 'toml') {
    return parseToIR(sourceCode, language, filePath);
  }

  if (isTreeSitterSupported(lang)) {
    try {
      const tsNodes = await parseWithTreeSitter(sourceCode, lang);
      if (tsNodes && tsNodes.length > 0) {
        cacheSet(sourceCode, lang, filePath, tsNodes);
        return tsNodes;
      }
    } catch { /* fall through to regex */ }
  }

  return parseToIR(sourceCode, language, filePath);
}
