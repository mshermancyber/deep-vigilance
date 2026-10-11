// Tree-sitter AST parser — replaces regex-based parsers for supported languages
// Produces the same IRNode[] format as the existing parsers in ast-engine.ts
import { logger } from '../utils/logger.js';
import type { IRNode, IRNodeType } from './ast-engine.js';

type SyntaxNode = {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  childCount: number;
  children: SyntaxNode[];
  namedChildCount: number;
  namedChildren: SyntaxNode[];
  childForFieldName(name: string): SyntaxNode | null;
  childrenForFieldName?(name: string): SyntaxNode[];
  parent: SyntaxNode | null;
};

type TreeSitterTree = { rootNode: SyntaxNode };
type TreeSitterParser = { parse(input: string): TreeSitterTree; setLanguage(lang: unknown): void };
type TreeSitterModule = {
  init(): Promise<void>;
  Language: { load(path: string): Promise<unknown> };
  Parser?: new () => TreeSitterParser;
};

let tsModule: TreeSitterModule | null = null;
const langCache = new Map<string, unknown>();

const LANG_TO_WASM: Record<string, string> = {
  python: 'tree-sitter-python.wasm',
  java: 'tree-sitter-java.wasm',
  go: 'tree-sitter-go.wasm',
  rust: 'tree-sitter-rust.wasm',
  c: 'tree-sitter-c.wasm',
  cpp: 'tree-sitter-cpp.wasm',
  csharp: 'tree-sitter-c_sharp.wasm',
  php: 'tree-sitter-php.wasm',
  ruby: 'tree-sitter-ruby.wasm',
  kotlin: 'tree-sitter-kotlin.wasm',
};

async function getParser(lang: string): Promise<TreeSitterParser | null> {
  const wasmFile = LANG_TO_WASM[lang];
  if (!wasmFile) return null;

  if (!tsModule) {
    try {
      const mod = await import('web-tree-sitter');
      tsModule = (mod.default || mod) as TreeSitterModule;
      await tsModule.init();
    } catch (err) {
      logger.warn({ err }, 'web-tree-sitter init failed');
      return null;
    }
  }

  if (!langCache.has(lang)) {
    try {
      const { createRequire } = await import('module');
      const require = createRequire(import.meta.url);
      const wasmsPath = require.resolve('tree-sitter-wasms/out/' + wasmFile);
      const language = await tsModule.Language.load(wasmsPath);
      langCache.set(lang, language);
    } catch (err) {
      logger.warn({ err, lang }, 'Failed to load tree-sitter grammar');
      return null;
    }
  }

  const ParserClass = tsModule.Parser || (tsModule as any);
  const parser: TreeSitterParser = new (ParserClass as any)();
  parser.setLanguage(langCache.get(lang)!);
  return parser;
}

function ir(
  type: IRNodeType, line: number, col: number, lang: string,
  name?: string, val?: string, children: IRNode[] = [],
  meta: Record<string, unknown> = {},
): IRNode {
  return { type, name, value: val, children, lineNumber: line, columnNumber: col, language: lang, metadata: meta };
}

function fieldText(node: SyntaxNode, field: string): string {
  return node.childForFieldName(field)?.text || '';
}

function extractParams(node: SyntaxNode): string[] {
  const paramList = node.childForFieldName('parameters') || node.childForFieldName('params');
  if (!paramList) return [];
  return paramList.namedChildren
    .filter(p => p.type !== ',' && p.type !== '(' && p.type !== ')')
    .map(p => {
      const name = p.childForFieldName('name');
      return name ? name.text : p.text;
    })
    .filter(Boolean);
}

// =========================================================================
// Python visitor
// =========================================================================

function visitPython(node: SyntaxNode, lang: string, nodes: IRNode[]): void {
  switch (node.type) {
    case 'import_statement':
    case 'import_from_statement': {
      const mod = node.childForFieldName('module_name') || node.childForFieldName('name');
      nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, node.text, undefined, [], {
        source: mod?.text || '',
      }));
      break;
    }
    case 'class_definition': {
      const name = fieldText(node, 'name');
      const bases = node.childForFieldName('superclasses');
      nodes.push(ir('ClassDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
        bases: bases ? bases.namedChildren.map(b => b.text) : [],
      }));
      for (const child of node.namedChildren) visitPython(child, lang, nodes);
      return;
    }
    case 'function_definition': {
      const name = fieldText(node, 'name');
      const params = extractParams(node);
      const isAsync = node.children.some(c => c.type === 'async');
      const decorators = node.namedChildren.filter(c => c.type === 'decorator').map(d => d.text);
      nodes.push(ir('FunctionDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
        params, async: isAsync, decorators,
      }));
      for (const child of node.namedChildren) visitPython(child, lang, nodes);
      return;
    }
    case 'decorated_definition': {
      for (const child of node.namedChildren) visitPython(child, lang, nodes);
      return;
    }
    case 'assignment':
    case 'augmented_assignment': {
      const left = node.namedChildren[0];
      const right = node.namedChildren[node.namedChildren.length - 1];
      if (left) {
        nodes.push(ir('Assign', node.startPosition.row + 1, node.startPosition.column, lang, left.text, undefined, [], {
          value: right?.text?.substring(0, 80) || '',
        }));
      }
      break;
    }
    case 'call': {
      const fn = node.childForFieldName('function');
      if (fn) nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, fn.text));
      break;
    }
    case 'return_statement':
      nodes.push(ir('Return', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'yield':
      nodes.push(ir('YieldExpr', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'if_statement':
    case 'elif_clause':
      nodes.push(ir('IfStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitPython(child, lang, nodes);
      return;
    case 'for_statement':
      nodes.push(ir('ForStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0], undefined, [], { loopType: 'for' }));
      for (const child of node.namedChildren) visitPython(child, lang, nodes);
      return;
    case 'while_statement':
      nodes.push(ir('WhileStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0], undefined, [], { loopType: 'while' }));
      for (const child of node.namedChildren) visitPython(child, lang, nodes);
      return;
    case 'try_statement':
      nodes.push(ir('TryStmt', node.startPosition.row + 1, node.startPosition.column, lang, 'try'));
      for (const child of node.namedChildren) visitPython(child, lang, nodes);
      return;
    case 'raise_statement':
      nodes.push(ir('ThrowStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'await':
      nodes.push(ir('AwaitExpr', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
  }
  for (const child of node.namedChildren) visitPython(child, lang, nodes);
}

// =========================================================================
// Java / C# / Kotlin visitor (brace languages)
// =========================================================================

function visitBraceLang(node: SyntaxNode, lang: string, nodes: IRNode[]): void {
  switch (node.type) {
    case 'import_declaration':
    case 'using_directive':
    case 'import_header':
    case 'package_declaration': {
      nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, node.text.replace(/;$/, '').trim()));
      break;
    }
    case 'class_declaration':
    case 'interface_declaration':
    case 'enum_declaration':
    case 'record_declaration':
    case 'annotation_type_declaration':
    case 'struct_declaration':
    case 'class_definition':
    case 'object_declaration': {
      const name = fieldText(node, 'name') || fieldText(node, 'identifier');
      const declType = node.type.replace('_declaration', '').replace('_definition', '');
      nodes.push(ir('ClassDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], { declType }));
      for (const child of node.namedChildren) visitBraceLang(child, lang, nodes);
      return;
    }
    case 'method_declaration':
    case 'constructor_declaration':
    case 'function_declaration':
    case 'function_definition': {
      const name = fieldText(node, 'name') || fieldText(node, 'identifier') || fieldText(node, 'declarator');
      const params = extractParams(node);
      const mods: string[] = [];
      for (const c of node.namedChildren) {
        if (c.type === 'modifiers' || c.type.endsWith('_modifier')) mods.push(c.text);
      }
      nodes.push(ir('FunctionDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
        params, modifiers: mods,
      }));
      for (const child of node.namedChildren) visitBraceLang(child, lang, nodes);
      return;
    }
    case 'method_invocation':
    case 'object_creation_expression':
    case 'invocation_expression': {
      const name = fieldText(node, 'name') || fieldText(node, 'function');
      if (name) nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, name));
      break;
    }
    case 'return_statement':
      nodes.push(ir('Return', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'if_statement':
      nodes.push(ir('IfStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitBraceLang(child, lang, nodes);
      return;
    case 'for_statement':
    case 'enhanced_for_statement':
    case 'foreach_statement':
      nodes.push(ir('ForStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitBraceLang(child, lang, nodes);
      return;
    case 'while_statement':
    case 'do_statement':
      nodes.push(ir(node.type === 'do_statement' ? 'DoWhileStmt' : 'WhileStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitBraceLang(child, lang, nodes);
      return;
    case 'try_statement':
    case 'try_with_resources_statement':
      nodes.push(ir('TryStmt', node.startPosition.row + 1, node.startPosition.column, lang, 'try'));
      for (const child of node.namedChildren) visitBraceLang(child, lang, nodes);
      return;
    case 'throw_statement':
      nodes.push(ir('ThrowStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'switch_expression':
    case 'switch_statement':
      nodes.push(ir('SwitchStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitBraceLang(child, lang, nodes);
      return;
    case 'marker_annotation':
    case 'annotation':
    case 'attribute': {
      const aName = fieldText(node, 'name') || node.text.replace(/^@/, '');
      nodes.push(ir('VariableDecl', node.startPosition.row + 1, node.startPosition.column, lang, aName, undefined, [], { annotation: true }));
      break;
    }
    case 'local_variable_declaration':
    case 'variable_declaration': {
      const decl = node.childForFieldName('declarator') || node.namedChildren.find(c => c.type.includes('declarator'));
      const name = decl?.childForFieldName('name')?.text || decl?.text?.split(/\s*[=;]/)[0] || '';
      if (name) nodes.push(ir('VariableDecl', node.startPosition.row + 1, node.startPosition.column, lang, name));
      break;
    }
  }
  for (const child of node.namedChildren) visitBraceLang(child, lang, nodes);
}

// =========================================================================
// Go visitor
// =========================================================================

function visitGo(node: SyntaxNode, lang: string, nodes: IRNode[]): void {
  switch (node.type) {
    case 'package_clause': {
      const name = fieldText(node, 'name') || node.namedChildren[0]?.text || '';
      nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, 'package ' + name));
      break;
    }
    case 'import_declaration':
    case 'import_spec': {
      const path = node.childForFieldName('path')?.text?.replace(/"/g, '') || node.text.replace(/"/g, '').trim();
      if (path && path !== 'import') nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, path));
      for (const child of node.namedChildren) visitGo(child, lang, nodes);
      return;
    }
    case 'type_declaration':
    case 'type_spec': {
      const name = fieldText(node, 'name') || node.namedChildren[0]?.text || '';
      const typeBody = node.childForFieldName('type');
      const declType = typeBody?.type === 'struct_type' ? 'struct' : typeBody?.type === 'interface_type' ? 'interface' : 'type';
      nodes.push(ir('ClassDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], { declType }));
      for (const child of node.namedChildren) visitGo(child, lang, nodes);
      return;
    }
    case 'function_declaration':
    case 'method_declaration': {
      const name = fieldText(node, 'name');
      const params = extractParams(node);
      const receiver = node.childForFieldName('receiver');
      nodes.push(ir('FunctionDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
        params,
        isEntry: name === 'main' || name === 'init',
        receiver: receiver?.text || undefined,
      }));
      for (const child of node.namedChildren) visitGo(child, lang, nodes);
      return;
    }
    case 'call_expression': {
      const fn = node.childForFieldName('function');
      if (fn) nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, fn.text));
      break;
    }
    case 'go_statement': {
      nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, 'go ' + (node.namedChildren[0]?.text || '')));
      for (const child of node.namedChildren) visitGo(child, lang, nodes);
      return;
    }
    case 'defer_statement': {
      nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, 'defer ' + (node.namedChildren[0]?.text?.split('(')[0] || '')));
      break;
    }
    case 'return_statement':
      nodes.push(ir('Return', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'if_statement':
      nodes.push(ir('IfStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitGo(child, lang, nodes);
      return;
    case 'for_statement':
      nodes.push(ir('ForStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitGo(child, lang, nodes);
      return;
    case 'switch_statement':
    case 'type_switch_statement':
      nodes.push(ir('SwitchStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitGo(child, lang, nodes);
      return;
    case 'short_var_declaration':
    case 'var_declaration':
    case 'var_spec': {
      const name = node.namedChildren[0]?.text || '';
      if (name) nodes.push(ir('VariableDecl', node.startPosition.row + 1, node.startPosition.column, lang, name));
      break;
    }
    case 'assignment_statement': {
      const left = node.childForFieldName('left') || node.namedChildren[0];
      if (left) nodes.push(ir('Assign', node.startPosition.row + 1, node.startPosition.column, lang, left.text));
      break;
    }
  }
  for (const child of node.namedChildren) visitGo(child, lang, nodes);
}

// =========================================================================
// Rust visitor
// =========================================================================

function visitRust(node: SyntaxNode, lang: string, nodes: IRNode[]): void {
  switch (node.type) {
    case 'use_declaration': {
      nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    }
    case 'mod_item': {
      const name = fieldText(node, 'name');
      nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, 'mod ' + name));
      break;
    }
    case 'struct_item':
    case 'enum_item':
    case 'trait_item':
    case 'impl_item': {
      const name = fieldText(node, 'name') || fieldText(node, 'type');
      const declType = node.type.replace('_item', '');
      nodes.push(ir('ClassDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], { declType }));
      for (const child of node.namedChildren) visitRust(child, lang, nodes);
      return;
    }
    case 'function_item': {
      const name = fieldText(node, 'name');
      const params = extractParams(node);
      const isAsync = node.children.some(c => c.text === 'async');
      const isUnsafe = node.children.some(c => c.text === 'unsafe');
      const isPub = node.children.some(c => c.type === 'visibility_modifier');
      nodes.push(ir('FunctionDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
        params, async: isAsync, unsafe: isUnsafe, pub: isPub,
        isEntry: name === 'main',
      }));
      for (const child of node.namedChildren) visitRust(child, lang, nodes);
      return;
    }
    case 'call_expression': {
      const fn = node.childForFieldName('function');
      if (fn) nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, fn.text));
      break;
    }
    case 'macro_invocation': {
      const macro = node.childForFieldName('macro') || node.namedChildren[0];
      if (macro) nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, macro.text + '!'));
      break;
    }
    case 'let_declaration': {
      const pat = node.childForFieldName('pattern');
      if (pat) nodes.push(ir('VariableDecl', node.startPosition.row + 1, node.startPosition.column, lang, pat.text));
      break;
    }
    case 'return_expression':
      nodes.push(ir('Return', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'if_expression':
      nodes.push(ir('IfStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitRust(child, lang, nodes);
      return;
    case 'for_expression':
      nodes.push(ir('ForStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitRust(child, lang, nodes);
      return;
    case 'while_expression':
    case 'loop_expression':
      nodes.push(ir('WhileStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitRust(child, lang, nodes);
      return;
    case 'match_expression':
      nodes.push(ir('SwitchStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitRust(child, lang, nodes);
      return;
    case 'await_expression':
      nodes.push(ir('AwaitExpr', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
  }
  for (const child of node.namedChildren) visitRust(child, lang, nodes);
}

// =========================================================================
// C / C++ visitor
// =========================================================================

function visitC(node: SyntaxNode, lang: string, nodes: IRNode[]): void {
  switch (node.type) {
    case 'preproc_include':
    case 'preproc_import': {
      const path = node.childForFieldName('path');
      nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, path?.text || node.text));
      break;
    }
    case 'using_declaration':
    case 'namespace_definition': {
      const name = fieldText(node, 'name') || node.text;
      nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, name));
      break;
    }
    case 'struct_specifier':
    case 'union_specifier':
    case 'enum_specifier':
    case 'class_specifier': {
      const name = fieldText(node, 'name');
      if (name) nodes.push(ir('ClassDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
        declType: node.type.replace('_specifier', ''),
      }));
      for (const child of node.namedChildren) visitC(child, lang, nodes);
      return;
    }
    case 'function_definition':
    case 'function_declarator':
    case 'declaration': {
      if (node.type === 'declaration') {
        const declarator = node.childForFieldName('declarator');
        if (declarator?.type === 'function_declarator') {
          const name = declarator.childForFieldName('declarator')?.text || '';
          const params = declarator.childForFieldName('parameters');
          const paramNames = params?.namedChildren.map(p => {
            const d = p.childForFieldName('declarator');
            return d?.text || p.text;
          }).filter(Boolean) || [];
          nodes.push(ir('FunctionDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], { params: paramNames }));
        }
        break;
      }
      if (node.type === 'function_definition') {
        const declarator = node.childForFieldName('declarator');
        let name = '';
        let paramNames: string[] = [];
        if (declarator?.type === 'function_declarator') {
          name = declarator.childForFieldName('declarator')?.text || '';
          const params = declarator.childForFieldName('parameters');
          paramNames = params?.namedChildren.map(p => {
            const d = p.childForFieldName('declarator');
            return d?.text || p.text;
          }).filter(Boolean) || [];
        }
        nodes.push(ir('FunctionDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
          params: paramNames, isEntry: name === 'main',
        }));
        for (const child of node.namedChildren) visitC(child, lang, nodes);
        return;
      }
      break;
    }
    case 'call_expression': {
      const fn = node.childForFieldName('function');
      if (fn) nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, fn.text));
      break;
    }
    case 'return_statement':
      nodes.push(ir('Return', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'if_statement':
      nodes.push(ir('IfStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitC(child, lang, nodes);
      return;
    case 'for_statement':
      nodes.push(ir('ForStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitC(child, lang, nodes);
      return;
    case 'while_statement':
      nodes.push(ir('WhileStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitC(child, lang, nodes);
      return;
    case 'do_statement':
      nodes.push(ir('DoWhileStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitC(child, lang, nodes);
      return;
    case 'switch_statement':
      nodes.push(ir('SwitchStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitC(child, lang, nodes);
      return;
    case 'try_statement':
      nodes.push(ir('TryStmt', node.startPosition.row + 1, node.startPosition.column, lang, 'try'));
      for (const child of node.namedChildren) visitC(child, lang, nodes);
      return;
    case 'throw_statement':
      nodes.push(ir('ThrowStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
  }
  for (const child of node.namedChildren) visitC(child, lang, nodes);
}

// =========================================================================
// PHP visitor
// =========================================================================

function visitPHP(node: SyntaxNode, lang: string, nodes: IRNode[]): void {
  switch (node.type) {
    case 'namespace_definition':
    case 'namespace_use_declaration': {
      nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    }
    case 'class_declaration':
    case 'interface_declaration':
    case 'trait_declaration': {
      const name = fieldText(node, 'name');
      nodes.push(ir('ClassDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
        declType: node.type.replace('_declaration', ''),
      }));
      for (const child of node.namedChildren) visitPHP(child, lang, nodes);
      return;
    }
    case 'method_declaration':
    case 'function_definition': {
      const name = fieldText(node, 'name');
      const params = extractParams(node);
      nodes.push(ir('FunctionDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], { params }));
      for (const child of node.namedChildren) visitPHP(child, lang, nodes);
      return;
    }
    case 'function_call_expression':
    case 'member_call_expression':
    case 'scoped_call_expression': {
      const fn = node.childForFieldName('function') || node.childForFieldName('name');
      if (fn) nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, fn.text));
      break;
    }
    case 'return_statement':
      nodes.push(ir('Return', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'if_statement':
      nodes.push(ir('IfStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitPHP(child, lang, nodes);
      return;
    case 'for_statement':
    case 'foreach_statement':
      nodes.push(ir('ForStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitPHP(child, lang, nodes);
      return;
    case 'while_statement':
    case 'do_statement':
      nodes.push(ir(node.type === 'do_statement' ? 'DoWhileStmt' : 'WhileStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitPHP(child, lang, nodes);
      return;
    case 'try_statement':
      nodes.push(ir('TryStmt', node.startPosition.row + 1, node.startPosition.column, lang, 'try'));
      for (const child of node.namedChildren) visitPHP(child, lang, nodes);
      return;
    case 'throw_expression':
      nodes.push(ir('ThrowStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'switch_statement':
      nodes.push(ir('SwitchStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitPHP(child, lang, nodes);
      return;
  }
  for (const child of node.namedChildren) visitPHP(child, lang, nodes);
}

// =========================================================================
// Ruby visitor
// =========================================================================

function visitRuby(node: SyntaxNode, lang: string, nodes: IRNode[]): void {
  switch (node.type) {
    case 'call': {
      const method = node.childForFieldName('method');
      const methodName = method?.text || '';
      if (['require', 'require_relative', 'include', 'load', 'gem'].includes(methodName)) {
        const args = node.childForFieldName('arguments');
        const arg = args?.namedChildren[0];
        nodes.push(ir('Import', node.startPosition.row + 1, node.startPosition.column, lang, arg?.text?.replace(/['"]/g, '') || methodName));
        break;
      }
      nodes.push(ir('CallExpr', node.startPosition.row + 1, node.startPosition.column, lang, methodName));
      break;
    }
    case 'module': {
      const name = fieldText(node, 'name') || node.namedChildren[0]?.text || '';
      nodes.push(ir('ClassDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], { declType: 'module' }));
      for (const child of node.namedChildren) visitRuby(child, lang, nodes);
      return;
    }
    case 'class': {
      const name = fieldText(node, 'name') || node.namedChildren[0]?.text || '';
      const superclass = node.childForFieldName('superclass');
      nodes.push(ir('ClassDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
        bases: superclass ? [superclass.text] : [],
      }));
      for (const child of node.namedChildren) visitRuby(child, lang, nodes);
      return;
    }
    case 'method':
    case 'singleton_method': {
      const name = fieldText(node, 'name') || node.namedChildren[0]?.text || '';
      const params = extractParams(node);
      nodes.push(ir('FunctionDef', node.startPosition.row + 1, node.startPosition.column, lang, name, undefined, [], {
        params, isSingleton: node.type === 'singleton_method',
      }));
      for (const child of node.namedChildren) visitRuby(child, lang, nodes);
      return;
    }
    case 'return':
      nodes.push(ir('Return', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'yield':
      nodes.push(ir('YieldExpr', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'if':
    case 'unless':
      nodes.push(ir('IfStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitRuby(child, lang, nodes);
      return;
    case 'for':
      nodes.push(ir('ForStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitRuby(child, lang, nodes);
      return;
    case 'while':
    case 'until':
      nodes.push(ir('WhileStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitRuby(child, lang, nodes);
      return;
    case 'begin':
      nodes.push(ir('TryStmt', node.startPosition.row + 1, node.startPosition.column, lang, 'begin'));
      for (const child of node.namedChildren) visitRuby(child, lang, nodes);
      return;
    case 'raise':
      nodes.push(ir('ThrowStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text));
      break;
    case 'case':
      nodes.push(ir('SwitchStmt', node.startPosition.row + 1, node.startPosition.column, lang, node.text.split('\n')[0]));
      for (const child of node.namedChildren) visitRuby(child, lang, nodes);
      return;
    case 'assignment': {
      const left = node.childForFieldName('left');
      if (left) nodes.push(ir('Assign', node.startPosition.row + 1, node.startPosition.column, lang, left.text));
      break;
    }
  }
  for (const child of node.namedChildren) visitRuby(child, lang, nodes);
}

// =========================================================================
// Visitor dispatch
// =========================================================================

const VISITORS: Record<string, (node: SyntaxNode, lang: string, nodes: IRNode[]) => void> = {
  python: visitPython,
  java: visitBraceLang,
  csharp: visitBraceLang,
  kotlin: visitBraceLang,
  go: visitGo,
  rust: visitRust,
  c: visitC,
  cpp: visitC,
  php: visitPHP,
  ruby: visitRuby,
};

export function isTreeSitterSupported(lang: string): boolean {
  return lang in LANG_TO_WASM;
}

export async function parseWithTreeSitter(sourceCode: string, language: string): Promise<IRNode[] | null> {
  if (!LANG_TO_WASM[language]) return null;

  const parser = await getParser(language);
  if (!parser) return null;

  try {
    const tree = parser.parse(sourceCode);
    const visitor = VISITORS[language];
    if (!visitor) return null;

    const nodes: IRNode[] = [];
    visitor(tree.rootNode, language, nodes);
    return nodes;
  } catch (err) {
    logger.warn({ err, language }, 'Tree-sitter parse failed');
    return null;
  }
}
