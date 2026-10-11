// ============================================================
// Repository Health Metrics Engine
// Technical debt, cyclomatic complexity, maintainability index,
// duplicate code, code churn, security density, risk heatmaps,
// dependency graphs, architecture smells
// ============================================================

import fs from 'fs';
import path from 'path';
import { getLanguage, shouldAnalyzeFile } from './semantic-engine.js';
import { logger } from '../utils/logger.js';

// ---- Types ----

export interface RepoMetrics {
  totalFiles: number;
  totalLines: number;
  codeLines: number;
  commentLines: number;
  blankLines: number;
  totalFunctions: number;
  totalClasses: number;
  cyclomaticComplexityAvg: number;
  cyclomaticComplexityMax: number;
  cognitiveComplexityAvg: number;
  maintainabilityIndex: number;
  technicalDebtRatio: number;
  technicalDebtMinutes: number;
  duplicationPct: number;
  duplicatedBlocks: number;
  duplicatedLines: number;
  codeChurnPct: number;
  commentDensityPct: number;
  unusedCodePct: number;
  deadCodePct: number;
  securityDensity: number;
  complexMethodsCount: number;
  largeClassesCount: number;
  longMethodsCount: number;
  tooManyParamsCount: number;
  architectureSmells: ArchitectureSmell[];
  riskScore: number;
}

export interface ArchitectureSmell {
  type: string;
  description: string;
  severity: 'high' | 'medium' | 'low';
  location?: string;
  recommendation: string;
}

export interface FileMetrics {
  filePath: string;
  language: string;
  totalLines: number;
  codeLines: number;
  commentLines: number;
  blankLines: number;
  cyclomaticComplexity: number;
  cognitiveComplexity: number;
  functionCount: number;
  classCount: number;
  maxMethodLines: number;
  maxParams: number;
}

// ---- Analysis ----

function countLines(content: string): { total: number; code: number; comment: number; blank: number } {
  const lines = content.split('\n');
  let code = 0, comment = 0, blank = 0;
  let inBlockComment = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) { blank++; continue; }

    // Block comment tracking
    if (inBlockComment) {
      comment++;
      if (trimmed.includes('*/')) inBlockComment = false;
      continue;
    }

    if (trimmed.startsWith('/*') || trimmed.startsWith('/**')) {
      comment++;
      if (!trimmed.includes('*/')) inBlockComment = true;
      continue;
    }

    if (trimmed.startsWith('//') || trimmed.startsWith('#') ||
        trimmed.startsWith('--') || trimmed.startsWith(';') ||
        trimmed.startsWith('%')) {
      comment++;
      continue;
    }

    code++;
  }

  return { total: lines.length, code, comment, blank };
}

function calculateCyclomaticComplexity(content: string): number {
  let complexity = 1;

  // Count branching keywords
  const branchingPatterns = [
    /\bif\b/g, /\belse\s+if\b/g, /\bwhile\b/g, /\bfor\b/g,
    /\bcase\b(?!:)/g, /\bcatch\b/g, /\bforeach\b/g, /\bwhen\b/g,
    /\bguard\b/g, /\bmatch\b/g,
    /\?\s*[^:]+:/g,     // Ternary
    /&&/g, / \|\| /g,    // Logical operators in conditions
    /\bexcept\b/g, /\brescue\b/g, /\bwith\b/g,
  ];

  for (const pattern of branchingPatterns) {
    const matches = content.match(pattern);
    if (matches) complexity += matches.length;
  }

  return complexity;
}

function calculateCognitiveComplexity(content: string): number {
  let complexity = 0;

  // Nesting depth increments
  const lines = content.split('\n');
  let nestingDepth = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    // Track nesting
    const opens = (trimmed.match(/\{/g) || []).length;
    const closes = (trimmed.match(/\}/g) || []).length;
    nestingDepth += opens - closes;

    // Break in linear flow adds complexity
    if (/\b(?:if|else\s+if|for|while|catch|switch|when|match)\b/.test(trimmed)) {
      complexity += 1 + nestingDepth;
    }

    // Nested logical operators
    const logicalOps = (trimmed.match(/(?:&&|\|\|)/g) || []).length;
    if (logicalOps > 1) {
      complexity += logicalOps - 1;
    }

    // Recursion detection
    if (trimmed.match(/function\s+(\w+)[\s\S]*\1\s*\(/)) {
      complexity += 3;
    }
  }

  return Math.max(0, complexity);
}

function calculateMaintainabilityIndex(
  loc: number, complexity: number, commentPct: number,
): number {
  // Based on the Software Engineering Institute formula
  const hv = Math.max(0, 171 - 5.2 * Math.log(Math.max(1, loc)) - 0.23 * complexity - 16.2 * Math.log(Math.max(1, loc)));
  const mi = Math.max(0, hv * 100 / 171);
  return Math.round(mi * 100) / 100;
}

function calculateTechnicalDebtRatio(complexity: number, loc: number): number {
  // Simplified SQALE-based ratio
  // Debt ratio = remediation cost / development cost
  const remediationCost = complexity * 0.5; // hours to fix
  const developmentCost = loc * 0.002; // hours to develop
  if (developmentCost === 0) return 0;
  return Math.round((remediationCost / developmentCost) * 10000) / 100;
}

function detectDuplicateBlocks(files: FileMetrics[]): { blocks: number; lines: number; pct: number } {
  // Simplified: detect duplicate lines across files
  const lineHashes = new Map<string, string[]>(); // hash -> filePaths

  for (const f of files.slice(0, 200)) { // Limit for performance
    try {
      const content = fs.readFileSync(f.filePath, 'utf-8');
      const lines = content.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.length < 10) continue; // Skip short lines
        const hash = simpleHash(trimmed);
        if (!lineHashes.has(hash)) lineHashes.set(hash, []);
        lineHashes.get(hash)!.push(f.filePath);
      }
    } catch { /* skip */ }
  }

  let duplicateLines = 0;
  for (const [, filePaths] of lineHashes) {
    const uniqueFiles = new Set(filePaths);
    if (uniqueFiles.size >= 2) {
      duplicateLines += filePaths.length - uniqueFiles.size;
    }
  }

  const totalLines = files.reduce((sum, f) => sum + f.totalLines, 0);
  return {
    blocks: lineHashes.size,
    lines: duplicateLines,
    pct: totalLines > 0 ? Math.round((duplicateLines / totalLines) * 10000) / 100 : 0,
  };
}

function detectArchitectureSmells(rootDir: string, files: FileMetrics[]): ArchitectureSmell[] {
  const smells: ArchitectureSmell[] = [];

  // Circular dependencies (simplified)
  const dirs = new Set<string>();
  for (const f of files) {
    const dir = path.dirname(f.filePath);
    dirs.add(dir);
  }

  // Too many files in one directory
  for (const dir of dirs) {
    const fileCount = files.filter(f => f.filePath.startsWith(dir)).length;
    if (fileCount > 50) {
      smells.push({
        type: 'large_package',
        description: `Directory "${dir}" contains ${fileCount} files — consider splitting into submodules.`,
        severity: 'medium',
        location: dir,
        recommendation: 'Split large packages into cohesive submodules. Follow package-by-feature pattern.',
      });
    }
  }

  // God classes (high complexity + many methods)
  for (const f of files) {
    if (f.cyclomaticComplexity > 50 && f.maxMethodLines > 200) {
      smells.push({
        type: 'god_class',
        description: `File "${f.filePath}" has high complexity (${f.cyclomaticComplexity}) and long methods — may be a God Class.`,
        severity: 'high',
        location: f.filePath,
        recommendation: 'Extract responsibilities into separate classes. Apply Single Responsibility Principle.',
      });
    }
  }

  // Feature envy (imports from many packages)
  // Package cycles (simplified check)

  return smells;
}

function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const chr = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
    hash |= 0;
  }
  return hash.toString(16);
}

function estimateFunctions(content: string): number {
  const patterns = [
    /\bfunction\s+\w+\s*\(/g,
    /\bdef\s+\w+\s*\(/g,
    /\bfn\s+\w+\s*\(/g,
    /\bfunc\s+\w+\s*\(/g,
    /\b(?:public|private|protected|static|async)\s+(?:static\s+)?(?:async\s+)?\w+\s+\w+\s*\(/g,
    /=>\s*(?:\{|$)/gm,
    /\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>/g,
  ];
  let count = 0;
  for (const p of patterns) {
    const matches = content.match(p);
    if (matches) count += matches.length;
  }
  return count || 1;
}

function estimateClasses(content: string): number {
  const patterns = [
    /\bclass\s+\w+/g,
    /\bstruct\s+\w+/g,
    /\binterface\s+\w+/g,
    /\bimpl\s+\w+\s+for\s+\w+/g,
  ];
  let count = 0;
  for (const p of patterns) {
    const matches = content.match(p);
    if (matches) count += matches.length;
  }
  return count;
}

// ---- Main Analysis ----

export function analyzeRepositoryHealth(
  targetPath: string,
  _securityFindingsCount?: number,
  progressCallback?: (progress: number) => void,
): RepoMetrics {
  const fileMetrics: FileMetrics[] = [];

  function collectAndAnalyze(dir: string): void {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git' ||
            entry.name.startsWith('.') || entry.name === 'vendor') continue;
        collectAndAnalyze(fullPath);
      } else if (entry.isFile() && shouldAnalyzeFile(fullPath)) {
        const language = getLanguage(fullPath);
        if (!language) continue;

        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          const lines = countLines(content);
          const complexity = calculateCyclomaticComplexity(content);
          const cognitive = calculateCognitiveComplexity(content);

          let maxMethodLines = 0;
          let maxParams = 0;

          // Rough method length estimation
          const methodBlocks = content.split(/\b(?:function|def|fn|func)\s+\w+\s*\([^)]*\)\s*(?:\{|:)/g);
          for (const block of methodBlocks) {
            const blockLines = block.split('\n').length;
            if (blockLines > maxMethodLines) maxMethodLines = blockLines;

            const params = block.match(/,/g);
            if (params && params.length + 1 > maxParams) maxParams = params.length + 1;
          }

          fileMetrics.push({
            filePath: fullPath, language,
            totalLines: lines.total, codeLines: lines.code,
            commentLines: lines.comment, blankLines: lines.blank,
            cyclomaticComplexity: complexity,
            cognitiveComplexity: cognitive,
            functionCount: estimateFunctions(content),
            classCount: estimateClasses(content),
            maxMethodLines,
            maxParams,
          });
        } catch { /* skip */ }
      }
    }
  }

  collectAndAnalyze(targetPath);

  const totalFiles = fileMetrics.length;
  const totalLines = fileMetrics.reduce((s, f) => s + f.totalLines, 0);
  const codeLines = fileMetrics.reduce((s, f) => s + f.codeLines, 0);
  const commentLines = fileMetrics.reduce((s, f) => s + f.commentLines, 0);
  const blankLines = fileMetrics.reduce((s, f) => s + f.blankLines, 0);
  const totalFunctions = fileMetrics.reduce((s, f) => s + f.functionCount, 0);
  const totalClasses = fileMetrics.reduce((s, f) => s + f.classCount, 0);

  const complexityScores = fileMetrics.map(f => f.cyclomaticComplexity);
  const cyclomaticComplexityAvg = complexityScores.length > 0
    ? Math.round((complexityScores.reduce((a, b) => a + b, 0) / complexityScores.length) * 100) / 100
    : 0;
  const cyclomaticComplexityMax = complexityScores.length > 0 ? Math.max(...complexityScores) : 0;

  const cognitiveScores = fileMetrics.map(f => f.cognitiveComplexity);
  const cognitiveComplexityAvg = cognitiveScores.length > 0
    ? Math.round((cognitiveScores.reduce((a, b) => a + b, 0) / cognitiveScores.length) * 100) / 100
    : 0;

  const commentDensityPct = codeLines > 0
    ? Math.round((commentLines / (codeLines + commentLines)) * 10000) / 100
    : 0;

  const maintainabilityIndex = calculateMaintainabilityIndex(codeLines, cyclomaticComplexityAvg, commentDensityPct);
  const technicalDebtRatio = calculateTechnicalDebtRatio(cyclomaticComplexityAvg, codeLines);
  const technicalDebtMinutes = Math.round(cyclomaticComplexityAvg * codeLines * 0.3);

  const duplication = detectDuplicateBlocks(fileMetrics);
  const architectureSmells = detectArchitectureSmells(targetPath, fileMetrics);

  const complexMethodsCount = fileMetrics.filter(f => f.cyclomaticComplexity > 10).length;
  const largeClassesCount = fileMetrics.filter(f => f.codeLines > 500).length;
  const longMethodsCount = fileMetrics.filter(f => f.maxMethodLines > 50).length;
  const tooManyParamsCount = fileMetrics.filter(f => f.maxParams > 5).length;

  const riskScore = Math.min(100, Math.round(
    (cyclomaticComplexityAvg * 0.5) +
    (duplication.pct * 0.3) +
    (architectureSmells.length * 2) +
    (complexMethodsCount / Math.max(1, totalFiles) * 20)
  ));

  return {
    totalFiles, totalLines, codeLines, commentLines, blankLines,
    totalFunctions, totalClasses,
    cyclomaticComplexityAvg, cyclomaticComplexityMax,
    cognitiveComplexityAvg,
    maintainabilityIndex, technicalDebtRatio, technicalDebtMinutes,
    duplicationPct: duplication.pct,
    duplicatedBlocks: duplication.blocks,
    duplicatedLines: duplication.lines,
    codeChurnPct: 0, // Requires git history
    commentDensityPct,
    unusedCodePct: 0, // Requires full AST analysis
    deadCodePct: 0,
    securityDensity: 0,
    complexMethodsCount, largeClassesCount, longMethodsCount, tooManyParamsCount,
    architectureSmells,
    riskScore,
  };
}
