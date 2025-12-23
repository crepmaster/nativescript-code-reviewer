const path = require('path');
const ts = (() => { try { return require('typescript'); } catch (e) { return null; } })();

// Try to load the TypeScript ESLint analyzer
let tsEslintAnalyzer;
try {
    tsEslintAnalyzer = require('./analyzers/typescript-eslint');
} catch (e) {
    tsEslintAnalyzer = null;
}

const varsRule = require('./rules/variables');
const methodsRule = require('./rules/methods');
const importsRule = require('./rules/imports');
const securityRule = require('./rules/security');
const nsRule = require('./rules/nativescript');
const performanceRule = require('./rules/performance');
const codeQualityRule = require('./rules/code-quality');
const gradleRule = require('./rules/gradle');
const packageJsonRule = require('./rules/package-json');
const androidManifestRule = require('./rules/android-manifest');

/**
 * Run TypeScript-aware ESLint analysis
 */
async function runTypeScriptESLint(filePath, content) {
    if (!tsEslintAnalyzer || !tsEslintAnalyzer.hasESLint()) {
        return [];
    }
    try {
        return await tsEslintAnalyzer.analyzeFile(filePath, content);
    } catch (e) {
        console.error('TypeScript ESLint error:', e.message);
        return [];
    }
}

function tsDiagnosticsForContent(filePath, content, root) {
  if (!ts) return null;
  try {
    const options = { allowJs: true, checkJs: true };
    const host = ts.createCompilerHost(options);
    const fileNames = [filePath];
    const program = ts.createProgram(fileNames, options, host);
    const diags = ts.getPreEmitDiagnostics(program);
    return diags.map(d => ({ message: ts.flattenDiagnosticMessageText(d.messageText, '\n'), code: d.code }));
  } catch (e) {
    return null;
  }
}

function basicTextChecks(filePath, content) {
  const issues = [];
  if (/\bvar\b/.test(content)) issues.push({ severity: 'warn', rule: 'no-var', message: 'Avoid using var; prefer let/const' });
  if (/eval\s*\(/.test(content) || /new\s+Function\s*\(/.test(content)) issues.push({ severity: 'high', rule: 'no-eval', message: 'Use of eval/Function is dangerous' });
  if (/https?:\/\//.test(content)) {
    const httpUrls = content.match(/http:\/\/[^\s'"<>]+/g);
    if (httpUrls) httpUrls.forEach(u => issues.push({ severity: 'high', rule: 'insecure-http', message: `Insecure http URL found: ${u}` }));
  }
  const secrets = content.match(/(api_key|apiKey|secret|password|token)\s*[:=]\s*['\"]([^'\"]{4,})['\"]/gi);
  if (secrets) secrets.forEach(s => issues.push({ severity: 'high', rule: 'hardcoded-credentials', message: 'Possible hardcoded credential or token' }));
  const consoleSensitive = content.match(/console\.(log|warn|error)\([^\)]*(token|password|secret)[^\)]*\)/gi);
  if (consoleSensitive) consoleSensitive.forEach(() => issues.push({ severity: 'warn', rule: 'log-sensitive', message: 'Logging may expose sensitive data' }));
  return issues;
}

async function nativescriptChecks(filePath, content) {
  const issues = [];
  issues.push(...nsRule.check(content, filePath));
  return issues;
}

async function analyzeFile(filePath, content, opts) {
  const ext = path.extname(filePath).toLowerCase();
  const fileName = path.basename(filePath).toLowerCase();
  const report = { file: filePath, ext, issues: [], meta: {} };

  // ===== GRADLE FILES =====
  if (/build\.gradle|gradle-wrapper\.properties/.test(fileName)) {
    try { report.issues.push(...gradleRule.check(content, filePath)); } catch(e){}
    report.summary = report.issues.reduce((acc, it) => {
      acc[it.severity] = (acc[it.severity] || 0) + 1; return acc;
    }, {});
    return report;
  }

  // ===== PACKAGE.JSON =====
  if (fileName === 'package.json') {
    try { report.issues.push(...packageJsonRule.check(content, filePath)); } catch(e){}
    report.summary = report.issues.reduce((acc, it) => {
      acc[it.severity] = (acc[it.severity] || 0) + 1; return acc;
    }, {});
    return report;
  }

  // ===== ANDROIDMANIFEST.XML =====
  if (/androidmanifest\.xml|manifestxml/.test(fileName)) {
    try { report.issues.push(...androidManifestRule.check(content, filePath)); } catch(e){}
    report.summary = report.issues.reduce((acc, it) => {
      acc[it.severity] = (acc[it.severity] || 0) + 1; return acc;
    }, {});
    return report;
  }

  // ===== SOURCE CODE FILES =====
  report.issues.push(...basicTextChecks(filePath, content));

  // Run rule modules
  try { report.issues.push(...varsRule.check(content, filePath)); } catch(e){}
  try { report.issues.push(...methodsRule.check(content, filePath)); } catch(e){}
  try { report.issues.push(...importsRule.check(content, filePath)); } catch(e){}
  try { report.issues.push(...securityRule.check(content, filePath)); } catch(e){}
  try { report.issues.push(...nsRule.check(content, filePath)); } catch(e){}
  try { report.issues.push(...performanceRule.check(content, filePath)); } catch(e){}
  try { report.issues.push(...codeQualityRule.check(content, filePath)); } catch(e){}

  // Try TypeScript-aware ESLint (preferred for .ts/.tsx files)
  const isTypeScript = ['.ts', '.tsx'].includes(ext);

  if (isTypeScript && tsEslintAnalyzer && tsEslintAnalyzer.hasESLint()) {
    const tsEslintIssues = await runTypeScriptESLint(filePath, content);
    if (tsEslintIssues.length > 0) {
      report.meta.tsEslint = tsEslintIssues;
      report.issues.push(...tsEslintIssues);
    }
  }

  // Try TypeScript diagnostics when available
  const tsdiags = tsDiagnosticsForContent(filePath, content, opts.root);
  if (tsdiags) {
    report.meta.tsc = tsdiags;
    tsdiags.forEach(d => report.issues.push({ severity: 'error', rule: 'tsc', message: d.message, code: d.code }));
  }

  // NativeScript specific heuristics
  const nsIssues = await nativescriptChecks(filePath, content);
  report.issues.push(...nsIssues);

  // Categorize issues
  report.summary = report.issues.reduce((acc, it) => {
    acc[it.severity] = (acc[it.severity] || 0) + 1; return acc;
  }, {});

  return report;
}

module.exports = { analyzeFile };
