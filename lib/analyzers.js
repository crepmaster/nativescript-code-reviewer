// analyzers.js
const path = require('path');
const crypto = require('crypto');
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
const android16kbRule = require('./rules/android-16kb');
const tsconfigRule = require('./rules/tsconfig');
const importsInteropRule = require('./rules/imports-interop');
const lockfileRule = require('./rules/lockfile');
const pluginHealthRule = require('./rules/plugin-health');
const xmlWellformedRule = require('./rules/xml-wellformed');
const platformSanityRule = require('./rules/platform-sanity');
const noPackagejsonImportRule = require('./rules/no-packagejson-import');
const noTopLevelRuntimeInitRule = require('./rules/no-top-level-runtime-initialization');
const noTopLevelFirebaseImportRule = require('./rules/no-top-level-firebase-import');
const { parseSuppressions, filterBySuppression } = require('./suppressions');

// -----------------------------
// Normalisation / Fingerprint
// -----------------------------
const SEVERITY_ORDER = ['info', 'warn', 'high', 'error'];

function normalizeSeverity(sev) {
  if (!sev) return 'info';
  const s = String(sev).toLowerCase();
  if (s === 'critical') return 'high';
  if (s === 'warning') return 'warn';
  if (s === 'err') return 'error';
  if (!SEVERITY_ORDER.includes(s)) return 'info';
  return s;
}

function makeFingerprint(issue, filePath) {
  const rule = issue.rule || issue.ruleId || 'unknown-rule';
  const line = issue.line || issue.lineno || 0;
  const col = issue.column || issue.col || 0;
  const msg = issue.message || '';
  const raw = `${rule}::${filePath}::${line}::${col}::${msg}`;
  return crypto.createHash('sha1').update(raw).digest('hex');
}

function normalizeIssue(issue, filePath) {
  const out = { ...issue };

  out.severity = normalizeSeverity(out.severity);
  out.rule = out.rule || out.ruleId || 'unknown-rule';
  out.message = out.message || 'No message provided';
  out.file = out.file || filePath;

  // Normalise location fields
  if (out.line == null && out.lineno != null) out.line = out.lineno;
  if (out.column == null && out.col != null) out.column = out.col;

  out.fingerprint = out.fingerprint || makeFingerprint(out, filePath);

  return out;
}

function dedupeIssues(issues) {
  const seen = new Set();
  const out = [];
  for (const it of issues) {
    const fp = it.fingerprint || makeFingerprint(it, it.file || '');
    if (seen.has(fp)) continue;
    seen.add(fp);
    out.push(it);
  }
  return out;
}

// -----------------------------
// TypeScript ESLint
// -----------------------------
async function runTypeScriptESLint(filePath, content) {
  if (!tsEslintAnalyzer || !tsEslintAnalyzer.hasESLint()) return [];
  try {
    return await tsEslintAnalyzer.analyzeFile(filePath, content);
  } catch (e) {
    console.error('TypeScript ESLint error:', e.message);
    return [];
  }
}

// -----------------------------
// TypeScript diagnostics (opt-in)
// -----------------------------
function tsDiagnosticsForContent(filePath, content, opts) {
  if (!ts) return null;
  if (!opts?.enableTsc) return null; // OPT-IN

  try {
    const options = {
      allowJs: true,
      checkJs: true,
      noEmit: true,
    };

    // Provide in-memory content so the program can actually parse this file
    const defaultHost = ts.createCompilerHost(options);
    const host = {
      ...defaultHost,
      getSourceFile: (fileName, languageVersion, onError, shouldCreateNewSourceFile) => {
        if (path.resolve(fileName) === path.resolve(filePath)) {
          return ts.createSourceFile(fileName, content, languageVersion, true);
        }
        return defaultHost.getSourceFile(fileName, languageVersion, onError, shouldCreateNewSourceFile);
      },
      readFile: (fileName) => {
        if (path.resolve(fileName) === path.resolve(filePath)) return content;
        return defaultHost.readFile(fileName);
      },
      fileExists: (fileName) => {
        if (path.resolve(fileName) === path.resolve(filePath)) return true;
        return defaultHost.fileExists(fileName);
      },
    };

    const program = ts.createProgram([filePath], options, host);
    const diags = ts.getPreEmitDiagnostics(program);

    return diags.map(d => ({
      message: ts.flattenDiagnosticMessageText(d.messageText, '\n'),
      code: d.code,
      line: d.file && typeof d.start === 'number'
        ? d.file.getLineAndCharacterOfPosition(d.start).line + 1
        : undefined,
      column: d.file && typeof d.start === 'number'
        ? d.file.getLineAndCharacterOfPosition(d.start).character + 1
        : undefined,
    }));
  } catch (e) {
    return null;
  }
}

// -----------------------------
// Basic lightweight checks (keep minimal)
// -----------------------------
function basicTextChecks(content) {
  const issues = [];

  // Keep only "smoke" checks here; leave detailed ones to dedicated rule modules.
  // Note: Report files are already skipped at analyzeFile level.

  if (/eval\s*\(/.test(content) || /new\s+Function\s*\(/.test(content)) {
    issues.push({ severity: 'high', rule: 'no-eval', message: 'Use of eval/Function is dangerous' });
  }

  const httpUrls = content.match(/http:\/\/[^\s'"<>]+/g);
  if (httpUrls) {
    // Filter out safe URLs (localhost, schemas, etc.)
    const safePatterns = [
      'localhost',
      '127.0.0.1',
      'schemas.android.com',
      'schemas.microsoft.com',
      'schemas.nativescript.org',
      'www.w3.org',
      'example.com',
      'example.org'
    ];
    httpUrls.forEach(u => {
      const isSafe = safePatterns.some(p => u.includes(p));
      if (!isSafe) {
        issues.push({ severity: 'high', rule: 'insecure-http', message: `Insecure http URL found: ${u}` });
      }
    });
  }

  return issues;
}

async function analyzeFile(filePath, content, opts = {}) {
  const ext = path.extname(filePath).toLowerCase();
  const fileName = path.basename(filePath).toLowerCase();
  const report = { file: filePath, ext, issues: [], meta: {} };

  // ===== SKIP REPORT/OUTPUT FILES =====
  // These are generated files that contain analysis results - don't analyze them
  const isReportFile = /report\.json|\.sarif|review-report|ns-review/.test(fileName);
  if (isReportFile) {
    report.summary = {};
    return report;
  }

  // ===== GRADLE FILES =====
  if (/build\.gradle|gradle-wrapper\.properties/.test(fileName)) {
    try { report.issues.push(...gradleRule.check(content, filePath)); } catch (e) {}
    try { report.issues.push(...android16kbRule.check(content, filePath)); } catch (e) {}
    report.issues = dedupeIssues(report.issues.map(i => normalizeIssue(i, filePath)));
    report.summary = report.issues.reduce((acc, it) => (acc[it.severity] = (acc[it.severity] || 0) + 1, acc), {});
    return report;
  }

  // ===== PACKAGE.JSON =====
  if (fileName === 'package.json') {
    try { report.issues.push(...packageJsonRule.check(content, filePath)); } catch (e) {}
    try { report.issues.push(...android16kbRule.check(content, filePath)); } catch (e) {}
    try { report.issues.push(...lockfileRule.check(content, filePath, { root: opts.root })); } catch (e) {}
    try { report.issues.push(...pluginHealthRule.check(content, filePath)); } catch (e) {}
    try { report.issues.push(...platformSanityRule.check(content, filePath, { root: opts.root })); } catch (e) {}
    report.issues = dedupeIssues(report.issues.map(i => normalizeIssue(i, filePath)));
    report.summary = report.issues.reduce((acc, it) => (acc[it.severity] = (acc[it.severity] || 0) + 1, acc), {});
    return report;
  }

  // ===== TSCONFIG.JSON =====
  if (fileName === 'tsconfig.json') {
    try { report.issues.push(...tsconfigRule.check(content, filePath)); } catch (e) {}
    report.issues = dedupeIssues(report.issues.map(i => normalizeIssue(i, filePath)));
    report.summary = report.issues.reduce((acc, it) => (acc[it.severity] = (acc[it.severity] || 0) + 1, acc), {});
    return report;
  }

  // ===== ANDROIDMANIFEST.XML =====
  if (/androidmanifest\.xml|manifestxml/.test(fileName)) {
    try { report.issues.push(...androidManifestRule.check(content, filePath)); } catch (e) {}
    try { report.issues.push(...xmlWellformedRule.check(content, filePath)); } catch (e) {}
    report.issues = dedupeIssues(report.issues.map(i => normalizeIssue(i, filePath)));
    report.summary = report.issues.reduce((acc, it) => (acc[it.severity] = (acc[it.severity] || 0) + 1, acc), {});
    return report;
  }

  // ===== OTHER XML FILES (NativeScript UI) =====
  if (ext === '.xml') {
    try { report.issues.push(...xmlWellformedRule.check(content, filePath)); } catch (e) {}
    report.issues = dedupeIssues(report.issues.map(i => normalizeIssue(i, filePath)));
    report.summary = report.issues.reduce((acc, it) => (acc[it.severity] = (acc[it.severity] || 0) + 1, acc), {});
    return report;
  }

  // ===== SOURCE CODE FILES =====

  // Parse inline suppressions for source files
  const suppressions = parseSuppressions(content, filePath);

  report.issues.push(...basicTextChecks(content));

  // Run rule modules (single pass; no duplication)
  try { report.issues.push(...varsRule.check(content, filePath)); } catch (e) {}
  try { report.issues.push(...methodsRule.check(content, filePath)); } catch (e) {}
  try { report.issues.push(...importsRule.check(content, filePath)); } catch (e) {}
  try { report.issues.push(...securityRule.check(content, filePath)); } catch (e) {}
  try { report.issues.push(...nsRule.check(content, filePath)); } catch (e) {}
  try { report.issues.push(...performanceRule.check(content, filePath)); } catch (e) {}
  try { report.issues.push(...codeQualityRule.check(content, filePath)); } catch (e) {}
  try { report.issues.push(...importsInteropRule.check(content, filePath)); } catch (e) {}
  try { report.issues.push(...noPackagejsonImportRule.check(content, filePath)); } catch (e) {}
  try { report.issues.push(...noTopLevelRuntimeInitRule.analyze(filePath, content)); } catch (e) {}
  try { report.issues.push(...noTopLevelFirebaseImportRule.analyze(filePath, content)); } catch (e) {}

  // TypeScript-aware ESLint for .ts/.tsx (preferred)
  const isTypeScript = ['.ts', '.tsx'].includes(ext);
  if (isTypeScript && tsEslintAnalyzer && tsEslintAnalyzer.hasESLint()) {
    const tsEslintIssues = await runTypeScriptESLint(filePath, content);
    if (tsEslintIssues.length > 0) {
      report.meta.tsEslint = tsEslintIssues;
      report.issues.push(...tsEslintIssues);
    }
  }

  // Optional TypeScript diagnostics (opt-in via --tsc flag)
  const tsdiags = tsDiagnosticsForContent(filePath, content, opts);
  if (tsdiags) {
    report.meta.tsc = tsdiags;
    tsdiags.forEach(d => report.issues.push({
      severity: 'error',
      rule: 'tsc',
      message: d.message,
      code: d.code,
      line: d.line,
      column: d.column,
    }));
  }

  // Normalize + dedupe
  report.issues = dedupeIssues(report.issues.map(i => normalizeIssue(i, filePath)));

  // Apply inline suppressions
  const { filtered, suppressed } = filterBySuppression(report.issues, suppressions);
  report.issues = filtered;
  if (suppressed > 0) {
    report.meta.suppressed = suppressed;
  }

  // Summary
  report.summary = report.issues.reduce((acc, it) => (acc[it.severity] = (acc[it.severity] || 0) + 1, acc), {});

  return report;
}

module.exports = { analyzeFile, normalizeSeverity, SEVERITY_ORDER };
