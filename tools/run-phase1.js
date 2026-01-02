#!/usr/bin/env node
/**
 * Phase 1 Runner - Boot & Entry BLOCKER Gate
 *
 * This script runs ONLY Phase 1 checks (Boot & Entry) and exits non-zero
 * if ANY Phase 1 BLOCKER is detected.
 *
 * Per the Reviewer Constitution v0.5.0:
 * - Phase 1 rules are the ONLY gating rules
 * - Phase 1 BLOCKERs are sacred and halt all other work
 *
 * Usage: node tools/run-phase1.js [project-root]
 */

const path = require('path');
const fs = require('fs');

// Phase 1 rules (frozen registry)
const nsEntrypointRule = require('../lib/rules/ns-entrypoint-sanity');
const webpackEntryRule = require('../lib/rules/webpack-entry-sanity');
const nsBootstrapRule = require('../lib/rules/ns-bootstrap-chain');
const noTopLevelFirebaseRule = require('../lib/rules/no-top-level-firebase-import');
const noTopLevelRuntimeRule = require('../lib/rules/no-top-level-runtime-initialization');

function runPhase1(projectRoot) {
  console.log('=== NativeScript Reviewer: Phase 1 (Boot & Entry) ===\n');
  console.log(`Project: ${projectRoot}\n`);

  const allIssues = [];

  // 1. Entry point sanity (package.json main field)
  console.log('[P1] Checking entry point configuration...');
  try {
    const entryIssues = nsEntrypointRule.checkProject(projectRoot);
    allIssues.push(...entryIssues.map(i => ({ ...i, phase: 'P1', checker: 'ns-entrypoint-sanity' })));
  } catch (e) {
    console.error(`  Error in ns-entrypoint-sanity: ${e.message}`);
  }

  // 2. Webpack entry sanity
  console.log('[P1] Checking webpack configuration...');
  try {
    const webpackIssues = webpackEntryRule.checkProject(projectRoot);
    allIssues.push(...webpackIssues.map(i => ({ ...i, phase: 'P1', checker: 'webpack-entry-sanity' })));
  } catch (e) {
    console.error(`  Error in webpack-entry-sanity: ${e.message}`);
  }

  // 3. Bootstrap chain validation
  console.log('[P1] Checking bootstrap chain...');
  try {
    const bootstrapIssues = nsBootstrapRule.checkProject(projectRoot);
    allIssues.push(...bootstrapIssues.map(i => ({ ...i, phase: 'P1', checker: 'ns-bootstrap-chain' })));
  } catch (e) {
    console.error(`  Error in ns-bootstrap-chain: ${e.message}`);
  }

  // 4. Scan source files for top-level import blockers
  console.log('[P1] Scanning source files for top-level import blockers...');
  const sourcePatterns = ['app/**/*.ts', 'app/**/*.js', 'src/**/*.ts', 'src/**/*.js'];
  const glob = require('glob');

  for (const pattern of sourcePatterns) {
    const files = glob.sync(pattern, { cwd: projectRoot, absolute: true, ignore: ['**/node_modules/**'] });
    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const relPath = path.relative(projectRoot, file);

        // Check for top-level Firebase imports
        const firebaseIssues = noTopLevelFirebaseRule.check(content, file);
        allIssues.push(...firebaseIssues.map(i => ({ ...i, file: relPath, phase: 'P1', checker: 'no-top-level-firebase-import' })));

        // Check for top-level runtime initialization
        const runtimeIssues = noTopLevelRuntimeRule.check(content, file);
        allIssues.push(...runtimeIssues.map(i => ({ ...i, file: relPath, phase: 'P1', checker: 'no-top-level-runtime-initialization' })));
      } catch (e) {
        // Skip unreadable files
      }
    }
  }

  // Filter to BLOCKERs only (severity: 'high' or 'blocker' or 'error' for Phase 1)
  // Per Constitution: Phase 1 rules have severity=blocker AND gating=true
  const blockers = allIssues.filter(i =>
    i.severity === 'high' || i.severity === 'blocker' || i.severity === 'error'
  );

  // Report
  console.log('\n=== Phase 1 Results ===\n');

  if (blockers.length === 0) {
    console.log('PHASE 1: PASS');
    console.log('No BLOCKER issues detected. App boot sequence is valid.\n');
    return 0;
  }

  console.log(`PHASE 1: FAIL (${blockers.length} BLOCKER(s))\n`);
  console.log('BLOCKER issues (must fix before app will run):\n');

  blockers.forEach((issue, idx) => {
    console.log(`  [${idx + 1}] ${issue.rule}`);
    console.log(`      ${issue.message}`);
    if (issue.file) console.log(`      File: ${issue.file}`);
    if (issue.line) console.log(`      Line: ${issue.line}`);
    if (issue.remediation) console.log(`      Fix: ${issue.remediation}`);
    console.log('');
  });

  // Non-blockers for context (warnings/info)
  const nonBlockers = allIssues.filter(i =>
    i.severity !== 'high' && i.severity !== 'blocker' && i.severity !== 'error'
  );

  if (nonBlockers.length > 0) {
    console.log(`Additional findings (${nonBlockers.length} non-blocking):`);
    nonBlockers.slice(0, 5).forEach(i => {
      console.log(`  - [${i.severity}] ${i.rule}: ${i.message}`);
    });
    if (nonBlockers.length > 5) {
      console.log(`  ... and ${nonBlockers.length - 5} more`);
    }
    console.log('');
  }

  return 1;
}

// Main
const projectRoot = path.resolve(process.argv[2] || process.cwd());

if (!fs.existsSync(projectRoot)) {
  console.error(`Error: Project root does not exist: ${projectRoot}`);
  process.exit(2);
}

const exitCode = runPhase1(projectRoot);
process.exit(exitCode);
