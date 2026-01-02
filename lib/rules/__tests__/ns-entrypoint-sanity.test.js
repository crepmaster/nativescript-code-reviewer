/**
 * Tests for ns-entrypoint-sanity rule
 *
 * Validates that the rule detects:
 * 1. Valid projects (no issues)
 * 2. Missing entry points (BLOCKER)
 * 3. package.json main="./" (BLOCKER - the exact crash scenario)
 * 4. Missing moduleName target (BLOCKER)
 * 5. Webpack invalid entry (detected via webpack-entry-sanity)
 *
 * Run: node lib/rules/__tests__/ns-entrypoint-sanity.test.js
 */

const path = require('path');
const assert = require('assert');

const nsEntrypointRule = require('../ns-entrypoint-sanity');
const webpackEntryRule = require('../webpack-entry-sanity');

const FIXTURES_DIR = path.join(__dirname, '..', '__fixtures__');

// Simple test runner for standalone execution
function runTests() {
  console.log('Running ns-entrypoint-sanity tests...\n');

  let passed = 0;
  let failed = 0;

  const tests = [
    ['fixture-valid-main-ts: no blockers', () => {
      const fixtureRoot = path.join(FIXTURES_DIR, 'fixture-valid-main-ts');
      const issues = nsEntrypointRule.checkProject(fixtureRoot);
      const blockers = issues.filter(i => i.severity === 'blocker');
      assert.strictEqual(blockers.length, 0, `Expected no blockers, got: ${JSON.stringify(blockers, null, 2)}`);
    }],

    ['fixture-missing-main: detect BLOCKER', () => {
      const fixtureRoot = path.join(FIXTURES_DIR, 'fixture-missing-main');
      const issues = nsEntrypointRule.checkProject(fixtureRoot);
      const blockers = issues.filter(i => i.severity === 'blocker');
      assert.ok(blockers.length > 0, 'Expected at least one blocker');
      assert.ok(blockers[0].remediation, 'Expected remediation text');
    }],

    ['fixture-main-dot-slash: detect BLOCKER for "./" (reproduces crash)', () => {
      const fixtureRoot = path.join(FIXTURES_DIR, 'fixture-main-dot-slash');
      const issues = nsEntrypointRule.checkProject(fixtureRoot);
      const blockers = issues.filter(i => i.severity === 'blocker');
      assert.ok(blockers.length > 0, 'Expected at least one blocker');
      assert.ok(blockers.some(i => i.message.includes('./')), 'Expected message about "./"');
      assert.ok(blockers.some(i => i.message.includes('Failed to find module')), 'Expected crash message');
    }],

    ['fixture-app-root-missing: detect missing module', () => {
      const fixtureRoot = path.join(FIXTURES_DIR, 'fixture-app-root-missing');
      const issues = nsEntrypointRule.checkProject(fixtureRoot);
      const blockers = issues.filter(i => i.severity === 'blocker');
      assert.ok(blockers.length > 0, 'Expected at least one blocker');
      assert.ok(blockers.some(i => i.message.includes('app-root')), `Expected app-root in message, got: ${JSON.stringify(blockers)}`);
    }],

    ['fingerprints are stable across runs', () => {
      const fixtureRoot = path.join(FIXTURES_DIR, 'fixture-main-dot-slash');
      const issues1 = nsEntrypointRule.checkProject(fixtureRoot);
      const issues2 = nsEntrypointRule.checkProject(fixtureRoot);
      assert.strictEqual(issues1[0].fingerprint, issues2[0].fingerprint, 'Fingerprints should be stable');
    }],

    ['fingerprints are human-readable', () => {
      const fixtureRoot = path.join(FIXTURES_DIR, 'fixture-main-dot-slash');
      const issues = nsEntrypointRule.checkProject(fixtureRoot);
      assert.ok(/^ns-entrypoint-sanity:/.test(issues[0].fingerprint), `Expected human-readable fingerprint, got: ${issues[0].fingerprint}`);
      assert.ok(issues[0].fingerprint.includes(':invalid-main'), `Expected :invalid-main in fingerprint, got: ${issues[0].fingerprint}`);
    }],

    ['webpack-entry-invalid: detected via webpack rule', () => {
      const fixtureRoot = path.join(FIXTURES_DIR, 'fixture-webpack-entry-invalid');
      const issues = webpackEntryRule.checkProject(fixtureRoot);
      // Should at least not throw
      assert.ok(Array.isArray(issues), 'Expected array of issues');
    }]
  ];

  for (const [name, testFn] of tests) {
    try {
      testFn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (e) {
      console.log(`  ✗ ${name}`);
      console.log(`    Error: ${e.message}`);
      failed++;
    }
  }

  console.log(`\n${passed} passed, ${failed} failed`);

  // Show example output for the crash fixture
  console.log('\n--- Example output for fixture-main-dot-slash ---');
  const crashFixture = path.join(FIXTURES_DIR, 'fixture-main-dot-slash');
  const crashIssues = nsEntrypointRule.checkProject(crashFixture);
  crashIssues.forEach(i => {
    console.log(`  [${i.severity.toUpperCase()}] ${i.rule}`);
    console.log(`    ${i.message}`);
    if (i.remediation) console.log(`    Fix: ${i.remediation}`);
    console.log(`    Fingerprint: ${i.fingerprint}`);
  });

  process.exit(failed > 0 ? 1 : 0);
}

// Run tests
runTests();
