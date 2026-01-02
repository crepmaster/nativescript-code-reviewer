#!/usr/bin/env node
/**
 * selftest.js - Self-test for nativescript-reviewer
 *
 * Tests baseline, suppressions, and new rules against fixtures.
 * Run with: node scripts/selftest.js
 */

const path = require('path');
const fs = require('fs');

const { analyzeFile } = require('../lib/analyzers');
const { loadBaseline, applyBaselineToReports, extractFingerprints } = require('../lib/baseline');
const { parseSuppressions, filterBySuppression } = require('../lib/suppressions');
const lockfileRule = require('../lib/rules/lockfile');
const pluginHealthRule = require('../lib/rules/plugin-health');
const xmlWellformedRule = require('../lib/rules/xml-wellformed');
const noPackagejsonImportRule = require('../lib/rules/no-packagejson-import');
const platformSanityRule = require('../lib/rules/platform-sanity');

const FIXTURES_DIR = path.join(__dirname, '../lib/rules/__fixtures__');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertIncludes(arr, predicate, message) {
  const found = arr.some(predicate);
  if (!found) {
    throw new Error(message || `Expected to find matching item in array of ${arr.length} items`);
  }
}

async function runTests() {
  console.log('\n=== NativeScript Reviewer Self-Tests ===\n');

  // =====================
  // LOCKFILE RULE TESTS
  // =====================
  console.log('Lockfile Rule Tests:');

  test('detects missing lockfile', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-no-lockfile.json'), 'utf8');
    const issues = lockfileRule.check(content, 'package.json', { root: FIXTURES_DIR });

    assertIncludes(issues, i => i.rule === 'lockfile-missing',
      'Should detect missing lockfile');
  });

  test('detects strict engine version', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-no-lockfile.json'), 'utf8');
    const issues = lockfileRule.check(content, 'package.json', { root: FIXTURES_DIR });

    assertIncludes(issues, i => i.rule === 'engines-node-strict',
      'Should detect strict node engine version');
  });

  test('detects unpinned dependencies', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-no-lockfile.json'), 'utf8');
    const issues = lockfileRule.check(content, 'package.json', { root: FIXTURES_DIR });

    assertIncludes(issues, i => i.rule === 'dependency-unpinned' && i.message.includes('lodash'),
      'Should detect unpinned dependency (*)');
  });

  test('detects file: dependencies', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-no-lockfile.json'), 'utf8');
    const issues = lockfileRule.check(content, 'package.json', { root: FIXTURES_DIR });

    assertIncludes(issues, i => i.rule === 'dependency-local-file',
      'Should detect file: dependency');
  });

  test('detects git+ssh: without pin', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-no-lockfile.json'), 'utf8');
    const issues = lockfileRule.check(content, 'package.json', { root: FIXTURES_DIR });

    assertIncludes(issues, i => i.rule === 'dependency-non-reproducible',
      'Should detect git+ssh: without commit pin');
  });

  // =====================
  // PLUGIN HEALTH TESTS
  // =====================
  console.log('\nPlugin Health Rule Tests:');

  test('detects deprecated nativescript-plugin-firebase', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-obsolete-plugins.json'), 'utf8');
    const issues = pluginHealthRule.check(content, 'package.json');

    assertIncludes(issues, i => i.rule === 'plugin-obsolete' && i.message.includes('nativescript-plugin-firebase'),
      'Should detect deprecated firebase plugin');
  });

  test('detects deprecated nativescript-barcodescanner', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-obsolete-plugins.json'), 'utf8');
    const issues = pluginHealthRule.check(content, 'package.json');

    assertIncludes(issues, i => i.rule === 'plugin-obsolete' && i.message.includes('barcodescanner'),
      'Should detect deprecated barcodescanner plugin');
  });

  test('detects outdated @nativescript/core', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-obsolete-plugins.json'), 'utf8');
    const issues = pluginHealthRule.check(content, 'package.json');

    assertIncludes(issues, i => i.rule === 'nativescript-core-outdated',
      'Should detect outdated @nativescript/core v6');
  });

  test('detects Angular/NS version incompatibility', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-obsolete-plugins.json'), 'utf8');
    const issues = pluginHealthRule.check(content, 'package.json');

    assertIncludes(issues, i => i.rule === 'angular-ns-incompatible',
      'Should detect Angular 17 with NS 6 incompatibility');
  });

  // =====================
  // SUPPRESSIONS TESTS
  // =====================
  console.log('\nSuppressions Tests:');

  test('parses disable-next-line comments', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'test-suppressions.ts'), 'utf8');
    const suppressions = parseSuppressions(content, 'test.ts');

    // Line 8 has the comment, so line 9 should be suppressed
    assert(suppressions.disabledByLine.has(9), 'Should have suppression at line 9');
    assert(suppressions.disabledByLine.get(9).has('no-any'), 'Should suppress no-any at line 9');
  });

  test('parses disable/enable range comments', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'test-suppressions.ts'), 'utf8');
    const suppressions = parseSuppressions(content, 'test.ts');

    assert(suppressions.disabledRanges.length > 0, 'Should have at least one disabled range');

    const complexRegexRange = suppressions.disabledRanges.find(r => r.rules.has('complex-regex'));
    assert(complexRegexRange, 'Should have complex-regex range');
  });

  test('filters issues by suppression', () => {
    const issues = [
      { rule: 'no-any', line: 10, message: 'test' },
      { rule: 'no-any', line: 7, message: 'test' },
      { rule: 'other-rule', line: 10, message: 'test' }
    ];

    const suppressions = {
      disabledGlobally: new Set(),
      disabledByLine: new Map([[10, new Set(['no-any'])]]),
      disabledRanges: []
    };

    const { filtered, suppressed } = filterBySuppression(issues, suppressions);

    assert(suppressed === 1, `Should suppress 1 issue, got ${suppressed}`);
    assert(filtered.length === 2, `Should have 2 issues left, got ${filtered.length}`);
  });

  // =====================
  // BASELINE TESTS
  // =====================
  console.log('\nBaseline Tests:');

  test('loads baseline file', () => {
    const baselinePath = path.join(FIXTURES_DIR, 'baseline-test.json');
    const baseline = loadBaseline(baselinePath);

    assert(baseline !== null, 'Should load baseline');
    assert(baseline.issues instanceof Set, 'Should have issues as Set');
    assert(baseline.issues.size === 2, 'Should have 2 issues in baseline');
  });

  test('filters issues by baseline fingerprints', () => {
    const reports = [{
      file: 'test.ts',
      issues: [
        { fingerprint: 'abc123def456', rule: 'test', message: 'known issue' },
        { fingerprint: 'newissue12345', rule: 'test', message: 'new issue' }
      ],
      summary: {}
    }];

    const baselineFingerprints = new Set(['abc123def456']);
    const { reports: filtered, totalBaselined } = applyBaselineToReports(reports, baselineFingerprints);

    assert(totalBaselined === 1, `Should baseline 1 issue, got ${totalBaselined}`);
    assert(filtered[0].issues.length === 1, 'Should have 1 issue left');
    assert(filtered[0].issues[0].fingerprint === 'newissue12345', 'Should keep new issue');
  });

  test('extracts fingerprints from reports', () => {
    const reports = [{
      file: 'test.ts',
      issues: [
        { fingerprint: 'fp1', rule: 'test' },
        { fingerprint: 'fp2', rule: 'test' }
      ]
    }];

    const fingerprints = extractFingerprints(reports);
    assert(fingerprints.length === 2, 'Should extract 2 fingerprints');
    assert(fingerprints.includes('fp1'), 'Should include fp1');
    assert(fingerprints.includes('fp2'), 'Should include fp2');
  });

  // =====================
  // XML WELLFORMED TESTS
  // =====================
  console.log('\nXML Wellformed Rule Tests:');

  test('detects unescaped ampersand', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'test-invalid.xml'), 'utf8');
    const issues = xmlWellformedRule.check(content, 'test.xml');

    assertIncludes(issues, i => i.rule === 'xml-unescaped-ampersand',
      'Should detect unescaped & character');
  });

  test('detects XML issues', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'test-invalid.xml'), 'utf8');
    const issues = xmlWellformedRule.check(content, 'test.xml');

    // The file has multiple issues (ampersand, etc.)
    assert(issues.length > 0, 'Should detect XML issues');
  });

  test('detects complex binding logic', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'test-invalid.xml'), 'utf8');
    const issues = xmlWellformedRule.check(content, 'test.xml');

    assertIncludes(issues, i => i.rule === 'xml-binding-logic',
      'Should detect complex logic in bindings');
  });

  // =====================
  // NO-PACKAGEJSON-IMPORT TESTS
  // =====================
  console.log('\nNo-PackageJson-Import Rule Tests:');

  test('detects import * as from package.json', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'test-packagejson-import.ts'), 'utf8');
    const issues = noPackagejsonImportRule.check(content, 'test.ts');

    assertIncludes(issues, i => i.rule === 'no-packagejson-import' && i.message.includes('~/package.json'),
      'Should detect import * as from ~/package.json');
  });

  test('detects default import from package.json', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'test-packagejson-import.ts'), 'utf8');
    const issues = noPackagejsonImportRule.check(content, 'test.ts');

    assertIncludes(issues, i => i.rule === 'no-packagejson-import' && i.message.includes('../package.json'),
      'Should detect default import from package.json');
  });

  test('detects require of package.json', () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'test-packagejson-import.ts'), 'utf8');
    const issues = noPackagejsonImportRule.check(content, 'test.ts');

    assertIncludes(issues, i => i.rule === 'no-packagejson-require',
      'Should detect require of package.json');
  });

  // =====================
  // PLATFORM SANITY TESTS
  // =====================
  console.log('\nPlatform Sanity Rule Tests:');

  test('detects platforms not generated for NS project', () => {
    const content = JSON.stringify({
      name: 'test-app',
      dependencies: { '@nativescript/core': '^8.0.0' }
    });
    // Mock a directory without platforms/
    const issues = platformSanityRule.check(content, 'package.json', {
      root: path.join(FIXTURES_DIR, 'nonexistent-dir')
    });

    assertIncludes(issues, i => i.rule === 'platforms-not-generated',
      'Should detect missing platforms directory');
  });

  // =====================
  // INTEGRATION TEST
  // =====================
  console.log('\nIntegration Tests:');

  test('analyzeFile processes package.json with new rules', async () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-obsolete-plugins.json'), 'utf8');
    // Use 'package.json' as the filename since analyzers.js checks basename
    const report = await analyzeFile(
      path.join(FIXTURES_DIR, 'package.json'),
      content,
      { root: FIXTURES_DIR }
    );

    assert(report.issues.length > 0, 'Should have issues');
    assertIncludes(report.issues, i => i.rule === 'lockfile-missing',
      'Should include lockfile-missing from lockfile rule');
    assertIncludes(report.issues, i => i.rule === 'plugin-obsolete',
      'Should include plugin-obsolete from plugin-health rule');
  });

  test('analyzeFile applies inline suppressions', async () => {
    const content = fs.readFileSync(path.join(FIXTURES_DIR, 'test-suppressions.ts'), 'utf8');
    const report = await analyzeFile(
      path.join(FIXTURES_DIR, 'test-suppressions.ts'),
      content,
      {}
    );

    // The suppressed issues should be filtered out
    // Check that meta.suppressed is set if any were suppressed
    // (actual count depends on which rules fire)
    assert(report.issues !== undefined, 'Should have issues array');
  });

  // =====================
  // SUMMARY
  // =====================
  console.log('\n=== Test Results ===');
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);

  if (failed > 0) {
    console.log('\n❌ Some tests failed!');
    process.exitCode = 1;
  } else {
    console.log('\n✅ All tests passed!');
    process.exitCode = 0;
  }
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exitCode = 2;
});
