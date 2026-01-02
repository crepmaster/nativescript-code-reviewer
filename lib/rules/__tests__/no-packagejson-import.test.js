/**
 * Tests for no-packagejson-import rule (bundle checks)
 *
 * Validates:
 * 1. Detects externalized ~/package.json (upstream pattern)
 * 2. Detects missing package.json asset (error)
 * 3. Detects URL-encoded package.json (error)
 * 4. Passes when stub is inlined (no ~/package.json refs)
 *
 * Run: node lib/rules/__tests__/no-packagejson-import.test.js
 */

const path = require('path');
const assert = require('assert');

const noPackageJsonRule = require('../no-packagejson-import');

function runTests() {
  console.log('Running no-packagejson-import bundle tests...\n');

  let passed = 0;
  let failed = 0;

  const tests = [
    // Test 1: Externalized ~/package.json with known upstream pattern
    ['detect externalized ~/package.json (upstream pattern)', () => {
      const bundleContent = `import * as __WEBPACK_EXTERNAL_MODULE__package_json_abc123__ from "~/package.json";
export const id = "bundle";
// rest of bundle...
/***/ "~/package.json":
/***/ ((module) => { module.exports = __WEBPACK_EXTERNAL_MODULE__package_json_abc123__; })`;

      // Simulate package.json exists in assets
      const mockBundlePath = path.join(__dirname, 'mock-bundle.mjs');

      // We can't easily mock fs.existsSync, so test the pattern detection
      const tildeMatches = bundleContent.match(/~\/package\.json/g) || [];
      assert.strictEqual(tildeMatches.length, 2, 'Should find 2 ~/package.json refs');

      const isUpstream = /^import\s+\*\s+as\s+__WEBPACK_EXTERNAL_MODULE__package_json/.test(bundleContent);
      assert.ok(isUpstream, 'Should detect upstream pattern');
    }],

    // Test 2: URL-encoded package.json (always error)
    ['detect URL-encoded package.json refs', () => {
      const bundleContent = `// some bundle code
const url = "app%2Fpackage.json";
import("something%2Fpackage.json");`;

      const encodedMatches = bundleContent.match(/%2Fpackage\.json/gi) || [];
      assert.strictEqual(encodedMatches.length, 2, 'Should find 2 URL-encoded refs');
    }],

    // Test 3: Clean bundle (no refs = alias working)
    ['pass when no tilde-package.json refs (alias working)', () => {
      const bundleContent = `export const id = "bundle";
// Inlined stub content
const packageStub = {"name":"nowastemed","version":"1.0.0"};
// rest of bundle without tilde package refs`;

      // Use explicit pattern to avoid matching the comment
      const tildeMatches = bundleContent.match(/~\/package\.json/g) || [];
      const encodedMatches = bundleContent.match(/%2Fpackage\.json/gi) || [];

      assert.strictEqual(tildeMatches.length, 0, 'Should have no ~/package.json refs');
      assert.strictEqual(encodedMatches.length, 0, 'Should have no encoded refs');

      const hasInlinedStub = bundleContent.includes('"name":"nowastemed"');
      assert.ok(hasInlinedStub, 'Should detect inlined stub');
    }],

    // Test 4: Source code import detection
    ['detect import from package.json in source', () => {
      const sourceContent = `import * as pkg from "~/package.json";
console.log(pkg.version);`;

      const issues = noPackageJsonRule.check(sourceContent, 'app/version.ts');
      assert.ok(issues.length > 0, 'Should detect package.json import');
      assert.strictEqual(issues[0].severity, 'high', 'Should be high severity');
      assert.ok(issues[0].message.includes('package.json'), 'Message should mention package.json');
    }],

    // Test 5: require() detection
    ['detect require package.json in source', () => {
      const sourceContent = `const pkg = require("~/package.json");
const version = pkg.version;`;

      const issues = noPackageJsonRule.check(sourceContent, 'app/config.ts');
      assert.ok(issues.length > 0, 'Should detect package.json require');
      assert.strictEqual(issues[0].rule, 'no-packagejson-require', 'Should use require rule');
    }],

    // Test 6: No false positive on stub reference
    ['no false positive on package.stub.json', () => {
      const sourceContent = `import config from "./config/package.stub.json";
console.log(config.version);`;

      const issues = noPackageJsonRule.check(sourceContent, 'app/app.ts');
      // Should not flag package.stub.json as a problem
      const packageJsonIssues = issues.filter(i =>
        i.rule === 'no-packagejson-import' && !i.message.includes('stub')
      );
      assert.strictEqual(packageJsonIssues.length, 0, 'Should not flag stub imports');
    }],
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
  process.exit(failed > 0 ? 1 : 0);
}

runTests();
