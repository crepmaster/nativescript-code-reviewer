/**
 * Tests for no-top-level-firebase-import rule
 *
 * This rule detects Firebase imports at top-level in NativeScript entry files,
 * which cause native crashes before the runtime is fully initialized.
 */

const assert = require('assert');
const rule = require('../no-top-level-firebase-import');

// ============================================================
// Test Helpers
// ============================================================

function assertHasIssue(issues, expectedPattern) {
    const found = issues.some(issue =>
        issue.message.includes(expectedPattern) ||
        issue.fingerprint.includes(expectedPattern) ||
        issue.context?.includes(expectedPattern)
    );
    assert.ok(found, `Expected issue containing "${expectedPattern}" but found: ${JSON.stringify(issues, null, 2)}`);
}

function assertNoIssues(issues, context = '') {
    assert.strictEqual(issues.length, 0,
        `Expected no issues${context ? ` for ${context}` : ''} but found: ${JSON.stringify(issues, null, 2)}`);
}

// ============================================================
// Test Cases
// ============================================================

const tests = [
    // --------------------------------------------------------
    // BLOCKER CASES - Must be detected
    // --------------------------------------------------------

    ['detect side-effect firebase-auth import', () => {
        const content = `
import { Application } from '@nativescript/core';
import '@nativescript/firebase-auth';

Application.run({ moduleName: 'app-root' });
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'firebase-auth');
        assert.strictEqual(issues[0].severity, 'error');
    }],

    ['detect side-effect firebase-firestore import', () => {
        const content = `
import '@nativescript/firebase-firestore';
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'firebase-firestore');
    }],

    ['detect side-effect firebase-core import', () => {
        const content = `
import '@nativescript/firebase-core';
`;
        const issues = rule.analyze('/project/app/main.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'firebase-core');
    }],

    ['detect multiple firebase imports', () => {
        const content = `
import { Application } from '@nativescript/core';
import '@nativescript/firebase-core';
import '@nativescript/firebase-auth';
import '@nativescript/firebase-firestore';

Application.run({ moduleName: 'app-root' });
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 3);
        assertHasIssue(issues, 'firebase-core');
        assertHasIssue(issues, 'firebase-auth');
        assertHasIssue(issues, 'firebase-firestore');
    }],

    ['detect named import from firebase', () => {
        const content = `
import { firebase } from '@nativescript/firebase-core';
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'firebase-core');
    }],

    ['detect namespace import from firebase', () => {
        const content = `
import * as firebaseAuth from '@nativescript/firebase-auth';
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'firebase-auth');
    }],

    ['detect default import from firebase', () => {
        const content = `
import firebase from '@nativescript/firebase-core';
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'firebase-core');
    }],

    ['detect in main.ts entry file', () => {
        const content = `
import '@nativescript/firebase-auth';
`;
        const issues = rule.analyze('/project/app/main.ts', content);
        assert.strictEqual(issues.length, 1);
    }],

    ['detect in bootstrap.ts entry file', () => {
        const content = `
import '@nativescript/firebase-auth';
`;
        const issues = rule.analyze('/project/app/bootstrap.ts', content);
        assert.strictEqual(issues.length, 1);
    }],

    // --------------------------------------------------------
    // SAFE CASES - Must NOT be detected
    // --------------------------------------------------------

    ['pass when using dynamic import', () => {
        const content = `
import { Application } from '@nativescript/core';

Application.on(Application.launchEvent, async () => {
    await import('@nativescript/firebase-auth');
    await import('@nativescript/firebase-firestore');
});

Application.run({ moduleName: 'app-root' });
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'dynamic import');
    }],

    ['pass for non-entry files', () => {
        const content = `
import '@nativescript/firebase-auth';
import '@nativescript/firebase-firestore';
`;
        const issues = rule.analyze('/project/app/services/firebase.service.ts', content);
        assertNoIssues(issues, 'non-entry file');
    }],

    ['pass for test files', () => {
        const content = `
import '@nativescript/firebase-auth';
`;
        const issues = rule.analyze('/project/app/__tests__/app.test.ts', content);
        assertNoIssues(issues, 'test file');
    }],

    ['pass when no firebase imports', () => {
        const content = `
import { Application } from '@nativescript/core';
import { SomeService } from './services/some.service';

Application.run({ moduleName: 'app-root' });
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'no firebase imports');
    }],

    // --------------------------------------------------------
    // Edge cases
    // --------------------------------------------------------

    ['verify fix suggestion is provided', () => {
        const content = `
import '@nativescript/firebase-auth';
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assert.ok(issues[0].fix);
        assert.ok(issues[0].fix.suggestion.includes('launchEvent'));
        assert.ok(issues[0].fix.suggestion.includes('await import'));
    }],

    ['verify fingerprint format', () => {
        const content = `
import '@nativescript/firebase-auth';
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assert.ok(issues[0].fingerprint.startsWith('no-top-level-firebase-import|'));
        assert.ok(issues[0].fingerprint.includes('app.ts'));
        assert.ok(issues[0].fingerprint.includes('firebase-auth'));
    }],

    // --------------------------------------------------------
    // Real-world scenario (the exact bug pattern)
    // --------------------------------------------------------

    ['detect the exact pattern that caused crashes', () => {
        const content = `
// FIRST LINE - Native Android log to prove JS execution
declare const android: any;

import { Application } from '@nativescript/core';

// These cause crashes!
import '@nativescript/firebase-auth';
import '@nativescript/firebase-firestore';

import { getAuthService } from './services/auth-factory.service';

Application.run({ moduleName: 'app-root' });
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 2);
        assertHasIssue(issues, 'firebase-auth');
        assertHasIssue(issues, 'firebase-firestore');
    }],

    ['pass the corrected pattern with lazy imports', () => {
        const content = `
import { Application } from "@nativescript/core";

async function initializeServices() {
    const { getEnvironmentService } = await import("./config/environment.config");
    const env = getEnvironmentService();

    if (env.isFeatureEnabled("useFirebaseAuth")) {
        await import("@nativescript/firebase-auth");
        await import("@nativescript/firebase-firestore");
    }
}

Application.on(Application.launchEvent, async () => {
    await initializeServices();
});

Application.run({ moduleName: "app-root" });
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'corrected lazy import pattern');
    }],
];

// ============================================================
// Test Runner
// ============================================================

function runTests() {
    console.log('Running no-top-level-firebase-import tests...\n');

    let passed = 0;
    let failed = 0;

    for (const [name, testFn] of tests) {
        try {
            testFn();
            console.log(`  ✓ ${name}`);
            passed++;
        } catch (error) {
            console.log(`  ✗ ${name}`);
            console.log(`    Error: ${error.message}`);
            failed++;
        }
    }

    console.log(`\n${passed} passed, ${failed} failed`);

    if (failed > 0) {
        process.exit(1);
    }
}

// Run if executed directly
if (require.main === module) {
    runTests();
}

module.exports = { tests, runTests };
