/**
 * Tests for no-top-level-runtime-initialization rule
 *
 * This rule detects the #1 cause of undebuggable NativeScript crashes:
 * top-level runtime initialization that crashes before JS error handlers are ready.
 */

const assert = require('assert');
const rule = require('../no-top-level-runtime-initialization');

// ============================================================
// Test Helpers
// ============================================================

function assertHasIssue(issues, expectedPattern) {
    const found = issues.some(issue =>
        issue.message.includes(expectedPattern) ||
        issue.fingerprint.includes(expectedPattern)
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

    ['detect getInstance() at top-level', () => {
        const content = `
import { Application } from '@nativescript/core';
import { AdminService } from './services/admin.service';

AdminService.getInstance();

Application.run({ moduleName: 'app-root' });
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'AdminService.getInstance()');
        assert.strictEqual(issues[0].severity, 'error');
    }],

    ['detect const = getInstance() at top-level', () => {
        const content = `
import { EnvironmentService } from './config/environment.config';

const env = EnvironmentService.getInstance();

console.log(env.name);
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'EnvironmentService.getInstance()');
    }],

    ['detect export const = getXxxService() at top-level', () => {
        const content = `
export const environment = getEnvironmentService();
`;
        const issues = rule.analyze('/project/app/environment.config.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'getEnvironmentService()');
    }],

    ['detect multiple getInstance() calls', () => {
        const content = `
import { Application } from '@nativescript/core';

AdminService.getInstance();
PermissionsService.getInstance();
NavigationService.getInstance();
DemoDataService.getInstance().initializeDemoData();

Application.run({ moduleName: 'app-root' });
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.ok(issues.length >= 4, `Expected at least 4 issues, got ${issues.length}`);
    }],

    ['detect factory function calls at top-level', () => {
        const content = `
import { getAuthService } from './services/auth-factory.service';

getAuthService();
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'getAuthService()');
    }],

    ['detect service.initialize() at top-level', () => {
        const content = `
import { FirebaseService } from './services/firebase.service';

FirebaseService.initialize();
`;
        const issues = rule.analyze('/project/app/main.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'initialize()');
    }],

    ['detect chained getInstance().method() at top-level', () => {
        const content = `
DemoDataService.getInstance().initializeDemoData();
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.ok(issues.length >= 1);
        assertHasIssue(issues, 'getInstance()');
    }],

    ['detect new Service() at top-level', () => {
        const content = `
const authService = new AuthService();
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assertHasIssue(issues, 'new');
    }],

    // --------------------------------------------------------
    // SAFE CASES - Must NOT be detected (false positive prevention)
    // --------------------------------------------------------

    ['pass when getInstance() is inside async function', () => {
        const content = `
import { Application } from '@nativescript/core';
import { AdminService } from './services/admin.service';

async function bootstrapApp() {
    AdminService.getInstance();
    PermissionsService.getInstance();
    Application.run({ moduleName: 'app-root' });
}

bootstrapApp().catch(err => console.error(err));
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'getInstance inside async function');
    }],

    ['pass when getInstance() is inside regular function', () => {
        const content = `
function initializeApp() {
    const env = getEnvironmentService();
    AdminService.getInstance();
}
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'getInstance inside function');
    }],

    ['pass when getInstance() is inside arrow function', () => {
        const content = `
const bootstrap = async () => {
    AdminService.getInstance();
    PermissionsService.getInstance();
};
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'getInstance inside arrow function');
    }],

    ['pass when getInstance() is inside class method', () => {
        const content = `
class AppBootstrap {
    async run() {
        AdminService.getInstance();
        PermissionsService.getInstance();
    }
}
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'getInstance inside class method');
    }],

    ['pass for pure imports only', () => {
        const content = `
import { Application } from '@nativescript/core';
import { AdminService } from './services/admin.service';
import { PermissionsService } from './services/permissions.service';

// No top-level initialization here
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'pure imports');
    }],

    ['pass for pure constant declarations', () => {
        const content = `
const CONFIG = {
    apiUrl: 'https://api.example.com',
    timeout: 5000
};

const VERSION = '1.0.0';
const DEBUG = true;
`;
        const issues = rule.analyze('/project/app/config.ts', content);
        assertNoIssues(issues, 'pure constants');
    }],

    ['pass for function declarations', () => {
        const content = `
function getConfig() {
    return EnvironmentService.getInstance().getConfig();
}

async function bootstrap() {
    AdminService.getInstance();
}
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'function declarations');
    }],

    ['pass for class declarations', () => {
        const content = `
class EnvironmentService {
    private static instance: EnvironmentService;

    static getInstance(): EnvironmentService {
        if (!EnvironmentService.instance) {
            EnvironmentService.instance = new EnvironmentService();
        }
        return EnvironmentService.instance;
    }
}
`;
        const issues = rule.analyze('/project/app/environment.config.ts', content);
        assertNoIssues(issues, 'class declarations with getInstance method');
    }],

    ['pass for non-sensitive files', () => {
        const content = `
// This is a utility file, not an entry point
const service = AdminService.getInstance();
`;
        const issues = rule.analyze('/project/app/utils/some-util.ts', content);
        assertNoIssues(issues, 'non-sensitive file');
    }],

    ['pass for test files', () => {
        const content = `
AdminService.getInstance();
`;
        const issues = rule.analyze('/project/app/__tests__/app.test.ts', content);
        assertNoIssues(issues, 'test file');
    }],

    // --------------------------------------------------------
    // Edge cases
    // --------------------------------------------------------

    ['detect in bootstrap.ts', () => {
        const content = `
const env = getEnvironmentService();
`;
        const issues = rule.analyze('/project/app/bootstrap.ts', content);
        assert.strictEqual(issues.length, 1);
    }],

    ['detect in environment.config.ts', () => {
        const content = `
export const environment = getEnvironmentService();
`;
        const issues = rule.analyze('/project/app/config/environment.config.ts', content);
        assert.strictEqual(issues.length, 1);
    }],

    ['verify fingerprint format', () => {
        const content = `
AdminService.getInstance();
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assert.ok(issues[0].fingerprint.startsWith('no-top-level-runtime-initialization|'));
        assert.ok(issues[0].fingerprint.includes('app.ts'));
        assert.ok(issues[0].fingerprint.includes('AdminService.getInstance()'));
    }],

    ['verify fix suggestion is provided', () => {
        const content = `
AdminService.getInstance();
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assert.strictEqual(issues.length, 1);
        assert.ok(issues[0].fix);
        assert.ok(issues[0].fix.suggestion.includes('async function bootstrapApp'));
        assert.ok(issues[0].fix.suggestion.includes('Application.run'));
    }],

    // --------------------------------------------------------
    // Real-world scenario (the exact bug we fixed)
    // --------------------------------------------------------

    ['detect the exact pattern that caused the crash', () => {
        const content = `
// app.ts - BEFORE fix (caused Java NPE crash)
import { Application } from '@nativescript/core';
import '@nativescript/firebase-auth';
import '@nativescript/firebase-firestore';

import { getAuthService } from './services/auth-factory.service';
import { AdminService } from './services/admin.service';
import { PermissionsService } from './services/permissions.service';
import { NavigationService } from './services/navigation.service';
import { DemoDataService } from './services/demo/demo-data.service';
import { getEnvironmentService } from './config/environment.config';

const env = getEnvironmentService();
getAuthService();
AdminService.getInstance();
PermissionsService.getInstance();
NavigationService.getInstance();

if (!env.isFeatureEnabled('useFirebaseAuth')) {
    DemoDataService.getInstance().initializeDemoData();
}

Application.run({ moduleName: 'app-root' });
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        // Should detect at least: getEnvironmentService(), getAuthService(),
        // AdminService.getInstance(), PermissionsService.getInstance(),
        // NavigationService.getInstance()
        assert.ok(issues.length >= 5, `Expected at least 5 issues, got ${issues.length}`);
        assertHasIssue(issues, 'getEnvironmentService()');
        assertHasIssue(issues, 'getAuthService()');
        assertHasIssue(issues, 'AdminService.getInstance()');
        assertHasIssue(issues, 'PermissionsService.getInstance()');
        assertHasIssue(issues, 'NavigationService.getInstance()');
    }],

    ['pass the corrected pattern', () => {
        const content = `
// app.ts - AFTER fix (correct pattern)
import { Application } from '@nativescript/core';
import '@nativescript/firebase-auth';
import '@nativescript/firebase-firestore';

import { getAuthService } from './services/auth-factory.service';
import { AdminService } from './services/admin.service';
import { PermissionsService } from './services/permissions.service';
import { NavigationService } from './services/navigation.service';
import { DemoDataService } from './services/demo/demo-data.service';
import { getEnvironmentService } from './config/environment.config';

async function bootstrapApp() {
    const env = getEnvironmentService();
    getAuthService();
    AdminService.getInstance();
    PermissionsService.getInstance();
    NavigationService.getInstance();

    if (!env.isFeatureEnabled('useFirebaseAuth')) {
        DemoDataService.getInstance().initializeDemoData();
    }

    Application.run({ moduleName: 'app-root' });
}

bootstrapApp().catch(err => {
    console.error("BOOTSTRAP FAILED", err);
    throw err;
});
`;
        const issues = rule.analyze('/project/app/app.ts', content);
        assertNoIssues(issues, 'corrected bootstrap pattern');
    }],
];

// ============================================================
// Test Runner
// ============================================================

function runTests() {
    console.log('Running no-top-level-runtime-initialization tests...\n');

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
