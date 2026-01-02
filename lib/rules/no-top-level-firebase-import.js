/**
 * Rule: no-top-level-firebase-import
 *
 * BLOCKER - Detects top-level Firebase imports in NativeScript entry files.
 *
 * In NativeScript, importing Firebase modules at the top-level of entry files
 * (app.ts, main.ts) causes them to initialize BEFORE the NativeScript runtime
 * is fully ready. This leads to:
 *
 * - Native crashes (Java NPE) with no JS stack trace
 * - "Cannot read properties of undefined" errors
 * - Inconsistent startup behavior
 *
 * FORBIDDEN in entry files:
 * - import '@nativescript/firebase-auth'
 * - import '@nativescript/firebase-firestore'
 * - import '@nativescript/firebase-core'
 * - import { ... } from '@nativescript/firebase-*'
 * - import * as firebase from '@nativescript/firebase-*'
 *
 * CORRECT PATTERN:
 * - Use dynamic import() inside launchEvent handler:
 *   Application.on(Application.launchEvent, async () => {
 *       await import('@nativescript/firebase-auth');
 *   });
 */

const path = require('path');

// Entry files where Firebase imports are dangerous
const ENTRY_FILE_PATTERNS = [
    /^app\.(ts|js)$/,
    /^main\.(ts|js)$/,
    /^bootstrap\.(ts|js)$/,
    /^index\.(ts|js)$/,
];

// Firebase import patterns to detect
const FIREBASE_IMPORT_PATTERNS = [
    // Side-effect imports: import '@nativescript/firebase-*'
    {
        pattern: /^\s*import\s+['"]@nativescript\/firebase-[^'"]+['"]\s*;?/gm,
        type: 'side-effect',
        example: "import '@nativescript/firebase-auth'"
    },
    // Named imports: import { ... } from '@nativescript/firebase-*'
    {
        pattern: /^\s*import\s+\{[^}]+\}\s+from\s+['"]@nativescript\/firebase-[^'"]+['"]\s*;?/gm,
        type: 'named',
        example: "import { firebase } from '@nativescript/firebase-core'"
    },
    // Namespace imports: import * as X from '@nativescript/firebase-*'
    {
        pattern: /^\s*import\s+\*\s+as\s+\w+\s+from\s+['"]@nativescript\/firebase-[^'"]+['"]\s*;?/gm,
        type: 'namespace',
        example: "import * as firebase from '@nativescript/firebase-core'"
    },
    // Default imports: import firebase from '@nativescript/firebase-*'
    {
        pattern: /^\s*import\s+\w+\s+from\s+['"]@nativescript\/firebase-[^'"]+['"]\s*;?/gm,
        type: 'default',
        example: "import firebase from '@nativescript/firebase-core'"
    },
];

// Dynamic import pattern (correct usage - should NOT be flagged)
const DYNAMIC_IMPORT_PATTERN = /await\s+import\s*\(\s*['"]@nativescript\/firebase-[^'"]+['"]\s*\)/;

function isEntryFile(filePath) {
    const fileName = path.basename(filePath);
    return ENTRY_FILE_PATTERNS.some(pattern => pattern.test(fileName));
}

function extractModuleName(importStatement) {
    const match = importStatement.match(/@nativescript\/firebase-[^'"]+/);
    return match ? match[0] : 'firebase module';
}

function analyze(filePath, content, options = {}) {
    const issues = [];
    const fileName = path.basename(filePath);

    // Only check entry files
    if (!isEntryFile(filePath)) {
        return issues;
    }

    // Skip test files
    if (filePath.includes('__tests__') || filePath.includes('.spec.') || filePath.includes('.test.')) {
        return issues;
    }

    const lines = content.split('\n');

    for (const { pattern, type, example } of FIREBASE_IMPORT_PATTERNS) {
        // Reset regex state
        pattern.lastIndex = 0;

        let match;
        while ((match = pattern.exec(content)) !== null) {
            const matchIndex = match.index;
            const matchedText = match[0].trim();

            // Check if this is inside a dynamic import (which is OK)
            const surroundingContext = content.substring(
                Math.max(0, matchIndex - 50),
                Math.min(content.length, matchIndex + matchedText.length + 50)
            );

            if (DYNAMIC_IMPORT_PATTERN.test(surroundingContext)) {
                continue; // Dynamic import is OK
            }

            // Calculate line number
            const beforeMatch = content.substring(0, matchIndex);
            const lineNumber = beforeMatch.split('\n').length;

            const moduleName = extractModuleName(matchedText);

            issues.push({
                rule: 'no-top-level-firebase-import',
                severity: 'error', // BLOCKER level
                message: `Top-level Firebase import detected: "${moduleName}". ` +
                    `Firebase modules must be loaded lazily via dynamic import() inside launchEvent handler. ` +
                    `Top-level imports trigger native initialization before the runtime is ready, causing crashes.`,
                file: filePath,
                line: lineNumber,
                column: 1,
                context: matchedText,
                fingerprint: `no-top-level-firebase-import|${fileName}|${moduleName}|${lineNumber}`,
                fix: {
                    description: 'Use dynamic import inside launchEvent handler',
                    before: matchedText,
                    after: `// Move to launchEvent handler:\n// await import("${moduleName}");`,
                    suggestion: `
Application.on(Application.launchEvent, async () => {
    // Load Firebase lazily after runtime is ready
    await import("${moduleName}");
    // ... rest of initialization
});`
                }
            });
        }
    }

    return issues;
}

module.exports = {
    id: 'no-top-level-firebase-import',
    name: 'No Top-Level Firebase Import',
    description: 'Detects top-level Firebase imports in entry files that can crash NativeScript before runtime is ready',
    severity: 'error',
    category: 'runtime-safety',
    analyze,
    // Export for testing
    _isEntryFile: isEntryFile,
    _FIREBASE_IMPORT_PATTERNS: FIREBASE_IMPORT_PATTERNS,
};
