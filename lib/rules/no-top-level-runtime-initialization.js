/**
 * Rule: no-top-level-runtime-initialization
 *
 * BLOCKER - Detects runtime initialization at module top-level in NativeScript apps.
 *
 * In NativeScript with ESM bundling, any code that executes at module load time
 * (top-level scope) can crash the native runtime BEFORE:
 * - Application.run() is called
 * - Error handlers are registered
 * - The Runtime is fully initialized
 *
 * This causes a Java-level crash (Runtime.initInstance NPE) with NO JavaScript stack trace,
 * making it nearly impossible to debug.
 *
 * FORBIDDEN at top-level:
 * - Service.getInstance() calls
 * - new Service() instantiations
 * - Factory function calls (getXxxService(), initXxx(), etc.)
 * - Async initialization (service.initialize(), service.setup())
 * - Exports with side-effects: export const x = getService()
 *
 * ALLOWED at top-level:
 * - import statements
 * - Pure declarations (const X = 42, const config = {...})
 * - Function/class declarations (not invocations)
 * - Type exports
 */

const path = require('path');

// Files that are entry points or loaded early in the app lifecycle
const SENSITIVE_FILE_PATTERNS = [
    /^app\.ts$/,
    /^app\.js$/,
    /^main\.ts$/,
    /^main\.js$/,
    /^bootstrap\.ts$/,
    /^bootstrap\.js$/,
    /environment.*\.(ts|js)$/,
    /config\.(ts|js)$/,
    /app-root\.(ts|js)$/,
];

// Patterns that indicate runtime initialization (forbidden at top-level)
const FORBIDDEN_PATTERNS = [
    // getInstance() calls - singleton initialization
    {
        pattern: /^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*\w+\.getInstance\s*\(/m,
        name: 'singleton-initialization',
        example: 'const service = Service.getInstance()'
    },
    // Standalone getInstance() calls
    {
        pattern: /^\s*\w+\.getInstance\s*\(\s*\)/m,
        name: 'singleton-call',
        example: 'Service.getInstance()'
    },
    // new Service() instantiations at top-level
    {
        pattern: /^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*new\s+\w+Service\s*\(/m,
        name: 'service-instantiation',
        example: 'const service = new MyService()'
    },
    // Factory function calls: getXxxService(), getXxx()
    {
        pattern: /^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*get\w+(?:Service)?\s*\(\s*\)/m,
        name: 'factory-initialization',
        example: 'const env = getEnvironmentService()'
    },
    // Standalone factory calls
    {
        pattern: /^\s*get\w+(?:Service)?\s*\(\s*\)\s*;/m,
        name: 'factory-call',
        example: 'getAuthService();'
    },
    // initialize/setup/init calls
    {
        pattern: /^\s*\w+\.(initialize|setup|init|load|start)\s*\(/m,
        name: 'initialization-call',
        example: 'service.initialize()'
    },
    // Direct method chaining on getInstance
    {
        pattern: /^\s*\w+\.getInstance\s*\(\s*\)\s*\.\w+\s*\(/m,
        name: 'chained-singleton-call',
        example: 'Service.getInstance().doSomething()'
    },
];

// Patterns that are safe (to avoid false positives)
const SAFE_PATTERNS = [
    // Inside function body
    /^\s*(async\s+)?function\s+\w+/,
    // Arrow function assignment (the function itself, not a call)
    /^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\([^)]*\)\s*=>/,
    /^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\w+\s*=>/,
    // Class declaration
    /^\s*(?:export\s+)?class\s+\w+/,
    // Type/interface (TypeScript)
    /^\s*(?:export\s+)?(?:type|interface)\s+\w+/,
    // Import statement
    /^\s*import\s+/,
    // Pure value assignment
    /^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*['"`\d\[{]/,
    // Export statement without initialization
    /^\s*export\s+\{/,
    /^\s*export\s+default\s+\w+\s*;/,
];

function isSensitiveFile(filePath) {
    const fileName = path.basename(filePath);
    return SENSITIVE_FILE_PATTERNS.some(pattern => pattern.test(fileName));
}

function isInsideFunction(content, matchIndex) {
    // Check if the match is inside a function body by counting braces
    const beforeMatch = content.substring(0, matchIndex);

    // Look for function declarations/expressions before this point
    const functionPattern = /(?:async\s+)?function\s+\w*\s*\([^)]*\)\s*\{|(?:async\s+)?\([^)]*\)\s*=>\s*\{|(?:async\s+)?\w+\s*=>\s*\{/g;

    let lastFunctionStart = -1;
    let match;
    while ((match = functionPattern.exec(beforeMatch)) !== null) {
        lastFunctionStart = match.index;
    }

    if (lastFunctionStart === -1) {
        return false; // No function found before this point
    }

    // Count braces from last function start to match position
    const segment = content.substring(lastFunctionStart, matchIndex);
    let braceCount = 0;
    for (const char of segment) {
        if (char === '{') braceCount++;
        if (char === '}') braceCount--;
    }

    return braceCount > 0; // Inside function if braces are unclosed
}

function isInsideClass(content, matchIndex) {
    const beforeMatch = content.substring(0, matchIndex);

    // Look for class declarations
    const classPattern = /class\s+\w+(?:\s+extends\s+\w+)?\s*\{/g;

    let lastClassStart = -1;
    let match;
    while ((match = classPattern.exec(beforeMatch)) !== null) {
        lastClassStart = match.index;
    }

    if (lastClassStart === -1) {
        return false;
    }

    // Count braces from class start
    const segment = content.substring(lastClassStart, matchIndex);
    let braceCount = 0;
    for (const char of segment) {
        if (char === '{') braceCount++;
        if (char === '}') braceCount--;
    }

    return braceCount > 0;
}

function analyze(filePath, content, options = {}) {
    const issues = [];
    const fileName = path.basename(filePath);

    // Only check sensitive files (entry points and early-loaded modules)
    if (!isSensitiveFile(filePath)) {
        return issues;
    }

    // Skip test files
    if (filePath.includes('__tests__') || filePath.includes('.spec.') || filePath.includes('.test.')) {
        return issues;
    }

    const lines = content.split('\n');

    for (const forbidden of FORBIDDEN_PATTERNS) {
        // Use global flag to find all matches
        const globalPattern = new RegExp(forbidden.pattern.source, 'gm');
        let match;

        while ((match = globalPattern.exec(content)) !== null) {
            const matchIndex = match.index;
            const matchedText = match[0].trim();

            // Skip if inside a function or class method
            if (isInsideFunction(content, matchIndex) || isInsideClass(content, matchIndex)) {
                continue;
            }

            // Calculate line number
            const beforeMatch = content.substring(0, matchIndex);
            const lineNumber = beforeMatch.split('\n').length;
            const line = lines[lineNumber - 1] || '';

            // Check if this line matches any safe pattern
            const isSafe = SAFE_PATTERNS.some(safe => safe.test(line));
            if (isSafe) {
                continue;
            }

            // Extract the specific call for fingerprinting
            let callName = matchedText;
            const instanceMatch = matchedText.match(/(\w+)\.getInstance/);
            const factoryMatch = matchedText.match(/(get\w+(?:Service)?)\s*\(/);
            const initMatch = matchedText.match(/(\w+)\.(initialize|setup|init|load|start)/);

            if (instanceMatch) {
                callName = `${instanceMatch[1]}.getInstance()`;
            } else if (factoryMatch) {
                callName = `${factoryMatch[1]}()`;
            } else if (initMatch) {
                callName = `${initMatch[1]}.${initMatch[2]}()`;
            }

            issues.push({
                rule: 'no-top-level-runtime-initialization',
                severity: 'error', // BLOCKER level
                message: `Top-level runtime initialization detected: "${callName}". ` +
                    `This can crash the NativeScript runtime before it's fully initialized, ` +
                    `causing a Java-level NPE with no JS stack trace. ` +
                    `Move this into an async bootstrap function.`,
                file: filePath,
                line: lineNumber,
                column: match.index - beforeMatch.lastIndexOf('\n'),
                context: line.trim(),
                fingerprint: `no-top-level-runtime-initialization|${fileName}|${callName}`,
                fix: {
                    description: 'Wrap initialization in async bootstrap function',
                    suggestion: `
async function bootstrapApp() {
    ${matchedText}
    // ... other initialization
    Application.run({ moduleName: 'app-root' });
}

bootstrapApp().catch(err => {
    console.error("BOOTSTRAP FAILED", err);
    throw err;
});`
                }
            });
        }
    }

    return issues;
}

module.exports = {
    id: 'no-top-level-runtime-initialization',
    name: 'No Top-Level Runtime Initialization',
    description: 'Detects runtime initialization at module top-level that can crash NativeScript before the app starts',
    severity: 'error',
    category: 'runtime-safety',
    analyze,
    // Export for testing
    _isSensitiveFile: isSensitiveFile,
    _isInsideFunction: isInsideFunction,
    _FORBIDDEN_PATTERNS: FORBIDDEN_PATTERNS,
};
