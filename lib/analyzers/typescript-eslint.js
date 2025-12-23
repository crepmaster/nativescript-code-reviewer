/**
 * TypeScript ESLint Analyzer
 *
 * Uses @typescript-eslint/parser for proper TypeScript analysis
 * Avoids false positives on valid TypeScript syntax
 */

let ESLint;
let hasESLint = false;

try {
    ESLint = require('eslint').ESLint;
    hasESLint = true;
} catch (e) {
    console.warn('⚠️  ESLint not available. Install with: npm install eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin');
}

const path = require('path');

// Get the reviewer tool's root directory (to resolve plugins from node_modules)
const reviewerRoot = path.resolve(__dirname, '..', '..');

// Resolve the parser path to use the absolute path from reviewer's node_modules
const tsParserPath = require.resolve('@typescript-eslint/parser');

// TypeScript ESLint configuration
const tsConfig = {
    parser: tsParserPath,
    parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        createDefaultProgram: true,
    },
    plugins: ['@typescript-eslint'],
    rules: {
        // ❌ DISABLE JavaScript rules that cause false positives
        'no-unused-vars': 'off',
        'no-undef': 'off',
        'no-redeclare': 'off',
        'no-use-before-define': 'off',
        'no-shadow': 'off',

        // ✅ ENABLE TypeScript equivalents
        '@typescript-eslint/no-unused-vars': ['warn', {
            argsIgnorePattern: '^_',
            varsIgnorePattern: '^_',
            destructuredArrayIgnorePattern: '^_',
            caughtErrors: 'none',
        }],
        '@typescript-eslint/no-redeclare': ['error', {
            ignoreDeclarationMerge: true,
        }],
        '@typescript-eslint/no-use-before-define': ['error', {
            functions: false,
            classes: true,
            variables: true,
            typedefs: false,
            ignoreTypeReferences: true,
        }],
        '@typescript-eslint/no-shadow': ['error', {
            ignoreTypeValueShadow: true,
            ignoreFunctionTypeParameterNameValueShadow: true,
        }],

        // TypeScript-specific rules
        '@typescript-eslint/explicit-function-return-type': 'off',
        '@typescript-eslint/explicit-module-boundary-types': 'off',
        '@typescript-eslint/no-explicit-any': 'warn',
        '@typescript-eslint/no-inferrable-types': 'off', // Allow explicit types
        '@typescript-eslint/ban-ts-comment': 'warn',
        '@typescript-eslint/no-non-null-assertion': 'warn',
    },
};

// JavaScript ESLint configuration
const jsConfig = {
    parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
    },
    rules: {
        'no-unused-vars': ['warn', {
            argsIgnorePattern: '^_',
            varsIgnorePattern: '^_',
        }],
        'no-undef': 'error',
        'no-use-before-define': 'error',
    },
};

/**
 * Check if TypeScript ESLint is available
 */
function hasTypeScriptESLint() {
    try {
        require('@typescript-eslint/parser');
        require('@typescript-eslint/eslint-plugin');
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Analyze a file using ESLint
 */
async function analyzeFile(filePath, content) {
    if (!hasESLint) {
        return [];
    }

    const ext = path.extname(filePath);
    const isTypeScript = ['.ts', '.tsx'].includes(ext);

    // Check if we have TypeScript ESLint for TS files
    if (isTypeScript && !hasTypeScriptESLint()) {
        console.warn(`⚠️  TypeScript ESLint not available for ${filePath}. Install: npm install @typescript-eslint/parser @typescript-eslint/eslint-plugin`);
        return [];
    }

    try {
        const config = isTypeScript ? tsConfig : jsConfig;

        const eslint = new ESLint({
            useEslintrc: false,
            overrideConfig: {
                ...config,
                env: {
                    browser: true,
                    node: true,
                    es2022: true,
                },
            },
            fix: false,
            // Resolve parser and plugins from the reviewer tool's node_modules
            resolvePluginsRelativeTo: reviewerRoot,
        });

        const results = await eslint.lintText(content, { filePath });
        const issues = [];

        for (const result of results) {
            for (const message of result.messages) {
                issues.push({
                    severity: message.severity === 2 ? 'error' : 'warn',
                    rule: `eslint:${message.ruleId || 'unknown'}`,
                    message: message.message,
                    line: message.line,
                    column: message.column,
                    suggestion: getSuggestion(message),
                });
            }
        }

        return issues;
    } catch (error) {
        console.error(`Error analyzing ${filePath}:`, error.message);
        return [];
    }
}

/**
 * Get improvement suggestion for common issues
 */
function getSuggestion(message) {
    if (!message.ruleId) return null;

    const suggestions = {
        '@typescript-eslint/no-unused-vars': 'Remove unused variable or prefix with _ if intentionally unused',
        '@typescript-eslint/no-explicit-any': 'Replace "any" with a specific type for better type safety',
        '@typescript-eslint/no-non-null-assertion': 'Use optional chaining (?.) instead of non-null assertion (!)',
        'no-unused-vars': 'Remove unused variable or prefix with _',
        'no-undef': 'Import or declare this variable before use',
    };

    return suggestions[message.ruleId] || null;
}

/**
 * Get installation instructions
 */
function getInstallInstructions() {
    return `
To enable TypeScript-aware linting, install:

  npm install eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin --save-dev

This will:
- Properly parse TypeScript syntax (interfaces, types, generics, decorators)
- Avoid false positives on valid TypeScript code
- Detect real issues like unused variables, undefined references
`;
}

module.exports = {
    analyzeFile,
    hasESLint: () => hasESLint,
    hasTypeScriptESLint,
    getInstallInstructions,
};
