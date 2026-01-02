/**
 * imports-interop.js - Import/Require Pattern Detection
 *
 * Detects common import/require patterns that cause runtime errors:
 * - "object is not a function"
 * - "undefined is not a function"
 * - Module resolution failures
 * - Shadowing of imported symbols
 */

module.exports = {
  check(content, filePath) {
    const issues = [];

    // Only process TypeScript/JavaScript files
    if (!/\.(ts|js|tsx|jsx)$/i.test(filePath)) {
      return issues;
    }

    // Skip declaration files
    if (/\.d\.ts$/i.test(filePath)) {
      return issues;
    }

    // ===== NAMESPACE IMPORTS CALLED AS FUNCTIONS =====
    // Pattern: import * as foo from 'bar'; foo() - This is almost always wrong
    const namespaceImports = [...content.matchAll(/import\s+\*\s+as\s+(\w+)\s+from\s+['"]([^'"]+)['"]/g)];

    namespaceImports.forEach(match => {
      const alias = match[1];
      const modulePath = match[2];

      // Check if the namespace is called as a function
      const functionCallPattern = new RegExp(`\\b${alias}\\s*\\(`, 'g');
      const functionCalls = [...content.matchAll(functionCallPattern)];

      if (functionCalls.length > 0) {
        issues.push({
          severity: 'error',
          rule: 'namespace-import-as-function',
          message: `Namespace import '${alias}' from '${modulePath}' is called as a function; use named import or default import instead`
        });
      }
    });

    // ===== REQUIRE CALLED DIRECTLY WHEN LIKELY AN OBJECT =====
    // Pattern: require('module')() - calling require result directly
    const requireDirectCalls = [...content.matchAll(/require\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\(/g)];

    requireDirectCalls.forEach(match => {
      const modulePath = match[1];
      // Skip known factory modules
      const factoryModules = ['express', 'koa', 'fastify', 'connect', 'morgan', 'cors', 'helmet'];
      const moduleName = modulePath.split('/').pop().replace(/\.[jt]sx?$/, '');

      if (!factoryModules.includes(moduleName)) {
        issues.push({
          severity: 'warn',
          rule: 'require-called-as-function',
          message: `require('${modulePath}')() - calling require result directly; verify module exports a function`
        });
      }
    });

    // ===== DEFAULT IMPORT FROM NON-ESM MODULE =====
    // Common problematic patterns with known CommonJS modules
    const commonCJSModules = [
      'path', 'fs', 'os', 'crypto', 'util', 'events', 'stream', 'http', 'https',
      'lodash', 'moment', 'underscore', 'async', 'request', 'cheerio', 'xml2js'
    ];

    commonCJSModules.forEach(mod => {
      const defaultImportPattern = new RegExp(`import\\s+(\\w+)\\s+from\\s+['"]${mod}['"](?!.*\\.)`, 'g');
      const matches = [...content.matchAll(defaultImportPattern)];

      matches.forEach(match => {
        const importName = match[1];
        // Check if used as a function
        const usagePattern = new RegExp(`\\b${importName}\\s*\\(`, 'g');
        if (usagePattern.test(content)) {
          issues.push({
            severity: 'warn',
            rule: 'cjs-default-import-as-function',
            message: `'${mod}' is CommonJS; default import '${importName}' may be an object, not a function. Use: import * as ${importName} or named imports`
          });
        }
      });
    });

    // ===== SHADOWING OF IMPORTED SYMBOLS =====
    // Collect all imports
    const importedSymbols = new Map();

    // Named imports: import { foo, bar as baz } from 'module'
    const namedImports = [...content.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"][^'"]+['"]/g)];
    namedImports.forEach(match => {
      const imports = match[1].split(',').map(s => {
        const parts = s.trim().split(/\s+as\s+/);
        return parts[parts.length - 1].trim();
      });
      imports.forEach(imp => {
        if (imp && /^[a-zA-Z_$][\w$]*$/.test(imp)) {
          importedSymbols.set(imp, 'named');
        }
      });
    });

    // Default imports: import foo from 'module'
    const defaultImports = [...content.matchAll(/import\s+(\w+)\s+from\s*['"][^'"]+['"]/g)];
    defaultImports.forEach(match => {
      const imp = match[1];
      if (imp !== '*') {
        importedSymbols.set(imp, 'default');
      }
    });

    // Namespace imports: import * as foo from 'module'
    namespaceImports.forEach(match => {
      importedSymbols.set(match[1], 'namespace');
    });

    // Check for shadowing by local declarations
    importedSymbols.forEach((type, symbol) => {
      // Check function declarations
      const funcPattern = new RegExp(`function\\s+${symbol}\\s*\\(`, 'g');
      if (funcPattern.test(content)) {
        issues.push({
          severity: 'warn',
          rule: 'import-shadowed-by-function',
          message: `Imported symbol '${symbol}' is shadowed by a function declaration`
        });
      }

      // Check variable declarations (excluding the import line itself)
      const varPatterns = [
        new RegExp(`(?:const|let|var)\\s+${symbol}\\s*[=:]`, 'g'),
        new RegExp(`(?:const|let|var)\\s+\\{[^}]*\\b${symbol}\\b[^}]*\\}\\s*=`, 'g')
      ];

      varPatterns.forEach(pattern => {
        const matches = [...content.matchAll(pattern)];
        matches.forEach(match => {
          // Make sure it's not part of an import statement
          const lineStart = content.lastIndexOf('\n', match.index) + 1;
          const line = content.substring(lineStart, match.index + match[0].length + 50);
          if (!line.includes('import ') && !line.includes('from ')) {
            issues.push({
              severity: 'warn',
              rule: 'import-shadowed-by-variable',
              message: `Imported symbol '${symbol}' is shadowed by a variable declaration`
            });
          }
        });
      });

      // Check parameter shadowing in functions
      const paramPattern = new RegExp(`\\(\\s*[^)]*\\b${symbol}\\b\\s*[,):=]`, 'g');
      const paramMatches = [...content.matchAll(paramPattern)];
      if (paramMatches.length > 0) {
        // This is often intentional, so just info level
        issues.push({
          severity: 'info',
          rule: 'import-shadowed-by-param',
          message: `Imported symbol '${symbol}' may be shadowed by a function parameter`
        });
      }
    });

    // ===== MIXED IMPORT/REQUIRE STYLES =====
    const hasESMImport = /\bimport\s+(?:\{|\*|[a-zA-Z_$])/m.test(content);
    const hasRequire = /\brequire\s*\(\s*['"]/.test(content);

    if (hasESMImport && hasRequire) {
      // Check if require is not for dynamic imports
      const dynamicRequire = /\brequire\s*\(\s*[^'"]/g.test(content);
      if (!dynamicRequire) {
        issues.push({
          severity: 'info',
          rule: 'mixed-import-require',
          message: 'File mixes ESM import and CommonJS require; consider using consistent module syntax'
        });
      }
    }

    // ===== DYNAMIC IMPORT ISSUES =====
    // Check for await on dynamic import
    const dynamicImports = [...content.matchAll(/import\s*\(\s*['"]([^'"]+)['"]\s*\)/g)];
    dynamicImports.forEach(match => {
      const beforeImport = content.substring(Math.max(0, match.index - 50), match.index);
      if (!/await\s*$/.test(beforeImport) && !/\.then\s*\(/.test(content.substring(match.index, match.index + match[0].length + 20))) {
        issues.push({
          severity: 'warn',
          rule: 'dynamic-import-no-await',
          message: `Dynamic import('${match[1]}') may need await or .then() handling`
        });
      }
    });

    // ===== TYPE-ONLY IMPORTS USED AS VALUES =====
    const typeOnlyImports = [...content.matchAll(/import\s+type\s+\{([^}]+)\}/g)];
    typeOnlyImports.forEach(match => {
      const types = match[1].split(',').map(s => s.trim().split(/\s+as\s+/).pop().trim());
      types.forEach(typeName => {
        if (typeName && /^[a-zA-Z_$][\w$]*$/.test(typeName)) {
          // Check if used as value (not in type position)
          const valueUsagePattern = new RegExp(`[^:]\\s*\\b${typeName}\\s*\\(|new\\s+${typeName}\\s*\\(|=\\s*${typeName}\\s*[;,)]`, 'g');
          if (valueUsagePattern.test(content)) {
            issues.push({
              severity: 'error',
              rule: 'type-import-as-value',
              message: `Type-only import '${typeName}' is used as a value; remove 'type' from import or add separate value import`
            });
          }
        }
      });
    });

    // ===== CIRCULAR DEPENDENCY HINTS =====
    // Check for late imports inside functions (often indicates circular dep workaround)
    const lateRequires = [...content.matchAll(/function\s+\w+\s*\([^)]*\)\s*\{[^}]*require\s*\(/gs)];
    if (lateRequires.length > 2) {
      issues.push({
        severity: 'info',
        rule: 'late-require-pattern',
        message: 'Multiple require() calls inside functions; may indicate circular dependency issues'
      });
    }

    // ===== EXTENSION IN IMPORTS =====
    // Check for missing extensions when using Node16/NodeNext resolution
    const localImports = [...content.matchAll(/from\s+['"](\.[^'"]+)['"]/g)];
    localImports.forEach(match => {
      const importPath = match[1];
      if (!/\.(js|ts|jsx|tsx|json|mjs|cjs)$/.test(importPath)) {
        issues.push({
          severity: 'info',
          rule: 'import-missing-extension',
          message: `Import '${importPath}' has no extension; may fail with Node16/NodeNext module resolution`
        });
      }
    });

    return issues;
  }
};
