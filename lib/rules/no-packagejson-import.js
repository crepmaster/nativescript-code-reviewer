/**
 * no-packagejson-import.js - Detect problematic package.json imports
 *
 * Detects imports of package.json that cause ESM bundling issues:
 * - import * as pkg from "~/package.json"
 * - import pkg from "package.json"
 * - require("~/package.json")
 *
 * These patterns cause crashes in NativeScript 8+ with webpack ESM bundling:
 * "Error while loading module... %2Fpackage.json"
 */

const fs = require('fs');
const path = require('path');

module.exports = {
  check(content, filePath, opts = {}) {
    const issues = [];

    // Process TypeScript/JavaScript files
    const ext = path.extname(filePath).toLowerCase();
    if (!['.ts', '.js', '.tsx', '.jsx', '.mjs', '.cjs'].includes(ext)) {
      return issues;
    }

    const lines = content.split('\n');

    // ===== IMPORT PATTERNS =====

    // Pattern 1: import * as X from "~/package.json" or similar
    const importStarPattern = /import\s+\*\s+as\s+(\w+)\s+from\s+['"]([^'"]*package\.json)['"]/g;

    // Pattern 2: import X from "package.json"
    const importDefaultPattern = /import\s+(\w+)\s+from\s+['"]([^'"]*package\.json)['"]/g;

    // Pattern 3: import { X } from "package.json"
    const importNamedPattern = /import\s+\{[^}]+\}\s+from\s+['"]([^'"]*package\.json)['"]/g;

    // Pattern 4: require("package.json")
    const requirePattern = /require\s*\(\s*['"]([^'"]*package\.json)['"]\s*\)/g;

    // Pattern 5: dynamic import("package.json")
    const dynamicImportPattern = /import\s*\(\s*['"]([^'"]*package\.json)['"]\s*\)/g;

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;

      // Skip comments
      const trimmedLine = line.trim();
      if (trimmedLine.startsWith('//') || trimmedLine.startsWith('*') || trimmedLine.startsWith('/*')) {
        return;
      }

      let match;

      // Check import * as
      while ((match = importStarPattern.exec(line)) !== null) {
        const varName = match[1];
        const importPath = match[2];

        issues.push({
          severity: 'high',
          rule: 'no-packagejson-import',
          message: `Import of '${importPath}' will fail in NativeScript ESM bundles. Use build-time constants instead.`,
          line: lineNum,
          column: match.index + 1,
          evidence: `import * as ${varName} from "${importPath}"`,
          fix: {
            suggestion: `Replace with build-time constant or use Application.getNativeApplication() for version info`
          }
        });
      }

      // Reset pattern
      importStarPattern.lastIndex = 0;

      // Check import default
      while ((match = importDefaultPattern.exec(line)) !== null) {
        const varName = match[1];
        const importPath = match[2];

        issues.push({
          severity: 'high',
          rule: 'no-packagejson-import',
          message: `Import of '${importPath}' will fail in NativeScript ESM bundles.`,
          line: lineNum,
          column: match.index + 1,
          evidence: `import ${varName} from "${importPath}"`,
          fix: {
            suggestion: `Replace with build-time constant via webpack DefinePlugin`
          }
        });
      }

      importDefaultPattern.lastIndex = 0;

      // Check import { named }
      while ((match = importNamedPattern.exec(line)) !== null) {
        const importPath = match[1];

        issues.push({
          severity: 'high',
          rule: 'no-packagejson-import',
          message: `Named import from '${importPath}' will fail in NativeScript ESM bundles.`,
          line: lineNum,
          column: match.index + 1,
          fix: {
            suggestion: `Replace with build-time constant via webpack DefinePlugin`
          }
        });
      }

      importNamedPattern.lastIndex = 0;

      // Check require()
      while ((match = requirePattern.exec(line)) !== null) {
        const importPath = match[1];

        // require is less problematic but still risky in ESM context
        issues.push({
          severity: 'warn',
          rule: 'no-packagejson-require',
          message: `require('${importPath}') may fail in ESM bundles. Consider build-time constants.`,
          line: lineNum,
          column: match.index + 1,
          evidence: `require("${importPath}")`,
          fix: {
            suggestion: `Use webpack DefinePlugin to inject version at build time`
          }
        });
      }

      requirePattern.lastIndex = 0;

      // Check dynamic import
      while ((match = dynamicImportPattern.exec(line)) !== null) {
        const importPath = match[1];

        issues.push({
          severity: 'high',
          rule: 'no-packagejson-dynamic-import',
          message: `Dynamic import of '${importPath}' will fail in NativeScript bundles.`,
          line: lineNum,
          column: match.index + 1,
          fix: {
            suggestion: `Replace with build-time constant`
          }
        });
      }

      dynamicImportPattern.lastIndex = 0;
    });

    // ===== CHECK FOR COMMON VERSION PATTERNS =====
    // Suggest alternatives when we detect version usage patterns

    if (content.includes('.version') && (content.includes('package') || content.includes('pkg'))) {
      // Check if they're accessing .version from a package.json import
      const versionAccessPattern = /(\w+)\.version/g;
      let match;

      while ((match = versionAccessPattern.exec(content)) !== null) {
        const varName = match[1].toLowerCase();
        if (['package', 'pkg', 'packagejson', 'packageinfo', 'appinfo'].includes(varName)) {
          const lineIdx = content.substring(0, match.index).split('\n').length;

          // Only add if we haven't already flagged an import issue
          const alreadyFlagged = issues.some(i => i.line === lineIdx);
          if (!alreadyFlagged) {
            issues.push({
              severity: 'info',
              rule: 'packagejson-version-access',
              message: `Accessing version from package.json variable. Ensure this is injected at build-time.`,
              line: lineIdx,
              fix: {
                suggestion: `Add to webpack.config.js: new webpack.DefinePlugin({ '__APP_VERSION__': JSON.stringify(require('./package.json').version) })`
              }
            });
          }
        }
      }
    }

    return issues;
  },

  /**
   * Check bundle output for package.json references (post-build check)
   * This is an optional check that can be run on the built bundle
   */
  checkBundle(bundleContent, bundlePath) {
    const issues = [];

    // Look for encoded package.json paths that indicate bundling issues
    const encodedPatterns = [
      /%2Fpackage\.json/gi,           // URL encoded
      /\/package\.json/g,              // Direct path
      /~\/package\.json/g,             // NativeScript alias
      /"package\.json"/g,              // String literal
    ];

    let foundCount = 0;

    for (const pattern of encodedPatterns) {
      const matches = bundleContent.match(pattern);
      if (matches) {
        foundCount += matches.length;
      }
    }

    if (foundCount > 0) {
      issues.push({
        severity: 'error',
        rule: 'bundle-contains-packagejson-ref',
        message: `Bundle contains ${foundCount} reference(s) to package.json. This will cause runtime errors.`,
        file: bundlePath,
        fix: {
          suggestion: 'Find and replace package.json imports in source code with build-time constants'
        }
      });
    }

    return issues;
  }
};
