module.exports = {
  check(content, filePath) {
    const issues = [];

    // Skip TypeScript/JavaScript import lines and type definitions
    const codeWithoutImports = content
      .replace(/^import\s+.*$/gm, '')
      .replace(/^export\s+(type|interface)\s+.*$/gm, '')
      .replace(/^export\s+\{.*\}.*$/gm, '');

    // Detect var usage (should use let/const)
    const varMatches = [...codeWithoutImports.matchAll(/\bvar\s+(\w+)/g)];
    varMatches.forEach(m => issues.push({
      severity: 'warn',
      rule: 'no-var',
      message: `Use let/const instead of var for '${m[1]}'`
    }));

    // Detect console.log in production code (should be removed or use proper logging)
    if (!/\.test\.|\.spec\.|test\.ts|spec\.ts/i.test(filePath)) {
      const consoleLogs = [...content.matchAll(/console\.(log|warn|error|debug|info)\s*\(/g)];
      if (consoleLogs.length > 5) {
        issues.push({
          severity: 'info',
          rule: 'too-many-console',
          message: `Found ${consoleLogs.length} console statements; consider using a logging service`
        });
      }
    }

    // Detect any type usage in TypeScript
    const anyTypes = [...content.matchAll(/:\s*any\b/g)];
    if (anyTypes.length > 0) {
      issues.push({
        severity: 'warn',
        rule: 'no-any',
        message: `Found ${anyTypes.length} 'any' type usage(s); prefer specific types for better type safety`
      });
    }

    // Detect magic numbers (numbers used directly without being assigned to const)
    // More targeted: look for numbers in comparisons, timeouts, sizes, etc.
    // Skip: years (19xx, 20xx), common values, array indices, port numbers
    const commonExceptions = new Set([
      '0', '1', '2', '3', '4', '5', '10', '100', '1000', '1024',
      '60', '24', '365', '7', '12', '30', '31', // time units
      '200', '201', '204', '400', '401', '403', '404', '500', '502', '503', // HTTP status
      '80', '443', '8080', '3000', '8000', // common ports
    ]);
    // Match numbers in contexts like: setTimeout(..., 5000), width: 300, size > 1000
    const magicContexts = [...content.matchAll(/(?:timeout|delay|duration|interval|width|height|size|max|min|limit|count)\s*[=:,]\s*(\d+)/gi)];
    const uniqueMagic = new Set();
    magicContexts.forEach(m => {
      const num = m[1];
      if (!commonExceptions.has(num) && !/^(19|20)\d{2}$/.test(num)) { // Skip years
        uniqueMagic.add(num);
      }
    });
    if (uniqueMagic.size > 3) {
      issues.push({
        severity: 'info',
        rule: 'magic-numbers',
        message: `${uniqueMagic.size} magic numbers detected; extract to named constants`
      });
    }

    // Detect TODO/FIXME comments
    const todos = [...content.matchAll(/\/\/\s*(TODO|FIXME|HACK|XXX)[\s:](.{0,50})/gi)];
    todos.forEach(m => issues.push({
      severity: 'info',
      rule: 'todo-comment',
      message: `${m[1].toUpperCase()}: ${m[2].trim()}`
    }));

    // Detect empty catch blocks
    const emptyCatch = content.match(/catch\s*\([^)]*\)\s*\{\s*\}/g);
    if (emptyCatch) {
      issues.push({
        severity: 'warn',
        rule: 'empty-catch',
        message: `Empty catch block detected; handle or log errors appropriately`
      });
    }

    // Detect potential null reference issues
    const unsafeAccess = [...content.matchAll(/(\w+)\.[a-zA-Z]+\s*\(/g)];
    // This is too noisy, skip for now

    // Detect hardcoded strings that might need i18n
    // Only flag UI-facing strings in XML or component files, not in services/utilities
    const isUIFile = /page\.ts|component\.ts|\.xml$/i.test(filePath);
    if (isUIFile && !filePath.includes('i18n') && !filePath.includes('locale') && !filePath.includes('translations')) {
      // Look for user-visible strings (sentences with spaces, button labels, etc.)
      const uiStrings = [...content.matchAll(/(?:text|title|label|message|placeholder|hint)\s*[=:]\s*['"]([A-Z][a-zA-Z\s]{10,})['"]/g)];
      if (uiStrings.length > 5) {
        issues.push({
          severity: 'info',
          rule: 'hardcoded-strings',
          message: `Found ${uiStrings.length} hardcoded UI strings; consider using i18n for localization`
        });
      }
    }

    return issues;
  }
};
