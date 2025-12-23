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
    const magicNumbers = [...content.matchAll(/[^.\d](\d{4,})[^.\d]/g)];
    magicNumbers.forEach(m => {
      if (m[1] !== '1000' && m[1] !== '1024') { // Common exceptions
        issues.push({
          severity: 'info',
          rule: 'magic-number',
          message: `Magic number ${m[1]} detected; consider using a named constant`
        });
      }
    });

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
    const hardcodedStrings = [...content.matchAll(/['"]([A-Z][a-z]+\s+[a-z]+.*?)['"]/g)];
    if (hardcodedStrings.length > 10 && !filePath.includes('i18n') && !filePath.includes('locale')) {
      issues.push({
        severity: 'info',
        rule: 'hardcoded-strings',
        message: `Found ${hardcodedStrings.length} hardcoded strings; consider using i18n for localization`
      });
    }

    return issues;
  }
};
