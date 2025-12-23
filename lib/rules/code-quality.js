module.exports = {
  check(content, filePath) {
    const issues = [];

    // ===== CODE DUPLICATION =====
    // Simple heuristic: detect repeated function patterns
    const funcPatterns = content.match(/function\s+\w+\s*\([^)]*\)\s*{[^}]{50,}}/g) || [];
    if (funcPatterns.length > 3) {
      issues.push({ severity: 'info', rule: 'potential-duplication', message: 'Multiple functions with similar structure detected; consider extracting common logic' });
    }

    // ===== CYCLOMATIC COMPLEXITY =====
    const conditionals = (content.match(/if\s*\(|else\s*if\s*\(|switch\s*\(|case\s+|catch\s*\(/g) || []).length;
    const lines = content.split('\n').length;
    const avgComplexity = lines > 0 ? conditionals / Math.max(lines / 10, 1) : 0;
    
    if (conditionals > 10) {
      issues.push({ severity: 'warn', rule: 'high-complexity', message: `High cyclomatic complexity detected (${conditionals} conditionals); consider breaking into smaller functions` });
    }

    // ===== MAGIC NUMBERS =====
    const magicNumbers = content.match(/[^a-zA-Z_]\s*\d{3,}\s*[;,)\]}]/g) || [];
    if (magicNumbers.length > 5) {
      issues.push({ severity: 'info', rule: 'magic-numbers', message: `${magicNumbers.length} magic numbers detected; extract to named constants` });
    }

    // ===== FUNCTION LENGTH =====
    const functions = content.match(/function\s+\w+\s*\([^)]*\)\s*{/g) || [];
    functions.forEach((func, i) => {
      const startIdx = content.indexOf(func);
      const endIdx = content.indexOf('}', startIdx);
      if (endIdx > 0) {
        const funcBody = content.substring(startIdx, endIdx);
        const lineCount = funcBody.split('\n').length;
        if (lineCount > 50) {
          const funcName = func.match(/function\s+(\w+)/)[1];
          issues.push({ severity: 'warn', rule: 'oversized-function', message: `Function '${funcName}' is ${lineCount} lines; consider breaking into smaller functions` });
        }
      }
    });

    // ===== NAMING CONVENTIONS =====
    // Check for non-descriptive names
    if (/\b(x|y|z|a|b|c|d|tmp|temp|data|obj|val)\s*[:=][\s\S]{1,}/i.test(content)) {
      const count = (content.match(/\b(x|y|z|a|b|c|d|tmp|temp|data|obj|val)\s*[:=]/gi) || []).length;
      if (count > 3) {
        issues.push({ severity: 'info', rule: 'poor-naming', message: `${count} non-descriptive variable names detected; use meaningful names (e.g., userId, totalPrice)` });
      }
    }

    // ===== MISSING COMMENTS =====
    const codeLines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('//') && !l.trim().startsWith('*')).length;
    const commentLines = (content.match(/\/\/|\/\*|\*\//g) || []).length;
    
    if (codeLines > 50 && commentLines < 2) {
      issues.push({ severity: 'info', rule: 'insufficient-comments', message: 'Large file with few comments; consider adding documentation for complex logic' });
    }

    // ===== ARROW FUNCTIONS vs FUNCTION =====
    if (/\bfunction\s+\w+\s*\([^)]*\)\s*{/.test(content) && /=>\s*{/.test(content)) {
      issues.push({ severity: 'info', rule: 'mixed-function-style', message: 'Both function declarations and arrow functions used; consider consistent style' });
    }

    // ===== TODOs & FIXMEs =====
    const todos = content.match(/\/\/\s*(TODO|FIXME|BUG|HACK|XXX|NOTE)\s*[:]*\s*(.+)/gi) || [];
    if (todos.length > 0) {
      issues.push({ severity: 'warn', rule: 'unresolved-todos', message: `Found ${todos.length} TODO/FIXME/BUG comments; resolve or track them` });
    }

    // ===== DEPRECATED PATTERNS =====
    if (/\.bind\(this\)|var\s+\w+\s*=\s*function|prototype\./.test(content)) {
      issues.push({ severity: 'info', rule: 'deprecated-pattern', message: 'Deprecated JS patterns detected; consider modern alternatives (arrow functions, class syntax)' });
    }

    // ===== ERROR HANDLING =====
    const tryBlocks = (content.match(/try\s*{/g) || []).length;
    const catchBlocks = (content.match(/catch\s*\(/g) || []).length;
    
    if (tryBlocks > 0 && tryBlocks !== catchBlocks) {
      issues.push({ severity: 'warn', rule: 'unmatched-try-catch', message: 'Try blocks without corresponding catch detected; add error handling' });
    }

    // Empty catch blocks
    if (/catch\s*\([^)]*\)\s*{[\s]*}/g.test(content)) {
      issues.push({ severity: 'warn', rule: 'empty-catch', message: 'Empty catch block detected; add logging or error handling' });
    }

    return issues;
  }
};
