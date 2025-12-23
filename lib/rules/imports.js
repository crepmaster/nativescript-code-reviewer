const path = require('path');
module.exports = {
  check(content, filePath) {
    const issues = [];
    // Find import/require names
    const imports = [...content.matchAll(/import\s+(?:.+\s+from\s+)?['\"]([^'\"]+)['\"]/g)].map(m => m[1])
      .concat([...content.matchAll(/require\(['\"]([^'\"]+)['\"]\)/g)].map(m => m[1]));

    // Detect relative paths that go up beyond root (heuristic)
    imports.forEach(p => {
      if (p.startsWith('.')) {
        const ups = (p.match(/\.\./g) || []).length;
        if (ups > 3) issues.push({ severity: 'warn', rule: 'deep-relative-import', message: `Deep relative import '${p}' - consider reorganizing or using alias` });
      }
    });

    // Simple unused import detection: compare imported identifiers vs usage (limited)
    const namedImports = [...content.matchAll(/import\s+\{([^}]+)\}\s+from\s+['\"][^'\"]+['\"]/g)].flatMap(m => m[1].split(',').map(s => s.trim()));
    namedImports.forEach(name => {
      if (!new RegExp(`\\b${name}\\b`).test(content)) issues.push({ severity: 'info', rule: 'unused-import', message: `Imported '${name}' but not used` });
    });

    return issues;
  }
};
