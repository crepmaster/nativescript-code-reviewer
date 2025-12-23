module.exports = {
  check(content, filePath) {
    const issues = [];
    // Detect async functions missing await inside (heuristic)
    const asyncFuncs = [...content.matchAll(/async\s+function\s+([A-Za-z_$][\w$]*)\s*\(|([A-Za-z_$][\w$]*)\s*=\s*async\s*\(/g)].map(m => (m[1] || m[2]));
    asyncFuncs.forEach(fn => {
      const bodyMatch = content.match(new RegExp(`async\\s+(?:function\\s+${fn}|${fn}\\s*=\\s*async)\\s*\\((?:[^\\)]*)\\)\\s*\\{([\\s\\S]*?)\\}`));
      if (bodyMatch) {
        const body = bodyMatch[1];
        if (!/\bawait\b/.test(body) && /\bfetch\b|\baxios\b|\.then\(/.test(body)) {
          issues.push({ severity: 'warn', rule: 'async-no-await', message: `Async function '${fn}' contains async calls but no await` });
        }
      }
    });

    // Detect functions declared but never used (heuristic)
    const funcDeclared = [...content.matchAll(/function\s+([A-Za-z_$][\w$]*)\s*\(/g)].map(m => m[1]);
    funcDeclared.forEach(n => {
      const occ = (content.match(new RegExp(`\\b${n}\\b`, 'g')) || []).length;
      if (occ === 1) issues.push({ severity: 'info', rule: 'unused-func', message: `Function '${n}' declared but not used` });
    });

    // Detect missing error handling in promises
    const promises = [...content.matchAll(/\.then\s*\(/g)];
    if (promises.length && !/\.catch\s*\(/.test(content)) {
      issues.push({ severity: 'warn', rule: 'promise-no-catch', message: 'Promises used without catch for errors' });
    }

    return issues;
  }
};
