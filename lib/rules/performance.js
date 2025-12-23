module.exports = {
  check(content, filePath) {
    const issues = [];

    // ===== UNNECESSARY OPERATIONS =====
    // Check for duplicate imports
    const imports = [...content.matchAll(/import\s+.*?from\s+['\"]([^'\"]+)['\"]/g)].map(m => m[1]);
    const importCounts = {};
    imports.forEach(imp => {
      importCounts[imp] = (importCounts[imp] || 0) + 1;
    });
    Object.entries(importCounts).forEach(([imp, count]) => {
      if (count > 1) issues.push({ severity: 'warn', rule: 'duplicate-import', message: `Module '${imp}' imported ${count} times` });
    });

    // ===== SYNCHRONOUS OPERATIONS =====
    if (/readFileSync|writeFileSync|readdirSync|JSON\.parse.*readFileSync/.test(content)) {
      issues.push({ severity: 'warn', rule: 'sync-io', message: 'Synchronous file I/O detected; use async methods to avoid blocking' });
    }

    // ===== UNOPTIMIZED LOOPS =====
    const loops = content.match(/for\s*\(\s*(?:let|const|var)\s+\w+\s+in\s+\w+\s*\)|\.forEach\s*\([^)]*\)\s*{[^}]*}/g) || [];
    if (loops.length > 0) {
      loops.forEach(loop => {
        if (/JSON\.stringify|JSON\.parse|fetch|http\.request/.test(loop)) {
          issues.push({ severity: 'warn', rule: 'heavy-loop', message: 'Heavy operation detected in loop; consider batching or optimization' });
        }
      });
    }

    // ===== IMAGE & ASSET HANDLING =====
    if (/(Image|ImageSource|BitmapFactory|\.jpg|\.png|\.gif)/.test(content)) {
      if (!/dispose|recycle|gc|cleanup/.test(content)) {
        issues.push({ severity: 'warn', rule: 'image-memory-leak', message: 'Image handling detected without apparent cleanup; ensure proper disposal' });
      }
    }

    // ===== LARGE COLLECTIONS =====
    if (/\.map\s*\(|\.filter\s*\(|\.reduce\s*\(/.test(content)) {
      // Check if chained without intermediate assignment
      if (/\.map\s*\([^)]*\)\s*\.\s*(?:map|filter|reduce)/.test(content)) {
        issues.push({ severity: 'info', rule: 'chain-optimization', message: 'Chained array operations detected; consider combining into single pass for performance' });
      }
    }

    // ===== REGEX COMPLEXITY =====
    const complexRegex = content.match(/\/[^\/]{50,}\/[gimuy]*/g);
    if (complexRegex) {
      issues.push({ severity: 'info', rule: 'complex-regex', message: 'Complex regex patterns detected; verify performance on large inputs' });
    }

    // ===== RENDERING & DOM =====
    if (/innerHTML\s*\+=/g.test(content)) {
      issues.push({ severity: 'warn', rule: 'dom-append-loop', message: 'innerHTML with += in loop detected; may cause re-rendering; use append or build string first' });
    }

    // ===== MEMORY ALLOCATION =====
    if (/(new Array|new Object|new String|new Number|new Boolean)[\s\(]/.test(content)) {
      issues.push({ severity: 'warn', rule: 'object-wrapper', message: 'Unnecessary object wrapper types detected; use primitives [] {} "" instead' });
    }

    return issues;
  }
};
