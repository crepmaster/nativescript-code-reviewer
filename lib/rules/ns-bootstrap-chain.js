/**
 * NativeScript Bootstrap Chain Validation
 *
 * Validates the boot sequence of a NativeScript application:
 * 1. Entry file (app.ts/main.ts) imports and initialization order
 * 2. Detection of potential circular dependencies in boot files
 * 3. Case sensitivity issues in import paths (Windows vs Linux)
 * 4. Missing module resolution in the boot chain
 *
 * This is a static analysis - it doesn't execute any code.
 */

const fs = require('fs');
const path = require('path');

/**
 * Extract imports from TypeScript/JavaScript content
 */
function extractImports(content) {
  const imports = [];

  // ES6 imports: import X from 'path' or import { X } from 'path'
  const es6Pattern = /import\s+(?:(?:\*\s+as\s+\w+|{\s*[^}]+\s*}|\w+)\s+from\s+)?["']([^"']+)["']/g;
  let match;
  while ((match = es6Pattern.exec(content)) !== null) {
    imports.push({
      type: 'import',
      path: match[1],
      raw: match[0]
    });
  }

  // CommonJS require: require('path')
  const cjsPattern = /require\s*\(\s*["']([^"']+)["']\s*\)/g;
  while ((match = cjsPattern.exec(content)) !== null) {
    imports.push({
      type: 'require',
      path: match[1],
      raw: match[0]
    });
  }

  // Dynamic imports: import('path')
  const dynamicPattern = /import\s*\(\s*["']([^"']+)["']\s*\)/g;
  while ((match = dynamicPattern.exec(content)) !== null) {
    imports.push({
      type: 'dynamic',
      path: match[1],
      raw: match[0]
    });
  }

  return imports;
}

/**
 * Check if an import path is relative
 */
function isRelativeImport(importPath) {
  return importPath.startsWith('./') || importPath.startsWith('../');
}

/**
 * Resolve a relative import path to an absolute file path
 */
function resolveImportPath(importPath, currentFile, projectRoot) {
  if (!isRelativeImport(importPath)) {
    return null; // Node module, can't resolve locally
  }

  const currentDir = path.dirname(currentFile);
  let resolved = path.resolve(currentDir, importPath);

  // Try various extensions
  const extensions = ['', '.ts', '.tsx', '.js', '.jsx', '.json'];

  for (const ext of extensions) {
    const fullPath = resolved + ext;
    if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
      return fullPath;
    }
  }

  // Check for index file in directory
  if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
    for (const ext of ['.ts', '.tsx', '.js', '.jsx']) {
      const indexPath = path.join(resolved, 'index' + ext);
      if (fs.existsSync(indexPath)) {
        return indexPath;
      }
    }
  }

  return null;
}

/**
 * Check for case sensitivity issues in imports
 * Windows is case-insensitive but Linux/Android runtime is case-sensitive
 */
function checkCaseSensitivity(importPath, currentFile, projectRoot) {
  if (!isRelativeImport(importPath)) {
    return null;
  }

  const currentDir = path.dirname(currentFile);
  const targetPath = path.resolve(currentDir, importPath);
  const targetDir = path.dirname(targetPath);
  const targetName = path.basename(targetPath);

  if (!fs.existsSync(targetDir)) {
    return null;
  }

  try {
    const files = fs.readdirSync(targetDir);
    const lowerTarget = targetName.toLowerCase();

    // Find files that match case-insensitively
    const matches = files.filter(f => {
      const base = f.replace(/\.(ts|tsx|js|jsx)$/, '');
      return base.toLowerCase() === lowerTarget ||
             f.toLowerCase() === lowerTarget;
    });

    // Check if there's a case mismatch
    for (const match of matches) {
      const baseName = match.replace(/\.(ts|tsx|js|jsx)$/, '');
      if (baseName !== targetName && baseName.toLowerCase() === lowerTarget) {
        return {
          expected: targetName,
          actual: baseName,
          file: match
        };
      }
    }
  } catch (e) {
    return null;
  }

  return null;
}

/**
 * Build dependency graph starting from entry file
 */
function buildDependencyGraph(entryFile, projectRoot, maxDepth = 10) {
  const graph = new Map(); // file -> Set<imported files>
  const visited = new Set();
  const queue = [{ file: entryFile, depth: 0 }];

  while (queue.length > 0) {
    const { file, depth } = queue.shift();

    if (visited.has(file) || depth > maxDepth) {
      continue;
    }
    visited.add(file);

    if (!fs.existsSync(file)) {
      continue;
    }

    try {
      const content = fs.readFileSync(file, 'utf8');
      const imports = extractImports(content);
      const dependencies = new Set();

      for (const imp of imports) {
        if (isRelativeImport(imp.path)) {
          const resolved = resolveImportPath(imp.path, file, projectRoot);
          if (resolved) {
            dependencies.add(resolved);
            queue.push({ file: resolved, depth: depth + 1 });
          }
        }
      }

      graph.set(file, dependencies);
    } catch (e) {
      // Skip files that can't be read
    }
  }

  return graph;
}

/**
 * Detect circular dependencies in the dependency graph
 */
function detectCircularDependencies(graph, startFile) {
  const cycles = [];
  const visited = new Set();
  const stack = [];

  function dfs(file) {
    if (stack.includes(file)) {
      // Found a cycle
      const cycleStart = stack.indexOf(file);
      cycles.push(stack.slice(cycleStart).concat(file));
      return;
    }

    if (visited.has(file)) {
      return;
    }

    visited.add(file);
    stack.push(file);

    const deps = graph.get(file) || new Set();
    for (const dep of deps) {
      dfs(dep);
    }

    stack.pop();
  }

  dfs(startFile);
  return cycles;
}

/**
 * Check a single source file for bootstrap issues
 */
function check(content, filePath) {
  const issues = [];
  const fileName = path.basename(filePath).toLowerCase();

  // Only check entry files deeply
  const isEntryFile = ['app.ts', 'main.ts', 'app.js', 'main.js'].includes(fileName);

  if (!isEntryFile) {
    return issues;
  }

  const imports = extractImports(content);

  // Check for problematic imports in entry file
  for (const imp of imports) {
    // Check for circular-prone patterns in entry file
    if (isRelativeImport(imp.path)) {
      // Entry file importing from services that import from entry is risky
      if (/services|utils|helpers/.test(imp.path)) {
        issues.push({
          severity: 'info',
          rule: 'ns-entry-imports-services',
          message: `Entry file imports from ${imp.path} - ensure no circular dependencies exist`,
          line: getLineNumber(content, imp.raw)
        });
      }
    }

    // Check for dynamic imports at app startup (may cause issues)
    if (imp.type === 'dynamic') {
      issues.push({
        severity: 'warn',
        rule: 'ns-entry-dynamic-import',
        message: 'Dynamic import in entry file may cause timing issues at app startup',
        line: getLineNumber(content, imp.raw)
      });
    }
  }

  // Check for Application.run with invalid moduleName
  const runMatch = content.match(/Application\.run\s*\(\s*{[^}]*moduleName\s*:\s*["']([^"']+)["']/);
  if (runMatch) {
    const moduleName = runMatch[1];
    if (moduleName === './' || moduleName === '.' || moduleName === '') {
      issues.push({
        severity: 'high',
        rule: 'ns-invalid-module-name',
        message: `Application.run has invalid moduleName: "${moduleName}"`,
        remediation: 'Use a valid module name like "app-root"'
      });
    }
  }

  return issues;
}

/**
 * Get line number for a match in content
 */
function getLineNumber(content, match) {
  const index = content.indexOf(match);
  if (index === -1) return undefined;
  return content.substring(0, index).split('\n').length;
}

/**
 * Project-level bootstrap chain validation
 */
function checkProject(projectRoot) {
  const issues = [];

  const appDir = path.join(projectRoot, 'app');
  const srcDir = path.join(projectRoot, 'src');
  const sourceDir = fs.existsSync(appDir) ? appDir : (fs.existsSync(srcDir) ? srcDir : null);

  if (!sourceDir) {
    return issues;
  }

  // Find entry file
  const entryFiles = ['main.ts', 'app.ts', 'main.js', 'app.js'];
  let entryFile = null;

  for (const ef of entryFiles) {
    const fullPath = path.join(sourceDir, ef);
    if (fs.existsSync(fullPath)) {
      entryFile = fullPath;
      break;
    }
  }

  if (!entryFile) {
    issues.push({
      severity: 'high',
      rule: 'ns-no-entry-file',
      message: 'No entry file found (app.ts, main.ts, app.js, or main.js)',
      file: sourceDir,
      remediation: 'Create app/main.ts with Application.run({ moduleName: "app-root" })'
    });
    return issues;
  }

  // Check entry file content
  try {
    const content = fs.readFileSync(entryFile, 'utf8');
    const fileIssues = check(content, entryFile);
    issues.push(...fileIssues.map(i => ({
      ...i,
      file: path.relative(projectRoot, entryFile)
    })));

    // Check imports for case sensitivity issues
    const imports = extractImports(content);
    for (const imp of imports) {
      if (isRelativeImport(imp.path)) {
        const caseMismatch = checkCaseSensitivity(imp.path, entryFile, projectRoot);
        if (caseMismatch) {
          issues.push({
            severity: 'high',
            rule: 'ns-case-sensitivity',
            message: `Import "${imp.path}" has case mismatch: expected "${caseMismatch.actual}" but got "${caseMismatch.expected}". This may work on Windows but fail on Android/Linux.`,
            file: path.relative(projectRoot, entryFile),
            remediation: `Change import to use correct case: "${caseMismatch.actual}"`
          });
        }

        // Check if import resolves
        const resolved = resolveImportPath(imp.path, entryFile, projectRoot);
        if (!resolved) {
          issues.push({
            severity: 'high',
            rule: 'ns-unresolved-import',
            message: `Import "${imp.path}" cannot be resolved - file does not exist`,
            file: path.relative(projectRoot, entryFile),
            remediation: `Create the missing file or fix the import path`
          });
        }
      }
    }

    // Build dependency graph and check for cycles
    const graph = buildDependencyGraph(entryFile, projectRoot, 5);
    const cycles = detectCircularDependencies(graph, entryFile);

    if (cycles.length > 0) {
      cycles.forEach(cycle => {
        const cyclePath = cycle.map(f => path.relative(projectRoot, f)).join(' -> ');
        issues.push({
          severity: 'warn',
          rule: 'ns-circular-dependency',
          message: `Circular dependency detected in boot chain: ${cyclePath}`,
          file: path.relative(projectRoot, entryFile),
          remediation: 'Refactor to break the circular dependency - this may cause issues at startup'
        });
      });
    }

  } catch (e) {
    issues.push({
      severity: 'warn',
      rule: 'ns-entry-read-error',
      message: `Could not read entry file: ${e.message}`,
      file: path.relative(projectRoot, entryFile)
    });
  }

  return issues;
}

module.exports = {
  check,
  checkProject,
  extractImports,
  checkCaseSensitivity,
  buildDependencyGraph,
  detectCircularDependencies
};
