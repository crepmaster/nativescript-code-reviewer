/**
 * NativeScript Entry Point Sanity Check
 *
 * BLOCKER-level rule that detects runtime boot failures BEFORE running the app.
 *
 * This rule catches the infamous crash:
 *   "Failed to find module: './', relative to: app//"
 *
 * BLOCKER findings (severity: 'blocker'):
 * 1. Missing entry point (no app/main.ts|js AND no valid package.json main)
 * 2. package.json main equals "./" or empty string
 * 3. Resolved entry file does not exist
 * 4. Entry file exists but does not contain Application.run(...)
 * 5. moduleName target (e.g., app-root) does not exist
 *
 * Fingerprint format: ns-entrypoint-sanity:key:reason (human-readable)
 *
 * Supported source directories: app/ (default) or src/
 *
 * Limitations:
 * - Application.run detection uses regex, may miss dynamic patterns like:
 *   Application.run({ moduleName: getModuleName() })
 * - Some projects use Application.run() without moduleName (code-only bootstrap)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Generate stable, human-readable fingerprint for a finding.
 * Format: ruleId:key:reason (e.g., "ns-entrypoint-sanity:main:./:invalid-main")
 */
function makeFingerprint(ruleId, key, reason) {
  // Sanitize key to be URL-safe (replace special chars)
  const safeKey = String(key).replace(/[^a-zA-Z0-9._/-]/g, '_').substring(0, 50);
  return `${ruleId}:${safeKey}:${reason}`;
}

/**
 * Check if a file exists and is a file (not directory)
 */
function fileExists(filePath) {
  try {
    return fs.existsSync(filePath) && fs.statSync(filePath).isFile();
  } catch (e) {
    return false;
  }
}

/**
 * Try to resolve a module path with extensions
 */
function resolveModule(basePath, moduleName) {
  const extensions = ['', '.ts', '.js', '.tsx', '.jsx'];

  for (const ext of extensions) {
    const fullPath = path.join(basePath, moduleName + ext);
    if (fileExists(fullPath)) {
      return fullPath;
    }
  }

  // Check for index files in directory
  const dirPath = path.join(basePath, moduleName);
  try {
    if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
      for (const ext of ['.ts', '.js', '.tsx', '.jsx']) {
        const indexPath = path.join(dirPath, 'index' + ext);
        if (fileExists(indexPath)) {
          return indexPath;
        }
      }
    }
  } catch (e) {}

  return null;
}

/**
 * Check if content contains Application.run call
 */
function hasApplicationRun(content) {
  return /Application\.run\s*\(/i.test(content) ||
         /application\.run\s*\(/i.test(content);
}

/**
 * Extract moduleName from Application.run({ moduleName: "..." })
 */
function extractModuleName(content) {
  const match = content.match(/Application\.run\s*\(\s*{\s*moduleName\s*:\s*["']([^"']+)["']/i);
  return match ? match[1] : null;
}

/**
 * Parse app-root.xml to find defaultPage references
 */
function parseAppRootXml(content) {
  const pages = [];
  const frameMatch = content.match(/defaultPage\s*=\s*["']([^"']+)["']/gi);
  if (frameMatch) {
    frameMatch.forEach(m => {
      const pageMatch = m.match(/["']([^"']+)["']/);
      if (pageMatch) {
        pages.push(pageMatch[1]);
      }
    });
  }
  return pages;
}

/**
 * Main project-level entry point check
 * Returns array of findings with stable fingerprints
 */
function checkProject(projectRoot) {
  const issues = [];

  const appDir = path.join(projectRoot, 'app');
  const srcDir = path.join(projectRoot, 'src');
  const sourceDir = fs.existsSync(appDir) ? appDir : (fs.existsSync(srcDir) ? srcDir : null);

  // 1. Check package.json exists
  const packageJsonPath = path.join(projectRoot, 'package.json');
  if (!fileExists(packageJsonPath)) {
    issues.push({
      severity: 'blocker',
      rule: 'ns-entrypoint-sanity',
      message: 'package.json not found. NativeScript cannot determine entry point.',
      file: 'package.json',
      remediation: 'Create package.json with "main": "app/main.ts" or "main": "app/app.ts"',
      fingerprint: makeFingerprint('ns-entrypoint-sanity', 'package.json', 'missing')
    });
    return issues;
  }

  // Parse package.json
  let packageJson;
  try {
    packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  } catch (e) {
    issues.push({
      severity: 'blocker',
      rule: 'ns-entrypoint-sanity',
      message: `package.json parse error: ${e.message}`,
      file: 'package.json',
      remediation: 'Fix JSON syntax errors in package.json',
      fingerprint: makeFingerprint('ns-entrypoint-sanity', 'package.json', 'parse-error')
    });
    return issues;
  }

  // Check if this is a NativeScript project
  if (!packageJson.nativescript) {
    return issues; // Not a NativeScript project, skip
  }

  // 2. Determine entry point
  const mainField = packageJson.main || packageJson.nativescript?.main || null;

  // Check for INVALID main values - BLOCKER
  if (mainField === './' || mainField === '.' || mainField === '') {
    issues.push({
      severity: 'blocker',
      rule: 'ns-entrypoint-sanity',
      message: `package.json "main" is "${mainField}" which causes runtime crash: "Failed to find module: './', relative to: app//"`,
      file: 'package.json',
      remediation: 'Change "main" to "app/main.ts" or "app/app.ts"',
      fingerprint: makeFingerprint('ns-entrypoint-sanity', mainField, 'invalid-main')
    });
    return issues;
  }

  // 3. Resolve the entry file
  let entryFile = null;

  if (mainField) {
    // Skip bundle.js/bundle.mjs as those are generated at build time
    if (/^bundle(\.(js|mjs))?$/.test(mainField)) {
      // For bundled projects, we need to check the source entry
      if (sourceDir) {
        const sourceEntries = ['main.ts', 'app.ts', 'main.js', 'app.js'];
        for (const ef of sourceEntries) {
          const fullPath = path.join(sourceDir, ef);
          if (fileExists(fullPath)) {
            entryFile = fullPath;
            break;
          }
        }
      }
    } else {
      // Try to resolve the main field as a path
      const mainPath = path.join(projectRoot, mainField);
      if (fileExists(mainPath)) {
        entryFile = mainPath;
      } else {
        // Try with extensions
        const resolved = resolveModule(projectRoot, mainField.replace(/\.(ts|js|tsx|jsx)$/, ''));
        if (resolved) {
          entryFile = resolved;
        } else {
          // Main field points to non-existent file - BLOCKER
          issues.push({
            severity: 'blocker',
            rule: 'ns-entrypoint-sanity',
            message: `package.json "main" points to "${mainField}" but file does not exist`,
            file: 'package.json',
            remediation: `Create ${mainField} or change "main" to an existing file (e.g., "app/app.ts")`,
            fingerprint: makeFingerprint('ns-entrypoint-sanity', mainField, 'file-not-found')
          });
          return issues;
        }
      }
    }
  }

  // 4. If no main field, check for default entry files
  if (!entryFile && sourceDir) {
    const defaultEntries = ['main.ts', 'app.ts', 'main.js', 'app.js'];
    for (const ef of defaultEntries) {
      const fullPath = path.join(sourceDir, ef);
      if (fileExists(fullPath)) {
        entryFile = fullPath;
        break;
      }
    }
  }

  // 5. No entry file found at all - BLOCKER
  if (!entryFile) {
    issues.push({
      severity: 'blocker',
      rule: 'ns-entrypoint-sanity',
      message: 'No entry point found. Missing package.json "main" AND no app/main.ts, app/app.ts exists.',
      file: sourceDir ? path.relative(projectRoot, sourceDir) : 'app',
      remediation: 'Create app/main.ts with:\n  import { Application } from "@nativescript/core";\n  Application.run({ moduleName: "app-root" });',
      fingerprint: makeFingerprint('ns-entrypoint-sanity', 'entrypoint', 'missing')
    });
    return issues;
  }

  // 6. Entry file exists - check for Application.run
  // Note: Some projects use code-only bootstrap without moduleName, so this is a warning
  try {
    const content = fs.readFileSync(entryFile, 'utf8');
    const relPath = path.relative(projectRoot, entryFile);

    if (!hasApplicationRun(content)) {
      // Check for alternative bootstrap patterns (NativeScript-Vue, NativeScript-Angular, etc.)
      const hasAlternativeBootstrap =
        /platformNativeScript|bootstrapApplication|createApp|NativeScriptModule/i.test(content);

      if (!hasAlternativeBootstrap) {
        issues.push({
          severity: 'warn',
          rule: 'ns-entrypoint-sanity',
          message: `Entry file "${relPath}" does not appear to call Application.run() or alternative bootstrap. App may not start.`,
          file: relPath,
          remediation: 'Add Application.run({ moduleName: "app-root" }) or use framework-specific bootstrap',
          fingerprint: makeFingerprint('ns-entrypoint-sanity', relPath, 'no-application-run')
        });
      }
    } else {
      // Check if moduleName is valid
      const moduleName = extractModuleName(content);
      if (moduleName && sourceDir) {
        // Verify the module exists (check .xml, .ts, .js)
        const moduleXml = path.join(sourceDir, moduleName + '.xml');
        const moduleTs = path.join(sourceDir, moduleName + '.ts');
        const moduleJs = path.join(sourceDir, moduleName + '.js');

        if (!fileExists(moduleXml) && !fileExists(moduleTs) && !fileExists(moduleJs)) {
          issues.push({
            severity: 'blocker',
            rule: 'ns-entrypoint-sanity',
            message: `Application.run references moduleName "${moduleName}" but neither ${moduleName}.xml, ${moduleName}.ts, nor ${moduleName}.js exists`,
            file: relPath,
            remediation: `Create app/${moduleName}.xml with <Frame defaultPage="pages/main-page" />`,
            fingerprint: makeFingerprint('ns-entrypoint-sanity', moduleName, 'module-not-found')
          });
        } else if (fileExists(moduleXml)) {
          // Check defaultPage in the XML
          try {
            const xmlContent = fs.readFileSync(moduleXml, 'utf8');
            const pages = parseAppRootXml(xmlContent);

            for (const page of pages) {
              const pageXml = path.join(sourceDir, page + '.xml');
              const pageTs = path.join(sourceDir, page + '.ts');
              const pageJs = path.join(sourceDir, page + '.js');
              const pageDir = path.join(sourceDir, page);

              const pageExists = fileExists(pageXml) ||
                                 fileExists(pageTs) ||
                                 fileExists(pageJs) ||
                                 (fs.existsSync(pageDir) && fs.statSync(pageDir).isDirectory());

              if (!pageExists) {
                issues.push({
                  severity: 'blocker',
                  rule: 'ns-entrypoint-sanity',
                  message: `${moduleName}.xml references defaultPage="${page}" but the module does not exist`,
                  file: `app/${moduleName}.xml`,
                  remediation: `Create ${page}.xml and ${page}.ts or update defaultPage to an existing page`,
                  fingerprint: makeFingerprint('ns-entrypoint-sanity', page, 'default-page-not-found')
                });
              }
            }
          } catch (e) {
            // XML read error, skip
          }
        }
      }
    }
  } catch (e) {
    const relPath = path.relative(projectRoot, entryFile);
    issues.push({
      severity: 'warn',
      rule: 'ns-entrypoint-sanity',
      message: `Could not read entry file: ${e.message}`,
      file: relPath,
      fingerprint: makeFingerprint('ns-entrypoint-sanity', relPath, 'read-error')
    });
  }

  return issues;
}

/**
 * File-level check (for package.json analysis during regular scan)
 */
function check(content, filePath) {
  const issues = [];
  const fileName = path.basename(filePath).toLowerCase();

  // Only check package.json at file level
  if (fileName !== 'package.json') {
    return issues;
  }

  let pkg;
  try {
    pkg = JSON.parse(content);
  } catch (e) {
    return issues; // Skip invalid JSON
  }

  // Only check NativeScript projects
  if (!pkg.nativescript) {
    return issues;
  }

  const mainField = pkg.main;

  // Check for BLOCKER conditions
  if (mainField === './' || mainField === '.' || mainField === '') {
    issues.push({
      severity: 'blocker',
      rule: 'ns-entrypoint-sanity',
      message: `"main" is "${mainField}" - this causes "Failed to find module: './', relative to: app//"`,
      remediation: 'Change "main" to "app/main.ts" or "app/app.ts"',
      fingerprint: makeFingerprint('ns-entrypoint-sanity', mainField, 'invalid-main')
    });
  }

  return issues;
}

module.exports = {
  check,
  checkProject,
  hasApplicationRun,
  extractModuleName,
  parseAppRootXml,
  makeFingerprint
};
