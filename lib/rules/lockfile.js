/**
 * lockfile.js - Lockfile and engines coherence checks
 *
 * Detects CI/deployment issues:
 * - Missing lockfile (npm ci fails)
 * - Lockfile parse errors
 * - packageManager mismatch with lockfile type
 * - Non-reproducible dependencies (file:, git+ssh:)
 * - Overly strict engine requirements
 */

const fs = require('fs');
const path = require('path');

module.exports = {
  /**
   * Check lockfile coherence
   * @param {string} content - package.json content
   * @param {string} filePath - Path to package.json
   * @param {object} opts - Options including root directory
   */
  check(content, filePath, opts = {}) {
    const issues = [];

    // Only process package.json
    if (!filePath.endsWith('package.json')) {
      return issues;
    }

    let pkg;
    try {
      pkg = JSON.parse(content);
    } catch (e) {
      // package-json.js already handles parse errors
      return issues;
    }

    // Determine root directory
    const root = opts.root || path.dirname(filePath);

    // ===== B1: LOCKFILE PRESENCE =====
    const lockfiles = {
      'package-lock.json': 'npm',
      'pnpm-lock.yaml': 'pnpm',
      'yarn.lock': 'yarn',
      'bun.lockb': 'bun'
    };

    let foundLockfile = null;
    let foundLockfileType = null;

    for (const [lockName, manager] of Object.entries(lockfiles)) {
      const lockPath = path.join(root, lockName);
      if (fs.existsSync(lockPath)) {
        foundLockfile = lockPath;
        foundLockfileType = manager;
        break;
      }
    }

    if (!foundLockfile) {
      issues.push({
        severity: 'high',
        rule: 'lockfile-missing',
        message: 'No lockfile found (package-lock.json, yarn.lock, pnpm-lock.yaml). CI installs will fail or be non-reproducible.',
        fix: {
          suggestion: 'Run `npm install` and commit the generated package-lock.json'
        }
      });
    }

    // ===== B2: ENGINES COHERENCE =====
    if (pkg.engines) {
      // Check for overly strict Node version
      if (pkg.engines.node) {
        const nodeEngine = pkg.engines.node;

        // Detect exact version pins (very strict)
        if (/^\d+\.\d+\.\d+$/.test(nodeEngine)) {
          issues.push({
            severity: 'warn',
            rule: 'engines-node-strict',
            message: `Node engine "${nodeEngine}" is pinned to exact version. Consider using semver range (e.g., ">=18.0.0").`,
            evidence: `engines.node: "${nodeEngine}"`
          });
        }

        // Detect very specific patch versions with >=
        if (/^>=\d+\.\d+\.\d+$/.test(nodeEngine)) {
          const [major, minor, patch] = nodeEngine.slice(2).split('.').map(Number);
          if (patch > 0) {
            issues.push({
              severity: 'info',
              rule: 'engines-node-patch-specific',
              message: `Node engine "${nodeEngine}" specifies patch version. May cause issues in CI with different patch. Consider ">=\${major}.\${minor}.0".`,
              evidence: `engines.node: "${nodeEngine}"`
            });
          }
        }
      }

      // Check npm engine
      if (pkg.engines.npm) {
        const npmEngine = pkg.engines.npm;
        if (/^\d+\.\d+\.\d+$/.test(npmEngine)) {
          issues.push({
            severity: 'warn',
            rule: 'engines-npm-strict',
            message: `npm engine "${npmEngine}" is pinned to exact version.`,
            evidence: `engines.npm: "${npmEngine}"`
          });
        }
      }
    }

    // ===== packageManager FIELD =====
    if (pkg.packageManager) {
      const pmMatch = pkg.packageManager.match(/^(npm|pnpm|yarn|bun)@/);
      if (pmMatch) {
        const declaredManager = pmMatch[1];

        // Check if lockfile matches declared package manager
        if (foundLockfileType && foundLockfileType !== declaredManager) {
          issues.push({
            severity: 'high',
            rule: 'packageManager-lockfile-mismatch',
            message: `packageManager declares "${declaredManager}" but found ${foundLockfileType} lockfile.`,
            evidence: `packageManager: "${pkg.packageManager}", lockfile: ${path.basename(foundLockfile)}`,
            fix: {
              suggestion: `Either change packageManager to "${foundLockfileType}" or regenerate lockfile with ${declaredManager}`
            }
          });
        }

        // Warn if packageManager is set but no lockfile
        if (!foundLockfile) {
          issues.push({
            severity: 'warn',
            rule: 'packageManager-no-lockfile',
            message: `packageManager set to "${declaredManager}" but no lockfile found.`,
            evidence: `packageManager: "${pkg.packageManager}"`
          });
        }
      }
    }

    // ===== B3: PACKAGE-LOCK.JSON VALIDATION =====
    if (foundLockfileType === 'npm' && foundLockfile) {
      try {
        const lockContent = fs.readFileSync(foundLockfile, 'utf8');
        const lockData = JSON.parse(lockContent);

        // Check lockfileVersion
        if (!lockData.lockfileVersion) {
          issues.push({
            severity: 'warn',
            rule: 'lockfile-version-missing',
            message: 'package-lock.json missing lockfileVersion. May be corrupted or very old.',
            fix: {
              suggestion: 'Delete package-lock.json and run npm install to regenerate'
            }
          });
        }

        // Check name/version consistency
        if (lockData.name && pkg.name && lockData.name !== pkg.name) {
          issues.push({
            severity: 'warn',
            rule: 'lockfile-name-mismatch',
            message: `package-lock.json name "${lockData.name}" differs from package.json name "${pkg.name}".`,
            fix: {
              suggestion: 'Regenerate lockfile with npm install'
            }
          });
        }

      } catch (e) {
        if (e instanceof SyntaxError) {
          issues.push({
            severity: 'error',
            rule: 'lockfile-parse-error',
            message: `package-lock.json is invalid JSON: ${e.message}`,
            fix: {
              suggestion: 'Delete package-lock.json and run npm install to regenerate'
            }
          });
        }
        // Other errors (file read) are not critical
      }
    }

    // ===== B4: NON-REPRODUCIBLE DEPENDENCIES =====
    const allDeps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.optionalDependencies || {})
    };

    const nonReproduciblePatterns = [
      { pattern: /^file:/, type: 'file:', severity: 'warn' },
      { pattern: /^git\+ssh:/, type: 'git+ssh:', severity: 'warn' },
      { pattern: /^git\+https:/, type: 'git+https:', severity: 'info' },
      { pattern: /^github:/, type: 'github:', severity: 'info' },
      { pattern: /^git:/, type: 'git:', severity: 'warn' }
    ];

    for (const [depName, depVersion] of Object.entries(allDeps)) {
      if (typeof depVersion !== 'string') continue;

      for (const { pattern, type, severity } of nonReproduciblePatterns) {
        if (pattern.test(depVersion)) {
          // Check if it has a commit/tag pin
          const hasPin = /#[a-f0-9]{7,40}$|#v?\d/.test(depVersion);

          if (!hasPin && (type === 'git+ssh:' || type === 'git:' || type === 'github:')) {
            issues.push({
              severity: 'warn',
              rule: 'dependency-non-reproducible',
              message: `Dependency "${depName}" uses ${type} without commit pin. Builds may be non-reproducible.`,
              evidence: `${depName}: "${depVersion}"`,
              fix: {
                suggestion: `Pin to specific commit: ${depVersion}#<commit-sha>`
              }
            });
          } else if (type === 'file:') {
            issues.push({
              severity,
              rule: 'dependency-local-file',
              message: `Dependency "${depName}" uses file: path. Will fail in CI unless path exists.`,
              evidence: `${depName}: "${depVersion}"`
            });
          }
          break;
        }
      }

      // Check for "latest" or "*" versions
      if (depVersion === '*' || depVersion === 'latest') {
        issues.push({
          severity: 'warn',
          rule: 'dependency-unpinned',
          message: `Dependency "${depName}" uses "${depVersion}". Builds will be non-reproducible.`,
          evidence: `${depName}: "${depVersion}"`,
          fix: {
            suggestion: `Pin to specific version: npm install ${depName}@latest --save-exact`
          }
        });
      }
    }

    return issues;
  }
};
