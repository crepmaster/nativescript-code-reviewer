module.exports = {
  check(content, filePath) {
    const issues = [];

    try {
      const pkg = JSON.parse(content);

      // ===== DEPENDENCIES ANALYSIS =====
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.optionalDependencies || {}) };
      
      // Known vulnerable packages (simplified list)
      const vulnerablePackages = {
        'lodash': '4.17.20', // before 4.17.21
        'serialize-javascript': '3.0.0', // before 3.1.0
        'moment': '2.29.1', // moment has known vulns
        'handlebars': '4.5.2', // before 4.5.3
        'minimist': '1.2.0', // before 1.2.5
        'js-yaml': '3.13.0', // before 3.13.1
        'express': '4.16.0', // older versions
      };

      Object.entries(allDeps).forEach(([pkg, version]) => {
        // Check if package is known vulnerable
        if (vulnerablePackages[pkg]) {
          issues.push({ 
            severity: 'high', 
            rule: 'npm-vulnerable-package', 
            message: `Package '${pkg}@${version}' has known vulnerabilities; upgrade to latest version` 
          });
        }

        // Check for old versions (> 2 years old estimates)
        if (version === '*' || version === 'latest') {
          issues.push({ 
            severity: 'warn', 
            rule: 'npm-dynamic-version', 
            message: `Package '${pkg}' uses dynamic version (*); pin to specific version for stability` 
          });
        }
      });

      // ===== NATIVESCRIPT SPECIFIC PACKAGES =====
      if (pkg.dependencies && pkg.dependencies['@nativescript/core']) {
        const nsVersion = pkg.dependencies['@nativescript/core'];
        if (nsVersion.startsWith('^6') || nsVersion.startsWith('^5')) {
          issues.push({ 
            severity: 'warn', 
            rule: 'nativescript-old-version', 
            message: 'NativeScript version is outdated; upgrade to 8.x for latest features' 
          });
        }
      }

      // ===== PEER DEPENDENCY MISMATCHES =====
      if (pkg.peerDependencies) {
        Object.entries(pkg.peerDependencies).forEach(([peerDep, peerVersion]) => {
          if (!allDeps[peerDep]) {
            issues.push({ 
              severity: 'warn', 
              rule: 'missing-peer-dep', 
              message: `Peer dependency '${peerDep}@${peerVersion}' not installed` 
            });
          }
        });
      }

      // ===== DEPRECATED PACKAGES =====
      const deprecatedPackages = ['node-uuid', 'events', 'ieeeaddress', 'randomstring'];
      Object.keys(allDeps).forEach(dep => {
        if (deprecatedPackages.includes(dep)) {
          issues.push({ 
            severity: 'warn', 
            rule: 'npm-deprecated-package', 
            message: `Package '${dep}' is deprecated; use modern alternative` 
          });
        }
      });

      // ===== CONFLICTING VERSIONS =====
      // Helper to get package base name (handles scoped packages like @nativescript/core)
      function getPackageBase(pkgName) {
        if (pkgName.startsWith('@')) {
          // Scoped package: @scope/name -> use full name as base
          return pkgName;
        }
        return pkgName;
      }

      const versions = {};
      Object.entries(allDeps).forEach(([pkgName, version]) => {
        const base = getPackageBase(pkgName);
        if (versions[base] && versions[base] !== version) {
          issues.push({
            severity: 'warn',
            rule: 'npm-version-conflict',
            message: `Multiple versions of '${base}' detected: ${versions[base]}, ${version}`
          });
        }
        versions[base] = version;
      });

      // ===== SECURITY SCRIPTS =====
      if (!pkg.scripts || !pkg.scripts.audit) {
        issues.push({ 
          severity: 'info', 
          rule: 'npm-no-audit-script', 
          message: 'Consider adding "npm audit" to CI/CD pipeline' 
        });
      }

      // ===== UNUSED DEPENDENCIES =====
      if (Object.keys(allDeps).length > 50) {
        issues.push({ 
          severity: 'info', 
          rule: 'npm-too-many-deps', 
          message: `${Object.keys(allDeps).length} dependencies detected; consider if all are necessary` 
        });
      }

      // ===== SECURITY SCANNING =====
      if (!pkg.devDependencies || !pkg.devDependencies['snyk'] && !pkg.devDependencies['npm-audit']) {
        issues.push({ 
          severity: 'info', 
          rule: 'npm-no-security-scan', 
          message: 'Consider adding security scanning with snyk or npm audit' 
        });
      }

    } catch (e) {
      issues.push({ severity: 'error', rule: 'json-parse-error', message: `Invalid JSON: ${e.message}` });
    }

    return issues;
  }
};
