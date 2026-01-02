/**
 * plugin-health.js - NativeScript plugin health and obsolescence checks
 *
 * Detects:
 * - Obsolete/deprecated plugins
 * - Play Services version issues
 * - Firebase BOM version drift
 * - NativeScript core version mismatches
 */

module.exports = {
  check(content, filePath) {
    const issues = [];

    // Only process package.json
    if (!filePath.endsWith('package.json')) {
      return issues;
    }

    let pkg;
    try {
      pkg = JSON.parse(content);
    } catch (e) {
      return issues;
    }

    const allDeps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.optionalDependencies || {})
    };

    // ===== C1: PLAY SERVICES OBSOLETE VERSIONS =====
    const playServicesPatterns = [
      {
        pattern: /^com\.google\.android\.gms:play-services-location:(\d+)/,
        minVersion: 18,
        name: 'play-services-location'
      },
      {
        pattern: /^com\.google\.android\.gms:play-services-maps:(\d+)/,
        minVersion: 18,
        name: 'play-services-maps'
      },
      {
        pattern: /^com\.google\.android\.gms:play-services-auth:(\d+)/,
        minVersion: 19,
        name: 'play-services-auth'
      }
    ];

    // Check for nativescript-geolocation with old play services
    if (allDeps['@nativescript/geolocation']) {
      const version = allDeps['@nativescript/geolocation'];
      // Extract major version
      const versionMatch = version.match(/\d+/);
      if (versionMatch) {
        const major = parseInt(versionMatch[0], 10);
        if (major < 8) {
          issues.push({
            severity: 'warn',
            rule: 'plugin-obsolete-geolocation',
            message: '@nativescript/geolocation version may use old Play Services. Update to latest for Android 12+ compatibility.',
            evidence: `@nativescript/geolocation: "${version}"`
          });
        }
      }
    }

    // ===== C2: FIREBASE VERSION DRIFT =====
    const firebasePackages = {};
    const firebasePattern = /^(@nativescript\/firebase-|firebase-|@angular\/fire)/;

    for (const [depName, depVersion] of Object.entries(allDeps)) {
      if (firebasePattern.test(depName)) {
        // Extract major version for comparison
        const versionMatch = String(depVersion).match(/(\d+)/);
        if (versionMatch) {
          const major = versionMatch[1];
          if (!firebasePackages[major]) {
            firebasePackages[major] = [];
          }
          firebasePackages[major].push({ name: depName, version: depVersion });
        }
      }
    }

    // If multiple major versions of firebase packages exist
    const firebaseMajors = Object.keys(firebasePackages);
    if (firebaseMajors.length > 1) {
      const examples = firebaseMajors.map(m =>
        `v${m}: ${firebasePackages[m].map(p => p.name).join(', ')}`
      ).join(' | ');

      issues.push({
        severity: 'warn',
        rule: 'firebase-version-drift',
        message: 'Multiple Firebase package versions detected. May cause runtime conflicts.',
        evidence: examples,
        fix: {
          suggestion: 'Align all Firebase packages to the same major version'
        }
      });
    }

    // ===== C3: OBSOLETE/RISKY PLUGINS =====
    const obsoletePlugins = [
      {
        name: 'nativescript-barcodescanner',
        severity: 'warn',
        message: 'nativescript-barcodescanner is outdated. Consider @nativescript/mlkit-barcode-scanning.',
        alternative: '@nativescript/mlkit-barcode-scanning'
      },
      {
        name: 'nativescript-camera',
        severity: 'info',
        message: 'nativescript-camera is legacy. Consider @nativescript/camera for better maintenance.',
        alternative: '@nativescript/camera'
      },
      {
        name: 'nativescript-background-http',
        severity: 'info',
        message: 'nativescript-background-http has known issues. Consider alternatives or update to latest.',
        alternative: null
      },
      {
        name: 'nativescript-socket.io',
        severity: 'info',
        message: 'nativescript-socket.io may have compatibility issues with newer NS versions.',
        alternative: '@nickvdz/nativescript-socket.io'
      },
      {
        name: 'nativescript-imagepicker',
        severity: 'info',
        message: 'nativescript-imagepicker is legacy. Use @nativescript/imagepicker.',
        alternative: '@nativescript/imagepicker'
      },
      {
        name: 'nativescript-permissions',
        severity: 'info',
        message: 'nativescript-permissions is deprecated. Permissions are now built into @nativescript/core.',
        alternative: '@nativescript/core (built-in)'
      },
      {
        name: 'nativescript-plugin-firebase',
        severity: 'high',
        message: 'nativescript-plugin-firebase is deprecated and unmaintained. Migrate to @nativescript/firebase-* packages.',
        alternative: '@nativescript/firebase-core + specific modules'
      },
      {
        name: 'nativescript-googlemaps-sdk',
        severity: 'warn',
        message: 'nativescript-googlemaps-sdk may be outdated. Check for @nativescript/google-maps.',
        alternative: '@nativescript/google-maps'
      },
      {
        name: 'nativescript-pro-ui',
        severity: 'high',
        message: 'nativescript-pro-ui is deprecated. Use @nativescript/ui-* packages.',
        alternative: '@nativescript/ui-listview, @nativescript/ui-chart, etc.'
      },
      {
        name: 'nativescript-purchase',
        severity: 'info',
        message: 'nativescript-purchase may need updates for billing library v5+.',
        alternative: null
      }
    ];

    for (const plugin of obsoletePlugins) {
      if (allDeps[plugin.name]) {
        const issue = {
          severity: plugin.severity,
          rule: 'plugin-obsolete',
          message: plugin.message,
          evidence: `${plugin.name}: "${allDeps[plugin.name]}"`
        };
        if (plugin.alternative) {
          issue.fix = { suggestion: `Consider migrating to: ${plugin.alternative}` };
        }
        issues.push(issue);
      }
    }

    // ===== C4: NATIVESCRIPT CORE VERSION MISMATCH =====
    const nsCoreVersion = allDeps['@nativescript/core'];
    if (nsCoreVersion) {
      const coreMatch = String(nsCoreVersion).match(/(\d+)/);
      if (coreMatch) {
        const coreMajor = parseInt(coreMatch[1], 10);

        // Check other @nativescript/* packages
        for (const [depName, depVersion] of Object.entries(allDeps)) {
          if (depName.startsWith('@nativescript/') && depName !== '@nativescript/core') {
            const pluginMatch = String(depVersion).match(/(\d+)/);
            if (pluginMatch) {
              const pluginMajor = parseInt(pluginMatch[1], 10);

              // Flag significant mismatches (>1 major version apart)
              // Exception: some plugins have independent versioning
              const independentPlugins = [
                '@nativescript/firebase-core',
                '@nativescript/firebase-auth',
                '@nativescript/firebase-firestore',
                '@nativescript/firebase-messaging',
                '@nativescript/google-maps',
                '@nativescript/mlkit-core'
              ];

              if (!independentPlugins.some(p => depName.startsWith(p.replace('-core', '')))) {
                if (Math.abs(coreMajor - pluginMajor) > 1) {
                  issues.push({
                    severity: 'warn',
                    rule: 'nativescript-version-mismatch',
                    message: `${depName} major version (${pluginMajor}) differs significantly from @nativescript/core (${coreMajor}).`,
                    evidence: `@nativescript/core: "${nsCoreVersion}", ${depName}: "${depVersion}"`,
                    fix: {
                      suggestion: 'Align plugin versions with your NativeScript core version'
                    }
                  });
                }
              }
            }
          }
        }

        // Warn about very old NativeScript versions
        if (coreMajor < 7) {
          issues.push({
            severity: 'high',
            rule: 'nativescript-core-outdated',
            message: `@nativescript/core v${coreMajor} is very outdated. Consider upgrading to v8+ for security and compatibility.`,
            evidence: `@nativescript/core: "${nsCoreVersion}"`,
            fix: {
              suggestion: 'Follow NativeScript migration guide: https://docs.nativescript.org/guide/migration'
            }
          });
        }
      }
    }

    // ===== ADDITIONAL: KNOWN BREAKING COMBINATIONS =====
    // Angular + NativeScript version combinations
    const angularCore = allDeps['@angular/core'];
    if (angularCore && nsCoreVersion) {
      const angularMatch = String(angularCore).match(/(\d+)/);
      const nsMatch = String(nsCoreVersion).match(/(\d+)/);

      if (angularMatch && nsMatch) {
        const angMajor = parseInt(angularMatch[1], 10);
        const nsMajor = parseInt(nsMatch[1], 10);

        // Known compatibility matrix (simplified)
        // Angular 15+ requires NS 8.4+
        // Angular 17+ may require NS 8.6+
        if (angMajor >= 17 && nsMajor < 8) {
          issues.push({
            severity: 'high',
            rule: 'angular-ns-incompatible',
            message: `Angular ${angMajor} may not be compatible with NativeScript ${nsMajor}. Angular 17+ typically requires NS 8.6+.`,
            evidence: `@angular/core: "${angularCore}", @nativescript/core: "${nsCoreVersion}"`
          });
        }
      }
    }

    return issues;
  }
};
