module.exports = {
  check(content, filePath) {
    const issues = [];

    // ===== GRADLE VERSION & SYNTAX =====
    if (!content.includes('plugins') && !content.includes('android')) {
      // Not a valid Gradle file, skip
      return issues;
    }

    // ===== DEPRECATED GRADLE API =====
    if (/buildToolsVersion\s*[=:]\s*["'](\d+)["']/.test(content)) {
      const match = content.match(/buildToolsVersion\s*[=:]\s*["'](\d+)["']/);
      const version = parseInt(match[1]);
      if (version < 30) {
        issues.push({ severity: 'warn', rule: 'gradle-old-build-tools', message: `Build tools version ${version} is outdated; upgrade to 30+` });
      }
    }

    // ===== GRADLE COMPATIBILITY VERSION =====
    if (/gradle.*wrapper|gradle-wrapper\.properties/.test(filePath)) {
      if (/distributionUrl.*gradle-\d\.\d\../.test(content)) {
        const versionMatch = content.match(/gradle-(\d\.\d+)/);
        if (versionMatch) {
          const version = parseFloat(versionMatch[1]);
          if (version < 6.0) {
            issues.push({ severity: 'warn', rule: 'gradle-old-version', message: `Gradle ${version} is outdated; upgrade to 7.0+` });
          }
        }
      }
    }

    // ===== MISSING OR UNSAFE PROGUARD =====
    if (/android\s*{|buildTypes\s*{/.test(content)) {
      if (!/(minifyEnabled|shrinkResources|proguardFiles)/.test(content)) {
        issues.push({ severity: 'warn', rule: 'gradle-no-proguard', message: 'minifyEnabled or proguard rules not detected; add code obfuscation for release builds' });
      }
    }

    // ===== HARDCODED API KEYS IN GRADLE =====
    const secrets = content.match(/(api[_-]?key|apiKey|secret|password|token)\s*[=:]\s*["']([^"']{4,})["']/gi);
    if (secrets) {
      issues.push({ severity: 'high', rule: 'gradle-hardcoded-secret', message: 'Hardcoded secret in Gradle file; use BuildConfig or properties file' });
    }

    // ===== DEBUGGABLE APK =====
    if (/debuggable\s*[=:]\s*true/.test(content)) {
      issues.push({ severity: 'high', rule: 'gradle-debuggable', message: 'debuggable=true in release build type; disable for production' });
    }

    // ===== MISSING VERSION CONSTRAINT =====
    if (/dependencies\s*{/.test(content)) {
      if (/['\"].*:.*:[+*]?['\"]\s*\/\/\s*Dynamic/i.test(content) || /['\"].*:.*:[+*]['\"]\s*$/.test(content)) {
        issues.push({ severity: 'warn', rule: 'gradle-dynamic-version', message: 'Dynamic dependency version detected (+, *); use pinned versions for stability' });
      }
    }

    // ===== UNSAFE REPOSITORIES =====
    if (/repositories\s*{/.test(content)) {
      if (/jcenter|http:\/\//.test(content)) {
        issues.push({ severity: 'warn', rule: 'gradle-unsafe-repo', message: 'JCenter (deprecated) or HTTP repository detected; use HTTPS and modern repos (mavenCentral, Google)' });
      }
    }

    // ===== SIGNING CONFIG =====
    if (/buildTypes\s*{[\s\S]*release/.test(content)) {
      if (!/signingConfig|sign/.test(content)) {
        issues.push({ severity: 'info', rule: 'gradle-no-signing', message: 'Release build type without signing config detected; add proper keystore configuration' });
      }
    }

    // ===== MIN SDK TOO LOW =====
    if (/minSdkVersion\s*[=:]\s*(\d+)/.test(content)) {
      const match = content.match(/minSdkVersion\s*[=:]\s*(\d+)/);
      const minSdk = parseInt(match[1]);
      if (minSdk < 21) {
        issues.push({ severity: 'info', rule: 'gradle-low-min-sdk', message: `minSdkVersion ${minSdk} is very old; consider 24+ for modern features` });
      }
    }

    // ===== TARGET SDK =====
    if (/targetSdkVersion\s*[=:]\s*(\d+)/.test(content)) {
      const match = content.match(/targetSdkVersion\s*[=:]\s*(\d+)/);
      const targetSdk = parseInt(match[1]);
      if (targetSdk < 31) {
        issues.push({ severity: 'warn', rule: 'gradle-low-target-sdk', message: `targetSdkVersion ${targetSdk} is outdated; upgrade to 33+ for latest security features` });
      }
    }

    // ===== NETWORK SECURITY =====
    if (/usesCleartextTraffic|cleartextTrafficPermitted/.test(content)) {
      issues.push({ severity: 'high', rule: 'gradle-cleartext-traffic', message: 'Cleartext traffic explicitly allowed; ensure HTTPS is used for production' });
    }

    // ===== MISSING LINT OPTIONS =====
    if (/lintOptions\s*{[\s\S]*disable/.test(content)) {
      issues.push({ severity: 'info', rule: 'gradle-lint-disabled', message: 'Lint checks disabled; consider enabling to catch issues early' });
    }

    return issues;
  }
};
