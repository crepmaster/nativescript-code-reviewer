/**
 * platform-sanity.js - Platform directory sanity checks
 *
 * Detects corrupted or incomplete platform installations that cause:
 * - "gradlew.bat n'est pas reconnu"
 * - Build failures due to missing files
 * - Release build issues
 */

const fs = require('fs');
const path = require('path');

module.exports = {
  /**
   * Check platform sanity
   * @param {string} content - Content (usually package.json to trigger check)
   * @param {string} filePath - Path to package.json
   * @param {object} opts - Options including root directory
   */
  check(content, filePath, opts = {}) {
    const issues = [];

    // Only trigger on package.json
    if (!filePath.endsWith('package.json')) {
      return issues;
    }

    const root = opts.root || path.dirname(filePath);
    const platformsDir = path.join(root, 'platforms');

    // Check if this is a NativeScript project
    let pkg;
    try {
      pkg = JSON.parse(content);
    } catch (e) {
      return issues;
    }

    const isNativeScriptProject = pkg.dependencies?.['@nativescript/core'] ||
                                   pkg.devDependencies?.['@nativescript/core'] ||
                                   pkg.nativescript;

    // Check if platforms directory exists
    if (!fs.existsSync(platformsDir)) {
      // Only warn if this is a NativeScript project
      if (isNativeScriptProject) {
        issues.push({
          severity: 'info',
          rule: 'platforms-not-generated',
          message: 'platforms/ directory not found. Run: ns platform add android/ios',
          fix: {
            suggestion: 'Run: ns platform add android'
          }
        });
      }
      return issues;
    }

    // ===== ANDROID PLATFORM CHECKS =====
    const androidDir = path.join(platformsDir, 'android');

    // Check if platforms/ exists but android/ doesn't
    if (!fs.existsSync(androidDir)) {
      if (isNativeScriptProject) {
        issues.push({
          severity: 'info',
          rule: 'platform-android-not-added',
          message: 'platforms/android not found. Run: ns platform add android',
          fix: {
            suggestion: 'Run: ns platform add android'
          }
        });
      }
    }

    if (fs.existsSync(androidDir)) {
      const androidChecks = [
        {
          path: 'gradlew',
          altPath: 'gradlew.bat',
          rule: 'platform-android-no-gradlew',
          message: 'Android platform missing gradlew/gradlew.bat. Builds will fail.',
          severity: 'high'
        },
        {
          path: 'gradle/wrapper/gradle-wrapper.properties',
          rule: 'platform-android-no-gradle-wrapper',
          message: 'Android platform missing gradle-wrapper.properties. Gradle wrapper is corrupted.',
          severity: 'high'
        },
        {
          path: 'gradle/wrapper/gradle-wrapper.jar',
          rule: 'platform-android-no-gradle-wrapper-jar',
          message: 'Android platform missing gradle-wrapper.jar. Gradle wrapper is corrupted.',
          severity: 'high'
        },
        {
          path: 'app/build.gradle',
          altPath: 'build.gradle',
          rule: 'platform-android-no-build-gradle',
          message: 'Android platform missing build.gradle. Platform installation is corrupted.',
          severity: 'high'
        },
        {
          path: 'app/src/main/AndroidManifest.xml',
          rule: 'platform-android-no-manifest',
          message: 'Android platform missing AndroidManifest.xml. Platform installation is corrupted.',
          severity: 'high'
        }
      ];

      for (const check of androidChecks) {
        const fullPath = path.join(androidDir, check.path);
        const altFullPath = check.altPath ? path.join(androidDir, check.altPath) : null;

        const exists = fs.existsSync(fullPath) || (altFullPath && fs.existsSync(altFullPath));

        if (!exists) {
          issues.push({
            severity: check.severity,
            rule: check.rule,
            message: check.message,
            fix: {
              suggestion: 'Run: ns platform remove android && ns platform add android'
            }
          });
        }
      }

      // Check gradlew permissions (Unix)
      if (process.platform !== 'win32') {
        const gradlewPath = path.join(androidDir, 'gradlew');
        if (fs.existsSync(gradlewPath)) {
          try {
            fs.accessSync(gradlewPath, fs.constants.X_OK);
          } catch (e) {
            issues.push({
              severity: 'warn',
              rule: 'platform-android-gradlew-not-executable',
              message: 'gradlew is not executable. Builds may fail.',
              fix: {
                suggestion: 'Run: chmod +x platforms/android/gradlew'
              }
            });
          }
        }
      }

      // Check for common corruption signs
      const settingsGradle = path.join(androidDir, 'settings.gradle');
      if (fs.existsSync(settingsGradle)) {
        try {
          const settingsContent = fs.readFileSync(settingsGradle, 'utf8');
          if (settingsContent.trim().length === 0) {
            issues.push({
              severity: 'high',
              rule: 'platform-android-empty-settings',
              message: 'settings.gradle is empty. Platform installation is corrupted.',
              fix: {
                suggestion: 'Run: ns platform remove android && ns platform add android'
              }
            });
          }
        } catch (e) {
          // Ignore read errors
        }
      }

      // Check gradle wrapper version in properties
      const wrapperProps = path.join(androidDir, 'gradle/wrapper/gradle-wrapper.properties');
      if (fs.existsSync(wrapperProps)) {
        try {
          const propsContent = fs.readFileSync(wrapperProps, 'utf8');

          // Extract gradle version
          const versionMatch = propsContent.match(/gradle-(\d+)\.(\d+)/);
          if (versionMatch) {
            const major = parseInt(versionMatch[1], 10);
            const minor = parseInt(versionMatch[2], 10);

            // Gradle 7.0+ required for modern Android builds
            if (major < 7) {
              issues.push({
                severity: 'warn',
                rule: 'platform-android-old-gradle',
                message: `Gradle ${major}.${minor} is outdated. Android builds may have issues with newer Android Gradle Plugin.`,
                evidence: `distributionUrl in gradle-wrapper.properties`,
                fix: {
                  suggestion: 'Update NativeScript and re-add Android platform for newer Gradle'
                }
              });
            }
          }
        } catch (e) {
          // Ignore read errors
        }
      }

      // Check for local.properties with SDK path
      const localProps = path.join(androidDir, 'local.properties');
      if (fs.existsSync(localProps)) {
        try {
          const localContent = fs.readFileSync(localProps, 'utf8');
          const sdkMatch = localContent.match(/sdk\.dir\s*=\s*(.+)/);
          if (sdkMatch) {
            const sdkPath = sdkMatch[1].replace(/\\\\/g, '\\').replace(/\\:/g, ':');
            // Check if SDK path exists (best effort)
            if (!fs.existsSync(sdkPath)) {
              issues.push({
                severity: 'warn',
                rule: 'platform-android-sdk-path-invalid',
                message: `Android SDK path in local.properties doesn't exist: ${sdkPath}`,
                fix: {
                  suggestion: 'Update ANDROID_HOME environment variable and regenerate platform'
                }
              });
            }
          }
        } catch (e) {
          // Ignore errors
        }
      }

      // Check for app/build.gradle content
      const appBuildGradle = path.join(androidDir, 'app/build.gradle');
      if (fs.existsSync(appBuildGradle)) {
        try {
          const gradleContent = fs.readFileSync(appBuildGradle, 'utf8');

          // Check for missing android block
          if (!gradleContent.includes('android {')) {
            issues.push({
              severity: 'high',
              rule: 'platform-android-invalid-build-gradle',
              message: 'app/build.gradle is missing android {} block. File may be corrupted.',
              fix: {
                suggestion: 'Run: ns platform remove android && ns platform add android'
              }
            });
          }

          // Check for deprecated compile dependencies
          if (/\bcompile\s+['"]/.test(gradleContent) && !/\bcompileOnly\s+['"]/.test(gradleContent)) {
            issues.push({
              severity: 'warn',
              rule: 'platform-android-deprecated-compile',
              message: 'build.gradle uses deprecated "compile" configuration. Use "implementation" instead.',
              fix: {
                suggestion: 'Replace "compile" with "implementation" in dependency declarations'
              }
            });
          }
        } catch (e) {
          // Ignore read errors
        }
      }
    }

    // ===== iOS PLATFORM CHECKS (basic) =====
    const iosDir = path.join(platformsDir, 'ios');

    if (fs.existsSync(iosDir) && process.platform === 'darwin') {
      const iosChecks = [
        {
          pattern: '*.xcodeproj',
          rule: 'platform-ios-no-xcodeproj',
          message: 'iOS platform missing .xcodeproj. Platform installation is corrupted.',
          severity: 'high'
        }
      ];

      for (const check of iosChecks) {
        if (check.pattern) {
          // Glob pattern check
          try {
            const files = fs.readdirSync(iosDir);
            const pattern = check.pattern.replace('*', '');
            const found = files.some(f => f.endsWith(pattern));
            if (!found) {
              issues.push({
                severity: check.severity,
                rule: check.rule,
                message: check.message,
                fix: {
                  suggestion: 'Run: ns platform remove ios && ns platform add ios'
                }
              });
            }
          } catch (e) {
            // Ignore errors
          }
        }
      }
    }

    return issues;
  }
};
