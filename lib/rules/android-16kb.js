/**
 * Android 16KB Page Size Compliance Checker
 *
 * Verifies that Android native libraries (.so) and dependencies
 * are compatible with 16KB memory page size required by Android 14+
 *
 * Google Play Store will reject APK/AAB with non-compliant native libraries
 * on devices with 16KB pages (ARMv9, newer Pixel devices, etc.)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// ============================================================================
// CONFIGURATION: Known problematic dependencies
// ============================================================================

// Dependencies known to have native libraries - require specific minimum versions
const NATIVE_DEPENDENCIES = {
  // Google Play Services - critical for 16KB
  'play-services-location': { minVersion: '21.0.0', minMajor: 21 },
  'play-services-maps': { minVersion: '18.2.0', minMajor: 18 },
  'play-services-auth': { minVersion: '20.7.0', minMajor: 20 },
  'play-services-basement': { minVersion: '18.3.0', minMajor: 18 },
  'play-services-base': { minVersion: '18.3.0', minMajor: 18 },
  'play-services-tasks': { minVersion: '18.1.0', minMajor: 18 },
  'play-services-fido': { minVersion: '20.1.0', minMajor: 20 },

  // Other native libs
  'pdfium-android': { minVersion: '1.9.0', minMajor: 1, minMinor: 9 },
  'conscrypt': { minVersion: '2.5.0', minMajor: 2, minMinor: 5 },
  'realm': { minVersion: '10.15.0', minMajor: 10, minMinor: 15 },
  'sqlcipher': { minVersion: '4.5.0', minMajor: 4, minMinor: 5 },
  'ffmpeg': { minVersion: '5.0.0', minMajor: 5 },
  'opencv': { minVersion: '4.8.0', minMajor: 4, minMinor: 8 },
};

// Firebase BOM - should be unified across project
const MIN_FIREBASE_BOM = '32.0.0';

// AndroidX minimum versions for stability
const ANDROIDX_MIN_VERSIONS = {
  'appcompat': '1.6.0',
  'core': '1.12.0',
  'fragment': '1.6.0',
  'activity': '1.8.0',
};

// Minimum toolchain versions
const MIN_NDK_VERSION = 26;
const MIN_AGP_VERSION = '8.3.0';
const MIN_GRADLE_VERSION = 8.0;
const MIN_JAVA_VERSION = 17;

// Required ABIs for modern Play Store
const REQUIRED_ABIS = ['arm64-v8a'];
const RECOMMENDED_ABIS = ['arm64-v8a', 'armeabi-v7a'];

// ============================================================================
// GRADLE FILE CHECKS
// ============================================================================

/**
 * Check Gradle files for 16KB compliance issues
 */
function checkGradle(content, filePath) {
  const issues = [];
  const fileName = path.basename(filePath).toLowerCase();

  if (!fileName.includes('gradle') && !fileName.includes('properties')) {
    return issues;
  }

  // ===== NDK VERSION =====
  const ndkMatch = content.match(/ndkVersion\s*[=:]\s*["']?([0-9.]+)/);
  if (ndkMatch) {
    const ndkVersion = ndkMatch[1];
    const ndkMajor = parseInt(ndkVersion.split('.')[0]);
    if (ndkMajor < MIN_NDK_VERSION) {
      issues.push({
        severity: 'high',
        rule: '16kb-old-ndk',
        message: `NDK r${ndkMajor} detected. 16KB compliance requires NDK r${MIN_NDK_VERSION}+.`,
        current: ndkVersion,
        fix: 'ndkVersion "27.1.12297006"'
      });
    }
  }

  // ===== ANDROID GRADLE PLUGIN =====
  const agpMatch = content.match(/com\.android\.tools\.build:gradle[:\s]+["']?(\d+\.\d+\.\d+)/);
  if (agpMatch) {
    if (compareVersions(agpMatch[1], MIN_AGP_VERSION) < 0) {
      issues.push({
        severity: 'warn',
        rule: '16kb-old-agp',
        message: `AGP ${agpMatch[1]} may not fully support 16KB. Upgrade to ${MIN_AGP_VERSION}+.`,
        current: agpMatch[1],
        fix: 'com.android.tools.build:gradle:8.12.1'
      });
    }
  }

  // ===== LEGACY PACKAGING (CRITICAL) =====
  if (/useLegacyPackaging\s*[=:]\s*true/.test(content)) {
    issues.push({
      severity: 'high',
      rule: '16kb-legacy-packaging',
      message: 'useLegacyPackaging=true DISABLES 16KB alignment. Play Store will reject.',
      fix: 'useLegacyPackaging = false'
    });
  }

  // ===== NATIVE DEPENDENCIES VERSION CHECK =====
  for (const [depName, config] of Object.entries(NATIVE_DEPENDENCIES)) {
    const depRegex = new RegExp(`['"]([^'"]*${depName})[:\\s]+([^'"\\s]+)['"]`, 'gi');
    let match;
    while ((match = depRegex.exec(content)) !== null) {
      const version = match[2].replace(/['"]/g, '');
      if (!isVersionSufficient(version, config)) {
        issues.push({
          severity: 'high',
          rule: '16kb-outdated-native-dep',
          message: `${depName}:${version} may have non-16KB aligned .so files. Upgrade to ${config.minVersion}+`,
          dependency: depName,
          current: version,
          required: config.minVersion
        });
      }
    }
  }

  // ===== FIREBASE BOM CONSISTENCY =====
  const bomMatches = content.match(/firebase-bom[:\s]+["']?(\d+\.\d+\.\d+)/g);
  if (bomMatches && bomMatches.length > 1) {
    const versions = bomMatches.map(m => m.match(/(\d+\.\d+\.\d+)/)[1]);
    const uniqueVersions = [...new Set(versions)];
    if (uniqueVersions.length > 1) {
      issues.push({
        severity: 'warn',
        rule: '16kb-firebase-bom-inconsistent',
        message: `Multiple Firebase BOM versions detected: ${uniqueVersions.join(', ')}. Use single BOM.`,
        versions: uniqueVersions,
        fix: 'Use single implementation platform("com.google.firebase:firebase-bom:33.13.0")'
      });
    }
  }

  // ===== RESOLUTION STRATEGY CHECK =====
  const hasResolutionStrategy = content.includes('resolutionStrategy');
  const hasForce = content.includes('force ') || content.includes('force(');

  // Check if problematic deps exist without protection
  for (const depName of Object.keys(NATIVE_DEPENDENCIES)) {
    if (content.includes(depName) && !hasResolutionStrategy) {
      issues.push({
        severity: 'info',
        rule: '16kb-no-resolution-strategy',
        message: `No resolutionStrategy found. Add force rules to prevent version regression for ${depName}.`,
        fix: `configurations.all { resolutionStrategy { force 'com.google.android.gms:${depName}:${NATIVE_DEPENDENCIES[depName].minVersion}' } }`
      });
      break;
    }
  }

  // ===== TARGET SDK CHECK =====
  const targetSdkMatch = content.match(/targetSdkVersion\s*[=:]\s*(\d+)/);
  if (targetSdkMatch) {
    const targetSdk = parseInt(targetSdkMatch[1]);
    if (targetSdk >= 34 && !content.includes('ndkVersion') && !fileName.includes('properties')) {
      issues.push({
        severity: 'warn',
        rule: '16kb-missing-ndk-for-sdk34',
        message: `targetSdk ${targetSdk} requires 16KB compliance. Specify ndkVersion explicitly.`,
        fix: 'ndkVersion "27.1.12297006"'
      });
    }
  }

  // ===== GRADLE WRAPPER VERSION =====
  if (fileName.includes('wrapper') && fileName.includes('properties')) {
    const gradleMatch = content.match(/gradle-(\d+\.\d+)/);
    if (gradleMatch && parseFloat(gradleMatch[1]) < MIN_GRADLE_VERSION) {
      issues.push({
        severity: 'warn',
        rule: '16kb-old-gradle',
        message: `Gradle ${gradleMatch[1]} is outdated. Use ${MIN_GRADLE_VERSION}+ for 16KB support.`,
        fix: 'distributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.3-bin.zip'
      });
    }
  }

  // ===== JAVA TOOLCHAIN =====
  const javaMatch = content.match(/JavaVersion\.VERSION_(\d+)|jvmTarget\s*[=:]\s*['"]?(\d+)/);
  if (javaMatch) {
    const javaVersion = parseInt(javaMatch[1] || javaMatch[2]);
    if (javaVersion < MIN_JAVA_VERSION) {
      issues.push({
        severity: 'warn',
        rule: '16kb-old-java',
        message: `Java ${javaVersion} detected. Use Java ${MIN_JAVA_VERSION}+ for modern toolchain.`,
        fix: `JavaVersion.VERSION_${MIN_JAVA_VERSION}`
      });
    }
  }

  // ===== ABI FILTERS CHECK =====
  const abiMatch = content.match(/abiFilters\s*[=(]\s*['"]?([^)\n]+)/);
  if (abiMatch) {
    const abis = abiMatch[1].replace(/['"]/g, '').split(/[,\s]+/).filter(Boolean);
    if (!abis.includes('arm64-v8a')) {
      issues.push({
        severity: 'high',
        rule: '16kb-missing-arm64',
        message: 'arm64-v8a ABI not included. Required for 16KB compliance on modern devices.',
        current: abis.join(', '),
        fix: "abiFilters 'arm64-v8a', 'armeabi-v7a'"
      });
    }
  }

  // ===== JNILIBS CHECK =====
  if (content.includes('jniLibs.srcDirs') || content.includes('jniLibs {')) {
    issues.push({
      severity: 'info',
      rule: '16kb-manual-jnilibs',
      message: 'Custom jniLibs configuration detected. Verify all .so files are 16KB aligned.',
      action: 'Run llvm-readelf -l on each .so and check LOAD segments have Align=0x4000'
    });
  }

  // ===== PACKAGING OPTIONS EXCLUSIONS =====
  if (/packagingOptions|packaging\s*{/.test(content)) {
    if (/exclude\s*[=(].*\.so/.test(content)) {
      issues.push({
        severity: 'warn',
        rule: '16kb-so-exclusion',
        message: 'Native library exclusion detected in packaging. May mask 16KB issues.',
        action: 'Review exclusions - ensure not hiding problematic .so files'
      });
    }
  }

  return issues;
}

// ============================================================================
// PACKAGE.JSON CHECKS
// ============================================================================

/**
 * Check package.json for NativeScript plugin versions
 */
function checkPackageJson(content, filePath) {
  const issues = [];

  if (!filePath.endsWith('package.json')) {
    return issues;
  }

  try {
    const pkg = JSON.parse(content);
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };

    // @nativescript/android version
    if (deps['@nativescript/android']) {
      const version = deps['@nativescript/android'].replace(/[\^~]/, '');
      const major = parseInt(version.split('.')[0]);
      if (major < 8) {
        issues.push({
          severity: 'high',
          rule: '16kb-old-ns-android',
          message: `@nativescript/android ${version} uses old NDK. Upgrade to 8.5+ (preferably 9.0+).`,
          current: version,
          required: '9.0.1'
        });
      } else if (major === 8 && parseInt(version.split('.')[1]) < 5) {
        issues.push({
          severity: 'warn',
          rule: '16kb-ns-android-upgrade',
          message: `@nativescript/android ${version} may have 16KB issues. Upgrade to 8.5+ or 9.0+.`,
          current: version,
          recommended: '9.0.1'
        });
      }
    }

    // Plugins known to bundle native libraries via old deps
    const riskPlugins = {
      '@nativescript/geolocation': {
        risk: 'play-services-location (often old version)',
        fix: "force 'com.google.android.gms:play-services-location:21.3.0'"
      },
      '@nicolomaioli/nativescript-pdfview': {
        risk: 'pdfium native library',
        fix: 'Verify pdfium version >= 1.9.0'
      },
      'nativescript-sqlite': {
        risk: 'SQLite native library',
        fix: 'Verify sqlcipher/sqlite version is modern'
      }
    };

    for (const [plugin, info] of Object.entries(riskPlugins)) {
      if (deps[plugin]) {
        issues.push({
          severity: 'warn',
          rule: '16kb-risky-plugin',
          message: `${plugin} may bundle ${info.risk}. Add resolutionStrategy protection.`,
          dependency: plugin,
          fix: info.fix
        });
      }
    }

    // Generic native plugin warning
    const nativePlugins = [
      'nativescript-barcodescanner',
      'nativescript-camera',
      'nativescript-imagepicker',
      '@aspect/nativescript-lottie',
      'nativescript-webview-ext',
      '@nicolomaioli/nativescript-pdfview',
      'nativescript-audio',
      'nativescript-videoplayer'
    ];

    for (const plugin of nativePlugins) {
      if (deps[plugin] && !riskPlugins[plugin]) {
        issues.push({
          severity: 'info',
          rule: '16kb-native-plugin',
          message: `${plugin} may contain native libraries. Verify 16KB compliance after build.`,
          dependency: plugin,
          action: 'Check APK: unzip -l app.apk | grep .so'
        });
      }
    }

  } catch (e) {
    // Invalid JSON
  }

  return issues;
}

// ============================================================================
// APK/AAB ANALYSIS
// ============================================================================

/**
 * Scan APK or AAB for native libraries and verify alignment
 */
async function scanArtifact(artifactPath, readelfPath) {
  const issues = [];
  const soFiles = [];

  if (!fs.existsSync(artifactPath)) {
    return { issues: [{ severity: 'error', rule: '16kb-artifact-not-found', message: `Artifact not found: ${artifactPath}` }], soFiles };
  }

  try {
    // List .so files in artifact
    const listOutput = execSync(`unzip -l "${artifactPath}" 2>/dev/null | grep "\\.so$"`, { encoding: 'utf8' });
    const lines = listOutput.split('\n').filter(l => l.includes('.so'));

    for (const line of lines) {
      const match = line.match(/\s+(\d+)\s+[\d-]+\s+[\d:]+\s+(.+\.so)$/);
      if (match) {
        const size = parseInt(match[1]);
        const soPath = match[2];
        const arch = soPath.includes('arm64-v8a') ? 'arm64-v8a' :
                     soPath.includes('armeabi-v7a') ? 'armeabi-v7a' :
                     soPath.includes('x86_64') ? 'x86_64' :
                     soPath.includes('x86') ? 'x86' : 'unknown';

        soFiles.push({ path: soPath, size, arch });
      }
    }

    // Check for arm64-v8a presence
    const hasArm64 = soFiles.some(f => f.arch === 'arm64-v8a');
    if (!hasArm64 && soFiles.length > 0) {
      issues.push({
        severity: 'high',
        rule: '16kb-missing-arm64-in-artifact',
        message: 'No arm64-v8a native libraries in artifact. Required for modern devices.',
        abis: [...new Set(soFiles.map(f => f.arch))]
      });
    }

    // Extract and verify arm64-v8a .so files
    if (readelfPath && hasArm64) {
      const arm64Files = soFiles.filter(f => f.arch === 'arm64-v8a');

      for (const soFile of arm64Files) {
        try {
          // Extract to temp
          const tempDir = path.join(require('os').tmpdir(), 'ns-review-16kb');
          if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

          const tempFile = path.join(tempDir, path.basename(soFile.path));
          execSync(`unzip -p "${artifactPath}" "${soFile.path}" > "${tempFile}"`, { encoding: 'utf8' });

          // Check alignment
          const alignIssues = await verifySoAlignment(tempFile, readelfPath);
          for (const issue of alignIssues) {
            issue.artifactPath = soFile.path;
            issues.push(issue);
          }

          // Cleanup
          try { fs.unlinkSync(tempFile); } catch (e) {}
        } catch (e) {
          issues.push({
            severity: 'warn',
            rule: '16kb-extraction-failed',
            message: `Failed to extract/verify ${soFile.path}: ${e.message}`,
            file: soFile.path
          });
        }
      }
    }

  } catch (e) {
    if (!e.message.includes('grep')) {
      issues.push({
        severity: 'warn',
        rule: '16kb-artifact-scan-failed',
        message: `Failed to scan artifact: ${e.message}`,
        artifact: artifactPath
      });
    }
  }

  return { issues, soFiles };
}

/**
 * Verify ELF alignment of .so file
 */
async function verifySoAlignment(soFilePath, readelfPath) {
  const issues = [];

  try {
    const output = execSync(`"${readelfPath}" -l "${soFilePath}"`, { encoding: 'utf8', timeout: 10000 });
    const loadLines = output.split('\n').filter(l => l.trim().startsWith('LOAD'));

    let hasAlignmentIssue = false;
    let minAlignment = Infinity;

    for (const line of loadLines) {
      const alignMatch = line.match(/0x([0-9a-fA-F]+)\s*$/);
      if (alignMatch) {
        const alignment = parseInt(alignMatch[1], 16);
        minAlignment = Math.min(minAlignment, alignment);
        if (alignment < 0x4000) {
          hasAlignmentIssue = true;
        }
      }
    }

    if (hasAlignmentIssue) {
      issues.push({
        severity: 'high',
        rule: '16kb-misaligned-so',
        message: `${path.basename(soFilePath)}: Alignment ${minAlignment} bytes (need 16384/0x4000). NOT 16KB COMPLIANT.`,
        file: soFilePath,
        alignment: minAlignment,
        required: 0x4000,
        compliant: false
      });
    } else if (minAlignment !== Infinity) {
      // Compliant - add info for report
      issues.push({
        severity: 'pass',
        rule: '16kb-aligned-so',
        message: `${path.basename(soFilePath)}: Alignment ${minAlignment} bytes. 16KB COMPLIANT.`,
        file: soFilePath,
        alignment: minAlignment,
        compliant: true
      });
    }

  } catch (e) {
    issues.push({
      severity: 'warn',
      rule: '16kb-verify-failed',
      message: `Cannot verify ${path.basename(soFilePath)}: ${e.message}`,
      file: soFilePath
    });
  }

  return issues;
}

// ============================================================================
// GRADLE DEPENDENCY RESOLUTION
// ============================================================================

/**
 * Run Gradle to get resolved dependencies
 */
function getResolvedDependencies(projectRoot, configuration = 'releaseRuntimeClasspath') {
  const gradlePath = path.join(projectRoot, 'platforms', 'android');

  if (!fs.existsSync(gradlePath)) {
    return { error: 'platforms/android not found', dependencies: [] };
  }

  try {
    const gradleCmd = process.platform === 'win32' ? 'gradlew.bat' : './gradlew';
    const output = execSync(
      `cd "${gradlePath}" && ${gradleCmd} :app:dependencies --configuration ${configuration} 2>/dev/null`,
      { encoding: 'utf8', timeout: 120000 }
    );

    const dependencies = [];
    const lines = output.split('\n');

    for (const line of lines) {
      // Match dependency lines like "+--- com.google.android.gms:play-services-location:21.3.0"
      const match = line.match(/[+\\|]\-+\s+([^:]+):([^:]+):([^\s(]+)/);
      if (match) {
        const [_, group, artifact, version] = match;
        dependencies.push({
          group,
          artifact,
          version: version.replace(/\s*->\s*[\d.]+/, ''), // Remove version override indicators
          fullName: `${group}:${artifact}:${version}`
        });
      }
    }

    return { dependencies, raw: output };

  } catch (e) {
    return { error: e.message, dependencies: [] };
  }
}

/**
 * Analyze resolved dependencies for 16KB issues
 */
function analyzeResolvedDependencies(dependencies) {
  const issues = [];
  const seen = new Set();

  for (const dep of dependencies) {
    const key = `${dep.group}:${dep.artifact}`;
    if (seen.has(key)) continue;
    seen.add(key);

    // Check against known native dependencies
    for (const [name, config] of Object.entries(NATIVE_DEPENDENCIES)) {
      if (dep.artifact === name || dep.artifact.includes(name)) {
        if (!isVersionSufficient(dep.version, config)) {
          issues.push({
            severity: 'high',
            rule: '16kb-resolved-dep-outdated',
            message: `Resolved ${dep.artifact}:${dep.version} is below minimum ${config.minVersion}. 16KB risk.`,
            dependency: dep.fullName,
            required: config.minVersion
          });
        }
      }
    }

    // Check Firebase BOM
    if (dep.artifact === 'firebase-bom') {
      if (compareVersions(dep.version, MIN_FIREBASE_BOM) < 0) {
        issues.push({
          severity: 'warn',
          rule: '16kb-firebase-bom-old',
          message: `Firebase BOM ${dep.version} is outdated. Use ${MIN_FIREBASE_BOM}+.`,
          current: dep.version,
          required: MIN_FIREBASE_BOM
        });
      }
    }
  }

  return issues;
}

// ============================================================================
// JNILIBS DIRECTORY CHECK
// ============================================================================

/**
 * Scan jniLibs directories for manual .so files
 */
function scanJniLibs(projectRoot) {
  const issues = [];
  const soFiles = [];

  const jniLibsPaths = [
    path.join(projectRoot, 'App_Resources', 'Android', 'src', 'main', 'jniLibs'),
    path.join(projectRoot, 'App_Resources', 'Android', 'libs'),
    path.join(projectRoot, 'platforms', 'android', 'app', 'src', 'main', 'jniLibs'),
    path.join(projectRoot, 'platforms', 'android', 'app', 'libs', 'jni'),
  ];

  for (const jniPath of jniLibsPaths) {
    if (!fs.existsSync(jniPath)) continue;

    issues.push({
      severity: 'warn',
      rule: '16kb-manual-jnilibs-found',
      message: `Manual jniLibs directory found: ${path.relative(projectRoot, jniPath)}. Verify all .so are 16KB compliant.`,
      path: jniPath
    });

    // Scan for .so files
    try {
      const walkDir = (dir) => {
        const files = fs.readdirSync(dir);
        for (const file of files) {
          const fullPath = path.join(dir, file);
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            walkDir(fullPath);
          } else if (file.endsWith('.so')) {
            const arch = fullPath.includes('arm64-v8a') ? 'arm64-v8a' :
                         fullPath.includes('armeabi-v7a') ? 'armeabi-v7a' :
                         fullPath.includes('x86_64') ? 'x86_64' :
                         fullPath.includes('x86') ? 'x86' : 'unknown';
            soFiles.push({ path: fullPath, arch, size: stat.size });
          }
        }
      };
      walkDir(jniPath);
    } catch (e) {}
  }

  // Check arm64-v8a presence in jniLibs
  if (soFiles.length > 0) {
    const hasArm64 = soFiles.some(f => f.arch === 'arm64-v8a');
    if (!hasArm64) {
      issues.push({
        severity: 'high',
        rule: '16kb-jnilibs-no-arm64',
        message: 'Manual jniLibs found but no arm64-v8a architecture. Required for 16KB compliance.',
        abis: [...new Set(soFiles.map(f => f.arch))]
      });
    }
  }

  return { issues, soFiles };
}

// ============================================================================
// ANTI-REGRESSION CHECK
// ============================================================================

/**
 * Check that protection mechanisms are in place
 */
function checkAntiRegression(gradleContent, filePath) {
  const issues = [];
  const protections = {
    hasResolutionStrategy: gradleContent.includes('resolutionStrategy'),
    hasForce: /force\s*[('"]/.test(gradleContent),
    hasPlayServicesForce: /force.*play-services/.test(gradleContent),
    hasFirebaseBomForce: /force.*firebase-bom/.test(gradleContent),
    hasUseLegacyPackagingFalse: /useLegacyPackaging\s*[=:]\s*false/.test(gradleContent),
    hasNdkVersion: gradleContent.includes('ndkVersion'),
  };

  // App.gradle should have protections
  if (filePath.includes('app.gradle') || filePath.includes('App_Resources')) {
    if (!protections.hasResolutionStrategy) {
      issues.push({
        severity: 'warn',
        rule: '16kb-no-anti-regression',
        message: 'No resolutionStrategy in app.gradle. Future plugin updates may regress 16KB compliance.',
        fix: 'Add configurations.all { resolutionStrategy { force ... } }'
      });
    }

    if (!protections.hasUseLegacyPackagingFalse && !gradleContent.includes('useLegacyPackaging')) {
      issues.push({
        severity: 'info',
        rule: '16kb-recommend-legacy-packaging',
        message: 'Consider explicitly setting useLegacyPackaging=false for clarity.',
        fix: 'packaging { jniLibs { useLegacyPackaging = false } }'
      });
    }
  }

  return { issues, protections };
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function compareVersions(v1, v2) {
  const parts1 = v1.split('.').map(Number);
  const parts2 = v2.split('.').map(Number);

  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const p1 = parts1[i] || 0;
    const p2 = parts2[i] || 0;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }
  return 0;
}

function isVersionSufficient(version, config) {
  const parts = version.split('.').map(n => parseInt(n) || 0);
  const major = parts[0];
  const minor = parts[1] || 0;

  if (config.minMajor !== undefined) {
    if (major < config.minMajor) return false;
    if (major > config.minMajor) return true;
    if (config.minMinor !== undefined && minor < config.minMinor) return false;
  }

  return compareVersions(version, config.minVersion) >= 0;
}

// ============================================================================
// MAIN CHECK FUNCTION
// ============================================================================

function check(content, filePath) {
  const issues = [];
  const fileName = path.basename(filePath).toLowerCase();

  if (fileName.includes('gradle') || fileName.includes('.properties')) {
    issues.push(...checkGradle(content, filePath));
  }

  if (fileName === 'package.json') {
    issues.push(...checkPackageJson(content, filePath));
  }

  return issues;
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  check,
  checkGradle,
  checkPackageJson,
  verifySoAlignment,
  scanArtifact,
  scanJniLibs,
  getResolvedDependencies,
  analyzeResolvedDependencies,
  checkAntiRegression,
  compareVersions,
  isVersionSufficient,

  // Configuration exports for customization
  NATIVE_DEPENDENCIES,
  MIN_NDK_VERSION,
  MIN_AGP_VERSION,
  MIN_GRADLE_VERSION,
  MIN_FIREBASE_BOM,
  REQUIRED_ABIS
};
