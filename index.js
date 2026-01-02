#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const glob = require('glob');
const { execSync } = require('child_process');

const analyzers = require('./lib/analyzers');
const android16kbRule = require('./lib/rules/android-16kb');
const nsEntrypointRule = require('./lib/rules/ns-entrypoint-sanity');
const webpackEntryRule = require('./lib/rules/webpack-entry-sanity');
const nsBootstrapRule = require('./lib/rules/ns-bootstrap-chain');

// ============================================================================
// FILE DISCOVERY
// ============================================================================

function findFiles(root) {
  const patterns = ['**/*.ts', '**/*.js', '**/*.xml', '**/*.css', '**/*.scss', '**/build.gradle', '**/build.gradle.kts', '**/package.json', '**/AndroidManifest.xml', '**/gradle-wrapper.properties'];
  const opts = { cwd: root, absolute: true, ignore: ['**/node_modules/**', '**/platforms/**', '**/hooks/**', '**/dist/**', '**/build/**'] };
  const files = new Set();
  for (const p of patterns) {
    for (const f of glob.sync(p, opts)) files.add(f);
  }
  return Array.from(files);
}

function findSoFiles(root) {
  const platformsAndroid = path.join(root, 'platforms', 'android');
  if (!fs.existsSync(platformsAndroid)) return [];

  const patterns = ['**/lib/**/*.so', '**/jniLibs/**/*.so', '**/*.so'];
  const opts = { cwd: platformsAndroid, absolute: true };
  const files = new Set();
  for (const p of patterns) {
    try { for (const f of glob.sync(p, opts)) files.add(f); } catch (e) {}
  }
  return Array.from(files);
}

function findPlatformGradleFiles(root) {
  const platformsAndroid = path.join(root, 'platforms', 'android');
  if (!fs.existsSync(platformsAndroid)) return [];

  const patterns = ['**/build.gradle', '**/gradle.properties', '**/gradle-wrapper.properties'];
  const opts = { cwd: platformsAndroid, absolute: true, ignore: ['**/build/**'] };
  const files = new Set();
  for (const p of patterns) {
    try { for (const f of glob.sync(p, opts)) files.add(f); } catch (e) {}
  }
  return Array.from(files);
}

function findArtifacts(root) {
  const artifacts = [];
  const outputDirs = [
    path.join(root, 'platforms', 'android', 'app', 'build', 'outputs', 'apk'),
    path.join(root, 'platforms', 'android', 'app', 'build', 'outputs', 'bundle'),
  ];

  for (const dir of outputDirs) {
    if (!fs.existsSync(dir)) continue;
    const patterns = ['**/*.apk', '**/*.aab'];
    for (const p of patterns) {
      try {
        for (const f of glob.sync(p, { cwd: dir, absolute: true })) {
          artifacts.push(f);
        }
      } catch (e) {}
    }
  }
  return artifacts;
}

function findReadelf() {
  const possiblePaths = [
    process.env.ANDROID_NDK_HOME,
    process.env.ANDROID_NDK,
    path.join(process.env.LOCALAPPDATA || '', 'Android', 'Sdk', 'ndk'),
    path.join(process.env.HOME || '', 'Android', 'Sdk', 'ndk'),
    path.join(process.env.HOME || '', 'Library', 'Android', 'sdk', 'ndk'),
  ].filter(Boolean);

  for (const ndkBase of possiblePaths) {
    if (!fs.existsSync(ndkBase)) continue;
    let ndkVersions = [];
    try { ndkVersions = fs.readdirSync(ndkBase).filter(d => /^\d+/.test(d)).sort().reverse(); } catch (e) { continue; }

    for (const ndkVersion of ndkVersions) {
      const readelfPath = path.join(ndkBase, ndkVersion, 'toolchains', 'llvm', 'prebuilt',
        process.platform === 'win32' ? 'windows-x86_64' : (process.platform === 'darwin' ? 'darwin-x86_64' : 'linux-x86_64'),
        'bin', process.platform === 'win32' ? 'llvm-readelf.exe' : 'llvm-readelf');
      if (fs.existsSync(readelfPath)) return readelfPath;
    }
  }
  return null;
}

// ============================================================================
// 16KB COMPLIANCE ANALYSIS
// ============================================================================

async function analyze16KB(root, readelfPath) {
  const report = {
    status: 'pending',
    issues: [],
    soFiles: [],
    artifacts: [],
    resolvedDeps: [],
    jniLibs: [],
    protections: {}
  };

  console.log('\n=== 16KB Page Size Compliance Check ===\n');

  // 1. Check App_Resources/Android gradle files (user config)
  console.log('[1/7] Checking App_Resources/Android configuration...');
  const appGradlePath = path.join(root, 'App_Resources', 'Android', 'app.gradle');
  if (fs.existsSync(appGradlePath)) {
    const content = fs.readFileSync(appGradlePath, 'utf8');
    const issues = android16kbRule.checkGradle(content, appGradlePath);
    const antiRegression = android16kbRule.checkAntiRegression(content, appGradlePath);
    report.issues.push(...issues.map(i => ({ ...i, file: 'App_Resources/Android/app.gradle' })));
    report.issues.push(...antiRegression.issues.map(i => ({ ...i, file: 'App_Resources/Android/app.gradle' })));
    report.protections = antiRegression.protections;
  } else {
    report.issues.push({
      severity: 'warn',
      rule: '16kb-no-app-gradle',
      message: 'App_Resources/Android/app.gradle not found. Cannot verify 16KB configuration.',
      file: 'App_Resources/Android/app.gradle'
    });
  }

  // 2. Check platforms/android gradle files
  console.log('[2/7] Checking platforms/android Gradle files...');
  const platformGradleFiles = findPlatformGradleFiles(root);
  for (const gradleFile of platformGradleFiles) {
    try {
      const content = fs.readFileSync(gradleFile, 'utf8');
      const issues = android16kbRule.checkGradle(content, gradleFile);
      report.issues.push(...issues.map(i => ({ ...i, file: path.relative(root, gradleFile) })));
    } catch (err) {}
  }

  // 3. Scan jniLibs directories
  console.log('[3/7] Scanning for manual jniLibs...');
  const jniLibsResult = android16kbRule.scanJniLibs(root);
  report.jniLibs = jniLibsResult.soFiles.map(f => ({ ...f, path: path.relative(root, f.path) }));
  report.issues.push(...jniLibsResult.issues);

  // 4. Find and verify .so files in platforms/android
  console.log('[4/7] Scanning native libraries in platforms/android...');
  const soFiles = findSoFiles(root);
  report.soFiles = soFiles.map(f => {
    const arch = f.includes('arm64-v8a') ? 'arm64-v8a' :
                 f.includes('armeabi-v7a') ? 'armeabi-v7a' :
                 f.includes('x86_64') ? 'x86_64' :
                 f.includes('x86') ? 'x86' : 'unknown';
    return { path: path.relative(root, f), arch };
  });

  if (soFiles.length > 0) {
    if (readelfPath) {
      console.log(`    Found ${soFiles.length} .so files, verifying alignment...`);
      for (const soFile of soFiles) {
        if (soFile.includes('arm64-v8a')) {
          try {
            const issues = await android16kbRule.verifySoAlignment(soFile, readelfPath);
            report.issues.push(...issues.map(i => ({ ...i, file: path.relative(root, soFile) })));
          } catch (err) {
            report.issues.push({
              severity: 'warn', rule: '16kb-check-failed',
              message: `Failed to verify ${path.basename(soFile)}: ${err.message}`,
              file: path.relative(root, soFile)
            });
          }
        }
      }
    } else {
      report.issues.push({
        severity: 'warn',
        rule: '16kb-no-readelf',
        message: 'NDK not found. Cannot verify .so alignment. Set ANDROID_NDK_HOME.',
        action: 'Install Android NDK 27+ and set ANDROID_NDK_HOME'
      });
    }
  }

  // 5. Scan APK/AAB artifacts
  console.log('[5/7] Scanning build artifacts (APK/AAB)...');
  const artifacts = findArtifacts(root);
  if (artifacts.length > 0 && readelfPath) {
    for (const artifact of artifacts) {
      console.log(`    Scanning ${path.basename(artifact)}...`);
      try {
        const result = await android16kbRule.scanArtifact(artifact, readelfPath);
        report.artifacts.push({
          path: path.relative(root, artifact),
          soFiles: result.soFiles,
          issues: result.issues
        });
        report.issues.push(...result.issues.map(i => ({
          ...i, artifact: path.relative(root, artifact)
        })));
      } catch (err) {
        report.issues.push({
          severity: 'warn', rule: '16kb-artifact-scan-failed',
          message: `Failed to scan ${path.basename(artifact)}: ${err.message}`,
          artifact: path.relative(root, artifact)
        });
      }
    }
  } else if (artifacts.length === 0) {
    report.issues.push({
      severity: 'info',
      rule: '16kb-no-artifacts',
      message: 'No APK/AAB found. Build the app to verify final artifact compliance.',
      action: 'Run: ns build android --release'
    });
  }

  // 6. Check resolved Gradle dependencies (optional, slow)
  console.log('[6/7] Checking resolved Gradle dependencies...');
  const gradlePath = path.join(root, 'platforms', 'android');
  if (fs.existsSync(gradlePath)) {
    try {
      // Quick check - just parse existing dependency files if available
      const depResult = android16kbRule.getResolvedDependencies(root);
      if (!depResult.error && depResult.dependencies.length > 0) {
        const depIssues = android16kbRule.analyzeResolvedDependencies(depResult.dependencies);
        report.resolvedDeps = depResult.dependencies.slice(0, 50); // Limit for report size
        report.issues.push(...depIssues);
        console.log(`    Analyzed ${depResult.dependencies.length} dependencies`);
      }
    } catch (err) {
      // Skip if Gradle not available or too slow
      console.log('    Skipped (Gradle not available or timed out)');
    }
  }

  // 7. Check ABI coverage
  console.log('[7/7] Verifying ABI coverage...');
  const hasArm64 = report.soFiles.some(f => f.arch === 'arm64-v8a');
  const hasArm32 = report.soFiles.some(f => f.arch === 'armeabi-v7a');

  if (report.soFiles.length > 0 && !hasArm64) {
    report.issues.push({
      severity: 'high',
      rule: '16kb-no-arm64-abi',
      message: 'No arm64-v8a libraries found. Required for 16KB page size compliance.',
      abis: [...new Set(report.soFiles.map(f => f.arch))]
    });
  }

  // Determine overall status
  const highIssues = report.issues.filter(i => i.severity === 'high');
  const warnIssues = report.issues.filter(i => i.severity === 'warn');
  const passIssues = report.issues.filter(i => i.severity === 'pass');

  if (highIssues.length > 0) {
    report.status = 'FAIL';
  } else if (warnIssues.length > 0) {
    report.status = 'WARN';
  } else {
    report.status = 'PASS';
  }

  // Summary
  console.log('\n=== 16KB Compliance Summary ===');
  console.log(`Status: ${report.status}`);
  console.log(`  HIGH: ${highIssues.length}`);
  console.log(`  WARN: ${warnIssues.length}`);
  console.log(`  PASS: ${passIssues.length}`);
  console.log(`  Native libs: ${report.soFiles.length}`);
  console.log(`  Artifacts: ${report.artifacts.length}`);

  if (highIssues.length > 0) {
    console.log('\nCritical issues:');
    highIssues.slice(0, 5).forEach(i => console.log(`  - ${i.message}`));
  }

  return report;
}

// ============================================================================
// MAIN ANALYSIS
// ============================================================================

async function analyze(root) {
  const files = findFiles(root);
  const report = {
    scannedAt: new Date().toISOString(),
    root,
    files: {},
    android16kb: null
  };

  // Analyze source files (quick checks only, skip slow TypeScript analysis)
  console.log(`Scanning ${files.length} source files...`);
  let processed = 0;
  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const fileReport = await analyzers.analyzeFile(file, content, { root });
      report.files[file] = fileReport;
    } catch (err) {
      report.files[file] = { error: String(err) };
    }
    processed++;
    if (processed % 50 === 0) {
      console.log(`  Processed ${processed}/${files.length} files...`);
    }
  }

  // 16KB compliance check
  const readelfPath = findReadelf();
  if (readelfPath) {
    console.log(`Using NDK readelf: ${readelfPath}`);
  }
  report.android16kb = await analyze16KB(root, readelfPath);

  return report;
}

// ============================================================================
// CLI
// ============================================================================

// ============================================================================
// POSTBUILD CHECK - Executable Sanity Checks
// ============================================================================

async function runPostbuildCheck(root, baselinePath) {
  console.log('\n=== Executable App Sanity Check ===\n');

  const issues = [];

  // 1. Entry point sanity
  console.log('[1/3] Checking entry point configuration...');
  const entryIssues = nsEntrypointRule.checkProject(root);
  issues.push(...entryIssues);

  // 2. Webpack entry sanity (if webpack.config.js exists)
  console.log('[2/3] Checking webpack configuration...');
  const webpackIssues = webpackEntryRule.checkProject(root);
  issues.push(...webpackIssues);

  // 3. Bootstrap chain validation
  console.log('[3/3] Checking bootstrap chain...');
  const bootstrapIssues = nsBootstrapRule.checkProject(root);
  issues.push(...bootstrapIssues);

  // Apply baseline if provided
  let finalIssues = issues;
  if (baselinePath && fs.existsSync(baselinePath)) {
    try {
      const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
      const baselineFingerprints = new Set(baseline.fingerprints || []);
      finalIssues = issues.filter(i => !baselineFingerprints.has(i.fingerprint));
      console.log(`\nBaseline applied: ${issues.length - finalIssues.length} issues suppressed`);
    } catch (e) {
      console.warn(`Warning: Could not read baseline file: ${e.message}`);
    }
  }

  // Count by severity
  const highIssues = finalIssues.filter(i => i.severity === 'high');
  const warnIssues = finalIssues.filter(i => i.severity === 'warn');
  const infoIssues = finalIssues.filter(i => i.severity === 'info');

  console.log('\n=== Postbuild Check Summary ===');
  console.log(`  BLOCKER (high): ${highIssues.length}`);
  console.log(`  WARNING: ${warnIssues.length}`);
  console.log(`  INFO: ${infoIssues.length}`);

  if (highIssues.length > 0) {
    console.log('\nBLOCKER issues (must fix before running app):');
    highIssues.forEach(i => {
      console.log(`  ✗ [${i.rule}] ${i.message}`);
      if (i.file) console.log(`    File: ${i.file}`);
      if (i.remediation) console.log(`    Fix: ${i.remediation}`);
    });
  }

  if (warnIssues.length > 0) {
    console.log('\nWarnings:');
    warnIssues.forEach(i => {
      console.log(`  ⚠ [${i.rule}] ${i.message}`);
    });
  }

  return {
    status: highIssues.length > 0 ? 'FAIL' : 'PASS',
    issues: finalIssues,
    summary: {
      high: highIssues.length,
      warn: warnIssues.length,
      info: infoIssues.length
    }
  };
}

function usage() {
  console.log(`
NativeScript Code Reviewer with 16KB Compliance Check

Usage: ns-review [path] [options]

Options:
  -h, --help          Show this help
  --16kb-only         Only run 16KB compliance check (faster)
  --postbuild-check   Run executable sanity checks only (entry point, webpack, bootstrap)
  --baseline <file>   Apply baseline file to suppress known issues

Examples:
  ns-review .                           # Full review of current directory
  ns-review ./myapp --16kb-only         # Only 16KB check
  ns-review ./myapp --postbuild-check   # Check entry points before running app
  ns-review . --baseline baseline.json  # Apply baseline suppressions

The reviewer checks:
  - Code quality, security, performance
  - NativeScript best practices
  - Android 16KB page size compliance (Play Store requirement)
  - Entry point configuration (--postbuild-check)

Postbuild checks (--postbuild-check):
  - Entry point exists and calls Application.run()
  - package.json main field is valid (not "./" or empty)
  - moduleName target exists (app-root.xml, etc.)
  - defaultPage targets exist
  - webpack.config.js entry is valid

16KB Compliance checks:
  - NDK version (r26+ required)
  - Gradle/AGP versions
  - Native library alignment
  - Dependency versions (play-services, firebase, etc.)
  - ABI coverage (arm64-v8a required)
  - Anti-regression protections
`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) return usage();

  const root = path.resolve(args.find(a => !a.startsWith('-')) || process.cwd());
  const only16kb = args.includes('--16kb-only');
  const postbuildCheck = args.includes('--postbuild-check');

  // Parse --baseline argument
  let baselinePath = null;
  const baselineIdx = args.indexOf('--baseline');
  if (baselineIdx !== -1 && args[baselineIdx + 1]) {
    baselinePath = path.resolve(args[baselineIdx + 1]);
  }

  console.log('NativeScript Reviewer');
  console.log(`Scanning: ${root}\n`);

  let report;
  let exitCode = 0;

  if (postbuildCheck) {
    // Postbuild check mode - only executable sanity checks
    const result = await runPostbuildCheck(root, baselinePath);
    report = {
      scannedAt: new Date().toISOString(),
      root,
      postbuildCheck: result
    };

    if (result.status === 'FAIL') {
      console.log('\n✗ Postbuild check FAILED - App will likely crash at startup');
      exitCode = 1;
    } else {
      console.log('\n✓ Postbuild check PASSED - Entry point configuration is valid');
    }
  } else if (only16kb) {
    // Fast mode - only 16KB check
    const readelfPath = findReadelf();
    report = {
      scannedAt: new Date().toISOString(),
      root,
      android16kb: await analyze16KB(root, readelfPath)
    };

    if (report.android16kb && report.android16kb.status === 'FAIL') {
      console.log('\n⚠️  16KB compliance FAILED - Fix issues before Play Store submission');
      exitCode = 1;
    }
  } else {
    // Full analysis
    report = await analyze(root);

    // Also run postbuild check in full mode
    console.log('\n--- Running postbuild sanity check ---');
    const postbuildResult = await runPostbuildCheck(root, baselinePath);
    report.postbuildCheck = postbuildResult;

    if (postbuildResult.status === 'FAIL') {
      console.log('\n✗ Postbuild check FAILED');
      exitCode = 1;
    }

    // Exit code based on 16KB status
    if (report.android16kb && report.android16kb.status === 'FAIL') {
      console.log('\n⚠️  16KB compliance FAILED - Fix issues before Play Store submission');
      exitCode = 1;
    }
  }

  const out = path.join(process.cwd(), 'ns-review-report.json');
  fs.writeFileSync(out, JSON.stringify(report, null, 2), 'utf8');
  console.log(`\nReport written to: ${out}`);

  if (exitCode !== 0) {
    process.exit(exitCode);
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(2);
});
