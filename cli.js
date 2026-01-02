#!/usr/bin/env node
// cli.js - NativeScript Reviewer CLI
const fs = require('fs');
const path = require('path');

const { analyzeFile } = require('./lib/analyzers');
const { walkFiles, defaultIgnores } = require('./lib/walk');
const { formatText, summarizeReports, shouldFail } = require('./lib/format');
const { loadBaseline, saveBaseline, applyBaselineToReports, extractFingerprints } = require('./lib/baseline');
const noPackagejsonImportRule = require('./lib/rules/no-packagejson-import');

function parseArgs(argv) {
  const args = {
    root: process.cwd(),
    format: 'text',    // text | json | sarif
    out: null,
    threshold: 'high', // error | high | warn
    tsc: false,
    ignore: defaultIgnores(),
    help: false,
    // Baseline options
    baseline: null,        // Path to baseline.json
    updateBaseline: false, // Generate/update baseline
    noBaseline: false,     // Ignore baseline even if specified
    // Post-build check
    postbuildCheck: false, // Check bundle output for package.json refs
  };

  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') {
      args.help = true;
    } else if (a === '--root' && argv[i + 1]) {
      args.root = path.resolve(argv[++i]);
    } else if (a === '--format' && argv[i + 1]) {
      args.format = argv[++i];
    } else if (a === '--out' && argv[i + 1]) {
      args.out = argv[++i];
    } else if (a === '--threshold' && argv[i + 1]) {
      args.threshold = argv[++i];
    } else if (a === '--tsc') {
      args.tsc = true;
    } else if (a === '--ignore' && argv[i + 1]) {
      // comma-separated list
      args.ignore = argv[++i].split(',').map(s => s.trim()).filter(Boolean);
    } else if (a === '--baseline' && argv[i + 1]) {
      args.baseline = path.resolve(argv[++i]);
    } else if (a === '--update-baseline') {
      args.updateBaseline = true;
    } else if (a === '--no-baseline') {
      args.noBaseline = true;
    } else if (a === '--postbuild-check') {
      args.postbuildCheck = true;
    } else if (!a.startsWith('-')) {
      // Positional argument - treat as root
      args.root = path.resolve(a);
    }
  }
  return args;
}

function printHelp() {
  console.log(`
NativeScript Reviewer - Code quality and security analyzer

Usage:
  nativescript-reviewer [options] [path]

Options:
  --root <path>       Root directory to scan (default: current directory)
  --format <type>     Output format: text | json (default: text)
  --out <file>        Write output to file instead of stdout
  --threshold <level> Fail threshold: error | high | warn (default: high)
  --tsc               Enable TypeScript compiler diagnostics (opt-in)
  --ignore <list>     Comma-separated list of directories to ignore
  --help, -h          Show this help message

Baseline Options:
  --baseline <path>   Use baseline file to filter known issues
  --update-baseline   Generate/update baseline from current findings
  --no-baseline       Ignore baseline even if --baseline is specified

Build Checks:
  --postbuild-check   Scan bundle output for package.json imports (causes runtime crashes)

Inline Suppressions:
  Use these comments in your source files to suppress specific issues:
    // ns-reviewer-disable-next-line <rule-id>
    // ns-reviewer-disable <rule-id>
    // ns-reviewer-enable <rule-id>

Examples:
  nativescript-reviewer                          # Scan current directory
  nativescript-reviewer ./my-app                 # Scan specific directory
  nativescript-reviewer --format json --out report.json
  nativescript-reviewer --threshold error        # Only fail on errors
  nativescript-reviewer --baseline baseline.json # Use baseline
  nativescript-reviewer --update-baseline --baseline baseline.json  # Create/update baseline
`);
}

async function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    printHelp();
    process.exitCode = 0;
    return;
  }

  console.log(`NativeScript Reviewer`);
  console.log(`Scanning: ${args.root}\n`);

  const files = walkFiles(args.root, { ignore: args.ignore });
  console.log(`Scanning ${files.length} source files...`);

  let reports = [];
  let processed = 0;

  for (const f of files) {
    let content;
    try {
      content = fs.readFileSync(f, 'utf8');
    } catch (e) {
      // skip unreadable/binary files
      continue;
    }

    const report = await analyzeFile(f, content, { root: args.root, enableTsc: args.tsc });
    reports.push(report);

    processed++;
    if (processed % 50 === 0) {
      console.log(`  Processed ${processed}/${files.length} files...`);
    }
  }

  // Handle baseline
  let baselineData = null;
  let totalBaselined = 0;

  if (args.updateBaseline && args.baseline) {
    // Update/create baseline mode
    const fingerprints = extractFingerprints(reports);
    saveBaseline(args.baseline, fingerprints);
    console.log(`\nBaseline updated: ${args.baseline}`);
    console.log(`  Total issues baselined: ${fingerprints.length}`);

    // In update mode, don't fail - just report
    const summary = summarizeReports(reports);
    console.log(`\n=== Summary ===`);
    console.log(`Files scanned: ${summary.files}`);
    console.log(`Total issues: ${summary.total}`);
    console.log(`  error: ${summary.error}`);
    console.log(`  high: ${summary.high}`);
    console.log(`  warn: ${summary.warn}`);
    console.log(`  info: ${summary.info}`);
    console.log(`\nStatus: BASELINE UPDATED (exit 0)`);
    process.exitCode = 0;
    return;
  }

  if (args.baseline && !args.noBaseline) {
    // Apply baseline filtering
    baselineData = loadBaseline(args.baseline);
    if (baselineData) {
      console.log(`  Using baseline: ${args.baseline} (${baselineData.issues.size} known issues)`);
      const result = applyBaselineToReports(reports, baselineData.issues);
      reports = result.reports;
      totalBaselined = result.totalBaselined;
    } else {
      console.log(`  Warning: Baseline file not found or invalid: ${args.baseline}`);
    }
  }

  const summary = summarizeReports(reports);

  let output;
  if (args.format === 'json') {
    const jsonOutput = {
      summary,
      reports,
      baseline: baselineData ? {
        path: args.baseline,
        issuesFiltered: totalBaselined
      } : null
    };
    output = JSON.stringify(jsonOutput, null, 2);
  } else {
    output = formatText(reports);
  }

  if (args.out) {
    fs.writeFileSync(args.out, output, 'utf8');
    console.log(`\nReport written to: ${args.out}`);
  } else {
    console.log('\n' + output);
  }

  // Print summary
  console.log(`\n=== Summary ===`);
  console.log(`Files scanned: ${summary.files}`);
  console.log(`Total issues: ${summary.total}`);
  console.log(`  error: ${summary.error}`);
  console.log(`  high: ${summary.high}`);
  console.log(`  warn: ${summary.warn}`);
  console.log(`  info: ${summary.info}`);

  if (totalBaselined > 0) {
    console.log(`  (baselined: ${totalBaselined} issues filtered)`);
  }

  // Count suppressed issues from meta
  const totalSuppressed = reports.reduce((acc, r) => acc + (r.meta?.suppressed || 0), 0);
  if (totalSuppressed > 0) {
    console.log(`  (suppressed: ${totalSuppressed} issues via inline comments)`);
  }

  // Post-build check for bundle issues
  if (args.postbuildCheck) {
    console.log(`\n=== Post-Build Check ===`);
    const bundlePaths = [
      path.join(args.root, 'platforms/android/app/src/main/assets/app/bundle.mjs'),
      path.join(args.root, 'platforms/android/app/src/main/assets/app/bundle.js'),
      path.join(args.root, 'platforms/ios/app/bundle.mjs'),
      path.join(args.root, 'platforms/ios/app/bundle.js'),
    ];

    let bundleIssues = 0;
    for (const bundlePath of bundlePaths) {
      if (fs.existsSync(bundlePath)) {
        console.log(`  Checking: ${path.relative(args.root, bundlePath)}`);
        try {
          const bundleContent = fs.readFileSync(bundlePath, 'utf8');
          const issues = noPackagejsonImportRule.checkBundle(bundleContent, bundlePath);
          if (issues.length > 0) {
            bundleIssues += issues.length;
            issues.forEach(issue => {
              console.log(`  [${issue.severity}] ${issue.rule} - ${issue.message}`);
            });
            // Add to summary
            summary.error = (summary.error || 0) + issues.filter(i => i.severity === 'error').length;
            summary.total = (summary.total || 0) + issues.length;
          }
        } catch (e) {
          console.log(`  Warning: Could not read ${bundlePath}: ${e.message}`);
        }
      }
    }

    if (bundleIssues === 0) {
      console.log(`  No bundle issues found.`);
    } else {
      console.log(`  Found ${bundleIssues} bundle issue(s).`);
    }
  }

  const failed = shouldFail(summary, args.threshold);
  if (failed) {
    console.log(`\nStatus: FAIL (threshold: ${args.threshold})`);
    process.exitCode = 1;
  } else {
    console.log(`\nStatus: PASS`);
    process.exitCode = 0;
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exitCode = 2;
});
