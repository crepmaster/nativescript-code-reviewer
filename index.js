#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const glob = require('glob');

const analyzers = require('./lib/analyzers');

function findFiles(root) {
  const patterns = ['**/*.ts', '**/*.js', '**/*.xml', '**/*.css', '**/*.scss', '**/build.gradle', '**/build.gradle.kts', '**/package.json', '**/AndroidManifest.xml', '**/gradle-wrapper.properties'];
  const opts = { cwd: root, absolute: true, ignore: ['**/node_modules/**', '**/platforms/**', '**/hooks/**', '**/dist/**', '**/build/**'] };
  const files = new Set();
  for (const p of patterns) {
    for (const f of glob.sync(p, opts)) files.add(f);
  }
  return Array.from(files);
}

async function analyze(root) {
  const files = findFiles(root);
  const report = { scannedAt: new Date().toISOString(), root, files: {} };

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const fileReport = await analyzers.analyzeFile(file, content, { root });
      report.files[file] = fileReport;
    } catch (err) {
      report.files[file] = { error: String(err) };
    }
  }

  return report;
}

function usage() {
  console.log('Usage: ns-review [path]');
  console.log('If path is omitted the current directory is scanned.');
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) return usage();
  const root = path.resolve(args[0] || process.cwd());
  console.log('Scanning', root);
  const report = await analyze(root);
  const out = path.join(process.cwd(), 'ns-review-report.json');
  fs.writeFileSync(out, JSON.stringify(report, null, 2), 'utf8');
  console.log('Report written to', out);
}

main().catch(err => {
  console.error(err);
  process.exit(2);
});
