const fs = require('fs');
const path = require('path');
const analyzers = require('./lib/analyzers');

async function run() {
  const samplesDir = path.join(__dirname, 'test-samples');
  const files = fs.readdirSync(samplesDir).map(f => path.join(samplesDir, f));
  const report = { scannedAt: new Date().toISOString(), files: {} };
  for (const f of files) {
    const content = fs.readFileSync(f, 'utf8');
    report.files[f] = await analyzers.analyzeFile(f, content, { root: path.resolve(__dirname) });
  }
  const out = path.join(__dirname, 'sample-report.json');
  fs.writeFileSync(out, JSON.stringify(report, null, 2), 'utf8');
  console.log('Sample report written to', out);
}

run().catch(e => { console.error(e); process.exit(2); });
