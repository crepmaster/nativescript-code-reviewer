// lib/format.js
const { SEVERITY_ORDER } = require('./analyzers');

function severityRank(sev) {
  const s = (sev || 'info').toLowerCase();
  const idx = SEVERITY_ORDER.indexOf(s);
  return idx >= 0 ? idx : 0;
}

function maxSeverity(issues) {
  let max = 'info';
  for (const i of issues) {
    if (severityRank(i.severity) > severityRank(max)) max = i.severity;
  }
  return max;
}

function summarizeReports(reports) {
  const summary = { info: 0, warn: 0, high: 0, error: 0, total: 0, files: reports.length };
  for (const r of reports) {
    for (const i of r.issues || []) {
      summary[i.severity] = (summary[i.severity] || 0) + 1;
      summary.total++;
    }
  }
  return summary;
}

function formatText(reports) {
  const lines = [];
  const summary = summarizeReports(reports);

  lines.push(`NativeScript Reviewer Report`);
  lines.push(`Files: ${summary.files} | Total issues: ${summary.total} | error: ${summary.error} | high: ${summary.high} | warn: ${summary.warn} | info: ${summary.info}`);
  lines.push('');

  for (const r of reports) {
    if (!r.issues || r.issues.length === 0) continue;
    lines.push(`${r.file}`);
    for (const it of r.issues) {
      const loc = it.line ? `:${it.line}${it.column ? ':' + it.column : ''}` : '';
      lines.push(`  [${it.severity}] ${it.rule}${loc} - ${it.message}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// CI policy: fail if >= threshold severity present
function shouldFail(summary, threshold) {
  const t = (threshold || 'high').toLowerCase();
  // high => fail on high or error
  // error => fail only on error
  if (t === 'error') return summary.error > 0;
  if (t === 'high') return (summary.error > 0) || (summary.high > 0);
  if (t === 'warn') return (summary.error > 0) || (summary.high > 0) || (summary.warn > 0);
  return false;
}

module.exports = { formatText, summarizeReports, shouldFail, maxSeverity, severityRank };
