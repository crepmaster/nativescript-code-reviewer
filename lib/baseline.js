/**
 * baseline.js - Baseline management for suppressing known issues
 *
 * Allows teams to adopt the tool incrementally by:
 * - Creating a baseline of existing issues
 * - Only failing CI on NEW issues
 * - Gradually fixing baseline issues over time
 */

const fs = require('fs');
const path = require('path');

/**
 * Load baseline from file
 * @param {string} baselinePath - Path to baseline.json
 * @returns {{ issues: Set<string>, createdAt: string } | null}
 */
function loadBaseline(baselinePath) {
  try {
    if (!fs.existsSync(baselinePath)) {
      return null;
    }
    const content = fs.readFileSync(baselinePath, 'utf8');
    const data = JSON.parse(content);

    if (!data.issues || !Array.isArray(data.issues)) {
      console.warn(`Warning: Invalid baseline format in ${baselinePath}`);
      return null;
    }

    return {
      issues: new Set(data.issues),
      createdAt: data.createdAt || 'unknown',
      tool: data.tool || 'nativescript-reviewer'
    };
  } catch (e) {
    console.warn(`Warning: Could not load baseline from ${baselinePath}: ${e.message}`);
    return null;
  }
}

/**
 * Save baseline to file
 * @param {string} baselinePath - Path to baseline.json
 * @param {string[]} fingerprints - Array of issue fingerprints
 */
function saveBaseline(baselinePath, fingerprints) {
  const data = {
    tool: 'nativescript-reviewer',
    createdAt: new Date().toISOString(),
    issueCount: fingerprints.length,
    issues: fingerprints
  };

  const dir = path.dirname(baselinePath);
  if (dir && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(baselinePath, JSON.stringify(data, null, 2), 'utf8');
}

/**
 * Filter issues by baseline - remove issues that exist in baseline
 * @param {Array} issues - Array of issue objects with fingerprint property
 * @param {Set<string>} baselineFingerprints - Set of fingerprints to exclude
 * @returns {{ filtered: Array, baselined: number }}
 */
function filterByBaseline(issues, baselineFingerprints) {
  if (!baselineFingerprints || baselineFingerprints.size === 0) {
    return { filtered: issues, baselined: 0 };
  }

  let baselined = 0;
  const filtered = issues.filter(issue => {
    if (issue.fingerprint && baselineFingerprints.has(issue.fingerprint)) {
      baselined++;
      return false;
    }
    return true;
  });

  return { filtered, baselined };
}

/**
 * Apply baseline filtering to reports array
 * @param {Array} reports - Array of file reports
 * @param {Set<string>} baselineFingerprints - Set of fingerprints to exclude
 * @returns {{ reports: Array, totalBaselined: number }}
 */
function applyBaselineToReports(reports, baselineFingerprints) {
  if (!baselineFingerprints || baselineFingerprints.size === 0) {
    return { reports, totalBaselined: 0 };
  }

  let totalBaselined = 0;

  const filteredReports = reports.map(report => {
    const { filtered, baselined } = filterByBaseline(report.issues, baselineFingerprints);
    totalBaselined += baselined;

    // Recalculate summary
    const summary = filtered.reduce((acc, it) => {
      acc[it.severity] = (acc[it.severity] || 0) + 1;
      return acc;
    }, {});

    return {
      ...report,
      issues: filtered,
      summary
    };
  });

  return { reports: filteredReports, totalBaselined };
}

/**
 * Extract all fingerprints from reports
 * @param {Array} reports - Array of file reports
 * @returns {string[]}
 */
function extractFingerprints(reports) {
  const fingerprints = [];
  for (const report of reports) {
    for (const issue of report.issues) {
      if (issue.fingerprint) {
        fingerprints.push(issue.fingerprint);
      }
    }
  }
  return fingerprints;
}

module.exports = {
  loadBaseline,
  saveBaseline,
  filterByBaseline,
  applyBaselineToReports,
  extractFingerprints
};
