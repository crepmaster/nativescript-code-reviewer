/**
 * suppressions.js - Inline suppression support
 *
 * Supports:
 * - // ns-reviewer-disable-next-line <ruleId1>, <ruleId2>
 * - // ns-reviewer-disable <ruleId>
 * - // ns-reviewer-enable <ruleId>
 * - <!-- ns-reviewer-disable-next-line <ruleId> --> (XML)
 * - # ns-reviewer-disable-next-line <ruleId> (Gradle/properties)
 */

/**
 * Parse suppression comments from file content
 * @param {string} content - File content
 * @param {string} filePath - File path (to determine comment style)
 * @returns {{
 *   disabledGlobally: Set<string>,
 *   disabledByLine: Map<number, Set<string>>,
 *   disabledRanges: Array<{ start: number, end: number, rules: Set<string> }>
 * }}
 */
function parseSuppressions(content, filePath) {
  const result = {
    disabledGlobally: new Set(),      // Rules disabled for entire file
    disabledByLine: new Map(),         // Map<lineNumber, Set<ruleId>>
    disabledRanges: []                 // Array of { start, end, rules }
  };

  if (!content) return result;

  const lines = content.split('\n');
  const ext = (filePath || '').toLowerCase();

  // Determine comment patterns based on file type
  const isXml = ext.endsWith('.xml');
  const isGradle = ext.endsWith('.gradle') || ext.endsWith('.properties');
  const isJson = ext.endsWith('.json');

  // JSON doesn't support comments, skip
  if (isJson) return result;

  // Track open disable ranges
  const openRanges = new Map(); // Map<ruleId, startLine>

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNumber = i + 1; // 1-indexed

    // Parse different comment styles
    let match = null;

    if (isXml) {
      // XML: <!-- ns-reviewer-disable-next-line rule1, rule2 -->
      match = line.match(/<!--\s*ns-reviewer-(disable-next-line|disable|enable)\s*([^>]*?)-->/i);
    } else if (isGradle) {
      // Gradle/properties: # ns-reviewer-disable rule1
      match = line.match(/#\s*ns-reviewer-(disable-next-line|disable|enable)\s*(.*?)$/i);
      if (!match) {
        // Also try // style for .gradle files
        match = line.match(/\/\/\s*ns-reviewer-(disable-next-line|disable|enable)\s*(.*?)$/i);
      }
    } else {
      // JS/TS: // ns-reviewer-disable rule1, rule2
      match = line.match(/\/\/\s*ns-reviewer-(disable-next-line|disable|enable)\s*(.*?)$/i);
      if (!match) {
        // Also try /* */ style
        match = line.match(/\/\*\s*ns-reviewer-(disable-next-line|disable|enable)\s*(.*?)\*\//i);
      }
    }

    if (!match) continue;

    const directive = match[1].toLowerCase();
    const rulesStr = match[2].trim();

    // Parse rule IDs (comma-separated, or empty for "all")
    const rules = new Set();
    if (rulesStr) {
      rulesStr.split(',').forEach(r => {
        const trimmed = r.trim();
        if (trimmed) rules.add(trimmed);
      });
    }
    // Empty rules means "all rules"
    const allRules = rules.size === 0;
    if (allRules) rules.add('*');

    if (directive === 'disable-next-line') {
      // Apply suppression to the next line
      const targetLine = lineNumber + 1;
      if (!result.disabledByLine.has(targetLine)) {
        result.disabledByLine.set(targetLine, new Set());
      }
      rules.forEach(r => result.disabledByLine.get(targetLine).add(r));

    } else if (directive === 'disable') {
      // Start a disabled range (or file-level if at top with no enable)
      rules.forEach(r => {
        openRanges.set(r, lineNumber);
      });

    } else if (directive === 'enable') {
      // Close any open ranges for these rules
      rules.forEach(r => {
        if (openRanges.has(r)) {
          result.disabledRanges.push({
            start: openRanges.get(r),
            end: lineNumber,
            rules: new Set([r])
          });
          openRanges.delete(r);
        }
        // Also check for wildcard
        if (openRanges.has('*') && (r === '*' || allRules)) {
          result.disabledRanges.push({
            start: openRanges.get('*'),
            end: lineNumber,
            rules: new Set(['*'])
          });
          openRanges.delete('*');
        }
      });
    }
  }

  // Any unclosed ranges become "disabled until end of file"
  openRanges.forEach((startLine, ruleId) => {
    result.disabledRanges.push({
      start: startLine,
      end: lines.length + 1, // Past end of file
      rules: new Set([ruleId])
    });
    // If disabled from line 1 or 2 (accounting for file headers), consider it global
    if (startLine <= 2) {
      result.disabledGlobally.add(ruleId);
    }
  });

  return result;
}

/**
 * Check if an issue should be suppressed
 * @param {object} issue - Issue object with rule and optional line
 * @param {object} suppressions - Result from parseSuppressions
 * @returns {boolean} - True if issue should be suppressed
 */
function isIssueSuppressed(issue, suppressions) {
  if (!suppressions) return false;

  const rule = issue.rule || issue.ruleId || '';
  const line = issue.line || issue.lineno || 0;

  // Check global suppressions
  if (suppressions.disabledGlobally.has('*') || suppressions.disabledGlobally.has(rule)) {
    return true;
  }

  // Check line-specific suppressions
  if (line > 0 && suppressions.disabledByLine.has(line)) {
    const lineRules = suppressions.disabledByLine.get(line);
    if (lineRules.has('*') || lineRules.has(rule)) {
      return true;
    }
  }

  // Check range suppressions
  if (line > 0) {
    for (const range of suppressions.disabledRanges) {
      if (line >= range.start && line <= range.end) {
        if (range.rules.has('*') || range.rules.has(rule)) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Filter issues by suppressions
 * @param {Array} issues - Array of issues
 * @param {object} suppressions - Result from parseSuppressions
 * @returns {{ filtered: Array, suppressed: number }}
 */
function filterBySuppression(issues, suppressions) {
  if (!suppressions) {
    return { filtered: issues, suppressed: 0 };
  }

  let suppressed = 0;
  const filtered = issues.filter(issue => {
    // Never suppress parsing/technical errors
    if (issue.rule === 'json-parse-error' ||
        issue.rule === 'tsconfig-parse-error' ||
        issue.rule === 'lockfile-parse-error') {
      return true;
    }

    if (isIssueSuppressed(issue, suppressions)) {
      suppressed++;
      return false;
    }
    return true;
  });

  return { filtered, suppressed };
}

module.exports = {
  parseSuppressions,
  isIssueSuppressed,
  filterBySuppression
};
