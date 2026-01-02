/**
 * xml-wellformed.js - XML validation for NativeScript UI files
 *
 * Uses fast-xml-parser for proper XML parsing with accurate error reporting.
 * Detects XML parsing errors that cause Webpack/bundle failures:
 * - Unescaped & characters (must be &amp;)
 * - Unescaped < or > in text/attributes
 * - Invalid characters
 * - Unclosed tags
 * - Mismatched tags
 */

const { XMLValidator } = require('fast-xml-parser');

module.exports = {
  check(content, filePath) {
    const issues = [];

    // Only process XML files
    if (!filePath.endsWith('.xml')) {
      return issues;
    }

    // Skip App_Resources - these are native platform XMLs with different rules
    const isAppResources = filePath.includes('App_Resources') || filePath.includes('app_resources');

    // ===== FAST-XML-PARSER VALIDATION =====
    // Use the library for proper XML parsing with accurate line/column errors
    const validationResult = XMLValidator.validate(content, {
      allowBooleanAttributes: true,
    });

    if (validationResult !== true) {
      // Parser returned an error object
      const err = validationResult.err;

      // Map parser errors to our format
      let rule = 'xml-parse-error';
      let severity = 'high';

      // Detect specific error types from the message
      if (err.msg) {
        if (err.msg.includes('Unclosed tag') || err.msg.includes('not closed')) {
          rule = 'xml-unclosed-tag';
        } else if (err.msg.includes('Invalid character') || err.msg.includes('InvalidChar')) {
          rule = 'xml-invalid-character';
        } else if (err.msg.includes('closing tag') && err.msg.includes('does not match')) {
          rule = 'xml-mismatched-tag';
        } else if (err.msg.includes('unexpected close tag')) {
          rule = 'xml-unexpected-close-tag';
        }
      }

      issues.push({
        severity,
        rule,
        message: err.msg || 'XML parsing error',
        line: err.line || 1,
        column: err.col || 1,
        fix: {
          suggestion: 'Fix the XML syntax error to ensure valid XML'
        }
      });
    }

    // ===== ADDITIONAL NATIVESCRIPT-SPECIFIC CHECKS =====
    // These run even if XML is technically valid

    const lines = content.split('\n');

    // Check for unescaped & in text content (common NativeScript issue)
    // Pattern: & not followed by valid entity reference
    const ampersandPattern = /&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)/g;

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      let match;

      // Reset regex lastIndex
      ampersandPattern.lastIndex = 0;

      while ((match = ampersandPattern.exec(line)) !== null) {
        // Skip if inside a comment or CDATA
        if (isInsideComment(content, idx, match.index)) continue;
        if (isInsideCDATA(content, idx, match.index)) continue;

        // Check if this & is inside a binding expression {{ }}
        // If so, it's likely && or || which is valid JS but technically invalid XML
        const isInBinding = isInsideBinding(line, match.index);

        // Downgrade to warn for && in bindings (common NativeScript pattern)
        // Keep high for & outside bindings (real XML issue)
        const severity = isInBinding ? 'warn' : 'high';
        const message = isInBinding
          ? `'&&' or '||' in binding expression. Consider using a computed property in view-model.`
          : `Unescaped '&' character at column ${match.index + 1}. Use '&amp;' instead.`;

        issues.push({
          severity,
          rule: 'xml-unescaped-ampersand',
          message,
          line: lineNum,
          column: match.index + 1,
          fix: {
            suggestion: isInBinding
              ? "Move complex logic to view-model computed property"
              : "Replace '&' with '&amp;'"
          },
          evidence: line.substring(Math.max(0, match.index - 10), match.index + 15).trim()
        });
      }
    });

    // Check for android namespace attributes in NativeScript UI files (not App_Resources)
    // This is a common mistake - android: attributes don't work in NS XML
    if (!isAppResources && content.includes('xmlns:android=')) {
      const androidAttrPattern = /android:(\w+)\s*=/g;
      let match;
      while ((match = androidAttrPattern.exec(content)) !== null) {
        const lineIdx = content.substring(0, match.index).split('\n').length;
        issues.push({
          severity: 'warn',
          rule: 'xml-android-namespace-in-ns',
          message: `Android namespace attribute 'android:${match[1]}' in NativeScript XML. This doesn't work - use App_Resources for native Android attributes.`,
          line: lineIdx
        });
      }
    }

    // Check for binding expressions with potential issues
    const bindingPattern = /\{\{\s*([^}]+)\s*\}\}/g;
    let match;
    while ((match = bindingPattern.exec(content)) !== null) {
      const expr = match[1];
      // Check for common binding mistakes
      if (expr.includes('&&') || expr.includes('||')) {
        const lineIdx = content.substring(0, match.index).split('\n').length;
        issues.push({
          severity: 'info',
          rule: 'xml-binding-logic',
          message: `Binding expression contains '${expr.includes('&&') ? '&&' : '||'}'. Complex logic in bindings may cause issues - consider moving to view model.`,
          line: lineIdx
        });
      }
    }

    return issues;
  }
};

/**
 * Check if position is inside a binding expression {{ }}
 */
function isInsideBinding(line, colIdx) {
  // Find all {{ and }} positions in the line
  let depth = 0;
  for (let i = 0; i < line.length - 1; i++) {
    if (line[i] === '{' && line[i + 1] === '{') {
      if (i < colIdx) depth++;
      i++; // skip next char
    } else if (line[i] === '}' && line[i + 1] === '}') {
      if (i < colIdx) depth--;
      i++; // skip next char
    }
  }
  return depth > 0;
}

/**
 * Check if position is inside an XML comment
 */
function isInsideComment(content, lineIdx, colIdx) {
  const lines = content.split('\n');
  const upToPosition = lines.slice(0, lineIdx).join('\n') + '\n' + lines[lineIdx].substring(0, colIdx);

  const lastCommentStart = upToPosition.lastIndexOf('<!--');
  const lastCommentEnd = upToPosition.lastIndexOf('-->');

  return lastCommentStart > lastCommentEnd;
}

/**
 * Check if position is inside a CDATA section
 */
function isInsideCDATA(content, lineIdx, colIdx) {
  const lines = content.split('\n');
  const upToPosition = lines.slice(0, lineIdx).join('\n') + '\n' + lines[lineIdx].substring(0, colIdx);

  const lastCDATAStart = upToPosition.lastIndexOf('<![CDATA[');
  const lastCDATAEnd = upToPosition.lastIndexOf(']]>');

  return lastCDATAStart > lastCDATAEnd;
}
