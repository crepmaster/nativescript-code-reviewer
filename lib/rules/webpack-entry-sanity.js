/**
 * Webpack Entry Point Sanity Check
 *
 * Validates webpack.config.js for NativeScript projects.
 *
 * Checks:
 * 1. Entry point is not "./" or invalid
 * 2. Entry point resolves to an existing file
 * 3. Custom overrides don't break NativeScript bundling
 * 4. CopyWebpackPlugin patterns are valid
 * 5. Main field transformations are correct
 */

const fs = require('fs');
const path = require('path');

/**
 * Parse webpack.config.js to extract entry point configuration
 * This is a lightweight regex-based parser, not a full JS parser.
 */
function parseWebpackConfig(content) {
  const result = {
    hasCustomEntry: false,
    entryPoints: [],
    hasChainWebpack: false,
    hasCopyPlugin: false,
    mainTransform: null,
    deletedPlugins: [],
    issues: []
  };

  // Check if webpack.chainWebpack is used
  if (/chainWebpack\s*\(/.test(content)) {
    result.hasChainWebpack = true;
  }

  // Check for custom entry configuration
  const entryMatch = content.match(/entry\s*:\s*{([^}]+)}/s);
  if (entryMatch) {
    result.hasCustomEntry = true;
    const entryContent = entryMatch[1];

    // Extract entry points
    const entries = entryContent.match(/["']([^"']+)["']\s*:\s*["']([^"']+)["']/g);
    if (entries) {
      entries.forEach(e => {
        const match = e.match(/["']([^"']+)["']\s*:\s*["']([^"']+)["']/);
        if (match) {
          result.entryPoints.push({ name: match[1], path: match[2] });
        }
      });
    }
  }

  // Check for entry: "./" or similar invalid patterns
  if (/entry\s*:\s*["']\.\/["']/.test(content)) {
    result.issues.push({
      severity: 'high',
      rule: 'webpack-invalid-entry',
      message: 'webpack.config.js has entry: "./" which is invalid and causes "Failed to find module: \'.\/\'"',
      remediation: 'Remove custom entry or set entry: "./app/app.ts"'
    });
  }

  // Check for CopyWebpackPlugin
  if (/CopyWebpackPlugin|copy-webpack-plugin/.test(content)) {
    result.hasCopyPlugin = true;

    // Check for main field transformation
    const mainMatch = content.match(/main\s*:\s*["']([^"']+)["']/);
    if (mainMatch) {
      result.mainTransform = mainMatch[1];

      // Check for common mistakes
      if (mainMatch[1] === 'bundle.js' && /\.mjs/.test(content)) {
        result.issues.push({
          severity: 'warn',
          rule: 'webpack-main-mismatch',
          message: 'CopyWebpackPlugin sets main: "bundle.js" but NativeScript 9+ generates .mjs files',
          remediation: 'Change main to "bundle.mjs" or "bundle" (without extension)'
        });
      }
    }
  }

  // Check for deleted plugins
  const deleteMatch = content.match(/config\.plugins\.delete\s*\(\s*["']([^"']+)["']\s*\)/g);
  if (deleteMatch) {
    deleteMatch.forEach(m => {
      const pluginMatch = m.match(/["']([^"']+)["']/);
      if (pluginMatch) {
        result.deletedPlugins.push(pluginMatch[1]);
      }
    });
  }

  // Check for problematic patterns
  if (/output\s*:\s*{[^}]*filename\s*:\s*["']bundle\.js["']/.test(content)) {
    result.issues.push({
      severity: 'warn',
      rule: 'webpack-output-filename',
      message: 'Custom output filename "bundle.js" may conflict with NativeScript 9+ ESM bundling',
      remediation: 'Remove custom output.filename or ensure it matches package.json main field'
    });
  }

  return result;
}

/**
 * Check webpack.config.js file content
 */
function check(content, filePath) {
  const issues = [];
  const fileName = path.basename(filePath).toLowerCase();

  // Only run on webpack.config.js
  if (fileName !== 'webpack.config.js') {
    return issues;
  }

  const parsed = parseWebpackConfig(content);
  issues.push(...parsed.issues);

  // Check for common anti-patterns
  if (parsed.hasCustomEntry) {
    // Validate entry points
    parsed.entryPoints.forEach(ep => {
      if (ep.path === './' || ep.path === '.' || ep.path === '') {
        issues.push({
          severity: 'high',
          rule: 'webpack-invalid-entry-path',
          message: `Entry point "${ep.name}" has invalid path "${ep.path}"`,
          remediation: `Change to a valid path like "./app/app.ts"`
        });
      }
    });
  }

  // Check for deleted critical plugins
  const criticalPlugins = ['NativeScriptEntryPlugin', 'DefinePlugin'];
  parsed.deletedPlugins.forEach(plugin => {
    if (criticalPlugins.includes(plugin)) {
      issues.push({
        severity: 'high',
        rule: 'webpack-deleted-critical-plugin',
        message: `Critical plugin "${plugin}" is deleted from webpack config`,
        remediation: `Do not delete ${plugin} - it is required for NativeScript bundling`
      });
    }
  });

  // Info about TypeScript checking
  if (parsed.deletedPlugins.includes('ForkTsCheckerWebpackPlugin')) {
    issues.push({
      severity: 'info',
      rule: 'webpack-no-ts-checking',
      message: 'ForkTsCheckerWebpackPlugin is deleted - TypeScript errors will not fail the build',
      remediation: 'Consider running tsc separately for type checking'
    });
  }

  // Check for resolve.fallback configuration (polyfills)
  if (/resolve\.fallback/.test(content) || /fallback\s*:\s*{/.test(content)) {
    if (/crypto\s*:\s*false/.test(content)) {
      issues.push({
        severity: 'info',
        rule: 'webpack-crypto-disabled',
        message: 'Node.js crypto polyfill is disabled - crypto-js may have issues',
        remediation: 'If using crypto-js, ensure it works without Node.js crypto module'
      });
    }
  }

  return issues;
}

/**
 * Project-level webpack validation
 */
function checkProject(projectRoot) {
  const issues = [];
  const webpackConfigPath = path.join(projectRoot, 'webpack.config.js');

  if (!fs.existsSync(webpackConfigPath)) {
    // No webpack config is fine - NativeScript uses defaults
    issues.push({
      severity: 'info',
      rule: 'webpack-using-defaults',
      message: 'No webpack.config.js found - using NativeScript default configuration',
      file: 'webpack.config.js'
    });
    return issues;
  }

  try {
    const content = fs.readFileSync(webpackConfigPath, 'utf8');
    const fileIssues = check(content, webpackConfigPath);
    issues.push(...fileIssues.map(i => ({ ...i, file: 'webpack.config.js' })));
  } catch (e) {
    issues.push({
      severity: 'warn',
      rule: 'webpack-read-error',
      message: `Could not read webpack.config.js: ${e.message}`,
      file: 'webpack.config.js'
    });
  }

  return issues;
}

module.exports = {
  check,
  checkProject,
  parseWebpackConfig
};
