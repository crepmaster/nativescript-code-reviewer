// lib/walk.js
const fs = require('fs');
const path = require('path');

function defaultIgnores() {
  return [
    '.git',
    'node_modules',
    'platforms',
    'dist',
    'build',
    'coverage',
    '.gradle',
    '.idea',
    '.vscode',
    'hooks',
  ];
}

function shouldIgnore(relPath, ignoreList) {
  const parts = relPath.split(path.sep);
  return parts.some(p => ignoreList.includes(p));
}

function isLikelyTextFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return [
    '.ts', '.tsx', '.js', '.jsx',
    '.json',
    '.xml',
    '.gradle',
    '.properties',
    '.md',
    '.css', '.scss',
  ].includes(ext) || /androidmanifest\.xml$/i.test(filePath) || /package\.json$/i.test(filePath);
}

function walkFiles(rootDir, options = {}) {
  const ignoreList = options.ignore || defaultIgnores();
  const results = [];

  function rec(current) {
    const rel = path.relative(rootDir, current);
    if (rel && shouldIgnore(rel, ignoreList)) return;

    let st;
    try {
      st = fs.statSync(current);
    } catch (e) {
      return; // Skip inaccessible files
    }

    if (st.isDirectory()) {
      let entries;
      try {
        entries = fs.readdirSync(current);
      } catch (e) {
        return; // Skip inaccessible directories
      }
      for (const e of entries) rec(path.join(current, e));
      return;
    }

    if (st.isFile() && isLikelyTextFile(current)) results.push(current);
  }

  rec(rootDir);
  return results;
}

module.exports = { walkFiles, defaultIgnores, shouldIgnore, isLikelyTextFile };
