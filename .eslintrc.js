module.exports = {
  root: true,
  env: { node: true, es6: true },
  parserOptions: { ecmaVersion: 2020, sourceType: 'module' },
  extends: ['eslint:recommended'],
  rules: {
    'no-var': 'warn',
    'prefer-const': 'warn',
    'no-eval': 'error',
    'no-unused-vars': ['warn', { vars: 'local', args: 'after-used', ignoreRestSiblings: true }]
  }
};
