/**
 * tsconfig.js - TypeScript Configuration Health Checks
 *
 * Detects common tsconfig.json misconfigurations that lead to:
 * - Runtime errors ("object is not a function", "undefined is not a function")
 * - Module resolution failures
 * - Type safety issues
 */

module.exports = {
  check(content, filePath) {
    const issues = [];

    // Only process tsconfig.json files
    if (!filePath.endsWith('tsconfig.json')) {
      return issues;
    }

    try {
      const config = JSON.parse(content);
      const compilerOptions = config.compilerOptions || {};

      // ===== STRICT MODE CHECKS =====

      // Check if strict mode is disabled
      if (compilerOptions.strict === false) {
        issues.push({
          severity: 'warn',
          rule: 'tsconfig-strict-disabled',
          message: 'TypeScript strict mode is explicitly disabled; consider enabling for better type safety'
        });
      } else if (compilerOptions.strict === undefined) {
        // Check individual strict flags if strict mode not set
        if (compilerOptions.strictNullChecks === false) {
          issues.push({
            severity: 'warn',
            rule: 'tsconfig-strictNullChecks-disabled',
            message: 'strictNullChecks is disabled; this allows null/undefined errors at runtime'
          });
        } else if (compilerOptions.strictNullChecks === undefined && !compilerOptions.strict) {
          issues.push({
            severity: 'info',
            rule: 'tsconfig-strictNullChecks-missing',
            message: 'strictNullChecks not enabled; consider enabling to catch null/undefined issues'
          });
        }

        if (compilerOptions.noImplicitAny === false) {
          issues.push({
            severity: 'warn',
            rule: 'tsconfig-noImplicitAny-disabled',
            message: 'noImplicitAny is disabled; implicit any types can cause runtime errors'
          });
        }

        if (compilerOptions.strictFunctionTypes === false) {
          issues.push({
            severity: 'info',
            rule: 'tsconfig-strictFunctionTypes-disabled',
            message: 'strictFunctionTypes is disabled; function parameter types won\'t be checked bivariantly'
          });
        }
      }

      // ===== MODULE RESOLUTION CHECKS =====

      const moduleResolution = compilerOptions.moduleResolution?.toLowerCase();
      const module = compilerOptions.module?.toLowerCase();

      // Check for risky moduleResolution settings
      if (moduleResolution === 'classic') {
        issues.push({
          severity: 'warn',
          rule: 'tsconfig-moduleResolution-classic',
          message: 'moduleResolution "classic" is outdated; use "node", "node16", or "bundler"'
        });
      }

      // Check module/moduleResolution compatibility
      if (module === 'esnext' || module === 'es2020' || module === 'es2022') {
        if (moduleResolution === 'node' && !compilerOptions.esModuleInterop) {
          issues.push({
            severity: 'warn',
            rule: 'tsconfig-esm-interop-missing',
            message: `Using "${module}" module with node resolution but esModuleInterop is not enabled; may cause import issues`
          });
        }
      }

      // Check for node16/nodenext without proper settings
      if (moduleResolution === 'node16' || moduleResolution === 'nodenext') {
        if (!module || (module !== 'node16' && module !== 'nodenext')) {
          issues.push({
            severity: 'warn',
            rule: 'tsconfig-module-resolution-mismatch',
            message: `moduleResolution "${moduleResolution}" should match module setting for consistency`
          });
        }
      }

      // ===== ESMODULE INTEROP CHECKS =====

      // esModuleInterop and allowSyntheticDefaultImports consistency
      if (compilerOptions.esModuleInterop === false) {
        issues.push({
          severity: 'warn',
          rule: 'tsconfig-esModuleInterop-disabled',
          message: 'esModuleInterop is disabled; default imports from CommonJS modules may fail at runtime'
        });
      }

      if (compilerOptions.allowSyntheticDefaultImports && !compilerOptions.esModuleInterop) {
        issues.push({
          severity: 'warn',
          rule: 'tsconfig-synthetic-without-interop',
          message: 'allowSyntheticDefaultImports without esModuleInterop may cause runtime errors; imports will compile but fail'
        });
      }

      // ===== TARGET CHECKS =====

      const target = compilerOptions.target?.toLowerCase();
      if (target === 'es3' || target === 'es5') {
        issues.push({
          severity: 'info',
          rule: 'tsconfig-outdated-target',
          message: `Target "${target}" is outdated for NativeScript; consider ES2017+ for async/await support`
        });
      }

      // ===== SKIP LIB CHECK =====

      if (compilerOptions.skipLibCheck === true) {
        issues.push({
          severity: 'info',
          rule: 'tsconfig-skipLibCheck',
          message: 'skipLibCheck is enabled; type errors in dependencies won\'t be caught'
        });
      }

      // ===== PATHS AND BASEURL =====

      if (compilerOptions.paths && !compilerOptions.baseUrl) {
        issues.push({
          severity: 'error',
          rule: 'tsconfig-paths-without-baseUrl',
          message: 'paths mapping requires baseUrl to be set; imports will fail to resolve'
        });
      }

      // ===== DECLARATION FILES =====

      if (compilerOptions.declaration === true && !compilerOptions.declarationDir && !compilerOptions.outDir) {
        issues.push({
          severity: 'info',
          rule: 'tsconfig-declaration-no-dir',
          message: 'declaration enabled but no declarationDir/outDir; .d.ts files will be alongside source'
        });
      }

      // ===== EXPERIMENTAL DECORATORS =====

      // NativeScript commonly uses decorators
      if (compilerOptions.experimentalDecorators === undefined) {
        // Check if project might use decorators (Angular/NativeScript)
        issues.push({
          severity: 'info',
          rule: 'tsconfig-decorators-not-set',
          message: 'experimentalDecorators not set; if using Angular or decorators, enable this'
        });
      }

      // ===== ISOLATEDMODULES =====

      if (compilerOptions.isolatedModules === true) {
        // This is actually good for bundlers, but may conflict with const enums
        if (content.includes('const enum')) {
          issues.push({
            severity: 'warn',
            rule: 'tsconfig-isolatedModules-const-enum',
            message: 'isolatedModules is enabled but const enums may not work with bundlers'
          });
        }
      }

      // ===== SOURCEMAPS =====

      if (!compilerOptions.sourceMap && !compilerOptions.inlineSourceMap) {
        issues.push({
          severity: 'info',
          rule: 'tsconfig-no-sourcemaps',
          message: 'Source maps not enabled; debugging will be difficult'
        });
      }

      // ===== RESOLVE JSON MODULE =====

      if (compilerOptions.resolveJsonModule === true && moduleResolution === 'classic') {
        issues.push({
          severity: 'warn',
          rule: 'tsconfig-resolveJson-classic',
          message: 'resolveJsonModule with classic moduleResolution may not work correctly'
        });
      }

    } catch (e) {
      issues.push({
        severity: 'error',
        rule: 'tsconfig-parse-error',
        message: `Invalid tsconfig.json: ${e.message}`
      });
    }

    return issues;
  }
};
