const path = require('path');

module.exports = {
  check(content, filePath) {
    const issues = [];
    const fileName = path.basename(filePath).toLowerCase();

    // ===== SKIP KNOWN FALSE POSITIVE FILES =====
    // Firebase client API keys are meant to be public (security is enforced by Firestore rules)
    // Translation files with "password" in UI strings are not credentials
    const isFirebaseConfig = /firebase\.config|google-services|environment\.config|\.template\.ts/.test(fileName);
    // Check full path for translation files (they may be named en.ts, fr.ts in i18n/translations folder)
    const isTranslationFile = /translations|i18n|locales|\.data\.ts/.test(fileName) ||
                              /[/\\](translations|i18n|locales)[/\\]/.test(filePath);
    const isDemoFile = /demo.*service|demo-data|mock|fixture|test/.test(fileName);
    const isReportFile = /report\.json|\.sarif|review-report|ns-review/.test(fileName);
    const isAppCheckService = /app-check/.test(fileName);

    // Skip report files entirely - they contain URLs and content from analysis results
    if (isReportFile) {
      return issues;
    }

    const skipApiKeyCheck = isFirebaseConfig;
    const skipPasswordCheck = isTranslationFile || isDemoFile;
    const skipCredentialCheck = isTranslationFile || isFirebaseConfig || isDemoFile || isAppCheckService;
    const skipTokenCheck = isAppCheckService; // App Check debug tokens are expected in dev

    // ===== HARDCODED CREDENTIALS & SECRETS =====
    const secretPatterns = [
      { pattern: /(api[_-]?key|apiKey)\s*[:=]\s*['\"]([^'\"]{4,})['\"]|"([^"]*api[_-]?key[^"]*)":\s*"([^"]{4,})"/gi, rule: 'hardcoded-api-key', msg: 'Hardcoded API key detected', skip: skipApiKeyCheck },
      { pattern: /(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]|"(password|pwd)":\s*"([^"]{4,})"/gi, rule: 'hardcoded-password', msg: 'Hardcoded password detected', skip: skipPasswordCheck },
      { pattern: /(token|access_token|refresh_token|auth_token)\s*[:=]\s*['\"]([^'\"]{4,})['\"]|"(access_token|refresh_token)":\s*"([^"]{4,})"/gi, rule: 'hardcoded-token', msg: 'Hardcoded authentication token detected', skip: skipTokenCheck },
      { pattern: /(secret|client_secret)\s*[:=]\s*['\"]([^'\"]{4,})['\"]|"(client_secret)":\s*"([^"]{4,})"/gi, rule: 'hardcoded-secret', msg: 'Hardcoded secret detected', skip: false },
      { pattern: /(firebase_key|firebase_secret|private_key|signing_key)\s*[:=]\s*['\"]([^'\"]{20,})['\"]|"firebase.*key":\s*"([^"]{20,})"/gi, rule: 'hardcoded-key', msg: 'Hardcoded cryptographic key detected', skip: false }
    ];
    secretPatterns.forEach(({ pattern, rule, msg, skip }) => {
      if (!skip && pattern.test(content)) issues.push({ severity: 'high', rule, message: msg });
    });

    // Generic credentials check - skip known safe files
    if (!skipCredentialCheck) {
      const secrets = content.match(/(api_key|apiKey|secret|password|token)\s*[:=]\s*['\"]([^'\"]{4,})['\"]/gi);
      if (secrets && secrets.length > 0) {
        // Only report if not already caught by specific patterns
        const existingRules = issues.map(i => i.rule);
        if (!existingRules.some(r => r.startsWith('hardcoded-'))) {
          issues.push({ severity: 'high', rule: 'hardcoded-credentials', message: 'Possible hardcoded credential or token' });
        }
      }
    }

    // ===== INSECURE STORAGE =====
    if (/(localStorage|sessionStorage|AsyncStorage)\.(setItem|set)\s*\(/.test(content) && !/SecureStorage/.test(content)) {
      issues.push({ severity: 'high', rule: 'insecure-storage-api', message: 'Use of insecure storage API (localStorage/AsyncStorage); prefer @nativescript-community/secure-storage' });
    }
    if (/writeFileSync\s*\(|fs\.writeFileSync\s*\(|File\.write\s*\(/.test(content) && !/encrypt|cipher|SecureStorage/.test(content)) {
      issues.push({ severity: 'warn', rule: 'unencrypted-file-write', message: 'File written without apparent encryption; verify sensitive data is protected' });
    }

    // ===== NETWORK SECURITY =====
    // Known safe HTTP URLs (XML schemas, localhost, etc.)
    const safeHttpPatterns = [
      'localhost',
      '127.0.0.1',
      'schemas.android.com',         // Android XML namespace
      'schemas.microsoft.com',       // Microsoft XML namespace
      'schemas.nativescript.org',    // NativeScript XML namespace
      'www.w3.org',                  // W3C standards
      'example.com',                 // Documentation examples
      'example.org'
    ];
    const httpMatches = content.match(/http:\/\/[^\s'"<>]+/g);
    if (httpMatches) {
      httpMatches.forEach(url => {
        const isSafe = safeHttpPatterns.some(pattern => url.includes(pattern));
        if (!isSafe) {
          issues.push({ severity: 'high', rule: 'insecure-http', message: `Insecure HTTP URL found: ${url} - use HTTPS` });
        }
      });
    }

    // Detect HTTP in string patterns without HTTPS (skip XML files which use schema namespaces)
    const isXmlFile = /\.xml$/i.test(filePath);
    if (!isXmlFile && /["'`]http:\/\/(?!localhost|127\.0\.0\.1|schemas\.)/.test(content)) {
      issues.push({ severity: 'high', rule: 'http-remote-url', message: 'Remote HTTP URLs detected - always use HTTPS for external APIs' });
    }

    // Check for missing SSL/TLS configuration
    if ((/fetch|axios|HttpClient|XMLHttpRequest|tns-core-modules.*http/.test(content)) && !/https:|tls|ssl|certificate|secure/.test(content)) {
      issues.push({ severity: 'info', rule: 'verify-ssl-config', message: 'Network requests found; verify HTTPS and SSL certificate validation are configured' });
    }

    // ===== INPUT VALIDATION & XSS PREVENTION =====
    const userInputPatterns = /routeParams|navigationContext|query\.|request\.body|FormData|formData\.|document\.getElementById|document\.querySelector|innerHTML|innerText/;
    const validationPatterns = /validate\(|sanitize\(|escape\(|trim\(\)|length\s*[<>]/;
    
    if (userInputPatterns.test(content)) {
      if (!validationPatterns.test(content)) {
        issues.push({ severity: 'warn', rule: 'no-input-validation', message: 'User input accessed without obvious validation/sanitization' });
      }
      if (/\.innerHTML\s*=|\.innerText\s*=|textContent\s*=/.test(content) && !/(sanitize|escape|validate)/.test(content)) {
        issues.push({ severity: 'high', rule: 'potential-xss', message: 'Direct DOM manipulation with user input detected - risk of XSS' });
      }
    }

    // ===== CODE INJECTION =====
    if (/eval\s*\(|new\s+Function\s*\(|Function\s*\(/.test(content)) {
      issues.push({ severity: 'high', rule: 'code-injection-eval', message: 'Use of eval/Function() is dangerous and allows code injection' });
    }

    // ===== LOGGING SENSITIVE DATA =====
    // Only flag when actual values are being logged, not just mentioning the word
    // Skip strings like "Using Firebase Auth" or "Password must be..." which are informational
    const sensitiveLoggingPatterns = [
      /console\.(log|error|warn|info|debug)\s*\([^)]*\$\{.*?(password|token|secret|api[_-]?key).*?\}/gi, // Template literals with sensitive vars
      /console\.(log|error|warn|info|debug)\s*\([^)]*,\s*(password|token|secret|apiKey)[^)]*\)/gi, // Variables passed to console
      /console\.(log|error|warn|info|debug)\s*\([^)]*\+\s*(password|token|secret|apiKey)/gi // String concatenation with sensitive vars
    ];
    for (const pattern of sensitiveLoggingPatterns) {
      if (pattern.test(content)) {
        issues.push({ severity: 'high', rule: 'log-sensitive-data', message: 'Logging may expose sensitive data (passwords, tokens, secrets)' });
        break;
      }
    }

    // ===== REGEX DOS PROTECTION =====
    const regexes = content.match(/\/[^\/\\]*(?:\\.[^\/\\]*)*\/[gimuy]*/g) || [];
    regexes.forEach(re => {
      // Very simple heuristic: nested quantifiers like (a+)+, (a*)*
      if (/[+*]{.*?[+*]/.test(re) || /\(.*\([+*]/.test(re)) {
        issues.push({ severity: 'warn', rule: 'regex-dos', message: `Regex may be vulnerable to ReDoS attack: ${re}` });
      }
    });

    // ===== CERTIFICATE & SSL PINNING =====
    if (/fetch\s*\(|https\s*:\/\/|http\.request|tns-core-modules.*http/.test(content)) {
      if (!/(certificate|ssl|tls|pin|secure|verify)/.test(content)) {
        issues.push({ severity: 'info', rule: 'no-ssl-pinning', message: 'Consider implementing SSL certificate pinning for sensitive APIs' });
      }
    }

    // ===== PERMISSION HANDLING =====
    if (/requestPermission|android\.permission|NSLocationWhenInUseUsageDescription/.test(content)) {
      if (!/try\s*{|catch|error\s*handler|onError/.test(content)) {
        issues.push({ severity: 'warn', rule: 'permission-no-error-handling', message: 'Permission requests should have error handling for denied permissions' });
      }
    }

    // ===== DATA EXPOSURE =====
    if (/stringify\s*\(|JSON\.stringify\s*\(/.test(content) && /console|debug|log/.test(content)) {
      issues.push({ severity: 'warn', rule: 'stringify-logging', message: 'Be careful when stringifying and logging objects - may expose sensitive data' });
    }

    return issues;
  }
};
