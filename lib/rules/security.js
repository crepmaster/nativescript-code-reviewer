module.exports = {
  check(content, filePath) {
    const issues = [];

    // ===== HARDCODED CREDENTIALS & SECRETS =====
    const secretPatterns = [
      { pattern: /(api[_-]?key|apiKey)\s*[:=]\s*['\"]([^'\"]{4,})['\"]|"([^"]*api[_-]?key[^"]*)":\s*"([^"]{4,})"/gi, rule: 'hardcoded-api-key', msg: 'Hardcoded API key detected' },
      { pattern: /(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]|"(password|pwd)":\s*"([^"]{4,})"/gi, rule: 'hardcoded-password', msg: 'Hardcoded password detected' },
      { pattern: /(token|access_token|refresh_token|auth_token)\s*[:=]\s*['\"]([^'\"]{4,})['\"]|"(access_token|refresh_token)":\s*"([^"]{4,})"/gi, rule: 'hardcoded-token', msg: 'Hardcoded authentication token detected' },
      { pattern: /(secret|client_secret)\s*[:=]\s*['\"]([^'\"]{4,})['\"]|"(client_secret)":\s*"([^"]{4,})"/gi, rule: 'hardcoded-secret', msg: 'Hardcoded secret detected' },
      { pattern: /(firebase_key|firebase_secret|private_key|signing_key)\s*[:=]\s*['\"]([^'\"]{20,})['\"]|"firebase.*key":\s*"([^"]{20,})"/gi, rule: 'hardcoded-key', msg: 'Hardcoded cryptographic key detected' }
    ];
    secretPatterns.forEach(({ pattern, rule, msg }) => {
      if (pattern.test(content)) issues.push({ severity: 'high', rule, message: msg });
    });

    // ===== INSECURE STORAGE =====
    if (/(localStorage|sessionStorage|AsyncStorage)\.(setItem|set)\s*\(/.test(content) && !/SecureStorage/.test(content)) {
      issues.push({ severity: 'high', rule: 'insecure-storage-api', message: 'Use of insecure storage API (localStorage/AsyncStorage); prefer @nativescript-community/secure-storage' });
    }
    if (/writeFileSync\s*\(|fs\.writeFileSync\s*\(|File\.write\s*\(/.test(content) && !/encrypt|cipher|SecureStorage/.test(content)) {
      issues.push({ severity: 'warn', rule: 'unencrypted-file-write', message: 'File written without apparent encryption; verify sensitive data is protected' });
    }

    // ===== NETWORK SECURITY =====
    const httpMatches = content.match(/http:\/\/[^\s'"<>]+/g);
    if (httpMatches) {
      httpMatches.forEach(url => {
        if (!url.includes('localhost') && !url.includes('127.0.0.1')) {
          issues.push({ severity: 'high', rule: 'insecure-http', message: `Insecure HTTP URL found: ${url} - use HTTPS` });
        }
      });
    }

    // Detect HTTP in string patterns without HTTPS
    if (/["'`]http:\/\/(?!localhost|127\.0\.0\.1)/.test(content)) {
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
    const sensitiveLogging = /console\.(log|error|warn|info|debug)\s*\([^)]*\b(password|token|secret|api[_-]?key|auth|credential|pii)\b[^)]*\)/gi;
    if (sensitiveLogging.test(content)) {
      issues.push({ severity: 'high', rule: 'log-sensitive-data', message: 'Logging may expose sensitive data (passwords, tokens, secrets)' });
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
