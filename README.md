# NativeScript Code Reviewer

This tool performs a static scan of a NativeScript project to detect syntax issues, potential security problems, and NativeScript-specific best-practices.

## Installation

1. From any project folder:

```bash
cd c:\Users\dell user\projects\tools\nativescript-reviewer
npm install
```

2. Optionally install `eslint` and `typescript` in this folder to enable deeper checks.

## Usage

### Scan a project
```bash
# From your project directory
node c:\Users\dell user\projects\tools\nativescript-reviewer\index.js .

# Or with full path
node c:\Users\dell user\projects\tools\nativescript-reviewer\index.js c:\Users\dell user\projects\pharmapp
```

### Add shortcut to your project's `package.json`

Add this script to your project's `package.json`:
```json
"scripts": {
  "ns-review": "node ../tools/nativescript-reviewer/index.js ."
}
```

Then run:
```bash
npm run ns-review
```

### Test with samples
```bash
cd c:\Users\dell user\projects\tools\nativescript-reviewer
npm run samples
# produces sample-report.json
```

## Output

The tool writes `ns-review-report.json` in your current working directory containing a structured report with per-file issues and metadata.

## Rules Analyzed

### Configuration Files

#### Gradle (build.gradle, build.gradle.kts, gradle-wrapper.properties)
- **Outdated Gradle**: Version checks for compatibility
- **Build Tools**: Deprecated build tools detection
- **Proguard/Obfuscation**: Missing code obfuscation for release builds
- **Hardcoded Secrets**: API keys and credentials in Gradle
- **Debuggable APK**: debuggable=true in release builds
- **Dynamic Versions**: Dynamic dependency versions (+, *) for stability
- **Unsafe Repositories**: JCenter (deprecated) or HTTP repositories
- **Signing Configuration**: Release builds without signing config
- **Min/Target SDK**: Too low or outdated SDK versions
- **Cleartext Traffic**: Explicit permission for unencrypted HTTP

#### package.json
- **Vulnerable Packages**: Known security vulnerabilities
- **Dynamic Versions**: Version pinning for stability
- **NativeScript Updates**: Outdated NativeScript versions
- **Peer Dependencies**: Missing required peer dependencies
- **Deprecated Packages**: Use of deprecated npm packages
- **Version Conflicts**: Multiple versions of same package
- **Security Scanning**: Missing npm audit in CI/CD
- **Too Many Dependencies**: Audit bloated dependency tree

#### AndroidManifest.xml
- **Exported Components**: Activities/Services/Receivers without proper protection
- **Dangerous Permissions**: Camera, Location, Contacts, Storage permissions
- **Launch Mode**: Intent hijacking vulnerabilities
- **Scheme Validation**: Intent schemes without path validation
- **Cleartext Traffic**: HTTP traffic explicitly allowed
- **Debuggable Flag**: debuggable="true" in production
- **ContentProvider Protection**: Unprotected content providers
- **Backup Enabled**: Data backup configuration
- **Queries Element**: Android 11+ compatibility

### Security (High Priority)
- **Hardcoded Credentials**: API keys, passwords, tokens, secrets in code
- **Insecure Storage**: localStorage, AsyncStorage without encryption
- **HTTP vs HTTPS**: Remote URLs using insecure HTTP
- **Code Injection**: eval/Function usage, XSS vulnerabilities
- **Input Validation**: Missing validation on user-provided data
- **Sensitive Logging**: Passwords, tokens, PII in console logs
- **SSL/TLS Configuration**: Network requests without HTTPS verification
- **Regex DoS**: Vulnerable regex patterns that cause denial of service
- **Certificate Pinning**: SSL pinning recommendations for sensitive APIs

### NativeScript-Specific
- **Lifecycle Hooks**: Missing onLoaded/onUnloaded/ngOnDestroy for cleanup
- **Data Binding**: Observable patterns, null-safe navigation ({{ obj?.prop }})
- **Memory Leaks**: Event listeners, subscriptions, timers without cleanup
- **Plugin Compatibility**: Platform-specific code for iOS/Android
- **Navigation**: Back stack management, parameter validation
- **Performance**: Blocking operations, heavy loops, image disposal
- **Modals & Dialogs**: Proper cleanup of modal context

### Variables
- Detects `var` usage (prefer let/const)
- Identifies possibly undeclared identifiers
- Flags unused variables
- Detects variable shadowing

### Methods & Functions
- Async functions missing await
- Unused function declarations
- Missing promise error handling (no catch)

### Imports
- Deep relative imports (> 3 levels up)
- Unused imports

### Performance
- Synchronous file I/O (readFileSync, writeFileSync)
- Heavy operations in loops
- Image memory leaks
- Chained array operations
- Complex regex patterns
- DOM re-rendering issues

### Code Quality
- Code duplication patterns
- High cyclomatic complexity
- Magic numbers (should use constants)
- Oversized functions (> 50 lines)
- Poor variable naming
- Insufficient comments
- TODO/FIXME/BUG comments
- Deprecated patterns (.bind, prototype, old function syntax)
- Unmatched try-catch or empty catch blocks

## TypeScript ESLint Integration (Recommended)

For proper TypeScript analysis without false positives, install the TypeScript ESLint packages:

```bash
npm run install:typescript-eslint

# Or manually:
npm install eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin --save-optional
```

This enables:
- **Proper TypeScript parsing** - Interfaces, types, generics, decorators are understood
- **No false positives** - Valid TypeScript syntax won't be flagged as errors
- **Smart unused variable detection** - Ignores type-only exports, underscore-prefixed vars
- **Function overload support** - Declaration merging works correctly

### TypeScript ESLint Rules Applied

```javascript
{
  // JavaScript rules that cause false positives are DISABLED
  'no-unused-vars': 'off',
  'no-undef': 'off',
  'no-redeclare': 'off',

  // TypeScript equivalents are ENABLED
  '@typescript-eslint/no-unused-vars': ['warn', {
    argsIgnorePattern: '^_',
    varsIgnorePattern: '^_',
  }],
  '@typescript-eslint/no-explicit-any': 'warn',
  '@typescript-eslint/no-non-null-assertion': 'warn',
}
```

## Notes

This is a pragmatic, extensible starter. For the most precise results, install TypeScript ESLint (see above) so the analyzer can properly parse TypeScript syntax. File-based heuristics provide a safety net when these packages are not available.
