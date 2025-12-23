module.exports = {
  check(content, filePath) {
    const issues = [];

    // ===== LIFECYCLE HOOKS =====
    if (/\b(Page|Frame|Component|View)\b/.test(content)) {
      // Check for component lifecycle hooks
      const hasLifecycleHook = /onLoaded|onUnloaded|onNavigatingTo|onNavigatedTo|onNavigatingFrom|onNavigatedFrom|ngOnInit|ngOnDestroy|ngAfterViewInit|viewDidLoad|viewDidUnload/i.test(content);
      if (!hasLifecycleHook) {
        issues.push({ severity: 'info', rule: 'ns-missing-lifecycle', message: 'Page/Frame/Component detected but no lifecycle hooks found; consider implementing onLoaded/onUnloaded for cleanup' });
      }
    }

    // ===== OBSERVABLE & DATA BINDING =====
    if (/\.xml$|<Page|<StackLayout|<GridLayout|bindingContext|{{ /i.test(content)) {
      // Check for two-way bindings
      const bindings = [...content.matchAll(/\{\{\s*([A-Za-z0-9_.]+)\s*\}\}/g)].map(m => m[1]);
      if (bindings.length > 0) {
        issues.push({ severity: 'info', rule: 'ns-data-binding-detected', message: `${bindings.length} data binding(s) detected; ensure all properties are defined on ViewModel` });
        
        // Check for null/undefined safe navigation
        bindings.forEach(b => {
          if (!b.includes('?.') && b.includes('.')) {
            issues.push({ severity: 'warn', rule: 'ns-binding-null-check', message: `Binding '${b}' uses dot notation; use safe navigation ({{ obj?.prop }}) for null safety` });
          }
        });
      }

      // Check for observable property changes
      if (!/propertyChange|notifyPropertyChange|Observable\.create|observableModule/.test(content)) {
        if (bindings.length > 0) {
          issues.push({ severity: 'warn', rule: 'ns-no-observable', message: 'Data bindings found but no Observable pattern detected; ensure ViewModel properly notifies changes' });
        }
      }
    }

    // ===== MEMORY LEAKS & CLEANUP =====
    // Event listeners without removal
    if (/(addEventListener|on\(|subscribe\(|.once|.on\s*\()/.test(content)) {
      if (!/(removeEventListener|off\(|unsubscribe|dispose|destroy)/.test(content)) {
        issues.push({ severity: 'warn', rule: 'ns-event-listener-leak', message: 'Event listeners/subscriptions detected but no corresponding cleanup/unsubscribe found' });
      }
    }

    // Timers without clearing
    if (/(setTimeout|setInterval)\s*\(/.test(content)) {
      if (!/clearTimeout|clearInterval/.test(content)) {
        issues.push({ severity: 'warn', rule: 'ns-timer-leak', message: 'Timer(s) created but not cleared; implement cleanup in ngOnDestroy or onUnloaded' });
      }
    }

    // ===== PLUGIN COMPATIBILITY =====
    const pluginPatterns = [
      { pattern: /nativescript-camera|@nativescript\/camera/, name: 'camera', check: /iOS|Android/ },
      { pattern: /nativescript-geolocation|@nativescript\/geolocation/, name: 'geolocation', check: /iOS|Android/ },
      { pattern: /nativescript-permissions|@nativescript\/permissions/, name: 'permissions', check: /requestPermission/ },
      { pattern: /nativescript-sqlite|better-sqlite3/, name: 'database', check: /iOS|Android/ }
    ];
    
    pluginPatterns.forEach(({ pattern, name, check }) => {
      if (pattern.test(content) && !check.test(content)) {
        issues.push({ severity: 'info', rule: 'ns-plugin-platform-check', message: `Plugin '${name}' referenced; verify platform-specific code handles both iOS and Android` });
      }
    });

    // ===== PERFORMANCE & BLOCKING OPERATIONS =====
    if (/\.forEach\s*\(|for\s*\(\w+\s+in\s+|\bwhile\s*\(true/.test(content)) {
      if (/JSON\.parse|JSON\.stringify|Image\.fromFile|readFileSync/.test(content)) {
        issues.push({ severity: 'warn', rule: 'ns-blocking-loop', message: 'Large loops with heavy operations (JSON parse, file I/O) detected; may block UI thread' });
      }
    }

    // ===== NAVIGATION & ROUTING =====
    if (/(Frame\.topmost|Navigate|router\.navigate|NavigationEntry)/.test(content)) {
      if (!/backstackVisible|clearHistory/.test(content)) {
        issues.push({ severity: 'info', rule: 'ns-navigation-backstack', message: 'Navigation detected; consider clearHistory for some transitions to manage back stack' });
      }
      // Check for navigation parameter validation
      if (/navigationContext\.context|params\.|query\./.test(content) && !/validate|sanitize/.test(content)) {
        issues.push({ severity: 'warn', rule: 'ns-navigation-params-unvalidated', message: 'Navigation parameters used without validation' });
      }
    }

    // ===== NATIVESCRIPT CORE MODULES VERSIONS =====
    if (/(tns-core-modules|@nativescript\/core)/.test(content)) {
      issues.push({ severity: 'info', rule: 'ns-core-module-usage', message: 'NativeScript core modules referenced; verify compatibility with project version' });
    }

    // ===== PLATFORM-SPECIFIC CODE =====
    if (/isAndroid|isIOS|Platform\.isAndroid|Platform\.isIOS/.test(content)) {
      issues.push({ severity: 'info', rule: 'ns-platform-specific', message: 'Platform-specific code detected; ensure both platforms are tested' });
    }

    // ===== GESTURE HANDLERS =====
    if (/(tap=|doubleTap=|longPress=|pan=|swipe=|pinch=|rotate=)/.test(content)) {
      if (!/try\s*{|catch|error|handler/.test(content)) {
        issues.push({ severity: 'info', rule: 'ns-gesture-error-handling', message: 'Gesture handlers detected; consider error handling for edge cases' });
      }
    }

    // ===== MODAL & DIALOG MANAGEMENT =====
    if (/(openModal|showModal|alert\(|confirm\(|action\()/.test(content)) {
      if (/\.then\s*\(|async\s+function|await/.test(content)) {
        issues.push({ severity: 'info', rule: 'ns-modal-handling', message: 'Modals/dialogs detected with promises; ensure proper cleanup of modal context' });
      }
    }

    // ===== PROPERTY CHANGE NOTIFICATIONS =====
    if (/bindingContext\s*=|set\s+bindingContext/.test(content)) {
      if (!/notifyPropertyChange|raisePropertyChange|observable/.test(content)) {
        issues.push({ severity: 'warn', rule: 'ns-binding-context-mutation', message: 'bindingContext set but no property change notifications detected; use Observable for proper updates' });
      }
    }

    return issues;
  }
};
