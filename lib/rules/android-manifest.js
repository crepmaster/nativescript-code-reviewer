module.exports = {
  check(content, filePath) {
    const issues = [];

    // ===== EXPORTED COMPONENTS WITHOUT PROTECTION =====
    // Parse each component individually to check if it has intent-filter or exported="true/false"
    const componentPattern = /<(activity|service|broadcast-receiver|content-provider)([^>]*?)(?:\/>|>([\s\S]*?)<\/\1>)/gi;
    let match;
    while ((match = componentPattern.exec(content)) !== null) {
      const componentType = match[1];
      const attributes = match[2];
      const innerContent = match[3] || '';

      const hasIntentFilter = /<intent-filter/i.test(innerContent);
      const hasExported = /android:exported\s*=\s*["']/.test(attributes);
      const exportedFalse = /android:exported\s*=\s*["']false["']/.test(attributes);

      // Activities with LAUNCHER intent-filter must be exported="true"
      const isLauncher = /android\.intent\.category\.LAUNCHER/i.test(innerContent);

      // Skip the main launcher activity - it must be exported
      if (isLauncher) continue;

      // Components without intent-filter should have exported="false" for security
      if (!hasIntentFilter && !hasExported) {
        issues.push({
          severity: 'high',
          rule: 'android-exported-component',
          message: `<${componentType}> component should have android:exported="false" (no intent-filter, may be implicitly exported)`
        });
      }
    }

    // ===== DANGEROUS PERMISSIONS =====
    const dangerousPerms = [
      'android.permission.RECORD_AUDIO',
      'android.permission.CAMERA',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.ACCESS_COARSE_LOCATION',
      'android.permission.READ_CONTACTS',
      'android.permission.READ_CALENDAR',
      'android.permission.WRITE_EXTERNAL_STORAGE',
      'android.permission.READ_EXTERNAL_STORAGE',
      'android.permission.CALL_PHONE',
      'android.permission.SEND_SMS',
    ];

    dangerousPerms.forEach(perm => {
      if (new RegExp(`android:name\s*=\s*["']${perm}["']`).test(content)) {
        issues.push({ 
          severity: 'warn', 
          rule: 'android-dangerous-permission', 
          message: `Dangerous permission '${perm}' requested; ensure runtime permission checks in code` 
        });
      }
    });

    // ===== OVERLY PERMISSIVE LAUNCHER =====
    if (/android:launchMode\s*=\s*["'](singleInstance|singleTask|singleTop)["']/.test(content)) {
      const match = content.match(/android:launchMode\s*=\s*["']([^"']+)["']/);
      issues.push({ 
        severity: 'info', 
        rule: 'android-launch-mode', 
        message: `Launch mode '${match[1]}' may cause intent hijacking; verify security implications` 
      });
    }

    // ===== MISSING SCHEME VALIDATION =====
    if (/(android:scheme|data\s+android:host)/.test(content)) {
      if (!/android:pathPattern|android:pathPrefix|android:mimeType/.test(content)) {
        issues.push({ 
          severity: 'warn', 
          rule: 'android-scheme-validation', 
          message: 'Intent scheme defined without path validation; add android:pathPrefix or android:pathPattern' 
        });
      }
    }

    // ===== CLEARTEXT TRAFFIC =====
    if (/android:usesCleartextTraffic\s*=\s*["']true["']/.test(content)) {
      issues.push({ 
        severity: 'high', 
        rule: 'android-cleartext-traffic', 
        message: 'Cleartext (HTTP) traffic allowed; enforce HTTPS for security' 
      });
    }

    // ===== DEBUGGABLE APP =====
    if (/android:debuggable\s*=\s*["']true["']/.test(content)) {
      issues.push({ 
        severity: 'high', 
        rule: 'android-debuggable', 
        message: 'android:debuggable="true" in release manifest; remove for production' 
      });
    }

    // ===== MISSING MINIMUM SDK =====
    if (!/(uses-sdk|android:minSdkVersion)/.test(content)) {
      issues.push({ 
        severity: 'warn', 
        rule: 'android-no-min-sdk', 
        message: 'minSdkVersion not defined in manifest; define in build.gradle instead' 
      });
    }

    // ===== MISSING TARGET SDK =====
    if (!/(uses-sdk|android:targetSdkVersion)/.test(content)) {
      issues.push({ 
        severity: 'info', 
        rule: 'android-no-target-sdk', 
        message: 'targetSdkVersion not explicitly set; define in build.gradle (preferably 33+)' 
      });
    }

    // ===== CONTENT PROVIDER WITHOUT PROTECTION =====
    if (/<provider/.test(content)) {
      if (!/android:permission|android:readPermission|android:writePermission/.test(content)) {
        issues.push({ 
          severity: 'high', 
          rule: 'android-provider-unprotected', 
          message: 'ContentProvider exposed without permission protection; add android:permission or android:readPermission' 
        });
      }
    }

    // ===== BROADCAST RECEIVER WITHOUT PROTECTION =====
    if (/<receiver/.test(content)) {
      if (!/android:permission|<intent-filter/.test(content)) {
        issues.push({ 
          severity: 'warn', 
          rule: 'android-receiver-unprotected', 
          message: 'BroadcastReceiver may be unprotected; add android:permission or restrict with intent-filter' 
        });
      }
    }

    // ===== SERVICE WITHOUT PROTECTION =====
    if (/<service/.test(content)) {
      if (!/android:permission|exported\s*=\s*["']false["']/.test(content)) {
        issues.push({ 
          severity: 'warn', 
          rule: 'android-service-unprotected', 
          message: 'Service may be exposed; add android:permission or set android:exported="false"' 
        });
      }
    }

    // ===== BACKUP ENABLED =====
    if (/android:allowBackup\s*=\s*["']true["']/.test(content)) {
      issues.push({ 
        severity: 'info', 
        rule: 'android-backup-enabled', 
        message: 'android:allowBackup="true" allows app data backup; set to false for sensitive data or use BackupAgent with proper selection' 
      });
    }

    // ===== UNNECESSARY QUERIES =====
    if (!/<queries>/.test(content) && /nativescript-permissions|camera|geolocation/.test(content)) {
      issues.push({ 
        severity: 'info', 
        rule: 'android-missing-queries', 
        message: 'Plugins used but <queries> element not defined; add for Android 11+ compatibility' 
      });
    }

    return issues;
  }
};
