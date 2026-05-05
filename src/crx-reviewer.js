/**
 * CRX Extension Reviewer — Privacy & Security audit engine
 * Analyzes Chrome Extension source code from extracted ZIP buffer.
 */
import JSZip from 'jszip';

// ── Risk weight constants ────────────────────────────────────────────────────

/** Sensitive permissions that grant broad access */
const HIGH_RISK_PERMISSIONS = new Set([
  'tabs',              // read all tab URLs
  'cookies',           // read/write all cookies
  'webRequest',        // intercept all network requests
  'webRequestBlocking',// modify network requests
  'webNavigation',     // track all navigation
  'history',           // read browsing history
  'bookmarks',         // read bookmarks
  'downloads',         // manage downloads
  'downloads.open',    // open downloaded files
  'management',        // manage other extensions
  'privacy',           // modify privacy settings
  'proxy',             // control proxy
  'debugger',          // attach debugger (Chrome DevTools Protocol)
  'pageCapture',       // save page as MHTML
  'desktopCapture',    // capture screen
  'nativeMessaging',   // communicate with native apps
  'identity',          // access OAuth tokens
  'identity.email',    // read email address
  'enterprise.deviceAttributes',
  'enterprise.platformKeys',
]);

const MEDIUM_RISK_PERMISSIONS = new Set([
  'storage',           // persistent storage (can be used for tracking)
  'unlimitedStorage',  // unlimited storage
  'notifications',     // push notifications
  'contextMenus',      // right-click menu
  'idle',              // detect user idle state
  'system.cpu', 'system.memory', 'system.storage', // system info
  'geolocation',       // location access
  'clipboardRead',     // read clipboard
  'clipboardWrite',    // write clipboard
  'activeTab',         // access current tab on click
  'scripting',         // inject scripts
  'alarms',            // scheduled tasks
  'background',        // background service worker
]);

/** Host permission patterns indicating broad access */
const BROAD_HOST_PATTERNS = [
  '<all_urls>',
  '*://*/*',
  'http://*/*',
  'https://*/*',
  'file:///*',
  '*://*/',
];

/** Known tracking/analytics domains */
const TRACKING_DOMAINS = [
  'google-analytics.com',
  'googletagmanager.com',
  'facebook.com/tr',
  'doubleclick.net',
  'hotjar.com',
  'mixpanel.com',
  'amplitude.com',
  'segment.com',
  'mouseflow.com',
  'fullstory.com',
  'clarity.ms',
  'browser-update.org',
  'newrelic.com',
  'sentry.io',
  'datadoghq.com',
  'logrocket.com',
  'intercom.io',
  'drift.com',
  'zendesk.com',
  'uservoice.com',
  'onesignal.com',
  'braze.com',
  'batch.com',
  'leanplum.com',
  'clevertap.com',
  'moengage.com',
  'adjust.com',
  'appsflyer.com',
  'branch.io',
  'facebook.net',      // Facebook pixel/CDN
];

/** Suspicious code patterns that may indicate malicious behavior */
const SUSPICIOUS_PATTERNS = [
  { pattern: /eval\s*\(/g, label: 'eval() usage — dynamic code execution' },
  { pattern: /new\s+Function\s*\(/g, label: 'new Function() — dynamic code generation' },
  { pattern: /document\.write\s*\(/g, label: 'document.write() — can inject malicious content' },
  { pattern: /\.innerHTML\s*=/g, label: 'innerHTML assignment — potential XSS vector' },
  { pattern: /\.outerHTML\s*=/g, label: 'outerHTML assignment — potential XSS vector' },
  { pattern: /document\.createElement\s*\(\s*['"]script['"]\s*\)/g, label: 'Dynamic script creation — script injection' },
  { pattern: /chrome\.runtime\.sendNativeMessage/g, label: 'Native messaging — can communicate outside browser' },
  { pattern: /fetch\s*\(\s*['"]https?:\/\//g, label: 'fetch() to remote URLs — may exfiltrate data' },
  { pattern: /XMLHttpRequest/g, label: 'XMLHttpRequest — may send data to remote servers' },
  { pattern: /navigator\.sendBeacon/g, label: 'sendBeacon() — can send analytics/tracking data' },
  { pattern: /new\s+WebSocket/g, label: 'WebSocket connection — persistent data channel' },
  { pattern: /chrome\.downloads\.download/g, label: 'Downloads API — can download files silently' },
  { pattern: /chrome\.tabs\.create\s*\(\s*\{[^}]*url\s*:/g, label: 'Tab creation with URL — may redirect user' },
  { pattern: /chrome\.windows\.create\s*\(\s*\{[^}]*url\s*:/g, label: 'Window creation with URL — may open popups' },
  { pattern: /btoa\s*\(\s*(?!['"][A-Za-z0-9+\/=]+['"])/g, label: 'base64 encoding of dynamic data — possible obfuscation' },
];

// ── Scoring constants ─────────────────────────────────────────────────────────

const SCORE_WEIGHTS = {
  criticalPermission: -15,
  mediumPermission: -3,
  broadHost: -12,
  trackingDomain: -5,
  suspiciousPattern: -6,
  weakCSP: -5,
  contentScriptAllUrls: -7,
  missingVersion: -2,
};

const MAX_SCORE = 100;
const MIN_SCORE = 0;

// ── Risk level thresholds ─────────────────────────────────────────────────────

const RISK_LEVELS = [
  { min: 80, label: 'Low Risk', class: 'risk-low', icon: '🟢' },
  { min: 55, label: 'Medium Risk', class: 'risk-medium', icon: '🟡' },
  { min: 30, label: 'High Risk', class: 'risk-high', icon: '🟠' },
  { min: 0,  label: 'Critical Risk', class: 'risk-critical', icon: '🔴' },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Wrap a promise with a timeout. If it doesn't settle within `ms`,
 * the returned promise resolves to `fallbackValue` instead.
 */
function withTimeout(promise, ms, fallbackValue) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(fallbackValue), ms);
    promise
      .then((val) => {
        clearTimeout(timer);
        resolve(val);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve(fallbackValue);
      });
  });
}

function textDecoder() {
  return new TextDecoder('utf-8', { fatal: false });
}

/** Decode a Uint8Array to string */
function decode(arr) {
  return textDecoder().decode(arr);
}

/** Check if a permission is in a set (exact match) */
function hasPermission(permissions, permSet) {
  if (!permissions) return [];
  return permissions.filter((p) => permSet.has(p));
}

/** Check if any host permission matches broad patterns */
function hasBroadHost(permissions) {
  if (!permissions) return [];
  return permissions.filter((p) =>
    BROAD_HOST_PATTERNS.some((pattern) => {
      if (pattern === p) return true;
      // Check if the permission contains a broad wildcard
      if (p.includes('://*') && !p.match(/^[a-z]+:\/\/[^/]+\/[^*]/)) return true;
      return false;
    })
  );
}

/** Search for tracking domains in code strings */
function findTrackingDomains(code) {
  const found = [];
  for (const domain of TRACKING_DOMAINS) {
    if (code.includes(domain)) {
      found.push(domain);
    }
  }
  return found;
}

/** Search for suspicious patterns in code */
function findSuspiciousPatterns(code) {
  const found = [];
  for (const { pattern, label } of SUSPICIOUS_PATTERNS) {
    // Reset regex lastIndex since we reuse the same regex objects
    pattern.lastIndex = 0;
    const matches = code.match(pattern);
    if (matches) {
      found.push({ label, count: matches.length });
    }
  }
  return found;
}

// ── Main Review Engine ────────────────────────────────────────────────────────

export class CRXReviewer {
  /**
   * Analyze a Chrome Extension ZIP with a hard timeout.
   * Falls back to an error report if review takes too long.
   * @param {ArrayBuffer} zipBuffer
   * @param {number} [timeoutMs=15000]
   * @returns {Promise<object>}
   */
  async reviewWithTimeout(zipBuffer, timeoutMs = 15000) {
    return withTimeout(
      this.review(zipBuffer),
      timeoutMs,
      { _error: 'Review timed out. The extension may be too large, or an unexpected error occurred. The source code is still downloadable below.' }
    );
  }

  /**
   * Analyze a Chrome Extension ZIP and produce a privacy/security report.
   * @param {ArrayBuffer} zipBuffer — the extracted ZIP archive
   * @returns {Promise<object>} review report
   */
  async review(zipBuffer) {
    const issues = [];
    let score = MAX_SCORE;

    let manifest = null;
    let manifestRaw = '';
    const jsFiles = [];

    // ── Step 1: Parse ZIP ──────────────────────────────────────────────────
    let zip;
    try {
      zip = await JSZip.loadAsync(zipBuffer);
    } catch {
      return { _error: 'Unable to parse the ZIP archive inside the .crx file.' };
    }

    // ── Step 2: Extract manifest.json ──────────────────────────────────────
    const manifestFile = zip.file('manifest.json');
    if (!manifestFile) {
      return { _error: 'manifest.json not found — not a valid Chrome Extension.' };
    }

    try {
      manifestRaw = await manifestFile.async('string');
      manifest = JSON.parse(manifestRaw);
    } catch {
      return { _error: 'manifest.json is corrupted or contains invalid JSON.' };
    }

    // ── Step 2b: Extract JS files for code analysis ───────────────────────
    const jsEntries = zip.file(/\.[jt]s$/);
    for (const entry of jsEntries) {
      if (entry.name === 'manifest.json') continue;
      try {
        const code = await entry.async('string');
        jsFiles.push({ name: entry.name, code });
      } catch {
        // Skip binary/corrupt files
      }
    }

    // ── Step 4: Analyze manifest.json ──────────────────────────────────────
    const manifestVersion = manifest.manifest_version;
    const extName = manifest.name || '(unnamed)';
    const extVersion = manifest.version || '?';

    // 4a: Permissions analysis
    const permissions = [
      ...(manifest.permissions || []),
      ...(manifest.optional_permissions || []),
      ...(manifest.host_permissions || []),
    ];

    const criticalPerms = hasPermission(permissions, HIGH_RISK_PERMISSIONS);
    const mediumPerms = hasPermission(permissions, MEDIUM_RISK_PERMISSIONS);
    const broadHosts = hasBroadHost(permissions);

    for (const perm of criticalPerms) {
      issues.push({
        severity: 'critical',
        category: 'permissions',
        detail: `Uses "${perm}" permission — grants broad access to user data or browser control`,
      });
      score += SCORE_WEIGHTS.criticalPermission;
    }

    for (const perm of mediumPerms) {
      issues.push({
        severity: 'medium',
        category: 'permissions',
        detail: `Uses "${perm}" permission — may impact privacy`,
      });
      score += SCORE_WEIGHTS.mediumPermission;
    }

    for (const host of broadHosts) {
      issues.push({
        severity: 'high',
        category: 'host_permissions',
        detail: `Host permission "${host}" — can access content on any website`,
      });
      score += SCORE_WEIGHTS.broadHost;
    }

    // 4b: CSP analysis
    const csp = manifest.content_security_policy;
    if (csp) {
      const cspStr = typeof csp === 'string' ? csp : (csp.extension_pages || csp.sandbox || '');
      if (cspStr.includes("'unsafe-eval'")) {
        issues.push({
          severity: 'high',
          category: 'csp',
          detail: 'CSP allows eval() — enables dynamic code execution and potential XSS',
        });
        score += SCORE_WEIGHTS.weakCSP;
      }
      if (cspStr.includes('*')) {
        issues.push({
          severity: 'medium',
          category: 'csp',
          detail: 'CSP contains wildcard — weakens script-src restrictions',
        });
        score += SCORE_WEIGHTS.weakCSP;
      }
    } else if (manifestVersion >= 3) {
      // MV3 has a default strict CSP, so no issue
    } else {
      issues.push({
        severity: 'medium',
        category: 'csp',
        detail: 'No Content Security Policy defined — scripts may be less restricted',
      });
      score += SCORE_WEIGHTS.weakCSP;
    }

    // 4c: Content scripts analysis
    const contentScripts = manifest.content_scripts || [];
    for (const cs of contentScripts) {
      const matches = cs.matches || [];
      for (const match of matches) {
        if (BROAD_HOST_PATTERNS.includes(match) || match.includes('://*')) {
          issues.push({
            severity: 'medium',
            category: 'content_scripts',
            detail: `Content script injected on "${match}" — runs on a broad set of pages`,
          });
          score += SCORE_WEIGHTS.contentScriptAllUrls;
          break;
        }
      }
      if ((cs.js || []).length === 0 && (cs.css || []).length > 0) {
        // CSS-only content scripts are less of a concern
      }
    }

    // 4d: Version check
    if (!extVersion || extVersion === '?' || extVersion === '0.0') {
      issues.push({
        severity: 'low',
        category: 'metadata',
        detail: 'Missing or placeholder version number',
      });
      score += SCORE_WEIGHTS.missingVersion;
    }

    // ── Step 5: Analyze JavaScript code ────────────────────────────────────
    const allCode = jsFiles.map((f) => f.code).join('\n');

    // 5a: Tracking domains
    const trackers = findTrackingDomains(allCode);
    for (const tracker of trackers) {
      issues.push({
        severity: 'medium',
        category: 'tracking',
        detail: `References "${tracker}" — possible user tracking/analytics`,
      });
      score += SCORE_WEIGHTS.trackingDomain;
    }

    // 5b: Suspicious patterns
    const suspicious = findSuspiciousPatterns(allCode);
    for (const susp of suspicious) {
      const severity = susp.label.includes('eval') || susp.label.includes('Function') ? 'high' : 'medium';
      issues.push({
        severity,
        category: 'code_pattern',
        detail: `${susp.label} (found ${susp.count} occurrence${susp.count > 1 ? 's' : ''})`,
      });
      score += SCORE_WEIGHTS.suspiciousPattern;
    }

    // 5c: Remote resource loading
    // Filter out comment-only lines to reduce false positives from
    // URLs that appear in documentation or commented-out code.
    const RE_REMOTE_SCRIPT = /['"`]https?:\/\/[^'"`\s]+\.js['"`]/g;
    const nonCommentLines = allCode
      .split('\n')
      .filter((line) => {
        const trimmed = line.trim();
        return trimmed
          && !trimmed.startsWith('//')
          && !trimmed.startsWith('/*')
          && !trimmed.startsWith('*');
      })
      .join('\n');
    const remoteScriptsMatch = nonCommentLines.match(RE_REMOTE_SCRIPT);
    if (remoteScriptsMatch) {
      const deduped = [...new Set(remoteScriptsMatch.map((s) => s.replace(/['"`]/g, '')))];
      for (const url of deduped.slice(0, 5)) { // limit to 5
        issues.push({
          severity: 'high',
          category: 'remote_resources',
          detail: `Loads remote script: ${url} — code not under extension developer control`,
        });
        score += SCORE_WEIGHTS.suspiciousPattern;
      }
      if (deduped.length > 5) {
        issues.push({
          severity: 'high',
          category: 'remote_resources',
          detail: `... and ${deduped.length - 5} more remote scripts loaded`,
        });
      }
    }

    // ── Step 6: Calculate final score & risk level ─────────────────────────
    score = Math.max(MIN_SCORE, Math.min(MAX_SCORE, score));
    const riskLevel = RISK_LEVELS.find((r) => score >= r.min) || RISK_LEVELS[RISK_LEVELS.length - 1];

    // ── Step 7: Build summary ──────────────────────────────────────────────
    const stats = {
      totalPermissions: permissions.length,
      criticalPermissions: criticalPerms.length,
      mediumPermissions: mediumPerms.length,
      broadHostPermissions: broadHosts.length,
      jsFilesAnalyzed: jsFiles.length,
      trackingDomainsFound: trackers.length,
      suspiciousPatternsFound: suspicious.length,
      remoteScriptsFound: remoteScriptsMatch ? new Set(remoteScriptsMatch.map((s) => s.replace(/['"`]/g, ''))).size : 0,
      totalIssues: issues.length,
    };

    return {
      extName,
      extVersion,
      manifestVersion,
      score,
      riskLevel,
      stats,
      issues: issues.sort((a, b) => {
        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return sevOrder[a.severity] - sevOrder[b.severity];
      }),
      permissions: {
        declared: permissions,
        critical: criticalPerms,
        medium: mediumPerms,
        broadHosts,
      },
    };
  }
}
