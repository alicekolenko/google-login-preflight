/**
 * A conservative HTTP/HTML preflight for Google Identity Services integrations.
 * Never treats static inspection as proof that an authentication flow works.
 * No credentials, cookies, or tokens are required or collected.
 */

const DOCS = 'https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid';
const SDK_URL = 'https://accounts.google.com/gsi/client';
const RESOURCE_URLS = {
  'script-src': SDK_URL,
  'frame-src': 'https://accounts.google.com/gsi/',
  'connect-src': 'https://accounts.google.com/gsi/',
  'style-src': 'https://accounts.google.com/gsi/style',
};

function getHeader(headers, name) {
  if (typeof headers?.get === 'function') return headers.get(name) || '';
  return Object.entries(headers || {}).find(([key]) => key.toLowerCase() === name)?.[1] ?? '';
}

function add(checks, severity, code, message, action) {
  checks.push({ severity, code, message, ...(action ? { action } : {}) });
}

function parsePolicy(value) {
  const directives = new Map();
  for (const part of value.split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/).filter(Boolean);
    if (name && !directives.has(name.toLowerCase())) {
      directives.set(name.toLowerCase(), sources);
    }
  }
  return directives;
}

function validSource(source, target) {
  const s = source.trim().toLowerCase();
  const dest = new URL(target);
  if (s === '*' || s === 'https:') return true;
  if (s === "'none'" || s === "'self'" || s.startsWith("'nonce-") || s.startsWith("'sha")) return false;
  // Bare hosts and https:// hosts are permitted by CSP's host-source syntax.
  const candidate = s.startsWith('https://') ? s : s.startsWith('accounts.google.com') || s.startsWith('*.google.com') ? `https://${s}` : null;
  if (!candidate) return false;
  try {
    const sourceUrl = new URL(candidate);
    const host = sourceUrl.hostname;
    const hostMatch = host.startsWith('*.')
      ? (dest.hostname.endsWith(host.slice(1)) && dest.hostname !== host.slice(2))
      : host === dest.hostname;
    if (!hostMatch || sourceUrl.protocol !== dest.protocol) return false;
    // CSP host-source path prefix: trailing '/' allows descendants.
    const path = sourceUrl.pathname;
    return path === '/' || (path.endsWith('/') ? dest.pathname.startsWith(path) : dest.pathname === path);
  } catch {
    return false;
  }
}

function effectiveSources(directives, name) {
  if (name === 'script-src' && directives.has('script-src-elem')) return directives.get('script-src-elem');
  if (name === 'frame-src' && directives.has('child-src')) return directives.get('frame-src') || directives.get('child-src');
  return directives.get(name) ?? directives.get('default-src');
}

function inspectCsp(checks, value, label = 'CSP') {
  if (!value) {
    add(checks, 'info', 'csp-absent', 'No enforcing CSP header was found; GIS is not blocked by a response-header CSP.', 'A CSP in HTML meta tags or applied by a proxy may still affect the page.');
    return;
  }
  // Multiple enforcing policies are cumulative. A comma-separated header can carry more than one.
  const policies = value.split(/,(?=\s*[a-z][\w-]*\s)/i).map(parsePolicy);
  for (const [directive, resource] of Object.entries(RESOURCE_URLS)) {
    for (const [index, policy] of policies.entries()) {
      const sources = effectiveSources(policy, directive);
      if (!sources) continue;
      if (directive === 'script-src' && sources.includes("'strict-dynamic'")) {
        add(checks, 'info', 'csp-script-dynamic', `${label} script execution uses strict-dynamic; host allowlists alone cannot determine whether the GIS script is allowed.`, 'Verify a trusted nonce/hash chain in the browser.');
        continue;
      }
      if (!sources.some(source => validSource(source, resource))) {
        add(checks, 'warn', `csp-${directive}`, `${label} policy ${index + 1} might block the GIS ${directive} resource.`, `Review ${directive} and allow ${resource} where appropriate. ${DOCS}#content_security_policy`);
      }
    }
  }
}

function sanitizeUrl(url) {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`; // Query strings may contain sensitive application data.
}

/**
 * Analyze the HTTP response for a page that implements Google login.
 * This is static inspection and does not execute page scripts or complete sign-in.
 */
export function inspectGoogleIdentityPage({ url, headers = {}, html = '' }) {
  const target = new URL(url);
  if (!['http:', 'https:'].includes(target.protocol)) throw new TypeError('Expected an HTTP(S) URL');
  const checks = [];
  const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(target.hostname);
  if (target.protocol === 'https:' || isLocal) {
    add(checks, 'pass', 'secure-context', 'The URL uses HTTPS or a localhost development origin.');
  } else {
    add(checks, 'error', 'insecure-context', 'Google One Tap / FedCM requires a secure context.', 'Serve this page over HTTPS or use localhost for development.');
  }

  const sdkScriptMatches = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']https:\/\/accounts\.google\.com\/gsi\/client(?:[?#][^"']*)?["'][^>]*>/gi)];
  if (sdkScriptMatches.length === 1) {
    add(checks, 'pass', 'gis-sdk-present', 'GIS SDK script is present in the server-delivered HTML.');
  } else if (sdkScriptMatches.length > 1) {
    add(checks, 'warn', 'gis-sdk-duplicated', `The GIS SDK script appears ${sdkScriptMatches.length} times in initial HTML.`, 'Load the GIS SDK once. This does not detect repeated google.accounts.id.initialize() calls.');
  } else {
    add(checks, 'info', 'gis-sdk-undetected', 'GIS SDK script was not found in initial HTML.', 'If your app loads the SDK dynamically, inspect the Network panel; this is not evidence of failure.');
  }
  if (/\bgapi\s*\.\s*auth2\b|apis\.google\.com\/js\/platform\.js/i.test(html)) {
    add(checks, 'warn', 'legacy-google-signin', 'Possible use of the deprecated Google Sign-In platform library.', 'Migrate legacy gapi.auth2 / platform.js integration to GIS.');
  }
  inspectCsp(checks, String(getHeader(headers, 'content-security-policy')));
  const reportOnly = getHeader(headers, 'content-security-policy-report-only');
  if (reportOnly) add(checks, 'info', 'csp-report-only', 'A report-only CSP is present; violations under this policy do not block loading.');
  const coop = String(getHeader(headers, 'cross-origin-opener-policy')).trim().toLowerCase();
  if (coop === 'same-origin') {
    add(checks, 'warn', 'coop-popup-risk', 'COOP same-origin can break non-FedCM Google login / authorization popups.', 'If using popups that need cross-window communication, review same-origin-allow-popups. FedCM sign-in may not need this change.');
  } else if (coop === 'same-origin-allow-popups') {
    add(checks, 'pass', 'coop-popup-compatible', 'COOP permits popup communication needed by supported non-FedCM flows.');
  } else {
    add(checks, 'info', 'coop-unknown', 'COOP is absent or uses another value; confirm popup behavior in the browser if relevant.');
  }
  const permissions = String(getHeader(headers, 'permissions-policy'));
  if (/\bidentity-credentials-get\s*=\s*\(\s*\)/i.test(permissions)) {
    add(checks, 'warn', 'fedcm-policy-denied', 'Permissions-Policy explicitly disables identity-credentials-get.', 'Allow the feature for the relevant origin; nested cross-origin iframes also need allow="identity-credentials-get".');
  }
  add(checks, 'info', 'cloud-console-manual', 'OAuth client Authorized JavaScript origins and redirect URIs cannot be verified from this page.', `Check Google Cloud Console manually against ${target.origin}.`);
  add(checks, 'info', 'runtime-manual', 'Repeated GIS initialization, browser permissions, FedCM prompts, and token verification require runtime/server testing.', 'For FedCM use Chrome DevTools Network filter resource-type:fedcm; never trust client-side ID-token parsing as server verification.');
  const summary = {
    errors: checks.filter(item => item.severity === 'error').length,
    warnings: checks.filter(item => item.severity === 'warn').length,
    passes: checks.filter(item => item.severity === 'pass').length,
    informational: checks.filter(item => item.severity === 'info').length,
  };
  return { schemaVersion: 1, url: sanitizeUrl(url), summary, checks };
}

/** Fetch one caller-supplied URL without cookies, credentials, or custom headers. */
export async function scanGoogleIdentityUrl(url, { fetcher = globalThis.fetch, timeoutMs = 10000 } = {}) {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new TypeError('Expected an HTTP(S) URL');
  const response = await fetcher(url, { redirect: 'follow', signal: AbortSignal.timeout(timeoutMs), credentials: 'omit' });
  if (!response.ok) throw new Error(`HTTP ${response.status} while fetching login page`);
  const html = await response.text();
  if (html.length > 2_000_000) throw new Error('HTML response is too large to inspect (2 MB limit)');
  return inspectGoogleIdentityPage({ url: response.url || url, headers: response.headers, html });
}
