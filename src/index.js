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

function validSource(source, target, page) {
  const dest = new URL(target);
  const keyword = source.toLowerCase();
  if (['*', 'http:', 'https:'].includes(keyword)) return true;
  if (keyword === "'self'") return page.origin === dest.origin;

  // shortcut: Compare literal paths for common GIS allowlists; check encoded paths in the browser.
  const match = /^(?:https?:\/\/)?(\*|(?:\*\.)?[a-z0-9.-]+)(?::(\*|\d+))?(\/[^?#]*)?$/i.exec(source);
  if (!match) return false;
  const [, host, port, path] = match;
  const hostname = host.toLowerCase();
  const hostMatch = hostname === '*' || (hostname.startsWith('*.')
    ? dest.hostname.endsWith(hostname.slice(1))
    : dest.hostname === hostname);
  if (!hostMatch || (port && port !== '*' && Number(port) !== 443)) return false;
  return !path || (path.endsWith('/') ? dest.pathname.startsWith(path) : dest.pathname === path);
}

function effectiveSources(directives, name) {
  const fallback = { 'script-src': 'script-src-elem', 'style-src': 'style-src-elem' };
  return directives.get(fallback[name]) ?? directives.get(name)
    ?? (name === 'frame-src' ? directives.get('child-src') : undefined)
    ?? directives.get('default-src');
}

function inspectCsp(checks, value, page) {
  if (!value) {
    add(checks, 'info', 'csp-absent', 'No enforcing CSP header was found; GIS is not blocked by a response-header CSP.', 'A CSP in HTML meta tags or applied by a proxy may still affect the page.');
    return;
  }
  // Multiple enforcing policies are cumulative. A comma-separated header can carry more than one.
  const policies = value.split(',').map(parsePolicy);
  for (const [directive, resource] of Object.entries(RESOURCE_URLS)) {
    for (const [index, policy] of policies.entries()) {
      const sources = effectiveSources(policy, directive);
      if (!sources) continue;
      if (directive === 'script-src' && sources.some(source => source.toLowerCase() === "'strict-dynamic'")) {
        add(checks, 'info', 'csp-script-dynamic', 'CSP script execution uses strict-dynamic; host allowlists alone cannot determine whether the GIS script is allowed.', 'Verify a trusted nonce/hash chain in the browser.');
        continue;
      }
      if (sources.some(source => validSource(source, resource, page))) continue;
      if (directive === 'script-src' && sources.some(source => /^'(?:nonce-|sha(?:256|384|512)-)/i.test(source))) {
        add(checks, 'info', 'csp-script-dynamic', 'CSP uses a script nonce or hash; host allowlists alone cannot determine whether the GIS script is allowed.', 'Verify the SDK request and its nonce or integrity metadata in the browser.');
      } else {
        add(checks, 'warn', `csp-${directive}`, `CSP policy ${index + 1} might block the GIS ${directive} resource.`, `Review ${directive} and allow ${resource} where appropriate. ${DOCS}#content_security_policy`);
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
  const isLocal = /^127\.\d+\.\d+\.\d+$/.test(target.hostname) || /^(?:.*\.)?localhost\.?$|^\[::1\]$/.test(target.hostname);
  if (target.protocol === 'https:' || isLocal) {
    add(checks, 'pass', 'secure-context', 'The URL uses HTTPS or a localhost development origin.');
  } else {
    add(checks, 'error', 'insecure-context', 'Google One Tap / FedCM requires a secure context.', 'Serve this page over HTTPS or use localhost for development.');
  }

  // shortcut: Scan initial script tags heuristically; use an HTML parser if inert markup must be distinguished.
  const sdkScriptMatches = [...html.matchAll(/<script(?=[\s/>])((?:"[^"]*"|'[^']*'|[^"'<>])*)>/gi)].filter(([, attributes]) => {
    const src = [...attributes.matchAll(/([^\s/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s]+)))?/g)]
      .find(([, name]) => name.toLowerCase() === 'src');
    return src && /^https:\/\/accounts\.google\.com\/gsi\/client(?:[?#].*)?$/.test(src[2] ?? src[3] ?? src[4] ?? '');
  });
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
  inspectCsp(checks, String(getHeader(headers, 'content-security-policy')), target);
  const reportOnly = getHeader(headers, 'content-security-policy-report-only');
  if (reportOnly) add(checks, 'info', 'csp-report-only', 'A report-only CSP is present; violations under this policy do not block loading.');
  const coop = String(getHeader(headers, 'cross-origin-opener-policy')).split(';', 1)[0].trim();
  if (coop === 'same-origin') {
    add(checks, 'warn', 'coop-popup-risk', 'COOP same-origin can break non-FedCM Google login / authorization popups.', 'If using popups that need cross-window communication, review same-origin-allow-popups. FedCM sign-in may not need this change.');
  } else if (coop === 'same-origin-allow-popups') {
    add(checks, 'pass', 'coop-popup-compatible', 'COOP uses same-origin-allow-popups; verify the popup flow in the browser.');
  } else {
    add(checks, 'info', 'coop-unknown', 'COOP is absent or uses another value; confirm popup behavior in the browser if relevant.');
  }
  const permissions = String(getHeader(headers, 'permissions-policy'));
  if (/(?:^|,)\s*identity-credentials-get\s*=\s*\(\s*\)/i.test(permissions)) {
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
  if (parsed.username || parsed.password) throw new TypeError('URL credentials are unsupported');
  const response = await fetcher(url, { redirect: 'follow', signal: AbortSignal.timeout(timeoutMs), credentials: 'omit' });
  if (!response.ok) throw new Error(`HTTP ${response.status} while fetching login page`);
  let html = '';
  const decoder = new TextDecoder();
  let size = 0;
  for await (const chunk of response.body ?? []) {
    size += chunk.byteLength;
    if (size > 2_000_000) throw new Error('HTML response is too large to inspect (2 MB limit)');
    html += decoder.decode(chunk, { stream: true });
  }
  html += decoder.decode();
  return inspectGoogleIdentityPage({ url: response.url || url, headers: response.headers, html });
}
