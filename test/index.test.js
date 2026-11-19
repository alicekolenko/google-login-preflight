import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { inspectGoogleIdentityPage, scanGoogleIdentityUrl } from '../src/index.js';

const script = '<script async src="https://accounts.google.com/gsi/client"></script>';
const has = (report, code) => report.checks.some(check => check.code === code);
const config = (headers = {}, html = script, url = 'https://example.com/login') =>
  inspectGoogleIdentityPage({ url, headers, html });

test('passes canonical resource allowlist under enforcing CSP', () => {
  const report = config({
    'content-security-policy': 'default-src \'self\'; script-src https://accounts.google.com/gsi/client; frame-src https://accounts.google.com/gsi/; connect-src https://accounts.google.com/gsi/; style-src https://accounts.google.com/gsi/style',
    'cross-origin-opener-policy': 'same-origin-allow-popups',
  });
  assert.equal(report.summary.warnings, 0);
  assert.equal(report.summary.errors, 0);
  assert.ok(has(report, 'gis-sdk-present'));
});

test('detects insecure non-local URL', () => {
  const report = config({}, script, 'http://example.com/login');
  assert.ok(has(report, 'insecure-context'));
  assert.equal(report.summary.errors, 1);
});

test('permits localhost development', () => {
  const report = config({}, script, 'http://localhost:3000/login');
  assert.ok(has(report, 'secure-context'));
});

test('warns for all missing GIS CSP allowances', () => {
  const report = config({'content-security-policy': "default-src 'self'"});
  for (const item of ['script-src', 'frame-src', 'connect-src', 'style-src']) {
    assert.ok(has(report, `csp-${item}`), `missing warning for ${item}`);
  }
});

test('handles path-specific allowlists conservatively', () => {
  const report = config({'content-security-policy': 'default-src https://accounts.google.com/other/'});
  assert.ok(has(report, 'csp-script-src'));
});

test('strict-dynamic is classified as indeterminate, not a false warning', () => {
  const report = config({'content-security-policy': "script-src 'nonce-random' 'strict-dynamic'; frame-src https://accounts.google.com/gsi/"});
  assert.ok(has(report, 'csp-script-dynamic'));
  assert.equal(report.summary.warnings, 0);
});

test('warns conditionally for COOP and explicit FedCM policy denial', () => {
  const report = config({
    'cross-origin-opener-policy': 'same-origin',
    'permissions-policy': 'geolocation=(), identity-credentials-get=()',
  });
  assert.ok(has(report, 'coop-popup-risk'));
  assert.ok(has(report, 'fedcm-policy-denied'));
});

test('detects legacy integration and duplicate scripts', () => {
  const report = config({}, `${script}${script}<script>gapi.auth2.init({});</script>`);
  assert.ok(has(report, 'gis-sdk-duplicated'));
  assert.ok(has(report, 'legacy-google-signin'));
});

test('does not claim dynamic SDK loading is broken', () => {
  const report = config({}, '<div id="root"></div>');
  assert.ok(has(report, 'gis-sdk-undetected'));
  assert.equal(report.summary.warnings, 0);
});

test('does not expose URL query parameters or fragment', () => {
  const report = config({}, script, 'https://example.com/login?code=secret#access_token=private');
  assert.equal(report.url, 'https://example.com/login');
});

test('supports injectable fetch for isolated testing', async () => {
  const report = await scanGoogleIdentityUrl('https://example.com/login?token=private', {
    fetcher: async () => new Response(script, {
      headers: {'cross-origin-opener-policy': 'same-origin-allow-popups'},
    }),
  });
  assert.equal(report.url, 'https://example.com/login');
  assert.ok(has(report, 'coop-popup-compatible'));
  assert.ok(has(report, 'gis-sdk-present'));
});

test('rejects non-HTTP schemes and failing requests', async () => {
  await assert.rejects(() => scanGoogleIdentityUrl('file:///tmp/secret'), /HTTP\(S\)/);
  await assert.rejects(() => scanGoogleIdentityUrl('https://example.com', {
    fetcher: async () => ({ok: false, status: 403}),
  }), /HTTP 403/);
});

test('CSP does not allow the SDK through an incorrect port or case-sensitive path', () => {
  for (const source of ['https://accounts.google.com:8443', 'https://accounts.google.com/GSI/client']) {
    assert.ok(has(config({'content-security-policy': "script-src " + source}), 'csp-script-src'));
  }
});

test('CSP handles wildcard ports and same-origin sources', () => {
  assert.equal(config({'content-security-policy': 'script-src https://accounts.google.com:*/gsi/client'}).summary.warnings, 0);
  assert.equal(config({'content-security-policy': "script-src 'self'"}, script, 'https://accounts.google.com/login').summary.warnings, 0);
});

test('each enforcing CSP policy applies, including directives without values', () => {
  assert.ok(has(config({'content-security-policy': 'script-src https:, script-src'}), 'csp-script-src'));
});

test('CSP nonce-only script policy remains indeterminate', () => {
  assert.equal(config({'content-security-policy': "script-src 'nonce-fixture'"}).summary.warnings, 0);
});

test('SDK tag requires a src attribute and recognizes unquoted values', () => {
  assert.ok(has(config({}, '<script data-src="https://accounts.google.com/gsi/client"></script>'), 'gis-sdk-undetected'));
  assert.ok(has(config({}, '<script src=https://accounts.google.com/gsi/client></script>'), 'gis-sdk-present'));
});

test('COOP detects same-origin with a reporting endpoint', () => {
  assert.ok(has(config({'cross-origin-opener-policy': 'same-origin; report-to="coop"'}), 'coop-popup-risk'));
});

test('rejects oversized responses before reading to completion', async () => {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(2_000_001));
    },
    cancel() {
      cancelled = true;
    },
  });
  await assert.rejects(
    () => scanGoogleIdentityUrl('https://example.com', {fetcher: async () => new Response(body)}),
    /2 MB limit/,
  );
  assert.ok(cancelled);
});

test('external stylesheet checks respect style-src-elem before style-src', () => {
  const headers = {'content-security-policy': "style-src https:; style-src-elem 'none'"};
  assert.ok(has(config(headers), 'csp-style-src'));
});

test('recognizes local development origins without trusting hostname lookalikes', () => {
  for (const host of ['127.0.0.2', 'app.localhost', '[::1]']) {
    assert.ok(has(config({}, script, `http://${host}/login`), 'secure-context'));
  }
  assert.ok(has(config({}, script, 'http://127.example.com/login'), 'insecure-context'));
});
