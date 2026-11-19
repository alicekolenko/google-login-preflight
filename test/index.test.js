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
    fetcher: async () => ({
      ok: true,
      status: 200,
      url: 'https://example.com/login?token=private',
      headers: new Headers({'cross-origin-opener-policy': 'same-origin-allow-popups'}),
      text: async () => script,
    }),
  });
  assert.equal(report.url, 'https://example.com/login');
  assert.ok(has(report, 'coop-popup-compatible'));
});

test('rejects non-HTTP schemes and failing requests', async () => {
  await assert.rejects(() => scanGoogleIdentityUrl('file:///tmp/secret'), /HTTP\(S\)/);
  await assert.rejects(() => scanGoogleIdentityUrl('https://example.com', {
    fetcher: async () => ({ok: false, status: 403}),
  }), /HTTP 403/);
});
