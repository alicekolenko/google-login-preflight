# Google Login Preflight

Google sign-in can fail when a page’s headers block the Google Identity Services (GIS) SDK or interfere with a popup. Google Login Preflight checks those headers and the initial HTML for common configuration issues. It’s a zero-dependency CLI that works with any web framework.

## Quick start

With Node.js 20 or later, run this from your application’s directory. Replace the URL with your deployed login page or local development server.

```sh
npx @karmadev.studio/google-login-preflight http://127.0.0.1:3000/login
```

Add `--json` for a versioned, machine-readable report or `--strict` to make warnings fail CI. Exit codes are `0` for no blocking findings, `1` for errors or warnings in strict mode, and `2` for invalid input or a failed request.

To install globally, run `npm install --global @karmadev.studio/google-login-preflight`, then use `google-login-preflight <url>`. From this repository’s checkout, use `node bin/google-login-preflight.js <url>`.

### Example output (excerpt)

A local test page with the GIS SDK tag and `Cross-Origin-Opener-Policy: same-origin` produced these lines:

```text
[PASS] GIS SDK script is present in the server-delivered HTML.
[WARN] COOP same-origin can break non-FedCM Google login / authorization popups.
  → If using popups that need cross-window communication, review same-origin-allow-popups. FedCM sign-in may not need this change.
```

## What the CLI checks

| Check | What the report tells you |
| --- | --- |
| HTTPS or loopback URL | Whether the URL uses HTTPS or a recognized local development origin |
| GIS SDK tag | Whether the initial HTML contains a direct SDK tag or apparent duplicates |
| Deprecated Google Sign-In | Whether the HTML contains possible `gapi.auth2` or `platform.js` references |
| Enforcing response CSP | Whether common policy rules appear to restrict Google’s recommended GIS sources. Endpoint-specific allowlists may work for some flows. |
| COOP | Whether `same-origin` could interfere with non-FedCM popups that need cross-window communication |
| Permissions-Policy | Whether the response explicitly disables `identity-credentials-get` |

The CLI inspects HTTP response headers and server-delivered HTML. It follows redirects, including to another host, uses a 10-second timeout, and stops reading successful responses above 2 MB. It fetches without credentials, cookies, or tokens and omits query strings from the report. Use a publicly reachable or local page that does not require authentication.

## What to verify manually

- **In the browser**, check that the SDK loads, GIS initializes as intended, and the relevant popup or FedCM flow works with the browser’s settings and iframe permissions. Dynamic loading can explain an informational missing-tag finding. Inert markup such as comments or templates can count toward the tag check. A static scan cannot reliably detect repeated `google.accounts.id.initialize()` calls.
- **For CSP**, confirm the actual browser requests when policies use nonces, hashes, `strict-dynamic`, encoded paths, or HTML meta tags.
- **In Google Cloud Console**, verify the authorized JavaScript origins and any redirect URIs against your deployed configuration.
- **On the server**, verify ID tokens before making security-critical decisions. Browser-side decoding alone does not verify a token.

A clean report covers the static checks above. Sign-in success and application security require browser and server validation. This project is independent of Google.

## Programmatic use

```js
import { inspectGoogleIdentityPage, scanGoogleIdentityUrl } from '@karmadev.studio/google-login-preflight';

const report = inspectGoogleIdentityPage({
  url: 'https://example.com/login',
  headers: { 'cross-origin-opener-policy': 'same-origin' },
  html: '<script src="https://accounts.google.com/gsi/client" async></script>',
});
console.log(report.checks);

// Or fetch a target page:
// const liveReport = await scanGoogleIdentityUrl('http://localhost:3000/login');
```

## Official references

- [Google Identity Services overview](https://developers.google.com/identity/gsi/web/guides/overview)
- [Google Identity Services setup, CSP and COOP](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid)
- [GIS JavaScript API](https://developers.google.com/identity/gsi/web/reference/js-reference)
- [Migration to FedCM](https://developers.google.com/identity/gsi/web/guides/fedcm-migration)
- [Chrome FedCM troubleshooting tools](https://developer.chrome.com/docs/identity/fedcm/setup)

## Contributing

This is a small proof of concept. Contributions should prioritize reliable, non-invasive diagnostics with actionable output, test fixtures, and an explicit distinction between **confirmed** and **possible** problems. No analytics or telemetry.

```sh
npm test
npm pack --dry-run
node --test test/cli.test.js
```

The CLI smoke test starts a loopback HTTP server with a GIS-recommended CSP fixture and a restrictive CSP/COOP fixture. It checks normal, strict, JSON, and strict JSON modes.

MIT licensed.
