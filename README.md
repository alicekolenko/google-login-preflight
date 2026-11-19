# Google GIS Preflight (experimental MVP)

A **zero-dependency** command-line preflight for [Google Identity Services (GIS)](https://developers.google.com/identity/gsi/web/guides/overview) sign-in on the web.

**Why?** Many Google login failures come from environment configuration rather than the login button: CSP, COOP, mismatched origins, unavailable SDK scripts or deprecated integrations. This tool surfaces some of those risks as actionable diagnostics, irrespective of React, Vue, Next.js, or the identity library you choose.

**What it is not:** an OAuth library, a sign-in simulator, a browser automation tool, or a security audit. It cannot inspect Google Cloud Console settings, guarantee OAuth success, diagnose dynamically executed JavaScript, or verify backend ID tokens. Never use it as proof an authentication implementation is secure.

## Quick start (from this repository)

```sh
node bin/gis-preflight.js https://your-domain.example/login
node bin/gis-preflight.js http://localhost:3000/login --json
node bin/gis-preflight.js https://your-domain.example/login --strict
```

The intended npm package name is **provisional** (`@karmadev/gis-preflight`): it is **not published** and npm ownership/availability has **not** been verified. After publication, the CLI can be run through `npx @karmadev/gis-preflight` if that name is available and owned.

## Checks performed

| Check | What we can infer |
| --- | --- |
| HTTPS / localhost | Whether the page URL is an appropriate secure context |
| GIS SDK script in initial HTML | Detects one/multiple direct GIS script tags, but not dynamic loading |
| Deprecated Google Sign-In | Flags visible `gapi.auth2` / `platform.js` usage |
| Enforcing response CSP | Flags common policies that appear to restrict the Google-recommended GIS sources. Some individually listed endpoints can work for a particular flow. |
| COOP popup compatibility | Warns about `same-origin` when non-FedCM popups need cross-window communication |
| Permissions-Policy | Warns if `identity-credentials-get` is explicitly disabled |
| Manual checks | Reminds you to verify Google Cloud origins, redirect URIs, iframe permissions, runtime FedCM status, and backend token verification |

Only HTTP response **headers** and server-delivered **HTML** are inspected. No Google account is accessed; no cookies, tokens or credentials are supplied to the target. The query string is removed from report output. The CLI starts at the URL you supply and follows HTTP redirects, including redirects to another host. It uses a 10-second timeout and stops reading successful responses above 2 MB. Use it on a publicly reachable or local development page without authentication.

`--json` outputs a versioned report. By default warnings do not affect the exit status; `--strict` makes warnings fail CI. Exit codes are `0` (no blocking findings), `1` (findings) and `2` (invalid input or request failed).

## Programmatic use

```js
import { inspectGoogleIdentityPage, scanGoogleIdentityUrl } from '@karmadev/gis-preflight';

const report = inspectGoogleIdentityPage({
  url: 'https://example.com/login',
  headers: { 'cross-origin-opener-policy': 'same-origin' },
  html: '<script src="https://accounts.google.com/gsi/client" async></script>',
});
console.log(report.checks);

// Or fetch a target page:
// const liveReport = await scanGoogleIdentityUrl('http://localhost:3000/login');
```

## Important limitations

- A missing SDK tag in server HTML can be normal for client-side dynamic loaders. This is **informational**, not an error.
- Even if the SDK script exists, a Google account login may fail because of settings in Google Cloud Console (not accessible to a static scan), user choices, browser behavior, or server logic.
- `google.accounts.id.initialize()` called multiple times is a real GIS issue, but cannot be reliably detected from HTML alone.
- COOP `same-origin` is a **conditional warning**, not always a bug; FedCM-driven sign-in can work without changing it.
- CSP policies with nonces, hashes, `strict-dynamic`, encoded source paths, or HTML meta policies require manual verification. The SDK tag check can count inert markup, such as scripts in comments or templates.
- **Server-side ID token verification is mandatory** for security-critical decisions; never trust profile details obtained solely from browser-side JWT decoding.
- This is an independent project; not affiliated with or endorsed by Google.

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
