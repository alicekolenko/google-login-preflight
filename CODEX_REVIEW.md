# Codex review brief — Google Login Preflight

Goal: prove or disprove that this tiny independent web Google Identity Services diagnostic CLI is useful. Keep the scope small. Do NOT build another login SDK.

## Working rules
- Work ONLY on `develop`. Leave `main` untouched and do NOT publish to npm.
- Treat imported MVP code as UNREVIEWED experimental code, not a finished solution.
- Prefer documentation-verified, test-backed fixes over adding features or dependencies.
- Do not request, capture, log, or store Google credentials, cookies, tokens, or secrets.

## Independent review
1. Compare the implemented CSP, COOP, FedCM, Permissions-Policy and GIS SDK checks against current official Google/Chrome docs. Call out false positives, false negatives, and anything that sounds overly certain.
2. Review URL fetching, redirects, timeouts, error handling, HTML parsing, SSR/dynamic script limitations, and CLI exit codes.
3. Run `npm test` and `npm pack --dry-run` and independently assess package quality, TypeScript declarations, bin behavior and Node compatibility.
4. Fix only serious correctness defects and missing tests needed for a credible proof; avoid expanding scope.

## Proof of functionality / acceptance
- Add/execute an end-to-end CLI smoke test against local fixture HTTP pages (healthy vs intentionally bad CSP/COOP).
- Show the CLI output and exit status with normal / --strict / --json.
- Tests must validate detection of known misconfigurations and explicitly distinguish unknown browser/runtime OAuth outcomes.
- If possible, try a PUBLIC real login page without submitting credentials; note that dynamic scripts and private Google Cloud settings cannot be checked statically.
- CI should run on pushes to develop.

## Report
Provide: critical findings (with evidence), changes/commit(s), passing/failing checks, a demonstration of both positive and negative detection, known limitations, and a clear GO/NO-GO for publishing this utility as an experimental npm package.
