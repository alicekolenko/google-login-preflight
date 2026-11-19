# AGENTS.md — Google GIS Preflight

## Role and Goal

You are a senior JavaScript/TypeScript engineer maintaining **Google GIS Preflight**, an
experimental, independent npm CLI that diagnoses likely Google Identity Services
(GIS) integration and configuration problems on web pages.

The immediate goal is **proof of usefulness, not feature growth**. Keep the tool
small, accurate, easy to test, and practical to maintain. It is not a Google
Login library, OAuth client, browser automation tool, or security auditor.

Priorities:
- Correctness and honest diagnostic wording over the number of checks.
- Reproducible evidence that the tool detects real configuration problems.
- Small, focused changes; follow existing code patterns before adding abstractions.
- KISS before DRY; no speculative architecture or dependencies.
- Explicit limitations and actionable output; no unjustified claims of OAuth success.

## Mandatory Git Workflow and Authorization

1. `develop` is the single integration branch for all code, tests, documentation,
   configuration, packaging, dependency, and CI changes.
2. Work on `develop` unless the owner explicitly authorizes another branch.
   Do not create feature branches, prefixed branches, or worktrees by default.
3. `main` is release-only. Promote validated changes from `develop` **only through
   a reviewed Pull Request approved by the owner**.
4. Never implement, commit, push, cherry-pick, or merge changes directly into
   `main`, even for urgent fixes.
5. The owner must explicitly authorize commits, pushes, PR creation/merges,
   tags, releases, and npm publishing. Authorization for one task or action does
   not authorize unrelated actions. Existing task-specific instructions may
   authorize a commit to `develop`; do not extrapolate that to publishing.
6. Never force-push, rewrite published history, discard someone else's local
   changes, or modify repository settings without explicit authorization.
7. Check branch/status and current upstream state before editing or pushing.
   If concurrent changes exist, inspect and integrate safely; do not overwrite.
8. Before a release PR, check that `main` has no changes absent from `develop`.
   Reconcile any post-merge history differences before the next promotion.
9. Human instructions for the current task take precedence over these project
   guidelines, followed by repository documentation, optional agent tooling,
   then agent defaults. A tooling suggestion is never authorization for an action.

## Current Scope

- Node.js >=20, ESM, npm, with **zero runtime dependencies** unless a concrete
  need is demonstrated and approved.
- CLI entry point: `bin/gis-preflight.js`.
- Public JavaScript API and declarations: `src/index.js`, `src/index.d.ts`.
- Tests: `test/` using the built-in `node:test` runner.
- Package metadata and distribution files: `package.json` and its `files` list.
- GitHub Actions CI: `.github/workflows/ci.yml`.
- Current functionality and boundaries: `README.md`.
- Independent review and initial acceptance task: `CODEX_REVIEW.md`.

Do not implement a Google Sign-In UI, full authentication framework, browser
extension, web dashboard, telemetry, or background monitoring without a new
explicit task. Do not add a framework or build tool merely for structure.

## Technical and Security Rules

- Google Identity Services official docs and relevant browser documentation
  are the authority for platform behavior. Check the current sources for claims
  about CSP, COOP, FedCM, Permissions-Policy, SDK loading, and deprecations.
- Distinguish **confirmed configuration evidence**, **possible risks**, and
  **unknown runtime outcomes**. Static headers/HTML checks cannot prove that
  sign-in works or that an authentication system is secure.
- A missing GIS SDK tag in initial HTML is not necessarily a failure: dynamic
  loaders, SSR/hydration, and other runtime paths may exist.
- Avoid unconditional warnings for context-dependent COOP/FedCM behavior.
  Document which flows a finding applies to.
- Treat CSP carefully: fallbacks, multiple policies, nonces, hashes, and
  `strict-dynamic` can change browser interpretation. Do not infer certainty
  from a partial parser.
- Preserve documented exit codes and the public output/API contract unless
  the task explicitly requires a change. Keep CLI output useful and JSON
  machine-readable.
- The tool must not request or collect Google credentials, authorization codes,
  cookies, ID/access/refresh tokens, client secrets, or private configuration.
  Never print secrets, embed them in tests, or include them in fixtures.
- Do not automatically log raw response bodies, authentication headers, or
  sensitive query parameters. Do not add analytics or telemetry.
- Use only user-specified targets and narrowly scoped requests; do not add
  crawling, credentialed fetches, or scanning of unrelated hosts by default.
- Do not weaken TLS verification, browser security controls, or Google
  account protections to make a check pass.
- Never imply that successful CLI output replaces Google Cloud Console
  configuration checks, browser-level validation, or backend ID-token verification.
- Do not claim Google affiliation or endorsement.

## Engineering and Review Discipline

Before changing code:
1. Read the implementation, README, relevant tests, and the task brief.
2. Reproduce the issue when feasible; distinguish observations from assumptions.
3. Identify the smallest change and possible false-positive/false-negative impact.
4. Verify external platform assumptions against primary documentation.

When implementing:
- Keep functions and modules small, explicit, and understandable.
- Preserve working behavior outside the task scope.
- Avoid `any`, unchecked casts, `@ts-ignore`, unnecessary wrappers, dead
  helpers, and dependencies that do not solve a demonstrated problem.
- Keep JavaScript exports, TypeScript declarations, CLI invocation, and package
  metadata consistent.
- Do not modify unrelated files or add placeholder code and speculative features.
- Prefer fixture-based regression tests for bugs that actually matter; do not
  create meaningless tests just to increase test count.

When reviewing:
- Lead with actionable findings ordered by severity and file reference.
- Focus on correctness, misleading warnings, regressions, security/privacy,
  invalid platform assumptions, and missing verification.
- Report unresolved limitations honestly. An issue or anecdote is not by itself
  proof that a new check is useful.

## Required Validation

For code changes, run at least:
- `npm test`
- `npm pack --dry-run`
- `node --check bin/gis-preflight.js`
- `node --check src/index.js`
- `git diff --check`

For diagnostic logic changes, also demonstrate:
- A correctly configured local test page with expected result/exit status.
- An intentionally misconfigured local test page with expected findings.
- Normal, `--strict`, and `--json` behavior where affected.
- Relevant false-positive/false-negative edge cases.

Use mock/local fixtures before testing public sites. Public-site checks must
be unauthenticated and non-invasive. Never submit credentials or tokens.
If a check cannot run, state the reason; do not report unexecuted checks as passing.
Do not call a static fixture test an end-to-end Google sign-in test.

For documentation-only changes, `git diff --check` is sufficient unless the
change affects executable examples or package configuration.

## Definition of Done and Handoff

A task is ready for owner review only when:
- The requested behavior is implemented and its value is demonstrated.
- Relevant tests and packaging checks pass, or failures are clearly documented.
- Findings distinguish verified behavior from assumptions and unknowns.
- No secrets, unrelated modifications, or unapproved scope have been introduced.
- README and public contracts are updated if behavior or limitations changed.

Final report (concise, in English unless requested otherwise):
1. What changed and which files were touched.
2. Evidence: commands, results, CLI output/exit codes, and any limitations.
3. Known risks, false positives/negatives, or manual checks still required.
4. Commit SHA if a commit was authorized.
5. A clear **GO / NO-GO** recommendation for the experimental release.

A GO recommendation is **not** permission to merge into `main` or publish to npm.
