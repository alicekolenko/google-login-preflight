#!/usr/bin/env node
import { scanGoogleIdentityUrl } from '../src/index.js';

const usage = `Google Login Preflight (experimental)
Usage: google-login-preflight <https://your-site.example/login> [--json] [--strict]

  --json     Structured report suitable for CI
  --strict   Return exit code 1 if warnings are present
  --help     Print this help

Exit codes: 0 = no blocking findings, 1 = findings, 2 = invalid input or request failed.
This is a static configuration check, not a completed Google login test.`;
const args = process.argv.slice(2);
if (args.includes('--help') || args.length === 0) {
  console.log(usage);
  process.exit(args.length === 0 ? 2 : 0);
}
const targets = args.filter(arg => !arg.startsWith('--'));
if (targets.length !== 1 || args.some(arg => arg.startsWith('--') && !['--json', '--strict'].includes(arg))) {
  console.error(usage);
  process.exit(2);
}
try {
  const report = await scanGoogleIdentityUrl(targets[0]);
  if (args.includes('--json')) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`Google Login Preflight: ${report.url}`);
    for (const item of report.checks) {
      console.log(`[${item.severity.toUpperCase()}] ${item.message}`);
      if (item.action) console.log(`  → ${item.action}`);
    }
    console.log(`\n${report.summary.errors} errors · ${report.summary.warnings} warnings · ${report.summary.passes} passed · ${report.summary.informational} informational`);
  }
  process.exitCode = report.summary.errors > 0 || (args.includes('--strict') && report.summary.warnings > 0) ? 1 : 0;
} catch (error) {
  console.error(`Preflight failed: ${error.message}`);
  process.exitCode = 2;
}
