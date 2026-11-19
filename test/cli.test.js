import { strict as assert } from 'node:assert';
import { execFile } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const bin = fileURLToPath(new URL('../bin/gis-preflight.js', import.meta.url));
const healthyCsp = [
  "default-src 'self'",
  'script-src https://accounts.google.com/gsi/client',
  'frame-src https://accounts.google.com/gsi/',
  'connect-src https://accounts.google.com/gsi/',
  'style-src https://accounts.google.com/gsi/style',
].join('; ');

test('CLI checks healthy and misconfigured local GIS pages', async t => {
  const server = createServer((req, res) => {
    const healthy = req.url === '/healthy';
    res.writeHead(200, {
      'content-type': 'text/html',
      'content-security-policy': healthy ? healthyCsp : "default-src 'self'",
      'cross-origin-opener-policy': healthy ? 'same-origin-allow-popups' : 'same-origin',
    });
    res.end('<!doctype html><script async src="https://accounts.google.com/gsi/client"></script>');
  });
  server.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');

  for (const page of ['healthy', 'bad']) {
    for (const flags of [[], ['--strict'], ['--json'], ['--strict', '--json']]) {
      const url = `http://127.0.0.1:${server.address().port}/${page}`;
      const result = await new Promise(resolve => {
        execFile(process.execPath, [bin, url, ...flags], {timeout: 5000}, (error, stdout, stderr) => {
          resolve({code: error ? error.code : 0, stdout, stderr});
        });
      });
      const warnings = page === 'healthy' ? 0 : 5;
      assert.equal(result.stderr, '');
      assert.equal(result.code, warnings && flags.includes('--strict') ? 1 : 0);
      if (flags.includes('--json')) {
        const report = JSON.parse(result.stdout);
        assert.equal(report.schemaVersion, 1);
        assert.equal(report.summary.warnings, warnings);
        assert.equal(report.summary.errors, 0);
        assert.ok(report.checks.some(check => check.code === 'runtime-manual'));
        if (warnings) {
          assert.deepEqual(report.checks.filter(check => check.severity === 'warn').map(check => check.code),
            ['csp-script-src', 'csp-frame-src', 'csp-connect-src', 'csp-style-src', 'coop-popup-risk']);
        }
      } else {
        assert.match(result.stdout, new RegExp(`0 errors · ${warnings} warnings`));
        assert.match(result.stdout, /require runtime\/server testing/);
      }
      t.diagnostic(`${page} ${flags.join(' ') || '(normal)'}: exit ${result.code}, ${warnings} warnings`);
    }
  }
});
