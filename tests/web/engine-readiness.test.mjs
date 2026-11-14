import test from 'node:test';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer as createNetServer } from 'node:net';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createDiagnosticLogBuffer,
  createWebServer,
  redactDiagnosticText,
} from '../../scripts/serve-web.mjs';
import { validateRuntimeConfig } from '../../apps/web/src/lib/runtime-config.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '../..');

async function reserveFreePort() {
  const srv = createNetServer();
  srv.listen(0, '127.0.0.1');
  await once(srv, 'listening');
  const port = srv.address().port;
  await new Promise(r => srv.close(r));
  return port;
}

async function buildTempEngineBinary(dir) {
  const binPath = join(dir, 'breachatlas-c29');
  const res = spawnSync('go', ['build', '-o', binPath, './cmd/breachatlas'], {
    cwd: root,
    encoding: 'utf8',
  });
  assert.equal(res.status, 0, `go build failed: ${res.stderr}`);
  return binPath;
}

async function spawnGoEngine(binPath, port, extraArgs = []) {
  const child = spawn(binPath, ['--host', '127.0.0.1', '--port', String(port), ...extraArgs], {
    cwd: root,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', chunk => {
    stderr += chunk.toString('utf8');
  });

  const rl = createInterface({ input: child.stdout });
  await new Promise((resolveReady, rejectReady) => {
    const timer = setTimeout(() => rejectReady(new Error(`Engine startup timeout; stderr=${stderr}`)), 5000);
    child.once('exit', code => {
      clearTimeout(timer);
      rejectReady(new Error(`Engine exited prematurely (${code}); stderr=${stderr}`));
    });
    rl.on('line', line => {
      try {
        const parsed = JSON.parse(line);
        if (parsed.status === 'listening' && parsed.port === port) {
          clearTimeout(timer);
          resolveReady();
        }
      } catch {
        // Ignore non-JSON lines
      }
    });
  });

  rl.close();
  child.stdout.resume();

  return async () => {
    if (child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise(resolveExit => {
        const t = setTimeout(() => {
          if (child.exitCode === null) child.kill('SIGKILL');
          resolveExit();
        }, 3000);
        child.once('exit', () => {
          clearTimeout(t);
          resolveExit();
        });
      });
    }
  };
}

test('runtime config files match and reject unsafe diagnostic overrides', async () => {
  const opsCfg = JSON.parse(await readFile(join(root, 'ops/web/runtime-config.json'), 'utf8'));
  const publicCfg = JSON.parse(await readFile(join(root, 'apps/web/public/runtime-config.json'), 'utf8'));
  assert.deepEqual(publicCfg, opsCfg);

  const valid = validateRuntimeConfig(opsCfg, 'breachatlas');
  assert.equal(valid.readinessPath, '/readyz');
  assert.equal(valid.diagnosticsPath, '/api/v1/diagnostics');
  assert.equal(valid.maxDiagnosticLogBytes, 16384);
  assert.equal(valid.maxDiagnosticEntries, 64);

  for (const badPatch of [
    { readinessPath: '/other' },
    { diagnosticsPath: 'https://evil.invalid/diag' },
    { maxDiagnosticLogBytes: 512 },
    { maxDiagnosticLogBytes: 100000 },
    { maxDiagnosticEntries: 0 },
    { maxDiagnosticEntries: 500 },
    { requiredProviders: [] },
    { requiredProviders: ['Bad Provider!'] },
  ]) {
    assert.throws(() => validateRuntimeConfig({ ...opsCfg, ...badPatch }, 'breachatlas'));
  }
});

test('diagnostic log buffer enforces entry/byte bounds and redacts synthetic secret sentinels', async () => {
  const invalidFixture = JSON.parse(
    await readFile(join(root, 'tests/fixtures/breachatlas/C29/invalid/degraded-and-secret-sentinels.json'), 'utf8')
  );

  for (const item of invalidFixture.synthetic_secret_sentinels) {
    const out = redactDiagnosticText(item.raw_message);
    assert.equal(out.redacted, true, `${item.label} should be marked redacted`);
    assert.equal(out.text.includes(item.forbidden_substring), false, `${item.label} leaked ${item.forbidden_substring}`);
    assert.match(out.text, /\[REDACTED/);
  }

  const buffer = createDiagnosticLogBuffer({ maxEntries: 5, maxBytes: 1200 });
  for (let i = 0; i < 20; i++) {
    const sentinel = invalidFixture.synthetic_secret_sentinels[i % invalidFixture.synthetic_secret_sentinels.length];
    buffer.record('error', 'relay', `err_${i}`, `${sentinel.raw_message} ${'z'.repeat(180)}`);
  }

  const snap = buffer.snapshot();
  assert.ok(snap.entries.length <= 5, `expected <= 5 entries, got ${snap.entries.length}`);
  assert.ok(snap.total_bytes <= 1200, `expected <= 1200 bytes, got ${snap.total_bytes}`);
  assert.ok(snap.evicted_count > 0, 'expected FIFO evictions under flood');
  assert.equal(snap.redacted_count, 20);

  const serialized = JSON.stringify(snap);
  for (const item of invalidFixture.synthetic_secret_sentinels) {
    assert.equal(serialized.includes(item.forbidden_substring), false, `snapshot leaked ${item.forbidden_substring}`);
  }
});

test('web health separates from engine, storage, and provider readiness across failures and restart', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'c29-readiness-'));
  const webRoot = join(dir, 'public');
  await mkdir(webRoot, { recursive: true });
  await writeFile(join(webRoot, 'index.html'), '<!doctype html><h1>BreachAtlas</h1>');

  const cfg = JSON.parse(await readFile(join(root, 'ops/web/runtime-config.json'), 'utf8'));
  const invalidFixture = JSON.parse(
    await readFile(join(root, 'tests/fixtures/breachatlas/C29/invalid/degraded-and-secret-sentinels.json'), 'utf8')
  );
  const expected = JSON.parse(
    await readFile(join(root, 'tests/fixtures/breachatlas/C29/expected-output/diagnostics-outcomes.json'), 'utf8')
  );

  // 1. Standalone web-only mode
  const standaloneServer = createWebServer({ root: webRoot, config: cfg, projectId: 'breachatlas' });
  standaloneServer.listen(0, '127.0.0.1');
  await once(standaloneServer, 'listening');
  const standaloneBase = `http://127.0.0.1:${standaloneServer.address().port}`;
  t.after(async () => {
    standaloneServer.closeAllConnections();
    await new Promise(r => standaloneServer.close(r));
  });

  const sReadyRes = await fetch(standaloneBase + '/readyz');
  assert.equal(sReadyRes.status, expected.web_only_readyz.http_status);
  const sReady = await sReadyRes.json();
  assert.equal(sReady.scope, expected.web_only_readyz.scope);
  assert.equal(sReady.webReady, true);
  assert.equal(sReady.engineReady, false);
  assert.equal(sReady.storageReady, false);
  assert.equal(sReady.providersReady, false);

  // 2. Unified runtime pointing to unreachable engine port -> /healthz 200, /readyz & /api/v1/diagnostics 503
  const enginePort = await reserveFreePort();
  const unifiedServer = createWebServer({
    root: webRoot,
    config: cfg,
    projectId: 'breachatlas',
    manifestEngine: { hostname: '127.0.0.1', port: enginePort },
  });
  unifiedServer.listen(0, '127.0.0.1');
  await once(unifiedServer, 'listening');
  const unifiedBase = `http://127.0.0.1:${unifiedServer.address().port}`;
  t.after(async () => {
    unifiedServer.closeAllConnections();
    await new Promise(r => unifiedServer.close(r));
    await rm(dir, { recursive: true, force: true });
  });

  // Record synthetic secret sentinel into web relay log and ensure HTTP response redacts it completely.
  unifiedServer.diagnosticLog.record('error', 'relay', 'sentinel_test', invalidFixture.synthetic_secret_sentinels[0].raw_message);

  const healthDown = await fetch(unifiedBase + '/healthz');
  assert.equal(healthDown.status, 200);
  assert.equal((await healthDown.json()).webHealthy, true);

  const readyDown = await fetch(unifiedBase + '/readyz');
  assert.equal(readyDown.status, 503);
  const readyDownBody = await readyDown.json();
  assert.equal(readyDownBody.webReady, true);
  assert.equal(readyDownBody.engineReady, false);
  assert.equal(readyDownBody.failures[0].code, 'engine_unavailable');

  const diagDown = await fetch(unifiedBase + '/api/v1/diagnostics');
  assert.equal(diagDown.status, 503);
  const diagDownText = await diagDown.text();
  assert.equal(diagDownText.includes(invalidFixture.synthetic_secret_sentinels[0].forbidden_substring), false);
  assert.ok(diagDownText.includes('[REDACTED]'));

  // Security headers and CSRF/forged-header rejection on /api/v1/diagnostics
  assert.equal((await fetch(unifiedBase + '/api/v1/diagnostics', { method: 'POST' })).status, 405);
  assert.equal((await fetch(unifiedBase + '/api/v1/diagnostics', { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await fetch(unifiedBase + '/api/v1/diagnostics', { headers: { 'x-provider': 'remote-kms' } })).status, 403);

  // 3. Real Go engine with missing storage dir -> /healthz 200, /readyz 503 storage_prerequisite_missing
  const binPath = await buildTempEngineBinary(dir);
  const missingStorageDir = join(dir, invalidFixture.missing_storage_path_suffix);
  const stopMissing = await spawnGoEngine(binPath, enginePort, [
    '--storage-dir', missingStorageDir,
    '--required-providers', 'local,csv,json',
  ]);
  try {
    assert.equal((await fetch(unifiedBase + '/healthz')).status, 200);
    const missingReadyRes = await fetch(unifiedBase + '/readyz');
    assert.equal(missingReadyRes.status, 503);
    const missingReady = await missingReadyRes.json();
    assert.equal(missingReady.engineReady, true);
    assert.equal(missingReady.storageReady, false);
    assert.equal(missingReady.storage.error_code, 'storage_prerequisite_missing');
  } finally {
    await stopMissing();
  }

  // 4. Restart Go engine with valid storage & required providers -> 200 ready
  const validStorageDir = join(dir, 'authoritative-storage');
  await mkdir(validStorageDir, { recursive: true });
  const stopHealthy = await spawnGoEngine(binPath, enginePort, [
    '--storage-dir', validStorageDir,
    '--required-providers', 'local,csv,json',
  ]);
  try {
    const okReadyRes = await fetch(unifiedBase + '/readyz');
    assert.equal(okReadyRes.status, 200);
    const okReady = await okReadyRes.json();
    assert.equal(okReady.status, 'ready');
    assert.equal(okReady.webReady, true);
    assert.equal(okReady.engineReady, true);
    assert.equal(okReady.storageReady, true);
    assert.equal(okReady.providersReady, true);
    assert.deepEqual(okReady.failures, []);

    const okDiagRes = await fetch(unifiedBase + '/api/v1/diagnostics');
    assert.equal(okDiagRes.status, 200);
    const okDiag = await okDiagRes.json();
    assert.equal(okDiag.status, 'ready');
    assert.equal(okDiag.web_health.webHealthy, true);
    assert.equal(okDiag.readiness.storageReady, true);
    assert.equal(okDiag.readiness.providersReady, true);
    assert.ok(Array.isArray(okDiag.diagnostics.engine.entries));
    assert.ok(Array.isArray(okDiag.diagnostics.web_relay.entries));
  } finally {
    await stopHealthy();
  }
});
