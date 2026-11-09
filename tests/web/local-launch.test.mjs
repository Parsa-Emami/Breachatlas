import test from 'node:test';
import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkEngineHealth, ensureEngineBinary, startSupervisor } from '../../scripts/start-local.mjs';
import { setup } from '../../scripts/oss-bootstrap.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '../..');

test('bootstrap setup builds engine binary and reports unified-local-runtime capability', async () => {
  const result = setup(['--check']);
  assert.equal(result.capability, 'unified-local-runtime');
  assert.equal(result.engineReady, true);
  assert.equal(result.binary, 'dist/bin/breachatlas');
});

test('engine binary exists or builds successfully in dist/bin/breachatlas', async () => {
  const binaryPath = resolve(root, 'dist/bin/breachatlas');
  const available = await ensureEngineBinary(binaryPath);
  assert.equal(available, true);
  await access(binaryPath);
});

test('supervisor rejects forbidden non-loopback host strings', async () => {
  await assert.rejects(
    async () => startSupervisor({ host: '0.0.0.0' }),
    /Supervisor strictly forbids non-loopback host/
  );
  await assert.rejects(
    async () => startSupervisor({ host: '192.168.1.50' }),
    /Supervisor strictly forbids non-loopback host/
  );
});

test('checkEngineHealth returns false for non-responsive endpoints', async () => {
  // Port 65432 should not have an engine running
  const healthy = await checkEngineHealth('127.0.0.1', 65432, 200);
  assert.equal(healthy, false);
});
