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

test('supervisor fails cleanly for a missing executable', async () => {
  await assert.rejects(startSupervisor({ engineBin: '/dev/null/missing', healthTimeoutMs: 300 }), /engine binary/i);
});

test('occupied engine or web port cannot leave a child serving requests', async t => {
  const { createServer } = await import('node:http');
  const { once } = await import('node:events');
  const occupied = createServer((_req, res) => {
    res.end('{"status":"ok","service":"breachatlas-engine"}');
  });
  occupied.listen(0, '127.0.0.1');
  await once(occupied, 'listening');
  t.after(() => occupied.close());
  const port = occupied.address().port;

  await assert.rejects(startSupervisor({ enginePort: port, healthTimeoutMs: 500, engineStdio: 'ignore' }), /engine/i);

  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const enginePort = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  await assert.rejects(startSupervisor({ port, enginePort, healthTimeoutMs: 1000, engineStdio: 'ignore' }), /EADDRINUSE/);
  assert.equal(await checkEngineHealth('127.0.0.1', enginePort, 150), false);
});

test('an unexpected engine exit closes the web listener', async () => {
  const { createServer } = await import('node:net');
  const { once } = await import('node:events');
  const reserve = async () => {
    const listener = createServer().listen(0, '127.0.0.1');
    await once(listener, 'listening');
    return listener;
  };
  const web = await reserve();
  const engine = await reserve();
  const port = web.address().port;
  const enginePort = engine.address().port;
  await Promise.all([web, engine].map(listener => new Promise(resolve => listener.close(resolve))));

  const supervisor = await startSupervisor({ port, enginePort, engineStdio: 'ignore' });
  try {
    assert.equal(await checkEngineHealth('127.0.0.1', enginePort), true);
    const closed = once(supervisor.webServer, 'close');
    supervisor.engineProcess.kill('SIGKILL');
    await closed;
    assert.equal(await checkEngineHealth('127.0.0.1', enginePort, 150), false);
  } finally {
    await supervisor.shutdown();
  }
});

test('cancelled startup does not start either server', async () => {
  const signal = AbortSignal.abort(new Error('cancelled'));
  await assert.rejects(startSupervisor({ signal }), /cancelled/);
});
