import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { Readable } from 'node:stream';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startSupervisor, ensureEngineBinary } from '../../scripts/start-local.mjs';

const fixtures = new URL('../fixtures/breachatlas/C04/', import.meta.url);
const evidenceFile = new URL('../fixtures/breachatlas/C01/positive/evidence-001.log', import.meta.url);
const endpoint = '/api/v1/evidence-manifests/validate';
const contentType = { 'Content-Type': 'application/json' };
const read = path => readFile(new URL(path, fixtures));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

async function freePort() {
  const listener = createServer().listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const { port } = listener.address();
  await new Promise(resolve => listener.close(resolve));
  return port;
}

test('versioned fixtures and bounded requests exercise the supervised Go engine across restart', async t => {
  const root = await mkdtemp(join(tmpdir(), 'breachatlas-contract-'));
  const engineBin = join(root, 'breachatlas');
  const port = await freePort();
  const enginePort = await freePort();
  let supervisor;
  t.after(async () => {
    await supervisor?.shutdown();
    await rm(root, { recursive: true, force: true });
  });
  assert.equal(await ensureEngineBinary(engineBin), true);
  const start = () => startSupervisor({ port, enginePort, engineBin, engineStdio: 'ignore' });
  supervisor = await start();
  const base = 'http://127.0.0.1:' + port;
  const send = (body, init = {}) => fetch(base + endpoint, { method: 'POST', body, headers: contentType, ...init });
  const manifest = await read('positive/manifest.json');
  const originalEvidence = await readFile(evidenceFile);
  const provenance = JSON.parse(await read('provenance.json'));
  assert.equal(provenance.license, 'Apache-2.0');
  for (const [path, hash] of Object.entries(provenance.sha256)) assert.equal(digest(await read(path)), hash);
  assert.equal(JSON.parse(manifest).sha256, digest(originalEvidence));
  assert.equal(JSON.parse(manifest).size_bytes, originalEvidence.length);
  const outcome = JSON.parse(await read('expected-output/outcomes.json'));

  for (const [path, expected] of Object.entries(outcome)) {
    await t.test(path, async () => {
      const body = await read(path);
      const response = await send(body);
      assert.equal(response.status, expected.http);
      const result = await response.json();
      assert.equal(result.schema_version, '1');
      if (expected.result) {
        assert.equal(result.status, 'valid');
        assert.deepEqual(result.result, expected.result);
        assert.equal(result.input_digest, digest(body));
        assert.match(result.engine_version, /^\d+\.\d+\.\d+$/);
      } else {
        assert.equal(result.status, 'error');
        assert.deepEqual(result.error, expected.field ? { code: expected.code, field: expected.field } : { code: expected.code });
      }
    });
  }

  for (const [body, status, code, init] of [
    [Buffer.concat([Buffer.from('{ "case_id": "duplicate",'), manifest.subarray(1)]), 422, 'unexpected_or_duplicate_field'],
    ['{} {}', 400, 'invalid_json'],
    ['[]', 422, 'invalid_manifest'],
    [Buffer.from([0x22, 0xff, 0x22]), 400, 'invalid_json'],
    [JSON.stringify({ ...JSON.parse(manifest), size_bytes: null }), 422, 'invalid_field'],
    [Buffer.alloc(16385, 32), 413, 'payload_too_large'],
    [Readable.from([Buffer.alloc(16000, 32), Buffer.alloc(385, 32)]), 413, 'payload_too_large', { duplex: 'half' }],
    [manifest, 403, 'origin_not_allowed', { headers: { ...contentType, Origin: 'https://example.invalid' } }],
    [manifest, 415, 'unsupported_media_type', { headers: { 'Content-Type': 'text/plain' } }],
  ]) {
    const response = await send(body, init);
    assert.equal(response.status, status, code);
    assert.equal((await response.json()).error.code, code);
  }
  const method = await fetch(base + endpoint);
  assert.equal(method.status, 405);
  assert.equal(method.headers.get('allow'), 'POST');
  assert.equal((await method.json()).error.code, 'method_not_allowed');

  await supervisor.shutdown();
  await assert.rejects(send(manifest));
  supervisor = await start();
  const repeated = await send(manifest);
  assert.equal(repeated.status, 200);
  assert.equal((await repeated.json()).input_digest, digest(manifest));
  assert.deepEqual(await readFile(evidenceFile), originalEvidence);
});
