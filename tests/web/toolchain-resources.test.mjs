import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateToolchainLock, validateResource, runProbes, runSelfTests } from '../../scripts/verify-resources.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '../..');

test('toolchain-lock.json specifies valid immutable digests and permissive open-source licenses', async () => {
  const raw = await readFile(resolve(root, 'docs/engineering/toolchain-lock.json'), 'utf8');
  const lock = JSON.parse(raw);
  const errors = validateToolchainLock(lock);
  assert.deepEqual(errors, []);
});

test('local toolchain probes confirm compatible Node, npm, and Go environments', () => {
  const probes = runProbes();
  assert.equal(probes.length, 3);
  for (const p of probes) {
    assert.equal(p.passed, true, `Probe failed for ${p.tool}: ${p.error || p.version}`);
  }
});

test('resource validator catches floating tags, missing licenses, and mandatory paid accounts', async () => {
  const selfTests = await runSelfTests();
  assert.ok(selfTests.length >= 6);
  for (const st of selfTests) {
    assert.equal(st.passed, true, `Self-test failed: ${st.name}`);
  }
});
