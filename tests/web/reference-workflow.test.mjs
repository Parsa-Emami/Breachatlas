import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateScenario, validateReferenceDoc, runSelfTests } from '../../scripts/verify-reference.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '../..');

test('reference workflow scenario validates required steps, invariants, and safe paths', async () => {
  const scenarioRaw = await readFile(resolve(root, 'tests/scenarios/clone-to-value.json'), 'utf8');
  const scenario = JSON.parse(scenarioRaw);
  const errors = validateScenario(scenario);
  assert.deepEqual(errors, []);
});

test('reference workflow documentation matches required invariants and planned status', async () => {
  const docContent = await readFile(resolve(root, 'docs/product/REFERENCE_WORKFLOW.md'), 'utf8');
  const errors = validateReferenceDoc(docContent);
  assert.deepEqual(errors, []);
});

test('reference workflow validator catches corrupted scenarios, escapes, and false claims', async () => {
  const selfTests = await runSelfTests();
  assert.ok(selfTests.length >= 8);
  for (const t of selfTests) {
    assert.equal(t.passed, true, `Negative test failed: ${t.name}`);
  }
});
