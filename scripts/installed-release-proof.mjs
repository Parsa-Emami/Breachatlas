import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const [playwrightPath, outputPath, sourceCommit, visibility] = process.argv.slice(2);
assert.match(sourceCommit, /^[0-9a-f]{40}$/);
assert.match(visibility, /^(true|false)$/);

const fixturePath = 'tests/fixtures/breachatlas/C40/scenarios.json';
const fixtureBytes = await readFile(fixturePath);
const fixture = JSON.parse(fixtureBytes);
const referenceBytes = await readFile(fixture.reference_fixture);
const playwright = JSON.parse(await readFile(playwrightPath, 'utf8'));
const tests = [];
function collect(suite) {
  for (const spec of suite.specs ?? []) {
    for (const test of spec.tests) {
      assert.equal(test.status, 'expected');
      assert.equal(test.results.length, 1);
      assert.equal(test.results[0].status, 'passed');
      tests.push(spec.title);
    }
  }
  for (const child of suite.suites ?? []) collect(child);
}
playwright.suites.forEach(collect);
assert.deepEqual(tests.sort(), [...fixture.browser_tests].sort());
assert.equal(playwright.stats.unexpected, 0);
assert.equal(playwright.stats.skipped, 0);

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const report = {
  passed: true,
  published: visibility === 'true',
  source_commit: sourceCommit,
  authenticated_assets: true,
  tampered_manifest_rejected: true,
  tests,
  fixture: { path: fixturePath, license: fixture.license, sha256: digest(fixtureBytes) },
  reference_fixture: { path: fixture.reference_fixture, sha256: digest(referenceBytes) },
  host: { platform: process.platform, architecture: process.arch, node: process.version },
};
await writeFile(outputPath, JSON.stringify(report, null, 2) + '\n');
