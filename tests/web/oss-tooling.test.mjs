import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setup, supportedNode } from '../../scripts/oss-bootstrap.mjs';
import { validate } from '../../scripts/roadmap.mjs';
import { packageSourceArtifacts, ALLOWED_LICENSES } from '../../scripts/package-source.mjs';
import { packageCompleteRelease } from '../../scripts/package-web.mjs';
import { runUpgradeRecoverySuite } from '../release/upgrade-recovery.mjs';
test('setup validates toolchain/options and stops at the first failed install', () => {
  assert.equal(supportedNode('v24.19.0'), true); assert.equal(supportedNode('v25.1.0'), false);
  assert.throws(() => setup(['--unknown']), /options/);
  const prior = process.env.npm_execpath; process.env.npm_execpath ??= 'test-npm';
  let calls = 0; assert.throws(() => setup([], () => { calls++; return { status: 1 }; }), /failed/); assert.equal(calls, 1);
  assert.equal(setup(['--check'], () => { throw new Error('must not execute'); }).executed, false);
  if (prior === undefined) delete process.env.npm_execpath; else process.env.npm_execpath = prior;
});
test('roadmap rejects absent resources, escaping paths and unproved completion', async () => {
  const read = async path => JSON.parse(await readFile(new URL('../../' + path, import.meta.url), 'utf8'));
  const values = await Promise.all(['plans/roadmap.json', 'plans/progress.json', 'plans/requirements.json', 'plans/release-gates.json'].map(read));
  assert.deepEqual(validate(...values), []);
  const missing = structuredClone(values); delete missing[0].commits[6].resources.fixture;
  assert.ok(validate(...missing).some(e => e.includes('resources')));
  const unsafe = structuredClone(values); unsafe[0].commits[6].deliverables.push('../escape'); assert.ok(validate(...unsafe).some(e => e.includes('unsafe')));
  const circular = structuredClone(values); circular[0].commits[0].verification_commands[1].introduced_by = 'C06'; assert.ok(validate(...circular).some(e => e.includes('future task')));
  const unsafeFixture = structuredClone(values); unsafeFixture[0].commits[6].resources.fixture.path = '../escape'; assert.ok(validate(...unsafeFixture).some(e => e.includes('unsafe')));
  const fake = structuredClone(values); fake[1].commits[6].status = 'verified'; fake[1].commits[6].source_identity = null; fake[1].commits[6].evidence = []; assert.ok(validate(...fake).some(e => e.includes('unproved')));
});
test('source archive & SPDX SBOM generation is reproducible and complete packager fails closed without built web assets', async t => {
  const emptyRoot = await mkdtemp(join(tmpdir(), 'breachatlas-pkg-failclosed-'));
  t.after(async () => rm(emptyRoot, { recursive: true, force: true }));
  await assert.rejects(() => packageCompleteRelease({ rootDir: emptyRoot }), /dist\/web\/index\.html missing/);

  const outA = await mkdtemp(join(tmpdir(), 'breachatlas-sbom-a-'));
  const outB = await mkdtemp(join(tmpdir(), 'breachatlas-sbom-b-'));
  t.after(async () => {
    await rm(outA, { recursive: true, force: true });
    await rm(outB, { recursive: true, force: true });
  });
  const resA = await packageSourceArtifacts({ outputDir: outA });
  const resB = await packageSourceArtifacts({ outputDir: outB });
  assert.equal(resA.archiveSha256, resB.archiveSha256);
  const sbom = JSON.parse(await readFile(resA.sbomPath, 'utf8'));
  assert.equal(sbom.spdxVersion, 'SPDX-2.3');
  assert.ok(sbom.packages.length >= 10);
  for (const pkg of sbom.packages) {
    assert.ok(ALLOWED_LICENSES.has(pkg.licenseConcluded), `${pkg.name} license ${pkg.licenseConcluded}`);
  }
});

test('C35 signed release verification and data-safe upgrade/rollback succeed end-to-end', async () => {
  const summary = await runUpgradeRecoverySuite();
  assert.equal(summary.passed, true);
  assert.equal(summary.source_build_alternative_verified, true);
  assert.equal(summary.lifecycle_checks.case_v1_preserved, true);
  assert.equal(summary.lifecycle_checks.case_v2_newer_preserved, true);
  assert.equal(summary.lifecycle_checks.sealed_bytes_modified, false);
  assert.equal(summary.lifecycle_checks.authority_high_water_mark, 2);
});
