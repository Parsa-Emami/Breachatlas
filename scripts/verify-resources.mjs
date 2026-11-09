#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

const ALLOWED_LICENSES = new Set([
  'MIT',
  'Apache-2.0',
  'BSD-3-Clause',
  'BSD-2-Clause',
  'Artistic-2.0',
  'ISC',
  'MPL-2.0'
]);

export function validateResource(res) {
  const errors = [];
  if (!res || typeof res !== 'object') {
    return ['Resource must be a non-null object.'];
  }

  // Version & floating tag check
  if (!res.version || typeof res.version !== 'string') {
    errors.push('Missing resource version.');
  } else {
    const v = res.version.trim();
    if (v === 'latest' || v.startsWith('^') || v.startsWith('~') || v.includes('*')) {
      if (!res.digest) {
        errors.push(`Floating or mutable version tag "${v}" without immutable digest is rejected.`);
      }
    }
  }

  // Digest check if present
  if (res.digest !== undefined && res.digest !== null) {
    if (typeof res.digest !== 'string' || !/^sha256:[a-f0-9]{64}$/i.test(res.digest)) {
      errors.push(`Invalid immutable digest format: ${res.digest}. Must be sha256:<64 hex chars>.`);
    }
  }

  // Official source URL check
  if (!res.official_source || typeof res.official_source !== 'string' || !/^https?:\/\//.test(res.official_source)) {
    errors.push('Missing or invalid official upstream source URL.');
  }

  // License check
  if (!res.license || typeof res.license !== 'string' || !ALLOWED_LICENSES.has(res.license)) {
    errors.push(`Missing or non-permissive open-source license: ${res.license}.`);
  }

  // Paid / Cloud account prohibition
  if (res.requires_paid_account === true) {
    errors.push('Mandatory paid or cloud account required is rejected under ADR-0003 open-source policy.');
  }

  return errors;
}

export function validateToolchainLock(lockData) {
  const errors = [];
  if (!lockData || typeof lockData !== 'object') {
    return ['toolchain-lock.json must be a valid JSON object.'];
  }

  if (lockData.project !== 'BreachAtlas') {
    errors.push(`Project mismatch: expected BreachAtlas, got ${lockData.project}.`);
  }

  if (!lockData.runtimes || typeof lockData.runtimes !== 'object') {
    errors.push('Missing runtimes section in toolchain-lock.json.');
  } else {
    for (const reqRuntime of ['node', 'npm', 'go']) {
      const runtime = lockData.runtimes[reqRuntime];
      if (!runtime) {
        errors.push(`Missing required runtime: "${reqRuntime}".`);
      } else {
        const resErrors = validateResource(runtime);
        for (const e of resErrors) {
          errors.push(`Runtime ${reqRuntime}: ${e}`);
        }
      }
    }
  }

  // Check providers section
  if (lockData.providers) {
    if (Array.isArray(lockData.providers.required_cloud_accounts) && lockData.providers.required_cloud_accounts.length > 0) {
      errors.push('Mandatory required cloud accounts detected in providers configuration.');
    }
    if (Array.isArray(lockData.providers.paid_dependencies) && lockData.providers.paid_dependencies.length > 0) {
      errors.push('Paid dependencies detected in providers configuration.');
    }
  }

  return errors;
}

export function runProbes() {
  const probes = [];

  // Probe Node.js
  try {
    const nodeVer = execSync('node -v', { encoding: 'utf8' }).trim();
    const match = nodeVer.match(/^v(\d+)\.(\d+)/);
    const major = match ? parseInt(match[1], 10) : 0;
    const passed = major >= 24;
    probes.push({ tool: 'node', version: nodeVer, passed, expected: '>= v24.19.0' });
  } catch (err) {
    probes.push({ tool: 'node', passed: false, error: err.message });
  }

  // Probe npm
  try {
    const npmVer = execSync('npm -v', { encoding: 'utf8' }).trim();
    const match = npmVer.match(/^(\d+)/);
    const major = match ? parseInt(match[1], 10) : 0;
    const passed = major >= 11;
    probes.push({ tool: 'npm', version: npmVer, passed, expected: '>= 11.0.0' });
  } catch (err) {
    probes.push({ tool: 'npm', passed: false, error: err.message });
  }

  // Probe Go
  try {
    const goVer = execSync('go version', { encoding: 'utf8' }).trim();
    const match = goVer.match(/go(\d+)\.(\d+)/);
    const major = match ? parseInt(match[1], 10) : 0;
    const minor = match ? parseInt(match[2], 10) : 0;
    const passed = major > 1 || (major === 1 && minor >= 24);
    probes.push({ tool: 'go', version: goVer, passed, expected: '>= go1.24' });
  } catch (err) {
    probes.push({ tool: 'go', passed: false, error: err.message });
  }

  return probes;
}

export async function runSelfTests() {
  const testResults = [];

  // Negative test 1: Floating tag without digest
  {
    const bad = {
      resource_id: 'test-floating',
      version: 'latest',
      license: 'MIT',
      official_source: 'https://example.org/download',
      digest: null
    };
    const errs = validateResource(bad);
    testResults.push({
      name: 'rejects floating tag without digest',
      passed: errs.some(e => e.includes('Floating or mutable version tag'))
    });
  }

  // Negative test 2: Missing source URL
  {
    const bad = {
      resource_id: 'test-no-source',
      version: '1.0.0',
      license: 'MIT',
      official_source: '',
      digest: 'sha256:' + 'a'.repeat(64)
    };
    const errs = validateResource(bad);
    testResults.push({
      name: 'rejects missing official source URL',
      passed: errs.some(e => e.includes('Missing or invalid official upstream source URL'))
    });
  }

  // Negative test 3: Missing or invalid license
  {
    const bad = {
      resource_id: 'test-no-license',
      version: '1.0.0',
      license: 'Proprietary',
      official_source: 'https://example.org/source',
      digest: 'sha256:' + 'a'.repeat(64)
    };
    const errs = validateResource(bad);
    testResults.push({
      name: 'rejects non-permissive open-source license',
      passed: errs.some(e => e.includes('Missing or non-permissive open-source license'))
    });
  }

  // Negative test 4: Digest mismatch / invalid digest format
  {
    const bad = {
      resource_id: 'test-bad-digest',
      version: '1.0.0',
      license: 'Apache-2.0',
      official_source: 'https://example.org/source',
      digest: 'invalid-not-sha256'
    };
    const errs = validateResource(bad);
    testResults.push({
      name: 'rejects invalid digest format',
      passed: errs.some(e => e.includes('Invalid immutable digest format'))
    });
  }

  // Negative test 5: Mandatory paid cloud provider
  {
    const bad = {
      resource_id: 'test-paid',
      version: '1.0.0',
      license: 'MIT',
      official_source: 'https://example.org/source',
      digest: 'sha256:' + 'a'.repeat(64),
      requires_paid_account: true
    };
    const errs = validateResource(bad);
    testResults.push({
      name: 'rejects mandatory paid cloud account',
      passed: errs.some(e => e.includes('Mandatory paid or cloud account required is rejected'))
    });
  }

  // Negative test 6: Missing required runtime in toolchain lock
  {
    const badLock = {
      project: 'BreachAtlas',
      runtimes: {
        node: {
          version: '24.19.0',
          license: 'MIT',
          official_source: 'https://nodejs.org',
          digest: 'sha256:' + 'b'.repeat(64)
        }
      }
    };
    const errs = validateToolchainLock(badLock);
    testResults.push({
      name: 'rejects missing required runtime in toolchain lock',
      passed: errs.some(e => e.includes('Missing required runtime: "go"'))
    });
  }

  return testResults;
}

export async function main() {
  const allErrors = [];

  // 1. Read and validate docs/engineering/toolchain-lock.json
  const lockPath = resolve(root, 'docs/engineering/toolchain-lock.json');
  let lockData;
  try {
    const raw = await readFile(lockPath, 'utf8');
    lockData = JSON.parse(raw);
  } catch (err) {
    allErrors.push(`Failed to read/parse ${lockPath}: ${err.message}`);
  }

  if (lockData) {
    const lockErrors = validateToolchainLock(lockData);
    allErrors.push(...lockErrors);
  }

  // 2. Verify lockfile presence
  const pkgLockPath = resolve(root, 'package-lock.json');
  try {
    await readFile(pkgLockPath, 'utf8');
  } catch (err) {
    allErrors.push(`package-lock.json is missing or unreadable: ${err.message}`);
  }

  // 3. Verify C02 fixtures against provenance
  const fixtureBase = resolve(root, 'tests/fixtures/breachatlas/C02');
  const provPath = join(fixtureBase, 'provenance.json');
  try {
    const provRaw = await readFile(provPath, 'utf8');
    const prov = JSON.parse(provRaw);
    if (prov.license !== 'Apache-2.0') {
      allErrors.push('C02 provenance.json missing Apache-2.0 license.');
    }
    for (const [relFile, meta] of Object.entries(prov.files || {})) {
      const fullPath = join(fixtureBase, relFile);
      const data = await readFile(fullPath);
      const digest = createHash('sha256').update(data).digest('hex');
      if (digest !== meta.sha256) {
        allErrors.push(`Fixture hash mismatch for ${relFile}: recorded ${meta.sha256}, calculated ${digest}.`);
      }
    }
  } catch (err) {
    allErrors.push(`Failed to verify C02 fixture provenance: ${err.message}`);
  }

  // 4. Run probes on local toolchain
  const probes = runProbes();
  for (const probe of probes) {
    if (!probe.passed) {
      allErrors.push(`Probe failure for ${probe.tool}: ${probe.error || `version ${probe.version} did not meet ${probe.expected}`}`);
    }
  }

  // 5. Run self-tests
  const selfTests = await runSelfTests();
  for (const st of selfTests) {
    if (!st.passed) {
      allErrors.push(`Self-test failed: ${st.name}`);
    }
  }

  if (allErrors.length > 0) {
    console.error('RESOURCE VERIFICATION FAILED:');
    for (const err of allErrors) {
      console.error(` - ${err}`);
    }
    process.exit(1);
  }

  console.log(`RESOURCE VERIFICATION PASSED: toolchain-lock.json validated, ${probes.length} toolchain probes verified, and ${selfTests.length} negative regression tests passed.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
