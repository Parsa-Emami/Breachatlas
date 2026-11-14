#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { resolve, isAbsolute, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

const REQUIRED_INVARIANTS = [
  'Sealed source bytes never modified',
  'Legal hold takes precedence over deletion',
  'Raw timestamp and confidence survive normalization',
];

const REQUIRED_STEPS = [
  'Upload synthetic evidence',
  'seal',
  'add custody',
  'parse bounded timeline',
  'hold/delete negative test',
  'export',
  'verify on another host with external trust',
  'recover consistency.',
];

const REQUIRED_UAT = [
  'evidence را upload/seal کن؛ byte عوض‌شده verifier را شکست دهد',
  'hold فعال اجازهٔ delete و expire ندهد',
  'export در دستگاه جدا بدون سرور با trust key مستقل بررسی شود و timezone خام حفظ شود',
];

function isSafePath(p) {
  if (typeof p !== 'string' || !p.trim()) return false;
  if (isAbsolute(p)) return false;
  const segments = p.split(/[\\/]/);
  return !segments.includes('..');
}

export function validateScenario(scenario, options = {}) {
  const errors = [];
  if (!scenario || typeof scenario !== 'object') {
    return ['Scenario must be a valid JSON object.'];
  }

  // Version check
  if (!scenario.version || typeof scenario.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(scenario.version)) {
    errors.push('Unsupported or missing scenario version.');
  }

  // Project identity
  if (scenario.project !== 'BreachAtlas') {
    errors.push(`Invalid project identity: expected BreachAtlas, got ${scenario.project}.`);
  }

  // Execution & contract status consistency check
  if (scenario.engine_implemented === true) {
    if (!scenario.status || scenario.status.includes('planned acceptance contract') || scenario.verified_at_commit !== 'C30') {
      errors.push('Claim of executed engine proof requires verified_at_commit C30 and non-planned status.');
    }
    if (!isSafePath(scenario.c30_fixtures) || !scenario.restart_and_restore?.restart_verified || !scenario.restart_and_restore?.restore_verified || scenario.restart_and_restore?.sealed_bytes_modified !== false) {
      errors.push('Claim of executed engine proof requires valid c30_fixtures and restart_and_restore verification.');
    }
  } else {
    if (!scenario.status || !scenario.status.includes('planned acceptance contract')) {
      errors.push('Status must indicate planned acceptance contract when engine_implemented is false.');
    }
  }

  // License & Provenance
  if (!scenario.license || scenario.license !== 'Apache-2.0') {
    errors.push('Scenario missing valid Apache-2.0 license declaration.');
  }
  if (!scenario.provenance || typeof scenario.provenance !== 'string') {
    errors.push('Scenario missing provenance declaration.');
  }

  // Fixture base path check
  if (!scenario.fixture_base || !isSafePath(scenario.fixture_base)) {
    errors.push(`Invalid or unsafe fixture_base path: ${scenario.fixture_base}.`);
  }

  // Expected invariants
  if (!Array.isArray(scenario.expected_invariants)) {
    errors.push('expected_invariants must be an array.');
  } else {
    for (const inv of REQUIRED_INVARIANTS) {
      if (!scenario.expected_invariants.includes(inv)) {
        errors.push(`Missing required invariant: "${inv}".`);
      }
    }
  }

  // Negative UAT
  if (!Array.isArray(scenario.negative_uat)) {
    errors.push('negative_uat must be an array.');
  } else {
    for (const uat of REQUIRED_UAT) {
      if (!scenario.negative_uat.includes(uat)) {
        errors.push(`Missing required negative UAT: "${uat}".`);
      }
    }
  }

  // Steps validation
  if (!Array.isArray(scenario.steps) || scenario.steps.length === 0) {
    errors.push('scenario.steps must be a non-empty array.');
  } else {
    if (scenario.steps.length !== REQUIRED_STEPS.length) {
      errors.push(`Expected ${REQUIRED_STEPS.length} workflow steps, found ${scenario.steps.length}.`);
    }

    const seenActions = [];
    for (let i = 0; i < scenario.steps.length; i++) {
      const step = scenario.steps[i];
      if (!step || typeof step !== 'object') {
        errors.push(`Step index ${i + 1} is not a valid object.`);
        continue;
      }

      if (!step.action || typeof step.action !== 'string') {
        errors.push(`Step index ${i + 1}: missing action.`);
      } else {
        seenActions.push(step.action.trim().toLowerCase());
      }

      if (!step.expected_state || typeof step.expected_state !== 'string') {
        errors.push(`Step index ${i + 1}: missing expected_state.`);
      }

      if (!Array.isArray(step.negative_cases) || step.negative_cases.length === 0) {
        errors.push(`Step index ${i + 1}: missing negative_cases.`);
      }

      // Check fixture references
      for (const fixtureField of ['input_fixture', 'expected_output_fixture']) {
        const fixtureRel = step[fixtureField];
        if (fixtureRel) {
          if (!isSafePath(fixtureRel)) {
            errors.push(`Step index ${i + 1}: unsafe fixture path in ${fixtureField} (${fixtureRel}).`);
          }
        }
      }
    }

    for (const reqStep of REQUIRED_STEPS) {
      const normalizedReq = reqStep.trim().toLowerCase();
      if (!seenActions.includes(normalizedReq)) {
        errors.push(`Missing workflow step action: "${reqStep}".`);
      }
    }
  }

  // Clean host commands
  if (!Array.isArray(scenario.clean_host_commands) || scenario.clean_host_commands.length === 0) {
    errors.push('Missing clean_host_commands.');
  }

  return errors;
}

export function validateReferenceDoc(docContent) {
  const errors = [];
  if (typeof docContent !== 'string' || !docContent.trim()) {
    return ['REFERENCE_WORKFLOW.md is empty or missing.'];
  }

  if (!docContent.includes('Planned domain acceptance contract') && !docContent.includes('C30 local usability verified')) {
    errors.push('REFERENCE_WORKFLOW.md must explicitly note planned or C30 verified acceptance status.');
  }

  for (const inv of REQUIRED_INVARIANTS) {
    if (!docContent.includes(inv)) {
      errors.push(`REFERENCE_WORKFLOW.md missing invariant: "${inv}".`);
    }
  }

  for (const step of REQUIRED_STEPS) {
    const cleanStep = step.replace(/\.$/, '');
    if (!docContent.toLowerCase().includes(cleanStep.toLowerCase())) {
      errors.push(`REFERENCE_WORKFLOW.md missing step mention: "${step}".`);
    }
  }

  return errors;
}

export async function runSelfTests() {
  const testResults = [];

  // Negative test 1: Missing action
  {
    const bad = {
      version: '1.0.0',
      project: 'BreachAtlas',
      status: 'planned acceptance contract; not executed domain proof',
      engine_implemented: false,
      license: 'Apache-2.0',
      provenance: 'repo-synthetic',
      fixture_base: 'tests/fixtures/breachatlas/C01/',
      expected_invariants: [...REQUIRED_INVARIANTS],
      negative_uat: [...REQUIRED_UAT],
      steps: [
        { expected_state: 'staged', negative_cases: ['fail'] }
      ],
      clean_host_commands: ['npm start']
    };
    const errs = validateScenario(bad);
    testResults.push({
      name: 'rejects missing action',
      passed: errs.some(e => e.includes('missing action'))
    });
  }

  // Negative test 2: Missing expected result / state
  {
    const bad = {
      version: '1.0.0',
      project: 'BreachAtlas',
      status: 'planned acceptance contract; not executed domain proof',
      engine_implemented: false,
      license: 'Apache-2.0',
      provenance: 'repo-synthetic',
      fixture_base: 'tests/fixtures/breachatlas/C01/',
      expected_invariants: [...REQUIRED_INVARIANTS],
      negative_uat: [...REQUIRED_UAT],
      steps: [
        { action: 'seal', negative_cases: ['fail'] }
      ],
      clean_host_commands: ['npm start']
    };
    const errs = validateScenario(bad);
    testResults.push({
      name: 'rejects missing expected state',
      passed: errs.some(e => e.includes('missing expected_state'))
    });
  }

  // Negative test 3: Missing invariant
  {
    const bad = {
      version: '1.0.0',
      project: 'BreachAtlas',
      status: 'planned acceptance contract; not executed domain proof',
      engine_implemented: false,
      license: 'Apache-2.0',
      provenance: 'repo-synthetic',
      fixture_base: 'tests/fixtures/breachatlas/C01/',
      expected_invariants: ['Sealed source bytes never modified'],
      negative_uat: [...REQUIRED_UAT],
      steps: [],
      clean_host_commands: ['npm start']
    };
    const errs = validateScenario(bad);
    testResults.push({
      name: 'rejects missing invariant',
      passed: errs.some(e => e.includes('Missing required invariant'))
    });
  }

  // Negative test 4: Missing provenance or license
  {
    const bad = {
      version: '1.0.0',
      project: 'BreachAtlas',
      status: 'planned acceptance contract; not executed domain proof',
      engine_implemented: false,
      fixture_base: 'tests/fixtures/breachatlas/C01/',
      expected_invariants: [...REQUIRED_INVARIANTS],
      negative_uat: [...REQUIRED_UAT],
      steps: [],
      clean_host_commands: ['npm start']
    };
    const errs = validateScenario(bad);
    testResults.push({
      name: 'rejects missing license and provenance',
      passed: errs.some(e => e.includes('license')) && errs.some(e => e.includes('provenance'))
    });
  }

  // Negative test 5: Fixture path outside repository (escape)
  {
    const bad = {
      version: '1.0.0',
      project: 'BreachAtlas',
      status: 'planned acceptance contract; not executed domain proof',
      engine_implemented: false,
      license: 'Apache-2.0',
      provenance: 'repo-synthetic',
      fixture_base: '../../outside/',
      expected_invariants: [...REQUIRED_INVARIANTS],
      negative_uat: [...REQUIRED_UAT],
      steps: [
        {
          action: 'seal',
          expected_state: 'sealed',
          input_fixture: '../escaped-file.txt',
          negative_cases: ['fail']
        }
      ],
      clean_host_commands: ['npm start']
    };
    const errs = validateScenario(bad);
    testResults.push({
      name: 'rejects out-of-repository fixture path',
      passed: errs.some(e => e.includes('unsafe fixture_base')) || errs.some(e => e.includes('unsafe fixture path'))
    });
  }

  // Negative test 6: Unsupported scenario version
  {
    const bad = {
      version: 'invalid-version',
      project: 'BreachAtlas',
      status: 'planned acceptance contract; not executed domain proof',
      engine_implemented: false,
      license: 'Apache-2.0',
      provenance: 'repo-synthetic',
      fixture_base: 'tests/fixtures/breachatlas/C01/',
      expected_invariants: [...REQUIRED_INVARIANTS],
      negative_uat: [...REQUIRED_UAT],
      steps: [],
      clean_host_commands: ['npm start']
    };
    const errs = validateScenario(bad);
    testResults.push({
      name: 'rejects unsupported scenario version',
      passed: errs.some(e => e.includes('Unsupported or missing scenario version'))
    });
  }

  // Negative test 7: Falsely claiming unimplemented engine passed
  {
    const bad = {
      version: '1.0.0',
      project: 'BreachAtlas',
      status: 'executed domain proof',
      engine_implemented: true,
      license: 'Apache-2.0',
      provenance: 'repo-synthetic',
      fixture_base: 'tests/fixtures/breachatlas/C01/',
      expected_invariants: [...REQUIRED_INVARIANTS],
      negative_uat: [...REQUIRED_UAT],
      steps: [],
      clean_host_commands: ['npm start']
    };
    const errs = validateScenario(bad);
    testResults.push({
      name: 'rejects false claim of engine execution passing',
      passed: errs.some(e => e.includes('Claim of executed engine proof'))
    });
  }

  // Negative test 8: Reference doc missing required invariants
  {
    const badDoc = '# BreachAtlas Reference Workflow\nOnly partial content here.';
    const errs = validateReferenceDoc(badDoc);
    testResults.push({
      name: 'rejects incomplete reference document',
      passed: errs.length >= 2
    });
  }

  return testResults;
}

export async function main() {
  const allErrors = [];

  // 1. Validate tests/scenarios/clone-to-value.json
  const scenarioPath = resolve(root, 'tests/scenarios/clone-to-value.json');
  let scenario;
  try {
    const raw = await readFile(scenarioPath, 'utf8');
    scenario = JSON.parse(raw);
  } catch (err) {
    allErrors.push(`Failed to read/parse ${scenarioPath}: ${err.message}`);
  }

  if (scenario) {
    const scenarioErrors = validateScenario(scenario);
    allErrors.push(...scenarioErrors);

    // Verify actual fixture files exist on disk and match provenance
    const fixtureBase = resolve(root, scenario.fixture_base);
    const provenancePath = join(fixtureBase, 'provenance.json');
    try {
      const provRaw = await readFile(provenancePath, 'utf8');
      const prov = JSON.parse(provRaw);
      if (prov.license !== 'Apache-2.0') {
        allErrors.push('provenance.json missing Apache-2.0 license.');
      }
      for (const [relFile, meta] of Object.entries(prov.files || {})) {
        const fullPath = join(fixtureBase, relFile);
        const data = await readFile(fullPath);
        const digest = createHash('sha256').update(data).digest('hex');
        if (digest !== meta.sha256) {
          allErrors.push(`Fixture hash mismatch for ${relFile}: recorded ${meta.sha256}, calculated ${digest}.`);
        }
      }
      if (scenario.c30_fixtures) {
        const c30Base = resolve(root, scenario.c30_fixtures);
        const c30Prov = JSON.parse(await readFile(join(c30Base, 'provenance.json'), 'utf8'));
        if (c30Prov.license !== 'Apache-2.0') allErrors.push('C30 provenance.json missing Apache-2.0 license.');
        for (const [relFile, expectedHex] of Object.entries(c30Prov.sha256 || {})) {
          const digest = createHash('sha256').update(await readFile(join(c30Base, relFile))).digest('hex');
          if (digest !== expectedHex) allErrors.push(`C30 fixture hash mismatch for ${relFile}.`);
        }
      }
    } catch (err) {
      allErrors.push(`Failed to verify fixture provenance at ${provenancePath}: ${err.message}`);
    }

    // Verify step fixture references exist
    for (const step of scenario.steps || []) {
      for (const f of [step.input_fixture, step.expected_output_fixture]) {
        if (f) {
          const target = join(fixtureBase, f);
          try {
            await readFile(target);
          } catch {
            allErrors.push(`Referenced fixture does not exist: ${f} (resolved to ${target})`);
          }
        }
      }
    }
  }

  // 2. Validate docs/product/REFERENCE_WORKFLOW.md
  const docPath = resolve(root, 'docs/product/REFERENCE_WORKFLOW.md');
  try {
    const docContent = await readFile(docPath, 'utf8');
    const docErrors = validateReferenceDoc(docContent);
    allErrors.push(...docErrors);
  } catch (err) {
    allErrors.push(`Failed to read ${docPath}: ${err.message}`);
  }

  // 3. Run Self-Tests / Negative Regression Cases
  const selfTests = await runSelfTests();
  const failedSelfTests = selfTests.filter(t => !t.passed);
  if (failedSelfTests.length > 0) {
    for (const failed of failedSelfTests) {
      allErrors.push(`Self-test failed: ${failed.name}`);
    }
  }

  if (allErrors.length > 0) {
    console.error('REFERENCE WORKFLOW CONTRACT VALIDATION FAILED:');
    for (const err of allErrors) {
      console.error(` - ${err}`);
    }
    process.exit(1);
  }

  console.log(`REFERENCE WORKFLOW CONTRACT VALIDATION PASSED: all 8 steps, invariants, fixtures, and ${selfTests.length} negative regression tests verified.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
