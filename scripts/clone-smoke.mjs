import { spawn, spawnSync } from 'node:child_process';
import { access, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'oss-clone-'));
let webOnlyServer;
let degradedSupervisor;

function run(command, args, cwd, options = {}) {
  const result = spawnSync(command, args, {
    cwd, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed (exit ${result.status}): ${result.stdout ?? ''}${result.stderr ?? result.error?.message ?? ''}`);
  }
  return (result.stdout ?? '').trim();
}

function getFreePort() {
  return new Promise((resolvePromise, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      if (!addr || typeof addr === 'string') {
        srv.close();
        reject(new Error('Failed to bind ephemeral loopback port'));
        return;
      }
      const { port } = addr;
      srv.close(() => resolvePromise(port));
    });
  });
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || !child.pid) return;
  child.kill('SIGTERM');
  const exited = new Promise(accept => child.once('exit', accept));
  const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
  await exited;
  clearTimeout(timer);
}

try {
  // Stage committed/index tree into an isolated bare repo so real `git clone` transfers objects cleanly.
  const tree = run('git', ['write-tree'], root);
  const identity = {
    ...process.env,
    GIT_AUTHOR_NAME: 'Clone smoke', GIT_AUTHOR_EMAIL: 'clone@example.invalid',
    GIT_COMMITTER_NAME: 'Clone smoke', GIT_COMMITTER_EMAIL: 'clone@example.invalid',
  };
  const commit = run('git', ['commit-tree', tree, '-m', 'temporary staged source proof'], root, { env: identity });

  const source = join(temp, 'source.git');
  run('git', ['init', '--bare', '--quiet', source], temp);
  const objects = resolve(root, run('git', ['rev-parse', '--git-path', 'objects'], root));
  await mkdir(join(source, 'objects', 'info'), { recursive: true });
  await writeFile(join(source, 'objects', 'info', 'alternates'), objects + '\n');
  run('git', ['--git-dir=' + source, 'update-ref', 'refs/heads/snapshot', commit], temp);

  const checkout = join(temp, 'checkout');
  run('git', ['clone', '--quiet', '--no-local', '--branch', 'snapshot', source, checkout], temp);
  if (run('git', ['rev-parse', 'HEAD^{tree}'], checkout) !== tree) throw new Error('Cloned tree differs from index');
  if (!process.env.npm_execpath) throw new Error('Invoke through npm run test:clone.');

  // 1. Clean-host setup (npm ci + build + go build breachatlas + go build verify)
  run(process.execPath, [process.env.npm_execpath, 'run', 'setup'], checkout);
  await access(join(checkout, 'dist/web/index.html'), constants.R_OK);
  await access(join(checkout, 'dist/bin/breachatlas'), constants.X_OK);
  await access(join(checkout, 'dist/bin/verify'), constants.X_OK);

  // 2. Web-only foundation proof (explicitly kept and labeled separate from engine readiness)
  const webOnlyLaunch = `
    import { createWebServer } from './scripts/serve-web.mjs';
    import fs from 'node:fs';
    const config = JSON.parse(fs.readFileSync('ops/web/runtime-config.json'));
    const instance = createWebServer({ root: 'dist/web', config, projectId: config.projectId });
    instance.listen(0, '127.0.0.1', () => console.log(instance.address().port));
  `;
  webOnlyServer = spawn(process.execPath, ['--input-type=module', '-e', webOnlyLaunch], {
    cwd: checkout, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const webOnlyPort = await new Promise((accept, reject) => {
    const timer = setTimeout(() => reject(new Error('Web-only startup deadline')), 10000);
    webOnlyServer.once('error', error => { clearTimeout(timer); reject(error); });
    webOnlyServer.once('exit', () => { clearTimeout(timer); reject(new Error('Web-only server exited')); });
    webOnlyServer.stdout.once('data', data => { clearTimeout(timer); accept(Number(data.toString().trim())); });
  });
  const webOnlyBase = 'http://127.0.0.1:' + webOnlyPort;
  const webOnlyReady = await fetch(webOnlyBase + '/readyz');
  const webOnlyState = await webOnlyReady.json();
  if (!webOnlyReady.ok || webOnlyState.engineReady !== false || (await fetch(webOnlyBase + '/api/v1/unimplemented')).status !== 503) {
    throw new Error('Incorrect web-only readiness boundary');
  }
  if (!(await fetch(webOnlyBase)).ok) throw new Error('Web-only workspace unavailable');
  await stopChild(webOnlyServer);
  webOnlyServer = undefined;

  // 3. Negative prerequisite probe: missing storage directory forces /readyz 503 under `npm start`
  const badStorageDir = join(temp, 'nonexistent-storage-prerequisite');
  const degWebPort = await getFreePort();
  const degEngPort = await getFreePort();
  degradedSupervisor = spawn(
    process.execPath,
    [
      'scripts/start-local.mjs',
      '--port', String(degWebPort),
      '--enginePort', String(degEngPort),
      '--storageDir', badStorageDir,
    ],
    { cwd: checkout, stdio: ['ignore', 'pipe', 'pipe'] }
  );
  await new Promise((accept, reject) => {
    const timer = setTimeout(() => reject(new Error('Degraded supervisor startup deadline')), 10000);
    degradedSupervisor.once('exit', code => { clearTimeout(timer); reject(new Error(`Degraded supervisor exited early (${code})`)); });
    degradedSupervisor.stdout.on('data', chunk => {
      if (chunk.toString().includes('"engineReady":true')) {
        clearTimeout(timer);
        accept();
      }
    });
  });
  const degReadyRes = await fetch(`http://127.0.0.1:${degWebPort}/readyz`);
  const degReadyJson = await degReadyRes.json();
  if (degReadyRes.status !== 503 || degReadyJson.storageReady !== false) {
    throw new Error(`Expected /readyz 503 storageReady:false for missing prerequisite, got ${degReadyRes.status}`);
  }
  await stopChild(degradedSupervisor);
  degradedSupervisor = undefined;

  // 4. Full C30 reference workflow, negative UATs, offline `verify`, restart, and restore via `npm start` + Chromium
  const acceptWebPort = await getFreePort();
  const acceptEngPort = await getFreePort();
  const playwrightCli = resolve(checkout, 'node_modules/@playwright/test/cli.js');
  run(
    process.execPath,
    [playwrightCli, 'test', 'tests/browser/clone-to-value.spec.ts'],
    checkout,
    {
      env: {
        ...process.env,
        BREACHATLAS_WEB_PORT: String(acceptWebPort),
        BREACHATLAS_ENGINE_PORT: String(acceptEngPort),
      },
    }
  );

  // 5. Verify doctor status and project state in cloned checkout
  const doctorOut = JSON.parse(run(process.execPath, [process.env.npm_execpath, 'run', '--silent', 'doctor'], checkout));
  if (!doctorOut.nodeSupported || !doctorOut.webAssetsBuilt || !doctorOut.engineBuilt) {
    throw new Error(`Unexpected doctor failure in cloned checkout: ${JSON.stringify(doctorOut)}`);
  }
  const projectState = JSON.parse(await readFile(join(checkout, 'plans/project-state.json'), 'utf8'));

  console.log(JSON.stringify({
    passed: true,
    stagedTree: tree,
    proof: 'real git clone -> npm run setup -> npm start -> tests/browser/clone-to-value.spec.ts -> offline verify -> restart & restore',
    webOnlyProof: {
      label: 'web-only-foundation-shell (kept separate from engine readiness)',
      passed: true,
      engineReady: false,
    },
    fullWorkflowProof: {
      label: 'c30-clone-to-value-local-usability',
      passed: true,
      engineReady: true,
      missingPrerequisiteStatus: degReadyRes.status,
      offlineVerifierPassed: true,
      restartAndRestorePassed: true,
      negativeCasesPassed: true,
    },
    coreReady: Boolean(projectState.core_ready),
  }));
} finally {
  await stopChild(degradedSupervisor);
  await stopChild(webOnlyServer);
  await rm(temp, { recursive: true, force: true });
}
