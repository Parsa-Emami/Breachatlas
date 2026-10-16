import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'oss-clone-'));
let server;

function run(command, args, cwd, options = {}) {
  const result = spawnSync(command, args, {
    cwd, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} failed: ${result.stdout ?? ''}${result.stderr ?? result.error?.message ?? ''}`);
  }
  return result.stdout.trim();
}

try {
  // Test the index so contributors can verify a proposed commit before pushing.
  const tree = run('git', ['write-tree'], root);
  const identity = {
    ...process.env,
    GIT_AUTHOR_NAME: 'Clone smoke', GIT_AUTHOR_EMAIL: 'clone@example.invalid',
    GIT_COMMITTER_NAME: 'Clone smoke', GIT_COMMITTER_EMAIL: 'clone@example.invalid',
  };
  const commit = run('git', ['commit-tree', tree, '-m', 'temporary staged source proof'], root, { env: identity });

  // Advertise the snapshot from an isolated repository. No source refs change;
  // a real transport clone collects every object, even from a shallow checkout.
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
  run(process.execPath, [process.env.npm_execpath, 'run', 'setup'], checkout);

  const launch = `
    import { createWebServer } from './scripts/serve-web.mjs';
    import fs from 'node:fs';
    const config = JSON.parse(fs.readFileSync('ops/web/runtime-config.json'));
    const instance = createWebServer({ root: 'dist/web', config, projectId: config.projectId });
    instance.listen(0, '127.0.0.1', () => console.log(instance.address().port));
  `;
  server = spawn(process.execPath, ['--input-type=module', '-e', launch], {
    cwd: checkout, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const port = await new Promise((accept, reject) => {
    const timer = setTimeout(() => reject(new Error('Startup deadline')), 10000);
    server.once('error', error => { clearTimeout(timer); reject(error); });
    server.once('exit', () => { clearTimeout(timer); reject(new Error('Server exited')); });
    server.stdout.once('data', data => { clearTimeout(timer); accept(Number(data.toString().trim())); });
  });
  const base = 'http://127.0.0.1:' + port;
  const health = await fetch(base + '/readyz');
  const state = await health.json();
  if (!health.ok || state.engineReady !== false || (await fetch(base + '/api/v1/unimplemented')).status !== 503) {
    throw new Error('Incorrect readiness boundary');
  }
  if (!(await fetch(base)).ok) throw new Error('Workspace unavailable');
  console.log(JSON.stringify({
    passed: true, stagedTree: tree,
    proof: 'real git clone -> npm run setup -> web startup', coreReady: false,
  }));
} finally {
  if (server && server.exitCode === null && server.pid) {
    server.kill('SIGTERM');
    await new Promise(accept => server.once('exit', accept));
  }
  await rm(temp, { recursive: true, force: true });
}
