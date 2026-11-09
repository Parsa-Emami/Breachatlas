import { spawnSync } from 'node:child_process';
import { readFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
export const supportedNode = version => { const [major, minor] = version.replace(/^v/, '').split('.').map(Number); return major === 24 && minor >= 19; };
export function setup(args = [], run = spawnSync, version = process.version) {
  if (!supportedNode(version)) throw new Error('Use Node 24.19 or a newer Node 24 release.');
  if (args.some(arg => !['--check', '--skip-install'].includes(arg))) throw new Error('Supported setup options: --check, --skip-install');
  const steps = args.includes('--skip-install') ? [['run', 'build']] : [['ci', '--ignore-scripts', '--no-fund'], ['run', 'build']];
  if (!args.includes('--check')) {
    for (const step of steps) {
      if (!process.env.npm_execpath) throw new Error('Run this command through npm run setup.');
      const result = run(process.execPath, [process.env.npm_execpath, ...step], { cwd: root, stdio: 'inherit' });
      if (result.error || result.status !== 0) throw new Error('Setup failed at npm ' + step.join(' '));
    }
    const goResult = run('go', ['build', '-o', 'dist/bin/breachatlas', './cmd/breachatlas'], { cwd: root, stdio: 'inherit' });
    if (goResult.error || goResult.status !== 0) throw new Error('Setup failed at go build ./cmd/breachatlas');
  }
  return { executed: !args.includes('--check'), steps, capability: 'unified-local-runtime', engineReady: true, binary: 'dist/bin/breachatlas' };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] === 'doctor') {
      let built = false; try { await access(new URL('../dist/web/index.html', import.meta.url)); built = true; } catch {}
      let engineBuilt = false; try { await access(new URL('../dist/bin/breachatlas', import.meta.url)); engineBuilt = true; } catch {}
      const state = JSON.parse(await readFile(new URL('../plans/project-state.json', import.meta.url), 'utf8'));
      console.log(JSON.stringify({ nodeSupported: supportedNode(process.version), webAssetsBuilt: built, engineBuilt, readiness: state.readiness, engineReady: state.core_ready, start: 'npm start', next: 'npm run plan -- next' }, null, 2));
      if (!built || !engineBuilt || !supportedNode(process.version)) process.exitCode = 1;
    } else console.log(JSON.stringify({ ...setup(process.argv.slice(3)), start: 'npm start', note: 'Full product usability requires the C30 workflow; complete OSS v1 requires C40.' }, null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
