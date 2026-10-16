import { cp, mkdir, readdir, readFile, writeFile, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
const output = 'dist/release';
await rm(output, { recursive: true, force: true }); await mkdir(output, { recursive: true });
await cp('dist/web', output + '/web', { recursive: true });
await cp('scripts/serve-web.mjs', output + '/scripts/serve-web.mjs');
await cp('apps/web/src/lib/runtime-config.mjs', output + '/apps/web/src/lib/runtime-config.mjs');
await cp('ops/web', output + '/ops/web', { recursive: true });
await cp('LICENSE', output + '/LICENSE');
await cp('NOTICE', output + '/NOTICE');
await cp('docs/engineering/WEB_RUNBOOK.md', output + '/README.md');
let source;
try { source = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(); } catch { throw new Error('Package from a git checkout so provenance is explicit.'); }
const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=normal'], { encoding: 'utf8' }).trim() !== '';
await writeFile(output + '/release.json', JSON.stringify({ sourceCommit: source, dirty, scope: 'web-foundation', engineReady: false }, null, 2) + '\n');
const files = [];
async function walk(path, prefix = '') {
  for (const entry of (await readdir(path, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const name = prefix + entry.name;
    if (entry.isDirectory()) await walk(join(path, entry.name), name + '/');
    else files.push(createHash('sha256').update(await readFile(join(path, entry.name))).digest('hex') + '  ' + name);
  }
}
await walk(output); await writeFile(output + '/SHA256SUMS.txt', files.join('\n') + '\n');
console.log('Packaged web-only release; source dirty=' + dirty + '; engineReady=false');
