import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createWebServer } from '../../scripts/serve-web.mjs';
import { validateRuntimeConfig } from '../../apps/web/src/lib/runtime-config.mjs';
import { inspectJson } from '../../apps/web/src/lib/preview.mjs';
const config = { projectId: 'test-project', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 };

test('public configuration fails closed on engine flags, external endpoints, unknown keys and project mismatch', () => {
  assert.equal(validateRuntimeConfig(config, 'test-project').engineEnabled, false);
  for (const patch of [{ engineEnabled: true }, { apiBasePath: 'https://outside.invalid' }, { token: 'secret' }, { maxPreviewBytes: 0 }, { maxPreviewBytes: 1048577 }, { projectId: 'another-project' }]) assert.throws(() => validateRuntimeConfig({ ...config, ...patch }, 'test-project'));
});
test('preview rejects hostile structure, excessive UTF-8 size and excessive complexity', () => {
  for (const text of ['[]', 'null', '{', '{"__proto__":{}}', '{"deep":{"constructor":1}}']) assert.throws(() => inspectJson(text, 1024));
  assert.throws(() => inspectJson('{"x":"éé"}', 10), /limit/);
  assert.throws(() => inspectJson('{"a":'.repeat(40) + '{}' + '}'.repeat(40), 10000), /complex/);
  const result = inspectJson('{"safe":"<script>alert(1)</script>"}', 1024);
  assert.deepEqual(result.fields, ['safe']);
  assert.equal({}.polluted, undefined);
});
test('HTTP isolation, cache rules, health semantics, methods, traversal and symlink containment', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'web-foundation-'));
  const root = join(dir, 'public');
  await mkdir(join(root, 'assets'), { recursive: true });
  await writeFile(join(root, 'index.html'), '<!doctype html><h1>workspace</h1>');
  await writeFile(join(root, 'assets', 'app-123.js'), 'export const ok = true;');
  await writeFile(join(dir, 'private.txt'), 'PRIVATE_SENTINEL');
  await symlink(join(dir, 'private.txt'), join(root, 'assets', 'leak.js'));
  const server = createWebServer({ root, config, projectId: 'test-project' });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(dir, { recursive: true }); });
  const index = await fetch(base);
  assert.equal(index.status, 200); assert.match(await index.text(), /workspace/);
  assert.equal(index.headers.get('cache-control'), 'no-store');
  assert.match(index.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(index.headers.get('x-content-type-options'), 'nosniff');
  assert.equal((await fetch(base + '/assets/app-123.js')).headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.equal((await fetch(base + '/api/v1/anything')).status, 503);
  const ready = await (await fetch(base + '/readyz')).json(); assert.equal(ready.engineReady, false);
  assert.equal((await fetch(base + '/runtime-config.json')).headers.get('cache-control'), 'no-store');
  for (const path of ['/package.json', '/.env', '/assets/%2e%2e/private.txt', '/assets/leak.js', '/%ZZ', '/unknown', '/api']) {
    const response = await fetch(base + path);
    assert.ok(response.status >= 400, path); assert.doesNotMatch(await response.text(), /PRIVATE_SENTINEL/);
  }
  const post = await fetch(base, { method: 'POST', body: 'data' }); assert.equal(post.status, 405);
  assert.equal(post.headers.get('allow'), 'GET, HEAD');
  assert.equal(await (await fetch(base, { method: 'HEAD' })).text(), '');
  await rm(join(root, 'index.html')); assert.equal((await fetch(base + '/readyz')).status, 503);
});
test('generated project and runtime identity agree with exactly forty original product tasks', async () => {
  const read = async path => JSON.parse(await readFile(new URL('../../' + path, import.meta.url), 'utf8'));
  const product = await read('apps/web/src/generated/project.json');
  const actual = await read('ops/web/runtime-config.json');
  validateRuntimeConfig(actual, product.slug);
  assert.equal(product.tasks.length, 40); assert.equal(new Set(product.tasks.map(task => task.id)).size, 40);
  assert.equal(product.webTasks.length, 8);
});
