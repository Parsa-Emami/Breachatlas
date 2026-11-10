import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('README quickstart enters the exact case-sensitive cloned directory', async () => {
  const readme = await readFile(new URL('../../README.md', import.meta.url), 'utf8');
  const blocks = [...readme.matchAll(/```(?:sh|bash)\n([\s\S]*?)\n```/g)];
  const quickstart = blocks.map(([, body]) => body)
    .find(body => body.includes('git clone https://github.com/Parsa-Emami/Breachatlas.git'));
  assert.ok(quickstart, 'README must include a shell quickstart');
  const commands = quickstart.split('\n').map(line => line.trim()).filter(Boolean);
  const remote = commands[0].match(/^git clone https:\/\/github\.com\/[^/]+\/([^\s/]+)\.git$/);
  assert.ok(remote, 'first command must clone a GitHub repository');
  assert.equal(commands[1], `cd ${remote[1]}`, 'clone and cd must use identical case');
  assert.deepEqual(commands.slice(2, 4), ['npm run setup', 'npm start']);
});
