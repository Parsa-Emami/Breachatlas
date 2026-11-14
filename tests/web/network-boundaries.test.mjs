import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import { createHash } from 'node:crypto';
import {
  createWebServer,
  isLoopbackHost,
  isLoopbackAuthority,
  validateLoopbackEngineTarget,
} from '../../scripts/serve-web.mjs';

const repoRoot = resolve(new URL('../..', import.meta.url).pathname);
const baseConfig = {
  projectId: 'breachatlas',
  apiBasePath: '/api',
  engineEnabled: false,
  maxPreviewBytes: 1048576,
};

function rawHttp(urlStr, { method = 'GET', headers = {}, body } = {}) {
  const url = new URL(urlStr);
  return new Promise((resolvePromise, reject) => {
    const req = httpRequest(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method,
        headers,
      },
      res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          resolvePromise({
            status: res.statusCode ?? 0,
            headers: res.headers,
            text: Buffer.concat(chunks).toString('utf8'),
          });
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('C32 loopback validators reject non-loopback authorities and upstream targets', async () => {
  const fxDir = join(repoRoot, 'tests/fixtures/breachatlas/C32');
  const prov = JSON.parse(await readFile(join(fxDir, 'provenance.json'), 'utf8'));
  assert.equal(prov.license, 'Apache-2.0');
  for (const [rel, expectedSha] of Object.entries(prov.sha256)) {
    const gotSha = createHash('sha256').update(await readFile(join(fxDir, rel))).digest('hex');
    assert.equal(gotSha, expectedSha, `fixture checksum mismatch for ${rel}`);
  }

  const pos = JSON.parse(await readFile(join(fxDir, 'positive/local-loopback-boundary.json'), 'utf8'));
  const neg = JSON.parse(await readFile(join(fxDir, 'invalid/non-loopback-and-cross-origin.json'), 'utf8'));

  for (const host of pos.loopback_hosts) {
    assert.equal(isLoopbackHost(host), true, host);
    assert.equal(isLoopbackAuthority(`${host}:4173`), true, host);
  }
  for (const badHost of neg.disallowed_hosts) {
    assert.equal(isLoopbackAuthority(badHost), false, badHost);
  }
  for (const badUpstream of neg.disallowed_upstream_hosts) {
    assert.throws(
      () => validateLoopbackEngineTarget({ hostname: badUpstream, port: 8080 }),
      /Loopback engine target required/
    );
  }
  assert.deepEqual(validateLoopbackEngineTarget({ hostname: '127.0.0.1', port: 8080 }), {
    hostname: '127.0.0.1',
    port: 8080,
  });
});

test('C32 web relay enforces loopback Host, Origin/Sec-Fetch-Site, forged headers, cache boundaries, and default unexposed engine across restart', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'breachatlas-c32-web-'));
  t.after(async () => rm(dir, { recursive: true, force: true }));
  const publicRoot = join(dir, 'web');
  await mkdir(join(publicRoot, 'assets'), { recursive: true });
  await writeFile(join(publicRoot, 'index.html'), '<!doctype html><h1>BreachAtlas</h1>');
  await writeFile(join(publicRoot, 'assets', 'app-c32.js'), 'export const c32 = true;');

  const fxDir = join(repoRoot, 'tests/fixtures/breachatlas/C32');
  const pos = JSON.parse(await readFile(join(fxDir, 'positive/local-loopback-boundary.json'), 'utf8'));
  const neg = JSON.parse(await readFile(join(fxDir, 'invalid/non-loopback-and-cross-origin.json'), 'utf8'));
  const expected = JSON.parse(await readFile(join(fxDir, 'expected/network-boundary-outcomes.json'), 'utf8'));

  // Reject non-loopback engine upstream configuration at server creation
  assert.throws(
    () =>
      createWebServer({
        root: publicRoot,
        config: baseConfig,
        projectId: 'breachatlas',
        manifestEngine: { hostname: '0.0.0.0', port: 8080 },
      }),
    /Loopback engine target required/
  );

  // Start standalone web shell (engine unexposed by default) and test across restart
  for (let cycle = 0; cycle < 2; cycle++) {
    const server = createWebServer({
      root: publicRoot,
      config: baseConfig,
      projectId: 'breachatlas',
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const port = server.address().port;
    const base = `http://127.0.0.1:${port}`;

    try {
      // Standalone web shell keeps engine work disabled (503)
      const apiRes = await rawHttp(`${base}/api/v1/evidence-manifests/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      assert.equal(apiRes.status, expected.standalone_api_status);
      assert.equal(JSON.parse(apiRes.text).error.code, expected.standalone_api_error);

      // Host header validation
      for (const badHost of neg.disallowed_hosts) {
        const res = await rawHttp(`${base}/healthz`, { headers: { Host: badHost } });
        assert.equal(res.status, expected.invalid_host_status);
        assert.equal(JSON.parse(res.text).error, expected.invalid_host_error);
      }

      // Origin & Sec-Fetch-Site enforcement on both API and non-API routes
      for (const route of ['/', '/healthz', '/readyz', '/runtime-config.json', '/assets/app-c32.js']) {
        const crossSite = await rawHttp(`${base}${route}`, {
          headers: { 'Sec-Fetch-Site': neg.disallowed_fetch_site },
        });
        assert.equal(crossSite.status, expected.origin_not_allowed_status, route);
        assert.equal(JSON.parse(crossSite.text).error, expected.origin_not_allowed_error);

        for (const badOrigin of neg.disallowed_origins) {
          const crossOrigin = await rawHttp(`${base}${route}`, {
            headers: { Origin: badOrigin },
          });
          assert.equal(crossOrigin.status, expected.origin_not_allowed_status, `${route} origin=${badOrigin}`);
          assert.equal(JSON.parse(crossOrigin.text).error, expected.origin_not_allowed_error);
        }
      }

      // Forged proxy/identity headers rejected on API
      for (const headerName of neg.forged_headers) {
        const forged = await rawHttp(`${base}/api/v1/diagnostics`, {
          headers: { [headerName]: 'admin' },
        });
        assert.equal(forged.status, expected.forged_header_status, headerName);
        assert.equal(JSON.parse(forged.text).error.code, expected.forged_header_error);
      }

      // Allowed Nginx transport headers remain compatible with loopback Host
      const proxied = await rawHttp(`${base}/readyz`, {
        headers: {
          Host: `127.0.0.1:${port}`,
          ...pos.allowed_proxy_transport_headers,
        },
      });
      assert.equal(proxied.status, 200);
      assert.equal(proxied.headers['cache-control'], 'no-store');

      // Cache-Control rules: immutable only on fingerprinted /assets/*; no-store on all dynamic/config/API routes
      const assetRes = await rawHttp(`${base}${pos.cache_control.asset_path}`);
      assert.equal(assetRes.status, 200);
      assert.equal(assetRes.headers['cache-control'], pos.cache_control.asset_header);

      for (const dynPath of pos.cache_control.dynamic_paths) {
        const dynRes = await rawHttp(`${base}${dynPath}`);
        assert.equal(dynRes.headers['cache-control'], pos.cache_control.dynamic_header, dynPath);
      }
    } finally {
      server.closeAllConnections();
      await new Promise(resolveClose => server.close(resolveClose));
    }
  }

  // Verify domain.json evidence agrees with local zero-domain profile
  const domainEvidence = JSON.parse(await readFile(join(repoRoot, 'docs/evidence/domain.json'), 'utf8'));
  assert.equal(domainEvidence.owned_public_domain_required, false);
  assert.equal(domainEvidence.standalone_web_engine_exposed_by_default, false);
  assert.equal(domainEvidence.boundaries.non_loopback_upstream_rejected, true);
  assert.equal(domainEvidence.boundaries.optional_private_tls_ingress.engine_port_exposed_externally, false);
});
