import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import http from 'node:http';

const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');

function rawHttpRequest(
  path: string,
  options: { method?: string; headers?: Record<string, string>; body?: string } = {}
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: 4173,
        path,
        method: options.method ?? 'GET',
        headers: options.headers,
      },
      res => {
        const chunks: Buffer[] = [];
        res.on('data', chunk => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      }
    );
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

test.describe('C27 cross-surface abuse, XSS/import, and authorization boundaries', () => {
  test('HTTP security headers, traversal/dotfile blocks, cross-origin/cross-site, forged headers, and oversized rejections on live relay', async ({ request }) => {
    // 1. Security headers on root HTML response
    const rootRes = await request.get('/');
    expect(rootRes.status()).toBe(200);
    const headers = rootRes.headers();
    expect(headers['content-security-policy']).toContain("default-src 'none'");
    expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(headers['content-security-policy']).toContain("object-src 'none'");
    expect(headers['content-security-policy']).toContain("base-uri 'none'");
    expect(headers['content-security-policy']).toContain("form-action 'none'");
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['referrer-policy']).toBe('no-referrer');
    expect(headers['cache-control']).toBe('no-store');

    // 2. Non-loopback Host header rejected with 403 invalid_host
    const badHost = await rawHttpRequest('/healthz', { headers: { Host: 'attacker.invalid:4173' } });
    expect(badHost.status).toBe(403);
    expect(JSON.parse(badHost.body)).toEqual({ error: 'invalid_host' });

    // 3. Dotfile and path traversal paths fail closed without leaking repository files
    for (const badPath of ['/.env', '/.env.example', '/package.json', '/assets/%2e%2e/package.json', '/..%2fetc%2fpasswd', '/%00']) {
      const res = await rawHttpRequest(badPath, { headers: { Host: '127.0.0.1:4173' } });
      expect(res.status, badPath).toBeGreaterThanOrEqual(400);
      expect(res.body).not.toContain('breachatlas-web');
      expect(res.body).not.toContain('root:x:0:0');
    }

    // 4. Cross-origin and cross-site rejections across all three /api/v1 endpoints
    const apiEndpoints = [
      '/api/v1/evidence-manifests/validate',
      '/api/v1/evidence-integrity/inspect',
      '/api/v1/timeline/inspect',
    ];
    for (const endpoint of apiEndpoints) {
      const crossOrigin = await request.post(endpoint, {
        headers: { 'Content-Type': 'application/json', Origin: 'https://attacker.invalid' },
        data: '{}',
      });
      expect(crossOrigin.status(), `${endpoint} cross-origin`).toBe(403);
      expect((await crossOrigin.json()).error.code).toBe('origin_not_allowed');

      const crossSite = await request.post(endpoint, {
        headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'cross-site' },
        data: '{}',
      });
      expect(crossSite.status(), `${endpoint} cross-site`).toBe(403);
      expect((await crossSite.json()).error.code).toBe('origin_not_allowed');

      // 5. Forged identity/proxy override headers fail closed with 403 forged_header
      for (const forgedHeader of [
        { 'x-identity-override': 'admin' },
        { 'X-Forwarded-User': 'root' },
        { 'x-forwarded-host': 'evil.invalid' },
        { 'x-role': 'admin' },
        { 'x-case-scope': 'case-other-999' },
        { 'x-provider': 'external-kms' },
      ]) {
        const forged = await request.post(endpoint, {
          headers: { 'Content-Type': 'application/json', ...forgedHeader },
          data: '{}',
        });
        expect(forged.status(), `${endpoint} ${Object.keys(forgedHeader)[0]}`).toBe(403);
        expect((await forged.json()).error.code).toBe('forged_header');
      }

      // 6. Method & Content-Type enforcement
      const getRes = await request.get(endpoint);
      expect(getRes.status()).toBe(405);
      expect(getRes.headers()['allow']).toBe('POST');

      const wrongType = await request.post(endpoint, {
        headers: { 'Content-Type': 'text/plain' },
        data: '{}',
      });
      expect(wrongType.status()).toBe(415);
      expect((await wrongType.json()).error.code).toBe('unsupported_media_type');
    }

    // 7. Query-string variants, unmapped /api/* routes, and /runtime-config.json cross-origin must fail closed with 403
    for (const queryVariant of [
      '/api/v1/evidence-manifests/validate?foo=1',
      '/api/v1/evidence-integrity/inspect?foo=1',
      '/api/v1/timeline/inspect?foo=1',
    ]) {
      const qOrigin = await request.post(queryVariant, {
        headers: { 'Content-Type': 'application/json', Origin: 'https://attacker.invalid' },
        data: '{}',
      });
      expect(qOrigin.status(), `${queryVariant} cross-origin`).toBe(403);
      expect((await qOrigin.json()).error.code).toBe('origin_not_allowed');

      const qForged = await request.post(queryVariant, {
        headers: { 'Content-Type': 'application/json', 'x-identity-override': 'admin' },
        data: '{}',
      });
      expect(qForged.status(), `${queryVariant} forged`).toBe(403);
      expect((await qForged.json()).error.code).toBe('forged_header');
    }

    for (const apiProbe of ['/api', '/api/v1/health']) {
      const getCross = await request.get(apiProbe, {
        headers: { 'Sec-Fetch-Site': 'cross-site' },
      });
      expect(getCross.status(), `${apiProbe} cross-site`).toBe(403);
      expect((await getCross.json()).error.code).toBe('origin_not_allowed');

      const getForged = await request.get(apiProbe, {
        headers: { 'x-role': 'admin' },
      });
      expect(getForged.status(), `${apiProbe} forged`).toBe(403);
      expect((await getForged.json()).error.code).toBe('forged_header');
    }

    const cfgCross = await request.get('/runtime-config.json', {
      headers: { Origin: 'https://attacker.invalid' },
    });
    expect(cfgCross.status()).toBe(403);
    expect((await cfgCross.json()).error).toBe('origin_not_allowed');

    // 8. Oversized inspect payload (>256 KiB) rejected with 413 payload_too_large
    const oversizedBody = JSON.stringify({
      schema_version: '1',
      case_id: 'case-c27-sec',
      items: [],
      pad: 'x'.repeat(263 * 1024),
    });
    const oversizedRes = await request.post('/api/v1/evidence-integrity/inspect', {
      headers: { 'Content-Type': 'application/json' },
      data: oversizedBody,
    });
    expect(oversizedRes.status()).toBe(413);
    expect((await oversizedRes.json()).error.code).toBe('payload_too_large');
  });

  test('XSS payloads and hostile imports fail closed on #workspace, #evidence, #timeline, and #roadmap without modifying fixtures', async ({ page }) => {
    const errors: string[] = [];
    const dialogs: string[] = [];
    page.on('pageerror', err => errors.push(err.message));
    page.on('dialog', dialog => {
      dialogs.push(dialog.message());
      void dialog.dismiss();
    });

    const fixturePath = 'tests/fixtures/breachatlas/C27/positive/authorized-security-baseline.json';
    const beforeFixtureBytes = await readFile(fixturePath);
    const baseline = JSON.parse(beforeFixtureBytes.toString('utf8'));

    // --- Surface 1: #workspace (local JSON preview + manifest validation) ---
    await page.goto('/#workspace');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

    const previewPanel = page.locator('section.panel', { hasText: 'Inspect a document' });
    const previewInput = previewPanel.getByLabel('Choose JSON file');
    // XSS key and value in local preview
    await previewInput.setInputFiles({
      name: '<img src=x onerror="window.__xssC27=\'file\'">.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({ '<script>window.__xssC27="key"</script>': '<svg onload="window.__xssC27=1">' })),
    });
    const previewStatus = previewPanel.getByRole('status');
    await expect(previewStatus).toContainText('<script>window.__xssC27="key"</script>');
    expect(await page.evaluate(() => (window as unknown as { __xssC27?: unknown }).__xssC27)).toBeUndefined();

    // Hostile prototype pollution imports rejected (__proto__ and constructor)
    for (const hostileProto of ['{"__proto__":{"polluted":true}}', '{"nested":{"constructor":{"prototype":{"polluted":true}}}}']) {
      await previewInput.setInputFiles({
        name: 'proto.json',
        mimeType: 'application/json',
        buffer: Buffer.from(hostileProto),
      });
      await expect(previewPanel.getByRole('alert')).toContainText('Unsafe document key');
      expect(await page.evaluate(() => ({} as { polluted?: unknown }).polluted)).toBeUndefined();
    }

    // Hostile manifest upload (path traversal case_id & oversized >16 KiB)
    const manifestPanel = page.locator('section.panel', { hasText: 'Validate an evidence manifest' });
    const manifestInput = manifestPanel.getByLabel('Validate manifest');
    await manifestInput.setInputFiles({
      name: 'traversal-manifest.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({ ...baseline.manifest, case_id: '../escape' })),
    });
    await expect(manifestPanel.getByRole('alert')).toContainText('invalid value');

    await manifestInput.setInputFiles({
      name: 'oversized-manifest.json',
      mimeType: 'application/json',
      buffer: Buffer.alloc(17 * 1024, 0x20),
    });
    await expect(manifestPanel.getByRole('alert')).toContainText('16 KiB');

    // --- Surface 2: #evidence (XSS rendering, tampered digest, broken custody, legal hold, negative UATs) ---
    await page.goto('/#evidence');
    const evidenceInput = page.getByLabel('Choose evidence snapshot JSON');

    await evidenceInput.setInputFiles({
      name: 'c27-evidence.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(baseline.evidence_inspect_snapshot)),
    });
    const evTable = page.getByRole('table', { name: 'Case evidence integrity and custody' });
    await expect(evTable).toBeVisible();
    await expect(evTable).toContainText('Failed verification');
    await expect(evTable).toContainText('Legal hold');
    await expect(evTable).toContainText('<script>window.__xssC27="filename"</script>');
    await page.getByRole('button', { name: 'Inspect ev-c27-001' }).click();
    const evDetail = page.getByRole('region', { name: 'Selected evidence details' });
    await expect(evDetail).toContainText('<svg onload="window.__xssC27=\'hold\'">');
    await expect(evDetail).toContainText('<script>window.__xssC27="custActor"</script>');
    await expect(evDetail).toContainText('<img src=x onerror="window.__xssC27=\'custReason\'">');
    expect(await page.evaluate(() => (window as unknown as { __xssC27?: unknown }).__xssC27)).toBeUndefined();

    // Tampered custody chain triggers Custody failed + Failed verification
    const brokenCustody = structuredClone(baseline.evidence_inspect_snapshot);
    brokenCustody.items = [brokenCustody.items[0]];
    brokenCustody.items[0].custody_events[0].event_digest = '0'.repeat(64);
    await evidenceInput.setInputFiles({
      name: 'broken-custody.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(brokenCustody)),
    });
    await expect(evTable).toContainText('Custody failed');
    await expect(evTable).toContainText('Failed verification');

    // Negative UAT: unavailable provider (503) and malformed JSON (400) on #evidence
    await evidenceInput.setInputFiles({
      name: 'unavail.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({ schema_version: '1', case_id: 'case-c27-sec', provider: 'cloud-kms', items: [] })),
    });
    await expect(page.getByRole('alert')).toContainText('Unavailable engine/provider:');

    await evidenceInput.setInputFiles({
      name: 'malformed.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{"schema_version":"1",'),
    });
    await expect(page.getByRole('alert')).toContainText('Invalid input:');

    // --- Surface 3: #timeline (XSS rendering, epistemic separation, promotion_forbidden, negative UATs) ---
    await page.goto('/#timeline');
    const timelineInput = page.getByLabel('Choose timeline snapshot JSON');

    await timelineInput.setInputFiles({
      name: 'c27-timeline.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(baseline.timeline_inspect_snapshot)),
    });
    const timelineList = page.getByRole('list', { name: 'Observed timeline events' });
    await expect(timelineList).toBeVisible();
    await expect(timelineList).toContainText('<script>window.__xssC27="summary"</script>');
    await expect(timelineList).toContainText('<img src=x onerror="window.__xssC27=\'dst\'">');

    const notesRegion = page.getByRole('region', { name: 'Analyst hypotheses and notes' });
    await expect(notesRegion).toContainText('Analyst hypothesis (non-evidence)');
    await expect(notesRegion).toContainText('Label: source_evidence');
    await expect(notesRegion).toContainText('<svg onload="window.__xssC27=\'noteAuthor\'">');
    expect(await page.evaluate(() => (window as unknown as { __xssC27?: unknown }).__xssC27)).toBeUndefined();

    // Negative UAT: epistemic promotion attempt rejected with promotion_forbidden
    await timelineInput.setInputFiles({
      name: 'promote.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({
        schema_version: '1',
        case_id: 'case-c27-sec',
        events: [],
        notes: [{
          hypothesis_id: 'hyp-promote',
          author: 'analyst-c27',
          rationale: 'illegal promotion',
          statement: 'must fail',
          claim_source_evidence: true,
        }],
      })),
    });
    await expect(page.getByRole('alert')).toContainText('Analyst notes cannot be promoted to observed source evidence.');

    // --- Surface 4: #roadmap (XSS in search input) ---
    await page.goto('/#roadmap');
    await page.getByLabel('Search tasks').fill('<script>window.__xssC27="roadmap"</script>');
    await expect(page.getByText('No matching tasks.')).toBeVisible();
    expect(await page.evaluate(() => (window as unknown as { __xssC27?: unknown }).__xssC27)).toBeUndefined();

    expect(dialogs).toEqual([]);
    expect(errors).toEqual([]);

    // Confirm fixture bytes remained unmodified
    const afterFixtureBytes = await readFile(fixturePath);
    expect(sha256(afterFixtureBytes)).toBe(sha256(beforeFixtureBytes));
  });
});
