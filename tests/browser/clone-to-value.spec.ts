import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { accessSync, constants, cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { startSupervisor } from '../../scripts/start-local.mjs';

const repoRoot = process.cwd();
const positiveFixture = JSON.parse(
  readFileSync(resolve(repoRoot, 'tests/fixtures/breachatlas/C30/positive/workflow-input.json'), 'utf8')
);
const negativeFixture = JSON.parse(
  readFileSync(resolve(repoRoot, 'tests/fixtures/breachatlas/C30/invalid/negative-cases.json'), 'utf8')
);
const expectedOutcomes = JSON.parse(
  readFileSync(resolve(repoRoot, 'tests/fixtures/breachatlas/C30/expected-output/acceptance-outcomes.json'), 'utf8')
);

function getFreePort(): Promise<number> {
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

function ensureVerifierBinary(tempDir: string): string {
  const builtPath = resolve(repoRoot, 'dist/bin/verify');
  try {
    accessSync(builtPath, constants.X_OK);
    return builtPath;
  } catch {
    const fallbackBin = join(tempDir, 'verify');
    execFileSync('go', ['build', '-o', fallbackBin, './cmd/verify'], { cwd: repoRoot, stdio: 'pipe' });
    return fallbackBin;
  }
}

test.describe('C30 clone-to-value full workflow, negative cases, offline verify, restart, and restore', () => {
  test('executes full 8-step reference workflow and negative UI/API cases through browser', async ({ page, request }) => {
    const readyRes = await request.get('/readyz');
    expect(readyRes.status()).toBe(200);
    const diagRes = await request.get('/api/v1/diagnostics');
    expect(diagRes.status()).toBe(200);
    const diagJson = await diagRes.json();
    expect(diagJson.status).toBe('ready');

    await page.goto('/#workflow');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('End-to-end DFIR case workflow.');

    // Responsive check on workflow route
    await page.setViewportSize({ width: 375, height: 812 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.setViewportSize({ width: 1280, height: 800 });

    const uniqueCase = `${positiveFixture.case_id}-ui`;
    await page.getByLabel('Case ID').fill(uniqueCase);
    await page.getByLabel('Evidence ID').fill(positiveFixture.evidence_id);
    await page.getByLabel('Artifact ID').fill(positiveFixture.artifact_id);
    await page.getByLabel('Bundle ID').fill(`${positiveFixture.bundle_id}-ui`);
    await page.getByLabel('Hold ID').fill(positiveFixture.hold_id);
    await page.getByLabel('Zone Hint').fill(positiveFixture.zone_hint);
    await page.getByLabel('Provider').fill(positiveFixture.provider);
    await page.getByLabel('Synthetic Evidence Payload').fill(positiveFixture.payload_jsonl);

    const expectedSHA = createHash('sha256').update(Buffer.from(positiveFixture.payload_jsonl, 'utf8')).digest('hex');

    // Steps 1-2: Upload & Seal
    await page.getByRole('button', { name: '1-2. Upload & Seal' }).click();
    await expect(page.getByRole('status')).toContainText(`Sealed ${positiveFixture.evidence_id}`);
    await expect(page.getByRole('status')).toContainText(expectedSHA);
    await expect(page.getByTestId('persisted-state')).toContainText('Verified: true');

    // Step 3: Add Custody
    await page.getByRole('button', { name: '3. Add Custody' }).click();
    await expect(page.getByRole('status')).toContainText('Custody chain updated: seq 2');
    await expect(page.getByTestId('persisted-state')).toContainText('Custody valid: true (2 events)');

    // Step 4: Parse Bounded Timeline (raw timestamp + timezone offset + confidence preserved)
    await page.getByRole('button', { name: '4. Parse Bounded Timeline' }).click();
    await expect(page.getByRole('status')).toContainText(`Indexed ${expectedOutcomes.timeline_count} timeline entries; raw_timestamps_preserved=true`);
    await expect(page.getByTestId('persisted-state')).toContainText(expectedOutcomes.preserved_raw_timestamp);
    await expect(page.getByTestId('persisted-state')).toContainText(expectedOutcomes.preserved_timezone_offset);
    await expect(page.getByTestId('persisted-state')).toContainText(`conf=${expectedOutcomes.preserved_confidence}`);

    // Step 5: Place Legal Hold + Negative Delete & Expire Rejection
    await page.getByRole('button', { name: '5a. Place Legal Hold' }).click();
    await expect(page.getByRole('status')).toContainText(`Legal hold active: ${positiveFixture.hold_id}`);
    await expect(page.getByTestId('persisted-state')).toContainText('Active holds: 1');

    await page.getByRole('button', { name: '5b. Attempt Delete (Expect Reject)' }).click();
    await expect(page.getByRole('alert')).toContainText('hold_active');
    await expect(page.getByRole('alert')).toContainText('sealed evidence intact');

    await page.getByRole('button', { name: '5c. Attempt Expire (Expect Reject)' }).click();
    await expect(page.getByRole('alert')).toContainText('hold_active');
    await expect(page.getByRole('alert')).toContainText('sealed evidence intact');

    // Step 6: Export Signed Bundle
    await page.getByRole('button', { name: '6. Export Signed Bundle' }).click();
    await expect(page.getByRole('status')).toContainText(`Exported signed bundle ${positiveFixture.bundle_id}-ui`);
    await expect(page.getByTestId('export-summary')).toContainText('Digest:');

    // Step 7: Authentic Verification + Tampered Byte Failure
    await page.getByRole('button', { name: '7a. Verify Authentic Bundle' }).click();
    await expect(page.getByTestId('verify-summary')).toContainText('verified:MATCH:trusted_signed');

    await page.getByRole('button', { name: '7b. Simulate Tampered Byte Verification' }).click();
    await expect(page.getByRole('alert')).toContainText('verification_failed');

    // Step 8: Recover Consistency & Restore Bundle
    await page.getByRole('button', { name: '8a. Recover Consistency' }).click();
    await expect(page.getByTestId('recover-summary')).toContainText(`rebuilt:${expectedOutcomes.timeline_count}:sealed_modified=false`);

    await page.getByRole('button', { name: '8b. Restore Bundle' }).click();
    await expect(page.getByTestId('recover-summary')).toContainText(`restored:1:entries=${expectedOutcomes.timeline_count}:sealed_modified=false`);

    // Explicit Negative API cases (empty upload, malformed JSON, unavailable provider)
    const emptyRes = await request.post('/api/v1/workflow/upload-seal', {
      data: {
        schema_version: '1',
        case_id: negativeFixture.empty_upload.case_id,
        evidence_id: negativeFixture.empty_upload.evidence_id,
        payload: negativeFixture.empty_upload.payload,
      },
    });
    expect(emptyRes.status()).toBe(400);
    expect((await emptyRes.json()).error.code).toBe(negativeFixture.empty_upload.expected_code);

    const badJsonRes = await request.post('/api/v1/workflow/upload-seal', {
      headers: { 'Content-Type': 'application/json' },
      data: negativeFixture.malformed_json.raw,
    });
    expect(badJsonRes.status()).toBe(negativeFixture.malformed_json.expected_status);
    expect((await badJsonRes.json()).error.code).toBe(negativeFixture.malformed_json.expected_code);

    const unavailProvRes = await request.get(
      `/api/v1/workflow/state?case_id=${encodeURIComponent(uniqueCase)}&provider=${encodeURIComponent(negativeFixture.unavailable_provider.provider)}`
    );
    expect(unavailProvRes.status()).toBe(negativeFixture.unavailable_provider.expected_status);
    expect((await unavailProvRes.json()).error.code).toBe(negativeFixture.unavailable_provider.expected_code);
  });

  test('proves offline verification without server, restart persistence, index rebuild, and bundle restore', async ({ page }) => {
    const storageDir = mkdtempSync(join(tmpdir(), 'breachatlas-c30-persist-'));
    const verifierWorkDir = mkdtempSync(join(tmpdir(), 'breachatlas-c30-verify-'));
    let sup1: Awaited<ReturnType<typeof startSupervisor>> | undefined;
    let sup2: Awaited<ReturnType<typeof startSupervisor>> | undefined;

    try {
      const webPort1 = await getFreePort();
      const engPort1 = await getFreePort();
      sup1 = await startSupervisor({
        host: '127.0.0.1',
        port: webPort1,
        enginePort: engPort1,
        storageDir,
        engineStdio: 'ignore',
      });
      const base1 = `http://127.0.0.1:${webPort1}`;

      await page.goto(`${base1}/#workflow`);
      await page.getByLabel('Case ID').fill(positiveFixture.case_id);
      await page.getByLabel('Bundle ID').fill(positiveFixture.bundle_id);
      await page.getByLabel('Synthetic Evidence Payload').fill(positiveFixture.payload_jsonl);

      await page.getByRole('button', { name: '1-2. Upload & Seal' }).click();
      await expect(page.getByRole('status')).toContainText(`Sealed ${positiveFixture.evidence_id}`);
      await page.getByRole('button', { name: '3. Add Custody' }).click();
      await expect(page.getByRole('status')).toContainText('Custody chain updated');
      await page.getByRole('button', { name: '4. Parse Bounded Timeline' }).click();
      await expect(page.getByRole('status')).toContainText(`Indexed ${expectedOutcomes.timeline_count} timeline entries`);
      await page.getByRole('button', { name: '5a. Place Legal Hold' }).click();
      await expect(page.getByRole('status')).toContainText('Legal hold active');

      // Capture exact export metadata before shutdown
      const [exportResponse] = await Promise.all([
        page.waitForResponse(res => res.url().includes('/api/v1/workflow/export') && res.status() === 200),
        page.getByRole('button', { name: '6. Export Signed Bundle' }).click(),
      ]);
      const exportData = await exportResponse.json();
      expect(exportData.signed).toBe(true);
      expect(typeof exportData.bundle_dir).toBe('string');
      expect(typeof exportData.public_key).toBe('string');

      // Stop first supervised process completely
      await sup1.shutdown();
      sup1 = undefined;

      // Step 7 offline verification with NO running server
      const verifyBin = ensureVerifierBinary(verifierWorkDir);
      const offRaw = execFileSync(
        verifyBin,
        ['-bundle', exportData.bundle_dir, '-trusted-key', exportData.public_key, '-require-signature', '-json'],
        { cwd: verifierWorkDir, encoding: 'utf8' }
      );
      const offResult = JSON.parse(offRaw);
      expect(offResult.verified).toBe(true);
      expect(offResult.evidence_integrity).toBe('MATCH');
      expect(offResult.custody_root_integrity).toBe('MATCH');
      expect(offResult.signature_status).toBe('trusted_signed');
      expect(offResult.raw_timestamps_preserved).toBe(true);
      expect(offResult.requires_server).toBe(false);

      // Offline negative check: untrusted key must fail non-zero
      const wrongKey = '00'.repeat(32);
      expect(() =>
        execFileSync(verifyBin, ['-bundle', exportData.bundle_dir, '-trusted-key', wrongKey, '-require-signature', '-json'], {
          cwd: verifierWorkDir,
          stdio: 'pipe',
        })
      ).toThrow();

      // Offline negative check: modified byte in copied bundle fails non-zero (sealed original untouched)
      const tamperedCopy = join(verifierWorkDir, 'tampered-bundle');
      cpSync(exportData.bundle_dir, tamperedCopy, { recursive: true });
      const blobCopy = join(tamperedCopy, 'evidence', positiveFixture.evidence_id, 'blob.dat');
      const blobBuf = Buffer.from(readFileSync(blobCopy));
      blobBuf[0] ^= 0xff;
      writeFileSync(blobCopy, blobBuf);
      expect(() =>
        execFileSync(verifyBin, ['-bundle', tamperedCopy, '-trusted-key', exportData.public_key, '-require-signature', '-json'], {
          cwd: verifierWorkDir,
          stdio: 'pipe',
        })
      ).toThrow();

      // Drop derived timeline index while stopped, then restart second supervised instance
      rmSync(join(storageDir, 'workflow-data', 'timeline-index', 'cases', `${positiveFixture.case_id}.json`), {
        force: true,
      });

      const webPort2 = await getFreePort();
      const engPort2 = await getFreePort();
      sup2 = await startSupervisor({
        host: '127.0.0.1',
        port: webPort2,
        enginePort: engPort2,
        storageDir,
        engineStdio: 'ignore',
      });
      const base2 = `http://127.0.0.1:${webPort2}`;

      await page.goto(`${base2}/#workflow`);
      await expect(page.getByTestId('persisted-state')).toContainText(positiveFixture.evidence_id);
      await expect(page.getByTestId('persisted-state')).toContainText('Custody valid: true');
      await expect(page.getByTestId('persisted-state')).toContainText('Active holds: 1');

      // Rebuild consistency from immutable sealed bytes & custody chain after restart
      await page.getByRole('button', { name: '8a. Recover Consistency' }).click();
      await expect(page.getByTestId('recover-summary')).toContainText(`rebuilt:${expectedOutcomes.timeline_count}:sealed_modified=false`);
      await expect(page.getByTestId('persisted-state')).toContainText(expectedOutcomes.preserved_raw_timestamp);

      // Legal hold still blocks delete after restart
      await page.getByRole('button', { name: '5b. Attempt Delete (Expect Reject)' }).click();
      await expect(page.getByRole('alert')).toContainText('hold_active');

      // Restore bundle after restart
      await page.getByRole('button', { name: '8b. Restore Bundle' }).click();
      await expect(page.getByTestId('recover-summary')).toContainText(`restored:1:entries=${expectedOutcomes.timeline_count}:sealed_modified=false`);
    } finally {
      if (sup1) await sup1.shutdown();
      if (sup2) await sup2.shutdown();
      rmSync(storageDir, { recursive: true, force: true });
      rmSync(verifierWorkDir, { recursive: true, force: true });
    }
  });
});
