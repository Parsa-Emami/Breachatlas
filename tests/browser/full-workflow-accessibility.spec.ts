import { test, expect, type Locator } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const repoRoot = process.cwd();
const positiveFixture = JSON.parse(
  readFileSync(resolve(repoRoot, 'tests/fixtures/breachatlas/C33/positive/workflow-and-n-minus-1.json'), 'utf8')
);
const negativeFixture = JSON.parse(
  readFileSync(resolve(repoRoot, 'tests/fixtures/breachatlas/C33/invalid/negative-cases.json'), 'utf8')
);
const expectedOutcomes = JSON.parse(
  readFileSync(resolve(repoRoot, 'tests/fixtures/breachatlas/C33/expected/expected-ux-outcomes.json'), 'utf8')
);

async function activateByKeyboard(locator: Locator, page: import('@playwright/test').Page) {
  await locator.focus();
  await expect(locator).toBeFocused();
  await page.keyboard.press('Enter');
}

async function assertNoHorizontalOverflow(page: import('@playwright/test').Page) {
  const noOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth <= window.innerWidth
  );
  expect(noOverflow).toBe(true);
}

test.describe('C33 keyboard, mobile/desktop 360px/1440px, table equivalents, and failure-handling', () => {
  test('completes full 8-step reference workflow with keyboard and accessible table equivalents at 360px and 1440px', async ({ page }) => {
    const mobileViewport = expectedOutcomes.viewports.find((v: { name: string }) => v.name === 'mobile');
    const desktopViewport = expectedOutcomes.viewports.find((v: { name: string }) => v.name === 'desktop');

    await page.setViewportSize({ width: mobileViewport.width, height: mobileViewport.height });
    await page.goto('/#workflow');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('End-to-end DFIR case workflow.');

    // Keyboard skip-to-content check
    await page.keyboard.press('Tab');
    const skipLink = page.getByRole('link', { name: 'Skip to content' });
    await expect(skipLink).toBeFocused();
    await assertNoHorizontalOverflow(page);

    const uniqueCase = `${positiveFixture.case_id}-kb`;
    const uniqueBundle = `${positiveFixture.bundle_id}-kb`;

    await page.getByLabel('Case ID').fill(uniqueCase);
    await page.getByLabel('Evidence ID').fill(positiveFixture.evidence_id);
    await page.getByLabel('Artifact ID').fill(positiveFixture.artifact_id);
    await page.getByLabel('Bundle ID').fill(uniqueBundle);
    await page.getByLabel('Hold ID').fill(positiveFixture.hold_id);
    await page.getByLabel('Zone Hint').fill(positiveFixture.zone_hint);
    await page.getByLabel('Provider').fill(positiveFixture.provider);
    await page.getByLabel('Synthetic Evidence Payload').fill(positiveFixture.payload_jsonl);

    // Steps 1-2 via keyboard on 360px mobile
    await activateByKeyboard(page.getByRole('button', { name: '1-2. Upload & Seal' }), page);
    await expect(page.getByRole('status')).toContainText(`Sealed ${positiveFixture.evidence_id}`);

    const evidenceTable = page.getByRole('table', { name: 'Sealed Evidence Table' });
    await expect(evidenceTable).toBeVisible();
    await expect(evidenceTable.getByRole('columnheader', { name: 'Evidence ID' })).toBeVisible();
    await expect(evidenceTable.getByRole('rowheader', { name: positiveFixture.evidence_id })).toBeVisible();
    await assertNoHorizontalOverflow(page);

    // Step 3 via keyboard on 360px mobile
    await activateByKeyboard(page.getByRole('button', { name: '3. Add Custody' }), page);
    await expect(page.getByRole('status')).toContainText('Custody chain updated: seq 2');

    // Step 4 via keyboard on 360px mobile and verify Timeline Table equivalent
    await activateByKeyboard(page.getByRole('button', { name: '4. Parse Bounded Timeline' }), page);
    await expect(page.getByRole('status')).toContainText(`Indexed ${expectedOutcomes.timeline_count} timeline entries`);

    const timelineTable = page.getByRole('table', { name: 'Workflow Timeline Table' });
    await expect(timelineTable).toBeVisible();
    await expect(timelineTable.getByRole('columnheader', { name: 'Raw Timestamp' })).toBeVisible();
    await expect(timelineTable).toContainText(expectedOutcomes.preserved_raw_timestamp);
    await expect(timelineTable).toContainText(expectedOutcomes.preserved_timezone_offset);
    await expect(timelineTable).toContainText(String(expectedOutcomes.preserved_confidence));
    await assertNoHorizontalOverflow(page);

    // Switch to 1440px desktop viewport for Steps 5-8 via keyboard
    await page.setViewportSize({ width: desktopViewport.width, height: desktopViewport.height });
    await assertNoHorizontalOverflow(page);

    await activateByKeyboard(page.getByRole('button', { name: '5a. Place Legal Hold' }), page);
    await expect(page.getByRole('status')).toContainText(`Legal hold active: ${positiveFixture.hold_id}`);

    await activateByKeyboard(page.getByRole('button', { name: '5b. Attempt Delete (Expect Reject)' }), page);
    await expect(page.getByRole('alert')).toContainText('hold_active');
    await expect(page.getByRole('alert')).toContainText('sealed evidence intact');

    await activateByKeyboard(page.getByRole('button', { name: '5c. Attempt Expire (Expect Reject)' }), page);
    await expect(page.getByRole('alert')).toContainText('hold_active');

    await activateByKeyboard(page.getByRole('button', { name: '6. Export Signed Bundle' }), page);
    await expect(page.getByRole('status')).toContainText(`Exported signed bundle ${uniqueBundle}`);

    await activateByKeyboard(page.getByRole('button', { name: '7a. Verify Authentic Bundle' }), page);
    await expect(page.getByTestId('verify-summary')).toContainText('verified:MATCH:trusted_signed');

    await activateByKeyboard(page.getByRole('button', { name: '7b. Simulate Tampered Byte Verification' }), page);
    await expect(page.getByRole('alert')).toContainText('verification_failed');

    await activateByKeyboard(page.getByRole('button', { name: '8a. Recover Consistency' }), page);
    await expect(page.getByTestId('recover-summary')).toContainText(
      `rebuilt:${expectedOutcomes.timeline_count}:sealed_modified=false`
    );

    await activateByKeyboard(page.getByRole('button', { name: '8b. Restore Bundle' }), page);
    await expect(page.getByTestId('recover-summary')).toContainText(
      `restored:1:entries=${expectedOutcomes.timeline_count}:sealed_modified=false`
    );
    await assertNoHorizontalOverflow(page);
  });

  test('handles empty, invalid, interrupted request, and provider-outage failures cleanly in UI and API', async ({ page, request }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    await page.goto('/#workflow');

    // 1. Empty payload via UI
    await page.getByLabel('Case ID').fill(negativeFixture.empty_upload.case_id);
    await page.getByLabel('Evidence ID').fill(negativeFixture.empty_upload.evidence_id);
    await page.getByLabel('Synthetic Evidence Payload').fill('');
    await activateByKeyboard(page.getByRole('button', { name: '1-2. Upload & Seal' }), page);
    await expect(page.getByRole('alert')).toContainText(negativeFixture.empty_upload.expected_code);

    // 2. Invalid identifier via UI
    await page.getByLabel('Case ID').fill(negativeFixture.invalid_case_id.case_id);
    await page.getByLabel('Synthetic Evidence Payload').fill(negativeFixture.invalid_case_id.payload);
    await activateByKeyboard(page.getByRole('button', { name: '1-2. Upload & Seal' }), page);
    await expect(page.getByRole('alert')).toContainText(negativeFixture.invalid_case_id.expected_code);

    // 3. Provider outage via UI
    await page.getByLabel('Case ID').fill(`${positiveFixture.case_id}-outage`);
    await page.getByLabel('Provider').fill(negativeFixture.unavailable_provider.provider);
    await activateByKeyboard(page.getByRole('button', { name: 'Refresh Persisted State' }), page);
    await expect(page.getByRole('alert')).toContainText(negativeFixture.unavailable_provider.expected_code);

    // 4. Interrupted network request recovery in UI (seal succeeds, custody aborted once, then retried cleanly)
    await page.getByLabel('Provider').fill('local');
    await page.getByLabel('Evidence ID').fill('ev-c33-interrupt-01');
    await page.getByLabel('Synthetic Evidence Payload').fill(positiveFixture.payload_jsonl);
    await activateByKeyboard(page.getByRole('button', { name: '1-2. Upload & Seal' }), page);
    await expect(page.getByRole('status')).toContainText('Sealed ev-c33-interrupt-01');

    await page.route('**/api/v1/workflow/custody', async route => {
      await route.abort('failed');
    });
    await activateByKeyboard(page.getByRole('button', { name: '3. Add Custody' }), page);
    await expect(page.getByRole('alert')).toContainText('Local engine unavailable during workflow request.');
    await page.unroute('**/api/v1/workflow/custody');

    // Retry custody after transient interruption and verify sealed evidence remains intact
    await activateByKeyboard(page.getByRole('button', { name: '3. Add Custody' }), page);
    await expect(page.getByRole('status')).toContainText('Custody chain updated: seq 2');
    await expect(page.getByRole('table', { name: 'Sealed Evidence Table' })).toContainText('true (2 events)');

    // 5. Malformed JSON API check
    const badJsonRes = await request.post('/api/v1/workflow/upload-seal', {
      headers: { 'Content-Type': 'application/json' },
      data: negativeFixture.malformed_json.raw,
    });
    expect(badJsonRes.status()).toBe(negativeFixture.malformed_json.expected_status);
    expect((await badJsonRes.json()).error.code).toBe(negativeFixture.malformed_json.expected_code);
  });
});
