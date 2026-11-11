import { test, expect } from '@playwright/test';

test.describe('C21 case evidence integrity and custody UI', () => {
  test('shows failed verification, incomplete seal, custody chain, keyboard table action, and keeps script sentinels inert', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));

    await page.goto('/#evidence');
    await expect(page.getByRole('heading', { level: 2, name: 'Inspect case evidence integrity' })).toBeVisible();
    await expect(page.getByRole('status')).toContainText('Empty: load a case evidence JSON snapshot');

    // Upload mixed integrity bundle verified by live loopback Go engine.
    await page.getByLabel('Choose evidence snapshot JSON').setInputFiles(
      'tests/fixtures/breachatlas/C21/positive/case-evidence-mixed-integrity.json'
    );

    const table = page.getByRole('table', { name: 'Case evidence integrity and custody' });
    await expect(table).toBeVisible();

    // Failed verification and incomplete seal remain visibly explicit with non-color text.
    await expect(page.getByRole('alert')).toContainText('Verification failed on 1 item(s)');
    await expect(page.getByRole('status')).toContainText('Incomplete seal on 1 item(s)');
    await expect(table).toContainText('Incomplete seal');
    await expect(table).toContainText('Failed verification');
    await expect(table).toContainText('Verified');

    // XSS sentinels stay strictly escaped text and never execute scripts.
    await expect(table).toContainText('<script>window.__xssSentinel=true</script>');
    expect(await page.evaluate(() => (window as unknown as { __xssSentinel?: boolean }).__xssSentinel)).toBeUndefined();

    // Keyboard/table row action selects the failed item and renders its failure reason.
    const inspectFailedBtn = page.getByRole('button', { name: 'Inspect ev-failed-03' });
    await inspectFailedBtn.focus();
    await page.keyboard.press('Enter');

    const detailPanel = page.getByRole('region', { name: 'Selected evidence details' });
    await expect(detailPanel).toContainText('ev-failed-03');
    await expect(detailPanel).toContainText('Sealed SHA-256 verification failed');

    // Inspect ev-verified-01 to verify escaped custody events & legal hold string rendering.
    await page.getByRole('button', { name: 'Inspect ev-verified-01' }).click();
    await expect(detailPanel).toContainText('Custody Chain (1)');
    await expect(detailPanel).toContainText('Custody verified <img src=x onerror="window.__xssSentinel=true">');
    await expect(detailPanel).toContainText('Litigation hold <b>active</b>');
    expect(await page.evaluate(() => (window as unknown as { __xssSentinel?: boolean }).__xssSentinel)).toBeUndefined();
    expect(errors).toEqual([]);
  });

  test('explicit empty, invalid, interrupted, and unavailable-provider states work at 360px without horizontal overflow', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));

    await page.setViewportSize({ width: 360, height: 780 });
    await page.goto('/#evidence');

    const assertNoOverflow = async () => {
      const fits = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
      expect(fits).toBe(true);
    };

    // 1. Initial empty state at 360px
    await expect(page.getByRole('status')).toContainText('Empty:');
    await assertNoOverflow();

    // 2. Empty case snapshot (0 items) at 360px
    const fileInput = page.getByLabel('Choose evidence snapshot JSON');
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C21/positive/empty-case-evidence.json');
    await expect(page.getByRole('status')).toContainText('0 evidence items recorded');
    await assertNoOverflow();

    // 3. Invalid snapshot (unsupported version) from Go engine at 360px
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C21/invalid/unsupported-version-bundle.json');
    await expect(page.getByRole('alert')).toContainText('Invalid input:');
    await expect(page.getByRole('alert')).toContainText('Unsupported evidence snapshot schema version');
    await assertNoOverflow();

    // 4. Unavailable provider from Go engine at 360px
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C21/invalid/unavailable-provider-bundle.json');
    await expect(page.getByRole('alert')).toContainText('Unavailable engine/provider:');
    await expect(page.getByRole('alert')).toContainText('Requested evidence provider is unavailable');
    await assertNoOverflow();

    // 5. Interrupted request state via delayed engine response + keyboard cancel at 360px
    let releaseDelayedRoute: (() => void) | undefined;
    await page.route('**/api/v1/evidence-integrity/inspect', async route => {
      await new Promise<void>(resolve => {
        releaseDelayedRoute = resolve;
      });
      await route.abort().catch(() => undefined);
    });
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C21/positive/case-evidence-mixed-integrity.json');
    const cancelBtn = page.getByRole('button', { name: 'Cancel inspection' });
    await expect(cancelBtn).toBeVisible();
    await cancelBtn.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('alert')).toContainText('Inspection interrupted');
    await assertNoOverflow();

    await page.unrouteAll({ behavior: 'ignoreErrors' });
    releaseDelayedRoute?.();

    // 6. Mixed integrity table at 360px fits stacked mobile layout without horizontal scroll
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C21/positive/case-evidence-mixed-integrity.json');
    await expect(page.getByRole('table', { name: 'Case evidence integrity and custody' })).toBeVisible();
    await assertNoOverflow();

    expect(errors).toEqual([]);
  });
});
