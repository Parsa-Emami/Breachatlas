import { test, expect } from '@playwright/test';

test.describe('C22 timezone-aware timeline and analyst notes UI', () => {
  test('renders raw timestamp, normalized time, unresolved DST/zones, confidence, table alternative, separated notes, keyboard selection, and inert XSS sentinels', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));

    await page.goto('/#timeline');
    await expect(page.getByRole('heading', { level: 2, name: 'Inspect timeline normalization & hypotheses' })).toBeVisible();
    await expect(page.getByRole('status')).toContainText('Empty: load a timeline and notes JSON snapshot');

    await page.getByLabel('Choose timeline snapshot JSON').setInputFiles(
      'tests/fixtures/breachatlas/C22/positive/mixed-timezone-timeline-and-notes.json'
    );

    const timelineList = page.getByRole('list', { name: 'Observed timeline events' });
    await expect(timelineList).toBeVisible();

    // Preserved raw timestamps, resolved UTC, unresolved DST/zone status, and confidence scores.
    await expect(timelineList).toContainText('2026-11-01T04:00:00-05:00');
    await expect(timelineList).toContainText('2026-11-01T09:00:00Z');
    await expect(timelineList).toContainText('2026-11-01 01:30:00');
    await expect(timelineList).toContainText('Unresolved (DST ambiguous)');
    await expect(timelineList).toContainText('0.91');

    // Script sentinel in event summary renders escaped as text only.
    await expect(timelineList).toContainText('<script>window.__xssSentinel=true</script>');
    expect(await page.evaluate(() => (window as unknown as { __xssSentinel?: boolean }).__xssSentinel)).toBeUndefined();

    // Separated Analyst Hypotheses & Notes section keeps author & rationale visible and never promotes UI label.
    const notesRegion = page.getByRole('region', { name: 'Analyst hypotheses and notes' });
    await expect(notesRegion).toContainText('Analyst hypothesis (non-evidence)');
    await expect(notesRegion).toContainText('Ambiguous 01:30 local wall clock precedes zoneless exec.');
    await expect(notesRegion).toContainText('<img src=x onerror="window.__xssSentinel=true">');
    await expect(notesRegion).toContainText('Label: source_evidence');
    expect(await page.evaluate(() => (window as unknown as { __xssSentinel?: boolean }).__xssSentinel)).toBeUndefined();

    // Switch via keyboard to accessible Table alternative and inspect DST event details.
    const tableBtn = page.getByRole('button', { name: 'Table view' });
    await tableBtn.focus();
    await page.keyboard.press('Enter');

    const table = page.getByRole('table', { name: 'Observed timeline table' });
    await expect(table).toBeVisible();
    await expect(table).toContainText('2026-11-01 01:30:00');
    await expect(table).toContainText('2026-11-01T09:00:00Z');

    const rowBtn = page.getByRole('button', { name: 'Inspect row 10' });
    await rowBtn.focus();
    await page.keyboard.press('Enter');

    const detailPanel = page.getByRole('region', { name: 'Selected timeline event' });
    await expect(detailPanel).toContainText('2026-11-01T05:30:00Z , 2026-11-01T06:30:00Z');
    await expect(detailPanel).toContainText('Raw confidence: 0.91');
    expect(errors).toEqual([]);
  });

  test('explicit empty, invalid, interrupted, and unavailable-provider states work at 360px without horizontal overflow', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));

    await page.setViewportSize({ width: 360, height: 780 });
    await page.goto('/#timeline');

    const assertNoOverflow = async () => {
      const fits = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
      expect(fits).toBe(true);
    };

    // 1. Initial empty state
    await expect(page.getByRole('status')).toContainText('Empty:');
    await assertNoOverflow();

    // 2. Empty snapshot
    const fileInput = page.getByLabel('Choose timeline snapshot JSON');
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C22/positive/empty-timeline.json');
    await expect(page.getByRole('status')).toContainText('0 observed events and 0 analyst notes');
    await assertNoOverflow();

    // 3. Invalid snapshot (unsupported version)
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C22/invalid/unsupported-version-timeline.json');
    await expect(page.getByRole('alert')).toContainText('Invalid input:');
    await expect(page.getByRole('alert')).toContainText('Unsupported timeline snapshot schema version');
    await assertNoOverflow();

    // 4. Unavailable provider
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C22/invalid/unavailable-provider-timeline.json');
    await expect(page.getByRole('alert')).toContainText('Unavailable engine/provider:');
    await expect(page.getByRole('alert')).toContainText('Requested timeline provider is unavailable');
    await assertNoOverflow();

    // 5. Interrupted request via delayed route + keyboard cancel
    let releaseDelayedRoute: (() => void) | undefined;
    await page.route('**/api/v1/timeline/inspect', async route => {
      await new Promise<void>(resolve => {
        releaseDelayedRoute = resolve;
      });
      await route.abort().catch(() => undefined);
    });
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C22/positive/mixed-timezone-timeline-and-notes.json');
    const cancelBtn = page.getByRole('button', { name: 'Cancel inspection' });
    await expect(cancelBtn).toBeVisible();
    await cancelBtn.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('alert')).toContainText('Inspection interrupted');
    await assertNoOverflow();

    await page.unrouteAll({ behavior: 'ignoreErrors' });
    releaseDelayedRoute?.();

    // 6. Table alternative fits cleanly at 360px
    await fileInput.setInputFiles('tests/fixtures/breachatlas/C22/positive/mixed-timezone-timeline-and-notes.json');
    await page.getByRole('button', { name: 'Table view' }).click();
    await expect(page.getByRole('table', { name: 'Observed timeline table' })).toBeVisible();
    await assertNoOverflow();

    expect(errors).toEqual([]);
  });
});
