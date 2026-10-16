import { test, expect } from '@playwright/test';
test('workspace, local preview, navigation and roadmap filters work', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  const uploads: string[] = [];
  page.on('request', request => { if (request.method() !== 'GET') uploads.push(request.url()); });
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.getByLabel('Choose JSON file').setInputFiles({ name: 'example.json', mimeType: 'application/json', buffer: Buffer.from('{"review":"synthetic"}') });
  await expect(page.getByRole('status')).toContainText('example.json');
  await expect(page.getByRole('status')).toContainText('1 top-level fields');
  await page.getByRole('button', { name: 'Clear preview' }).click();
  await expect(page.getByRole('status')).toHaveCount(0);
  await page.getByLabel('Choose JSON file').setInputFiles({ name: 'bad.json', mimeType: 'application/json', buffer: Buffer.from('{') });
  await expect(page.getByRole('alert')).toContainText('valid JSON');
  await page.getByRole('link', { name: 'Roadmap', exact: true }).click();
  await page.getByLabel('Search tasks').fill('C40');
  await expect(page.locator('.tasks > li')).toHaveCount(1);
  await expect(page.locator('.tasks')).toContainText('C40');
  await page.setViewportSize({ width: 375, height: 812 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(uploads).toEqual([]); expect(errors).toEqual([]);
});
test('configuration failure blocks workspace startup', async ({ page }) => {
  await page.route('**/runtime-config.json', route => route.fulfill({ status: 200, contentType: 'application/json', body: '{"engineEnabled":true}' }));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Workspace unavailable' })).toBeVisible();
  await expect(page.getByLabel('Choose JSON file')).toHaveCount(0);
});
