import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/browser',
  timeout: 30000,
  use: {
    baseURL: 'http://127.0.0.1:4173', browserName: 'chromium', headless: true,
    launchOptions: process.env.WEB_TEST_CHROMIUM ? { executablePath: process.env.WEB_TEST_CHROMIUM, args: ['--no-sandbox'] } : {},
  },
  webServer: { command: 'npm start', url: 'http://127.0.0.1:4173/readyz', reuseExistingServer: false, timeout: 15000 },
  reporter: 'list',
});
