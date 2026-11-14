import { defineConfig } from '@playwright/test';
const webPort = Number(process.env.BREACHATLAS_WEB_PORT || '4173');
const enginePort = Number(process.env.BREACHATLAS_ENGINE_PORT || '8080');
const baseURL = `http://127.0.0.1:${webPort}`;
const startCmd = process.env.BREACHATLAS_WEB_PORT || process.env.BREACHATLAS_ENGINE_PORT
  ? `node scripts/start-local.mjs --port ${webPort} --enginePort ${enginePort}`
  : 'npm start';
export default defineConfig({
  testDir: '.',
  testMatch: ['tests/browser/**/*.spec.ts', 'apps/web/tests/**/*.spec.ts'],
  timeout: 30000,
  use: {
    baseURL, browserName: 'chromium', headless: true,
    launchOptions: process.env.WEB_TEST_CHROMIUM ? { executablePath: process.env.WEB_TEST_CHROMIUM, args: ['--no-sandbox'] } : {},
  },
  webServer: { command: startCmd, url: `${baseURL}/readyz`, reuseExistingServer: false, timeout: 15000 },
  reporter: 'list',
});
