import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  timeout: 60_000,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    headless: true,
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        browserName: 'chromium',
        launchOptions: process.env.ECP_BROWSER_PATH
          ? { executablePath: process.env.ECP_BROWSER_PATH }
          : {},
      },
    },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
  webServer: {
    command: 'node scripts/serve.mjs',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false,
  },
});
