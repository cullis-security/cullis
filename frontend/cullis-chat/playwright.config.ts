import { defineConfig, devices } from '@playwright/test';

const PORT = 4321;
const MOCK_PORT = 7777;

/**
 * Two webServers: the mock Ambassador on :7777, the Astro dev server
 * on :4321. Playwright reuses them between specs (no restart).
 *
 * The dev server is fed `CULLIS_LOCAL_TOKEN=test-token` so the
 * /api/session/init endpoint can mint a cookie even when the test
 * environment doesn't have a real Connector profile on disk.
 */
export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  timeout: 30_000,

  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: [
    {
      command: 'node mock/ambassador.mjs',
      port: MOCK_PORT,
      reuseExistingServer: !process.env.CI,
      timeout: 10_000,
      stdout: 'pipe',
      stderr: 'pipe',
    },
    {
      command: 'npm run dev',
      port: PORT,
      reuseExistingServer: !process.env.CI,
      timeout: 30_000,
      env: {
        CULLIS_LOCAL_TOKEN: 'test-token',
        CULLIS_AMBASSADOR_URL: `http://127.0.0.1:${MOCK_PORT}`,
        // The audit panel is dev-only (production hides it). Tests
        // exercise it, so enable it explicitly here.
        PUBLIC_DEV_AUDIT_PANEL: '1',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    },
  ],
});
