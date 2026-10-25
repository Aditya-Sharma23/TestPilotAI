const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  testMatch: '**/*.spec.cjs',
  fullyParallel: true,
  workers: 4,
  reporter: [['list'], ['./tests/dashboard-reporter.cjs']],
  retries: process.env.CI ? 1 : 0,
  use: { baseURL: process.env.TESTPILOT_BASE_URL || 'http://127.0.0.1:8000', trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop-chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile-chromium', use: { ...devices['Pixel 7'] } },
  ],
  outputDir: "./playwright-artifacts",
  webServer: process.env.TESTPILOT_BASE_URL ? undefined : {
    command: process.platform === 'win32' ? '.\\.venv\\Scripts\\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000' : '.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000',
    url: 'http://127.0.0.1:8000/',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});



