const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

const scanResult = {
  id: 123,
  created_at: '2026-10-25T00:00:00+00:00',
  url: 'https://api.example.com/items',
  status: 'PASSED',
  summary: '8 target check groups are reported. HTTPX passed 4/4; target accessibility passed.',
  ai_summary: { source: 'Gemma AI', risk_level: 'LOW', executive_summary: 'The submitted website responded successfully; the selected automated checks found no immediate issues.', http_summary: 'HTTPX passed 4 of 4 checks with HTTP 200.', key_findings: [], priority_actions: ['Continue with manual review.'], limitations: [], check_results: [{ name: 'Status 200', status: 'PASSED', evidence: 'HTTP 200' }], contract_result: { status: 'PASSED', summary: 'GET-only API contract checks completed.' } },
  ai_summary_source: 'Gemma AI',
  httpx: {
    status_code: 200, content_type: 'application/json', header_count: 8, elapsed_seconds: 0.1,
    checks: [
      { id: 'status_200', status: 'PASSED', actual: 'HTTP 200' },
      { id: 'response_header_present', status: 'PASSED', actual: '8 headers' },
      { id: 'response_time_under_5s', status: 'PASSED', actual: '0.1 seconds' },
      { id: 'body_not_empty', status: 'PASSED', actual: 'Body contains text' }
    ]
  },
  security_checks: [{ title: 'Content-Security-Policy', status: 'PASSED', evidence: 'Header present' }],
  security: [],
  accessibility: {
    engine: 'Playwright + axe-core', status: 'COMPLETED', checks_passed: 42, incomplete: 0, violations: [],
    browser_checks: [{ id: 'target_page_loads', title: 'Playwright page response', status: 'PASSED', evidence: 'HTTP 200' }]
  },
  contract: { engine: 'Schemathesis', status: 'PASSED', summary: 'GET-only API contract checks completed.', schema_url: 'https://api.example.com/openapi.json', operations_tested: 2 },
  test_groups: [
    { id: 'status_200', title: 'Status 200', status: 'PASSED', evidence: 'HTTP 200' },
    { id: 'response_header_present', title: 'Response header present', status: 'PASSED', evidence: '8 headers' },
    { id: 'response_time_under_5s', title: 'Response time under 5s', status: 'PASSED', evidence: '0.1 seconds' },
    { id: 'body_not_empty', title: 'Body not empty', status: 'PASSED', evidence: 'Body contains text' },
    { id: 'security_headers', title: 'Security header policy', status: 'PASSED', evidence: '6 header checks' },
    { id: 'cookie_security', title: 'Cookie security flags', status: 'SKIPPED', evidence: 'No Set-Cookie headers observed' },
    { id: 'exposed_resources', title: 'Exposed resource probes', status: 'PASSED', evidence: '3 HEAD checks' },
    { id: 'browser_accessibility', title: 'Playwright + axe accessibility', status: 'PASSED', evidence: '0 violations' }
  ]
};

async function scan(page, label) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa', 'best-practice'])
    .analyze();
  expect(results.violations, `${label}: ${JSON.stringify(results.violations, null, 2)}`).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.route('**/api/scan-reports?limit=10', route => route.fulfill({ json: [] }));
  await page.route('**/api/dashboard', route => route.fulfill({ json: { total_scans: 0, vulnerabilities: 0, security_issues: 0, accessibility_issues: 0 } }));
});

test('empty dashboard meets accessibility rules', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'TestPilot' })).toBeVisible();
  await expect(page.locator('#quality-results')).toContainText('Submit a target URL to run HTTPX');
  await scan(page, 'empty target dashboard');
});

test('one pasted target produces all eight groups and one combined summary', async ({ page }) => {
  await page.route('**/api/scans', route => route.fulfill({ json: scanResult }));
  await page.goto('/');
  await page.getByLabel('Website URL to scan').fill(scanResult.url);
  await page.getByText('Advanced scan options').click();
  await page.getByLabel('I own this website or have permission to test it').check();
  await page.getByRole('button', { name: 'Start Scan' }).click();
  await expect(page.getByRole('heading', { name: scanResult.url })).toBeVisible();
  await expect(page.locator('#test-group-count')).toHaveText('8 target groups');
  await expect(page.locator('#test-results')).toContainText('Status 200');
  await expect(page.locator('#test-results')).toContainText('Playwright + axe accessibility');
  await expect(page.locator('#contract-report')).toContainText('GET-only API contract checks completed.');
  await expect(page.locator('#website-scan-result')).toContainText('Gemma assessment');
  await expect(page.locator('#website-scan-result')).toContainText('Recommended next steps');
  await expect(page.locator('#website-scan-result')).toContainText('All check results');
  await expect(page.locator('#website-scan-result')).not.toContainText('**');
  await scan(page, 'combined target scan');
});

test('target scan error is announced and remains accessible', async ({ page }) => {
  await page.route('**/api/scans', route => route.fulfill({ status: 400, json: { detail: 'Enter a valid HTTP(S) URL.' } }));
  await page.goto('/');
  await page.getByLabel('Website URL to scan').fill('https://api.example.com/items');
  await page.getByRole('button', { name: 'Start Scan' }).click();
  await expect(page.locator('#scan-status')).toContainText('Enter a valid HTTP(S) URL.');
  await scan(page, 'target scan error');
});

test('navigation and target scan controls are keyboard reachable', async ({ page }) => {
  await page.goto('/');
  await page.keyboard.press('Tab');
  await expect(page.locator('.brand')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Dashboard' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Scan Website' })).toBeFocused();
  for (let i = 0; i < 5; i++) await page.keyboard.press('Tab');
  await expect(page.getByRole('searchbox', { name: 'Search scans, URLs or vulnerabilities' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Toggle color theme' })).toBeFocused();
  for (let i = 0; i < 8 && !(await page.getByLabel('Website URL to scan').evaluate(el => el === document.activeElement)); i++) await page.keyboard.press('Tab');
  await expect(page.getByLabel('Website URL to scan')).toBeFocused();
});

test('dashboard has one URL field and no TestPilot self-test buttons', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('input[type="url"]')).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Run Playwright browser suite' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Run API contract tests' })).toHaveCount(0);
});
