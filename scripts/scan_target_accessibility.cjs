const { chromium } = require("@playwright/test");

(async () => {
  const target = process.env.TESTPILOT_TARGET_URL;
  const axePath = process.env.TESTPILOT_AXE_PATH;
  const origin = new URL(target).origin;
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
  try {
    const context = await browser.newContext({ serviceWorkers: "block" });
    await context.route("**/*", async route => {
      try {
        const url = new URL(route.request().url());
        if ((url.protocol === "http:" || url.protocol === "https:") && url.origin === origin) await route.continue();
        else await route.abort();
      } catch { await route.abort(); }
    });
    const page = await context.newPage();
    const runtimeErrors = [];
    page.on("pageerror", error => runtimeErrors.push(String(error && error.name || "PageError")));
    const response = await page.goto(target, { waitUntil: "domcontentloaded", timeout: 20000 });
    const title = (await page.title()).trim();
    await page.keyboard.press("Tab").catch(() => {});
    const keyboardFocus = await page.evaluate(() => document.activeElement && document.activeElement !== document.body);
    const interactiveCount = await page.locator("a[href],button,input,select,textarea,[tabindex]").count();
    await page.addScriptTag({ path: axePath });
    const axe = await page.evaluate(async () => {
      const results = await window.axe.run(document, {
        runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa", "best-practice"] }
      });
      return {
        checks_passed: results.passes.length,
        incomplete: results.incomplete.length,
        violations: results.violations.slice(0, 100).map(item => ({
          id: item.id, impact: item.impact || "moderate", help: item.help,
          description: item.description, help_url: item.helpUrl, node_count: item.nodes.length,
          targets: item.nodes.slice(0, 20).map(node => node.target.join(" "))
        }))
      };
    });
    await page.waitForTimeout(150);
    const browserChecks = [
      { id: "target_page_loads", title: "Playwright page response", status: response && response.status() < 400 ? "PASSED" : "FLAGGED", evidence: response ? `HTTP ${response.status()}` : "No main document response" },
      { id: "document_title", title: "Page has a document title", status: title ? "PASSED" : "FLAGGED", evidence: title ? title.slice(0, 160) : "Document title is empty" },
      { id: "keyboard_focus", title: "Keyboard reaches an interactive element", status: keyboardFocus || !interactiveCount ? "PASSED" : "FLAGGED", evidence: interactiveCount ? (keyboardFocus ? "Tab reached a focusable element" : "Tab did not move focus from the document body") : "No interactive elements found" },
      { id: "uncaught_javascript_errors", title: "No uncaught page JavaScript errors", status: runtimeErrors.length ? "FLAGGED" : "PASSED", evidence: runtimeErrors.length ? `${runtimeErrors.length} page error(s): ${runtimeErrors.slice(0, 3).join(", ")}` : "No uncaught page errors observed" }
    ];
    process.stdout.write(JSON.stringify({ engine: "Playwright + axe-core", status: "COMPLETED", browser_checks: browserChecks, ...axe }));
  } finally { await browser.close(); }
})().catch(error => {
  process.stderr.write(String(error && error.name || "ScanError"));
  process.exitCode = 1;
});
