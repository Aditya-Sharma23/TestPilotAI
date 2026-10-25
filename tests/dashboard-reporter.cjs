const fs = require('node:fs');
const path = require('node:path');

class DashboardReporter {
  onBegin(config, suite) {
    this.suite = suite;
  }

  onEnd(result) {
    const tests = this.suite.allTests();
    const outcomes = tests.map(test => test.outcome());
    const passed = outcomes.filter(outcome => outcome === 'expected').length;
    const flaky = outcomes.filter(outcome => outcome === 'flaky').length;
    const failed = outcomes.filter(outcome => outcome === 'unexpected').length;
    const skipped = outcomes.filter(outcome => outcome === 'skipped').length;
    const report = {
      id: 'accessibility',
      suite: 'Playwright app accessibility suite',
      status: result.status === 'passed' ? 'PASSED' : 'FAILED',
      total: tests.length,
      passed,
      failed,
      flaky,
      skipped,
      ran_at: new Date().toISOString(),
      summary: passed + ' of ' + tests.length + ' desktop/mobile browser checks passed' + (flaky ? '; ' + flaky + ' flaky.' : '.'),
      command: 'pnpm run test:a11y'
    };
    const outputDir = path.resolve(process.cwd(), 'quality-reports');
    fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(path.join(outputDir, 'accessibility-summary.json'), JSON.stringify(report, null, 2));
  }
}

module.exports = DashboardReporter;
