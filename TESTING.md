# Quality checks

## Run all checks on Windows

From PowerShell:

    cd "E:\test pilot"
    .\run-tests.cmd

The launcher locates bundled Node.js and installs Chromium if needed. The public dashboard takes one target URL and starts the target scan. It runs HTTPX response checks, security checks, target-site Playwright smoke checks, and axe-core accessibility checks. After authorization, it also discovers a same-origin OpenAPI JSON schema and runs bounded GET-only Schemathesis cases when available. It reports the engine and status for each test group; it never substitutes tests of TestPilot for tests of the submitted target.

## What the single-link scan runs

The dashboard displays eight target check groups: HTTP 200, response headers, response time, non-empty body, security headers, cookie flags, exposed-resource probes, and target Playwright/axe accessibility. The browser group also checks page load, title, keyboard focus, and uncaught JavaScript errors. Optional inert reflection and access-control probes are included only when enabled and authorized.

Schemathesis is an additional target check only when the target publishes a same-origin OpenAPI JSON schema. It runs GET operations only, with at most one generated example per operation, one worker, rate limiting, no redirect following, and a short timeout. If no schema is found, the report says so instead of checking TestPilot's own API.

The Playwright browser scan uses the installed Node package and Chromium. If browser scanning cannot start, the report labels its limited static HTML fallback; it does not report that as a Playwright pass.

## API key handling

The Gemini key is read only by the server from `.env` or the process environment. Install Node.js, the `package.json` dependencies, and Playwright Chromium on the app server for full target-site browser checks. `.env` and other `.env.*` files are ignored; `.env.example` contains no credential. Never put the key in a URL, request body, browser code, or committed file. Add `GEMINI_API_KEY` if you want Gemma-generated combined summaries. If Gemma is unavailable, TestPilot generates a summary from the observed target scan results.



## Website security dashboard

The dashboard's single-URL Website Scan performs read-only HTTPX checks, security-header and cookie-flag checks, HEAD-only checks for a short list of commonly exposed files, and a Playwright + axe-core scan of the submitted public target. If Playwright is unavailable, it reports a limited static HTML scan and clearly labels that engine. The dashboard retains individual reports in SQLite and combines counts with older HTTPX run history.

Only scan public websites that you own or have permission to assess. Routine checks do not submit forms, authenticate, or follow redirects. Optional active probes are disabled by default; enabling them requires the authorization checkbox and uses an inert HTML canary plus a small set of bounded GET requests. These probes are indicators for manual review, not proof of vulnerabilities. The scanner does not read bodies from exposed-file HEAD probes and does not send page contents or cookie values to Gemma.

For local use, run the app as documented above and use **Website Scan**. All visible scan controls use the one target URL. The repository self-test suites remain available to developers through `run-tests.cmd`, not as target-scan buttons. Deployments need the FastAPI server, the Node package dependencies, and Playwright Chromium for full target-site axe scans. Configure the Gemini key only in the server environment if AI summaries are desired; built-in summaries work without a key.
