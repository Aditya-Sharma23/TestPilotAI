# TestPilot AI

**TestPilot scans the website URL you submit.** One scan runs HTTPX response checks, security checks, Playwright browser smoke checks, axe accessibility rules, and—when the authorized target publishes an OpenAPI schema—bounded GET-only Schemathesis tests. Gemma summarizes the combined target results.

## What it does

- **HTTPX endpoint checks:** makes a read-only GET request and checks status, response headers, response time, and whether the response has content. It records evidence and recent runs in SQLite.
- **axe-core accessibility scan:** runs axe against the submitted target page in a Playwright browser and shows violations and affected elements in the combined report.
- **Playwright target checks:** opens the submitted site, checks the main response, document title, keyboard focus, and uncaught page errors, then runs axe-core against that target page.
- **Schemathesis target contract:** discovers a same-origin OpenAPI JSON schema and tests GET operations only with bounded examples and a request rate limit. It reports “not available” when no schema can safely be found.
- **One target report:** displays the eight target check groups, individual findings, the discovered API contract result, and Gemma’s summary. Scan reports are saved in `testpilot.db`.
- **Resilient AI planning:** uses Gemma when configured and falls back to a safe built-in checklist when the model is unavailable.

## Run locally on Windows

Open PowerShell:

```powershell
cd "E:\test pilot"
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Keep the PowerShell window open while using the site. If port 8000 is already occupied, use the running site or stop its existing server before starting another one.

From the website:

1. Paste the website URL once in **Website Scan**.
2. Confirm that you own the website or have permission to test it. This enables optional active probes and the GET-only Schemathesis run.
3. Click **Start Scan**. HTTPX, security, Playwright, axe, and any discovered API contract tests run against that target.
4. Review the eight target groups and Gemma summary in the combined report.
5. Review the eight target check groups, detailed findings, and the combined Gemma summary in the scan report.

For the full developer regression suite from PowerShell, run:

```powershell
.\run-tests.cmd
```

## Configuration and deployment

- Python dependencies are listed in `requirements.txt`.
- Browser test dependencies are listed in `package.json` and locked in `pnpm-lock.yaml`. The server needs Node.js, those npm packages, and Playwright Chromium for full target-site browser and axe checks.
- Set `GEMINI_API_KEY` on the server if Gemma-generated combined scan summaries are desired. The app continues to work with its built-in safe checks without a key.
- The deployment must allow the app to run the target browser scan subprocess and make outbound requests to the URL submitted by the user.
- `.env` is ignored by Git. `.env.example` lists optional settings without real credentials.

## Safety notes

Target scans use bounded read-only requests and block loopback/private targets. Optional inert probes require the user to confirm authorization. Schemathesis checks only a same-origin OpenAPI schema and its GET operations, with limits on examples, rate, redirects, workers, and time. The app's own regression suite is separate and runs only from the developer command line.

See [TESTING.md](TESTING.md) for the test coverage and detailed verification notes.


## Target scan scope

The browser dashboard scans the URL entered by the user. It does not expose TestPilot's own Playwright/Schemathesis self-tests as website-scanning buttons. Those developer checks remain available through `run-tests.cmd`. Target Schemathesis runs only after authorization, only for same-origin OpenAPI JSON schemas, and only for GET operations; absent or unsafe schemas are reported as skipped.
