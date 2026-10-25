# TestPilot AI

TestPilot scans a website URL and brings the results together in one report. A scan can run HTTPX response checks, security checks, Playwright browser checks, axe accessibility rules, and bounded GET-only Schemathesis tests when the authorized target publishes an OpenAPI schema. Gemma summarizes the results when configured; otherwise, the app uses a built-in summary.

## What it checks

- **HTTP response:** status, headers, response time, and whether the response has content.
- **Browser behavior:** main response, page title, keyboard focus, and uncaught page errors.
- **Accessibility:** axe-core rules and affected elements on the target page.
- **API contract:** discovers a same-origin OpenAPI JSON schema and tests GET operations with bounded examples and a request rate limit. Reports unavailable when no schema can safely be found.
- **Security:** performs bounded checks against the authorized target and includes findings in the combined report.
- **Reports and history:** displays the target check groups, findings, API contract result, and summary. Scan reports are saved in SQLite.

## Run locally on Windows

From PowerShell, run:

```powershell
cd "D:\test pilot"
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and keep the PowerShell window open while using the site.

1. Enter a website URL in **Website Scan**.
2. Confirm that you own the website or have permission to test it. Authorization enables optional active probes and the GET-only Schemathesis run.
3. Select **Start Scan** and review the results.

## Run the developer checks

From PowerShell, in the project folder:

```powershell
.\run-tests.cmd
```

See [TESTING.md](TESTING.md) for test coverage and verification details.

## Configuration and deployment

- Python dependencies are listed in `requirements.txt`.
- Browser dependencies are listed in `package.json` and locked in `pnpm-lock.yaml`. Full browser and accessibility checks need Node.js, the installed packages, and Playwright Chromium.
- Set `GEMINI_API_KEY` on the server to enable Gemma summaries. The app can use its built-in summary when no key is configured.
- The deployment must allow the app to run browser scan subprocesses and make outbound requests to submitted URLs.
- `.env` is ignored by Git. Use `.env.example` as a template; do not commit real credentials.

## Safety

Scans use bounded requests and block loopback and private network targets. Optional active probes require the user to confirm authorization. Schemathesis tests only GET operations from a same-origin OpenAPI schema and applies limits to examples, request rate, redirects, workers, and time.
