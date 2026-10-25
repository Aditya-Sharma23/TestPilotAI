from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hmac
import ipaddress
import json
import os
import socket
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from google import genai
from pydantic import AnyHttpUrl, BaseModel, Field, StrictBool, field_validator

import database
import httpx_runner
import security_scanner
import target_api_contract

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
MODEL = os.getenv("GEMMA_MODEL", "gemma-4-26b-a4b-it")
_gemma_client = None

@asynccontextmanager
async def lifespan(_app):
    database.init_database()
    yield


app = FastAPI(title="TestPilot AI", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class AxeFinding(BaseModel):
    id: str = Field(max_length=100)
    impact: str | None = Field(default=None, max_length=30)
    description: str = Field(max_length=500)
    help: str = Field(max_length=500)
    help_url: str = Field(max_length=1000)
    node_count: int = Field(ge=0, le=10000)
    targets: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("node_count", mode="before")
    @classmethod
    def reject_boolean_node_count(cls, value):
        if isinstance(value, bool):
            raise ValueError("node_count must be an integer, not a boolean")
        return value


class AxePageReport(BaseModel):
    passed: int = Field(ge=0, le=100000)
    incomplete: int = Field(ge=0, le=100000)
    violations: list[AxeFinding] = Field(default_factory=list, max_length=100)

    @field_validator("passed", "incomplete", mode="before")
    @classmethod
    def reject_boolean_counts(cls, value):
        if isinstance(value, bool):
            raise ValueError("Counts must be integers, not booleans")
        return value

_quality_run_lock = threading.Lock()
_last_quality_run = 0.0
_playwright_run_lock = threading.Lock()
_last_playwright_run = 0.0
QUALITY_RUN_COOLDOWN_SECONDS = 15


class RunRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    goal: str = Field(min_length=3, max_length=1000)
    expected_json_example: str | None = Field(default=None, max_length=5000)


class WebsiteScanRequest(BaseModel):
    url: AnyHttpUrl
    security_scan: StrictBool = True
    accessibility_scan: StrictBool = True
    active_security_probes: StrictBool = False
    api_contract_scan: StrictBool = True
    authorized: StrictBool = False



def validate_url(raw):
    parsed = urlparse(raw.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid HTTP(S) URL without embedded credentials.")
    if parsed.port not in (None, 80, 443):
        raise ValueError("Only standard HTTP(S) ports are allowed.")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise ValueError("Local network targets are blocked.")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    host,
                    parsed.port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
            }
        except OSError as exc:
            raise ValueError("Hostname could not be resolved.") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("Local or non-public network targets are blocked.")
    return raw.strip()


def gemma(prompt):
    global _gemma_client
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("Set GEMINI_API_KEY in your .env file.")
    if _gemma_client is None:
        _gemma_client = genai.Client(api_key=key)
    try:
        response = _gemma_client.models.generate_content(model=MODEL, contents=prompt)
    except Exception as exc:
        raise RuntimeError("Gemma request failed; check GEMINI_API_KEY and connectivity.") from exc
    if not response.text:
        raise RuntimeError("Gemma returned an empty response.")
    return response.text.strip()


def plan_tests(url, goal, has_json_example):
    allowed = ["status_200", "response_header_present", "response_time_under_5s", "body_not_empty"]
    if has_json_example:
        allowed.append("json_structure_matches")
    prompt = (
        "Return only a JSON object with exactly these keys: title, checks, note. "
        "The checks value must be a non-empty array containing only these IDs, without duplicates: "
        + ", ".join(allowed)
        + ". status_200 means exactly HTTP 200. response_header_present means at least one response header exists. "
        "response_time_under_5s means less than 5 seconds. body_not_empty means the captured body preview has non-whitespace text. "
        "json_structure_matches is available only because the user supplied a sample JSON shape. Never suggest non-GET requests, credentials, arbitrary code, or other URLs. "
        + "User goal: " + goal + "\nTarget URL: " + url
    )
    fallback = {
        "title": "HTTP response validation",
        "checks": allowed,
        "note": "The built-in checks were used for this run.",
    }
    try:
        raw = gemma(prompt).strip()
    except RuntimeError:
        fallback["note"] = "Gemma was unavailable; the built-in safe checks were used."
        return fallback
    candidate_text = raw
    if candidate_text.startswith("```"):
        candidate_text = candidate_text.split("\n", 1)[-1]
        if candidate_text.rstrip().endswith("```"):
            candidate_text = candidate_text.rstrip()[:-3].strip()
    try:
        try:
            plan = json.loads(candidate_text)
        except json.JSONDecodeError:
            start, end = candidate_text.find("{"), candidate_text.rfind("}")
            if start < 0 or end <= start:
                raise ValueError("No JSON object found")
            plan = json.loads(candidate_text[start:end + 1])
        if not isinstance(plan, dict) or not isinstance(plan.get("title"), str) or not isinstance(plan.get("note"), str):
            return fallback
        checks = plan.get("checks")
        if (
            not isinstance(checks, list)
            or not checks
            or any(not isinstance(check, str) or check not in allowed for check in checks)
            or len(set(checks)) != len(checks)
        ):
            return fallback
        fallback["title"] = plan["title"][:100] or fallback["title"]
        fallback["checks"] = checks
        fallback["note"] = plan["note"][:300] or fallback["note"]
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return fallback
    return fallback




def _clean_report_text(value, limit=700):
    if not isinstance(value, str):
        return ""
    return " ".join(value.replace("**", "").replace("__", "").split())[:limit]


def _fallback_target_report(data):
    groups = data.get("target_test_groups", [])
    security_findings = data.get("security_findings", [])
    a11y = data.get("accessibility", {})
    a11y_findings = a11y.get("violations", [])
    httpx_checks = data.get("httpx_checks", [])
    failed_groups = [item for item in groups if item.get("status") in {"FAILED", "ERROR"}]
    limitations = []
    warning = a11y.get("warning")
    if warning:
        limitations.append(_clean_report_text(warning))
    if a11y.get("incomplete"):
        limitations.append(f"{a11y['incomplete']} accessibility rule(s) need manual review.")
    contract = data.get("schemathesis", {})
    if contract.get("status") == "SKIPPED":
        limitations.append(_clean_report_text(contract.get("summary", "API contract tests were skipped.")))
    elif contract.get("status") == "ERROR":
        limitations.append(_clean_report_text(contract.get("summary", "API contract test runner failed.")))
    elif contract.get("status") == "NOT_RUN":
        limitations.append(_clean_report_text(contract.get("summary", "API contract tests were not selected.")))
    if any(item.get("status") == "DEGRADED" for item in groups):
        limitations.append("At least one check used a limited fallback; see its check result for details.")

    findings = []
    for item in security_findings[:20]:
        findings.append({
            "title": _clean_report_text(item.get("title") or item.get("category") or "Potential security finding", 160),
            "severity": _clean_report_text(item.get("severity") or "Review", 32),
            "detail": _clean_report_text(item.get("evidence") or item.get("description") or "Requires manual review."),
            "recommended_fix": _clean_report_text(item.get("recommendation") or "Review the affected control and apply the recommended secure configuration."),
            "source": "Security scan",
        })
    for item in a11y_findings[:20]:
        findings.append({
            "title": _clean_report_text(item.get("help") or item.get("id") or "Accessibility violation", 160),
            "severity": _clean_report_text(item.get("impact") or "Review", 32),
            "detail": _clean_report_text(item.get("description") or item.get("id") or "Accessibility rule violation."),
            "recommended_fix": "Review the affected elements against the linked axe rule and verify the fix with keyboard and assistive technology testing.",
            "source": "axe-core",
        })
    findings.sort(key=lambda item: {"critical": 0, "serious": 1, "high": 1, "moderate": 2, "medium": 2, "minor": 3, "low": 3}.get(item["severity"].lower(), 4))
    actions = []
    for finding in findings:
        action = finding["recommended_fix"]
        if action and action not in actions:
            actions.append(action)
        if len(actions) == 5:
            break
    if not actions and failed_groups:
        actions = [f"Investigate the {item.get('title', item.get('id', 'failed check'))} result and rerun the scan after remediation." for item in failed_groups[:5]]
    if not actions:
        actions = ["No immediate fixes were identified by the selected automated checks. Continue with manual security and accessibility review."]

    passed = sum(item.get("status") == "PASSED" for item in httpx_checks)
    if findings or failed_groups:
        headline = f"The scan found {len(findings)} potential issue(s) and {len(failed_groups)} failed or errored check group(s). Prioritize the fixes below."
        risk = "HIGH" if any(item["severity"].lower() in {"critical", "serious", "high"} for item in findings) else "REVIEW"
    else:
        headline = "The automated checks did not report a confirmed issue. This result covers only the checks listed below."
        risk = "LOW"
    return {
        "executive_summary": headline,
        "risk_level": risk,
        "http_summary": f"HTTPX passed {passed} of {len(httpx_checks)} response checks; the target returned HTTP {data.get('http_evidence', {}).get('status_code', 'unknown')} in {data.get('http_evidence', {}).get('elapsed_seconds', 'unknown')} seconds.",
        "key_findings": findings[:20],
        "priority_actions": actions,
        "limitations": list(dict.fromkeys(item for item in limitations if item)),
        "check_results": [{"name": item.get("title", item.get("id", "Check")), "status": item.get("status", "UNKNOWN"), "evidence": item.get("evidence", "")} for item in groups],
        "contract_result": {"name": "Schemathesis API contract", "status": contract.get("status", "NOT_RUN"), "summary": _clean_report_text(contract.get("summary") or "Not run.")},
        "source": "Built-in structured summary",
    }


def summarize_target_report(data):
    fallback = _fallback_target_report(data)
    prompt = (
        "You are TestPilot's report writer. All scans already ran; do not call, invent, or request tools. "
        "Create a complete report using only the supplied JSON observations. Do not claim a potential finding is exploitable. "
        "Explain that skipped checks are not passes. Include all eight target check groups with their exact names, statuses, and evidence, plus the Schemathesis status and reason. "
        "Prioritize concrete remediations. Keep descriptions concise but complete. Return ONLY valid JSON, no Markdown or code fences, with exactly this shape: "
        '{"executive_summary":"string","risk_level":"HIGH|REVIEW|LOW|UNKNOWN","http_summary":"string",'
        '"key_findings":[{"title":"string","severity":"string","detail":"string","recommended_fix":"string","source":"string"}],'
        '"priority_actions":["string"],"limitations":["string"]}. '
        "Do not omit reported findings or any non-passing, skipped, degraded, or errored check. JSON evidence follows:\n"
        + json.dumps(data, ensure_ascii=False)
    )
    try:
        raw = gemma(prompt).strip()
        candidate = raw
        if candidate.startswith("```"):
            candidate = candidate.split("\n", 1)[-1]
            if candidate.rstrip().endswith("```"):
                candidate = candidate.rstrip()[:-3].strip()
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            start, end = candidate.find("{"), candidate.rfind("}")
            parsed = json.loads(candidate[start:end + 1]) if start >= 0 and end > start else None
        if not isinstance(parsed, dict):
            raise ValueError("Gemma did not return a JSON object")
        required_strings = ("executive_summary", "risk_level", "http_summary")
        if any(not isinstance(parsed.get(key), str) or not parsed[key].strip() for key in required_strings):
            raise ValueError("Gemma report is missing required fields")
        for key in ("key_findings", "priority_actions", "limitations"):
            if not isinstance(parsed.get(key), list):
                raise ValueError("Gemma report contains an invalid list")
        clean_findings = []
        for finding in parsed["key_findings"][:20]:
            if not isinstance(finding, dict):
                continue
            clean_findings.append({
                "title": _clean_report_text(finding.get("title"), 160),
                "severity": _clean_report_text(finding.get("severity") or "Review", 32),
                "detail": _clean_report_text(finding.get("detail")),
                "recommended_fix": _clean_report_text(finding.get("recommended_fix")),
                "source": _clean_report_text(finding.get("source") or "Automated scan", 80),
            })
        known_titles = {item["title"].casefold() for item in clean_findings}
        clean_findings.extend(item for item in fallback["key_findings"] if item["title"].casefold() not in known_titles)
        actions = [_clean_report_text(item) for item in parsed["priority_actions"][:8] if isinstance(item, str) and item.strip()]
        actions.extend(item for item in fallback["priority_actions"] if item not in actions)
        limitations = [_clean_report_text(item) for item in parsed["limitations"][:12] if isinstance(item, str) and item.strip()]
        limitations.extend(item for item in fallback["limitations"] if item not in limitations)
        model_risk = _clean_report_text(parsed["risk_level"], 32).upper()
        if fallback["risk_level"] == "HIGH" or (fallback["risk_level"] == "REVIEW" and model_risk == "LOW"):
            model_risk = fallback["risk_level"]
        return {
            "executive_summary": _clean_report_text(parsed["executive_summary"]),
            "risk_level": model_risk,
            "http_summary": _clean_report_text(parsed["http_summary"]),
            "key_findings": clean_findings[:30],
            "priority_actions": actions[:12],
            "limitations": limitations[:16],
            "check_results": fallback["check_results"],
            "contract_result": fallback["contract_result"],
            "source": "Gemma AI",
        }
    except (RuntimeError, ValueError, TypeError, json.JSONDecodeError):
        return fallback




@app.get("/", response_class=HTMLResponse)
def home():
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")




@app.post("/api/scans", responses={400: {"description": "Invalid scan request."}, 403: {"description": "Authorization confirmation required."}, 502: {"description": "The target could not be scanned."}})
def create_website_scan(request: WebsiteScanRequest):
    """Run bounded checks against a public site the caller is authorized to assess."""
    if request.active_security_probes and not request.authorized:
        raise HTTPException(403, "Confirm that you own or are authorized to test this site before running active probes.")
    try:
        target = validate_url(str(request.url))
        observation = httpx_runner.get(target)
        security = security_scanner.scan_security(
            target, validate_url, active_probes=request.active_security_probes
        ) if request.security_scan else {"checks": [], "findings": [], "active_probes_run": False}
        accessibility = security_scanner.scan_target_accessibility(
            target, observation.get("body_text", ""), validate_url, BASE_DIR
        ) if request.accessibility_scan else {"engine": "Not run", "status": "NOT_RUN", "checks": [], "browser_checks": [], "violations": []}
        if request.api_contract_scan and request.authorized:
            contract = target_api_contract.run_target_contract_scan(target, validate_url, BASE_DIR)
        elif request.api_contract_scan:
            contract = {"engine": "Schemathesis", "status": "SKIPPED", "summary": "Confirm site authorization to run bounded GET-only API contract checks.", "schema_url": None, "operations_tested": 0}
        else:
            contract = {"engine": "Schemathesis", "status": "NOT_RUN", "summary": "API contract scan disabled.", "schema_url": None, "operations_tested": 0}
        httpx_checks = httpx_runner.evaluate(
            ["status_200", "response_header_present", "response_time_under_5s", "body_not_empty"],
            observation,
        )
        security_findings = security.get("findings", [])
        a11y_violations = accessibility.get("violations", [])
        security_checks = security.get("checks", [])
        def group_status(items):
            statuses = [item.get("status") for item in items]
            if not statuses or all(status == "SKIPPED" for status in statuses): return "NOT_RUN" if not statuses else "SKIPPED"
            if "ERROR" in statuses: return "ERROR"
            return "REVIEW" if "FLAGGED" in statuses else "PASSED"
        header_names = {"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Clickjacking protection", "Strict-Transport-Security"}
        header_checks = [item for item in security_checks if item.get("title") in header_names]
        cookie_checks = [item for item in security_checks if item.get("title") == "Cookie flags"]
        exposure_checks = [item for item in security_checks if str(item.get("title", "")).startswith("Exposure probe:")]
        browser_checks = accessibility.get("browser_checks", [])
        if accessibility.get("status") == "NOT_RUN":
            browser_group_status = "NOT_RUN"
        elif accessibility.get("status") == "ERROR":
            browser_group_status = "ERROR"
        elif a11y_violations or any(item.get("status") == "FLAGGED" for item in browser_checks):
            browser_group_status = "ISSUES_FOUND"
        elif accessibility.get("engine") == "Static HTML checks":
            browser_group_status = "DEGRADED"
        else:
            browser_group_status = "PASSED"
        test_groups = [
            {"id": item["id"], "title": item["id"].replace("_", " ").title(), "status": item["status"], "evidence": item["actual"]}
            for item in httpx_checks
        ] + [
            {"id": "security_headers", "title": "Security header policy", "status": group_status(header_checks), "evidence": f"{len(header_checks)} header/protection checks"},
            {"id": "cookie_security", "title": "Cookie security flags", "status": group_status(cookie_checks), "evidence": f"{len(cookie_checks)} cookie check(s)" if cookie_checks else "No Set-Cookie headers observed"},
            {"id": "exposed_resources", "title": "Exposed resource probes", "status": group_status(exposure_checks), "evidence": f"{len(exposure_checks)} HEAD-only resource checks"},
            {"id": "browser_accessibility", "title": "Playwright + axe accessibility", "status": browser_group_status, "evidence": f"{accessibility.get('engine', 'Not run')}: {len(a11y_violations)} violation(s); {len(browser_checks)} browser smoke checks"},
        ]
        failures = sum(item.get("status") != "PASSED" for item in httpx_checks)
        summary = (
            f"8 target check groups are reported for {security_scanner.safe_display_url(target)}. "
            f"HTTPX passed {len(httpx_checks) - failures}/{len(httpx_checks)} checks; "
            f"security reported {len(security_findings)} potential finding(s); "
            f"accessibility reported {len(a11y_violations)} violation(s) "
            f"using {accessibility.get('engine', 'the selected scanner')}. "
            f"{contract.get('summary', 'Schemathesis not run.') }"
        )
        sanitized = {
            "httpx_checks": [{k: item.get(k) for k in ("id", "status", "expected", "actual")} for item in httpx_checks],
            "target_test_groups": test_groups,
            "browser_checks": [{k: item.get(k) for k in ("title", "status", "evidence")} for item in browser_checks],
            "schemathesis": {k: contract.get(k) for k in ("status", "summary", "operations_tested", "method_scope")},
            "http_evidence": {k: observation.get(k) for k in ("status_code", "content_type", "header_count", "elapsed_seconds")},
            "security_checks": [{k: item.get(k) for k in ("title", "status", "evidence")} for item in security.get("checks", [])[:40]],
            "security_findings": [{k: item.get(k) for k in ("title", "category", "severity", "evidence", "recommendation")} for item in security_findings[:30]],
            "accessibility": {
                "engine": accessibility.get("engine"), "status": accessibility.get("status"),
                "checks_passed": accessibility.get("checks_passed"), "incomplete": accessibility.get("incomplete"),
                "violations": [{k: item.get(k) for k in ("id", "impact", "help", "description", "node_count")} for item in a11y_violations[:30]],
                "warning": accessibility.get("warning"),
            },
        }
        ai_summary = summarize_target_report(sanitized)
        ai_summary_source = ai_summary.get("source", "Built-in structured summary")
        httpx_result = {k: observation.get(k) for k in ("status_code", "content_type", "header_count", "elapsed_seconds")}
        httpx_result["checks"] = httpx_checks
        scan_errors = any(item.get("status") == "ERROR" for item in security_checks) or accessibility.get("status") == "ERROR" or contract.get("status") == "ERROR"
        target_failures = (sum(group.get("status") == "FAILED" for group in test_groups)
                           + len(security_findings) + len(a11y_violations)
                           + int(contract.get("status") == "ISSUES_FOUND"))
        report = {
            "url": security_scanner.safe_display_url(target),
            "status": "ERROR" if scan_errors else ("ISSUES_FOUND" if target_failures else "PASSED"),
            "summary": summary,
            "security": security_findings,
            "security_checks": security_checks,
            "security_scan_enabled": request.security_scan,
            "active_probes_run": bool(security.get("active_probes_run", False)),
            "accessibility": accessibility,
            "test_groups": test_groups,
            "contract": contract,
            "httpx": httpx_result,
            "ai_summary": ai_summary,
            "ai_summary_source": ai_summary_source,
        }
        report_id = database.save_scan_report(report["url"], report["status"], summary, report["security"], accessibility, report["httpx"], json.dumps(ai_summary, ensure_ascii=False), contract, security_checks, test_groups, security.get("active_probes_run", False))
        report["id"] = report_id
        report["created_at"] = database.get_scan_report(report_id)["created_at"]
        return report
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(502, f"Scan failed: {type(exc).__name__}.") from exc
    except sqlite3.Error as exc:
        raise HTTPException(500, "Could not save scan history.") from exc


@app.get("/api/scan-reports")
def get_website_scans(limit: int = Query(default=10, ge=1, le=100)):
    return database.list_scan_reports(limit)


@app.get("/api/scans/{scan_id}", responses={404: {"description": "Scan report not found."}})
def get_website_scan(scan_id: int):
    report = database.get_scan_report(scan_id)
    if report is None:
        raise HTTPException(404, "Scan report not found.")
    return report


@app.get("/api/dashboard")
def dashboard_summary():
    return database.dashboard_stats()


@app.post("/api/run", responses={400: {"description": "Invalid URL or sample JSON."}, 500: {"description": "Run history could not be saved."}, 502: {"description": "An upstream service failed."}})
def run(request: RunRequest):
    try:
        url = validate_url(request.url)
        expected_json_example = None
        if request.expected_json_example and request.expected_json_example.strip():
            try:
                expected_json_example = json.loads(request.expected_json_example)
            except json.JSONDecodeError as exc:
                raise HTTPException(400, "Sample JSON is invalid. Check its quotes, commas, and brackets.") from exc
        plan = plan_tests(url, request.goal, expected_json_example is not None)
        observation = httpx_runner.get(url)
        checks = httpx_runner.evaluate(plan["checks"], observation, expected_json_example)
        facts = {
            "status_code": observation["status_code"],
            "header_count": observation["header_count"],
            "content_type": observation["content_type"],
            "elapsed_seconds": observation["elapsed_seconds"],
            "checks": checks,
        }
        try:
            summary = gemma("Summarize in two short sentences using only these facts. Do not infer a cause: " + json.dumps(facts))[:600]
        except RuntimeError:
            passed = sum(check["status"] == "PASSED" for check in checks)
            summary = (
                f"HTTP {observation['status_code']} returned {observation['header_count']} headers "
                f"in {observation['elapsed_seconds']} seconds. {passed} of {len(checks)} checks passed."
            )
        status = "PASSED" if all(check["status"] == "PASSED" for check in checks) else "FAILED"
        run_id = database.save_run(url, request.goal, plan, status, checks, observation, summary)
        response_evidence = {key: value for key, value in observation.items() if key != "body_text"}
        return {
            "id": run_id,
            "created_at": database.get_run(run_id)["created_at"],
            "url": url,
            "goal": request.goal,
            "status": status,
            "plan": plan,
            "checks": checks,
            "evidence": response_evidence,
            "summary": summary,
        }
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))
    except sqlite3.Error as exc:
        raise HTTPException(500, "Could not save run history to SQLite.") from exc


def require_quality_access(request: Request, token: str | None):
    expected = os.getenv("QUALITY_RUNNER_TOKEN")
    if expected:
        if not token or not hmac.compare_digest(token, expected):
            raise HTTPException(403, "A valid quality-runner token is required.")
        return
    client_host = request.client.host if request.client else ""
    if client_host not in {"127.0.0.1", "::1", "testclient"}:
        raise HTTPException(503, "Set QUALITY_RUNNER_TOKEN on the deployed server to enable remote test runs.")


def run_playwright_suite():
    global _last_playwright_run
    if not _playwright_run_lock.acquire(blocking=False):
        raise HTTPException(409, "Playwright browser tests are already running.")
    try:
        now = time.monotonic()
        if now - _last_playwright_run < QUALITY_RUN_COOLDOWN_SECONDS:
            raise HTTPException(429, "Please wait before starting another Playwright run.")
        _last_playwright_run = now
        node = shutil.which("node")
        if not node:
            bundled_node = Path(os.getenv("USERPROFILE", "")) / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "node" / "bin" / ("node.exe" if os.name == "nt" else "node")
            node = str(bundled_node) if bundled_node.is_file() else None
        cli = BASE_DIR / "node_modules" / "@playwright" / "test" / "cli.js"
        if not node or not cli.is_file():
            raise HTTPException(503, "Playwright browser tests need Node.js and the project's npm dependencies installed on the server.")
        base_url = os.getenv("TESTPILOT_BASE_URL", f"http://127.0.0.1:{os.getenv('PORT', '8000')}")
        env = os.environ.copy()
        env["TESTPILOT_BASE_URL"] = base_url
        try:
            completed = subprocess.run(
                [node, str(cli), "test"], cwd=BASE_DIR, env=env,
                capture_output=True, text=True, timeout=180, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(504, "Playwright browser tests exceeded their 180-second limit.") from exc
        report_path = BASE_DIR / "quality-reports" / "accessibility-summary.json"
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            detail = (completed.stderr or completed.stdout or "No test report was generated.")[-1200:]
            raise HTTPException(500, f"The Playwright run did not produce a report. {detail}") from exc
        if completed.returncode != 0 and report.get("status") == "PASSED":
            report["status"] = "FAILED"
            report["summary"] = "The Playwright browser test process failed."
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
    finally:
        _playwright_run_lock.release()

def run_contract_suite():
    global _last_quality_run
    if not _quality_run_lock.acquire(blocking=False):
        raise HTTPException(409, "API contract tests are already running.")
    try:
        now = time.monotonic()
        if now - _last_quality_run < QUALITY_RUN_COOLDOWN_SECONDS:
            raise HTTPException(429, "Please wait before starting another API contract run.")
        _last_quality_run = now
        report_path = BASE_DIR / "quality-reports" / "api-contract-summary.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps({
            "id": "api-contract", "suite": "FastAPI / Schemathesis API contract",
            "status": "RUNNING", "total": 0, "passed": 0, "failed": 0, "skipped": 0,
            "ran_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": "API contract tests are running.", "command": "Run from the TestPilot dashboard",
        }), encoding="utf-8")
        try:
            completed = subprocess.run(
                [sys.executable, "-m", "pytest", "-q"],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            report_path.write_text(json.dumps({
                "id": "api-contract", "suite": "FastAPI / Schemathesis API contract",
                "status": "FAILED", "total": 0, "passed": 0, "failed": 1, "skipped": 0,
                "ran_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "summary": "The contract run exceeded its 120-second limit.",
                "command": "Run from the TestPilot dashboard",
            }), encoding="utf-8")
            raise HTTPException(504, "API contract tests exceeded their time limit.") from exc
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(500, "The API contract run did not produce a report.") from exc
        if completed.returncode != 0 and report.get("status") == "PASSED":
            report["status"] = "FAILED"
            report["summary"] = "The API contract process failed; see the server logs."
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
    finally:
        _quality_run_lock.release()


@app.post("/api/quality/run-contract")
def start_contract_run(
    request: Request,
    x_quality_token: str | None = Header(default=None),
):
    require_quality_access(request, x_quality_token)
    return run_contract_suite()


@app.post("/api/quality/run-playwright", responses={503: {"description": "Playwright dependencies are not installed"}})
def start_playwright_run(
    request: Request,
    x_quality_token: str | None = Header(default=None),
):
    require_quality_access(request, x_quality_token)
    return run_playwright_suite()

@app.post("/api/quality/accessibility", responses={400: {"description": "Malformed JSON request body"}})
def save_browser_accessibility_report(
    report: AxePageReport,
    request: Request,
    x_quality_token: str | None = Header(default=None),
):
    require_quality_access(request, x_quality_token)
    violations = [finding.model_dump() for finding in report.violations]
    failed = len(violations)
    summary = f"{failed} axe-core accessibility violations; {report.passed} rules passed."
    result = {
        "id": "browser-accessibility",
        "suite": "Browser axe-core scan",
        "status": "FAILED" if failed else "PASSED",
        "total": report.passed + failed,
        "passed": report.passed,
        "failed": failed,
        "skipped": report.incomplete,
        "ran_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary,
        "command": "Run from the TestPilot dashboard",
        "violations": violations,
    }
    report_path = BASE_DIR / "quality-reports" / "browser-accessibility-summary.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result

@app.get("/api/quality")
def quality_reports():
    """Return the latest shared summaries from the local automated test suites."""
    suites = []
    try:
        latest_httpx = database.list_runs(1)
    except sqlite3.Error:
        latest_httpx = None
    if latest_httpx:
        latest = latest_httpx[0]
        checks = latest.get("checks", [])
        passed = sum(check.get("status") == "PASSED" for check in checks)
        failed = sum(check.get("status") == "FAILED" for check in checks)
        suites.append({
            "id": "httpx", "suite": "HTTPX live endpoint check", "status": latest.get("status", "UNKNOWN"),
            "total": len(checks), "passed": passed, "failed": failed, "skipped": 0,
            "ran_at": latest.get("created_at"), "summary": latest.get("summary", "Latest endpoint check"),
            "command": "Run a check from the TestPilot form",
        })
    elif latest_httpx == []:
        suites.append({
            "id": "httpx", "suite": "HTTPX live endpoint check", "status": "NOT_RUN",
            "total": 0, "passed": 0, "failed": 0, "skipped": 0, "ran_at": None,
            "summary": "No endpoint checks yet", "command": "Run a check from the TestPilot form",
        })
    else:
        suites.append({
            "id": "httpx", "suite": "HTTPX live endpoint check", "status": "ERROR",
            "total": 0, "passed": 0, "failed": 0, "skipped": 0, "ran_at": None,
            "summary": "Run history could not be loaded", "command": "Check local SQLite availability",
        })
    report_specs = (
        ("accessibility", "Playwright app accessibility suite", "accessibility-summary.json", "Run from the TestPilot dashboard"),
        ("browser-accessibility", "Browser axe-core scan", "browser-accessibility-summary.json", "Run from the TestPilot dashboard"),
        ("api-contract", "FastAPI / Schemathesis API contract", "api-contract-summary.json", "Run from the TestPilot dashboard"),
    )
    report_dir = BASE_DIR / "quality-reports"
    for suite_id, title, filename, command in report_specs:
        report_path = report_dir / filename
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(report, dict) or report.get("id") != suite_id:
                raise ValueError("Report format is invalid")
            suites.append(report)
        except FileNotFoundError:
            suites.append({
                "id": suite_id, "suite": title, "status": "NOT_RUN", "total": 0,
                "passed": 0, "failed": 0, "skipped": 0, "ran_at": None,
                "summary": "No report yet", "command": command,
            })
        except (OSError, ValueError, json.JSONDecodeError):
            suites.append({
                "id": suite_id, "suite": title, "status": "ERROR", "total": 0,
                "passed": 0, "failed": 0, "skipped": 0, "ran_at": None,
                "summary": "The latest report could not be read", "command": command,
            })
    return {"suites": suites}

@app.get("/api/runs")
def list_runs(limit: int = Query(default=10, ge=1, le=50)):
    try:
        return database.list_runs(limit)
    except sqlite3.Error as exc:
        raise HTTPException(500, "Could not load run history from SQLite.") from exc


@app.get("/api/runs/{run_id}", responses={404: {"description": "Run not found."}, 500: {"description": "Run history could not be loaded."}})
def get_run(run_id: int):
    try:
        run_record = database.get_run(run_id)
    except sqlite3.Error as exc:
        raise HTTPException(500, "Could not load this run from SQLite.") from exc
    if run_record is None:
        raise HTTPException(404, "Run not found.")
    return run_record







