import pytest
import schemathesis
import shutil
import tempfile
from pathlib import Path

import app as app_module
import database
import httpx_runner


# Exercise the app in-process, including POST. Each generated request gets its
# own temporary stubs so Hypothesis never retains state between examples.
schema = schemathesis.openapi.from_asgi("/openapi.json", app_module.app)


@schema.parametrize()
def test_openapi_contract(case):
    with tempfile.TemporaryDirectory(prefix="testpilot-quality-") as temp_dir, pytest.MonkeyPatch.context() as monkeypatch:
        temporary_root = Path(temp_dir)
        static_dir = temporary_root / "static"
        static_dir.mkdir()
        shutil.copyfile(Path(app_module.__file__).parent / "static" / "index.html", static_dir / "index.html")
        monkeypatch.setattr(app_module, "BASE_DIR", temporary_root)
        def dns_stub(*args, **kwargs):
            return [(2, 1, 6, "", ("8.8.8.8", 443))]

        monkeypatch.setattr(app_module.socket, "getaddrinfo", dns_stub)
        monkeypatch.setattr(app_module, "plan_tests", lambda url, goal, has_json: {
            "title": "Contract test run", "checks": ["status_200"], "note": "Stubbed for contract testing."
        })
        monkeypatch.setattr(httpx_runner, "get", lambda url: {
            "status_code": 200, "content_type": "application/json", "header_count": 2,
            "elapsed_seconds": 0.01, "body_preview": '{"ok":true}', "body_text": '{"ok":true}',
            "body_truncated": False, "final_url": url,
        })
        monkeypatch.setattr(app_module.security_scanner, "scan_security", lambda *args, **kwargs: {"checks": [], "findings": [], "active_probes_run": False})
        monkeypatch.setattr(app_module.security_scanner, "scan_target_accessibility", lambda *args, **kwargs: {"engine": "Stub", "status": "COMPLETED", "checks": [], "violations": []})
        monkeypatch.setattr(app_module.target_api_contract, "run_target_contract_scan", lambda *args, **kwargs: {"engine": "Schemathesis", "status": "SKIPPED", "summary": "Stubbed no-schema response.", "schema_url": None, "operations_tested": 0})
        monkeypatch.setattr(database, "save_scan_report", lambda *args, **kwargs: 1)
        monkeypatch.setattr(database, "get_scan_report", lambda scan_id: {"created_at": "2026-01-01T00:00:00+00:00"})
        monkeypatch.setattr(database, "list_scan_reports", lambda limit=10: [])
        monkeypatch.setattr(database, "dashboard_stats", lambda: {"total_scans": 0, "vulnerabilities": 0, "security_issues": 0, "accessibility_issues": 0})
        monkeypatch.setattr(app_module, "gemma", lambda prompt: "Contract test summary.")
        monkeypatch.setattr(database, "save_run", lambda *args, **kwargs: 1)
        monkeypatch.setattr(database, "get_run", lambda run_id: {"created_at": "2026-01-01T00:00:00+00:00"})
        monkeypatch.setattr(database, "list_runs", lambda limit=10: [])
        monkeypatch.setattr(app_module, "require_quality_access", lambda request, token: None)
        monkeypatch.setattr(app_module, "run_playwright_suite", lambda: {
            "id": "accessibility", "suite": "Playwright app accessibility suite", "status": "PASSED",
            "total": 1, "passed": 1, "failed": 0, "skipped": 0, "ran_at": "2026-01-01T00:00:00+00:00",
            "summary": "Stubbed browser test.", "command": "Run from the TestPilot dashboard",
        })
        monkeypatch.setattr(app_module, "run_contract_suite", lambda: {
            "id": "api-contract", "suite": "FastAPI / Schemathesis API contract", "status": "PASSED",
            "total": 1, "passed": 1, "failed": 0, "skipped": 0, "ran_at": "2026-01-01T00:00:00+00:00",
            "summary": "Stubbed contract runner.", "command": "Run from the TestPilot dashboard",
        })
        case.call_and_validate()


def test_url_validation_rejects_loopback():
    with pytest.raises(ValueError, match="blocked"):
        app_module.validate_url("http://127.0.0.1/health")


def test_url_validation_rejects_embedded_credentials():
    with pytest.raises(ValueError, match="without embedded credentials"):
        app_module.validate_url("https://user:secret@example.com/items")


def test_url_validation_rejects_nonstandard_ports():
    with pytest.raises(ValueError, match="standard HTTP"):
        app_module.validate_url("https://example.com:8443/items")


def test_url_validation_accepts_public_ip_without_dns():
    url = "https://8.8.8.8/items"
    assert app_module.validate_url(url) == url




def test_single_target_scan_builds_eight_groups_and_saves_contract(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "target-scan.db")
    monkeypatch.setattr(app_module, "validate_url", lambda raw: "https://example.com/")
    monkeypatch.setattr(app_module, "gemma", lambda prompt: '{"executive_summary":"The target responded successfully; automated checks found no issues.","risk_level":"LOW","http_summary":"HTTPX passed 4 of 4 checks; HTTP 200 in 0.2 seconds.","key_findings":[],"priority_actions":["Continue manual review."],"limitations":[]}')
    monkeypatch.setattr(httpx_runner, "get", lambda url: {
        "status_code": 200, "content_type": "text/html", "header_count": 6,
        "elapsed_seconds": 0.2, "body_preview": "hello", "body_text": "<html>hello</html>",
        "body_truncated": False, "final_url": url,
    })
    monkeypatch.setattr(app_module.security_scanner, "scan_security", lambda *args, **kwargs: {
        "checks": [
            {"title": "Content-Security-Policy", "status": "PASSED", "evidence": "present"},
            {"title": "Cookie flags", "status": "SKIPPED", "evidence": "No cookies"},
            {"title": "Exposure probe: .env file", "status": "PASSED", "evidence": "HEAD returned 404"},
        ], "findings": [], "active_probes_run": False,
    })
    monkeypatch.setattr(app_module.security_scanner, "scan_target_accessibility", lambda *args, **kwargs: {
        "engine": "Playwright + axe-core", "status": "COMPLETED", "checks_passed": 20,
        "incomplete": 0, "violations": [],
        "browser_checks": [{"id": "target_page_loads", "title": "Page response", "status": "PASSED", "evidence": "HTTP 200"}],
    })
    monkeypatch.setattr(app_module.target_api_contract, "run_target_contract_scan", lambda *args, **kwargs: {
        "engine": "Schemathesis", "status": "PASSED", "summary": "GET-only checks passed.",
        "schema_url": "https://example.com/openapi.json", "operations_tested": 1,
    })
    with TestClient(app_module.app) as client:
        response = client.post("/api/scans", json={"url": "https://example.com", "authorized": True})
        assert response.status_code == 200, response.text
        report = response.json()
        assert len(report["test_groups"]) == 8
        assert report["contract"]["engine"] == "Schemathesis"
        assert report["ai_summary"]["source"] == "Gemma AI"
        assert len(report["ai_summary"]["check_results"]) == 8
        saved_report = client.get(f"/api/scans/{report['id']}").json()
        assert saved_report["contract"]["schema_url"] == "https://example.com/openapi.json"
        assert len(saved_report["ai_summary"]["check_results"]) == 8
