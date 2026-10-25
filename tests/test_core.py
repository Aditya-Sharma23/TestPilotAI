import json

import httpx
import pytest
from fastapi.testclient import TestClient

import app as app_module
import database
import httpx_runner


def test_plan_tests_executes_the_selected_checks(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "gemma",
        lambda prompt: json.dumps({
            "title": "Fast response",
            "checks": ["response_time_under_5s"],
            "note": "Check the response time only.",
        }),
    )

    plan = app_module.plan_tests("https://example.com/", "Check speed", False)

    assert plan["checks"] == ["response_time_under_5s"]
    assert plan["title"] == "Fast response"


def test_plan_tests_falls_back_when_gemma_is_unavailable(monkeypatch):
    def unavailable(prompt):
        raise RuntimeError("Gemma unavailable")

    monkeypatch.setattr(app_module, "gemma", unavailable)
    plan = app_module.plan_tests("https://example.com/", "Check it", False)

    assert plan["checks"] == ["status_200", "response_header_present", "response_time_under_5s", "body_not_empty"]
    assert "built-in safe checks" in plan["note"]


def test_plan_tests_rejects_empty_or_repeated_checks(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "gemma",
        lambda prompt: json.dumps({"title": "Bad", "checks": ["status_200", "status_200"], "note": "Bad"}),
    )

    plan = app_module.plan_tests("https://example.com/", "Check it", False)

    assert plan["title"] == "HTTP response validation"
    assert plan["checks"] == ["status_200", "response_header_present", "response_time_under_5s", "body_not_empty"]


def test_httpx_runner_records_redirect_without_following_it():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(302, headers={"Location": "/next"}, text="redirect", request=request)
    )

    observation = httpx_runner.get("https://example.com/start", transport=transport)

    assert observation["status_code"] == 302
    assert observation["final_url"] == "https://example.com/start"
    assert observation["body_preview"] == "redirect"


def test_httpx_runner_caps_captured_body_at_one_megabyte():
    content = b"x" * (httpx_runner.MAX_BODY_BYTES + 1)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=content, request=request))

    observation = httpx_runner.get("https://example.com/large", transport=transport)

    assert observation["body_truncated"] is True
    assert len(observation["body_text"].encode("utf-8")) <= httpx_runner.MAX_BODY_BYTES


def test_httpx_runner_reports_timeouts_without_leaking_transport_details():
    def timeout(request):
        raise httpx.ReadTimeout("sensitive transport message", request=request)

    with pytest.raises(RuntimeError, match="timed out after"):
        httpx_runner.get("https://example.com/slow", transport=httpx.MockTransport(timeout))

def test_api_run_uses_safe_fallback_when_gemini_key_is_missing(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(app_module, "_gemma_client", None)
    monkeypatch.setattr(httpx_runner, "get", lambda url: {
        "status_code": 200, "content_type": "text/plain", "header_count": 1,
        "elapsed_seconds": 0.1, "body_preview": "ok", "body_text": "ok",
        "body_truncated": False, "final_url": url,
    })
    monkeypatch.setattr(database, "save_run", lambda *args, **kwargs: 9)
    monkeypatch.setattr(database, "get_run", lambda run_id: {"created_at": "2026-01-01T00:00:00+00:00"})

    with TestClient(app_module.app) as client:
        response = client.post("/api/run", json={
            "url": "https://8.8.8.8/health",
            "goal": "Check the health endpoint",
        })

    assert response.status_code == 200
    result = response.json()
    assert result["plan"]["checks"] == [
        "status_200", "response_header_present", "response_time_under_5s", "body_not_empty"
    ]
    assert "Gemma was unavailable" in result["plan"]["note"]
    assert "4 of 4 checks passed" in result["summary"]
    assert "GEMINI_API_KEY" not in response.text

