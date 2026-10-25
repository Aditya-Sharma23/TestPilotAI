"""Discover a same-origin OpenAPI schema and run bounded GET-only Schemathesis checks."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlparse, urlunparse, urljoin

import httpx

MAX_SCHEMA_BYTES = 512_000
SCHEMA_PATHS = ("openapi.json", "swagger.json", "api/openapi.json", "v3/api-docs")


def _origin(url):
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def _schema_candidates(target):
    parsed = urlparse(target)
    origin = _origin(target)
    parent = parsed.path.rsplit("/", 1)[0].strip("/")
    candidates = []
    if parent:
        candidates.append(urljoin(origin + "/", f"{parent}/openapi.json"))
    candidates.extend(urljoin(origin + "/", path) for path in SCHEMA_PATHS)
    return list(dict.fromkeys(candidates))


def _get_schema(target, validate_target):
    with httpx.Client(timeout=3, follow_redirects=False, trust_env=False,
                      headers={"User-Agent": "TestPilot-Hackathon-Scanner/1.0", "Accept": "application/json"}) as client:
        for schema_url in _schema_candidates(target):
            try:
                validate_target(schema_url)
                with client.stream("GET", schema_url) as response:
                    if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                        continue
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        keep = chunk[:MAX_SCHEMA_BYTES - size]
                        chunks.append(keep)
                        size += len(keep)
                        if size >= MAX_SCHEMA_BYTES or len(keep) < len(chunk):
                            break
                    schema = json.loads(b"".join(chunks))
                    if isinstance(schema, dict) and (str(schema.get("openapi", "")).startswith("3.") or schema.get("swagger") == "2.0"):
                        return schema_url, schema
            except (httpx.HTTPError, ValueError, json.JSONDecodeError):
                continue
    return None, None


def _has_remote_refs(value):
    if isinstance(value, dict):
        if "$ref" in value and isinstance(value["$ref"], str) and not value["$ref"].startswith("#/"):
            return True
        return any(_has_remote_refs(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_remote_refs(item) for item in value)
    return False


def _get_base_url(schema, target, validate_target):
    origin = _origin(target)
    servers = schema.get("servers") or []
    server = servers[0].get("url") if servers and isinstance(servers[0], dict) else None
    if server and "{" in server:
        return None
    base_url = urljoin(origin + "/", server or "/")
    validate_target(base_url)
    return base_url.rstrip("/") or origin if _origin(base_url) == origin else None


def _get_operations(schema):
    methods = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    return [(path, method) for path, item in schema.get("paths", {}).items() if isinstance(item, dict)
            for method in item if method.lower() in methods]


def run_target_contract_scan(target, validate_target, base_dir):
    schema_url, schema = _get_schema(target, validate_target)
    if not schema:
        return {"engine": "Schemathesis", "status": "SKIPPED", "summary": "No OpenAPI JSON schema was found at the standard same-origin locations.", "schema_url": None, "operations_tested": 0}
    operations = _get_operations(schema)
    get_count = sum(method.lower() == "get" for _, method in operations)
    if not get_count:
        return {"engine": "Schemathesis", "status": "SKIPPED", "summary": "The discovered schema has no GET operations; only read-only operations are tested automatically.", "schema_url": schema_url, "operations_tested": 0}
    if _has_remote_refs(schema):
        return {"engine": "Schemathesis", "status": "SKIPPED", "summary": "The schema references external documents; external references are not fetched by this scan.", "schema_url": schema_url, "operations_tested": 0}
    try:
        base_url = _get_base_url(schema, target, validate_target)
    except ValueError:
        base_url = None
    if not base_url:
        return {"engine": "Schemathesis", "status": "SKIPPED", "summary": "The schema declares an off-origin or variable server URL; it was not followed.", "schema_url": schema_url, "operations_tested": 0}
    cli = shutil.which("st") or shutil.which("schemathesis")
    if not cli:
        scripts_dir = Path(sys.executable).parent
        for name in ("st.exe", "schemathesis.exe", "st", "schemathesis"):
            candidate = scripts_dir / name
            if candidate.is_file():
                cli = str(candidate)
                break
    if not cli:
        return {"engine": "Schemathesis", "status": "ERROR", "summary": "Schemathesis CLI is not installed on this server.", "schema_url": schema_url, "operations_tested": 0}
    with tempfile.TemporaryDirectory(prefix="testpilot-schema-") as temporary_dir:
        schema_path = Path(temporary_dir) / "openapi.json"
        report_path = Path(temporary_dir) / "report.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        command = [cli, "run", str(schema_path), "--url", base_url, "--include-method", "GET",
                   "--max-examples", "1", "--max-time", "12", "--workers", "1",
                   "--rate-limit", "2/s", "--max-redirects", "0", "--request-timeout", "3",
                   "--report-json-path", str(report_path), "--no-color"]
        try:
            completed = subprocess.run(command, cwd=base_dir, env={**os.environ, "NO_COLOR": "1"},
                                       capture_output=True, text=True, timeout=18, check=False)
        except subprocess.TimeoutExpired:
            return {"engine": "Schemathesis", "status": "ERROR", "summary": "The bounded GET-only contract run exceeded its 18-second limit.", "schema_url": schema_url, "operations_tested": get_count}
        except OSError as exc:
            return {"engine": "Schemathesis", "status": "ERROR", "summary": f"Schemathesis could not start ({type(exc).__name__}).", "schema_url": schema_url, "operations_tested": get_count}
    if completed.returncode == 0:
        status, summary = "PASSED", f"Schemathesis GET-only contract checks completed for {get_count} documented operation(s)."
    elif completed.returncode == 1:
        status, summary = "ISSUES_FOUND", f"Schemathesis reported API contract findings across up to {get_count} GET operation(s)."
    else:
        status, summary = "ERROR", "Schemathesis could not complete the discovered API schema checks."
    return {"engine": "Schemathesis", "status": status, "summary": summary,
            "schema_url": schema_url, "operations_tested": get_count,
            "method_scope": "GET only", "max_examples_per_operation": 1,
            "rate_limit": "2 requests/second", "return_code": completed.returncode}
