import os
import tempfile
from pathlib import Path

import pytest

# Keep contract-test startup and writes isolated from the developer's local history.
_test_db_dir = tempfile.TemporaryDirectory(prefix="testpilot-contract-")
os.environ["TESTPILOT_DB_PATH"] = str(Path(_test_db_dir.name) / "runs.sqlite3")


def pytest_sessionfinish(session, exitstatus):
    from datetime import datetime, timezone
    import json

    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    stats = reporter.stats if reporter else {}
    passed = len(stats.get("passed", []))
    failed = len(stats.get("failed", [])) + len(stats.get("error", []))
    skipped = len(stats.get("skipped", []))
    total = passed + failed + skipped
    report = {
        "id": "api-contract",
        "suite": "FastAPI / Schemathesis API contract",
        "status": "PASSED" if exitstatus == 0 else "FAILED",
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "ran_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": str(passed) + " of " + str(total) + " API and safety checks passed.",
        "command": ".\\.venv\\Scripts\\python.exe -m pytest -q",
    }
    report_dir = Path(__file__).resolve().parent.parent / "quality-reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "api-contract-summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


def pytest_unconfigure(config):
    _test_db_dir.cleanup()

