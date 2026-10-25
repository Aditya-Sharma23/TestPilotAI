import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import json
import os

DB_PATH = Path(os.getenv("TESTPILOT_DB_PATH", Path(__file__).resolve().parent / "testpilot.db"))


@contextmanager
def _connection():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_database():
    """Create the local run-history table if it does not exist yet."""
    with _connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL,
                security_json TEXT NOT NULL,
                accessibility_json TEXT NOT NULL,
                httpx_json TEXT NOT NULL,
                ai_summary TEXT NOT NULL,
                contract_json TEXT NOT NULL DEFAULT '{}',
                security_checks_json TEXT NOT NULL DEFAULT '[]',
                test_groups_json TEXT NOT NULL DEFAULT '[]',
                active_probes_run INTEGER NOT NULL DEFAULT 0
            )
        """)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_reports)").fetchall()}
        if "contract_json" not in columns:
            connection.execute("ALTER TABLE scan_reports ADD COLUMN contract_json TEXT NOT NULL DEFAULT '{}' ")
        if "security_checks_json" not in columns:
            connection.execute("ALTER TABLE scan_reports ADD COLUMN security_checks_json TEXT NOT NULL DEFAULT '[]'")
        if "test_groups_json" not in columns:
            connection.execute("ALTER TABLE scan_reports ADD COLUMN test_groups_json TEXT NOT NULL DEFAULT '[]'")
        if "active_probes_run" not in columns:
            connection.execute("ALTER TABLE scan_reports ADD COLUMN active_probes_run INTEGER NOT NULL DEFAULT 0")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS test_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                url TEXT NOT NULL,
                goal TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                checks_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                summary TEXT NOT NULL
            )
        """)


def save_run(url, goal, plan, status, checks, evidence, summary):
    """Save result metadata only; never persist response bodies or credentials."""
    saved_evidence = {
        key: evidence[key]
        for key in ("status_code", "header_count", "content_type", "elapsed_seconds", "final_url", "body_truncated")
        if key in evidence
    }
    with _connection() as connection:
        cursor = connection.execute(
            """INSERT INTO test_runs
               (created_at, url, goal, title, status, checks_json, evidence_json, summary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                url,
                goal,
                plan["title"],
                status,
                json.dumps(checks),
                json.dumps(saved_evidence),
                summary,
            ),
        )
        return cursor.lastrowid


def _row_to_run(row):
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "url": row["url"],
        "goal": row["goal"],
        "plan": {"title": row["title"]},
        "status": row["status"],
        "checks": json.loads(row["checks_json"]),
        "evidence": json.loads(row["evidence_json"]),
        "summary": row["summary"],
    }


def list_runs(limit=10):
    with _connection() as connection:
        rows = connection.execute(
            "SELECT * FROM test_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_run(row) for row in rows]


def get_run(run_id):
    with _connection() as connection:
        row = connection.execute(
            "SELECT * FROM test_runs WHERE id = ?", (run_id,)
        ).fetchone()
    return _row_to_run(row) if row else None


def save_scan_report(url, status, summary, security, accessibility, httpx_result, ai_summary, contract=None, security_checks=None, test_groups=None, active_probes_run=False):
    with _connection() as connection:
        cursor = connection.execute(
            """INSERT INTO scan_reports
               (created_at, url, status, summary, security_json, accessibility_json, httpx_json, ai_summary, contract_json,
                security_checks_json, test_groups_json, active_probes_run)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), url, status, summary,
             json.dumps(security), json.dumps(accessibility), json.dumps(httpx_result), ai_summary, json.dumps(contract or {}),
             json.dumps(security_checks or []), json.dumps(test_groups or []), int(bool(active_probes_run))),
        )
        return cursor.lastrowid


def _scan_row_to_report(row):
    ai_summary = row["ai_summary"]
    try:
        decoded_summary = json.loads(ai_summary)
        if isinstance(decoded_summary, dict):
            ai_summary = decoded_summary
    except (TypeError, json.JSONDecodeError):
        pass
    return {
        "id": row["id"], "created_at": row["created_at"], "url": row["url"],
        "status": row["status"], "summary": row["summary"],
        "security": json.loads(row["security_json"]),
        "accessibility": json.loads(row["accessibility_json"]),
        "httpx": json.loads(row["httpx_json"]), "ai_summary": ai_summary,
        "contract": json.loads(row["contract_json"]) if "contract_json" in row.keys() else {},
        "security_checks": json.loads(row["security_checks_json"]) if "security_checks_json" in row.keys() else [],
        "test_groups": json.loads(row["test_groups_json"]) if "test_groups_json" in row.keys() else [],
        "active_probes_run": bool(row["active_probes_run"]) if "active_probes_run" in row.keys() else False,
    }


def list_scan_reports(limit=10):
    with _connection() as connection:
        rows = connection.execute("SELECT * FROM scan_reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_scan_row_to_report(row) for row in rows]


def get_scan_report(scan_id):
    with _connection() as connection:
        row = connection.execute("SELECT * FROM scan_reports WHERE id = ?", (scan_id,)).fetchone()
    return _scan_row_to_report(row) if row else None


def dashboard_stats():
    with _connection() as connection:
        run_count = connection.execute("SELECT COUNT(*) FROM test_runs").fetchone()[0]
        rows = connection.execute("SELECT security_json, accessibility_json FROM scan_reports").fetchall()
    security_issues = 0
    vulnerabilities = 0
    accessibility_issues = 0
    for row in rows:
        try:
            findings = json.loads(row["security_json"])
            accessibility = json.loads(row["accessibility_json"])
            security_issues += sum(1 for item in findings if item.get("status") == "FLAGGED")
            vulnerabilities += sum(
                1 for item in findings if item.get("status") == "FLAGGED"
                and item.get("category") in {"XSS reflection", "Access control", "Exposed resource"}
            )
            accessibility_issues += len(accessibility.get("violations", []))
        except (TypeError, ValueError, AttributeError):
            continue
    return {
        "total_scans": run_count + len(rows),
        "vulnerabilities": vulnerabilities,
        "security_issues": security_issues,
        "accessibility_issues": accessibility_issues,
    }