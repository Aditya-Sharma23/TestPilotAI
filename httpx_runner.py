import json
import time

import httpx

MAX_BODY_BYTES = 1_000_000
TIMEOUT_SECONDS = 12


def get(url, *, transport=None):
    """Perform one bounded read-only GET and return response observations."""
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False, transport=transport) as client:
            with client.stream("GET", url, headers={"User-Agent": "TestPilotAI-Hackathon/0.1"}) as response:
                chunks = []
                total_bytes = 0
                for chunk in response.iter_bytes():
                    total_bytes += len(chunk)
                    if total_bytes > MAX_BODY_BYTES:
                        break
                    chunks.append(chunk)
                body_text = b"".join(chunks).decode("utf-8", errors="replace")
                return {
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "header_count": len(response.headers),
                    "elapsed_seconds": round(time.perf_counter() - started, 3),
                    "body_preview": body_text[:2000],
                    "body_text": body_text,
                    "body_truncated": total_bytes > MAX_BODY_BYTES,
                    "final_url": str(response.url),
                }
    except httpx.TimeoutException as exc:
        raise RuntimeError(f"HTTP request timed out after {TIMEOUT_SECONDS} seconds.") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"HTTPX request failed: {type(exc).__name__}.") from exc


def matches_json_shape(actual, example):
    if isinstance(example, dict):
        return isinstance(actual, dict) and actual.keys() == example.keys() and all(
            matches_json_shape(actual[key], value) for key, value in example.items()
        )
    if isinstance(example, list):
        return isinstance(actual, list) and (
            not example or all(matches_json_shape(item, example[0]) for item in actual)
        )
    if isinstance(example, bool):
        return isinstance(actual, bool)
    if isinstance(example, (int, float)):
        return isinstance(actual, (int, float)) and not isinstance(actual, bool)
    return type(actual) is type(example)


def evaluate(check_ids, observation, expected_json_example=None):
    """Evaluate the fixed checklist against HTTPX observations."""
    checks = {
        "status_200": (
            observation["status_code"] == 200,
            "HTTP status is exactly 200",
            f"HTTP {observation['status_code']}",
        ),
        "response_header_present": (
            observation["header_count"] > 0,
            "At least one response header exists",
            f"{observation['header_count']} response headers",
        ),
        "response_time_under_5s": (
            observation["elapsed_seconds"] < 5,
            "Response time is under 5 seconds",
            f"{observation['elapsed_seconds']} seconds",
        ),
        "body_not_empty": (
            bool(observation["body_preview"].strip()),
            "Captured response body preview contains non-whitespace text",
            "Body contains text" if observation["body_preview"].strip() else "Body is empty or whitespace-only",
        ),
    }
    if expected_json_example is not None:
        try:
            actual_json = json.loads(observation["body_text"])
            matches = matches_json_shape(actual_json, expected_json_example)
            actual = "JSON structure matches the sample" if matches else "JSON parsed, but keys/types/array shape differ from the sample"
        except json.JSONDecodeError:
            matches, actual = False, "Response body is not valid JSON"
        checks["json_structure_matches"] = (
            matches,
            "Response JSON matches the supplied sample structure",
            actual,
        )
    return [
        {
            "id": check_id,
            "status": "PASSED" if checks[check_id][0] else "FAILED",
            "expected": checks[check_id][1],
            "actual": checks[check_id][2],
        }
        for check_id in check_ids
    ]
