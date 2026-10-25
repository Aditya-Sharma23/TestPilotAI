"""Bounded, opt-in checks adapted from the supplied SnitchScan project."""
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
from urllib.parse import urlparse, urlunparse

import httpx

TIMEOUT_SECONDS = 6
MAX_RESPONSE_BYTES = 128_000
USER_AGENT = "TestPilot-Hackathon-Scanner/1.0"


def safe_display_url(url):
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))


def _request(client, method, url, validate_target, *, params=None, body_limit=0):
    validate_target(url)
    with client.stream(method, url, params=params, follow_redirects=False) as response:
        body = b""
        if body_limit:
            chunks = []
            size = 0
            for chunk in response.iter_bytes():
                keep = chunk[: max(0, body_limit - size)]
                if keep:
                    chunks.append(keep)
                    size += len(keep)
                if size >= body_limit or len(keep) != len(chunk):
                    break
            body = b"".join(chunks)
        return response.status_code, dict(response.headers), response.headers.get_list("set-cookie"), body


def _check(title, category, status, severity, evidence, recommendation, url):
    return {
        "title": title, "category": category, "status": status, "severity": severity,
        "evidence": evidence[:320], "recommendation": recommendation[:320], "url": safe_display_url(url),
    }


def scan_security(target, validate_target, *, active_probes=False):
    """Run a small, read-only probe set. Active probes are inert and only opt-in."""
    findings = []
    checks = []
    safe_url = safe_display_url(target)
    origin = urlparse(target)
    root_url = urlunparse((origin.scheme, origin.netloc, "/", "", "", ""))
    client = httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False, trust_env=False,
                          headers={"User-Agent": USER_AGENT})
    try:
        try:
            status_code, headers, cookies, _ = _request(client, "GET", target, validate_target)
        except (httpx.HTTPError, ValueError) as exc:
            return {"checks": [{"title": "Target response", "status": "ERROR", "evidence": type(exc).__name__}],
                    "findings": [], "active_probes_run": False}

        lower_headers = {key.lower(): value for key, value in headers.items()}
        html_page = "text/html" in lower_headers.get("content-type", "").lower()
        header_rules = [
            ("Content-Security-Policy", "medium", "Add a restrictive Content-Security-Policy appropriate for the site."),
            ("X-Content-Type-Options", "low", "Set X-Content-Type-Options: nosniff."),
            ("Referrer-Policy", "low", "Set a Referrer-Policy that limits referrer data."),
            ("Permissions-Policy", "info", "Set a Permissions-Policy to disable unused browser capabilities."),
        ]
        for name, severity, recommendation in header_rules:
            present = name.lower() in lower_headers
            check = {"title": name, "status": "PASSED" if present else "FLAGGED",
                     "evidence": "Header present" if present else "Header missing"}
            checks.append(check)
            if not present and (html_page or name != "Content-Security-Policy"):
                findings.append(_check(f"Missing {name}", "Security header", "FLAGGED", severity,
                                       f"HTTP {status_code}; {name} was not returned.", recommendation, safe_url))

        frame_protected = "x-frame-options" in lower_headers or "frame-ancestors" in lower_headers.get("content-security-policy", "").lower()
        checks.append({"title": "Clickjacking protection", "status": "PASSED" if frame_protected else "FLAGGED",
                       "evidence": "Frame protection observed" if frame_protected else "No X-Frame-Options or CSP frame-ancestors directive"})
        if not frame_protected and html_page:
            findings.append(_check("Missing clickjacking protection", "Security header", "FLAGGED", "low",
                                   "No X-Frame-Options or CSP frame-ancestors directive was observed.",
                                   "Set Content-Security-Policy frame-ancestors or X-Frame-Options.", safe_url))

        hsts_present = "strict-transport-security" in lower_headers
        if origin.scheme == "https":
            checks.append({"title": "Strict-Transport-Security", "status": "PASSED" if hsts_present else "FLAGGED",
                           "evidence": "Header present" if hsts_present else "Header missing on HTTPS"})
            if not hsts_present:
                findings.append(_check("Missing HSTS", "Security header", "FLAGGED", "medium",
                                       "Strict-Transport-Security was not returned over HTTPS.",
                                       "Enable HSTS after confirming every subdomain is HTTPS-ready.", safe_url))
        else:
            checks.append({"title": "Strict-Transport-Security", "status": "SKIPPED", "evidence": "Not applicable to HTTP."})

        if not cookies:
            checks.append({"title": "Cookie flags", "status": "SKIPPED", "evidence": "No Set-Cookie header observed."})
        for cookie in cookies[:20]:
            parts = [part.strip().lower() for part in cookie.split(";")]
            name = cookie.split("=", 1)[0].strip()[:80] or "unnamed cookie"
            missing = [flag for flag in ("secure", "httponly", "samesite") if not any(part == flag or part.startswith(flag + "=") for part in parts[1:])]
            checks.append({"title": "Cookie flags", "status": "FLAGGED" if missing else "PASSED",
                           "evidence": f"{name}: missing {', '.join(missing)}" if missing else f"{name}: expected flags observed"})
            if missing:
                findings.append(_check(f"Cookie {name} flags", "Cookie security", "FLAGGED", "medium" if "httponly" in missing else "low",
                                       f"{name} is missing {', '.join(missing)}. Cookie values were not retained.",
                                       "Set Secure, HttpOnly, and an appropriate SameSite attribute where applicable.", safe_url))

        for label, path in ((".env file", "/.env"), ("Git metadata", "/.git/HEAD"), ("Backup archive", "/backup.zip")):
            probe_url = urlunparse((origin.scheme, origin.netloc, path, "", "", ""))
            try:
                probe_status, _, _, _ = _request(client, "HEAD", probe_url, validate_target)
                flagged = probe_status == 200
                checks.append({"title": f"Exposure probe: {label}", "status": "FLAGGED" if flagged else "PASSED",
                               "evidence": f"HEAD returned HTTP {probe_status}; no response body was read."})
                if flagged:
                    findings.append(_check(f"Potentially exposed {label}", "Exposed resource", "FLAGGED", "medium",
                                           f"A HEAD request returned HTTP 200 for {path}; confirm whether this is a real file or a generic application route.",
                                           "Remove public access to secrets, repository metadata, and backup files.", probe_url))
            except (httpx.HTTPError, ValueError) as exc:
                checks.append({"title": f"Exposure probe: {label}", "status": "ERROR", "evidence": type(exc).__name__})

        if active_probes:
            marker = "<testpilot-probe-" + secrets.token_hex(8) + ">"
            try:
                probe_status, _, _, body = _request(client, "GET", target, validate_target,
                                                    params={"testpilot_probe": marker}, body_limit=MAX_RESPONSE_BYTES)
                reflected = marker.encode("ascii") in body
                checks.append({"title": "Reflected input canary", "status": "FLAGGED" if reflected else "PASSED",
                               "evidence": "Inert markup canary returned unescaped; no script was executed." if reflected else f"Canary was not returned unescaped (HTTP {probe_status})."})
                if reflected:
                    findings.append(_check("Potential reflected HTML injection", "XSS reflection", "FLAGGED", "medium",
                                           "An inert HTML canary was reflected unescaped. This does not confirm script execution.",
                                           "Encode output for its HTML/JavaScript context and validate the affected input.", target))
            except (httpx.HTTPError, ValueError) as exc:
                checks.append({"title": "Reflected input canary", "status": "ERROR", "evidence": type(exc).__name__})

            for path in ("/admin", "/manage", "/settings", "/account", "/profile"):
                probe_url = urlunparse((origin.scheme, origin.netloc, path, "", "", ""))
                try:
                    probe_status, probe_headers, _, body = _request(client, "GET", probe_url, validate_target, body_limit=4096)
                    body_text = body.decode("utf-8", errors="replace").lower()
                    login_page = any(word in body_text for word in ("login", "sign in", "password"))
                    potential = probe_status == 200 and bool(body) and not login_page
                    checks.append({"title": f"Access-control route {path}", "status": "FLAGGED" if potential else "PASSED",
                                   "evidence": f"HTTP {probe_status}; response body was inspected in memory only."})
                    if potential:
                        findings.append(_check(f"Review access control for {path}", "Access control", "FLAGGED", "medium",
                                               f"An unauthenticated GET returned HTTP 200 without common login text. This is a potential finding, not proof of access-control failure.",
                                               "Confirm the route requires authorization using an account that is not logged in.", probe_url))
                except (httpx.HTTPError, ValueError) as exc:
                    checks.append({"title": f"Access-control route {path}", "status": "ERROR", "evidence": type(exc).__name__})
    finally:
        client.close()
    return {"checks": checks, "findings": findings, "active_probes_run": active_probes}


class _StaticA11yParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.html_lang = None
        self.title = ""
        self.in_title = False
        self.images_without_alt = 0
        self.controls = []
        self.labels = set()
        self.label_depth = 0
        self.empty_links = 0
        self.open_interactive = []
        self.is_html = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "html":
            self.is_html = True
            self.html_lang = attrs.get("lang")
        elif tag == "title":
            self.in_title = True
        elif tag == "label":
            self.label_depth += 1
            if attrs.get("for"):
                self.labels.add(attrs["for"])
        elif tag == "img" and "alt" not in attrs:
            self.images_without_alt += 1
        elif tag in {"input", "textarea", "select"}:
            if not (tag == "input" and attrs.get("type", "text") in {"hidden", "submit", "button", "reset"}):
                self.controls.append((attrs.get("id"), bool(attrs.get("aria-label") or attrs.get("aria-labelledby")), self.label_depth > 0))
        elif tag == "a" and "href" in attrs:
            self.open_interactive.append({"tag": tag, "text": "", "named": bool(attrs.get("aria-label") or attrs.get("title"))})

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "label" and self.label_depth:
            self.label_depth -= 1
        elif tag == "a" and self.open_interactive:
            item = self.open_interactive.pop()
            if not item["text"].strip() and not item["named"]:
                self.empty_links += 1

    def handle_data(self, data):
        if self.in_title:
            self.title += data
        if self.open_interactive and data.strip():
            self.open_interactive[-1]["text"] += data


def static_accessibility_scan(html, target):
    parser = _StaticA11yParser()
    parser.feed(html or "")
    checks = []
    if not parser.is_html:
        return {"engine": "Static HTML checks", "status": "NOT_APPLICABLE", "checks": [], "violations": [],
                "warning": "The response was not recognized as HTML."}
    def add(title, failed, evidence, help_text):
        checks.append({"id": title.lower().replace(" ", "-"), "impact": "moderate" if failed else None,
                       "help": help_text, "description": evidence, "targets": [], "node_count": int(bool(failed))})
    add("HTML language", not bool(parser.html_lang), f"lang={parser.html_lang or 'missing'}", "Declare the document language.")
    add("Document title", not bool(parser.title.strip()), f"title={'present' if parser.title.strip() else 'missing'}", "Give the page a descriptive title.")
    add("Image alternative text", parser.images_without_alt > 0, f"{parser.images_without_alt} image(s) missing alt", "Provide meaningful alt text or empty alt for decorative images.")
    unlabeled = sum(not (aria or nested or (control_id and control_id in parser.labels)) for control_id, aria, nested in parser.controls)
    add("Form labels", unlabeled > 0, f"{unlabeled} of {len(parser.controls)} control(s) may lack a label", "Associate each form control with a visible label or accessible name.")
    add("Link names", parser.empty_links > 0, f"{parser.empty_links} link(s) may have no readable name", "Give links an accessible name.")
    violations = [item for item in checks if item["impact"]]
    return {"engine": "Static HTML checks", "status": "COMPLETED", "checks": checks,
            "browser_checks": [{"id": "playwright_browser", "title": "Target browser checks", "status": "NOT_RUN", "evidence": "Playwright browser dependencies are unavailable."}],
            "violations": violations, "warning": "Playwright/axe browser scan was unavailable; static checks cover fewer rules."}


def scan_target_accessibility(url, html, validate_target, base_dir):
    """Run the ZIP's target-site axe scan using the project's Node Playwright stack; fall back transparently."""
    node = shutil.which("node")
    if not node:
        bundled = Path(os.getenv("USERPROFILE", "")) / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "node" / "bin" / ("node.exe" if os.name == "nt" else "node")
        node = str(bundled) if bundled.is_file() else None
    script = Path(base_dir) / "scripts" / "scan_target_accessibility.cjs"
    validate_target(url)
    if node and script.is_file():
        environment = os.environ.copy()
        environment["TESTPILOT_TARGET_URL"] = url
        environment["TESTPILOT_AXE_PATH"] = str(Path(base_dir) / "static" / "axe.min.js")
        try:
            completed = subprocess.run([node, str(script)], cwd=base_dir, env=environment,
                                       capture_output=True, text=True, timeout=45, check=False)
            if completed.returncode == 0:
                report = json.loads(completed.stdout)
                report["warning"] = "External subresources and off-origin redirects are blocked during this scan."
                return report
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError, ValueError):
            pass
    report = static_accessibility_scan(html, url)
    report["browser_checks"] = [{"id": "playwright_browser", "title": "Target browser checks", "status": "NOT_RUN", "evidence": "Playwright browser scan could not start."}]
    report["warning"] = "Playwright/axe browser scan could not start; limited static checks are shown instead."
    return report
