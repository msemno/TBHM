"""
Curl Probe Library - v2.16 fixed/merged

Real-curl probes used by curl_verify. This file intentionally keeps the broader
v2.16 probes and restores the v2.15 checks that were accidentally dropped:
WebDAV, X-Original-URL admin bypass, Range-header DoS indicator, and Apache
server-status/server-info/dotfile body validation.

Each probe returns:
  (vulnerable: bool, severity: str, evidence: str, curl_cmd: str)
"""
from __future__ import annotations

import hashlib
import re
import secrets
import shlex
import subprocess
import contextvars
import json
import uuid
from pathlib import Path
from urllib.parse import urlparse


CURL_BASE = [
    "curl", "-sk", "-i", "--max-time", "15",
    "-A", "Mozilla/5.0 (TBHM Curl Probe; Kali Linux)",
]


import time as _time

# v2.20: global rate limit so curl_verify honours --rate-limit (was unthrottled).
_MIN_INTERVAL = 0.0
_LAST_CALL = [0.0]
_RUN_CONTEXT = contextvars.ContextVar('tbhm_curl_context', default=None)
_CAPTURES = contextvars.ContextVar('tbhm_curl_captures', default=None)


def set_rate(rps: float):
    global _MIN_INTERVAL
    _MIN_INTERVAL = 1.0 / max(0.1, rps) if rps else 0.0


def _throttle():
    if _MIN_INTERVAL <= 0:
        return
    d = _time.monotonic() - _LAST_CALL[0]
    if d < _MIN_INTERVAL:
        _time.sleep(_MIN_INTERVAL - d)
    _LAST_CALL[0] = _time.monotonic()


def _run_curl(args: list[str], timeout: int = 18) -> tuple[int, str, str]:
    """Execute curl with given args. Returns (returncode, stdout, stderr)."""
    ctx = _RUN_CONTEXT.get()
    if ctx is not None:
        return run_captured_curl(ctx, args, timeout=timeout)
    _throttle()
    try:
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="ignore",
            check=False,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "curl not found"


def run_captured_curl(ctx, args, *, timeout=18):
    """Meter one no-redirect curl operation and retain its sanitized response.

    The argv is request intent, not a wire-level request capture. These artifacts
    do not carry strict-proof authority. Every attempt enters the test ledger.
    """
    from core.http_policy import BudgetedSession, RequestBlocked
    from core.safe_writes import ctx_gate
    from core.scoped_http import effective_rps
    from core.evidence_redaction import safe_argv, redact_text
    from types import SimpleNamespace
    url = str(args[-1])
    method = args[args.index('-X')+1] if '-X' in args else ('HEAD' if '-I' in args else 'GET')
    tx = ctx.storage.start_test_execution(test_id='curl-exchange-v426', phase='curl_verify',
        target=url, operation=method, extra={'vulnerability_confirmation':False})
    result = None
    class Transport:
        _tbhm_action = 'curl_verify'
        headers = {}
        def request(self, method, target, **kwargs):
            nonlocal result
            proxy = getattr(ctx.args, 'proxy', None)
            command = list(args)
            # curl's inherited environment is not an authorization source.
            if proxy:
                command = command[:-1]+['--proxy', proxy, command[-1]]
            result = ctx.runner.run(command, timeout=timeout, log_name='curl_probe',
                env={k:'' for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')})
            return SimpleNamespace(status_code=_status_code(result[1]) or 0, headers={})
    try:
        allowed, reason = ctx_gate(ctx, method, url)
        if not allowed:
            raise RequestBlocked(reason)
        BudgetedSession(ctx, Transport(), budget=6000, max_rps=effective_rps(ctx)).request(method, url)
        rc, stdout, stderr = result
        status = 'tool-error' if rc else 'inconclusive'
        ledger = getattr(ctx, 'execution_ledger', None)
        if ledger:
            ledger.record(kind='http', status='executed' if rc == 0 else 'network-error',
                method=method, url=url, returncode=rc,
                response_representation_bytes=len(stdout.encode('utf-8')))
    except RequestBlocked as exc:
        rc, stdout, stderr = 77, '', str(exc)
        status = 'blocked'
        ledger = getattr(ctx, 'execution_ledger', None)
        if ledger:
            ledger.record(kind='http', status='blocked', method=method, url=url, reason=stderr)
    stdout, stderr = redact_text(stdout), redact_text(stderr)
    out = Path(ctx.output)/'evidence/curl_exchanges'
    out.mkdir(parents=True, exist_ok=True)
    path = out/(uuid.uuid4().hex+'.json')
    cap = min(16*1024*1024, int(ctx.profile.get('http_policy', {}).get('max_response_bytes', 2*1024*1024)))
    encoded = stdout.encode('utf-8')
    truncated = len(encoded) > cap
    captured = encoded[:cap].decode('utf-8', 'ignore')
    payload = {'schema':'tbhm.curl-exchange/1', 'test_execution_id':tx,
        'request_intent':{'method':method,'url':url,'argv':safe_argv(args)},
        'response_raw':captured, 'response_truncated':truncated, 'returncode':rc,
        'stderr':stderr[:2000], 'strict_proof_authority':False}
    path.write_text(json.dumps(payload, indent=2)+'\n');path.chmod(0o600)
    ref = {'path':path.relative_to(ctx.output).as_posix(),
           'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    ctx.storage.complete_test_execution(tx, status=status,
        result_summary='HTTP observation only; class-specific proof controls were not evaluated.',
        error=stderr[:500] if rc else '', artifact_refs=[ref])
    record = {'test_execution_id':tx, 'http_exchange_refs':[ref], 'response_raw':captured[:8000],
        'evidence_capture_status':'tool-response-partial' if truncated or rc else 'tool-response-captured'}
    ctx._last_curl_capture = record
    captures = _CAPTURES.get()
    if captures is not None:
        captures[_curl_str(args)] = record
    return rc, stdout, stderr


def _curl_str(args: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in args)


def _split_response(out: str) -> tuple[str, str]:
    """Return (headers, body) for the last response block from curl -i output."""
    # curl -i can include several HTTP blocks after redirects/100-continue. Use the last.
    blocks = re.split(r"\r?\n\r?\n", out, maxsplit=1)
    if len(blocks) == 2:
        return blocks[0], blocks[1]
    return out, ""


def _get_status(out: str) -> str:
    """Extract the final HTTP status line from curl output."""
    status = ""
    for line in out.splitlines():
        if line.startswith("HTTP/"):
            status = line.strip()
    return status


def _status_code(out: str) -> int | None:
    m = re.search(r"HTTP/\S+\s+(\d{3})", _get_status(out))
    return int(m.group(1)) if m else None


def _header_value(headers: str, name: str) -> str:
    match = re.search(rf"(?im)^{re.escape(name)}\s*:\s*(.+?)\s*$", headers or "")
    return match.group(1).strip() if match else ""


def _normalized_body(body: str) -> str:
    value = re.sub(r"[a-f0-9]{16,}", "<RANDOM>", body or "", flags=re.I)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:100_000]


def _response_signature(out: str) -> dict:
    headers, body = _split_response(out)
    normalized = _normalized_body(body)
    return {
        "status": _status_code(out),
        "body": body,
        "normalized": normalized,
        "hash": hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest(),
        "length": len(normalized),
        "content_type": _header_value(headers, "Content-Type").split(";", 1)[0].strip().lower(),
        "location": _header_value(headers, "Location"),
    }


def _same_response(left: dict, right: dict, tolerance: float = 0.08) -> bool:
    if not left or not right:
        return False
    if left.get("hash") and left.get("hash") == right.get("hash"):
        return True
    if left.get("status") != right.get("status"):
        return False
    l_len, r_len = int(left.get("length") or 0), int(right.get("length") or 0)
    if not l_len or not r_len:
        return l_len == r_len
    if abs(l_len - r_len) / max(l_len, r_len) > tolerance:
        return False
    l_type, r_type = left.get("content_type"), right.get("content_type")
    return not l_type or not r_type or l_type == r_type


def _random_control(root: str) -> tuple[dict | None, str]:
    url = root.rstrip("/") + f"/__tbhm_missing_{secrets.token_hex(12)}"
    args = CURL_BASE + [url]
    rc, out, _ = _run_curl(args)
    return (_response_signature(out) if rc == 0 else None), _curl_str(args)


def _root(base_url: str) -> str:
    parsed = urlparse(base_url if base_url.startswith("http") else f"https://{base_url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _with_param(url: str, key: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{key}={value}"


# ──────────────────────────────────────────────────────────────────────────────
# 1. HTTP methods and override checks
# ──────────────────────────────────────────────────────────────────────────────

def probe_trace(url: str):
    """Detect HTTP TRACE method enabled — Cross-Site Tracing risk."""
    args = CURL_BASE + ["-X", "TRACE", "-H", "X-Probe: TBHM", url]
    rc, out, _ = _run_curl(args)
    if rc != 0:
        return (False, "", "", _curl_str(args))

    headers, body = _split_response(out)
    if "X-Probe: TBHM" in body or "TRACE " in body:
        return (
            True,
            "LOW",
            "Server echoes TRACE request back — XST may be possible if combined with XSS or credential theft via TRACE-reflected headers.",
            _curl_str(args),
        )
    return (False, "", "", _curl_str(args))


def probe_options(url: str):
    """Check OPTIONS method for dangerous enabled methods."""
    args = CURL_BASE + ["-X", "OPTIONS", url]
    rc, out, _ = _run_curl(args)
    if rc != 0:
        return (False, "", "", _curl_str(args))

    dangerous = {"PUT", "DELETE", "CONNECT", "PATCH"}
    for line in out.splitlines():
        if line.lower().startswith("allow:"):
            methods = {m.strip().upper() for m in re.split(r"[,\s]+", line.split(":", 1)[1]) if m.strip()}
            hit = sorted(dangerous.intersection(methods))
            if hit:
                return (True, "LOW", f"Dangerous HTTP methods advertised in Allow header: {', '.join(hit)}", _curl_str(args))
    return (False, "", "", _curl_str(args))


def probe_webdav(url: str):
    """Detect exposed WebDAV — PROPFIND 207 Multi-Status is the strongest signal."""
    args = CURL_BASE + ["-X", "PROPFIND", "-H", "Depth: 0", url]
    rc, out, _ = _run_curl(args)
    if rc != 0:
        return (False, "", "", _curl_str(args))

    status = _get_status(out)
    lower = out.lower()
    if " 207 " in status or "multistatus" in lower or "<d:multistatus" in lower:
        return (
            True,
            "HIGH",
            "WebDAV PROPFIND responded with Multi-Status — server allows WebDAV operations. Manually test PUT/MKCOL/COPY/MOVE only if authorized.",
            _curl_str(args),
        )
    # weaker WebDAV fingerprint from OPTIONS/DAV header
    if re.search(r"(?im)^dav:\s*", out):
        return (True, "MEDIUM", "Server exposes a DAV header, indicating WebDAV support may be enabled.", _curl_str(args))
    return (False, "", "", _curl_str(args))


def probe_method_override(url: str):
    """Detect method-override processing using a same-request control.

    A plain 405 is never sufficient. The injected response must either mention
    the synthetic DEBUG method in method-processing context or differ materially
    from the ordinary GET control.
    """
    control_args = CURL_BASE + ["-X", "GET", url]
    control_rc, control_out, _ = _run_curl(control_args)
    args = CURL_BASE + [
        "-X", "GET",
        "-H", "X-HTTP-Method-Override: DEBUG",
        "-H", "X-Method-Override: DEBUG",
        "-H", "X-Original-Method: DEBUG",
        url,
    ]
    rc, out, _ = _run_curl(args)
    if rc != 0:
        return (False, "", "", _curl_str(args))

    lower = out.lower()
    explicit = "debug" in lower and any(
        phrase in lower for phrase in ("method not allowed", "unsupported method", "request method", "http method")
    )
    differential = False
    if control_rc == 0:
        injected = _response_signature(out)
        control = _response_signature(control_out)
        differential = not _same_response(injected, control) and injected.get("status") != control.get("status")
    if explicit or differential:
        basis = "response references the injected DEBUG method" if explicit else "response status changed from the ordinary GET control"
        return (
            True,
            "MEDIUM",
            f"Server appears to process method-override headers; {basis}. Test state-changing methods only if explicitly authorized.",
            _curl_str(args),
        )
    return (False, "", "", _curl_str(args))


# ──────────────────────────────────────────────────────────────────────────────
# 2. CORS and header injection
# ──────────────────────────────────────────────────────────────────────────────

def probe_cors(url: str):
    """Check for permissive CORS configurations."""
    evil = "https://tbhm-evil.example.com"
    args = CURL_BASE + ["-H", f"Origin: {evil}", url]
    rc, out, _ = _run_curl(args)
    if rc == 0:
        lower = out.lower()
        if evil.lower() in lower and "access-control-allow-origin" in lower:
            if re.search(r"(?im)^access-control-allow-credentials:\s*true\s*$", out):
                return (True, "HIGH", "CORS reflects arbitrary Origin and allows credentials.", _curl_str(args))
            return (True, "MEDIUM", "CORS reflects arbitrary Origin.", _curl_str(args))

    args_null = CURL_BASE + ["-H", "Origin: null", url]
    rc, out, _ = _run_curl(args_null)
    if rc == 0 and re.search(r"(?im)^access-control-allow-origin:\s*null\s*$", out):
        return (True, "MEDIUM", "CORS allows the literal null origin.", _curl_str(args_null))
    return (False, "", "", _curl_str(args))


def probe_host_header(url: str):
    """Detect Host / X-Forwarded-Host reflection in body or Location header."""
    canary = "tbhm-canary.example"
    args = CURL_BASE + ["-H", f"Host: {canary}", url]
    rc, out, _ = _run_curl(args)
    if rc == 0:
        headers, body = _split_response(out)
        for line in headers.splitlines():
            if line.lower().startswith("location:") and canary in line.lower():
                return (
                    True,
                    "HIGH",
                    f"Host header injection: '{canary}' reflected in Location header — possible password-reset poisoning/open redirect via Host.",
                    _curl_str(args),
                )
        if canary in body:
            return (
                True,
                "MEDIUM",
                f"Host header value '{canary}' reflected in response body — possible cache poisoning or password-reset poisoning.",
                _curl_str(args),
            )

    args_fwd = CURL_BASE + ["-H", f"X-Forwarded-Host: {canary}", url]
    rc, out, _ = _run_curl(args_fwd)
    if rc == 0 and canary in out.lower():
        return (True, "MEDIUM", "X-Forwarded-Host reflection detected.", _curl_str(args_fwd))
    return (False, "", "", _curl_str(args))


def probe_admin_bypass(base_url: str):
    """Compare direct /admin access with header-based routing controls."""
    root = _root(base_url)
    admin_path = "/admin"
    direct_args = CURL_BASE + [root + admin_path]
    direct_rc, direct_out, _ = _run_curl(direct_args)
    args = CURL_BASE + [
        "-H", f"X-Original-URL: {admin_path}",
        "-H", f"X-Rewrite-URL: {admin_path}",
        "-H", f"X-Override-URL: {admin_path}",
        root + "/",
    ]
    rc, out, _ = _run_curl(args)
    if rc != 0:
        return (False, "", "", _curl_str(args))

    bypass = _response_signature(out)
    direct = _response_signature(direct_out) if direct_rc == 0 else None
    body = str(bypass.get("body") or "").lower()
    admin_marker = any(
        kw in body for kw in ("admin panel", "administrator", "users list", "moderation queue", "admin dashboard")
    )
    direct_denied = direct is None or direct.get("status") in {401, 403, 404, 410}
    meaningful_delta = direct is None or not _same_response(bypass, direct)
    bypass_access = bypass.get("status") in {200, 401, 403}
    # A generic root dashboard is not evidence of an admin routing bypass.
    if bypass_access and admin_marker and direct_denied and meaningful_delta:
        return (True, "HIGH", "Header-routed request exposed admin-specific content while the direct /admin control was denied or absent.", _curl_str(args))
    return (False, "", "", _curl_str(args))


# ──────────────────────────────────────────────────────────────────────────────
# 3. Information disclosure and exposure checks
# ──────────────────────────────────────────────────────────────────────────────

def probe_sensitive_files(base_url: str):
    """Check common sensitive files using GET with body validation, not HEAD only."""
    root = _root(base_url)
    checks = [
        ("/.env", "CRITICAL", [r"(?m)^[A-Z0-9_]+=.+$", r"(?i)(APP_KEY|DB_PASSWORD|SECRET|API_KEY|AWS_ACCESS_KEY)="]),
        ("/.env.local", "CRITICAL", [r"(?m)^[A-Z0-9_]+=.+$", r"(?i)(DB_PASSWORD|SECRET|API_KEY)="]),
        ("/.git/config", "HIGH", [r"\[core\]", r"repositoryformatversion"]),
        ("/.svn/entries", "HIGH", [r"(?i)(dir|svn)"]),
        ("/web.config", "HIGH", [r"(?i)<configuration", r"connectionStrings"]),
        ("/appsettings.json", "HIGH", [r"(?i)(ConnectionStrings|Logging|AllowedHosts|Password|Secret)"]),
        ("/config.php.bak", "HIGH", [r"(?i)(\$db|password|mysql|mysqli|pdo)"]),
        ("/actuator/env", "HIGH", [r"(?i)(propertySources|systemProperties|activeProfiles)"]),
        ("/phpinfo.php", "MEDIUM", [r"(?i)php version", r"(?i)phpinfo\(\)"]),
        ("/robots.txt", "INFO", [r"(?im)^(user-agent|disallow):"]),
        ("/.well-known/security.txt", "INFO", [r"(?i)(contact:|expires:|preferred-languages:)"]),
    ]
    control, _ = _random_control(root)
    for path, sev, patterns in checks:
        args = CURL_BASE + [root + path]
        rc, out, _ = _run_curl(args)
        if rc != 0:
            continue
        candidate = _response_signature(out)
        body = str(candidate.get("body") or "")
        if candidate.get("status") != 200 or (control and _same_response(candidate, control)):
            continue
        matched = [pattern for pattern in patterns if re.search(pattern, body, re.I | re.M)]
        if not matched:
            continue
        # Raw configuration/repository artifacts should not be inferred from a
        # generic HTML shell that happens to mention APP_KEY or git configuration.
        content_type = str(candidate.get("content_type") or "")
        if path in {"/.env", "/.env.local", "/.git/config", "/web.config", "/appsettings.json", "/config.php.bak"} and "html" in content_type:
            continue
        return (True, sev, f"Sensitive/exposure path confirmed by distinctive response body: {path}", _curl_str(args))
    return (False, "", "", "")


def probe_admin_paths(base_url: str):
    """Enumerate common admin/debug interfaces with status-only evidence."""
    root = _root(base_url)
    paths = ["/admin", "/administrator", "/wp-admin", "/cpanel", "/dashboard", "/debug", "/metrics"]
    for path in paths:
        args = CURL_BASE + ["-I", root + path]
        rc, out, _ = _run_curl(args)
        if rc != 0:
            continue
        status = _get_status(out)
        if any(s in status for s in [" 200 ", " 401 ", " 403 "]):
            return (True, "INFO", f"Admin/debug path detected: {path} ({status})", _curl_str(args))
    return (False, "", "", "")


def probe_server_status(base_url: str):
    """Check for exposed /server-status and /server-info plus critical dotfiles."""
    root = _root(base_url)
    findings = []
    control, _ = _random_control(root)
    for path in ("/server-status", "/server-info", "/.env", "/.git/config"):
        args = CURL_BASE + [root + path]
        rc, out, _ = _run_curl(args)
        if rc != 0 or _status_code(out) != 200:
            continue
        candidate = _response_signature(out)
        if control and _same_response(candidate, control):
            continue
        body = str(candidate.get("body") or "")
        lower = body.lower()
        if path == "/server-status" and "apache server status" in lower:
            findings.append(("HIGH", "Apache mod_status exposed at /server-status", _curl_str(args)))
        elif path == "/server-info" and ("server settings" in lower or "module name" in lower):
            findings.append(("HIGH", "Apache mod_info exposed at /server-info", _curl_str(args)))
        elif path == "/.env" and ("=" in body and len(body) < 10000 and re.search(r"(?m)^[A-Z0-9_]+=.+$", body)):
            findings.append(("CRITICAL", "/.env file exposed", _curl_str(args)))
        elif path == "/.git/config" and "[core]" in body:
            findings.append(("HIGH", "/.git/config exposed — repository may be recoverable", _curl_str(args)))
    if findings:
        sev, ev, cmd = findings[0]
        return (True, sev, ev, cmd)
    return (False, "", "", "")


# ──────────────────────────────────────────────────────────────────────────────
# 4. Input validation and API discovery
# ──────────────────────────────────────────────────────────────────────────────

def probe_open_redirect(url: str):
    """Basic open redirect check on common parameters."""
    target = "https://example.com"
    for p in ["next", "url", "redirect", "return", "continue", "to"]:
        test_url = _with_param(url, p, target)
        args = CURL_BASE + ["-I", test_url]
        rc, out, _ = _run_curl(args)
        if rc == 0 and re.search(r"(?im)^location:\s*https://example\.com", out):
            return (True, "MEDIUM", f"Possible open redirect on parameter: {p}", _curl_str(args))
    return (False, "", "", "")


def probe_reflection(url: str):
    """Check for reflected input (XSS precursor)."""
    marker = "TBHM_REFLECT_TEST"
    for p in ["q", "s", "search", "id", "query"]:
        test_url = _with_param(url, p, marker)
        args = CURL_BASE + [test_url]
        rc, out, _ = _run_curl(args)
        if rc == 0 and marker in _split_response(out)[1]:
            return (True, "INFO", f"Input reflected in response body: parameter {p}", _curl_str(args))
    return (False, "", "", "")


def probe_sql_errors(url: str):
    """Check for SQL error leakage with a single quote."""
    error_patterns = [
        r"SQL syntax", r"mysql_", r"ORA-", r"PostgreSQL", r"SQLite",
        r"ODBC", r"SQL Server", r"syntax error", r"unterminated quoted string",
    ]
    for p in ["id", "page", "cat", "search"]:
        test_url = _with_param(url, p, "%27")
        args = CURL_BASE + [test_url]
        rc, out, _ = _run_curl(args)
        if rc == 0 and any(re.search(pat, out, re.I) for pat in error_patterns):
            return (True, "MEDIUM", f"SQL error leaked in response: parameter {p}", _curl_str(args))
    return (False, "", "", "")


def probe_path_traversal(url: str):
    """Check for path traversal normalization behavior."""
    root = _root(url)
    for path in ["/static/../robots.txt", "/assets/../robots.txt", "/js/../robots.txt"]:
        args = CURL_BASE + ["-I", root + path]
        rc, out, _ = _run_curl(args)
        if rc == 0 and _status_code(out) == 200:
            return (True, "LOW", f"Path traversal normalization accepted: {path}", _curl_str(args))
    return (False, "", "", "")


def probe_api_roots(base_url: str):
    """Detect API roots and docs endpoints."""
    root = _root(base_url)
    for path in ["/api", "/api/v1", "/api/v2", "/v1", "/v2", "/graphql", "/swagger.json", "/openapi.json"]:
        args = CURL_BASE + ["-I", root + path]
        rc, out, _ = _run_curl(args)
        code = _status_code(out)
        if rc == 0 and code in {200, 401, 403, 405}:
            return (True, "INFO", f"API/docs endpoint detected: {path} ({_get_status(out)})", _curl_str(args))
    return (False, "", "", "")


def probe_range_overflow(url: str):
    """Apache Range header DoS indicator (CVE-2011-3192 pattern)."""
    # Non-destructive indicator only: overlapping ranges. Patched servers often reject with 200/416.
    range_header = ",".join(f"0-{i}" for i in range(20))
    args = CURL_BASE + ["-H", f"Range: bytes={range_header}", url]
    rc, out, _ = _run_curl(args, timeout=20)
    if rc != 0:
        return (False, "", "", _curl_str(args))
    if _status_code(out) == 206:
        return (
            True,
            "MEDIUM",
            "Server returned 206 Partial Content for many overlapping ranges — possible Apache Range-header DoS pattern (CVE-2011-3192). Manually retest safely before reporting.",
            _curl_str(args),
        )
    return (False, "", "", _curl_str(args))


# ──────────────────────────────────────────────────────────────────────────────
# Run all probes against a single URL
# ──────────────────────────────────────────────────────────────────────────────

def run_all(url: str, *, ctx=None) -> list[dict]:
    token = _RUN_CONTEXT.set(ctx)
    captured = {}
    capture_token = _CAPTURES.set(captured)
    try:
        return _run_all(url, ctx, captured)
    finally:
        _CAPTURES.reset(capture_token)
        _RUN_CONTEXT.reset(token)


def _run_all(url, ctx, captured):
    """Run every probe; return a list of finding-shaped dicts."""
    out = []
    probes = [
        ("trace_method",     probe_trace,          "HTTP TRACE method enabled"),
        ("options_method",   probe_options,        "Dangerous HTTP methods advertised"),
        ("webdav",           probe_webdav,         "WebDAV PROPFIND exposed"),
        ("method_override",  probe_method_override,"HTTP method-override headers honored"),
        ("cors_check",       probe_cors,           "Permissive CORS policy"),
        ("host_header",      probe_host_header,    "Host header / X-Forwarded-Host injection"),
        ("admin_bypass",     probe_admin_bypass,   "X-Original-URL admin bypass"),
        ("sensitive_files",  probe_sensitive_files, "Exposed sensitive files"),
        ("server_status",    probe_server_status,  "Apache server-status/server-info or dotfiles"),
        ("admin_paths",      probe_admin_paths,    "Exposed admin/debug interfaces"),
        ("open_redirect",    probe_open_redirect,  "Possible open redirect"),
        ("reflection",       probe_reflection,     "Reflected input detected"),
        ("sql_errors",       probe_sql_errors,     "SQL error leakage"),
        ("path_traversal",   probe_path_traversal, "Path traversal normalization"),
        ("api_roots",        probe_api_roots,      "API root discovery"),
        ("range_dos",        probe_range_overflow, "Apache Range DoS indicator (CVE-2011-3192)"),
    ]
    for probe_id, fn, title_prefix in probes:
        if ctx is not None:
            event = getattr(ctx.runner, '_cancel_event', None)
            if event is not None and event.is_set():
                break
            state = getattr(ctx, '_http_policy_state', {})
            if state and state.get('used', 0) >= state.get('budget', 0):
                break
        try:
            ok, sev, evidence, curl_cmd = fn(url)
        except Exception:
            continue
        if ok:
            out.append({
                "probe": probe_id,
                "title": title_prefix,
                "severity": sev,
                "evidence": evidence,
                "reproducer_curl": curl_cmd,
                **captured.get(curl_cmd, {}),
            })
    return out
