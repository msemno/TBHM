"""
Phase: audit (Burp/ZAP-style active scanner)

This is the FLAGSHIP feature added in v2.2. It's structurally different from
phases/injections.py:

  - injections.py: spray payloads at URLs with params, look for indicators
  - audit.py:      establish baseline → identify insertion points →
                   send mutations → diff against baseline → verify 3x
                   → score confidence → report

Workflow per URL:
  1. Establish baseline (3 requests to gather variance)
  2. Discover insertion points (query, body, JSON, headers, path)
  3. For each (insertion_point, check_class):
       a. Generate context-appropriate payloads (small list)
       b. Send mutation, compare to baseline
       c. If suspicious_score >= threshold → verify with 2 more requests
       d. If verified → emit finding with full evidence chain

Check classes implemented:
  - SQLi (error-based, boolean-based, time-based)
  - XSS (reflection + context analysis)
  - SSTI (arithmetic test 7*7=49)
  - Path Traversal (signature match in response)
  - Command Injection (time-based)
  - SSRF (out-of-band via interactsh-client, if installed)

NOT a replacement for Burp Pro. But works on the same architectural pattern,
and produces far fewer false positives than phases/injections.py.
"""
from __future__ import annotations

import json
import os
import random
import re
import string
import subprocess
import time
from urllib.parse import urlparse

from core import insertion_points as ip
from core import diff_engine as de
from core.session_state import Session
from core.intensity import get as intensity_get

try:
    import requests
except ImportError:
    requests = None


# Threshold above which a mutation is considered worth verifying
SUSPICIOUS_THRESHOLD = 50

# Cap on URLs to audit per run (this phase is slow)
MAX_AUDIT_URLS = {
    "quick":    0,       # disabled — too slow for quick
    "standard": 30,
    "deep":     100,
    "insane":   500,
}


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        ctx.log("INFO", "audit", "passive profile — skipping")
        return
    if not ctx.profile.get("send_payloads", False):
        ctx.log("INFO", "audit", "profile disallows payloads — skipping")
        return
    if not requests:
        ctx.log("WARN", "audit", "requests library not installed — skipping")
        return

    intensity_name = ctx.profile.get("_intensity", "standard")
    max_urls = MAX_AUDIT_URLS.get(intensity_name, 30)
    if max_urls == 0:
        ctx.log("INFO", "audit", f"intensity={intensity_name} → audit disabled (use --standard or higher)")
        return

    # Audit the TOP-SCORED endpoints (from discovery phase scoring algebra)
    top = ctx.storage.top_endpoints(n=max_urls)
    if not top:
        ctx.log("WARN", "audit", "no scored endpoints — run discovery first")
        return

    # Filter to URLs with parameters (no params → nothing to inject)
    urls_to_audit = [e["url"] for e in top
                     if ("?" in e["url"] and "=" in e["url"])
                     or _has_id_like_path(e["url"])]

    if not urls_to_audit:
        ctx.log("WARN", "audit", "no parameterized URLs in top scored endpoints")
        return

    ctx.log("INFO", "audit",
            f"━━━ Active audit on {len(urls_to_audit)} top-scored endpoints ━━━")
    ctx.log("INFO", "audit",
            "  workflow: baseline(3x) → insertion-points → mutate → diff → verify(2x)")

    # Session state (cookies, CSRF) — shared across audit run
    session = Session()

    # OAST via interactsh-client (optional)
    oast = _start_oast(ctx)

    n_findings = 0
    for i, url in enumerate(urls_to_audit, 1):
        ctx.log("INFO", "audit", f"[{i}/{len(urls_to_audit)}] {url[:80]}")
        try:
            n_findings += _audit_url(ctx, url, session, oast)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            ctx.log("WARN", "audit", f"  audit failed: {e}")

    # Tear down OAST
    if oast:
        try:
            oast["process"].terminate()
        except Exception:
            pass

    ctx.log("OK", "audit", f"audit complete: {n_findings} verified findings")


def _has_id_like_path(url: str) -> bool:
    """Even URLs without query strings can have path insertion points."""
    points = ip.discover("GET", url)
    return any(p.type == ip.PATH_SEGMENT for p in points)


# ──────────────────────────────────────────────────────────────────────────────
# Per-URL audit workflow
# ──────────────────────────────────────────────────────────────────────────────
def _audit_url(ctx, url: str, session: Session, oast) -> int:
    method = "GET"  # we only audit GETs by default; POST audit requires form data
    base_headers = {"User-Agent": "Mozilla/5.0 (TBHM-Audit/2.2)"}
    headers, _ = session.apply(base_headers, "", "")

    # 1. Establish baseline
    baseline = de.collect_baseline(method, url, headers=headers, body=None, n=3)
    if not baseline.is_valid:
        ctx.log("WARN", "audit", f"  baseline failed — skipping")
        return 0
    # Update session from baseline responses (cookies, CSRF)
    if baseline.samples:
        for s in baseline.samples:
            session.update_from_response_headers(s.headers, url)
            session.update_from_response_body(s.body)

    ctx.log("INFO", "audit",
            f"  baseline: status={baseline.status_mode} "
            f"len_mean={baseline.length_mean:.0f} t_p95={baseline.time_p95:.0f}ms")

    # 2. Discover insertion points
    points = ip.discover(method, url, headers=headers)
    if not points:
        ctx.log("INFO", "audit", "  no insertion points — skipping")
        return 0
    ctx.log("INFO", "audit", f"  {len(points)} insertion points")

    n = 0
    # 3. Run each check against each insertion point
    for point in points:
        # Skip Authorization header — fuzzing it is structural only
        if point.type == ip.HEADER and point.name.lower() == "authorization":
            continue

        for check in CHECK_REGISTRY:
            try:
                finding = check(ctx, method, url, headers, "", point, baseline, session, oast)
                if finding:
                    ctx.save_finding(finding)
                    n += 1
                    # One finding per insertion point is enough proof — move on
                    break
            except Exception as e:
                ctx.log("WARN", "audit", f"  check error: {e}")

    return n


# ──────────────────────────────────────────────────────────────────────────────
# Helpers: send + verify
# ──────────────────────────────────────────────────────────────────────────────
def _send_and_diff(method, url, headers, body, point, payload, baseline,
                   append=False) -> de.DiffResult | None:
    new_url, new_h, new_b = ip.apply(method, url, headers, body, point, payload, append=append)
    resp = de.send_one(method, new_url, headers=new_h, body=new_b or None)
    if not resp:
        return None
    return de.compare(baseline, resp, payload=payload)


def _verify(method, url, headers, body, point, payload, baseline,
            n_attempts: int = 2) -> bool:
    """Retest the mutation N times. Verified if suspicious_score consistently high."""
    scores = []
    for _ in range(n_attempts):
        diff = _send_and_diff(method, url, headers, body, point, payload, baseline)
        if diff:
            scores.append(diff.suspicious_score)
        time.sleep(0.3)
    if not scores:
        return False
    # Must average above threshold to be verified
    return sum(scores) / len(scores) >= SUSPICIOUS_THRESHOLD


# ──────────────────────────────────────────────────────────────────────────────
# Vulnerability checks (each returns finding dict or None)
# ──────────────────────────────────────────────────────────────────────────────
def check_sqli(ctx, method, url, headers, body, point, baseline, session, oast):
    """SQLi: error-based + boolean-based + time-based."""
    # 1. Error-based: append a quote
    diff = _send_and_diff(method, url, headers, body, point, "'", baseline, append=True)
    if diff and diff.error_indicators:
        sql_errors = [e for e in diff.error_indicators if "sql" in e.lower() or "ora-" in e.lower()
                      or "pdo" in e.lower() or "sqlstate" in e.lower()]
        if sql_errors and _verify(method, url, headers, body, point, "'", baseline):
            return {
                "phase": "audit", "severity": "HIGH", "confidence": "HIGH",
                "title": f"SQL Injection (error-based) in {point.location_desc}",
                "target": urlparse(url).hostname or url,
                "url": url, "method": method, "parameter": point.name, "payload": "'",
                "evidence": "; ".join(sql_errors)[:300],
                "description": f"Appending a single quote at {point.location_desc} "
                               f"triggered a database error: {sql_errors[0]}. "
                               f"Verified via 3x confirmation.",
                "impact": "Possible data extraction, auth bypass, or RCE.",
                "remediation": "Use parameterized queries / prepared statements everywhere.",
                "cwe": "CWE-89", "mrs_score": 90,
            }

    # 2. Boolean-based: 'AND 1=1' should match baseline, 'AND 1=2' should differ
    p_true  = "' AND '1'='1"
    p_false = "' AND '1'='2"
    diff_true  = _send_and_diff(method, url, headers, body, point, p_true,  baseline, append=True)
    diff_false = _send_and_diff(method, url, headers, body, point, p_false, baseline, append=True)
    if diff_true and diff_false:
        true_similar  = (diff_true.content_similarity  >= 0.85 and not diff_true.status_changed)
        false_differs = (diff_false.content_similarity < 0.7 or diff_false.status_changed
                         or abs(diff_false.length_pct_change) > 15)
        if true_similar and false_differs:
            if _verify(method, url, headers, body, point, p_false, baseline):
                return {
                    "phase": "audit", "severity": "HIGH", "confidence": "HIGH",
                    "title": f"SQL Injection (boolean-based) in {point.location_desc}",
                    "target": urlparse(url).hostname or url,
                    "url": url, "method": method, "parameter": point.name, "payload": p_false,
                    "evidence": f"AND 1=1 → similarity {diff_true.content_similarity:.2f}; "
                                f"AND 1=2 → similarity {diff_false.content_similarity:.2f}, "
                                f"length Δ {diff_false.length_pct_change:.1f}%",
                    "description": "Boolean-based SQLi confirmed: TRUE condition matches baseline, "
                                   "FALSE condition differs significantly. Verified via 3x confirmation.",
                    "impact": "Data extraction via blind SQLi.",
                    "remediation": "Parameterized queries.",
                    "cwe": "CWE-89", "mrs_score": 80,
                }

    # 3. Time-based: SLEEP(5) should add ~5s
    p_time = "'+(SELECT(0)FROM(SELECT(SLEEP(5)))a)--"
    diff = _send_and_diff(method, url, headers, body, point, p_time, baseline, append=True)
    if diff and diff.time_delta_ms > 4000:
        # Verify it's not network noise
        diff2 = _send_and_diff(method, url, headers, body, point, p_time, baseline, append=True)
        if diff2 and diff2.time_delta_ms > 4000:
            return {
                "phase": "audit", "severity": "HIGH", "confidence": "HIGH",
                "title": f"SQL Injection (time-based) in {point.location_desc}",
                "target": urlparse(url).hostname or url,
                "url": url, "method": method, "parameter": point.name, "payload": p_time,
                "evidence": f"Response delayed by {diff.time_delta_ms:.0f}ms vs baseline "
                            f"(P95={baseline.time_p95:.0f}ms). Confirmed in 2nd attempt.",
                "description": "Time-based SQLi: SLEEP(5) payload added ~5s delay.",
                "impact": "Blind SQLi enables data extraction.",
                "remediation": "Parameterized queries.",
                "cwe": "CWE-89", "mrs_score": 75,
            }
    return None


def check_xss(ctx, method, url, headers, body, point, baseline, session, oast):
    """Reflected XSS with context awareness."""
    canary = "tbhm" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    diff = _send_and_diff(method, url, headers, body, point, canary, baseline)
    if not (diff and diff.reflected_payload):
        return None
    # Canary reflected — now try context-appropriate payload
    body_text = diff.response_body
    if not canary in body_text:
        return None

    # What context is it in?
    payloads_by_context = []
    # In script context?
    if re.search(rf'<script[^>]*>[^<]*{re.escape(canary)}', body_text, re.I):
        payloads_by_context.append(f"';alert(1);//")
    # In attribute?
    if re.search(rf'=["\'][^"\']*{re.escape(canary)}', body_text):
        payloads_by_context.append(f'"><svg/onload=alert(1)>')
        payloads_by_context.append(f"' autofocus onfocus=alert(1) x='")
    # Default HTML body
    payloads_by_context.append("<svg/onload=alert(1)>")
    payloads_by_context.append("<script>alert(1)</script>")

    for xss_payload in payloads_by_context:
        diff = _send_and_diff(method, url, headers, body, point, xss_payload, baseline)
        if not diff:
            continue
        # Did the executable structure survive?
        bd = diff.response_body
        # Look for the payload's "executable" portion intact
        signal = ("onload=alert" in bd) or ("<script>alert" in bd) or \
                 ("onfocus=alert" in bd)
        if signal:
            if _verify(method, url, headers, body, point, xss_payload, baseline):
                return {
                    "phase": "audit", "severity": "HIGH", "confidence": "HIGH",
                    "title": f"Reflected XSS in {point.location_desc}",
                    "target": urlparse(url).hostname or url,
                    "url": url, "method": method, "parameter": point.name, "payload": xss_payload,
                    "evidence": f"Payload reflected with executable HTML intact. "
                                f"Canary {canary} confirmed reflection. Context-aware payload verified.",
                    "description": "Reflected XSS confirmed via 2-stage canary + context-aware "
                                   "payload + 3x verification.",
                    "impact": "Execute JS in victim browser; steal cookies, sessions.",
                    "remediation": "Output-encode user input per context (HTML, attribute, JS). Add CSP.",
                    "cwe": "CWE-79", "mrs_score": 90,
                }
    return None


def check_ssti(ctx, method, url, headers, body, point, baseline, session, oast):
    """SSTI: probe with arithmetic (7*7=49) across engines."""
    probes = [
        ("{{7*7}}", "49"),               # Jinja2 / Django / Twig
        ("${7*7}", "49"),                 # FreeMarker / Spring / JSP EL
        ("#{7*7}", "49"),                 # Ruby ERB
        ("<%= 7*7 %>", "49"),             # ERB
        ("{{7*'7'}}", "7777777"),         # Jinja2 specific (string multiplication)
    ]
    for payload, expected in probes:
        diff = _send_and_diff(method, url, headers, body, point, payload, baseline)
        if not diff:
            continue
        if expected in diff.response_body and expected not in baseline.samples[0].body:
            if _verify(method, url, headers, body, point, payload, baseline):
                return {
                    "phase": "audit", "severity": "CRITICAL", "confidence": "HIGH",
                    "title": f"Server-Side Template Injection in {point.location_desc}",
                    "target": urlparse(url).hostname or url,
                    "url": url, "method": method, "parameter": point.name, "payload": payload,
                    "evidence": f"Payload {payload} produced {expected} in response. "
                                f"Verified via 3x.",
                    "description": "SSTI confirmed. Often leads to RCE.",
                    "impact": "Remote Code Execution in many template engines.",
                    "remediation": "Never pass user input to template rendering. Use auto-escaping.",
                    "cwe": "CWE-1336", "mrs_score": 85,
                }
    return None


def check_path_traversal(ctx, method, url, headers, body, point, baseline, session, oast):
    payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
    ]
    for p in payloads:
        diff = _send_and_diff(method, url, headers, body, point, p, baseline)
        if diff and "Linux /etc/passwd content" in diff.error_indicators:
            if _verify(method, url, headers, body, point, p, baseline):
                return {
                    "phase": "audit", "severity": "HIGH", "confidence": "HIGH",
                    "title": f"Path Traversal in {point.location_desc}",
                    "target": urlparse(url).hostname or url,
                    "url": url, "method": method, "parameter": point.name, "payload": p,
                    "evidence": "Response contains /etc/passwd content (root:x:0:0:...)",
                    "description": "Path traversal confirmed by /etc/passwd contents in response.",
                    "impact": "Read sensitive files; possibly RCE via log poisoning.",
                    "remediation": "Reject path traversal sequences. Use whitelist-based file access.",
                    "cwe": "CWE-22", "mrs_score": 90,
                }
    return None


def check_cmd_injection(ctx, method, url, headers, body, point, baseline, session, oast):
    """Time-based command injection (works on Linux+Windows)."""
    payloads = [
        "; sleep 5",
        "& sleep 5",
        "| sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        "&& sleep 5",
        "; ping -n 5 127.0.0.1 ||",   # Windows
    ]
    for p in payloads:
        diff = _send_and_diff(method, url, headers, body, point, p, baseline, append=True)
        if diff and diff.time_delta_ms > 4000:
            diff2 = _send_and_diff(method, url, headers, body, point, p, baseline, append=True)
            if diff2 and diff2.time_delta_ms > 4000:
                return {
                    "phase": "audit", "severity": "CRITICAL", "confidence": "HIGH",
                    "title": f"OS Command Injection in {point.location_desc}",
                    "target": urlparse(url).hostname or url,
                    "url": url, "method": method, "parameter": point.name, "payload": p,
                    "evidence": f"Payload caused {diff.time_delta_ms:.0f}ms delay (2nd attempt: "
                                f"{diff2.time_delta_ms:.0f}ms). Baseline P95={baseline.time_p95:.0f}ms.",
                    "description": "Time-based command injection confirmed via 2 successive trials.",
                    "impact": "Remote Code Execution.",
                    "remediation": "Never pass user input to shell. Use language-native APIs with arrays.",
                    "cwe": "CWE-78", "mrs_score": 80,
                }
    return None


def check_ssrf_oob(ctx, method, url, headers, body, point, baseline, session, oast):
    """SSRF via out-of-band (interactsh). Skip if interactsh unavailable."""
    if not oast:
        return None
    # Inject the unique callback URL
    callback = oast["domain"]
    diff = _send_and_diff(method, url, headers, body, point, f"http://{callback}", baseline)
    if not diff:
        return None
    # Give the target time to perform the SSRF
    time.sleep(8)
    interactions = _poll_oast(oast)
    if interactions:
        return {
            "phase": "audit", "severity": "CRITICAL", "confidence": "HIGH",
            "title": f"Out-of-band SSRF in {point.location_desc}",
            "target": urlparse(url).hostname or url,
            "url": url, "method": method, "parameter": point.name,
            "payload": f"http://{callback}",
            "evidence": f"Target server contacted interactsh callback {callback}. "
                        f"Interactions: {len(interactions)}.",
            "description": "Server-Side Request Forgery confirmed via out-of-band callback.",
            "impact": "Pivot to internal network, cloud metadata theft, etc.",
            "remediation": "Block RFC1918 + cloud metadata ranges. URL whitelist.",
            "cwe": "CWE-918", "mrs_score": 75,
        }
    return None


# Registry — order matters: cheapest checks first
CHECK_REGISTRY = [
    check_xss,
    check_sqli,
    check_ssti,
    check_path_traversal,
    check_cmd_injection,
    check_ssrf_oob,
]


# ──────────────────────────────────────────────────────────────────────────────
# Out-of-band setup (interactsh-client)
# ──────────────────────────────────────────────────────────────────────────────
def _start_oast(ctx):
    """Start interactsh-client in background. Returns dict or None if unavailable."""
    import shutil
    if not shutil.which("interactsh-client"):
        ctx.log("INFO", "audit", "  interactsh-client not installed → SSRF OOB check disabled")
        return None
    try:
        # interactsh prints the assigned domain on startup
        proc = subprocess.Popen(
            ["interactsh-client", "-json", "-o",
             str(ctx.output / "scans" / "oast.jsonl"), "-v"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        # Read first few lines to grab domain
        domain = None
        for _ in range(20):
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.2)
                continue
            m = re.search(r"([a-z0-9]+\.oast\.\w+)", line, re.I)
            if m:
                domain = m.group(1)
                break
        if domain:
            ctx.log("OK", "audit", f"  interactsh OAST domain: {domain}")
            return {"process": proc, "domain": domain,
                    "out_file": ctx.output / "scans" / "oast.jsonl"}
        else:
            proc.terminate()
            return None
    except Exception as e:
        ctx.log("WARN", "audit", f"  interactsh failed to start: {e}")
        return None


def _poll_oast(oast) -> list:
    """Check interactsh output file for new interactions."""
    if not oast or not oast["out_file"].exists():
        return []
    out = []
    for line in oast["out_file"].read_text(errors="ignore").splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out
