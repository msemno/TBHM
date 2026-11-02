"""
Curl Reproducer Generator.

For every finding, produces a curl command the human can copy-paste into
a HackerOne / Bugcrowd report or run themselves to verify.

This is THE difference between a finding that gets accepted and one that
gets closed as "unable to reproduce" — give the triager a single command
they can run.

How it's used:
  - Hooked into storage.save_finding (automatic for every finding)
  - reporter.py reads finding["reproducer_curl"] and shows it prominently
  - The curl is always safe-by-default (no destructive paths), and always
    includes -i (show headers) and -k (allow self-signed) for max compat
"""
from __future__ import annotations
import shlex
from urllib.parse import urlparse, parse_qs, urlencode, quote


def build(finding: dict) -> str:
    """
    Generate a single-line curl command that reproduces this finding.
    Return empty string if we can't build a useful command.
    """
    url = finding.get("url") or finding.get("target") or ""
    if not url:
        return ""

    method = (finding.get("method") or "GET").upper()
    payload = finding.get("payload", "")
    parameter = finding.get("parameter", "")
    phase = finding.get("phase", "")
    title = (finding.get("title") or "").lower()

    # Branch by finding type for cleanest curl
    if phase == "audit" or "sqli" in title or "xss" in title or "ssti" in title:
        return _build_audit_curl(url, method, parameter, payload, finding)

    if phase == "api_key_pivot":
        return _build_pivot_curl(finding)

    if phase == "protected_routes":
        return _build_anon_curl(url)

    if phase == "console_leaks":
        return _build_js_fetch_curl(url, hint=finding.get("evidence", ""))

    if "open redirect" in title or "redirect" in title:
        return _build_redirect_curl(url, parameter, payload)

    if "cors" in title:
        return _build_cors_curl(url)

    if "header" in title and ("injection" in title or "smuggling" in title or "cache" in title):
        return _build_header_curl(url, payload)

    if "method" in title and ("trace" in title or "options" in title or "put" in title):
        return _build_method_curl(url, method)

    if "subdomain takeover" in title:
        return _build_takeover_curl(url)

    # v2.10: cloud bucket findings get the full ownership-verification script
    if phase in ("cloud_recon", "cloud_recon_extended"):
        return _build_bucket_verification_curl(url)

    if phase == "backend_map":
        return _build_anon_curl(url)

    # Default: a simple GET with verbose headers
    return _build_basic_curl(url, method, payload, parameter)


# ──────────────────────────────────────────────────────────────────────────────
# Per-category builders
# ──────────────────────────────────────────────────────────────────────────────
def _build_audit_curl(url: str, method: str, parameter: str,
                      payload: str, finding: dict) -> str:
    """Audit phase: param injection (XSS/SQLi/SSTI/cmd inj)."""
    if not parameter or not payload:
        return _build_basic_curl(url, method, payload, parameter)

    if method == "GET":
        # Use -G with --data-urlencode so curl encodes the payload properly
        # AND keeps existing query string params intact
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        # Preserve existing params (besides the injected one)
        existing = parse_qs(parsed.query, keep_blank_values=True)
        existing.pop(parameter, None)
        parts = [f"curl -i -sk -G {shlex.quote(base)}"]
        for k, vs in existing.items():
            for v in vs:
                parts.append(f"--data-urlencode {shlex.quote(f'{k}={v}')}")
        parts.append(f"--data-urlencode {shlex.quote(f'{parameter}={payload}')}")
        return " \\\n     ".join(parts)

    # POST: send body with the payload
    body_field = f"{parameter}={payload}"
    return (f"curl -i -sk -X {method} {shlex.quote(url)} \\\n"
            f"     -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
            f"     --data-urlencode {shlex.quote(body_field)}")


def _build_pivot_curl(finding: dict) -> str:
    """API key pivot — show how to re-verify the key against the service."""
    title = (finding.get("title") or "").lower()
    # The payload field already has the partial key like "AIzaSy...byS4U"
    secret = finding.get("payload", "<API_KEY>")

    if "google" in title and "gemini" in title:
        return (f"# Verify Gemini API access\n"
                f"curl -sk 'https://generativelanguage.googleapis.com/v1beta/models?key={secret}'")
    if "google" in title and "maps" in title:
        return (f"# Verify Maps JS API enabled\n"
                f"curl -sk -o /dev/null -w '%{{http_code}}\\n' "
                f"'https://maps.googleapis.com/maps/api/js?key={secret}'")
    if "google" in title:
        return (f"# Verify Google API key state\n"
                f"curl -sk 'https://generativelanguage.googleapis.com/v1beta/models?key={secret}'\n"
                f"# If above returns 'API_KEY_SERVICE_BLOCKED' → key is real but service-restricted\n"
                f"# If 'API_KEY_INVALID' → key is invalid\n"
                f"# If 200 with model list → CRITICAL: exploitable")
    if "stripe" in title:
        return (f"# Verify Stripe key\n"
                f"curl -sk -u {secret}: 'https://api.stripe.com/v1/charges?limit=1'")
    if "github" in title:
        return (f"# Verify GitHub PAT scope\n"
                f"curl -sk -H 'Authorization: token {secret}' 'https://api.github.com/user'\n"
                f"# Check scopes header in response: X-OAuth-Scopes")
    if "slack" in title:
        return (f"# Verify Slack token\n"
                f"curl -sk -X POST 'https://slack.com/api/auth.test' "
                f"-d 'token={secret}'")
    if "sendgrid" in title:
        return (f"# Verify SendGrid key\n"
                f"curl -sk -H 'Authorization: Bearer {secret}' "
                f"'https://api.sendgrid.com/v3/user/profile'")
    if "firebase" in title:
        url = finding.get("url", "")
        return (f"# Verify Firebase RTDB anonymous read\n"
                f"curl -sk {shlex.quote(url.rstrip('/') + '/.json')}")
    return _build_basic_curl(finding.get("url", ""), "GET", "", "")


def _build_anon_curl(url: str) -> str:
    """Anonymous access test — no cookies, no auth."""
    return (f"# Anonymous access test (no auth, no cookies)\n"
            f"curl -i -sk {shlex.quote(url)} \\\n"
            f"     -H 'User-Agent: Mozilla/5.0' \\\n"
            f"     --cookie ''")


def _build_redirect_curl(url: str, parameter: str, payload: str) -> str:
    """Open redirect verification — show Location header."""
    if parameter and payload:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return (f"# Open redirect — check the Location: response header\n"
                f"curl -sk -o /dev/null -D - {shlex.quote(base)} \\\n"
                f"     --data-urlencode {shlex.quote(f'{parameter}={payload}')} -G \\\n"
                f"     | grep -i 'location:'")
    return (f"# Open redirect — check Location: response header\n"
            f"curl -sk -o /dev/null -D - {shlex.quote(url)} | grep -i 'location:'")


def _build_cors_curl(url: str) -> str:
    """CORS misconfiguration — send origin and inspect ACAO/ACAC."""
    return (f"# CORS test — check Access-Control-Allow-Origin and -Credentials\n"
            f"curl -i -sk -H 'Origin: https://attacker.example' {shlex.quote(url)} \\\n"
            f"     | grep -i 'access-control'")


def _build_header_curl(url: str, payload: str) -> str:
    """Header injection — show how to reproduce with the payload header."""
    return (f"# Header injection / cache poisoning test\n"
            f"curl -i -sk {shlex.quote(url)} \\\n"
            f"     -H 'X-Forwarded-Host: evil.example' \\\n"
            f"     -H 'X-Original-URL: /admin' \\\n"
            f"     -H 'X-Rewrite-URL: /admin' \\\n"
            f"     -H 'X-Forwarded-For: 127.0.0.1'")


def _build_method_curl(url: str, method: str) -> str:
    """Unusual HTTP method (TRACE, OPTIONS, PUT)."""
    return f"curl -i -sk -X {method or 'OPTIONS'} {shlex.quote(url)}"


def _build_takeover_curl(url: str) -> str:
    """Subdomain takeover — show the DNS + HTTP signature."""
    host = urlparse(url).hostname or url
    return (f"# Subdomain takeover verification\n"
            f"dig +short CNAME {host}\n"
            f"curl -i -sk {shlex.quote(url)}\n"
            f"# Look for: NoSuchBucket, 'There isn\\'t a GitHub Pages site here', etc.")


def _build_bucket_verification_curl(url: str) -> str:
    """
    v2.10: For cloud_recon and cloud_recon_extended findings — the full
    bucket ownership-verification script (lists contents, checks for prior
    research, downloads sample, total size, date range). The user MUST run
    this before reporting any cloud-bucket finding.
    """
    try:
        from core import ownership_confirm
        return ownership_confirm.build_bucket_verification_curl(url)
    except Exception:
        # Fallback: simple anonymous GET
        return f"curl -i -sk {shlex.quote(url)}"


def _build_js_fetch_curl(url: str, hint: str = "") -> str:
    """Fetch a JS file and grep for the leaking string."""
    needle = "console.log"
    # If the evidence quote contains a specific pattern, grep for it
    if "AIza" in hint:
        needle = "AIza"
    elif "sk_" in hint:
        needle = "sk_"
    elif "token" in hint.lower():
        needle = "token"
    return (f"# Fetch JS bundle and inspect console.* statements\n"
            f"curl -sk {shlex.quote(url)} | grep -oE '{needle}[^\"\\x27 ]{{10,80}}' | head -5")


def _build_basic_curl(url: str, method: str, payload: str, parameter: str) -> str:
    """Generic fallback."""
    if method in ("GET", "HEAD"):
        return f"curl -i -sk -X {method} {shlex.quote(url)}"
    return (f"curl -i -sk -X {method} {shlex.quote(url)} \\\n"
            f"     -H 'Content-Type: application/json' "
            f"-d {shlex.quote(payload or '{}')}")
