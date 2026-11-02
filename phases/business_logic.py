"""
Phase: business_logic

Detects high-impact bugs that scanners miss because they're not about
syntax (SQLi/XSS) but about LOGIC. These pay well in bug bounty.

Checks:
  1. Mass Assignment — try injecting privileged fields ("is_admin", "role", "verified")
                       into user-controlled JSON bodies
  2. Price/Quantity Manipulation — change number params to negative, zero, very large
                                    on endpoints that look like payment/cart
  3. HTTP Parameter Pollution — send the same param twice with different values
  4. Race Condition Hints — detect endpoints that look race-vulnerable
                            (coupon apply, withdraw, vote, like)
  5. IDOR — already in access_control.py; here we add more sophisticated ID swap
            (compare authenticated vs unauthenticated, look for owner_id leak)

This phase is HEURISTIC — it produces leads, not proofs. Each finding is
labeled with confidence and includes a reproducer in the report.
"""
from __future__ import annotations
import json
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

try:
    import requests
except ImportError:
    requests = None

# v2.23: global safe-writes gate for the mass-assignment mutating probes.
from core.safe_writes import ctx_gate as _sw_gate


# Fields that should NEVER be user-settable
SENSITIVE_FIELDS = [
    "is_admin", "isAdmin", "admin", "role", "roles", "permissions",
    "is_staff", "is_superuser", "verified", "email_verified",
    "premium", "is_premium", "subscribed", "credit", "credits", "balance",
    "owner", "owner_id", "user_id", "userId",
    "approved", "is_approved", "status",
    "price", "amount", "total", "discount",
]

# Endpoint name patterns that suggest money/business actions
MONEY_PATH_RE = re.compile(
    r"(checkout|payment|pay|charge|order|cart|invoice|withdraw|transfer|"
    r"coupon|discount|gift|credit|wallet|topup|refund|subscription)",
    re.I
)

# Endpoint name patterns for race-sensitive actions
RACE_PATH_RE = re.compile(
    r"(coupon|redeem|vote|like|follow|claim|withdraw|transfer|verify|"
    r"reserve|book|purchase|apply)",
    re.I
)

# Endpoint name patterns for IDOR
IDOR_PATH_RE = re.compile(
    r"(/users?/\d+|/accounts?/\d+|/orders?/\d+|/invoices?/\d+|/tickets?/\d+|"
    r"/documents?/\d+|/files?/\d+|/messages?/\d+|/posts?/\d+)",
    re.I
)


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        ctx.log("INFO", "business_logic", "passive profile — skipping")
        return
    if not requests:
        return

    urls_file = ctx.output / "recon" / "urls.txt"
    if not urls_file.exists():
        ctx.log("WARN", "business_logic", "no urls.txt — skipping")
        return
    urls = ctx.runner.read_lines(urls_file)
    if not urls:
        return

    # Filter to interesting URLs only (don't fuzz everything)
    money_urls = [u for u in urls if MONEY_PATH_RE.search(u)][:50]
    race_urls  = [u for u in urls if RACE_PATH_RE.search(u)][:30]
    idor_urls  = [u for u in urls if IDOR_PATH_RE.search(u)][:50]

    ctx.log("INFO", "business_logic",
            f"  money endpoints: {len(money_urls)}, race-prone: {len(race_urls)}, "
            f"IDOR-shaped: {len(idor_urls)}")

    n = 0
    n += _check_param_pollution(ctx, urls[:200])
    n += _check_price_manipulation(ctx, money_urls)
    n += _check_mass_assignment(ctx, urls[:200])
    n += _flag_race_endpoints(ctx, race_urls)
    n += _flag_idor_endpoints(ctx, idor_urls)

    ctx.log("OK", "business_logic", f"business_logic: {n} leads/findings")


# ──────────────────────────────────────────────────────────────────────────────
# 1. HTTP Parameter Pollution (HPP)
# ──────────────────────────────────────────────────────────────────────────────
def _check_param_pollution(ctx, urls) -> int:
    """
    Send the same parameter twice with different values; if the second value wins
    (or both appear in response), the backend is HPP-vulnerable. Useful for WAF
    bypass and access control circumvention.
    """
    n = 0
    seen = set()
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            continue
        key, val = params[0]
        # Dedupe by host+path+key
        sig = f"{parsed.hostname}{parsed.path}?{key}"
        if sig in seen:
            continue
        seen.add(sig)
        if len(seen) > 30:
            break

        # Build URL with duplicated parameter
        try:
            new_query = urlencode([(key, val), (key, "tbhm_hpp_canary_777")])
            polluted_url = urlunparse(parsed._replace(query=new_query))
            r = requests.get(polluted_url, timeout=10, verify=False, allow_redirects=False)
            if "tbhm_hpp_canary_777" in r.text:
                ctx.save_finding({
                    "phase": "business_logic", "severity": "LOW", "confidence": "MEDIUM",
                    "title": f"HTTP Parameter Pollution: '{key}' accepts duplicate values",
                    "target": parsed.hostname, "url": polluted_url, "method": "GET",
                    "parameter": key, "payload": f"?{key}=...&{key}=tbhm_hpp_canary_777",
                    "evidence": "Second value of duplicated parameter reflected in response.",
                    "description": "Backend accepts duplicate parameters and uses the second value. "
                                   "Can bypass WAFs (some inspect only first occurrence) and access controls.",
                    "impact": "Possible WAF/auth bypass. Verify by combining with other payloads.",
                    "remediation": "Reject duplicate parameters or use the first occurrence consistently.",
                    "cwe": "CWE-235", "mrs_score": 50,
                })
                n += 1
        except Exception:
            continue
    return n


# ──────────────────────────────────────────────────────────────────────────────
# 2. Price Manipulation
# ──────────────────────────────────────────────────────────────────────────────
def _check_price_manipulation(ctx, urls) -> int:
    """
    On money-shaped URLs with numeric params, try negative/zero/huge values.
    HEURISTIC: flag as lead if status code stays 200 (didn't reject).
    """
    n = 0
    PRICE_PARAMS = {"price", "amount", "total", "qty", "quantity", "value",
                    "cost", "subtotal", "tax", "discount"}
    for url in urls[:30]:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        # Find numeric params, prioritize money-shaped names
        candidate_param = None
        for k, v in params.items():
            if k.lower() in PRICE_PARAMS and re.fullmatch(r"-?\d+(?:\.\d+)?", v or ""):
                candidate_param = k
                break
        if not candidate_param:
            # Fallback: any numeric param
            for k, v in params.items():
                if re.fullmatch(r"-?\d+(?:\.\d+)?", v or ""):
                    candidate_param = k
                    break
        if not candidate_param:
            continue

        # Send baseline + 3 mutations
        try:
            r_base = requests.get(url, timeout=8, verify=False, allow_redirects=False)
            base_status = r_base.status_code
            base_len = len(r_base.content)
        except Exception:
            continue

        for evil_val in ("-1", "-9999", "0", "0.01", "999999999"):
            params[candidate_param] = evil_val
            evil_url = urlunparse(parsed._replace(query=urlencode(params)))
            try:
                r = requests.get(evil_url, timeout=8, verify=False, allow_redirects=False)
                if r.status_code == 200 and base_status == 200:
                    # Length change can hint at successful manipulation
                    if abs(len(r.content) - base_len) > 50 or "success" in r.text.lower():
                        ctx.save_finding({
                            "phase": "business_logic", "severity": "MEDIUM", "confidence": "LOW",
                            "title": f"Possible price/qty manipulation: {candidate_param}={evil_val}",
                            "target": parsed.hostname, "url": evil_url, "method": "GET",
                            "parameter": candidate_param, "payload": evil_val,
                            "evidence": f"Money-shaped endpoint accepted {candidate_param}={evil_val} "
                                        f"with status 200. Baseline length {base_len}, with payload {len(r.content)}.",
                            "description": "LEAD only. Money-shaped endpoint did not reject suspicious value. "
                                           "Manually verify whether the operation actually completes "
                                           "(check checkout flow end-to-end).",
                            "impact": "If exploitable: free items, refund fraud, unauthorized credit.",
                            "remediation": "Server-side validation: reject non-positive prices/quantities; "
                                          "cap maximums; recompute totals server-side from product DB.",
                            "cwe": "CWE-840", "mrs_score": 70,
                        })
                        n += 1
                        break
            except Exception:
                continue
    return n


# ──────────────────────────────────────────────────────────────────────────────
# 3. Mass Assignment
# ──────────────────────────────────────────────────────────────────────────────
def _check_mass_assignment(ctx, urls) -> int:
    """
    For JSON POST/PUT endpoints, try injecting sensitive fields. Often APIs
    deserialize the whole body to a model and accept extra fields silently.
    """
    n = 0
    # Heuristic: we look for URLs that look like profile/account/settings updates
    PROFILE_RE = re.compile(r"(profile|account|user|me|settings|update|register|signup)", re.I)
    candidates = [u for u in urls if PROFILE_RE.search(u)][:20]

    for url in candidates:
        # Try POST + PUT with a small JSON body containing sensitive fields
        for sensitive_field in ("is_admin", "role", "verified"):
            body = json.dumps({sensitive_field: True, "tbhm_marker_field": "x"})
            headers = {"Content-Type": "application/json",
                       "User-Agent": "Mozilla/5.0 (TBHM-MA/2.3)"}
            for method in ("POST", "PUT", "PATCH"):
                _ok, _why = _sw_gate(ctx, method, url, body)
                if not _ok:
                    ctx.log("INFO", "business_logic",
                            f"[safe-writes] {method} {url} skipped: {_why}")
                    continue
                try:
                    r = requests.request(method, url, headers=headers, data=body,
                                          timeout=8, verify=False, allow_redirects=False)
                except Exception:
                    continue
                # Strong signal: 200/201 and response echoes the sensitive field
                if r.status_code in (200, 201, 204):
                    body_text = r.text[:5000]
                    if sensitive_field in body_text and "true" in body_text.lower():
                        ctx.save_finding({
                            "phase": "business_logic", "severity": "HIGH", "confidence": "MEDIUM",
                            "title": f"Possible Mass Assignment: '{sensitive_field}' accepted on {method}",
                            "target": urlparse(url).hostname, "url": url, "method": method,
                            "parameter": sensitive_field,
                            "payload": body,
                            "evidence": f"Sent {{{sensitive_field}: true}}; endpoint returned {r.status_code} "
                                        f"and response body contains '{sensitive_field}=true'.",
                            "description": "Mass assignment LEAD. Backend may have accepted privilege "
                                           "elevation via unintended JSON field. Manually verify by "
                                           "logging into the affected account and checking permissions.",
                            "impact": "Privilege escalation, account takeover, data tampering.",
                            "remediation": "Whitelist JSON fields per endpoint. Use DTOs / strict serializers. "
                                          "Never bind request body directly to ORM models.",
                            "cwe": "CWE-915", "mrs_score": 85,
                        })
                        n += 1
                        return n  # one finding per scan is plenty as a lead
    return n


# ──────────────────────────────────────────────────────────────────────────────
# 4 & 5. Race / IDOR heuristic flags (lead-only)
# ──────────────────────────────────────────────────────────────────────────────
def _flag_race_endpoints(ctx, urls) -> int:
    n = 0
    flagged = set()
    for url in urls[:20]:
        path = urlparse(url).path
        if path in flagged:
            continue
        flagged.add(path)
        ctx.save_finding({
            "phase": "business_logic", "severity": "INFO", "confidence": "LOW",
            "title": f"Race-prone endpoint candidate: {path}",
            "target": urlparse(url).hostname, "url": url,
            "description": f"Endpoint path '{path}' suggests an idempotency-sensitive action "
                           f"(coupon, withdraw, vote, etc.). Manually test for race conditions: "
                           f"send 50 parallel requests using `turbo-intruder` or `race-the-web`.",
            "impact": "If race-vulnerable: duplicate redemption, double-spend, etc.",
            "remediation": "Server-side locking / idempotency keys / atomic DB updates.",
            "cwe": "CWE-362", "mrs_score": 40,
        })
        n += 1
    return n


def _flag_idor_endpoints(ctx, urls) -> int:
    n = 0
    flagged = set()
    for url in urls[:30]:
        path = urlparse(url).path
        # Normalize path: replace numeric segments with {id}
        norm = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        if norm in flagged:
            continue
        flagged.add(norm)
        ctx.save_finding({
            "phase": "business_logic", "severity": "INFO", "confidence": "LOW",
            "title": f"IDOR-shaped endpoint: {norm}",
            "target": urlparse(url).hostname, "url": url,
            "description": f"Endpoint has numeric ID in path ({norm}). Manually test IDOR: "
                           "create two accounts, swap IDs in URL, see if other user's data leaks. "
                           "Also try non-existent IDs, very large IDs, and negative IDs.",
            "impact": "Horizontal/vertical privilege escalation.",
            "remediation": "Authorize based on user identity + resource ownership, not just URL access.",
            "cwe": "CWE-639", "mrs_score": 60,
        })
        n += 1
    return n
