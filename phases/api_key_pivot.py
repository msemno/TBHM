"""
Phase: api_key_pivot

When a secret is found in JS, identify WHICH service it belongs to and
test the RELEVANT endpoints for that service. This is the workflow the
user did manually for Google API keys — now automated.

Services covered:
  - Google API (Maps + Gemini + Geocoding + Places)
  - Stripe (live + test keys)
  - GitHub (PAT + OAuth)
  - Slack (bot/user tokens)
  - AWS (Access Key ID, but only metadata-style checks; we DON'T sign requests)
  - Twilio Account SID + Auth Token
  - SendGrid
  - Mapbox
  - Firebase

The goal is to upgrade findings from "key found in JS" (info) to
"key found AND verified active on service X" (high).
"""
from __future__ import annotations
import re
import time
from pathlib import Path

from core import anti_block

try:
    import requests
except ImportError:
    requests = None


# ──────────────────────────────────────────────────────────────────────────────
# Service detection
# ──────────────────────────────────────────────────────────────────────────────
SERVICE_PATTERNS = [
    ("google_api",    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_live",   re.compile(r"\bsk_live_[0-9a-zA-Z]{24,99}\b")),
    ("stripe_pub",    re.compile(r"\bpk_live_[0-9a-zA-Z]{24,99}\b")),
    ("stripe_test",   re.compile(r"\bsk_test_[0-9a-zA-Z]{24,99}\b")),
    ("github_pat",    re.compile(r"\bghp_[0-9a-zA-Z]{36,76}\b")),
    ("github_fine",   re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82,}\b")),
    ("slack_bot",     re.compile(r"\bxoxb-[0-9]{10,15}-[0-9]{10,15}-[0-9a-zA-Z]{20,40}\b")),
    ("slack_user",    re.compile(r"\bxoxp-[0-9]{10,15}-[0-9]{10,15}-[0-9]{10,15}-[0-9a-f]{30,40}\b")),
    ("aws_key_id",    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("twilio_sid",    re.compile(r"\bAC[0-9a-f]{32}\b")),
    ("sendgrid",      re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("mapbox",        re.compile(r"\bpk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("firebase_db",   re.compile(r"\bhttps://[a-z0-9.\-]+\.firebaseio\.com\b")),
]


def run(ctx):
    if not requests:
        return
    # Find secrets from the run-scoped sealed vault (primary), the legacy
    # plaintext file (compat), and saved findings (fallback).
    from core import secret_vault
    secrets_file = ctx.output / "recon" / "js_secrets.txt"
    sealed = secret_vault.unseal(ctx)
    discovered = _collect_secrets(secrets_file, ctx.storage.all_findings(), sealed)
    if not discovered:
        ctx.log("INFO", "api_key_pivot", "no secrets to pivot on")
        return

    # v2.23: live third-party key verification is an active, outbound action.
    # Under passive_only (or when writes are disabled and the profile is passive)
    # do NOT contact vendor APIs — just record the secrets as UNVERIFIED leads so
    # the finding is honest and no external call is made.
    from core.safe_writes import _profile_name as _pname
    _profile = _pname(ctx)
    if _profile == "passive_only":
        for service, secret, source in discovered:
            ctx.save_finding({
                "phase": "api_key_pivot", "severity": "MEDIUM", "confidence": "LOW",
                "title": f"Potential {service} secret found (UNVERIFIED — passive mode)",
                "target": source,
                "url": source if source.startswith("http") else "",
                "payload": f"{secret[:6]}...{secret[-4:]}",
                "evidence": "Secret located in client-side material. Live verification "
                            "was skipped because the profile is passive_only.",
                "description": f"A possible {service} secret was found in {source}. It was "
                               "NOT verified against the live service (passive mode). Treat "
                               "as a lead and validate manually or re-run with an active profile.",
                "impact": "If valid, may allow access to the associated third-party service.",
                "remediation": "Rotate the secret and move it server-side. Verify manually.",
                "cwe": "CWE-798", "mrs_score": 50,
            })
        ctx.log("OK", "api_key_pivot",
                f"passive mode: {len(discovered)} secret(s) recorded as UNVERIFIED leads")
        return

    ctx.log("INFO", "api_key_pivot",
            f"━━━ Pivoting on {len(discovered)} discovered secret(s) ━━━")

    n = 0
    for service, secret, source in discovered:
        try:
            result = _pivot(service, secret)
        except Exception as e:
            ctx.log("WARN", "api_key_pivot", f"  {service} pivot error: {e}")
            continue
        if not result:
            continue
        sev, conf, title, evidence, impact = result
        ctx.save_finding({
            "phase": "api_key_pivot", "severity": sev, "confidence": conf,
            "title": title,
            "target": source,
            "url": source if source.startswith("http") else "",
            "payload": f"{secret[:6]}...{secret[-4:]}",   # redacted
            "evidence": evidence,
            "description": f"A {service} secret found in {source} was verified "
                           "against the live service endpoint. The response indicates "
                           "the secret is real and may be exploitable.",
            "impact": impact,
            "remediation": "Rotate the secret immediately. Move secrets to backend / "
                          "environment variables. Apply scope restrictions where supported.",
            "cwe": "CWE-798", "mrs_score": 90 if sev in ("CRITICAL", "HIGH") else 60,
        })
        n += 1
        time.sleep(1)   # be very gentle with 3rd-party verification

    ctx.log("OK", "api_key_pivot", f"api_key_pivot: {n} verified findings")


# ──────────────────────────────────────────────────────────────────────────────
# Per-service pivot probes (read-only, no destructive ops)
# ──────────────────────────────────────────────────────────────────────────────
def _pivot(service: str, secret: str):
    if service == "google_api":
        return _pivot_google(secret)
    if service in ("stripe_live", "stripe_test"):
        return _pivot_stripe(secret)
    if service == "stripe_pub":
        return ("LOW", "HIGH",
                "Stripe publishable key (pk_live) found",
                "Publishable keys are designed to be public — informational only. "
                "Verify the secret key (sk_live) is NOT exposed alongside.",
                "Low. These keys can only create tokens, not charge cards.")
    if service in ("github_pat", "github_fine"):
        return _pivot_github(secret)
    if service in ("slack_bot", "slack_user"):
        return _pivot_slack(secret)
    if service == "aws_key_id":
        # We don't sign AWS requests (would require secret). Just flag.
        return ("MEDIUM", "MEDIUM",
                "AWS Access Key ID found in client code",
                "AWS Access Key IDs are not secrets by themselves but indicate the "
                "secret key may be nearby. Search the surrounding JS for the "
                "matching AWS_SECRET_ACCESS_KEY.",
                "Information disclosure. If the matching secret is also exposed, "
                "attackers can sign AWS API requests on behalf of the account.")
    if service == "twilio_sid":
        return _pivot_twilio(secret)
    if service == "sendgrid":
        return _pivot_sendgrid(secret)
    if service == "firebase_db":
        return _pivot_firebase(secret)
    if service == "mapbox":
        return ("INFO", "MEDIUM",
                "Mapbox public token found",
                "Mapbox 'pk' tokens are designed to be public. Only worth reporting "
                "if scoped to write or admin permissions (rare).",
                "Usually low — verify scopes at https://account.mapbox.com/")
    return None


def _pivot_google(key: str):
    # Try the Maps JS endpoint first (cheapest)
    try:
        r = requests.get(f"https://maps.googleapis.com/maps/api/js?key={key}", timeout=10)
        if r.status_code == 200 and "google" in r.text.lower() and "function" in r.text:
            return ("HIGH", "HIGH",
                    "Google API key with Maps JavaScript API ENABLED",
                    f"GET https://maps.googleapis.com/maps/api/js?key={key[:10]}... → "
                    f"200 with JS payload. Key is active.",
                    "Exhaust quota / billing abuse. Test other Google APIs (Gemini, "
                    "Geocoding) for higher impact.")
    except Exception:
        pass
    # Try Gemini ListModels
    try:
        r = requests.get("https://generativelanguage.googleapis.com/v1beta/models",
                         params={"key": key}, timeout=10)
        if r.status_code == 200 and "models" in r.text:
            return ("CRITICAL", "HIGH",
                    "Google API key with Gemini API ENABLED",
                    f"GET .../models?key={key[:10]}... → 200 with model list. "
                    f"Attacker can run Gemini queries on the project.",
                    "Quota/billing abuse + unauthorized AI inference on owner account.")
        # Even an error reveals state
        if "API_KEY_SERVICE_BLOCKED" in r.text:
            return ("INFO", "HIGH",
                    "Google API key recognized but Gemini API service-blocked",
                    "Key was previously enabled or recently restricted on Gemini. "
                    "Response: API_KEY_SERVICE_BLOCKED. Worth reporting as "
                    "informational secret-management finding.",
                    "Low impact today. Standing risk if restrictions are relaxed.")
    except Exception:
        pass
    # Final check: is the key even recognized?
    try:
        r = requests.get(f"https://www.googleapis.com/oauth2/v3/userinfo?key={key}",
                         timeout=10)
        if "invalid" in r.text.lower():
            return None
    except Exception:
        pass
    return ("LOW", "MEDIUM",
            "Google API key found (no enabled services detected)",
            "Key appears to be recognized by Google but all tested services rejected it. "
            "Run gmapsapiscanner / Google-Map-Api-Key-Tester manually for full coverage.",
            "Standing risk — secret in client code is bad hygiene even when restricted.")


def _pivot_stripe(key: str):
    # GET /v1/charges with the key — Stripe returns 200 with charges list if key works
    try:
        r = requests.get("https://api.stripe.com/v1/charges", timeout=10,
                         auth=(key, ""))
        if r.status_code == 200:
            return ("CRITICAL", "HIGH",
                    f"Stripe {'live' if 'live' in key else 'test'} SECRET key works",
                    f"GET api.stripe.com/v1/charges with {key[:10]}... → 200. "
                    f"Key has full account access.",
                    "Full Stripe account access: read/write charges, customers, payouts. "
                    "Live secret keys = direct money manipulation.")
        if r.status_code == 401:
            return ("INFO", "HIGH",
                    "Stripe secret key found but invalid/revoked",
                    f"Stripe returned 401 for the key. Likely revoked.",
                    "Low — already invalidated.")
    except Exception:
        pass
    return None


def _pivot_github(token: str):
    try:
        r = requests.get("https://api.github.com/user",
                         headers={"Authorization": f"token {token}",
                                  "Accept": "application/vnd.github+json"},
                         timeout=10)
        if r.status_code == 200:
            data = r.json()
            login = data.get("login", "?")
            return ("CRITICAL", "HIGH",
                    f"GitHub PAT valid for user '{login}'",
                    f"GET api.github.com/user with token {token[:10]}... → 200, "
                    f"login='{login}'. Token has at least 'user' scope.",
                    "Repository/account compromise. Check scopes — if 'repo' is "
                    "included, attacker can read/write private code.")
        if r.status_code == 401:
            return ("INFO", "HIGH",
                    "GitHub PAT found but invalid",
                    "Token returned 401 — already revoked.",
                    "Low — invalidated.")
    except Exception:
        pass
    return None


def _pivot_slack(token: str):
    try:
        r = requests.post("https://slack.com/api/auth.test",
                          data={"token": token}, timeout=10)
        if r.ok and r.json().get("ok"):
            team = r.json().get("team", "?")
            user = r.json().get("user", "?")
            return ("CRITICAL", "HIGH",
                    f"Slack token valid (team={team}, user={user})",
                    f"auth.test → ok:true, team={team}, user={user}.",
                    "Read/write Slack messages, files, channels. Often used for "
                    "lateral movement and sensitive data exfil.")
    except Exception:
        pass
    return None


def _pivot_twilio(sid: str):
    # We don't have the auth token, so just confirm the SID format
    return ("MEDIUM", "MEDIUM",
            "Twilio Account SID exposed",
            f"Twilio Account SID {sid[:8]}... found. Without the Auth Token, we cannot "
            "verify exploitability, but SIDs in client code suggest the Auth Token "
            "may be exposed nearby.",
            "If matching Auth Token is also exposed: send/read SMS, place calls on "
            "the account.")


def _pivot_sendgrid(key: str):
    try:
        r = requests.get("https://api.sendgrid.com/v3/user/profile",
                         headers={"Authorization": f"Bearer {key}"}, timeout=10)
        if r.status_code == 200:
            return ("CRITICAL", "HIGH",
                    "SendGrid API key valid",
                    "GET api.sendgrid.com/v3/user/profile → 200. Key is active.",
                    "Send emails on behalf of the account, view stats, manage "
                    "subscriptions. Often used for phishing.")
    except Exception:
        pass
    return None


def _pivot_firebase(url: str):
    try:
        r = requests.get(url.rstrip("/") + "/.json", timeout=8)
        if r.status_code == 200 and r.text.strip() not in ("null", ""):
            return ("CRITICAL", "HIGH",
                    "Firebase RTDB allows anonymous read",
                    f"GET {url}/.json → 200 with content. Root readable without auth.",
                    "Full database exposure — users, messages, sensitive state.")
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Collect candidate secrets
# ──────────────────────────────────────────────────────────────────────────────
def _collect_secrets(secrets_file: Path, findings: list[dict], sealed: list[dict] | None = None):
    """Return list of (service, secret, source_url)."""
    out = []
    seen = set()
    # 0. From the run-scoped sealed vault produced by js_analysis (primary).
    for row in (sealed or []):
        value = str(row.get("match") or "")
        url = str(row.get("url") or "")
        if not value:
            continue
        for service, pat in SERVICE_PATTERNS:
            for m in pat.finditer(value):
                s = m.group(0)
                if s not in seen:
                    seen.add(s)
                    out.append((service, s, url or "sealed-vault"))
    # 1. From js_secrets.txt produced by discovery phase
    if secrets_file.exists():
        text = secrets_file.read_text(errors="ignore")
        for service, pat in SERVICE_PATTERNS:
            for m in pat.finditer(text):
                s = m.group(0)
                if s not in seen:
                    seen.add(s)
                    out.append((service, s, str(secrets_file.name)))
    # 2. From existing findings (the evidence field often quotes the secret)
    for f in findings:
        ev = (f.get("evidence", "") or "") + (f.get("payload", "") or "")
        for service, pat in SERVICE_PATTERNS:
            for m in pat.finditer(ev):
                s = m.group(0)
                if s not in seen:
                    seen.add(s)
                    out.append((service, s, f.get("url") or f.get("target", "")))
    return out
