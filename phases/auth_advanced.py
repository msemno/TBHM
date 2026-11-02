"""Phase: auth_advanced - 2FA paths, JWT audit, OAuth callback flags."""
from __future__ import annotations
import base64
import json
import re

try:
    import requests
except ImportError:
    requests = None

TFA_PATHS = ["/api/v1/auth/2fa/disable", "/api/2fa/disable",
             "/account/2fa/remove", "/settings/2fa/disable",
             "/api/auth/skip-2fa", "/2fa/skip"]


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        return
    urls_file = ctx.output / "recon" / "urls.txt"
    urls = ctx.runner.read_lines(urls_file) if urls_file.exists() else []
    _jwt_audit(ctx, urls)
    _tfa_surfaces(ctx)
    _oauth_flags(ctx, urls)


def _b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _audit_jwt(token):
    issues = []
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return []
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
    except Exception:
        return []
    alg = header.get("alg", "").lower()
    if alg == "none":
        issues.append({
            "severity": "CRITICAL", "title": "JWT alg=none accepted",
            "evidence": json.dumps(header),
            "description": "Token uses 'none' alg - signature not verified.",
            "impact": "Attacker can forge any token.",
            "remediation": "Reject alg=none. Pin allowed algs.",
        })
    if "exp" not in payload:
        issues.append({
            "severity": "MEDIUM", "title": "JWT has no expiry claim",
            "evidence": json.dumps(payload)[:200],
            "description": "Token has no `exp` - reusable forever if leaked.",
            "impact": "Stolen tokens valid indefinitely.",
            "remediation": "Always include `exp`; rotate tokens.",
        })
    return issues


def _jwt_audit(ctx, urls):
    pat = re.compile(r"eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{0,}")
    n = 0
    for u in urls[:200]:
        m = pat.search(u)
        if not m:
            continue
        for issue in _audit_jwt(m.group(0)):
            ctx.save_finding({
                "phase": "auth_advanced",
                "severity": issue["severity"], "confidence": "HIGH",
                "title": issue["title"], "target": ctx.targets[0], "url": u[:500],
                "evidence": issue["evidence"][:300],
                "description": issue["description"],
                "impact": issue.get("impact", ""),
                "remediation": issue.get("remediation", ""),
                "cwe": "CWE-347", "mrs_score": 90,
            })
            n += 1
    if n:
        ctx.log("OK", "auth_advanced", f"{n} JWT issues")


def _tfa_surfaces(ctx):
    if not requests:
        return
    from core.targets import get_domains
    for primary in get_domains(ctx):
        for path in TFA_PATHS:
            url = f"https://{primary}{path}"
            try:
                r = requests.get(url, timeout=8, allow_redirects=False)
                from core import soft404
                if r.status_code in (200, 201, 204) and not soft404.is_catch_all(url, r.status_code, r.text):
                    ctx.save_finding({
                        "phase": "auth_advanced", "severity": "INFO", "confidence": "LOW",
                        "title": f"2FA endpoint accessible: {path}",
                        "target": primary, "url": url, "method": "GET",
                        "evidence": f"Status: {r.status_code}",
                        "description": "Endpoint matching 2FA-disable paths returned non-error. "
                                       "Manually test whether 2FA removal requires re-auth + OTP.",
                        "impact": "Possible 2FA bypass if no re-auth required.",
                        "remediation": "Require re-auth + OTP before 2FA modification.",
                        "cwe": "CWE-287", "mrs_score": 60,
                    })
            except Exception:
                continue


def _oauth_flags(ctx, urls):
    cb = [u for u in urls if any(k in u.lower() for k in ("/callback", "/oauth", "code="))]
    for u in cb[:10]:
        ctx.save_finding({
            "phase": "auth_advanced", "severity": "INFO", "confidence": "LOW",
            "title": "OAuth callback detected (manual review)",
            "target": ctx.targets[0], "url": u[:500],
            "description": "Manually review: redirect_uri whitelist strictness, "
                           "state/PKCE validation, code reuse, ATO via redirect_uri.",
            "impact": "Possible ATO via OAuth misconfig.",
            "remediation": "Strict redirect_uri whitelist. PKCE. State validation.",
            "cwe": "CWE-601", "mrs_score": 50,
        })
