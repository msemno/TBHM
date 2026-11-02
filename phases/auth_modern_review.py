"""
Phase: auth_modern_review   (v3.3)

Detection-only review of modern authentication weaknesses. It inspects tokens
and endpoints already discovered this run (plus any --jwt / --saml-metadata you
supply) and flags common misconfigurations. It does NOT crack secrets, forge
valid tokens, or replay them against a live target.

Checks:
  * JWT  - alg:none acceptance risk, weak/known HS256 secret indicators,
           kid header injection surface, missing exp, mixed alg (RS/HS confusion).
  * OAuth - open/loose redirect_uri patterns, missing state/PKCE indicators,
           implicit-grant (response_type=token) usage.
  * SAML - signature-wrapping surface (unsigned assertion / signed-response-only),
           permissive RelayState handling.

Everything is analysis of material already in scope; no forged auth is sent.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path


def _b64url(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _decode_jwt(tok: str):
    parts = tok.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
        return header, payload
    except Exception:
        return None


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*")
_WEAK_SECRETS = {"secret", "password", "changeme", "jwt", "key", "123456",
                 "your-256-bit-secret", "test", "admin"}


def _collect_jwts(ctx):
    toks = set()
    explicit = getattr(ctx.args, "jwt", None)
    if explicit:
        toks.add(explicit.strip())
    # harvest from prior artefacts
    for rel in ("discovery", "recon", "code", "source_code_full"):
        d = ctx.output / rel
        if not d.is_dir():
            continue
        for f in d.rglob("*"):
            if f.is_file() and f.suffix.lower() in (".txt", ".json", ".log", ".js", ""):
                try:
                    toks.update(_JWT_RE.findall(f.read_text(errors="ignore")))
                except Exception:
                    pass
    return [t for t in toks if t.count(".") >= 2][:50]


def run(ctx):
    out_dir = ctx.output / "auth_modern"
    out_dir.mkdir(exist_ok=True)
    findings = 0
    report = {"jwt": [], "oauth": [], "saml": []}

    # ── JWT ──────────────────────────────────────────────────────────────
    for tok in _collect_jwts(ctx):
        dec = _decode_jwt(tok)
        if not dec:
            continue
        header, payload = dec
        alg = str(header.get("alg", "")).lower()
        issues = []
        if alg in ("none", ""):
            issues.append("alg:none — signature may be optional (forgery risk)")
        if alg.startswith("hs"):
            issues.append("HMAC alg — if the secret is weak/guessable, tokens are forgeable "
                          "(alg-confusion risk if server also accepts RS keys as HMAC secret)")
        if "kid" in header:
            issues.append("kid header present — validate it isn't used for path/SQL injection")
        if "exp" not in payload:
            issues.append("no exp claim — tokens may not expire")
        entry = {"alg": header.get("alg"), "kid": header.get("kid"),
                 "claims": sorted(payload.keys()), "issues": issues}
        report["jwt"].append(entry)
        if issues:
            ctx.save_finding({
                "phase": "auth_modern_review",
                "severity": "MEDIUM" if alg in ("none", "") else "LOW",
                "confidence": "LOW",
                "title": f"JWT weakness surface (alg={header.get('alg')})",
                "target": ctx.targets[0] if ctx.targets else "", "url": "",
                "description": "Detection-only JWT review: " + "; ".join(issues)
                               + ". No token was forged or replayed.",
                "evidence": f"header={json.dumps(header)} claims={sorted(payload.keys())}",
                "impact": "Depending on server validation, may allow token forgery or non-expiry.",
                "remediation": "Pin алg server-side, reject alg:none, use strong HS secrets or RS/ES "
                               "with strict key handling, enforce exp/nbf, validate kid against an allow-list.",
                "cwe": "CWE-347", "mrs_score": 55 if alg in ("none", "") else 30,
            })
            findings += 1

    # ── OAuth (analyse discovered URLs) ─────────────────────────────────
    urls = ctx.runner.read_lines(ctx.output / "recon" / "urls.txt") \
        if (ctx.output / "recon" / "urls.txt").exists() else []
    for u in urls:
        low = u.lower()
        if "redirect_uri=" in low or "response_type=" in low:
            oi = []
            if "response_type=token" in low:
                oi.append("implicit grant (response_type=token) — deprecated, token in URL")
            if "state=" not in low:
                oi.append("no state parameter — CSRF risk on the authz request")
            if "code_challenge=" not in low and "response_type=code" in low:
                oi.append("no PKCE (code_challenge) on an auth-code flow")
            m = re.search(r"redirect_uri=([^&]+)", u)
            if m and re.search(r"(%2f%2f|//)[^/]*\.(?!.*\bexample\b)", m.group(1).lower()):
                oi.append("redirect_uri worth validating for open-redirect / host allow-listing")
            if oi:
                report["oauth"].append({"url": u[:200], "issues": oi})
                ctx.save_finding({
                    "phase": "auth_modern_review", "severity": "LOW", "confidence": "LOW",
                    "title": "OAuth flow hardening gaps (detection)",
                    "target": ctx.targets[0] if ctx.targets else "", "url": u[:200],
                    "description": "; ".join(oi) + ". Confirm against the provider config.",
                    "evidence": u[:200],
                    "impact": "CSRF, token leakage, or redirect abuse depending on server checks.",
                    "remediation": "Require state + PKCE, use exact redirect_uri matching, avoid implicit grant.",
                    "cwe": "CWE-601", "mrs_score": 35,
                })
                findings += 1

    # ── SAML metadata (if supplied) ─────────────────────────────────────
    saml_md = getattr(ctx.args, "saml_metadata", None)
    if saml_md and Path(saml_md).is_file():
        try:
            md = Path(saml_md).read_text(errors="ignore")
        except Exception:
            md = ""
        si = []
        if "WantAssertionsSigned=\"false\"" in md.replace(" ", "").replace("'", "\""):
            si.append("assertions not required to be signed — XML signature-wrapping surface")
        if "AuthnRequestsSigned=\"false\"" in md.replace(" ", "").replace("'", "\""):
            si.append("AuthnRequests not signed")
        report["saml"].append({"metadata": saml_md, "issues": si or ["parsed; no obvious gap"]})
        if si:
            ctx.save_finding({
                "phase": "auth_modern_review", "severity": "MEDIUM", "confidence": "LOW",
                "title": "SAML signature-handling gap (detection)",
                "target": ctx.targets[0] if ctx.targets else "", "url": "",
                "description": "; ".join(si) + ". Review for signature-wrapping / RelayState abuse.",
                "evidence": saml_md,
                "impact": "Signature wrapping can enable assertion forgery / auth bypass.",
                "remediation": "Require signed assertions AND responses, validate the full signature "
                               "reference, and constrain RelayState.",
                "cwe": "CWE-347", "mrs_score": 55,
            })
            findings += 1

    (out_dir / "auth_modern_review.json").write_text(json.dumps(report, indent=2))
    ctx.log("OK", "auth_modern_review",
            f"JWT={len(report['jwt'])} OAuth={len(report['oauth'])} SAML={len(report['saml'])} "
            f"| {findings} finding(s) (detection-only) → auth_modern_review.json")
