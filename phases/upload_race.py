"""Phase: upload_race - file upload, race conditions, prototype-pollution hints."""
from __future__ import annotations

try:
    import requests
except ImportError:
    requests = None

# v2.23: gate the upload POST probe through the global safe-writes gate.
from core.safe_writes import ctx_gate as _sw_gate

UPLOAD_PATHS = ["/upload", "/api/upload", "/api/v1/upload",
                "/file/upload", "/files/upload", "/avatar/upload"]


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        return
    if not ctx.profile.get("send_payloads", False):
        return
    from core.targets import get_domains
    for primary in get_domains(ctx):
        _upload_probe(ctx, primary)
    _proto_pollution_hints(ctx)


def _upload_probe(ctx, primary):
    """Light probe - just see if upload endpoints exist + probe for double-extension."""
    if not requests:
        return
    benign_content = b"GIF89a;\n<!-- TBHM probe; harmless test file -->\n"
    for path in UPLOAD_PATHS:
        url = f"https://{primary}{path}"
        _ok, _why = _sw_gate(ctx, "POST", url, "upload-probe")
        if not _ok:
            ctx.log("INFO", "upload_race", f"[safe-writes] upload probe {url} skipped: {_why}")
            continue
        try:
            r = requests.post(url,
                              files={"file": ("test.gif.html", benign_content, "image/gif")},
                              timeout=10)
        except Exception:
            continue
        from core import soft404
        if r.status_code in (200, 201, 204) and not soft404.is_catch_all(url, r.status_code, r.text):
            stored_loc = ""
            for h in ("Location", "location"):
                if h in r.headers:
                    stored_loc = r.headers[h]; break
            ctx.save_finding({
                "phase": "upload_race", "severity": "INFO", "confidence": "LOW",
                "title": f"Upload endpoint accepted double-extension test file: {path}",
                "target": primary, "url": url, "method": "POST",
                "evidence": f"Status: {r.status_code}; Location: {stored_loc}",
                "description": "An upload endpoint accepted a file named test.gif.html. "
                               "Verify whether it's served as HTML when fetched (XSS) or as "
                               "a static download.",
                "impact": "If served as HTML/JS: stored XSS or RCE depending on server config.",
                "remediation": "Validate by content, not extension. Serve uploads from a "
                               "separate origin with X-Content-Type-Options: nosniff.",
                "cwe": "CWE-434", "mrs_score": 70,
            })


def _proto_pollution_hints(ctx):
    """Look at param names for hints of prototype-pollution-prone code paths."""
    params_file = ctx.output / "recon" / "params.txt"
    if not params_file.exists():
        return
    params = ctx.runner.read_lines(params_file)
    suspicious = [p for p in params
                  if p.lower() in ("__proto__", "constructor", "prototype")]
    if suspicious:
        ctx.save_finding({
            "phase": "upload_race", "severity": "MEDIUM", "confidence": "LOW",
            "title": "Prototype-pollution-prone parameter names detected",
            "target": ctx.targets[0],
            "evidence": ", ".join(suspicious),
            "description": "App accepts parameter names like __proto__/constructor. "
                           "If these reach a deep-merge or Object.assign without filtering, "
                           "prototype pollution is possible.",
            "impact": "App-wide property override; may chain to RCE in Express apps.",
            "remediation": "Filter __proto__/constructor/prototype keys in merge functions. "
                           "Use Object.create(null) or Map for untrusted-key dictionaries.",
            "cwe": "CWE-1321", "mrs_score": 60,
        })
