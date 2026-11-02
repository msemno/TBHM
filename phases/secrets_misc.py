"""Phase: secrets_misc - .git/.env, host header injection, security headers, dangerous HTTP methods."""
from __future__ import annotations

try:
    import requests
except ImportError:
    requests = None

EXPOSURE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.git/index",
    "/.svn/entries", "/.DS_Store", "/web.config",
    "/config.json", "/config.yml", "/config.yaml",
    "/backup.zip", "/backup.tar.gz", "/database.sql",
    "/debug", "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/api-docs",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/storybook/", "/coverage/", "/jsdoc/",
]
SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]


def run(ctx):
    alive = ctx.runner.read_lines(ctx.output / "recon" / "alive.txt")
    if not alive:
        return
    _exposed_files(ctx, alive)
    if ctx.profile.get("active_probes", True):
        _security_headers(ctx, alive)
        _dangerous_methods(ctx, alive)
        _host_header(ctx, alive)


def _exposed_files(ctx, alive):
    if not requests:
        return
    ctx.log("INFO", "secrets_misc", f"probing {min(len(alive),30)} hosts for exposed files...")
    for host in alive[:30]:
        for path in EXPOSURE_PATHS:
            url = host.rstrip("/") + path
            try:
                r = requests.get(url, timeout=8, allow_redirects=False)
            except Exception:
                continue
            if r.status_code != 200 or len(r.text) < 5:
                continue
            indicators = {
                "/.env":          ["DB_HOST", "DB_PASSWORD", "API_KEY", "SECRET"],
                "/.git/config":   ["[core]", "repositoryformatversion"],
                "/.git/HEAD":     ["ref: refs/"],
                "phpinfo":        ["PHP Version", "phpinfo()"],
                "actuator":       ["status", "_links"],
                "swagger":        ["swagger", "openapi"],
                "config":         ["password", "api_key", "secret"],
            }
            matched = None
            txt_low = r.text.lower()
            for key, inds in indicators.items():
                if key in path:
                    if any(i.lower() in txt_low for i in inds):
                        matched = key
                        break
            sev = "HIGH" if matched in (".env", ".git/config", "actuator") else "MEDIUM"
            if matched:
                ctx.save_finding({
                    "phase": "secrets_misc", "severity": sev, "confidence": "HIGH",
                    "title": f"Exposed sensitive file: {path}",
                    "target": host, "url": url,
                    "evidence": r.text[:400],
                    "description": f"Sensitive file `{path}` is publicly accessible.",
                    "impact": "Credentials, source code, or runtime info leaked.",
                    "remediation": "Block access to dotfiles + dev artifacts at web server. "
                                   "Don't ship .git or .env to production.",
                    "cwe": "CWE-538", "mrs_score": 100,
                })


def _security_headers(ctx, alive):
    if not requests:
        return
    for host in alive[:5]:
        try:
            r = requests.get(host, timeout=10)
        except Exception:
            continue
        missing = [h for h in SECURITY_HEADERS if h.lower() not in
                   {k.lower() for k in r.headers}]
        if len(missing) >= 4:
            ctx.save_finding({
                "phase": "secrets_misc", "severity": "LOW", "confidence": "HIGH",
                "title": f"Missing security headers ({len(missing)} of {len(SECURITY_HEADERS)})",
                "target": host, "url": host,
                "evidence": "Missing: " + ", ".join(missing),
                "description": "Multiple security headers absent.",
                "impact": "Reduced defense-in-depth: clickjacking, MIME sniffing, weaker CSP.",
                "remediation": "Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options.",
                "cwe": "CWE-693", "mrs_score": 100,
            })


def _dangerous_methods(ctx, alive):
    if not requests:
        return
    for host in alive[:10]:
        try:
            r = requests.options(host, timeout=10)
        except Exception:
            continue
        allow = r.headers.get("Allow", "") or r.headers.get("allow", "")
        bad = [m for m in ("PUT", "DELETE", "TRACE", "TRACK") if m in allow.upper()]
        if bad:
            ctx.save_finding({
                "phase": "secrets_misc", "severity": "LOW", "confidence": "HIGH",
                "title": f"Dangerous HTTP methods enabled: {', '.join(bad)}",
                "target": host, "url": host, "method": "OPTIONS",
                "evidence": f"Allow: {allow}",
                "description": "Server advertises potentially-dangerous HTTP methods.",
                "impact": "TRACE: XST. PUT: file upload abuse. DELETE: data deletion.",
                "remediation": "Disable methods that aren't required by the application.",
                "cwe": "CWE-650", "mrs_score": 100,
            })


def _host_header(ctx, alive):
    if not requests:
        return
    evil = "evil.example.com"
    for host in alive[:5]:
        try:
            r = requests.get(host, headers={"Host": evil}, timeout=10,
                             allow_redirects=False)
            if evil in r.text or evil in r.headers.get("Location", ""):
                ctx.save_finding({
                    "phase": "secrets_misc", "severity": "MEDIUM", "confidence": "MEDIUM",
                    "title": "Host Header Injection",
                    "target": host, "url": host, "method": "GET",
                    "payload": f"Host: {evil}",
                    "evidence": "Server reflected attacker Host into response/redirect",
                    "description": "Server uses untrusted Host header in URLs/links.",
                    "impact": "Cache poisoning, password-reset poisoning, SSRF chains.",
                    "remediation": "Validate Host. Use absolute trusted domains in app config.",
                    "cwe": "CWE-20", "mrs_score": 85,
                })
        except Exception:
            continue
