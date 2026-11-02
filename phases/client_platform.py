"""
Phase: client_platform   (v2.19)

PWA / service-worker checks (playbook §48). Fetches manifest.json,
service-worker.js, sw.js and flags:
  - service worker present with an overly broad scope ('/')
  - manifest present (surface note)
Plus the manual lead: verify cached authenticated responses are not served after
logout (cannot be confirmed without a session — flagged for manual test).

Detection only, rate-limited.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

try:
    import requests
except Exception:
    requests = None

from core import ratelimit

SW_PATHS = ["/service-worker.js", "/sw.js", "/serviceworker.js", "/service_worker.js",
            "/firebase-messaging-sw.js"]
MANIFEST_PATHS = ["/manifest.json", "/manifest.webmanifest", "/site.webmanifest"]


def run(ctx):
    if requests is None:
        return
    requests.packages.urllib3.disable_warnings()
    bases = []
    f = ctx.output / "recon" / "alive.txt"
    if f.exists():
        bases = ctx.runner.read_lines(f)
    if not bases:
        bases = [t if t.startswith("http") else f"https://{t}" for t in ctx.targets]
    bases = list(dict.fromkeys(b.rstrip("/") for b in bases))[:25]
    if not bases:
        return

    rps = ratelimit.cap(ctx.profile, ctx.profile.get("rate_limit", {}).get("global_rps", 5))
    iv = 1.0 / max(0.5, rps)
    import time
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (TBHM client_platform)"})
    proxy = getattr(ctx.args, "proxy", None)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    def get(url):
        time.sleep(iv)
        try:
            return session.get(url, timeout=10, verify=False, allow_redirects=False)
        except Exception:
            return None

    n = 0
    for base in bases:
        host = urlparse(base).hostname
        for p in SW_PATHS:
            r = get(base + p)
            if r is None or r.status_code != 200 or "javascript" not in r.headers.get("Content-Type", "").lower():
                continue
            body = r.text or ""
            broad = bool(re.search(r"scope\s*[:=]\s*['\"]/['\"]", body)) or "/service-worker.js" in p
            caches_auth = bool(re.search(r"cache\.(put|add)|caches\.open", body))
            n += 1
            ctx.save_finding({
                "phase": "client_platform",
                "severity": "LOW" if (broad and caches_auth) else "INFO",
                "confidence": "MEDIUM",
                "title": f"Service worker present: {p}",
                "target": host, "url": base + p, "method": "GET",
                "evidence": f"caches={caches_auth} broad_scope={broad}; {body[:150]}",
                "description": "A service worker is active. Manually verify: (1) scope is not the "
                               "whole origin unnecessarily, (2) authenticated responses in the cache "
                               "are NOT served after logout, (3) sensitive data is excluded from the "
                               "offline cache.",
                "impact": "Stale-auth serving / offline data exposure if the cache holds private responses.",
                "remediation": "Scope the SW narrowly; purge auth-scoped caches on logout; exclude PII from cache.",
                "cwe": "CWE-525", "mrs_score": 25,
            })
            break
        for p in MANIFEST_PATHS:
            r = get(base + p)
            if r is None or r.status_code != 200:
                continue
            if "\"start_url\"" in (r.text or "") or "webmanifest" in r.headers.get("Content-Type", ""):
                ctx.save_finding({
                    "phase": "client_platform", "severity": "INFO", "confidence": "LOW",
                    "title": f"PWA manifest present: {p}",
                    "target": host, "url": base + p, "method": "GET",
                    "evidence": (r.text or "")[:150],
                    "description": "PWA manifest found — confirms a service-worker/offline surface to review.",
                    "impact": "Context for PWA/service-worker testing.",
                    "remediation": "N/A (informational).",
                    "cwe": "", "mrs_score": 15,
                })
            break
    ctx.log("OK", "client_platform", f"client_platform: {n} service worker(s) flagged")
