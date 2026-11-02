"""
Phase: cache_deception

Web Cache Deception (WCD) — when a CDN/proxy caches a personalized response
because the URL looks like a static asset. Example:
   /account/settings           → real auth-required page
   /account/settings.css       → cache layer thinks it's CSS, caches it
   /account/settings;.css      → same thing via path parameter trick

The bug: an attacker who can make the victim visit /account/settings.css
gets the cached response back later anonymously.

Detection (read-only, 2-3 probes per endpoint, no aggression):
  1. Fetch the original URL (auth-aware crawl might have done this — we just
     issue a fresh GET and capture the response baseline)
  2. Fetch URL + extension force (e.g. /account/settings.css)
  3. Compare:
        - Status both 200
        - Bodies are similar (>70% chunk match) — suggesting the .css variant
          returned the same auth-required content
        - Cache headers present on the .css variant (Age, X-Cache: HIT, ...)
     → WCD candidate

This phase is gentle: 2-3 GET requests per candidate URL, capped at 30
candidates per scan. No state mutation.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from core import anti_block, noise_filter, fp_engine
from core.targets import get_root_domains

try:
    import requests
except ImportError:
    requests = None


# Extension-forcing patterns — append these to suspect URLs
EXT_FORCERS = [
    "/x.css",                # /api/account → /api/account/x.css
    "/x.js",
    "/x.png",
    ";.css",                 # path-parameter trick
    ";.js",
    "%2fx.css",              # encoded
    "/non-existent-rel.css", # nginx-style cache key trick
]

# Routes that often contain personalized content (high WCD value)
PERSONALIZED_HINT_RE = re.compile(
    r"/(account|profile|settings|me|user|dashboard|billing|orders|invoices?|"
    r"payment|address|api/me|api/user|api/profile|api/v\d+/me)", re.I
)

# Cache-hit indicators
CACHE_HEADERS = ("age", "x-cache", "x-cache-hits", "cf-cache-status",
                 "x-served-by", "x-served-from", "x-cache-status")


def run(ctx):
    if not requests:
        return

    # Pull candidate URLs from crawl + alive
    candidates = set()
    crawl_file = ctx.output / "recon" / "crawl_urls.txt"
    alive_file = ctx.output / "recon" / "alive.txt"
    for f in (crawl_file, alive_file):
        if f.exists():
            candidates.update(ctx.runner.read_lines(f))

    in_scope = set(get_root_domains(ctx))

    # Keep only personalized-looking + in-scope URLs
    personalized = []
    for url in candidates:
        if noise_filter.is_noise(url, in_scope_hosts=in_scope)[0]:
            continue
        if PERSONALIZED_HINT_RE.search(urlparse(url).path or ""):
            personalized.append(url)

    if not personalized:
        ctx.log("INFO", "cache_deception",
                "no personalized-looking routes — skipping")
        return

    ctx.log("INFO", "cache_deception",
            f"━━━ WCD probing on {min(len(personalized), 30)} candidates ━━━")

    n = 0
    for url in personalized[:30]:
        n += _probe_url(ctx, url, in_scope)

    ctx.log("OK", "cache_deception", f"cache_deception: {n} findings")


def _probe_url(ctx, url: str, in_scope) -> int:
    host = urlparse(url).hostname or ""

    # 1. Baseline: anonymous GET on original URL
    try:
        r_base = requests.get(url, headers=anti_block.headers_for(host),
                              timeout=12, verify=False, cookies={},
                              allow_redirects=False)
        anti_block.observe(host, r_base.status_code, len(r_base.content),
                           r_base.text[:1000])
    except Exception:
        return 0

    # We need the path to look auth-required. Heuristic:
    #   - Status 200 with HTML body (real page)
    #   - OR 401/403/302 to login → indicates auth-required
    is_auth_required = (
        r_base.status_code in (401, 403) or
        (r_base.status_code == 302 and
         "login" in (r_base.headers.get("Location") or "").lower())
    )
    looks_like_real_page = (
        r_base.status_code == 200 and len(r_base.content) > 1000
    )
    if not (is_auth_required or looks_like_real_page):
        return 0

    # 2. Try extension-forced variants
    found = 0
    for ext in EXT_FORCERS:
        variant = url.rstrip("/") + ext
        try:
            r_var = requests.get(variant, headers=anti_block.headers_for(host),
                                 timeout=12, verify=False, cookies={},
                                 allow_redirects=False)
            anti_block.observe(host, r_var.status_code, len(r_var.content))
        except Exception:
            continue

        if r_var.status_code != 200 or len(r_var.content) < 500:
            continue

        # Did we get the same content as the auth-required version anonymously?
        # If r_base was 401/403, this is unambiguous — any 200 on a /settings.css
        # variant is suspicious.
        if is_auth_required:
            # Strong WCD candidate — anon got 200 on /resource.css when /resource was 401
            cache_hits = [h for h in CACHE_HEADERS if h in {k.lower() for k in r_var.headers}]
            ctx.save_finding({
                "phase": "cache_deception", "severity": "HIGH",
                "confidence": "HIGH" if cache_hits else "MEDIUM",
                "title": "Possible Web Cache Deception (auth path served anonymously on .ext variant)",
                "target": host, "url": variant, "method": "GET",
                "evidence": f"Original {url} → {r_base.status_code} (auth-required); "
                            f"variant {variant} → 200, {len(r_var.content)} bytes. "
                            f"Cache headers: {cache_hits or 'none observed'}.",
                "description": "An auth-required endpoint is reachable anonymously "
                              "when appended with a static-file extension. CDN/proxy "
                              "may be caching the personalized response. If victim "
                              "is tricked into visiting the .css variant, attacker "
                              "can retrieve the cached content anonymously.",
                "impact": "Disclosure of victim's personalized data (account details, "
                         "billing info, internal pages) via crafted URL.",
                "remediation": "Strip path suffix before auth check at the application "
                              "layer. Configure CDN: never cache responses that contain "
                              "Set-Cookie or Authorization-validated content, regardless "
                              "of URL extension.",
                "cwe": "CWE-525", "mrs_score": 80 if cache_hits else 65,
            })
            found += 1
        else:
            # Tier 2 check: the variant body looks suspiciously like the original
            # (suggesting the proxy stripped the .css and served the dynamic content)
            sim = _body_similarity(r_base.text[:3000], r_var.text[:3000])
            if sim > 0.7:
                content_type = (r_var.headers.get("Content-Type") or "").lower()
                # If the response claims to be CSS/JS but content is HTML → suspicious
                content_type_mismatch = (
                    "css" in (ext or "") and "html" in content_type
                )
                cache_hits = [h for h in CACHE_HEADERS
                              if h in {k.lower() for k in r_var.headers}]
                if content_type_mismatch or cache_hits:
                    ctx.save_finding({
                        "phase": "cache_deception", "severity": "MEDIUM",
                        "confidence": "MEDIUM",
                        "title": f"WCD candidate: dynamic content served on {ext} variant",
                        "target": host, "url": variant, "method": "GET",
                        "evidence": f"Body similarity to original: {sim:.0%}. "
                                    f"Content-Type='{content_type}'. "
                                    f"Cache headers: {cache_hits or 'none'}.",
                        "description": "Anonymous GET on a /resource.css URL returned "
                                      "content that closely matches the dynamic page at /resource. "
                                      "Manually verify with an authenticated victim cookie.",
                        "impact": "Possible WCD; manual verification needed.",
                        "remediation": "Same as above.",
                        "cwe": "CWE-525", "mrs_score": 60,
                    })
                    found += 1
        if found >= 1:
            break    # one finding per URL is enough
    return found


def _body_similarity(a: str, b: str) -> float:
    """Cheap chunk-based similarity (0..1)."""
    if not a or not b:
        return 0.0
    chunks_a = {a[i:i+60] for i in range(0, min(len(a), 3000), 60)}
    chunks_b = {b[i:i+60] for i in range(0, min(len(b), 3000), 60)}
    if not chunks_a:
        return 0.0
    return len(chunks_a & chunks_b) / max(len(chunks_a), len(chunks_b))
