"""
Phase: backend_map

For each interesting page, identify which backend API endpoints it calls.
Output: a JSON graph showing:
    page  → [list of API endpoints it talks to]
    api   → [pages that call it]
    api   → "primary" boolean (the most-frequently-called per page)

Two collection modes:
  1. STATIC (default, fast, free): parse JS bundles for fetch()/axios/XHR strings
  2. RUNTIME (optional, --headless-crawl): Playwright intercepts network traffic

Why this matters:
  - Find IDOR by knowing exactly which API endpoint a profile-page hits
  - Find admin-only APIs that the frontend usually hides
  - Map auth-inheritance: page X calls /api/users — does anon get /api/users too?
"""
from __future__ import annotations
import json
import re
from collections import Counter, defaultdict
from urllib.parse import urlparse, urljoin

from core.targets import get_root_domains
from core import noise_filter, anti_block

try:
    import requests
except ImportError:
    requests = None


# Regex patterns to find API calls in JS source
API_CALL_PATTERNS = [
    # fetch("/api/...") or fetch(`/api/...`)
    re.compile(r"""fetch\s*\(\s*["'`]([^"'`]+)["'`]""", re.I),
    # axios.get("/..."), axios.post("/...")
    re.compile(r"""axios\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]""", re.I),
    # axios({url:"/..."})
    re.compile(r"""axios\s*\(\s*\{\s*[^}]*url\s*:\s*["'`]([^"'`]+)["'`]""", re.I),
    # $.ajax({url:"/..."}), $.get("/..."), $.post("/...")
    re.compile(r"""\$\.(?:ajax|get|post|put|delete)\s*\(\s*\{?\s*(?:url\s*:\s*)?["'`]([^"'`]+)["'`]""", re.I),
    # new XMLHttpRequest(); xhr.open("GET","/...")
    re.compile(r"""\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`]([^"'`]+)["'`]""", re.I),
    # Generic API path strings (string literals starting with /api or matching api shape)
    re.compile(r"""["'`](/api/[\w\-/.{}?=&]+)["'`]"""),
    re.compile(r"""["'`](/v\d+/[\w\-/.{}?=&]+)["'`]"""),     # /v1/, /v2/
    re.compile(r"""["'`](/graphql/?[\w\-/]*)["'`]""", re.I),
]

# URL shapes that are clearly API endpoints (used to filter out HTML pages)
API_PATH_RE = re.compile(r"^/(api|v\d+|graphql|gql|rest|service|svc)/", re.I)


def run(ctx):
    """Build the backend-map graph from collected JS files."""
    if not requests:
        return
    js_urls_file = ctx.output / "recon" / "javascript.txt"
    crawl_urls_file = ctx.output / "recon" / "crawl_urls.txt"

    pages_to_apis: dict[str, list[dict]] = defaultdict(list)
    api_call_count: Counter = Counter()

    # 1. Pull all known pages
    pages = set()
    if crawl_urls_file.exists():
        pages.update(ctx.runner.read_lines(crawl_urls_file))
    if (ctx.output / "recon" / "alive.txt").exists():
        pages.update(ctx.runner.read_lines(ctx.output / "recon" / "alive.txt"))

    if not pages:
        ctx.log("WARN", "backend_map", "no pages — skipping (run discovery/smart_crawl first)")
        return

    root_domains = set(get_root_domains(ctx))
    in_scope = set(root_domains)

    ctx.log("INFO", "backend_map",
            f"━━━ Building backend map from {len(pages)} pages ━━━")

    n_pages_with_apis = 0
    for page_url in sorted(pages)[:200]:  # cap
        host = urlparse(page_url).hostname or ""
        # Skip pages on noise hosts
        if noise_filter.is_noise(page_url, in_scope_hosts=in_scope)[0]:
            continue

        # Fetch the page HTML
        try:
            h = anti_block.headers_for(host)
            r = requests.get(page_url, headers=h, timeout=12,
                             allow_redirects=True, verify=False)
            anti_block.observe(host, r.status_code, len(r.content), r.text[:1000])
        except Exception:
            continue

        # Collect referenced JS URLs
        js_in_page = _extract_js_refs(page_url, r.text)
        # Fetch each JS file (with caching to avoid re-fetching shared bundles)
        api_endpoints_seen = []
        for js_url in js_in_page[:8]:   # cap JS files per page
            if noise_filter.is_noise(js_url, in_scope_hosts=in_scope)[0]:
                continue
            js_text = _fetch_js(ctx, js_url)
            if not js_text:
                continue
            for ep in _extract_api_calls(js_text):
                # Resolve to absolute URL
                abs_ep = urljoin(page_url, ep)
                # Only keep in-scope endpoints
                ep_host = urlparse(abs_ep).hostname or host
                if ep_host in root_domains or any(ep_host.endswith("." + d) for d in root_domains):
                    api_endpoints_seen.append(abs_ep)
                    api_call_count[abs_ep] += 1

        if api_endpoints_seen:
            n_pages_with_apis += 1
            # Per page: identify primary API (most-referenced)
            counts = Counter(api_endpoints_seen)
            primary = counts.most_common(1)[0][0] if counts else None
            for ep, cnt in counts.items():
                pages_to_apis[page_url].append({
                    "endpoint":   ep,
                    "call_count": cnt,
                    "primary":    (ep == primary),
                })

    # Build reverse map: api → pages
    apis_to_pages: dict[str, list[str]] = defaultdict(list)
    for page, eps in pages_to_apis.items():
        for ep in eps:
            apis_to_pages[ep["endpoint"]].append(page)

    # Find "lonely admin APIs" — APIs called by very few pages (suspicious)
    lonely_apis = [ep for ep, count in api_call_count.most_common()
                   if count == 1 and ("/admin" in ep.lower() or "/internal" in ep.lower())]

    out_dir = ctx.output / "recon"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "backend_map.json").write_text(json.dumps({
        "pages_to_apis":      dict(pages_to_apis),
        "apis_to_pages":      {k: v for k, v in apis_to_pages.items()},
        "api_call_frequency": dict(api_call_count.most_common(100)),
        "lonely_admin_apis":  lonely_apis,
        "stats": {
            "n_pages":           len(pages),
            "n_pages_with_apis": n_pages_with_apis,
            "n_unique_apis":     len(api_call_count),
            "n_lonely_admin":    len(lonely_apis),
        },
    }, indent=2, default=str))

    ctx.log("OK", "backend_map",
            f"backend_map: {n_pages_with_apis} pages → {len(api_call_count)} unique APIs "
            f"({len(lonely_apis)} lonely admin APIs)")

    # Raise findings for lonely admin APIs (high-value targets)
    for api in lonely_apis[:10]:
        ctx.save_finding({
            "phase": "backend_map", "severity": "INFO", "confidence": "MEDIUM",
            "title": f"Lonely admin API discovered: {urlparse(api).path}",
            "target": urlparse(api).hostname, "url": api,
            "description": "This admin/internal API is referenced by only one page "
                           "in the frontend. Often these are forgotten endpoints "
                           "with weaker auth controls. Manually test auth bypass + IDOR.",
            "impact": "Possible auth bypass or privilege escalation if reachable without admin role.",
            "remediation": "Audit which user roles can access this endpoint server-side.",
            "mrs_score": 65,
        })

    # Bump scores on APIs that appear in the backend map (they are real endpoints)
    for api in api_call_count:
        ctx.storage.boost_endpoint_score(api, +5)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)""", re.I)
# Module preload (used by modern bundlers)
LINK_PRELOAD_RE = re.compile(
    r"""<link[^>]+rel\s*=\s*["'](?:modulepreload|preload)["'][^>]+href\s*=\s*["']([^"']+\.js)""",
    re.I,
)


def _extract_js_refs(base_url: str, html_body: str) -> list[str]:
    """Find all .js URLs referenced by an HTML page."""
    out = set()
    for m in SCRIPT_SRC_RE.finditer(html_body):
        out.add(urljoin(base_url, m.group(1)))
    for m in LINK_PRELOAD_RE.finditer(html_body):
        out.add(urljoin(base_url, m.group(1)))
    return list(out)


_js_cache: dict[str, str] = {}


def _fetch_js(ctx, js_url: str) -> str:
    """Cached JS fetch with size cap."""
    if js_url in _js_cache:
        return _js_cache[js_url]
    host = urlparse(js_url).hostname or ""
    try:
        h = anti_block.headers_for(host)
        r = requests.get(js_url, headers=h, timeout=15, verify=False)
        anti_block.observe(host, r.status_code, len(r.content))
        if r.status_code != 200:
            _js_cache[js_url] = ""
            return ""
        # Cap to 2MB per JS file
        text = r.text[:2_000_000]
        _js_cache[js_url] = text
        return text
    except Exception:
        _js_cache[js_url] = ""
        return ""


def _extract_api_calls(js_text: str) -> list[str]:
    """Run all patterns; return de-duplicated list of unique endpoints."""
    out = set()
    for pat in API_CALL_PATTERNS:
        for m in pat.finditer(js_text):
            ep = m.group(1).strip()
            # Filter junk: very short, no slashes, etc.
            if len(ep) < 3 or " " in ep:
                continue
            # Only keep things that look like paths or API URLs
            if ep.startswith("/") or ep.startswith("http"):
                out.add(ep)
            # OR explicit API path shape
            elif API_PATH_RE.match("/" + ep):
                out.add("/" + ep)
    return list(out)
