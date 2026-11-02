"""
Phase: smart_crawl (ZAP-style stateful crawler)

Builds an APPLICATION GRAPH, not just a URL list:
  - Each endpoint has: methods, params, content types, status codes seen
  - Forms are extracted with their inputs
  - JS-served URLs are found via embedded strings + JSON responses
  - Session cookies are preserved across requests (Burp-style)

Two crawl modes:
  - traditional: pure HTML/JS parsing (fast, low resource)
  - headless:    Playwright headless Chromium (catches SPAs but uses ~200MB RAM)

Headless is OPT-IN via --headless-crawl (or intensity >= deep).
"""
from __future__ import annotations
import json
import re
import time
from urllib.parse import urlparse, urljoin, urldefrag

from core.session_state import Session
from core.targets import get_root_domains, get_url_targets, target_scope_allows
from core import intensity

try:
    import requests
except ImportError:
    requests = None


# Crawl limits per intensity
CRAWL_LIMITS = {
    "quick":    {"max_urls": 50,    "max_depth": 1, "headless": False},
    "standard": {"max_urls": 300,   "max_depth": 2, "headless": False},
    "deep":     {"max_urls": 2000,  "max_depth": 3, "headless": True},
    "insane":   {"max_urls": 20000, "max_depth": 5, "headless": True},
}


def run(ctx):
    if not requests:
        ctx.log("WARN", "smart_crawl", "requests not installed — skipping")
        return

    intensity_name = ctx.profile.get("_intensity", "standard")
    limits = CRAWL_LIMITS.get(intensity_name, CRAWL_LIMITS["standard"])

    alive_file = ctx.output / "recon" / "alive.txt"
    if not alive_file.exists():
        ctx.log("WARN", "smart_crawl", "no alive.txt — skipping")
        return
    alive = ctx.runner.read_lines(alive_file)
    if not alive:
        return

    out_dir = ctx.output / "recon"
    graph_file = out_dir / "app_graph.json"
    forms_file = out_dir / "forms.json"
    crawl_urls_file = out_dir / "crawl_urls.txt"

    root_domains = get_root_domains(ctx)
    session = Session()
    graph = ApplicationGraph()

    ctx.log("INFO", "smart_crawl",
            f"━━━ ZAP-style crawl (max {limits['max_urls']} URLs, depth {limits['max_depth']}) ━━━")

    # Seed queue with alive hosts
    queue = [(u, 0) for u in alive[:50]]  # depth 0
    visited = set()
    n_processed = 0

    while queue and n_processed < limits["max_urls"]:
        url, depth = queue.pop(0)
        if url in visited or depth > limits["max_depth"]:
            continue
        visited.add(url)

        # v4: single scope authority — same decision the rest of TBHM uses,
        # instead of smart_crawl's old root-domain-only _in_scope().
        if not target_scope_allows(ctx, url):
            continue

        # Fetch with session
        h, _ = session.apply({"User-Agent": "Mozilla/5.0 (TBHM-Crawl/2.3)"}, "", "")
        try:
            r = requests.get(url, headers=h, timeout=12, allow_redirects=False, verify=False)
        except Exception:
            continue

        session.update(r)
        graph.add(url, r)
        n_processed += 1

        if n_processed % 25 == 0:
            ctx.log("INFO", "smart_crawl", f"  crawled {n_processed} URLs, {len(queue)} in queue")

        # Extract new URLs from response body
        if depth < limits["max_depth"]:
            ct = r.headers.get("Content-Type", "").lower()
            body = r.text[:300000]  # cap to 300KB per page

            new_urls = _extract_urls(url, body, ct)
            for nu in new_urls:
                nu = urldefrag(nu)[0]  # strip #fragment
                if nu not in visited and len(queue) < limits["max_urls"] * 3:
                    queue.append((nu, depth + 1))

            # Forms
            if "html" in ct:
                forms = _extract_forms(url, body)
                for f in forms:
                    graph.add_form(f)

    # Headless crawl pass (intensity-gated)
    if limits["headless"] and ctx.profile.get("headless_crawl", True):
        _headless_pass(ctx, alive[:5], graph, session)

    # Persist
    graph_file.write_text(json.dumps(graph.to_dict(), indent=2))
    forms_file.write_text(json.dumps(graph.forms, indent=2))
    ctx.runner.write_lines(crawl_urls_file, sorted(graph.nodes.keys()))

    # Score boost: endpoints with multiple methods / forms get higher score
    for url, node in graph.nodes.items():
        if len(node["methods"]) > 1 or node.get("has_form"):
            ctx.storage.boost_endpoint_score(url, +10)

    ctx.log("OK", "smart_crawl",
            f"crawl complete: {len(graph.nodes)} endpoints, {len(graph.forms)} forms")

    # Save a summary finding
    ctx.save_finding({
        "phase": "smart_crawl", "severity": "INFO", "confidence": "HIGH",
        "title": f"Application graph: {len(graph.nodes)} endpoints, {len(graph.forms)} forms",
        "target": root_domains[0] if root_domains else "",
        "description": f"Stateful crawl discovered {len(graph.nodes)} unique endpoints "
                       f"and {len(graph.forms)} forms across {len(root_domains)} root domain(s).",
    })


# ──────────────────────────────────────────────────────────────────────────────
# ApplicationGraph
# ──────────────────────────────────────────────────────────────────────────────
class ApplicationGraph:
    def __init__(self):
        self.nodes: dict = {}    # url → {methods, content_types, status_codes, params}
        self.forms: list = []    # list of form dicts

    def add(self, url, response):
        parsed = urlparse(url)
        node = self.nodes.setdefault(url, {
            "host": parsed.hostname, "path": parsed.path,
            "methods": set(), "content_types": set(), "status_codes": set(),
            "params": set(), "has_form": False,
        })
        node["methods"].add("GET")
        node["content_types"].add(response.headers.get("Content-Type", "").split(";")[0])
        node["status_codes"].add(response.status_code)
        # Extract params from URL
        from urllib.parse import parse_qsl
        for k, _ in parse_qsl(parsed.query, keep_blank_values=True):
            node["params"].add(k)

    def add_form(self, form: dict):
        self.forms.append(form)
        if form.get("action") in self.nodes:
            self.nodes[form["action"]]["has_form"] = True
            self.nodes[form["action"]]["methods"].add(form.get("method", "POST").upper())

    def to_dict(self):
        return {
            url: {
                **node,
                "methods": sorted(node["methods"]),
                "content_types": sorted(node["content_types"]),
                "status_codes": sorted(node["status_codes"]),
                "params": sorted(node["params"]),
            }
            for url, node in self.nodes.items()
        }


# ──────────────────────────────────────────────────────────────────────────────
# Extractors
# ──────────────────────────────────────────────────────────────────────────────
HREF_RE = re.compile(r"""\bhref\s*=\s*["']([^"'#]+)""", re.I)
SRC_RE  = re.compile(r"""\bsrc\s*=\s*["']([^"']+)""", re.I)
ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"']+)""", re.I)

# Fetch URLs from JS strings
JS_URL_RE = re.compile(r"""["']((?:/[A-Za-z0-9_\-./?=&%]+)|(?:https?://[^"'\s]+))["']""")
# fetch("..."), axios.get("..."), $.ajax({url: "..."})
JS_FETCH_RE = re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:ajax|get|post))\s*\(\s*["']([^"']+)""", re.I)


def _extract_urls(base_url: str, body: str, content_type: str) -> list[str]:
    out = set()
    if "html" in content_type or "xml" in content_type:
        for m in HREF_RE.finditer(body):
            out.add(urljoin(base_url, m.group(1)))
        for m in SRC_RE.finditer(body):
            out.add(urljoin(base_url, m.group(1)))
        for m in ACTION_RE.finditer(body):
            out.add(urljoin(base_url, m.group(1)))
    if "javascript" in content_type or "html" in content_type:
        for m in JS_URL_RE.finditer(body):
            u = m.group(1)
            if u.startswith("/") or u.startswith("http"):
                out.add(urljoin(base_url, u))
        for m in JS_FETCH_RE.finditer(body):
            out.add(urljoin(base_url, m.group(1)))
    if "json" in content_type:
        # Extract any "/path" or URL strings from JSON
        for m in JS_URL_RE.finditer(body):
            u = m.group(1)
            if u.startswith("/") or u.startswith("http"):
                out.add(urljoin(base_url, u))
    return list(out)


FORM_RE = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
INPUT_RE = re.compile(r"""<input[^>]+name\s*=\s*["']([^"']+)["']""", re.I)
TEXTAREA_RE = re.compile(r"""<textarea[^>]+name\s*=\s*["']([^"']+)""", re.I)
SELECT_RE = re.compile(r"""<select[^>]+name\s*=\s*["']([^"']+)""", re.I)


def _extract_forms(base_url: str, body: str) -> list[dict]:
    forms = []
    for fm in FORM_RE.finditer(body):
        form_html = fm.group(0)
        action_match = ACTION_RE.search(form_html)
        method_match = re.search(r"""method\s*=\s*["']?(\w+)""", form_html, re.I)
        inputs = set()
        inputs.update(INPUT_RE.findall(form_html))
        inputs.update(TEXTAREA_RE.findall(form_html))
        inputs.update(SELECT_RE.findall(form_html))
        if inputs:
            forms.append({
                "action": urljoin(base_url, action_match.group(1)) if action_match else base_url,
                "method": (method_match.group(1) if method_match else "GET").upper(),
                "inputs": sorted(inputs),
                "source_url": base_url,
            })
    return forms


def _in_scope(url: str, root_domains: list[str], excludes: list[str]) -> bool:
    """DEPRECATED compatibility shim. smart_crawl now calls
    core.targets.target_scope_allows(ctx, url) directly as the single scope
    authority. This function is retained only for any external caller and applies
    the same conservative host + exclude logic; it does NOT widen to a bare apex
    beyond the configured roots it is given."""
    h = (urlparse(url).hostname or "").lower()
    if not h:
        return False
    if excludes and any(ex.lower() in url.lower() for ex in excludes):
        return False
    return any(h == d or h.endswith("." + d) for d in root_domains)


# ──────────────────────────────────────────────────────────────────────────────
# Headless pass (Playwright optional)
# ──────────────────────────────────────────────────────────────────────────────
def _load_sync_playwright():
    """Load Playwright from the runtime or TBHM's isolated tool environment."""
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright
    except ImportError:
        import glob
        import os
        import sys
        from pathlib import Path

        tool_home = Path(os.environ.get("TBHM_TOOL_HOME", Path.home() / ".local/share/tbhm-tools"))
        patterns = [
            str(tool_home / "venvs/playwright/lib/python*/site-packages"),
            str(tool_home / "venvs/playwright/Lib/site-packages"),
        ]
        for pattern in patterns:
            for candidate in sorted(glob.glob(pattern), reverse=True):
                if candidate not in sys.path:
                    sys.path.insert(0, candidate)
                try:
                    from playwright.sync_api import sync_playwright
                    return sync_playwright
                except ImportError:
                    continue
    return None


def _launch_chromium(playwright):
    """Prefer Playwright's managed Chromium; fall back to a local binary."""
    import shutil
    try:
        return playwright.chromium.launch(headless=True), "managed"
    except Exception as managed_error:
        for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
            path = shutil.which(name)
            if not path:
                continue
            try:
                return playwright.chromium.launch(headless=True, executable_path=path), f"system:{path}"
            except Exception:
                continue
        raise managed_error


def _headless_pass(ctx, urls: list[str], graph, session):
    """Try Playwright; gracefully skip if neither package nor browser is usable."""
    sync_playwright = _load_sync_playwright()
    if sync_playwright is None:
        ctx.log("INFO", "smart_crawl",
                "  playwright not installed — skipping headless pass. "
                "Enable with: INSTALL_PLAYWRIGHT=1 ./install.sh")
        return

    ctx.log("INFO", "smart_crawl", f"  headless pass on {len(urls)} top URLs (Playwright)…")
    try:
        with sync_playwright() as p:
            browser, browser_source = _launch_chromium(p)
            if browser_source != "managed":
                ctx.log("WARN", "smart_crawl", f"  using Playwright compatibility fallback {browser_source}")
            context = browser.new_context(
                user_agent="Mozilla/5.0",
                ignore_https_errors=False,
                service_workers="block",
            )
            from core.http_policy import BudgetedSession, RequestBlocked
            from core.safe_writes import ctx_gate
            def guarded_route(route):
                request = route.request
                allowed, reason = ctx_gate(ctx, request.method, request.url, request.post_data)
                if not allowed:
                    route.abort()
                    return
                class BrowserTransport:
                    _tbhm_action = 'smart_crawl'
                    headers = {}
                    def request(self, method, url, **options):
                        return route.continue_(headers=options['headers'])
                try:
                    BudgetedSession(ctx, BrowserTransport(), budget=500, max_rps=5).request(
                        request.method, request.url, headers=request.headers)
                except (RequestBlocked, ValueError):
                    route.abort()
            context.route('**/*', guarded_route)
            if hasattr(context, 'route_web_socket'):
                context.route_web_socket('**/*', lambda socket: socket.close())
            for url in urls[:10]:  # heavy — keep tight
                try:
                    page = context.new_page()
                    # Intercept all network requests
                    seen_urls = set()
                    page.on("request", lambda req: seen_urls.add(req.url))
                    page.goto(url, timeout=15000, wait_until="networkidle")
                    page.wait_for_timeout(2000)
                    # Add intercepted URLs to graph (as URLs only, not full fetch).
                    # v4: scope-filter through the central authority so analytics/
                    # CDN/OAuth third parties the browser contacted are NOT recorded
                    # or later treated as in-scope targets.
                    for u in seen_urls:
                        if not target_scope_allows(ctx, u):
                            continue
                        if u not in graph.nodes:
                            graph.nodes[u] = {
                                "host": urlparse(u).hostname, "path": urlparse(u).path,
                                "methods": {"GET"}, "content_types": set(),
                                "status_codes": set(), "params": set(),
                                "has_form": False, "source": "headless",
                            }
                    page.close()
                except Exception:
                    continue
            browser.close()
    except Exception as e:
        ctx.log("WARN", "smart_crawl", f"  headless crawl failed: {e}")
