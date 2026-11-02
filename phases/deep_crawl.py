"""Phase: deep_crawl (v3.9.3-new)

Follow verified in-scope links and endpoints to discover more of the real attack
surface, then hand every newly found endpoint to the EXISTING audit pipeline by
scoring it into storage (audit pulls from storage.top_endpoints, so no change to
audit itself — and all of audit's profile/rate/intensity gates still apply).

This is a DISCOVERY expansion, not a new active scanner:
  * GET only. Never sends a payload, never mutates. (Active testing remains the
    job of audit/injections, behind their own send_payloads/active_probes gates.)
  * In-scope only. Every candidate URL is checked against root domains + excludes
    before it is fetched or stored.
  * Bounded. Max pages, max depth, and per-host caps prevent runaway crawling;
    the global rate limiter and anti_block throttle apply.

Seeds (from earlier phases):
  recon/alive.txt, recon/urls.txt, recon/js_endpoints.txt, recon/app_graph.json
Outputs:
  crawl/discovered_urls.txt   — every in-scope URL found
  scored endpoints in storage — so audit/injections test them
Findings: none directly (this feeds other phases); a summary INFO is emitted.
"""
from __future__ import annotations

import json
import re
from collections import deque
from urllib.parse import urlparse, urljoin

from core import noise_filter, anti_block
from core.targets import get_root_domains, target_scope_allows
from core.scoped_http import network_discovery_enabled, effective_rps, safe_get
from core.scoring import score_endpoint

try:
    import requests
except ImportError:
    requests = None

_HREF_RE = re.compile(r"""(?i)(?:href|src|action)\s*=\s*["']([^"'#<>]+)["']""")
_TIMEOUT = 15
# bounds by intensity — mirror the tool's existing intensity philosophy
_BUDGET = {"quick": 120, "standard": 400, "deep": 1200, "insane": 4000}
_MAX_DEPTH = {"quick": 2, "standard": 3, "deep": 4, "insane": 5}
_PER_HOST = 300


def _in_scope(ctx, url: str) -> bool:
    """Authoritative target/scope/exclusion decision for crawl candidates."""
    return target_scope_allows(ctx, url)


def _interesting(url: str) -> bool:
    """Skip static assets that aren't worth following/auditing."""
    path = urlparse(url).path.lower()
    if re.search(r"\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|mp4|webm|pdf|zip|gz)($|\?)", path):
        return False
    return True


def run(ctx):
    if not requests:
        ctx.log("WARN", "deep_crawl", "requests not available — skipping")
        return
    # Fetching pages is network-active even though it is GET-only. Honour passive
    # and explicit zero-rate profiles before constructing or sending any request.
    if not network_discovery_enabled(ctx):
        ctx.log("INFO", "deep_crawl", "passive/zero-touch profile — skipping active crawl")
        return

    recon = ctx.output / "recon"
    roots = get_root_domains(ctx)
    intensity = ctx.profile.get("_intensity", "standard")
    budget = _BUDGET.get(intensity, 400)
    max_depth = _MAX_DEPTH.get(intensity, 3)

    # seed set: alive hosts + already-known URLs + JS-derived endpoints
    seeds = set()
    for fname in ("alive.txt", "urls.txt", "js_endpoints.txt"):
        f = recon / fname
        if f.exists():
            for line in ctx.runner.read_lines(f):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("/"):
                    # bare path — attach to each alive host
                    for hostline in ctx.runner.read_lines(recon / "alive.txt") if (recon / "alive.txt").exists() else []:
                        base = hostline.strip().rstrip("/")
                        if base:
                            seeds.add(base + line)
                else:
                    seeds.add(line if line.startswith("http") else "https://" + line)

    seeds = {u for u in seeds if _in_scope(ctx, u) and _interesting(u)}
    if not seeds:
        ctx.log("WARN", "deep_crawl", "no in-scope seeds — run recon/discovery first")
        return

    ctx.log("INFO", "deep_crawl",
            f"crawling from {len(seeds)} seed(s); budget={budget}, max_depth={max_depth}")

    # v3.9.3 item 4: enforce the profile's per-target rate limit on this crawl.
    from core.api_baseline import RateLimiter
    rps = effective_rps(ctx)
    if rps <= 0:
        ctx.log("INFO", "deep_crawl", "request rate is zero — skipping active crawl")
        return
    rl = RateLimiter(rps)

    visited = set()
    per_host = {}
    discovered = set()
    protected = set()
    q = deque((u, 0) for u in seeds)

    while q and len(visited) < budget:
        url, depth = q.popleft()
        if url in visited:
            continue
        host = urlparse(url).hostname or ""
        if per_host.get(host, 0) >= _PER_HOST:
            continue
        if noise_filter.is_noise(url, in_scope_hosts=set(roots))[0]:
            continue
        visited.add(url)
        per_host[host] = per_host.get(host, 0) + 1

        try:
            h = anti_block.headers_for(host)
            r, final_url, _redirect_chain = safe_get(
                ctx, requests, url, headers=h, timeout=_TIMEOUT, verify=False,
                rate_limiter=rl, max_redirects=5)
            final_host = urlparse(final_url).hostname or host
            anti_block.observe(final_host, r.status_code, len(r.content))
        except Exception as exc:
            ctx.log("INFO", "deep_crawl", f"request blocked/failed: {str(exc)[:140]}")
            continue

        # Only successful resources are called reachable and scored. Protected
        # routes are useful coverage evidence but are kept in a separate file;
        # 404/5xx responses are not injected into the audit queue.
        status = int(getattr(r, "status_code", 0) or 0)
        if status in (401, 403):
            protected.add(final_url)
            continue
        if not (200 <= status < 300):
            continue
        discovered.add(final_url)

        # only parse HTML for more links
        ctype = r.headers.get("Content-Type", "")
        if "html" not in ctype.lower() or not r.text:
            continue
        if depth >= max_depth:
            continue
        for m in _HREF_RE.finditer(r.text):
            raw = m.group(1).strip()
            if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            # Resolve relative links against the final URL after redirects.
            nxt = urljoin(final_url, raw)
            if not _in_scope(ctx, nxt) or not _interesting(nxt):
                continue
            if nxt not in visited:
                q.append((nxt, depth + 1))

    # write discovered URLs and score them so AUDIT picks them up
    crawl_dir = ctx.output / "crawl"
    crawl_dir.mkdir(exist_ok=True)
    (crawl_dir / "discovered_urls.txt").write_text("\n".join(sorted(discovered)), encoding="utf-8")
    (crawl_dir / "protected_urls.txt").write_text("\n".join(sorted(protected)), encoding="utf-8")

    scored = 0
    for url in discovered:
        if not _in_scope(ctx, url):
            continue
        # parameterised or id-like URLs are the ones audit can actually test
        parsed = urlparse(url)
        params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p] if parsed.query else []
        try:
            sc, comp = score_endpoint(url, method="GET", params=params)
            ctx.storage.save_endpoint_score(url, sc, comp)
            scored += 1
        except Exception:
            continue

    ctx.save_finding({
        "phase": "deep_crawl", "severity": "INFO", "confidence": "HIGH",
        "title": f"Deep crawl expanded the tested surface: {len(discovered)} URL(s)",
        "target": ", ".join(roots)[:200], "url": "",
        "description": f"Followed in-scope links from {len(seeds)} seed(s) and discovered "
                       f"{len(discovered)} reachable URL(s), {len(protected)} protected route(s); "
                       f"{scored} scored into the audit queue.",
        "evidence": f"visited={len(visited)}, discovered={len(discovered)}, protected={len(protected)}, scored={scored}",
        "impact": "Broader, evidence-driven coverage for the audit/injection phases.",
        "remediation": "N/A — informational.",
        "cwe": "", "mrs_score": 10, "verified": True,
    })
    ctx.log("OK", "deep_crawl",
            f"discovered {len(discovered)} URL(s); scored {scored} for auditing")
