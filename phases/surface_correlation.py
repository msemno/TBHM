"""Phase: surface_correlation (v3.9.3-new)

The connective tissue between discovery sources and the audit engine.

Different phases discover attack surface into different files:
  recon/alive.txt            live hosts (web)
  recon/urls.txt             discovered URLs
  recon/js_endpoints.txt     endpoints extracted from JS (js_analysis)
  code/endpoints.txt         endpoints found in source code (code_scan/code_intel)
  code/hosts.txt             hosts referenced in source code
  mobile/endpoints.txt       endpoints in APK/IPA (mobile_scan)
  crawl/discovered_urls.txt  URLs found by deep_crawl

Historically these stayed siloed: an endpoint found in the SDK source or a mobile
binary never got web-tested unless the operator wired it by hand. This phase
CORRELATES them — it takes every code/mobile/JS endpoint path, joins it against
every live host, and scores the resulting concrete URLs into the shared endpoint
store so the EXISTING audit/injections phases test them.

Read-only. It sends no requests itself (reachability is confirmed later by the
audit path under its own gates); it only unifies and scores what other phases
already discovered. This turns "guess the endpoint" into "test the endpoint the
code told us exists on the host we know is live."
"""
from __future__ import annotations

import json
from urllib.parse import urlparse, urljoin

from core.targets import get_root_domains, target_scope_allows
from core.scoring import score_endpoint


def _read(ctx, rel):
    f = ctx.output / rel
    if not f.exists():
        return []
    try:
        return [l.strip() for l in ctx.runner.read_lines(f) if l.strip()]
    except Exception:
        return []


def _in_scope(ctx, value):
    return target_scope_allows(ctx, value)


def run(ctx):
    roots = get_root_domains(ctx)
    if not roots:
        ctx.log("WARN", "surface_correlation", "no root domains — skipping")
        return

    # 1) live hosts (bases we can actually hit)
    alive = _read(ctx, "recon/alive.txt")
    live_bases = []
    for line in alive:
        line = line.split()[0] if line.split() else line
        if line.startswith("http"):
            live_bases.append(line.rstrip("/"))
        elif line:
            live_bases.append("https://" + line.rstrip("/"))
    # de-dup by host
    seen_bases, bases = set(), []
    for b in live_bases:
        hb = urlparse(b).hostname or ""
        if hb and hb not in seen_bases and _in_scope(ctx, b):
            seen_bases.add(hb)
            bases.append(b)

    # Source-referenced hosts were previously documented but ignored.  Treat them
    # as candidate bases only after the same target/scope/exclusion check used for
    # every persisted URL.  Downstream audit remains responsible for reachability.
    source_hosts = set()
    for host_value in _read(ctx, "code/hosts.txt"):
        candidate = host_value if host_value.startswith("http") else "https://" + host_value
        host = urlparse(candidate).hostname or ""
        if host and _in_scope(ctx, candidate):
            source_hosts.add(host)
            if host not in seen_bases:
                seen_bases.add(host)
                bases.append(candidate.rstrip("/"))

    # 2) endpoint PATHS discovered by code/mobile/JS (things to try on each host)
    paths = set()
    for rel in ("code/endpoints.txt", "mobile/endpoints.txt",
                "recon/js_endpoints.txt", "recon/endpoints.txt"):
        for e in _read(ctx, rel):
            if e.startswith("/"):
                paths.add(e)
            elif e.startswith("http"):
                # absolute URL discovered in code — score directly if in scope
                if _in_scope(ctx, e):
                    paths.add(("ABS", e))

    # 3) already-known full URLs (urls.txt, crawl)
    known_urls = set()
    for rel in ("recon/urls.txt", "crawl/discovered_urls.txt", "code/urls.txt"):
        for u in _read(ctx, rel):
            if u.startswith("http") and _in_scope(ctx, u):
                known_urls.add(u)

    # 4) correlate: every code/mobile/JS path × every live host = a concrete URL
    correlated = set(known_urls)
    for p in paths:
        if isinstance(p, tuple):          # absolute URL from code
            correlated.add(p[1])
            continue
        for base in bases:
            correlated.add(urljoin(base + "/", p.lstrip("/")))

    correlated = {u for u in correlated if _in_scope(ctx, u)}

    if not correlated:
        ctx.log("INFO", "surface_correlation", "nothing to correlate yet")
        return

    # 5) score everything into storage so AUDIT/INJECTIONS test it
    scored = 0
    for url in correlated:
        if not _in_scope(ctx, url):
            continue
        parsed = urlparse(url)
        params = [q.split("=")[0] for q in parsed.query.split("&") if "=" in q] if parsed.query else []
        try:
            sc, comp = score_endpoint(url, method="GET", params=params)
            ctx.storage.save_endpoint_score(url, sc, comp)
            scored += 1
        except Exception:
            continue

    # write the unified surface for the report + downstream visibility
    out = ctx.output / "correlation"
    out.mkdir(exist_ok=True)
    (out / "unified_surface.txt").write_text("\n".join(sorted(correlated)), encoding="utf-8")
    (out / "sources.json").write_text(json.dumps({
        "live_hosts_and_scoped_source_hosts": len(bases),
        "source_hosts_consumed": len(source_hosts),
        "code_mobile_js_paths": len([p for p in paths if not isinstance(p, tuple)]),
        "absolute_code_urls": len([p for p in paths if isinstance(p, tuple)]),
        "known_urls": len(known_urls),
        "correlated_total": len(correlated),
        "scored_into_audit_queue": scored,
    }, indent=2), encoding="utf-8")

    ctx.save_finding({
        "phase": "surface_correlation", "severity": "INFO", "confidence": "HIGH",
        "title": f"Correlated attack surface: {len(correlated)} URL(s) from code/mobile/JS/crawl",
        "target": ", ".join(roots)[:200], "url": "",
        "description": f"Joined {len(paths)} code/mobile/JS endpoint(s) against {len(bases)} live host(s) "
                       f"and {len(known_urls)} known URL(s); scored {scored} concrete URL(s) into the "
                       f"audit queue so source- and binary-discovered endpoints get web-tested.",
        "evidence": f"live_hosts={len(bases)}, endpoint_paths={len(paths)}, correlated={len(correlated)}, scored={scored}",
        "impact": "Source/mobile-discovered endpoints are now tested on live hosts instead of being siloed.",
        "remediation": "N/A — informational.",
        "cwe": "", "mrs_score": 10, "verified": False,
        "finding_class": "informational",
    })
    ctx.log("OK", "surface_correlation",
            f"unified {len(correlated)} URL(s); scored {scored} into audit queue")
