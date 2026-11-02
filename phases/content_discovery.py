"""
Phase: content_discovery
Brute-force directories and files using ffuf + SecLists wordlists.

This finds endpoints that aren't in wayback/gau/katana output (admin panels,
backup files, hidden API routes, etc.) — often where the best bugs hide.
"""
from __future__ import annotations
from core import ratelimit
import json
import time
from pathlib import Path

from core import seclists


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        ctx.log("INFO", "content_discovery", "passive profile - skipping")
        return
    if not ctx.runner.has("ffuf"):
        ctx.log("WARN", "content_discovery", "ffuf not installed - skipping")
        return

    alive_file = ctx.output / "recon" / "alive.txt"
    alive = ctx.runner.read_lines(alive_file)
    if not alive:
        ctx.log("WARN", "content_discovery", "no alive hosts - skipping")
        return

    # Choose wordlist by profile aggressiveness
    katana_depth = ctx.profile.get("katana_depth", 2)
    if katana_depth >= 4:
        wl_names = ["content_raft_lg", "api_endpoints", "backups"]
    elif katana_depth >= 2:
        wl_names = ["content_quickhits", "content_common", "api_endpoints"]
    else:
        wl_names = ["content_quickhits"]

    wls = []
    for n in wl_names:
        p = seclists.get(n)
        if p:
            wls.append((n, p))
    if not wls:
        ctx.log("WARN", "content_discovery",
                "no SecLists wordlists found - install SecLists for content discovery")
        return

    ctx.log("INFO", "content_discovery",
            f"using wordlists: {', '.join(n for n,_ in wls)}")

    # Limit to top hosts (don't ffuf 1000 subdomains)
    from core.targets import target_scope_allows
    targets = [url for url in alive if target_scope_allows(ctx, url)][:5]
    rl = ctx.profile.get("rate_limit", {})
    from phases.recon import _network_rate
    rps = _network_rate(ctx)
    if rps < 1:
        ctx.log('WARN', 'content_discovery', 'child scanner cannot honor zero/fractional rates; no launch')
        return

    out_dir = ctx.output / "scans" / "content"
    out_dir.mkdir(parents=True, exist_ok=True)

    findings_count = 0
    failures = 0
    deadline = time.monotonic() + max(1, min(3600, float(
        ctx.profile.get('runtime', {}).get('content_discovery_seconds', 900))))
    cancelled = getattr(ctx.runner, '_cancel_event', None)
    for host in targets:
        for wl_name, wl_path in wls:
            if cancelled is not None and cancelled.is_set():
                ctx.log('WARN', 'content_discovery', f'cancelled; retained {findings_count} partial observations')
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                ctx.log('WARN', 'content_discovery', 'phase deadline reached; remaining wordlists not executed')
                ledger = getattr(ctx, 'execution_ledger', None)
                if ledger:
                    ledger.record(kind='coverage', status='partial', reason='content discovery phase deadline reached')
                return
            host_slug = host.replace("https://", "").replace("http://", "").replace("/", "_")
            out_json = out_dir / f"{host_slug}__{wl_name}.json"
            ctx.log("INFO", "content_discovery", f"ffuf {host} with {wl_name}...")
            cmd = ["ffuf",
                   "-u", host.rstrip("/") + "/FUZZ",
                   "-w", str(wl_path),
                   "-mc", "200,201,204,301,302,307,401,403,405",
                   "-fs", "0",  # filter zero-length
                   # v2.20: -ac auto-calibration defeats SPA/catch-all (200-for-all).
                   "-ac",
                   "-rate", str(ratelimit.cap(ctx.profile, int(rps))),
                   "-t", "20",
                   "-of", "json",
                   "-o", str(out_json),
                   "-s",  # silent
                   "-timeout", "8"]
            # Never parse a stale result left by a previous attempt/resume.
            out_json.unlink(missing_ok=True)
            rc, out, err = ctx.runner.run(cmd, timeout=min(900, remaining), log_name=f"ffuf_{wl_name}")
            findings_count += _parse_ffuf_results(ctx, out_json, host)
            if rc:
                failures += 1
                ctx.log('WARN', 'content_discovery', f'ffuf rc={rc}; output is partial, not a clean no-match')
            if rc == 130 or (cancelled is not None and cancelled.is_set()):
                return

    ctx.log('WARN' if failures else 'OK', 'content_discovery',
            f'discovered {findings_count} interesting paths; failed jobs={failures}')


def _parse_ffuf_results(ctx, out_json: Path, host: str) -> int:
    if not out_json.exists():
        return 0
    try:
        data = json.loads(out_json.read_text())
    except (ValueError, OSError) as exc:
        ledger = getattr(ctx, 'execution_ledger', None)
        if ledger:
            ledger.record(kind='parser', status='parser-error', tool='ffuf', reason=str(exc)[:240])
        return 0
    if not isinstance(data, dict) or not isinstance(data.get('results', []), list):
        ledger = getattr(ctx, 'execution_ledger', None)
        if ledger:
            ledger.record(kind='parser', status='parser-error', tool='ffuf', reason='expected ffuf results array')
        return 0
    results = data.get("results", []) or []
    # v2.20: soft-404 post-filter. On a SPA/catch-all, one (status,size) response
    # dominates. If a single size cluster is >40% of results (and >25 hits), it is
    # the wildcard response — drop it entirely. Belt-and-suspenders behind ffuf -ac.
    if len(results) > 25:
        from collections import Counter
        sizes = Counter((r.get("status", 0), r.get("length", 0)) for r in results)
        total = len(results)
        drop_clusters = {k for k, c in sizes.items() if c / total > 0.40 and c > 25}
        if drop_clusters:
            before = len(results)
            results = [r for r in results
                       if (r.get("status", 0), r.get("length", 0)) not in drop_clusters]
            ctx.log("INFO", "content_discovery",
                    f"soft-404 filter dropped {before - len(results)} catch-all responses on {host}")
    n = 0
    for r in results:
        if not isinstance(r, dict):
            continue
        path = r.get("input", {}).get("FUZZ", "")
        url = r.get("url", "")
        from core.targets import target_scope_allows
        if not target_scope_allows(ctx, url):
            continue
        status = r.get("status", 0)
        size = r.get("length", 0)
        # Severity heuristics
        sev = "INFO"
        title = f"Discovered: /{path} ({status})"
        if status in (200, 201, 204):
            if any(k in path.lower() for k in
                   ["admin", "backup", ".git", ".env", "config", "phpinfo",
                    "actuator", "swagger", "console", "debug", "internal",
                    "private", "secret"]):
                sev = "MEDIUM"
                title = f"Sensitive path accessible: /{path}"
        elif status in (401, 403):
            # Forbidden but exists - useful info, lower severity
            if any(k in path.lower() for k in ["admin", "internal", "private"]):
                sev = "INFO"
                title = f"Forbidden but present: /{path} ({status})"
        ctx.save_finding({
            "phase": "content_discovery",
            "severity": sev,
            "confidence": "MEDIUM" if sev != "INFO" else "HIGH",
            "title": title,
            "target": host,
            "url": url,
            "method": "GET",
            "evidence": f"Status: {status}, Size: {size}",
            "description": f"Path discovered via ffuf brute-force.",
            "impact": "Sensitive paths may leak data or expose admin functions."
                      if sev != "INFO" else "Informational - validates the asset surface.",
            "remediation": "Restrict access via authentication and authorization. "
                           "Remove dev/debug endpoints from production.",
            "mrs_score": 100,
        })
        n += 1
    return n
