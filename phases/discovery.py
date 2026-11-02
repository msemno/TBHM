"""
Phase: discovery
URL harvest, JS analysis, params, endpoint scoring.
"""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

from core.scoring import score_endpoint
from core.targets import get_domains, get_root_domains, target_scope_allows


def _archive_domains(ctx):
    """Never broaden an exact app target to an unauthorized hosting apex."""
    domains = [root for root in get_root_domains(ctx) if target_scope_allows(ctx, root)]
    for host in get_domains(ctx):
        if (target_scope_allows(ctx, host) and
                not any(host == root or host.endswith('.'+root) for root in domains)):
            domains.append(host)
    return list(dict.fromkeys(domains))


SECRET_REGEXES = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"'\s:=]+([0-9a-zA-Z/+]{40})", "AWS Secret"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack Token"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Token"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token"),
    (r"github_pat_[0-9a-zA-Z_]{82}", "GitHub Fine-grained PAT"),
    (r"glpat-[0-9a-zA-Z\-_]{20}", "GitLab PAT"),
    (r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY", "Private Key"),
    (r"eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}", "JWT"),
    (r"(?i)mongodb(\+srv)?://[^\s\"']{10,}", "MongoDB URI"),
    (r"(?i)postgres(ql)?://[^\s\"']{10,}", "Postgres URI"),
    (r"(?i)redis://[^\s\"']{10,}", "Redis URI"),
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key"),
]

ENDPOINT_REGEXES = [
    re.compile(r"""['"`]((?:/|https?://)[a-zA-Z0-9_/\-?=&.%~+]{4,200})['"`]"""),
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`]+)['"`]"""),
]


def run(ctx):
    from core.targets import get_root_domains, primary_label
    alive_file = ctx.output / "recon" / "alive.txt"
    if not alive_file.exists():
        ctx.log("WARN", "discovery", "no alive.txt — skipping")
        return
    alive = ctx.runner.read_lines(alive_file)
    if not alive:
        ctx.log("WARN", "discovery", "no live hosts — skipping")
        return

    disc = ctx.output / "recon"
    urls_file = disc / "urls.txt"
    js_file = disc / "javascript.txt"
    endpoints_file = disc / "js_endpoints.txt"
    secrets_file = disc / "js_secrets.txt"
    params_file = disc / "params.txt"
    katana_file = disc / "katana_urls.txt"
    paramspider_file = disc / "paramspider_urls.txt"

    all_urls = set()
    katana_urls = set()
    paramspider_urls = set()
    all_root_domains = get_root_domains(ctx)
    primary = primary_label(ctx)

    # Multi-target: iterate over ALL root domains
    for domain in _archive_domains(ctx):
        if ctx.runner.has("waybackurls"):
            ctx.log("INFO", "discovery", f"waybackurls for {domain}...")
            lines = ctx.runner.run_lines(["waybackurls", domain],
                                         timeout=600, log_name=f"waybackurls_{domain}")
            all_urls.update(lines)
            ctx.log("OK", "discovery", f"  waybackurls {domain}: +{len(lines)}")

        if ctx.runner.has("gau"):
            ctx.log("INFO", "discovery", f"gau for {domain}...")
            lines = ctx.runner.run_lines(["gau", "--threads", str(max(1, min(int(getattr(ctx, "threads", 5)), 20))), domain],
                                         timeout=600, log_name=f"gau_{domain}")
            all_urls.update(lines)
            ctx.log("OK", "discovery", f"  gau {domain}: +{len(lines)}")

        if ctx.profile.get("active_probes", True) and ctx.runner.has("paramspider"):
            ctx.log("INFO", "discovery", f"ParamSpider for {domain}...")
            lines = ctx.runner.run_lines(
                ["paramspider", "-d", domain, "-s"], timeout=900,
                log_name=f"paramspider_{domain}")
            clean = {line.strip() for line in lines if line.strip().startswith(("http://", "https://"))
                     and target_scope_allows(ctx, line.strip())}
            paramspider_urls.update(clean)
            all_urls.update(clean)
            ctx.log("OK", "discovery", f"  ParamSpider {domain}: +{len(clean)} URL(s)")

    ctx.runner.write_lines(paramspider_file, sorted(paramspider_urls))

    if ctx.profile.get("active_probes", True) and ctx.runner.has("katana"):
        depth = ctx.profile.get("katana_depth", 2)
        ctx.log("INFO", "discovery", f"running katana (depth={depth})...")
        rate = max(1, int(float((ctx.profile.get("rate_limit", {}) or {}).get("per_target_rps", 1) or 1)))
        lines = ctx.runner.run_lines(
            ["katana", "-list", str(alive_file), "-d", str(depth),
             "-silent", "-jc", "-jsl", "-rl", str(rate)],
            timeout=900, log_name="katana"
        )
        katana_urls.update(line.strip() for line in lines if line.strip().startswith(("http://", "https://"))
                           and target_scope_allows(ctx, line.strip()))
        all_urls.update(katana_urls)
        ctx.runner.write_lines(katana_file, sorted(katana_urls))
        ctx.log("OK", "discovery", f"katana: +{len(katana_urls)} URLs")

    # Apply the same host-boundary decision used before dispatch/persistence.
    all_urls = {u for u in all_urls if target_scope_allows(ctx, u)}
    ctx.runner.write_lines(urls_file, all_urls)
    ctx.log("OK", "discovery", f"Total URLs (across all targets): {len(all_urls)}")

    ctx.log("INFO", "discovery", "scoring endpoints (algebra from design doc 3.1)...")
    scored = 0
    for url in list(all_urls)[:5000]:
        score, comp = score_endpoint(url)
        if score > 5:
            ctx.storage.save_endpoint_score(url, score, comp)
            scored += 1
    ctx.log("OK", "discovery", f"Scored {scored} endpoints (kept score > 5)")
    top = ctx.storage.top_endpoints(30)
    if top:
        ctx.log("INFO", "discovery",
                f"Top endpoint: {top[0]['url'][:80]} (score={top[0]['score']:.1f})")

    js_urls = sorted(u for u in all_urls if u.lower().endswith((".js", ".mjs")) or ".js?" in u.lower() or ".mjs?" in u.lower())
    ctx.runner.write_lines(js_file, js_urls)
    if js_urls:
        ctx.log("OK", "discovery", f"queued {len(js_urls)} JavaScript candidate(s) for the dedicated js_analysis phase")

    discovered_params = set()
    for u in all_urls:
        if "?" in u:
            for kv in u.split("?", 1)[1].split("&"):
                if "=" in kv:
                    discovered_params.add(kv.split("=", 1)[0])

    if ctx.profile.get("active_probes", True) and ctx.runner.has("arjun"):
        ctx.log("INFO", "discovery", "running arjun on top-scored endpoints...")
        param_urls = [t["url"] for t in top[:20]]
        if param_urls:
            param_input = ctx.output / "recon" / "_arjun_in.txt"
            ctx.runner.write_lines(param_input, param_urls)
            rc, out, _ = ctx.runner.run(
                ["arjun", "-i", str(param_input), "-oJ",
                 str(ctx.output / "recon" / "arjun.json"), "-q"],
                timeout=600, log_name="arjun"
            )
            found = set()
            try:
                data = json.loads((ctx.output / "recon" / "arjun.json").read_text())
                for v in data.values():
                    for p in v.get("params", []):
                        found.add(p)
            except Exception:
                pass
            merged_params = discovered_params | found
            ctx.runner.write_lines(params_file, merged_params)
            ctx.log("OK", "discovery", f"arjun: +{len(found)} parameters; total {len(merged_params)}")
        else:
            ctx.runner.write_lines(params_file, discovered_params)
    else:
        ctx.runner.write_lines(params_file, discovered_params)


def _analyze_js(ctx, js_urls):
    endpoints = set()
    secrets = []
    for url in js_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TBHM/2.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                body = r.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
        except Exception:
            continue
        for rx in ENDPOINT_REGEXES:
            for m in rx.findall(body):
                ep = m if isinstance(m, str) else m[0]
                if 4 < len(ep) < 200 and not ep.startswith(("data:", "blob:", "javascript:")):
                    endpoints.add(ep)
        for pattern, name in SECRET_REGEXES:
            for m in re.finditer(pattern, body):
                secrets.append({"url": url, "type": name, "match": m.group(0)})
    return sorted(endpoints), secrets
