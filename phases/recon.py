"""
Phase: recon (v2.1 multi-target rewrite)

Iterates over ALL inputs:
  - Domain inputs: full subdomain enumeration per domain
  - URL inputs: extracted host + URL added directly to alive list
  - Results de-duplicated and unified into recon/alive.txt

Sources (degraded gracefully when tools/keys missing):
  Passive:
    crt.sh, subfinder (8+ sources), assetfinder, chaos (CHAOS_KEY),
    github-subdomains (GITHUB_TOKEN), amass passive
  Active:
    dnsx + SecLists brute-force, dns permutations (gotator/altdns),
    httpx for liveness + tech fingerprint
"""
from __future__ import annotations

import json
import math
import os
import re
import urllib.request
from pathlib import Path

from core import seclists, intensity
from core.targets import get_root_domains, get_url_targets, get_domains, _bare_host, target_scope_allows


def _network_rate(ctx):
    profile=getattr(ctx,'profile',{}) or {}
    if profile.get('active_probes') is False or profile.get('name')=='passive_only': return 0.0
    rate=profile.get('rate_limit',{}) or {}; hard=profile.get('hard_limits',{}) or {}
    values=[rate.get('global_rps',1),rate.get('per_target_rps',1),rate.get('hard_cap',50),
            hard.get('max_global_rps',50),hard.get('max_per_target_rps',20)]
    policy=getattr(ctx,'program_policy',None)
    if policy: values.append(policy.get('max_requests_per_second',0))
    try:
        numbers=[float(v) for v in values]
        return min(numbers) if all(math.isfinite(v) and v>0 for v in numbers) else 0.0
    except (TypeError,ValueError): return 0.0


def _dns_authorized(ctx, host):
    if not target_scope_allows(ctx,host): return False
    policy=getattr(ctx,'program_policy',None)
    if policy:
        from core.program_policy import evaluate_asset, evaluate_action
        return (evaluate_asset(policy,host)['decision']=='in_scope'
                and evaluate_action(policy,'recon_dns')['allowed'])
    return True


def run(ctx):
    if _network_rate(ctx)<=0:
        recon_dir=ctx.output/'recon'; recon_dir.mkdir(parents=True,exist_ok=True)
        for name in ('subdomains.txt','alive.txt'): ctx.runner.write_lines(recon_dir/name,[])
        (recon_dir/'tech.json').write_text('[]')
        ctx.phase_state['alive_hosts']=[]
        ctx.phase_state['recon_status']={'status':'blocked','reason':'passive/zero/invalid network rate'}
        ctx.log('INFO','recon','network collection disabled before DNS, providers and liveness')
        return
    domains = get_root_domains(ctx)
    all_input_domains = get_domains(ctx)
    url_targets = [u for u in get_url_targets(ctx) if target_scope_allows(ctx, u)]

    ctx.log("INFO", "recon",
            f"Multi-target recon over {len(domains)} root domain(s) + {len(url_targets)} URL input(s)")
    ctx.log("INFO", "recon", f"Root domains: {', '.join(domains[:5])}"
            + (f" (+{len(domains)-5} more)" if len(domains) > 5 else ""))

    # Tool/API availability report (transparency)
    _report_recon_capabilities(ctx)

    recon_dir = ctx.output / "recon"
    subdomains_file = recon_dir / "subdomains.txt"
    alive_file = recon_dir / "alive.txt"
    tech_file = recon_dir / "tech.json"

    all_subs = set()
    # Seed with the input hosts themselves (don't lose them)
    all_subs.update(all_input_domains)

    # ── Run all sources per root domain ─────────────────────────────────────
    for domain in domains:
        ctx.log("INFO", "recon", f"━━━ enumerating {domain} ━━━")
        before = len(all_subs)
        if _dns_authorized(ctx,domain):
            _dns_basics(ctx, domain, recon_dir)
            all_subs.update(_crtsh(ctx, domain))
            all_subs.update(_subfinder(ctx, domain))
            all_subs.update(_assetfinder(ctx, domain))
            all_subs.update(_chaos(ctx, domain))
            all_subs.update(_github_subdomains(ctx, domain))
            all_subs.update(_amass_passive(ctx, domain))
        else:
            ctx.log('INFO','recon',f'apex source adapters blocked outside authorized scope: {domain}')
        if ctx.profile.get("active_probes", True):
            all_subs.update(_dns_bruteforce(ctx, domain, recon_dir))
            all_subs.update(_dns_permutations(ctx, all_subs, domain, recon_dir))
        added = len(all_subs) - before
        ctx.log("OK", "recon", f"  {domain}: +{added} subdomains "
                f"({len(all_subs)} total)")

    # ── Filter to in-scope ───────────────────────────────────────────────────
    in_scope_subs = set()
    for s in all_subs:
        s = s.strip().lower().lstrip("*.")
        if not s or "*" in s:
            continue
        # Must end in one of our root domains
        if any(s == d or s.endswith("." + d) for d in domains):
            in_scope_subs.add(s)
        else:
            # Allow if it's an exact input host (URL-input case)
            if s in all_input_domains:
                in_scope_subs.add(s)

    # Apply scope: in-scope allowlist (--scope) AND out-of-scope denylist (--exclude).
    # v2.15: previously only excludes were applied; --scope is now enforced too.
    scope = getattr(ctx, "scope", None)
    if scope is not None:
        before = len(in_scope_subs)
        in_scope_subs = scope.filter(in_scope_subs)
        dropped = before - len(in_scope_subs)
        if dropped:
            ctx.log("INFO", "recon", f"scope filter dropped {dropped} out-of-scope host(s)")
    elif ctx.scope_excludes:
        in_scope_subs = {s for s in in_scope_subs
                         if not any(ex.lower() in s for ex in ctx.scope_excludes)}

    in_scope_subs = {s for s in in_scope_subs if target_scope_allows(ctx, s)}
    ctx.runner.write_lines(subdomains_file, in_scope_subs)
    ctx.log("OK", "recon", f"Total unique in-scope subdomains: {len(in_scope_subs)}")

    # An empty authorized set is blocked, never replaced with unfiltered seeds.
    if not in_scope_subs and not url_targets:
        ctx.runner.write_lines(alive_file, [])
        tech_file.write_text("[]")
        ctx.phase_state["alive_hosts"] = []
        ctx.log("WARN", "recon", "no authorized liveness inputs — blocked")
        return

    # ── Liveness check ───────────────────────────────────────────────────────
    alive = _alive_check(ctx, subdomains_file, alive_file, tech_file, url_targets)
    ctx.phase_state["alive_hosts"] = alive
    ctx.log("OK", "recon", f"Live hosts: {len(alive)}")

    # Persist count as INFO finding
    if alive:
        ctx.save_finding({
            "phase": "recon",
            "severity": "INFO",
            "confidence": "HIGH",
            "title": f"Recon: {len(in_scope_subs)} subdomains, {len(alive)} live",
            "target": ", ".join(domains[:3]),
            "description": (f"Multi-target recon over {len(domains)} root domain(s) "
                            f"found {len(in_scope_subs)} subdomains in scope. "
                            f"{len(alive)} responded to HTTP probes."),
        })


# ──────────────────────────────────────────────────────────────────────────────
# Capability report (transparency)
# ──────────────────────────────────────────────────────────────────────────────
def _report_recon_capabilities(ctx):
    """Tell the user what tools+keys are available — sets expectations honestly."""
    have = lambda t: ctx.runner.has(t)
    key  = lambda k: bool(os.environ.get(k))

    items = [
        ("crt.sh",                "always available (no install)", True),
        ("subfinder",             "Go install",                    have("subfinder")),
        ("assetfinder",           "Go install",                    have("assetfinder")),
        ("amass",                 "Go install",                    have("amass")),
        ("chaos (PD)",            "CHAOS_KEY env + 'chaos' binary",
                                                                   have("chaos") and key("CHAOS_KEY")),
        ("github-subdomains",     "GITHUB_TOKEN env + binary",
                                                                   have("github-subdomains") and key("GITHUB_TOKEN")),
        ("findomain",             "binary",                        have("findomain")),
        ("dnsx (brute)",          "Go install",                    have("dnsx")),
        ("gotator/altdns (perm)", "perm wordlist generation",      have("gotator") or have("altdns")),
        ("httpx",                 "liveness + fingerprint",        have("httpx")),
    ]
    ctx.log("INFO", "recon", "── recon source capability report ──")
    for name, hint, ok in items:
        mark = "✓" if ok else "✗"
        sev  = "INFO" if ok else "WARN"
        ctx.log(sev, "recon", f"  [{mark}] {name:<22} ({hint})")
    if not any(key(k) for k in ("CHAOS_KEY", "GITHUB_TOKEN", "SHODAN_API_KEY",
                                 "CENSYS_API_ID", "VIRUSTOTAL_API_KEY")):
        ctx.log("WARN", "recon",
                "No recon API keys detected. Subdomain coverage will be limited. "
                "See README → 'API Keys' for free signup links.")


# ──────────────────────────────────────────────────────────────────────────────
# Individual sources
# ──────────────────────────────────────────────────────────────────────────────
def _dns_basics(ctx, domain, recon_dir):
    if _network_rate(ctx)<1 or not _dns_authorized(ctx,domain): return
    out_lines = []
    if ctx.runner.has("dig"):
        for rec in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
            rc, out, _ = ctx.runner.run(["dig", "+short", domain, rec],
                                         timeout=15, log_name=f"dig_{rec}")
            if out.strip():
                out_lines.append(f"=== {rec} ===\n{out.strip()}")
    if ctx.runner.has("whois"):
        rc, out, _ = ctx.runner.run(["whois", domain], timeout=20, log_name="whois")
        if out:
            out_lines.append(f"=== WHOIS ===\n{out[:5000]}")
    if out_lines:
        path = recon_dir / f"dns_whois_{domain}.txt"
        path.write_text("\n\n".join(out_lines))


def _crtsh(ctx, domain) -> set[str]:
    try:
        req = urllib.request.Request(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": "TBHM/2.1 recon"}
        )
        with urllib.request.urlopen(req, timeout=45) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        names = set()
        for row in data:
            for name in (row.get("name_value", "") or "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and "*" not in name:
                    names.add(name)
        ctx.log("OK", "recon", f"  crt.sh: +{len(names)} subdomains")
        return names
    except Exception as e:
        ctx.log("WARN", "recon", f"  crt.sh failed for {domain}: {e}")
        return set()


def _subfinder(ctx, domain) -> set[str]:
    if not ctx.runner.has("subfinder"):
        return set()
    lines = ctx.runner.run_lines(
        ["subfinder", "-d", domain, "-silent", "-all", "-recursive"],
        timeout=900, log_name=f"subfinder_{domain}")
    ctx.log("OK", "recon", f"  subfinder: +{len(lines)} subdomains")
    return {l.strip().lower() for l in lines}


def _assetfinder(ctx, domain) -> set[str]:
    if not ctx.runner.has("assetfinder"):
        return set()
    lines = ctx.runner.run_lines(
        ["assetfinder", "--subs-only", domain],
        timeout=300, log_name=f"assetfinder_{domain}")
    ctx.log("OK", "recon", f"  assetfinder: +{len(lines)} subdomains")
    return {l.strip().lower() for l in lines}


def _chaos(ctx, domain) -> set[str]:
    if not ctx.runner.has("chaos"):
        return set()
    if not (os.environ.get("CHAOS_KEY") or os.environ.get("PDCP_API_KEY")):
        return set()
    lines = ctx.runner.run_lines(
        ["chaos", "-d", domain, "-silent"],
        timeout=300, log_name=f"chaos_{domain}",
        env={"PDCP_API_KEY": os.environ.get("CHAOS_KEY") or os.environ["PDCP_API_KEY"]},
        log_redactions=[os.environ.get("CHAOS_KEY") or os.environ["PDCP_API_KEY"]])
    ctx.log("OK", "recon", f"  chaos: +{len(lines)} subdomains")
    return {l.strip().lower() for l in lines}


def _github_subdomains(ctx, domain) -> set[str]:
    if not ctx.runner.has("github-subdomains"):
        return set()
    if not os.environ.get("GITHUB_TOKEN"):
        return set()
    lines = ctx.runner.run_lines(
        ["github-subdomains", "-d", domain],
        timeout=300, log_name=f"github_subs_{domain}",
        env={"GITHUB_TOKEN": os.environ["GITHUB_TOKEN"]},
        log_redactions=[os.environ["GITHUB_TOKEN"]])
    ctx.log("OK", "recon", f"  github-subdomains: +{len(lines)} subdomains")
    return {l.strip().lower() for l in lines}


def _amass_passive(ctx, domain) -> set[str]:
    if not ctx.runner.has("amass"):
        return set()
    # amass passive is fast enough for standard intensity
    rc, out, _ = ctx.runner.run(
        ["amass", "enum", "-passive", "-d", domain, "-silent"],
        timeout=600, log_name=f"amass_{domain}")
    lines = [l.strip().lower() for l in out.splitlines() if l.strip()]
    ctx.log("OK", "recon", f"  amass passive: +{len(lines)} subdomains")
    return set(lines)


def _dns_bruteforce(ctx, domain, recon_dir) -> set[str]:
    rl=_network_rate(ctx)
    if rl<1:
        ctx.log('INFO','recon','DNS child adapter blocked: zero/fractional rate unsupported')
        return set()
    if not ctx.runner.has("dnsx"):
        ctx.log("WARN", "recon", "  dnsx not installed - skipping DNS brute-force")
        return set()
    wl_name = intensity.get(ctx.profile, "subdomain_wordlist", "subdomains_small")
    wl_path = seclists.get(wl_name)
    if not wl_path:
        ctx.log("WARN", "recon", f"  wordlist '{wl_name}' not found - install SecLists")
        return set()
    max_count = intensity.get(ctx.profile, "max_subdomains_brute",
                              ctx.profile.get("max_subdomains", 2000))
    words = [w.strip() for w in wl_path.read_text(errors="ignore").splitlines()
             if w.strip() and not w.startswith("#")]
    words = words[:max_count]
    cand_file = recon_dir / f"_dns_brute_candidates_{domain}.txt"
    candidates=[f'{w}.{domain}' for w in words if _dns_authorized(ctx,f'{w}.{domain}')]
    if not candidates: return set()
    cand_file.write_text("\n".join(candidates))
    ctx.log("INFO", "recon",
            f"  dnsx brute-force ({wl_name}, {len(words)} candidates)…")
    rc, out, _ = ctx.runner.run(
        ["dnsx", "-l", str(cand_file), "-silent",
         "-rl", str(int(rl))],
        timeout=1200, log_name=f"dnsx_brute_{domain}")
    found = {l.strip().lower() for l in out.splitlines() if l.strip()}
    ctx.log("OK", "recon", f"  dnsx brute: +{len(found)} live subdomains")
    return {host for host in found if _dns_authorized(ctx,host)}


def _dns_permutations(ctx, existing_subs, domain, recon_dir) -> set[str]:
    """gotator/altdns generate permutations from already-found subs."""
    rl=_network_rate(ctx)
    if rl<1: return set()
    if not (ctx.runner.has("gotator") or ctx.runner.has("altdns")):
        return set()
    if not ctx.runner.has("dnsx"):
        return set()
    seeds = [s for s in existing_subs if s.endswith("." + domain) and _dns_authorized(ctx,s)][:200]
    if not seeds:
        return set()
    seed_file = recon_dir / f"_perm_seeds_{domain}.txt"
    seed_file.write_text("\n".join(seeds))
    perms_file = recon_dir / f"_perms_{domain}.txt"

    if ctx.runner.has("gotator"):
        rc, out, _ = ctx.runner.run(
            ["gotator", "-sub", str(seed_file), "-depth", "1",
             "-numbers", "3", "-mindup", "-adv"],
            timeout=120, log_name=f"gotator_{domain}")
        perms_file.write_text(out)
    else:
        # altdns
        rc, out, _ = ctx.runner.run(
            ["altdns", "-i", str(seed_file), "-o", str(perms_file)],
            timeout=120, log_name=f"altdns_{domain}")

    if not perms_file.exists() or perms_file.stat().st_size == 0:
        return set()
    # Cap to 50k permutations
    perms = [l.strip() for l in perms_file.read_text(errors="ignore").splitlines()
             if l.strip() and _dns_authorized(ctx,l.strip())][:50000]
    if not perms: return set()
    perms_file.write_text("\n".join(perms))
    ctx.log("INFO", "recon", f"  resolving {len(perms)} permutations…")
    rc, out, _ = ctx.runner.run(
        ["dnsx", "-l", str(perms_file), "-silent",
         "-rl", str(int(rl))],
        timeout=600, log_name=f"dnsx_perm_{domain}")
    found = {l.strip().lower() for l in out.splitlines() if l.strip()}
    ctx.log("OK", "recon", f"  permutations: +{len(found)} subdomains")
    return {host for host in found if _dns_authorized(ctx,host)}


# ──────────────────────────────────────────────────────────────────────────────
# Liveness — robust against httpx output variations
# ──────────────────────────────────────────────────────────────────────────────
def _alive_check(ctx, subs_file, alive_file, tech_file, url_targets):
    """
    httpx is finicky about flags across versions. We use plain text output
    (most reliable) and accept tech metadata as a bonus when JSON parses.
    URL inputs are always included in the alive list (they came pre-verified
    from the user).
    """
    alive = []
    tech_records = []
    # Recheck at the child boundary, including direct plugin calls to this helper.
    allowed = [s for s in ctx.runner.read_lines(subs_file) if target_scope_allows(ctx, s)]
    ctx.runner.write_lines(subs_file, allowed)
    url_targets = [u for u in url_targets if target_scope_allows(ctx, u)]
    if not allowed:
        alive = sorted(set(url_targets))
        ctx.runner.write_lines(alive_file, alive)
        tech_file.write_text("[]")
        return alive

    if ctx.runner.has("httpx") and _network_rate(ctx) >= 1:
        ctx.log("INFO", "recon", "running httpx (plain text first, JSON if successful)…")
        rl = int(_network_rate(ctx))
        # Plain text mode (most reliable). One URL per line.
        rc, out, err = ctx.runner.run(
            ["httpx", "-l", str(subs_file), "-silent",
             "-rl", str(rl), "-threads", str(max(1, min(int(getattr(ctx, "threads", 10)), 50))), "-timeout", "10",
             "-no-color"],
            timeout=1200, log_name="httpx_plain"
        )
        for line in out.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")) and target_scope_allows(ctx, line):
                alive.append(line)

        if rc:
            ctx.log('WARN', 'recon', f'HTTPX liveness rc={rc}; retained {len(alive)} partial URLs')
        cancelled = getattr(ctx.runner, '_cancel_event', None)
        if cancelled is not None and cancelled.is_set():
            ctx.runner.write_lines(alive_file, sorted(set(alive+url_targets)))
            tech_file.write_text('[]')
            return alive
        # JSON fingerprinting has a separate execution and parser outcome.
        try:
            rc, out, json_err = ctx.runner.run(
                ["httpx", "-l", str(subs_file), "-silent", "-json",
                 "-status-code", "-title", "-tech-detect", "-no-color",
                 "-rl", str(rl), "-threads", str(max(1, min(int(getattr(ctx, "threads", 10)), 50))), "-timeout", "10"],
                timeout=900, log_name="httpx_json"
            )
            from core.httpx_adapter import parse_records
            records, errors = parse_records(out)
            if rc:
                ctx.log('WARN', 'recon', f'HTTPX fingerprint TOOL_ERROR rc={rc}: {json_err[:240]}')
            ledger = getattr(ctx, 'execution_ledger', None)
            if errors and ledger:
                ledger.record(kind='parser', status='parser-error', tool='httpx',
                              reason=f'{len(errors)} invalid JSON/URL records', errors=errors[:10])
            for rec in records:
                if target_scope_allows(ctx, rec['url']):
                    tech_records.append({'url':rec['url'],
                        'status':rec.get('status_code') or rec.get('status-code'),
                        'title':rec.get('title', ''), 'tech':rec.get('technologies') or rec.get('tech') or []})
        except (ValueError, OSError) as exc:
            ctx.log('WARN', 'recon', f'HTTPX fingerprint parser failed: {exc}')
    else:
        ctx.log("WARN", "recon", "httpx not installed — Python fallback (slow)")
        alive = _python_alive_fallback(ctx, subs_file)

    # Always include URL inputs
    for u in url_targets:
        if u not in alive:
            alive.append(u)

    alive = sorted(set(alive))
    ctx.runner.write_lines(alive_file, alive)
    tech_file.write_text(json.dumps(tech_records, indent=2))

    # Diagnostic: if 0 live hosts, that's a red flag
    if not alive:
        ctx.log("WARN", "recon",
                "ZERO live hosts after liveness check. This is unusual. "
                "Common causes: httpx version flag mismatch, network egress blocked, "
                "or all targets DNS-resolve but deny HTTP. Inspect logs/httpx_plain.log")
    return alive


def _python_alive_fallback(ctx, subs_file):
    """stdlib-only fallback. Slow but always works."""
    import ssl
    from core.http_policy import BudgetedSession
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    proxy = getattr(getattr(ctx, 'args', None), 'proxy', None)
    proxies = {'http': proxy, 'https': proxy} if proxy else {}
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler(proxies),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    class Transport:
        _tbhm_action = 'recon'
        headers = {}
        def request(self, method, url, **options):
            req = urllib.request.Request(url, headers=options['headers'], method=method)
            return opener.open(req, timeout=options.get('timeout', 5))
    broker = BudgetedSession(ctx, Transport(), budget=600, max_rps=max(_network_rate(ctx), 0.0001))
    alive = []
    for sub in ctx.runner.read_lines(subs_file)[:300]:
        for proto in ("https", "http"):
            url = f"{proto}://{sub}"
            if not target_scope_allows(ctx, url):
                continue
            try:
                with broker.request("GET", url, timeout=5):
                    pass
                alive.append(url)
                break
            except urllib.error.HTTPError as exc:
                # A redirect proves the authorized origin responded. Record
                # that origin without following Location to another host.
                exc.close()
                if 300 <= exc.code < 400:
                    alive.append(url)
                    break
            except Exception:
                continue
    return alive
