"""
Phase: api_fuzz   (v2.13)

Hidden-endpoint discovery for APIs that hide behind a catch-all gateway (every
path -> 200 + the same {"code":"invalid_endpoint"} envelope). Normal fuzzers are
blind here because status and size never change. This phase:

  1. Calibrates the catch-all baseline per host (random nonsense paths).
  2. Fuzzes a curated API wordlist, reporting ONLY responses that deviate from
     the baseline, including JSON error-code changes. These are routing
     observations; gateway/WAF policy can produce them without a real endpoint.
  3. Method-fuzzes each path (GET + POST by default) because many API routes
     only respond to POST. OPTIONS is probed for the Allow header.

Rate limited (default 2 req/sec) to honour automated-tool limits. POST/PUT/etc.
are only sent with --allow-writes; without it the phase stays GET/OPTIONS/HEAD.
"""
from __future__ import annotations

import secrets
from pathlib import Path
from urllib.parse import urlparse

import requests

from core import api_baseline as AB
from core import noise_filter
from core.targets import target_scope_allows
from core.http_policy import BudgetedSession

# Methods considered "writes" — gated behind --allow-writes.
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _request(session, method, url, rl, timeout=12, allow_post_body=False):
    """One rate-limited request. Returns (status, body, headers) or None."""
    rl.wait()
    try:
        kwargs = {"timeout": timeout, "allow_redirects": False, "verify": False}
        if method in ("POST", "PUT", "PATCH") and allow_post_body:
            # Send an empty JSON body — enough to trip 'missing parameter' on
            # real endpoints without submitting meaningful data.
            kwargs["json"] = {}
        resp = session.request(method, url, **kwargs)
        return resp.status_code, resp.text, dict(resp.headers)
    except requests.RequestException:
        return None


def _calibrate(session, base_url, methods, rl, allow_writes) -> AB.Baseline:
    """Fingerprint the catch-all response for each method."""
    bl = AB.Baseline(host=urlparse(base_url).hostname or base_url)
    for method in methods:
        sigs = []
        for _ in range(3):
            token = secrets.token_hex(12)
            url = base_url.rstrip("/") + "/" + token
            r = _request(session, method, url, rl, allow_post_body=allow_writes)
            if r is None:
                continue
            status, body, headers = r
            sigs.append(AB.make_signature(status, body, headers, strip_token=token))
        if sigs:
            # Use the first as representative; record whether it's a catch-all.
            bl.per_method[method] = sigs[0]
            if AB.detect_catch_all(sigs):
                bl.detected = True
    return bl


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        ctx.log("INFO", "api_fuzz", "passive profile - skipping")
        return

    requests.packages.urllib3.disable_warnings()  # silence TLS verify=False noise

    # Determine base URLs to test.
    bases = []
    explicit = getattr(ctx.args, "api_base", None)
    if explicit:
        bases = [explicit]
    else:
        for fname in ("alive.txt",):
            f = ctx.output / "recon" / fname
            if f.exists():
                bases.extend(ctx.runner.read_lines(f))
        if not bases:
            bases = [t if t.startswith("http") else f"https://{t}" for t in ctx.targets]

    in_scope = set()
    try:
        from core.targets import get_root_domains
        in_scope = set(get_root_domains(ctx))
    except Exception:
        pass
    bases = [b for b in bases if target_scope_allows(ctx, b)
             and not noise_filter.is_noise(b, in_scope_hosts=in_scope)[0]]
    bases = list(dict.fromkeys(bases))[:25]
    if not bases:
        ctx.log("WARN", "api_fuzz", "no base URLs - skipping")
        return

    # Methods to fuzz.
    allow_writes = bool(getattr(ctx.args, "allow_writes", False))
    methods_arg = getattr(ctx.args, "api_methods", None) or "GET,POST"
    methods = [m.strip().upper() for m in methods_arg.split(",") if m.strip()]
    if not allow_writes:
        blocked = [m for m in methods if m in WRITE_METHODS]
        methods = [m for m in methods if m not in WRITE_METHODS]
        if "OPTIONS" not in methods:
            methods.append("OPTIONS")
        if blocked:
            ctx.log("INFO", "api_fuzz",
                    f"write methods {blocked} skipped (use --allow-writes to enable); "
                    f"running {methods}")
    methods = list(dict.fromkeys(methods)) or ["GET"]

    # Rate limit.
    requested_rps = getattr(ctx.args, "api_rate", None)
    api_rps = float(2.0 if requested_rps is None else requested_rps)

    # Budget guard so a big list × methods can't run away.
    requested_budget = getattr(ctx.args, "api_budget", None)
    budget = int(6000 if requested_budget is None else requested_budget)
    if api_rps <= 0 or budget <= 0:
        ctx.log("INFO", "api_fuzz", "zero rate or request budget — skipping")
        return

    # Wordlist.
    wl_path = getattr(ctx.args, "api_wordlist", None)
    candidates = _load_wordlist(ctx, wl_path)
    if not candidates:
        ctx.log("WARN", "api_fuzz", "no API wordlist found - skipping")
        return

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (TBHM api_fuzz; authorized testing)",
        "Accept": "application/json, */*",
    })
    # Route through Burp/ZAP if --proxy is set, so every probe is captured for
    # manual replay of the discovered GET/POST endpoints.
    proxy = getattr(ctx.args, "proxy", None)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        session.verify = False
        ctx.log("INFO", "api_fuzz", f"proxying api_fuzz through {proxy}")

    ctx.log("INFO", "api_fuzz",
            f"━━━ API fuzz: {len(bases)} host(s) × {len(candidates)} paths × "
            f"{methods} @ {api_rps} req/s ━━━")

    session = BudgetedSession(ctx, session, budget=budget, max_rps=api_rps)
    rl = session

    total_req = 0
    total_found = 0
    out_dir = ctx.output / "api"
    out_dir.mkdir(exist_ok=True)
    discovered_log = out_dir / "discovered_endpoints.txt"
    disc_lines = []

    for base_url in bases:
        if total_req >= budget:
            break
        base_url = base_url.rstrip("/")
        bl = _calibrate(session, base_url, methods, rl, allow_writes)
        total_req = session.used
        if bl.detected:
            ctx.log("INFO", "api_fuzz",
                    f"{bl.host}: catch-all gateway detected — filtering against baseline")
        else:
            ctx.log("INFO", "api_fuzz",
                    f"{bl.host}: no catch-all (normal 404s) — fuzzing anyway")

        for path in candidates:
            if total_req >= budget:
                ctx.log("WARN", "api_fuzz", f"request budget {budget} reached — stopping")
                break
            url = base_url + "/" + path.lstrip("/")
            for method in methods:
                if not session.remaining:
                    break
                r = _request(session, method, url, rl,
                             allow_post_body=(allow_writes and method in WRITE_METHODS))
                total_req = session.used
                if r is None:
                    continue
                status, body, headers = r
                cand = AB.make_signature(status, body, headers)
                base_sig = bl.sig_for(method) or bl.sig_for("GET")
                deviates, classification, severity = AB.classify(cand, base_sig)

                # OPTIONS Allow header is a free existence + method leak.
                allow_hdr = headers.get("Allow") or headers.get("allow")
                if method == "OPTIONS" and allow_hdr and not deviates:
                    deviates = True
                    classification = f"OPTIONS Allow header: {allow_hdr}"
                    severity = "INFO"

                if not deviates:
                    continue

                total_found += 1
                disc_lines.append(f"{status}\t{method}\t{url}\t{classification}")
                evidence = f"{method} {url} -> HTTP {status}"
                if cand.json_code:
                    evidence += f" | code={cand.json_code}"
                if allow_hdr:
                    evidence += f" | Allow={allow_hdr}"
                ctx.save_finding({
                    "phase": "api_fuzz",
                    "severity": severity,
                    "confidence": "HIGH" if cand.json_code else "MEDIUM",
                    "title": f"API response inventory: /{path} [{method}]",
                    "finding_class": "lead",
                    "target": bl.host,
                    "url": url,
                    "method": method,
                    "parameter": "",
                    "description": (
                        f"Path /{path} deviates from the catch-all baseline on {method}. "
                        f"{classification}. A gateway, WAF, redirect, or generic error handler "
                        "may also produce this deviation. Endpoint existence, sensitive "
                        "content, and authorization behavior remain unverified."
                    ),
                    "evidence": evidence[:400],
                    "impact": classification,
                    "remediation": "Confirm the route, then test it for authz/IDOR/injection per its function.",
                    "reproducer_curl": _curl(method, url, allow_writes and method in WRITE_METHODS),
                    "response_raw": (body or "")[:2000],
                    "mrs_score": {"MEDIUM": 55, "LOW": 35, "INFO": 25}.get(severity, 25),
                })

    if disc_lines:
        discovered_log.write_text("\n".join(disc_lines))
    session.close()
    ctx.log("OK", "api_fuzz",
            f"api_fuzz: {total_found} response deviation(s) from {total_req} requests "
            f"(baseline-filtered). List: {discovered_log if disc_lines else '(none)'}")


def _curl(method, url, with_body):
    c = f"curl -i -sk -X {method} '{url}'"
    if with_body:
        c += " -H 'Content-Type: application/json' -d '{}'"
    return c


def _load_wordlist(ctx, override):
    paths = []
    if override and Path(override).is_file():
        paths.append(Path(override))
    # Bundled API wordlist.
    bundled = Path(__file__).resolve().parent.parent / "wordlists" / "api-endpoints.txt"
    if bundled.is_file():
        paths.append(bundled)
    # SecLists API list as a bonus if present.
    try:
        from core import seclists
        sl = seclists.get("api_endpoints")
        if sl:
            paths.append(Path(sl))
    except Exception:
        pass
    words = []
    seen = set()
    for p in paths:
        try:
            for ln in p.read_text(errors="ignore").splitlines():
                w = ln.strip().lstrip("/")
                if w and not w.startswith("#") and w not in seen:
                    seen.add(w)
                    words.append(w)
        except Exception:
            continue
    return words
