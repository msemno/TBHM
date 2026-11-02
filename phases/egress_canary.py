"""
Phase: egress_canary   (v3.2)   [--test-egress-canary]

Automated DLP / egress-monitoring reachability matrix. It answers the red-team
question "which outbound channels does this network actually allow?" WITHOUT
exfiltrating any real data.

Safety model:
  * Every probe carries only a random, meaningless canary token.
  * TCP channel tests CONNECT and immediately close — no bytes of payload sent.
  * DNS tests resolve a unique canary subdomain (the token is the only content).
  * HTTP(S)/webhook tests only run against a canary host YOU provide
    (--egress-canary-host, e.g. your interactsh/canarytokens listener); the body
    is the random token, never data from the target.
  * No target data is ever read or transmitted. Opt-in only.

Output: egress_matrix.json — per channel: allowed / blocked / latency.
"""
from __future__ import annotations

import json
import secrets
import socket
import subprocess
import time
from pathlib import Path


def _tcp_probe(host, port, timeout=5):
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.time() - t0) * 1000)
    except Exception:
        return False, None


def _dns_probe(fqdn, timeout=5):
    t0 = time.time()
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(fqdn, None)
        return True, round((time.time() - t0) * 1000)
    except Exception:
        # NXDOMAIN still proves the query egressed to a resolver
        return None, round((time.time() - t0) * 1000)


def _http_probe(url, token, verify=False, timeout=8):
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
        t0 = time.time()
        r = requests.get(url, params={"c": token}, timeout=timeout, verify=verify)
        return r.status_code < 500, round((time.time() - t0) * 1000)
    except Exception:
        return False, None


def _icmp_probe(host):
    try:
        rc = subprocess.run(["ping", "-c", "1", "-W", "3", host],
                            capture_output=True, timeout=8).returncode
        return rc == 0, None
    except Exception:
        return False, None


def run(ctx):
    if not getattr(ctx.args, "test_egress_canary", False):
        return
    # Explicit egress-canary mode does not override offline isolation.
    if getattr(ctx.args, 'offline', False):
        ctx.log('WARN', 'egress_canary', 'offline: external egress tests blocked')
        return

    token = "tbhm" + secrets.token_hex(6)
    canary = (getattr(ctx.args, "egress_canary_host", None) or "").strip().strip("/")
    out_dir = ctx.output / "egress"
    out_dir.mkdir(exist_ok=True)
    ctx.log("INFO", "egress_canary",
            "━━━ egress reachability matrix (canary-only, no data) ━━━")

    results = []

    # TCP connect-only channels (no payload) — proves the port/host is allowed out
    tcp_channels = [
        ("HTTPS (443)", "www.github.com", 443),
        ("HTTP (80)", "www.github.com", 80),
        ("DNS/TCP (53)", "1.1.1.1", 53),
        ("SSH (22)", "github.com", 22),
        ("SMTP (25)", "aspmx.l.google.com", 25),
        ("IRC (6667)", "irc.libera.chat", 6667),
        ("WebSocket/HTTPS (443)", "gateway.discord.gg", 443),
        ("Slack egress (443)", "hooks.slack.com", 443),
        ("Telegram (443)", "api.telegram.org", 443),
        ("Pastebin (443)", "pastebin.com", 443),
        ("DoH (443)", "cloudflare-dns.com", 443),
    ]
    for label, host, port in tcp_channels:
        ok, ms = _tcp_probe(host, port)
        results.append({"channel": label, "type": "tcp-connect", "host": host,
                        "port": port, "allowed": bool(ok), "latency_ms": ms,
                        "payload": "none (connect only)"})

    # DNS exfil channel (query carries the token as a subdomain, if canary given)
    if canary:
        fqdn = f"{token}.{canary}"
        ok, ms = _dns_probe(fqdn)
        results.append({"channel": "DNS exfil (subdomain)", "type": "dns",
                        "host": fqdn, "allowed": ok is not False, "latency_ms": ms,
                        "payload": "random token only"})
        # HTTP/HTTPS/webhook style to the canary listener
        for scheme in ("https", "http"):
            url = f"{scheme}://{canary}/{token}"
            ok, ms = _http_probe(url, token)
            results.append({"channel": f"{scheme.upper()} to canary", "type": "http",
                            "host": canary, "allowed": bool(ok), "latency_ms": ms,
                            "payload": "random token only"})
        icmp_ok, _ = _icmp_probe(canary.split("/")[0])
        results.append({"channel": "ICMP", "type": "icmp", "host": canary,
                        "allowed": bool(icmp_ok), "latency_ms": None,
                        "payload": "none"})
    else:
        ctx.log("INFO", "egress_canary",
                "no --egress-canary-host given; running connect-only TCP matrix "
                "(pass your interactsh/canarytokens host for DNS/HTTP/ICMP tests)")

    (out_dir / "egress_matrix.json").write_text(json.dumps(
        {"canary_token": token, "results": results}, indent=2))

    allowed = [r for r in results if r["allowed"]]
    ctx.log("OK", "egress_canary",
            f"{len(allowed)}/{len(results)} channels reachable outbound → egress_matrix.json")

    if allowed:
        risky = [r["channel"] for r in allowed if r["channel"] not in
                 ("HTTPS (443)", "HTTP (80)", "DNS/TCP (53)")]
        ctx.save_finding({
            "phase": "egress_canary", "severity": "MEDIUM" if risky else "INFO",
            "confidence": "MEDIUM",
            "title": f"Outbound egress: {len(allowed)} channel(s) reachable"
                     + (f", {len(risky)} unusual" if risky else ""),
            "target": ctx.targets[0] if ctx.targets else "",
            "description": "Reachability-only egress test (no data exfiltrated). Channels "
                           "reachable outbound: " + ", ".join(r["channel"] for r in allowed)
                           + ". Unusual channels suggest weak egress filtering / DLP gaps.",
            "evidence": json.dumps([r["channel"] for r in allowed]),
            "impact": "Permissive egress enables C2 and data exfiltration paths a SOC may not monitor.",
            "remediation": "Restrict egress to an allow-list, inspect DNS/DoH, and alert on unusual "
                           "outbound protocols (IRC, raw SMTP, pastebin, messaging APIs).",
            "cwe": "CWE-1008", "mrs_score": 50 if risky else 20,
        })
