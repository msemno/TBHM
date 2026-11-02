"""
Phase: smuggling   (v2.18)

Timing-differential HTTP request smuggling detection (CL.TE / TE.CL). DETECTION
ONLY — it sends a small number of probes and measures response delay; it does not
exploit, poison caches, or desync live user traffic.

OPT-IN: runs only with --smuggle, because even detection probes touch front-end/
back-end parsing and some programs disallow it. Off by default. Rate-limited by
--rate-limit / the profile like everything else.

Method: a normal request establishes baseline latency. A CL.TE probe declares a
Content-Length that stops before a chunk terminator; if the back-end speaks TE it
waits for more data → measurable delay vs baseline. A large, repeatable delta is
a smuggling indicator to confirm manually.
"""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from core import ratelimit


def _send_raw(host, port, use_tls, payload, timeout):
    """Send a raw HTTP payload over a socket; return elapsed seconds or None."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx_ssl = ssl.create_default_context()
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode = ssl.CERT_NONE
            sock = ctx_ssl.wrap_socket(sock, server_hostname=host)
        t0 = time.monotonic()
        sock.sendall(payload.encode())
        sock.settimeout(timeout)
        try:
            sock.recv(4096)
        except socket.timeout:
            pass
        dt = time.monotonic() - t0
        sock.close()
        return dt
    except Exception:
        return None


def _probe(host, port, use_tls, path, timeout):
    baseline = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Connection: close\r\n\r\n"
    )
    # CL.TE: front-end honours Content-Length, back-end honours chunked and waits.
    body = "0\r\n\r\nG"
    clte = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {len(body) - 1}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n{body}"
    )
    b = _send_raw(host, port, use_tls, baseline, timeout)
    c = _send_raw(host, port, use_tls, clte, timeout)
    return b, c


def run(ctx):
    if not getattr(ctx.args, "smuggle", False):
        return  # opt-in only

    targets = []
    f = ctx.output / "recon" / "alive.txt"
    if f.exists():
        targets = ctx.runner.read_lines(f)
    if not targets:
        targets = [t if t.startswith("http") else f"https://{t}" for t in ctx.targets]
    targets = list(dict.fromkeys(targets))[:25]
    if not targets:
        return

    # Rate: reuse the global cap (these are raw sockets, not through requests).
    rps = ratelimit.cap(ctx.profile, ctx.profile.get("rate_limit", {}).get("global_rps", 5))
    interval = 1.0 / max(0.5, rps)
    timeout = 12
    ctx.log("INFO", "smuggling", f"━━━ CL.TE/TE.CL timing probes on {len(targets)} host(s) (opt-in) ━━━")

    n = 0
    for url in targets:
        u = urlparse(url)
        host = u.hostname
        if not host:
            continue
        use_tls = (u.scheme == "https")
        port = u.port or (443 if use_tls else 80)
        path = u.path or "/"
        time.sleep(interval)
        b, c = _probe(host, port, use_tls, path, timeout)
        if b is None or c is None:
            continue
        # Significant, absolute delay on the CL.TE probe vs baseline = indicator.
        if c > (b + 5) and c >= 5:
            n += 1
            ctx.save_finding({
                "phase": "smuggling",
                "severity": "HIGH",
                "confidence": "LOW",
                "title": f"Possible HTTP request smuggling (CL.TE timing) on {host}",
                "target": host, "url": url, "method": "POST",
                "description": f"CL.TE probe delayed {c:.1f}s vs baseline {b:.1f}s. This timing "
                               f"differential suggests front-end/back-end disagree on request "
                               f"boundaries. UNCONFIRMED — verify manually before reporting; "
                               f"false positives occur with slow endpoints.",
                "evidence": f"baseline={b:.2f}s  clte_probe={c:.2f}s  delta={c-b:.2f}s",
                "impact": "Request queue poisoning, cache poisoning, auth bypass if confirmed.",
                "remediation": "Normalise/​reject ambiguous Content-Length + Transfer-Encoding; "
                               "use HTTP/2 end-to-end; align front-end and back-end parsers.",
                "cwe": "CWE-444",
                "mrs_score": 60,
            })
    ctx.log("OK", "smuggling", f"smuggling: {n} timing indicator(s) (manual confirmation required)")
