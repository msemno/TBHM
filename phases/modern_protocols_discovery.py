"""
Phase: modern_protocols_discovery   (v3.3)

Read-only discovery of modern/real-time protocols that classic web scanners miss.
It complements interface_probe with:

  * passive LAN discovery: mDNS (5353/udp) and SSDP (1900/udp) — a single
    multicast query, listens briefly, records responders.
  * HTTP-level detection of WebSocket, graphql-ws, MCP (Model Context Protocol),
    AsyncAPI, and Server-Sent-Events endpoints via upgrade/headers/paths.

No fuzzing, no auth attempts. Discovery only.
"""
from __future__ import annotations

import json
import socket
import struct
import time
from urllib.parse import urlparse

_SSDP_MSG = ("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
             "MAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n").encode()


def _ssdp_discover(timeout=2):
    found = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.sendto(_SSDP_MSG, ("239.255.255.250", 1900))
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(2048)
                found.append({"addr": addr[0], "banner": data.decode(errors="ignore")[:200]})
            except socket.timeout:
                break
        s.close()
    except Exception:
        pass
    # dedup by addr
    seen, out = set(), []
    for f in found:
        if f["addr"] not in seen:
            seen.add(f["addr"]); out.append(f)
    return out


def _mdns_discover(timeout=2):
    found = []
    try:
        # minimal mDNS PTR query for _services._dns-sd._udp.local
        q = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for part in (b"_services", b"_dns-sd", b"_udp", b"local"):
            q += bytes([len(part)]) + part
        q += b"\x00\x00\x0c\x00\x01"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.sendto(q, ("224.0.0.251", 5353))
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(2048)
                found.append({"addr": addr[0], "bytes": len(data)})
            except socket.timeout:
                break
        s.close()
    except Exception:
        pass
    seen, out = set(), []
    for f in found:
        if f["addr"] not in seen:
            seen.add(f["addr"]); out.append(f)
    return out


def run(ctx):
    out_dir = ctx.output / "modern_protocols"
    out_dir.mkdir(exist_ok=True)
    result = {"ssdp": [], "mdns": [], "http_protocols": []}

    if getattr(ctx.args, "lan_discovery", False):
        result["ssdp"] = _ssdp_discover()
        result["mdns"] = _mdns_discover()
        ctx.log("INFO", "modern_protocols_discovery",
                f"LAN: SSDP={len(result['ssdp'])} mDNS responders={len(result['mdns'])}")

    # HTTP protocol detection
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except Exception:
        requests = None

    if requests:
        cands = []
        for t in (ctx.targets or []):
            base = t if t.startswith("http") else "https://" + t
            p = urlparse(base)
            root = f"{p.scheme}://{p.netloc}"
            for path in ("/", "/ws", "/socket.io/", "/graphql", "/mcp", "/sse",
                         "/asyncapi", "/asyncapi.json", "/events"):
                cands.append(root + path)
        for url in list(dict.fromkeys(cands))[:40]:
            ctx.runner.throttle("modern_proto")
            try:
                r = requests.get(url, timeout=8, verify=False,
                                 headers={"Upgrade": "websocket", "Connection": "Upgrade"})
            except Exception:
                continue
            hdr = {k.lower(): v.lower() for k, v in r.headers.items()}
            proto = None
            if r.status_code == 101 or "websocket" in hdr.get("upgrade", ""):
                proto = "WebSocket"
            elif "text/event-stream" in hdr.get("content-type", ""):
                proto = "Server-Sent Events"
            elif "graphql-ws" in r.text.lower() or "subscriptions-transport-ws" in r.text.lower():
                proto = "graphql-ws"
            elif "asyncapi" in r.text.lower() and url.endswith(("asyncapi", "asyncapi.json")):
                proto = "AsyncAPI"
            elif "/mcp" in url and r.status_code < 500 and ("jsonrpc" in r.text.lower() or "mcp" in r.text.lower()):
                proto = "MCP"
            if proto:
                result["http_protocols"].append({"url": url, "protocol": proto,
                                                  "status": r.status_code})

    (out_dir / "modern_protocols.json").write_text(json.dumps(result, indent=2))
    for hp in result["http_protocols"]:
        ctx.save_finding({
            "phase": "modern_protocols_discovery", "severity": "INFO", "confidence": "MEDIUM",
            "title": f"{hp['protocol']} endpoint discovered",
            "target": ctx.targets[0] if ctx.targets else hp["url"], "url": hp["url"],
            "description": f"A {hp['protocol']} endpoint was detected (discovery only). Real-time "
                           f"protocols often lack the auth/rate controls of the REST surface.",
            "evidence": f"{hp['url']} -> {hp['status']} ({hp['protocol']})",
            "impact": "Untested real-time surface may expose auth/authorization or DoS gaps.",
            "remediation": "Apply the same authN/Z, origin checks, and rate limits as REST endpoints.",
            "mrs_score": 15,
        })
    ctx.log("OK", "modern_protocols_discovery",
            f"HTTP real-time endpoints: {len(result['http_protocols'])} → modern_protocols.json")
