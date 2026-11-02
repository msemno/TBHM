"""
Phase: ot_ics_safe   (v3.3)

Read-only OT/ICS attack-surface discovery. It ONLY connects and reads; it never
writes coils/registers, never sends control commands, and never fuzzes a PLC. It
identifies exposed industrial services and SCADA/HMI web interfaces so they can
be reported for specialised, separately-authorized testing.

  * TCP service presence: Modbus/502, DNP3/20000, BACnet/47808, S7comm/102,
    EtherNet-IP/44818, OMRON FINS/9600, ProConOS/20547.
  * SCADA/HMI web fingerprints on discovered http(s) services.

Requires --ot-enable (OT testing needs explicit approval). Connect-only.
"""
from __future__ import annotations

import json
import socket
from urllib.parse import urlparse

_ICS_PORTS = [
    ("Modbus", 502), ("DNP3", 20000), ("BACnet", 47808), ("S7comm", 102),
    ("EtherNet/IP", 44818), ("OMRON FINS", 9600), ("ProConOS", 20547),
    ("Niagara Fox", 1911), ("IEC-104", 2404),
]
_SCADA_WEB_SIGS = ("wonderware", "ignition", "citect", "clearscada", "genesis64",
                   "factorytalk", " /hmi", "scada", "historian", "modbus",
                   "niagara", "tridium")


def _connect(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def run(ctx):
    if not getattr(ctx.args, "ot_enable", False):
        return  # OT needs explicit approval

    out_dir = ctx.output / "ot_ics"
    out_dir.mkdir(exist_ok=True)
    findings = 0
    results = []

    hosts = []
    for t in (ctx.targets or []):
        h = urlparse(t if t.startswith("http") else "//" + t).netloc or t
        hosts.append(h.split(":")[0])
    hosts = list(dict.fromkeys(hosts))

    for host in hosts:
        for name, port in _ICS_PORTS:
            ctx.runner.throttle("ot")
            if _connect(host, port):
                results.append({"host": host, "service": name, "port": port})
                ctx.save_finding({
                    "phase": "ot_ics_safe", "severity": "HIGH", "confidence": "MEDIUM",
                    "title": f"Exposed ICS service: {name} ({host}:{port})",
                    "target": host, "url": "",
                    "description": f"{name} responded on {host}:{port}. Connect-only probe; no "
                                   f"control command was sent. ICS exposure warrants specialised, "
                                   f"separately-authorized testing.",
                    "evidence": f"TCP connect {host}:{port} ({name})",
                    "impact": "Exposed industrial protocols can allow process disruption or safety impact.",
                    "remediation": "Segment OT from IT/Internet, require VPN/jump host, and apply "
                                   "protocol-aware firewalling.",
                    "cwe": "CWE-668", "cvss": "8.6", "mrs_score": 85,
                })
                findings += 1

    # SCADA web fingerprint on any discovered http services
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
        urls = ctx.runner.read_lines(ctx.output / "recon" / "urls.txt") \
            if (ctx.output / "recon" / "urls.txt").exists() else []
        for u in urls[:60]:
            ctx.runner.throttle("ot")
            try:
                r = requests.get(u, timeout=8, verify=False)
                low = (r.text[:4000] + " " + " ".join(f"{k}:{v}" for k, v in r.headers.items())).lower()
                if any(s in low for s in _SCADA_WEB_SIGS):
                    results.append({"url": u, "type": "scada-web"})
                    ctx.save_finding({
                        "phase": "ot_ics_safe", "severity": "MEDIUM", "confidence": "LOW",
                        "title": "Possible SCADA/HMI web interface",
                        "target": ctx.targets[0] if ctx.targets else u, "url": u[:200],
                        "description": "Response contained SCADA/HMI product markers. Read-only.",
                        "evidence": u[:200],
                        "impact": "HMI exposure can allow monitoring or control of physical processes.",
                        "remediation": "Restrict HMI access to the OT network and authenticated operators.",
                        "cwe": "CWE-284", "mrs_score": 50,
                    })
                    findings += 1
            except Exception:
                continue
    except Exception:
        pass

    (out_dir / "ot_ics.json").write_text(json.dumps(results, indent=2))
    ctx.log("OK", "ot_ics_safe",
            f"{len([r for r in results if 'port' in r])} ICS service(s) + "
            f"{len([r for r in results if r.get('type')=='scada-web'])} SCADA web | {findings} finding(s)")
