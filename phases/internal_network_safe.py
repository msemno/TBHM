"""Internal network safe discovery and segmentation review."""
from __future__ import annotations
from pathlib import Path
from core import redteam_utils as RT

INTERESTING = {
    21: ("FTP", "LOW"), 22: ("SSH", "INFO"), 23: ("Telnet", "HIGH"), 53: ("DNS", "INFO"),
    80: ("HTTP", "INFO"), 88: ("Kerberos", "INFO"), 111: ("RPCbind", "MEDIUM"),
    135: ("MSRPC", "INFO"), 139: ("NetBIOS", "INFO"), 161: ("SNMP", "MEDIUM"),
    389: ("LDAP", "MEDIUM"), 443: ("HTTPS", "INFO"), 445: ("SMB", "MEDIUM"),
    502: ("Modbus", "HIGH"), 554: ("RTSP", "MEDIUM"), 623: ("IPMI", "HIGH"),
    636: ("LDAPS", "INFO"), 1433: ("MSSQL", "MEDIUM"), 1883: ("MQTT", "HIGH"),
    2049: ("NFS", "HIGH"), 3306: ("MySQL", "MEDIUM"), 3389: ("RDP", "MEDIUM"),
    5432: ("PostgreSQL", "MEDIUM"), 5672: ("AMQP", "MEDIUM"), 5900: ("VNC", "HIGH"),
    5985: ("WinRM HTTP", "MEDIUM"), 5986: ("WinRM HTTPS", "INFO"), 6379: ("Redis", "HIGH"),
    8080: ("Alt HTTP", "INFO"), 8443: ("Alt HTTPS", "INFO"), 8883: ("MQTT TLS", "MEDIUM"),
    9100: ("Printer JetDirect", "MEDIUM"), 9200: ("Elasticsearch", "HIGH"), 47808: ("BACnet", "HIGH"),
}


def _run_nmap_ping(ctx, cidr, out):
    if not ctx.runner.has("nmap"):
        return []
    gn = out / f"ping_{cidr.replace('/', '_')}.gnmap"
    rc, stdout, stderr = ctx.runner.run(["nmap", "-sn", "-oG", str(gn), cidr], timeout=1800,
                                        log_name=f"rt_nmap_ping_{cidr.replace('/', '_')}")
    text = gn.read_text(errors="ignore") if gn.exists() else stdout
    return RT.parse_nmap_grepable_hosts(text)


def _run_service_scan(ctx, hosts, out):
    if not hosts or not ctx.runner.has("nmap"):
        return []
    target_file = out / "live_hosts.txt"
    target_file.write_text("\n".join(hosts) + "\n")
    ports = ",".join(str(p) for p in sorted(INTERESTING))
    normal = out / "internal_services.nmap"
    gnmap = out / "internal_services.gnmap"
    cmd = ["nmap", "-sV", "--version-light", "-Pn", "--max-retries", "2", "--host-timeout", "60s",
           "-p", ports, "-iL", str(target_file), "-oN", str(normal), "-oG", str(gnmap)]
    ctx.runner.run(cmd, timeout=7200, log_name="rt_internal_services", capture_mode="tail")
    text = normal.read_text(errors="ignore") if normal.exists() else ""
    return RT.parse_nmap_normal_services(text)


def run(ctx):
    cidrs = RT.get_cidrs(ctx)
    out = RT.evidence_dir(ctx, "04_internal_network")
    if not cidrs:
        RT.write_md(out / "INTERNAL_NETWORK_NOT_RUN.md", "Internal Network Not Run", [
            ("Reason", "No --corp-cidr or --corp-cidrs-file was provided. This branch is marked Not Tested, not Safe."),
            ("How to run", "Example: ./tbhm.py -d company.com --profile authorized_redteam -y --redteam --corp-cidr 10.10.0.0/16 --dc-ip 10.10.10.10"),
        ])
        RT.add_control_finding(ctx, "internal_network_safe", "Internal network branch not tested", "INFO",
                               "No internal CIDR was supplied; do not claim internal network coverage.",
                               str(out / "INTERNAL_NETWORK_NOT_RUN.md"), remediation="Provide approved internal CIDRs and rerun this phase.")
        return

    all_hosts = []
    for cidr in cidrs:
        ctx.log("INFO", "internal_network", f"safe host discovery on {cidr}")
        all_hosts += _run_nmap_ping(ctx, cidr, out)
    all_hosts = sorted(set(all_hosts))
    (out / "live_hosts.txt").write_text("\n".join(all_hosts) + ("\n" if all_hosts else ""))

    services = _run_service_scan(ctx, all_hosts[:1000], out)
    RT.save_json(out / "internal_services.json", services)

    summary = []
    for s in services:
        port = int(s.get("port", 0))
        if port in INTERESTING:
            name, sev = INTERESTING[port]
            summary.append({**s, "risk_label": name, "severity": sev})
            if sev in ("HIGH", "MEDIUM"):
                RT.add_control_finding(
                    ctx, "internal_network_safe", f"Internal {name} service reachable: {s['host']}:{port}", sev,
                    f"Read-only service discovery found {name} reachable on internal host. This may be intended, but it must be segmented, authenticated, monitored, and owner-approved.",
                    f"{s['host']}:{port}/{s.get('proto')} {s.get('service')} {s.get('version')}", target=s['host'],
                    remediation="Validate business need, restrict by VLAN/firewall/NAC, enforce strong auth, and add monitoring."
                )
    RT.write_csv(out / "interesting_internal_services.csv", summary)
    sections = [
        ("Scope", "\n".join(f"- {c}" for c in cidrs)),
        ("Live hosts", f"{len(all_hosts)} live hosts discovered using nmap -sn."),
        ("Interesting services", f"{len(summary)} interesting service observations written to interesting_internal_services.csv."),
        ("Segmentation questions", "Are user VLANs blocked from server/admin/IoT/CCTV/backup VLANs? Are management ports restricted to admin jump hosts? Are IPv6 and rogue DHCP/NAC controls covered separately?"),
    ]
    RT.write_md(out / "INTERNAL_NETWORK_SUMMARY.md", "Internal Network Safe Discovery Summary", sections)
    ctx.log("OK", "internal_network", f"{len(all_hosts)} hosts, {len(services)} service rows, {len(summary)} interesting")
