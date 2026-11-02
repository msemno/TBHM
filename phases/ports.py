"""
Phase: ports
Port discovery + service detection on resolved IPs.

Tools:
  - naabu  (fast TCP SYN/CONNECT scanner, ProjectDiscovery)
  - nmap   (service detection, scripts)
  - masscan (optional, for --deep / --insane against IP ranges)

Output:
  recon/ports.json   — { host: [{port, service, version, banner}, ...] }
  Findings raised on:
    - admin services exposed (kibana, elasticsearch, redis, memcached, mongodb)
    - DB ports open externally (3306, 5432, 27017, 6379)
    - dev ports (8080, 8081, 9090, 3000, 5000)
"""
from __future__ import annotations
from core import ratelimit
import json
import re
import ipaddress
import socket
from pathlib import Path

from core import intensity
from core.targets import get_domains


# Ports we always treat as "interesting" if open externally
INTERESTING_PORTS = {
    22:    ("SSH",          "INFO",   "SSH open externally — verify access is intended"),
    23:    ("Telnet",       "HIGH",   "Telnet sends credentials in cleartext"),
    25:    ("SMTP",         "INFO",   "Mail server exposed"),
    53:    ("DNS",          "INFO",   "DNS server exposed"),
    110:   ("POP3",         "LOW",    "Cleartext mail protocol"),
    143:   ("IMAP",         "LOW",    "Cleartext mail protocol"),
    389:   ("LDAP",         "MEDIUM", "LDAP exposed — risk of anonymous bind"),
    445:   ("SMB",          "HIGH",   "SMB exposed to internet"),
    1433:  ("MSSQL",        "HIGH",   "Microsoft SQL Server exposed"),
    1521:  ("Oracle",       "HIGH",   "Oracle DB exposed"),
    2049:  ("NFS",          "HIGH",   "NFS exposed externally"),
    2375:  ("Docker API",   "CRITICAL", "Unauthenticated Docker API = container escape"),
    2376:  ("Docker TLS",   "HIGH",   "Docker API exposed (TLS)"),
    3306:  ("MySQL",        "HIGH",   "MySQL exposed externally"),
    3389:  ("RDP",          "HIGH",   "RDP exposed to internet"),
    5432:  ("PostgreSQL",   "HIGH",   "PostgreSQL exposed externally"),
    5601:  ("Kibana",       "HIGH",   "Kibana dashboard exposed"),
    5984:  ("CouchDB",      "HIGH",   "CouchDB exposed"),
    6379:  ("Redis",        "CRITICAL", "Redis usually has no auth — RCE risk"),
    7474:  ("Neo4j",        "HIGH",   "Neo4j exposed"),
    8086:  ("InfluxDB",     "HIGH",   "InfluxDB exposed"),
    8545:  ("Geth/Ethereum RPC", "CRITICAL", "Ethereum RPC exposed"),
    8888:  ("Jupyter",      "HIGH",   "Jupyter notebook exposed"),
    9000:  ("PHP-FPM/SonarQube", "MEDIUM", "PHP-FPM or admin panel"),
    9042:  ("Cassandra",    "HIGH",   "Cassandra exposed"),
    9092:  ("Kafka",        "HIGH",   "Kafka broker exposed"),
    9200:  ("Elasticsearch","CRITICAL", "Elasticsearch usually has no auth — data theft"),
    9300:  ("ES transport", "HIGH",   "Elasticsearch transport port"),
    11211: ("Memcached",    "HIGH",   "Memcached cache exposed"),
    15672: ("RabbitMQ",     "HIGH",   "RabbitMQ management UI"),
    27017: ("MongoDB",      "CRITICAL", "MongoDB often unauthenticated — data theft"),
    27018: ("MongoDB shard","CRITICAL", "MongoDB shard exposed"),
    50070: ("Hadoop NameNode", "HIGH", "Hadoop NameNode exposed"),
}


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        ctx.log("INFO", "ports", "passive profile — skipping port scan")
        return

    port_scan_mode = intensity.get(ctx.profile, "port_scan", "top100")
    if port_scan_mode is None:
        return

    domains = get_domains(ctx)
    if not domains:
        return

    # We scan the resolved IPs of live hosts only (don't scan IPs we haven't seen).
    alive_hosts = ctx.runner.read_lines(ctx.output / "recon" / "alive.txt")
    if not alive_hosts:
        ctx.log("WARN", "ports", "no alive hosts — skipping port scan")
        return

    max_to_scan = intensity.get(ctx.profile, "max_alive_hosts_to_scan", 50)
    targets_for_ports = _hosts_from_urls(alive_hosts)[:max_to_scan]
    targets_for_ports, denied = _authorized_addresses(ctx, targets_for_ports)
    (ctx.output / 'recon' / 'port_scope_review.json').write_text(json.dumps({
        'schema': 'tbhm.network-scope-review/1', 'authorized_ips': targets_for_ports,
        'denied': denied, 'dns_association_confers_authorization': False}, indent=2)+'\n')
    if not targets_for_ports:
        ctx.log('WARN', 'ports', 'No explicitly authorized IPs; see port_scope_review.json. Port scan not executed.')
        if getattr(ctx, 'execution_ledger', None):
            ctx.execution_ledger.record(kind='capability', status='unavailable', tool='network_port_scan',
                reason='Explicit --network-scope IP/CIDR authorization required; HTTP scope is insufficient')
        return
    ctx.log("INFO", "ports", f"port scan ({port_scan_mode}) on {len(targets_for_ports)} hosts…")

    target_file = ctx.output / "recon" / "_port_targets.txt"
    target_file.write_text("\n".join(targets_for_ports))

    open_ports: dict[str, list[int]] = {}

    # ── Tier 1: naabu for fast TCP scan ────────────────────────────────────
    if ctx.runner.has("naabu"):
        open_ports = _naabu(ctx, target_file, port_scan_mode)
    elif ctx.runner.has("nmap"):
        open_ports = _nmap_discover(ctx, targets_for_ports, port_scan_mode)
    else:
        ctx.log("WARN", "ports", "neither naabu nor nmap installed — skipping")
        return

    if not open_ports:
        ctx.log("INFO", "ports", "no open ports discovered")
        return
    # Scanner stdout is untrusted. Never feed an unexpected host or port from
    # its output into the service-detection subprocess.
    open_ports = {h: [p for p in ports if type(p) is int and 1 <= p <= 65535]
                  for h, ports in open_ports.items() if h in targets_for_ports}

    # ── Tier 2: nmap service detection on found ports ──────────────────────
    if ctx.runner.has("nmap"):
        _nmap_service_detect(ctx, open_ports)

    # ── Raise findings on interesting open ports ───────────────────────────
    n_findings = 0
    for host, ports in open_ports.items():
        for p in ports:
            if p in INTERESTING_PORTS:
                name, sev, msg = INTERESTING_PORTS[p]
                ctx.save_finding({
                    "phase": "ports",
                    "severity": "INFO",
                    "finding_class": "lead",
                    "confidence": "HIGH",
                    "title": f"{name} exposed on {host}:{p}",
                    "target": host,
                    "url": f"{host}:{p}",
                    "evidence": f"TCP {p} open",
                    "description": f"TCP {p} responded. Service identity and authentication are unverified.",
                    "impact": "An open port alone does not establish a vulnerable or unauthenticated service.",
                    "remediation": "Restrict access via firewall/security group. "
                                   "Require VPN or bastion. Disable if not needed.",
                    "cwe": "CWE-668",
                    "mrs_score": 100,
                })
                n_findings += 1
    ctx.log("OK", "ports", f"port scan: {n_findings} interesting-port findings")

    # Persist full result
    (ctx.output / "recon" / "ports.json").write_text(
        json.dumps(open_ports, indent=2, sort_keys=True))


def _hosts_from_urls(alive):
    out = []
    seen = set()
    for u in alive:
        from urllib.parse import urlparse
        h = urlparse(u).hostname if u.startswith(("http://", "https://")) else u.split(":")[0]
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _naabu(ctx, target_file, mode) -> dict[str, list[int]]:
    rl = ctx.profile.get("rate_limit", {}).get("global_rps", 10)
    if mode == "top100":
        port_arg = ["-top-ports", "100"]
    elif mode == "top1000":
        port_arg = ["-top-ports", "1000"]
    elif mode == "top5000":
        port_arg = ["-top-ports", "5000"]
    elif mode == "all":
        port_arg = ["-p", "1-65535"]
    else:
        port_arg = ["-top-ports", "100"]
    cmd = ["naabu", "-list", str(target_file), "-silent",
           "-rate", str(max(1, min(int(getattr(ctx.args, 'port_rate', 10)), 100))), "-c", "2"] + port_arg
    rc, out, err = ctx.runner.run(cmd, timeout=600, log_name="naabu")
    result = {}
    for line in out.splitlines():
        line = line.strip()
        # naabu output: "host:port"
        if ":" in line:
            h, p = line.rsplit(":", 1)
            try:
                port = int(p)
            except ValueError:
                continue
            result.setdefault(h, []).append(port)
    for h in result:
        result[h] = sorted(set(result[h]))
    ctx.log("OK", "ports", f"naabu found {sum(len(p) for p in result.values())} open ports "
            f"across {len(result)} hosts")
    return result


def _nmap_discover(ctx, hosts, mode) -> dict[str, list[int]]:
    if mode == "all":
        port_arg = "-p-"
    elif mode == "top5000":
        port_arg = "--top-ports=5000"
    elif mode == "top1000":
        port_arg = "--top-ports=1000"
    else:
        port_arg = "--top-ports=100"
    out_dir = ctx.output / "scans" / "nmap"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["nmap", "-T3", "-Pn", port_arg, "--open", "--max-retries", "1",
           "--max-rate", str(max(1, min(int(getattr(ctx.args, 'port_rate', 10)), 100))),
           "-oG", str(out_dir / "discover.gnmap"), "--"] + hosts
    rc, out, err = ctx.runner.run(cmd, timeout=600, log_name="nmap_discover")
    return _parse_gnmap(out_dir / "discover.gnmap")


def _nmap_service_detect(ctx, open_ports: dict[str, list[int]]):
    out_dir = ctx.output / "scans" / "nmap"
    out_dir.mkdir(parents=True, exist_ok=True)
    for host, ports in open_ports.items():
        if not ports:
            continue
        port_str = ",".join(str(p) for p in ports)
        cmd = ["nmap", "-T3", "-Pn", "-sV", "--version-intensity", "2",
               "--max-rate", str(max(1, min(int(getattr(ctx.args, 'port_rate', 10)), 100))), "-p", port_str,
               "-oX", str(out_dir / f"sv_{host}.xml"), host]
        ctx.runner.run(cmd, timeout=900, log_name=f"nmap_sv_{host}", capture_mode="tail")


def _parse_gnmap(path: Path) -> dict[str, list[int]]:
    if not path.exists():
        return {}
    out = {}
    pat = re.compile(r"Host:\s+(\S+).+Ports:\s+(.+?)\s+Ignored", re.S)
    for line in path.read_text(errors="ignore").splitlines():
        m = pat.search(line)
        if not m:
            continue
        host = m.group(1)
        ports = []
        for tok in m.group(2).split(","):
            tok = tok.strip()
            mp = re.match(r"^(\d+)/open/", tok)
            if mp:
                ports.append(int(mp.group(1)))
        if ports:
            out[host] = sorted(set(ports))
    return out


def _impact_for_port(p: int) -> str:
    high_impact = {
        6379:  "Redis with no auth often leads to RCE via SLAVEOF / CONFIG SET.",
        27017: "MongoDB exposes all collections, often without auth.",
        9200:  "Elasticsearch exposes all indices, often without auth.",
        2375:  "Unauthenticated Docker API = full container escape.",
        8545:  "Ethereum RPC with admin namespace = arbitrary transaction signing.",
    }
    return high_impact.get(p, "Service exposed to internet; verify authentication.")


def _authorized_addresses(ctx, hosts):
    """Never turn a DNS/CDN relationship into network scan authorization."""
    scope_path = getattr(ctx.args, 'network_scope', None)
    if not scope_path:
        return [], [{'host': h, 'reason': 'no explicit IP/CIDR authorization'} for h in hosts]
    path = Path(scope_path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000:
        raise ValueError('network scope requires a bounded regular IP/CIDR file')
    networks = [ipaddress.ip_network(line.strip(), strict=False)
                for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if len(networks) > 4096:
        raise ValueError('network scope entry budget exceeded')
    approved, denied = set(), []
    from core.program_policy import evaluate_asset, evaluate_action
    policy = getattr(ctx, 'program_policy', None)
    if policy and not evaluate_action(policy, 'ports').get('allowed'):
        return [], [{'host': h, 'reason': 'network action prohibited by program policy'} for h in hosts]
    for host in hosts:
        try:
            addresses = {str(ipaddress.ip_address(host))}
        except ValueError:
            try:
                addresses = {entry[4][0] for entry in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
            except OSError:
                denied.append({'host': host, 'reason': 'DNS resolution failed'})
                continue
        for address in sorted(addresses):
            ip = ipaddress.ip_address(address)
            if not any(ip.version == n.version and ip in n for n in networks):
                denied.append({'host': host, 'ip': address, 'reason': 'IP not explicitly authorized'})
            elif policy and evaluate_asset(policy, address).get('decision') != 'in_scope':
                denied.append({'host': host, 'ip': address, 'reason': 'program policy did not authorize IP'})
            else:
                approved.add(address)
    return sorted(approved), denied
