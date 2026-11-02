"""Utilities for TBHM red-team expansion phases.

All helpers are intentionally read-only / evidence-oriented. They do not perform
credential theft, persistence, exploitation, DoS, destructive writes, or bypasses.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse


def rt_dir(ctx) -> Path:
    d = ctx.output / "redteam"
    d.mkdir(exist_ok=True)
    return d


def evidence_dir(ctx, name: str) -> Path:
    d = rt_dir(ctx) / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_md(path: Path, title: str, sections: list[tuple[str, str]]) -> None:
    lines = [f"# {title}", ""]
    for h, body in sections:
        lines += [f"## {h}", "", body.strip(), ""]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    if fieldnames is None:
        keys = []
        for r in rows:
            for k in r.keys():
                if k not in keys:
                    keys.append(k)
        fieldnames = keys or ["status"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def read_lines(path: str | Path | None) -> list[str]:
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        return []
    return [l.strip() for l in p.read_text(errors="ignore").splitlines()
            if l.strip() and not l.strip().startswith("#")]


def get_cidrs(ctx) -> list[str]:
    vals = []
    raw = getattr(ctx.args, "corp_cidr", None)
    if raw:
        vals += [x.strip() for x in raw.split(",") if x.strip()]
    vals += read_lines(getattr(ctx.args, "corp_cidrs_file", None))
    # Also accept CIDR-looking targets supplied in -l/-d.
    for t in getattr(ctx, "targets", []) or []:
        if "/" in t:
            vals.append(t.strip())
    out, seen = [], set()
    for v in vals:
        try:
            n = ipaddress.ip_network(v, strict=False)
            s = str(n)
            if s not in seen:
                seen.add(s); out.append(s)
        except Exception:
            continue
    return out


def get_dc_ips(ctx) -> list[str]:
    vals = []
    raw = getattr(ctx.args, "dc_ip", None)
    if raw:
        vals += [x.strip() for x in raw.split(",") if x.strip()]
    vals += read_lines(getattr(ctx.args, "dc_ips_file", None))
    out, seen = [], set()
    for v in vals:
        try:
            ipaddress.ip_address(v)
            if v not in seen:
                seen.add(v); out.append(v)
        except Exception:
            continue
    return out


def safe_target_file(ctx, name: str, targets: list[str]) -> Path:
    p = evidence_dir(ctx, "inputs") / name
    p.write_text("\n".join(targets) + ("\n" if targets else ""), encoding="utf-8")
    return p


def parse_nmap_grepable_hosts(text: str) -> list[str]:
    hosts = []
    for line in text.splitlines():
        if "Status: Up" in line:
            m = re.search(r"Host:\s+(\S+)", line)
            if m:
                hosts.append(m.group(1))
    return sorted(set(hosts))


def parse_nmap_open_ports_gnmap(text: str) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for line in text.splitlines():
        if "Ports:" not in line or "Host:" not in line:
            continue
        hm = re.search(r"Host:\s+(\S+)", line)
        if not hm:
            continue
        host = hm.group(1)
        ports = []
        for pm in re.finditer(r"(\d+)/open/", line):
            try:
                ports.append(int(pm.group(1)))
            except Exception:
                pass
        if ports:
            result[host] = sorted(set(ports))
    return result


def parse_nmap_normal_services(text: str) -> list[dict]:
    rows = []
    host = ""
    for line in text.splitlines():
        m = re.search(r"Nmap scan report for (?:\S+ \()?([0-9a-fA-F:.]+)\)?", line)
        if m:
            host = m.group(1)
            continue
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line.strip())
        if m and host:
            rows.append({"host": host, "port": int(m.group(1)), "proto": m.group(2),
                         "service": m.group(3), "version": m.group(4).strip()})
    return rows


def cmd_available(ctx, tool: str) -> bool:
    return bool(getattr(ctx, "runner", None) and ctx.runner.has(tool))


def host_from_url(url: str) -> str:
    if url.startswith(("http://", "https://")):
        return urlparse(url).hostname or ""
    return url.split("/")[0].split(":")[0]


def save_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def add_control_finding(ctx, phase: str, title: str, severity: str, description: str,
                        evidence: str, target: str = "", remediation: str = ""):
    ctx.save_finding({
        "phase": phase,
        "severity": severity,
        "confidence": "MEDIUM" if severity in ("LOW", "INFO") else "HIGH",
        "title": title,
        "target": target,
        "description": description,
        "evidence": evidence[:2000],
        "impact": "Enterprise red-team coverage item. Risk depends on business criticality and compensating controls.",
        "remediation": remediation or "Confirm ownership, restrict exposure, harden configuration, monitor, and retest.",
        "cwe": "CWE-693",
        "mrs_score": {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 55, "LOW": 30, "INFO": 10}.get(severity, 10),
    })
