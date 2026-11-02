"""
Phase: deep_scan
Additional vuln scanners that complement nuclei.

Tools (all optional, gracefully skipped if missing):
  - nikto    — classic web server scanner
  - jaeles   — modular signature scanner (different rule set than nuclei)
  - wapiti   — black-box web app scanner

Each runs only when intensity flag enables it.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

from core import intensity


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        return
    alive_file = ctx.output / "recon" / "alive.txt"
    alive = ctx.runner.read_lines(alive_file)
    if not alive:
        return

    out_dir = ctx.output / "scans" / "deep"
    out_dir.mkdir(parents=True, exist_ok=True)

    max_hosts = intensity.get(ctx.profile, "max_alive_hosts_to_scan", 50)
    targets = alive[:min(max_hosts, 20)]  # extra-cap; these scanners are slow

    if intensity.get(ctx.profile, "nikto_enabled", False):
        _nikto(ctx, targets, out_dir)
    if intensity.get(ctx.profile, "jaeles_enabled", False):
        _jaeles(ctx, alive_file, out_dir)
    if intensity.get(ctx.profile, "wapiti_enabled", False):
        _wapiti(ctx, targets, out_dir)


def _nikto(ctx, targets, out_dir):
    if not ctx.runner.has("nikto"):
        ctx.log("WARN", "deep_scan", "nikto not installed — skipping")
        return
    ctx.log("INFO", "deep_scan", f"nikto on {len(targets)} hosts…")
    for host in targets:
        slug = host.replace("https://", "").replace("http://", "").replace("/", "_")
        out_file = out_dir / f"nikto_{slug}.txt"
        rc, out, _ = ctx.runner.run(
            ["nikto", "-h", host, "-Tuning", "1,2,3,4,5,6,7,8,9,b",
             "-Format", "txt", "-output", str(out_file), "-ask", "no", "-nointeractive"],
            timeout=1800, log_name=f"nikto_{slug}"
        )
        if not out_file.exists():
            continue
        n = 0
        for line in out_file.read_text(errors="ignore").splitlines():
            # Nikto findings start with "+ "
            if line.startswith("+ ") and "OSVDB" in line or "CVE-" in line.upper():
                sev = "MEDIUM"
                if "CVE-" in line:
                    sev = "HIGH"
                ctx.save_finding({
                    "phase": "deep_scan",
                    "severity": sev,
                    "confidence": "MEDIUM",
                    "title": "Nikto: " + line[:120].lstrip("+ ").strip(),
                    "target": host, "url": host,
                    "evidence": line[:500],
                    "description": "Reported by Nikto. Verify manually.",
                    "impact": "Varies — see Nikto reference.",
                    "remediation": "Patch underlying issue; harden web server.",
                    "mrs_score": 80,
                })
                n += 1
        ctx.log("OK", "deep_scan", f"  nikto {host}: {n} findings")


def _jaeles(ctx, alive_file, out_dir):
    if not ctx.runner.has("jaeles"):
        ctx.log("WARN", "deep_scan", "jaeles not installed — skipping")
        return
    out_jsonl = out_dir / "jaeles.jsonl"
    ctx.log("INFO", "deep_scan", "running jaeles…")
    rc, out, _ = ctx.runner.run(
        ["jaeles", "scan", "-U", str(alive_file),
         "-s", "/passive,/cves,/sensitive",
         "-c", "20", "-o", str(out_jsonl)],
        timeout=3600, log_name="jaeles"
    )
    if not out_jsonl.exists():
        return
    n = 0
    for line in out_jsonl.read_text().splitlines():
        try:
            r = json.loads(line)
        except Exception:
            continue
        sev = (r.get("info", {}).get("risk") or r.get("risk") or "info").upper()
        if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            mapped_sev = sev
        else:
            mapped_sev = "INFO"
        ctx.save_finding({
            "phase": "deep_scan",
            "severity": mapped_sev,
            "confidence": "MEDIUM",
            "title": "Jaeles: " + (r.get("sign_name") or r.get("name") or "finding"),
            "target": r.get("host", ""),
            "url": r.get("url", ""),
            "evidence": json.dumps(r)[:600],
            "description": r.get("info", {}).get("description", ""),
            "remediation": "See Jaeles signature for context.",
            "mrs_score": 80,
        })
        n += 1
    ctx.log("OK", "deep_scan", f"jaeles: {n} findings")


def _wapiti(ctx, targets, out_dir):
    if not ctx.runner.has("wapiti"):
        ctx.log("WARN", "deep_scan", "wapiti not installed — skipping")
        return
    ctx.log("INFO", "deep_scan", f"wapiti on {len(targets)} hosts…")
    for host in targets[:5]:  # wapiti is slow
        slug = host.replace("https://", "").replace("http://", "").replace("/", "_")
        out_file = out_dir / f"wapiti_{slug}.json"
        rc, out, _ = ctx.runner.run(
            ["wapiti", "-u", host, "-f", "json", "-o", str(out_file),
             "-m", "sql,xss,exec,file,blindsql,crlf,ssrf,xxe,csrf,csp",
             "--flush-attacks", "--flush-session"],
            timeout=2400, log_name=f"wapiti_{slug}"
        )
        if not out_file.exists():
            continue
        try:
            data = json.loads(out_file.read_text())
        except Exception:
            continue
        vulns = data.get("vulnerabilities", {})
        for vtype, items in vulns.items():
            for it in items:
                ctx.save_finding({
                    "phase": "deep_scan",
                    "severity": _wapiti_sev(it.get("level", 1)),
                    "confidence": "MEDIUM",
                    "title": f"Wapiti: {vtype}",
                    "target": host,
                    "url": it.get("path", host),
                    "method": it.get("method", "GET"),
                    "parameter": it.get("parameter", ""),
                    "evidence": (it.get("info") or "")[:500],
                    "description": "Reported by Wapiti.",
                    "remediation": "Address the underlying input validation / output encoding issue.",
                    "mrs_score": 75,
                })


def _wapiti_sev(level):
    return {3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(int(level or 1), "LOW")
