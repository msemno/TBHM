"""Phase: access_control - IDOR heuristics, CORS misconfigurations."""
from __future__ import annotations
import re
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        return
    urls_file = ctx.output / "recon" / "urls.txt"
    urls = ctx.runner.read_lines(urls_file) if urls_file.exists() else []
    _idor_heuristic(ctx, urls)
    alive = ctx.runner.read_lines(ctx.output / "recon" / "alive.txt")
    _cors(ctx, alive)


def _idor_heuristic(ctx, urls):
    """Flag URLs matching numeric/UUID ID patterns -- needs manual review."""
    pat_num = re.compile(r"/(?:user|users|account|profile|order|orders|"
                         r"invoice|invoices|ticket|tickets|message|file|"
                         r"item|items)/([0-9]+)(?:/|$|\?)")
    pat_uuid = re.compile(r"/(?:user|users|account|order|orders|invoice|"
                          r"ticket|message|file)/([a-f0-9]{8}-[a-f0-9]{4}-)")
    cands = []
    seen = set()
    for u in urls:
        if pat_num.search(u) or pat_uuid.search(u):
            base = re.sub(r"/[0-9a-f]+(/|$|\?)", "/{ID}\\1", u)
            if base in seen:
                continue
            seen.add(base)
            cands.append(u)
    if not cands:
        return
    ctx.log("INFO", "access_control", f"{len(cands)} IDOR-shaped URLs flagged for review")
    for u in cands[:50]:
        ctx.save_finding({
            "phase": "access_control", "severity": "INFO", "confidence": "LOW",
            "title": "IDOR candidate (manual verification required)",
            "target": ctx.targets[0], "url": u[:500],
            "description": "Endpoint contains an ID-shaped path. Manually test with two "
                           "accounts: log in as A, capture request, change ID to B's resource, "
                           "see if data leaks across accounts.",
            "impact": "If exploitable: read/modify other users' data.",
            "remediation": "Server-side authorization on every object access.",
            "cwe": "CWE-639",
            "mrs_score": 50,
        })


def _cors(ctx, alive):
    if not requests or not alive:
        return
    ctx.log("INFO", "access_control", f"CORS check on {min(len(alive),50)} hosts...")
    evil = "https://evil.example.com"
    for url in alive[:50]:
        try:
            r = requests.get(url, headers={"Origin": evil}, timeout=10,
                             allow_redirects=False)
            aco = r.headers.get("Access-Control-Allow-Origin", "")
            acc = r.headers.get("Access-Control-Allow-Credentials", "")
            if aco == evil and acc.lower() == "true":
                ctx.save_finding({
                    "phase": "access_control", "severity": "HIGH", "confidence": "HIGH",
                    "title": "CORS reflects arbitrary Origin with credentials",
                    "target": ctx.targets[0], "url": url[:500], "method": "GET",
                    "evidence": f"ACAO: {aco}; ACAC: {acc}",
                    "description": "Server reflects arbitrary Origin and allows credentials. "
                                   "Attacker can read authenticated responses cross-origin.",
                    "impact": "Steal user data via attacker-hosted JS.",
                    "remediation": "Whitelist origins. Don't reflect Origin. Drop credentials for cross-origin.",
                    "cwe": "CWE-942", "mrs_score": 95,
                })
            elif aco == "null" and acc.lower() == "true":
                ctx.save_finding({
                    "phase": "access_control", "severity": "MEDIUM", "confidence": "HIGH",
                    "title": "CORS Allow-Origin: null with credentials",
                    "target": ctx.targets[0], "url": url[:500], "method": "GET",
                    "evidence": f"ACAO: null; ACAC: {acc}",
                    "description": "Allow-Origin: null can be exploited via sandboxed iframes.",
                    "impact": "Cross-origin data read in some attack scenarios.",
                    "remediation": "Never use null for ACAO with credentials.",
                    "cwe": "CWE-942", "mrs_score": 85,
                })
        except Exception:
            continue
