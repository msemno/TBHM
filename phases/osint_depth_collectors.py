"""Depth-oriented corporate OSINT collectors and import normalizer (v3.9.6).

Live actions are bounded to approved, read-only collectors. Dark-web/paste,
commercial internet-search and search-engine results are import-only. Person
collection requires an explicit PII policy and matching approval.
"""
from __future__ import annotations
import base64
import csv
import hashlib
import json
import re
import struct
import time
from pathlib import Path
from urllib.parse import urlparse

from core import redteam_utils as RT
from core.approval_gate import approved, load_manifest, summary as approval_summary
from core.scoped_http import network_discovery_enabled, safe_get
from core.targets import target_scope_allows

try:
    import requests
except Exception:
    requests = None

_DOMAIN = re.compile(r"(?<![@A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h1 = seed & 0xffffffff
    rounded = len(data) & ~0x3
    for i in range(0, rounded, 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = (k1 * c1) & 0xffffffff; k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff; k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1; h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff; h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = data[rounded:]
    if len(tail) == 3: k1 ^= tail[2] << 16
    if len(tail) >= 2: k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]; k1 = (k1 * c1) & 0xffffffff; k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff; k1 = (k1 * c2) & 0xffffffff; h1 ^= k1
    h1 ^= len(data); h1 ^= h1 >> 16; h1 = (h1 * 0x85ebca6b) & 0xffffffff; h1 ^= h1 >> 13; h1 = (h1 * 0xc2b2ae35) & 0xffffffff; h1 ^= h1 >> 16
    return h1 if h1 < 0x80000000 else h1 - 0x100000000


def _favicon_hash(data: bytes) -> int:
    encoded = base64.encodebytes(data)
    return _murmur3_32(encoded)


def _read_lines(path, cap=5000):
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        return []
    return [x.strip() for x in p.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip() and not x.lstrip().startswith("#")][:cap]


def _import_values(path):
    if not path:
        return []
    root = Path(path)
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.is_dir() else []
    rows = []
    for p in files[:2000]:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")[:10_000_000]
            rows.append({"source": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "domains": sorted(set(_DOMAIN.findall(text)))[:5000], "ips": sorted(set(_IP.findall(text)))[:5000], "urls": sorted(set(_URL.findall(text)))[:5000]})
        except Exception:
            continue
    return rows


def run(ctx):
    if not (getattr(ctx.args, "osint_depth", False) or getattr(ctx.args, "osint_depth_results", None)
            or getattr(ctx.args, "osint_favicon_urls", None) or getattr(ctx.args, "osint_google_dorks", False)
            or getattr(ctx.args, "osint_axfr", False)):
        return
    out = RT.evidence_dir(ctx, "11_osint_depth_collectors")
    try:
        manifest = load_manifest(getattr(ctx.args, "approval_manifest", None))
    except Exception as exc:
        manifest = {}; ctx.log("WARN", "osint_depth_collectors", str(exc))
    imported = _import_values(getattr(ctx.args, "osint_depth_results", None))
    favicon_rows = []
    budget = max(1, min(int(getattr(ctx.args, "osint_request_budget", 50) or 50), 500))
    urls = _read_lines(getattr(ctx.args, "osint_favicon_urls", None), cap=budget)
    if urls and getattr(ctx.args, "osint_live", False) and requests is not None and network_discovery_enabled(ctx):
        for raw in urls[:budget]:
            url = raw if raw.startswith(("http://", "https://")) else "https://" + raw
            if not target_scope_allows(ctx, url):
                favicon_rows.append({"url": url, "status": "blocked-out-of-scope"}); continue
            try:
                base = f"{urlparse(url).scheme}://{urlparse(url).netloc}/favicon.ico"
                response, final, chain = safe_get(ctx, requests, base, timeout=12, verify=False)
                data = bytes(getattr(response, "content", b""))[:2_000_000]
                if int(response.status_code) == 200 and data:
                    favicon_rows.append({"url": final, "status": 200, "sha256": hashlib.sha256(data).hexdigest(), "mmh3": _favicon_hash(data), "redirect_chain": chain})
                else:
                    favicon_rows.append({"url": final, "status": int(response.status_code), "redirect_chain": chain})
            except Exception as exc:
                favicon_rows.append({"url": url, "status": "error", "detail": str(exc)[:300]})
            time.sleep(0.05)
    dorks = []
    if getattr(ctx.args, "osint_google_dorks", False):
        domains = []
        for target in getattr(ctx, "targets", []) or []:
            host = urlparse(target).hostname if str(target).startswith(("http://", "https://")) else str(target).split(":")[0]
            if host and "." in host: domains.append(host)
        for domain in sorted(set(domains))[:100]:
            dorks.extend([
                f"site:{domain} ext:pdf OR ext:docx OR ext:xlsx",
                f"site:{domain} inurl:admin OR inurl:login OR inurl:api",
                f"site:github.com \"{domain}\"",
                f"site:{domain} \"index of\"",
            ])
    axfr_rows = []
    if getattr(ctx.args, "osint_axfr", False):
        if ctx.runner.has("dig"):
            domains = []
            for target in getattr(ctx, "targets", []) or []:
                host = urlparse(target).hostname if str(target).startswith(("http://", "https://")) else str(target).split(":")[0]
                if host and "." in host: domains.append(host)
            for domain in sorted(set(domains))[:20]:
                ok, detail = approved(manifest, "osint_active_dns", domain)
                if not ok:
                    axfr_rows.append({"domain": domain, "status": "blocked", "detail": detail})
                    continue
                rc, nsout, _ = ctx.runner.run(["dig", "+short", "NS", domain], timeout=30, log_name=f"osint_ns_{domain.replace('.', '_')}")
                for ns in [x.strip().rstrip(".") for x in nsout.splitlines() if x.strip()][:10]:
                    rc2, stdout, stderr = ctx.runner.run(["dig", "AXFR", f"@{ns}", domain, "+time=5", "+tries=1"], timeout=20, log_name=f"osint_axfr_{domain.replace('.', '_')}")
                    success = rc2 == 0 and "Transfer failed" not in stdout and "XFR size:" in stdout
                    axfr_rows.append({"domain": domain, "nameserver": ns, "success": success, "output_sha256": hashlib.sha256(stdout.encode()).hexdigest()})
                    if success:
                        ctx.save_finding({"phase":"osint_depth_collectors","severity":"MEDIUM","confidence":"HIGH","title":"DNS zone transfer permitted","target":domain,"description":"An approved bounded AXFR request returned a zone transfer. Analyst review is required before treating the record as current ownership evidence.","evidence":stdout[:3000],"impact":"Zone data may expose internal naming and external attack-surface information.","remediation":"Restrict AXFR to authorized secondary name servers and retest.","cwe":"CWE-200","finding_class":"supported","status":"supported","verified":False})
        else:
            axfr_rows.append({"status": "blocked", "detail": "dig unavailable"})
    person_enabled = bool(getattr(ctx.args, "osint_person_collection", False) and getattr(ctx.args, "osint_pii_policy", None))
    person_plan = []
    for username in _read_lines(getattr(ctx.args, "osint_usernames", None), cap=100):
        ok, detail = approved(manifest, "osint_person_exposure", username)
        person_plan.append({"username_hash": hashlib.sha256(username.lower().encode()).hexdigest(), "approved": ok and person_enabled, "detail": detail, "tools": ["sherlock", "maigret"], "execution": "operator-controlled bounded collector or import"})
    payload = {
        "approval": approval_summary(manifest), "imported_sources": imported,
        "favicon_hashes": favicon_rows, "asn_bgp": "asnmap/BBOT/SpiderFoot/BGP/RDAP results accepted through --osint-depth-results; discovered netblocks remain scope candidates",
        "internet_search_sources": "Shodan, Censys, FOFA, Quake, BinaryEdge, Netlas and similar provider results are API/manual imports unless a separately reviewed connector is configured",
        "dark_web_and_pastes": "import-only from lawful approved providers; TBHM does not crawl hidden services or authenticate with leaked credentials",
        "job_postings": "HTML/CSV/JSON results accepted through --osint-depth-results and normalized as claims, not verified infrastructure",
        "google_dork_plan": dorks, "axfr": axfr_rows, "person_collection_plan": person_plan,
    }
    (out / "osint_depth_summary.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    RT.write_csv(out / "favicon_hashes.csv", favicon_rows)
    RT.write_csv(out / "axfr_results.csv", axfr_rows)
    (out / "google_dork_plan.txt").write_text("\n".join(dorks) + ("\n" if dorks else ""), encoding="utf-8")
    RT.write_md(out / "OSINT_DEPTH_SUMMARY.md", "Corporate OSINT Depth Collectors", [
        ("Summary", f"{len(imported)} imported source(s), {len(favicon_rows)} favicon result(s), {len(axfr_rows)} AXFR check(s)."),
        ("Scope", "Every discovered domain, IP, account, company or netblock is intelligence evidence only. It never expands active scope automatically."),
        ("Privacy", "Person-level collection requires an explicit PII policy and approval. Usernames are stored as hashes in the plan by default."),
    ])
    ctx.phase_state["osint_depth"] = {"imports": len(imported), "favicon": len(favicon_rows), "axfr": len(axfr_rows)}
    ctx.log("OK", "osint_depth_collectors", f"{len(imported)} imports, {len(favicon_rows)} favicon, {len(axfr_rows)} AXFR records")
