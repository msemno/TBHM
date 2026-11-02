#!/usr/bin/env python3
"""Explicit updater for public vulnerability-intelligence caches.

Nothing downloads unless the operator runs this helper (or a future wrapper
with --intel-online). Files are written atomically with SHA-256 provenance.
"""
from __future__ import annotations
import argparse, hashlib, json, os, tempfile, urllib.request
from datetime import datetime, timezone
from pathlib import Path

CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BY_DATE = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
OSV_CVE = "https://api.osv.dev/v1/vulns/{cve}"


def _download(url: str, path: Path, max_bytes: int) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "TBHM-v4.0.0-feed-updater/1"})
    h = hashlib.sha256(); total = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(req, timeout=60) as src:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk: break
                total += len(chunk)
                if total > max_bytes: raise ValueError(f"download exceeds {max_bytes} bytes")
                h.update(chunk); out.write(chunk)
        Path(temp_name).replace(path)
    except Exception:
        try: Path(temp_name).unlink(missing_ok=True)
        except Exception: pass
        raise
    return {"url": url, "path": str(path), "bytes": total, "sha256": h.hexdigest(),
            "retrieved_at": datetime.now(timezone.utc).isoformat()}


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--kev", action="store_true")
    ap.add_argument("--epss", action="store_true")
    ap.add_argument("--osv-cves", metavar="FILE", help="one CVE per line; bounded individual OSV records")
    ns=ap.parse_args(); out=Path(ns.output); out.mkdir(parents=True,exist_ok=True)
    if not (ns.kev or ns.epss or ns.osv_cves): ns.kev=ns.epss=True
    records=[]
    if ns.kev:
        rec=_download(CISA_KEV,out/"known_exploited_vulnerabilities.json",50_000_000)
        json.loads(Path(rec["path"]).read_text()); records.append(rec)
    if ns.epss:
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d")
        records.append(_download(EPSS_BY_DATE.format(date=date),out/f"epss_scores-{date}.csv.gz",250_000_000))
    if ns.osv_cves:
        cves=[]
        for line in Path(ns.osv_cves).read_text(errors="ignore").splitlines():
            value=line.strip().upper()
            if value.startswith("CVE-") and value not in cves: cves.append(value)
        if len(cves)>5000: raise SystemExit("OSV CVE list exceeds hard cap 5000")
        for cve in cves:
            try:
                rec=_download(OSV_CVE.format(cve=cve),out/"osv"/f"{cve}.json",10_000_000)
                json.loads(Path(rec["path"]).read_text()); records.append(rec)
            except Exception as exc:
                records.append({"url":OSV_CVE.format(cve=cve),"error":str(exc),"cve":cve})
    manifest={"generated_at":datetime.now(timezone.utc).isoformat(),"records":records}
    (out/"feed_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    print(json.dumps(manifest,indent=2)); return 0
if __name__ == "__main__": raise SystemExit(main())
