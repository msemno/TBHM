"""Local/optional-online vulnerability intelligence feed helpers.

Feeds are cached under the run output or an operator-supplied directory.  Online
collection is opt-in and uses only documented public feeds.  The module never
claims that an exploit exists merely because a CVE is present.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import re
from pathlib import Path

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def extract_cves(finding: dict) -> list[str]:
    text = " ".join(str(finding.get(k) or "") for k in (
        "title", "description", "evidence", "references_json", "cve", "cvss"))
    return sorted({m.group(0).upper() for m in CVE_RE.finditer(text)})


def load_kev(path: str | Path | None) -> dict[str, dict]:
    if not path or not Path(path).is_file(): return {}
    try: data = json.loads(Path(path).read_text(errors="ignore"))
    except Exception: return {}
    rows = data.get("vulnerabilities", data if isinstance(data, list) else [])
    return {str(x.get("cveID") or x.get("cve") or "").upper(): x for x in rows if isinstance(x, dict) and (x.get("cveID") or x.get("cve"))}


def load_epss(path: str | Path | None) -> dict[str, dict]:
    if not path or not Path(path).is_file(): return {}
    p = Path(path)
    try:
        raw = p.read_bytes()
        if raw.startswith(b"\x1f\x8b"): raw = gzip.decompress(raw)
        text = raw.decode("utf-8", "ignore")
    except Exception: return {}
    # FIRST CSV may start with a metadata line beginning '#'.
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    out = {}
    try:
        for row in csv.DictReader(lines):
            cve = str(row.get("cve") or "").upper()
            if cve:
                out[cve] = {"epss": _float(row.get("epss")), "percentile": _float(row.get("percentile")), "date": row.get("date", "")}
    except Exception: return {}
    return out


def load_osv(path: str | Path | None) -> dict[str, dict]:
    if not path or not Path(path).exists(): return {}
    files = [Path(path)] if Path(path).is_file() else list(Path(path).rglob("*.json"))
    out = {}
    for p in files[:10000]:
        try: data = json.loads(p.read_text(errors="ignore"))
        except Exception: continue
        values = data if isinstance(data, list) else [data]
        for item in values:
            if not isinstance(item, dict): continue
            aliases = [item.get("id")] + list(item.get("aliases") or [])
            for alias in aliases:
                if str(alias).upper().startswith("CVE-"):
                    out[str(alias).upper()] = item
    return out


def _float(v):
    try: return float(v)
    except Exception: return None
