"""
core/sbom.py   (v2.18)

Software Bill of Materials + known-CVE lookup.

parse_dependencies(root) -> [{name, version, ecosystem, file}]
query_osv(components)     -> attaches {vulns:[{id, summary, severity, fixed}]} via OSV.dev
cyclonedx(components)     -> CycloneDX 1.5 JSON dict

OSV.dev (api.osv.dev) is free and needs no key. Reachability ("is the vulnerable
function actually called") is NOT determined here — that requires call-graph
analysis; CVE hits are listed for manual triage. If OSV is unreachable (offline),
the SBOM is still produced without vuln data.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

try:
    import requests
except Exception:
    requests = None

OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE = "https://api.osv.dev/v1/query"


# ── Dependency file parsers ───────────────────────────────────────────────────
def _npm(path: Path):
    out = []
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return out
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in (data.get(section) or {}).items():
            out.append((name, re.sub(r"[^\d.]", "", str(ver)) or str(ver), "npm"))
    return out


def _requirements(path: Path):
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9._\-]+)\s*==\s*([0-9][\w.\-]*)", line)
        if m:
            out.append((m.group(1), m.group(2), "PyPI"))
    return out


def _go_mod(path: Path):
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        m = re.match(r"\s*([\w./\-]+)\s+v([0-9][\w.\-+]*)", line.strip())
        if m and "module " not in line and "go 1" not in line:
            out.append((m.group(1), m.group(2), "Go"))
    return out


def _cargo(path: Path):
    out = []
    txt = path.read_text(errors="ignore")
    for m in re.finditer(r'name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', txt):
        out.append((m.group(1), m.group(2), "crates.io"))
    return out


def _pom(path: Path):
    out = []
    txt = path.read_text(errors="ignore")
    for m in re.finditer(r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>", txt):
        out.append((m.group(1), m.group(2), "Maven"))
    return out


def _gemfile(path: Path):
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        m = re.search(r"\(([0-9][\w.\-]*)\)", line)
        n = re.match(r"\s+([\w\-]+)\s+\(", line)
        if m and n:
            out.append((n.group(1), m.group(1), "RubyGems"))
    return out


_PARSERS = {
    "package.json": _npm,
    "requirements.txt": _requirements,
    "go.mod": _go_mod,
    "Cargo.lock": _cargo,
    "pom.xml": _pom,
    "Gemfile.lock": _gemfile,
}


def parse_dependencies(root: Path) -> list[dict]:
    seen = set()
    comps = []
    for fname, parser in _PARSERS.items():
        for path in root.rglob(fname):
            if "node_modules" in str(path):
                continue
            for name, ver, eco in parser(path):
                key = (name, ver, eco)
                if key in seen:
                    continue
                seen.add(key)
                comps.append({"name": name, "version": ver, "ecosystem": eco,
                              "file": str(path.relative_to(root)) if root in path.parents else str(path)})
    return comps


# ── OSV.dev lookup ────────────────────────────────────────────────────────────
def query_osv(components: list[dict], timeout=30) -> list[dict]:
    if not requests or not components:
        return components
    queries = [{"package": {"name": c["name"], "ecosystem": c["ecosystem"]},
                "version": c["version"]} for c in components]
    try:
        r = requests.post(OSV_URL, json={"queries": queries}, timeout=timeout)
        if r.status_code != 200:
            return components
        results = r.json().get("results", [])
    except Exception:
        return components
    for c, res in zip(components, results):
        vulns = res.get("vulns") or []
        c["vulns"] = [{"id": v.get("id", ""), "summary": v.get("summary", "")[:200]}
                      for v in vulns]
    return components


# ── CycloneDX SBOM ────────────────────────────────────────────────────────────
def cyclonedx(components: list[dict]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": [{"vendor": "TBHM", "name": "sbom"}]},
        "components": [{
            "type": "library",
            "name": c["name"],
            "version": c["version"],
            "purl": f"pkg:{c['ecosystem'].lower()}/{c['name']}@{c['version']}",
        } for c in components],
    }
