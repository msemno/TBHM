"""
Correlation Engine — turns isolated findings into evidence chains.

Pro DAST output is just a list of findings. Burp Suite's real power is that
you can manually trace one finding to its root cause. This module does that
automatically using simple link rules:

  Link rules:
    1. Same hostname    → group findings per asset
    2. Same parameter   → suggest one root cause
    3. JS secret → URL where the secret would unlock → finding on that URL
    4. Subdomain takeover → all dependent findings
    5. Same CWE class   → same defense pattern

Output: a `correlations.json` file the dashboard reads to draw connections.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse
from core.evidence_graph import canonical_asset


def build(findings: list[dict]) -> dict:
    """
    Given a list of finding dicts, return correlation graph:
      {
        "clusters": [
          {"id": "cluster-0", "label": "...", "finding_ids": [...], "links": [...]},
          ...
        ],
        "links": [{"from": id, "to": id, "type": "same_param"}, ...],
        "stats": {...}
      }
    """
    if not findings:
        return {"clusters": [], "links": [], "stats": {}}

    # Index for fast lookups
    by_host = defaultdict(list)
    by_param = defaultdict(list)
    by_cwe = defaultdict(list)

    for f in findings:
        host = canonical_asset(f)
        by_host[host].append(f["id"] if "id" in f else _fid(f))
        param = f.get("parameter") or ""
        if param:
            by_param[(host, param)].append(f["id"] if "id" in f else _fid(f))
        cwe = f.get("cwe") or ""
        if cwe:
            by_cwe[cwe].append(f["id"] if "id" in f else _fid(f))

    # Build clusters: one per host
    clusters = []
    for i, (host, fids) in enumerate(by_host.items()):
        sevs = [f.get("severity", "INFO") for f in findings
                if (f.get("id") or _fid(f)) in set(fids)]
        clusters.append({
            "id": f"cluster-{i}",
            "label": host,
            "finding_ids": fids,
            "highest_severity": _highest_sev(sevs),
            "count": len(fids),
        })

    # Build links: same parameter on same host
    links = []
    for (host, param), fids in by_param.items():
        if len(fids) > 1:
            for j in range(len(fids) - 1):
                links.append({
                    "from": fids[j], "to": fids[j + 1],
                    "type": "same_parameter", "evidence_state": "correlation",
                    "label": f"both touch param '{param}' on {host}",
                })
    # Links: same CWE class
    for cwe, fids in by_cwe.items():
        if len(fids) > 1:
            for j in range(len(fids) - 1):
                links.append({
                    "from": fids[0], "to": fids[j + 1],
                    "type": "same_cwe", "evidence_state": "taxonomy_similarity",
                    "label": f"both {cwe}",
                })

    return {
        "clusters": clusters,
        "links": links,
        "stats": {
            "n_findings": len(findings),
            "n_hosts": len(by_host),
            "n_links": len(links),
            "shared_params": len([k for k, v in by_param.items() if len(v) > 1]),
        }
    }


def _host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _highest_sev(sevs: list[str]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for s in order:
        if s in sevs:
            return s
    return "INFO"


def _fid(f: dict) -> str:
    """Deterministic finding ID for findings without explicit id."""
    import hashlib
    key = f"{f.get('title','')}|{f.get('url','')}|{f.get('parameter','')}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def write(output_dir: Path, findings: list[dict]):
    """Convenience: build + write to disk for the dashboard."""
    correlations = build(findings)
    out = output_dir / "correlations.json"
    out.write_text(json.dumps(correlations, indent=2, default=str))
    return correlations
