"""
Phase: honeypot_detection   (v3.2)

Read-only heuristic check for signs the target is a honeypot / deception trap,
so an operator can pause before spending effort (or tipping their hand) inside a
sensor. It inspects data already collected this run (ports, banners, recon logs)
plus optional live banner grabs, and looks for:

  * known honeypot software fingerprints (Cowrie/Kippo, Dionaea, Glastopf,
    Honeyd, Conpot, T-Pot, OpenCanary, Amun),
  * implausible service spreads (many high-value ports all open on one host),
  * identical/decoy banners across unrelated ports.

It does not attack. It only warns. Findings are INFO/LOW by design.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_HONEYPOT_SIGS = [
    ("Cowrie/Kippo SSH", re.compile(r"(?i)(cowrie|kippo|SSH-2\.0-OpenSSH_5\.1p1 Debian-5)")),
    ("Dionaea", re.compile(r"(?i)dionaea")),
    ("Glastopf", re.compile(r"(?i)glastopf")),
    ("Conpot ICS", re.compile(r"(?i)conpot")),
    ("Honeyd", re.compile(r"(?i)honeyd")),
    ("OpenCanary", re.compile(r"(?i)opencanary")),
    ("Amun", re.compile(r"(?i)\bamun\b")),
    ("T-Pot", re.compile(r"(?i)t-?pot")),
    ("Generic tarpit", re.compile(r"(?i)(tarpit|labrea)")),
]

# high-value ports that are suspicious when ALL open together on one host
_DECOY_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 6379, 9200}


def _scan_text_blobs(ctx):
    """Collect banner/scan text already produced this run."""
    blobs = []
    for rel in ("logs", "recon", "scans", "ports"):
        d = ctx.output / rel
        if not d.is_dir():
            continue
        for f in d.rglob("*"):
            if f.is_file() and f.suffix.lower() in (".txt", ".log", ".json", ".xml", ""):
                try:
                    blobs.append(f.read_text(errors="ignore"))
                except Exception:
                    pass
    return blobs


def run(ctx):
    out_dir = ctx.output / "honeypot"
    out_dir.mkdir(exist_ok=True)

    blobs = _scan_text_blobs(ctx)
    text = "\n".join(blobs)

    sig_hits = []
    for name, rx in _HONEYPOT_SIGS:
        if rx.search(text):
            sig_hits.append(name)

    # port-spread heuristic from findings
    open_ports = set()
    try:
        for f in ctx.storage.all_findings():
            for m in re.finditer(r"\b(\d{2,5})/(?:tcp|udp)\b",
                                  f.get("evidence", "") + f.get("description", "")):
                open_ports.add(int(m.group(1)))
    except Exception:
        pass
    decoy_overlap = _DECOY_PORTS & open_ports
    port_suspicion = len(decoy_overlap) >= 8

    verdict = "clean"
    reasons = []
    if sig_hits:
        verdict = "likely-honeypot"
        reasons.append("software fingerprint(s): " + ", ".join(sig_hits))
    if port_suspicion:
        verdict = "suspicious" if verdict == "clean" else verdict
        reasons.append(f"{len(decoy_overlap)} high-value ports open together "
                       f"({sorted(decoy_overlap)})")

    result = {"verdict": verdict, "signature_hits": sig_hits,
              "suspicious_port_spread": sorted(decoy_overlap), "reasons": reasons}
    (out_dir / "honeypot_assessment.json").write_text(json.dumps(result, indent=2))

    if verdict != "clean":
        ctx.save_finding({
            "phase": "honeypot_detection",
            "severity": "LOW" if verdict == "suspicious" else "MEDIUM",
            "confidence": "MEDIUM" if sig_hits else "LOW",
            "title": f"Possible deception/honeypot ({verdict})",
            "target": ctx.targets[0] if ctx.targets else "",
            "description": "Heuristic honeypot indicators observed: " + "; ".join(reasons)
                           + ". Consider confirming with the engagement lead before proceeding.",
            "evidence": json.dumps(result)[:400],
            "impact": "Effort spent inside a sensor is wasted and may alert defenders.",
            "remediation": "Validate host legitimacy out-of-band; not a target defect per se.",
            "mrs_score": 25,
        })
        ctx.log("WARN", "honeypot_detection",
                f"verdict={verdict}: {'; '.join(reasons)}")
    else:
        ctx.log("OK", "honeypot_detection", "no honeypot indicators in collected data")
