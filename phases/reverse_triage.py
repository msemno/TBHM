"""Phase 1: rapid static fingerprinting and reverse-engineering triage (v3.9.2)."""
from __future__ import annotations

from core.version import SEMANTIC_VERSION

import json
import re
from pathlib import Path

from core import redteam_utils as RT
from core import reverse_utils as RU


def _emit(ctx, title, severity, target, evidence, cwe="CWE-912", impact="", artifact_id=""):
    return ctx.save_finding({
        "phase": "reverse_triage",
        "severity": severity,
        "confidence": "MEDIUM",
        "title": title[:180],
        "target": str(target),
        "url": "",
        "description": "Static reverse-engineering triage observation. The target artifact was not executed.",
        "evidence": str(evidence)[:4000],
        "impact": impact or "The artifact may contain risky capabilities, embedded secrets, network indicators, unsafe imports, or packing/obfuscation that requires deeper review.",
        "remediation": "Confirm the code path and runtime reachability, remove embedded secrets, replace unsafe APIs, enable compiler mitigations, and repeat the analysis on the rebuilt artifact.",
        "cwe": cwe,
        "mrs_score": 45,
        "finding_class": "lead",
        "validation_required": "Static triage evidence alone does not prove exploitability. Correlate it with decompiler output and controlled sandbox evidence.",
        "artifact_id": artifact_id,
    })


def run(ctx):
    if not (getattr(ctx.args, "binary_path", None) or getattr(ctx.args, "reverse_tooling", False) or getattr(ctx.args, "reverse_static", False)):
        return
    out = RT.evidence_dir(ctx, "25a_reverse_triage")
    max_files = getattr(ctx.args, "reverse_max_files", 50)
    max_mb = getattr(ctx.args, "reverse_max_file_mb", 200)
    minimum = getattr(ctx.args, "reverse_strings_min", 8)
    records = []

    for artifact in RU.iter_files(getattr(ctx.args, "binary_path", None), max_files, max_mb):
        stem = RU.safe_stem(artifact)
        strings = RU.extract_strings(artifact, minimum=minimum)
        indic = RU.indicators(strings)
        # Import names can be shorter than the configured printable-string floor.
        try:
            raw_sample = artifact.read_bytes()[:64 * 1024 * 1024]
            seen_names = {item.get("name") for item in indic.get("suspicious_imports", [])}
            for name, (cwe, reason) in RU.SUSPICIOUS_IMPORTS.items():
                if name not in seen_names and name.encode("ascii", "ignore") in raw_sample:
                    indic.setdefault("suspicious_imports", []).append({"name": name, "cwe": cwe, "reason": reason})
        except Exception:
            pass
        artifact_id = RU.artifact_id(artifact)
        record = {
            "path": str(artifact), "artifact_id": artifact_id,
            "size": artifact.stat().st_size,
            "magic": RU.magic_type(artifact),
            "hashes": RU.hashes(artifact),
            "sample_entropy": round(RU.sample_entropy(artifact), 4),
            "string_count": len(strings),
            "indicators": indic,
            "tool_outputs": {},
            "execution_performed": False,
        }

        if ctx.runner.has("file"):
            rc, stdout, stderr = ctx.runner.run(["file", "-b", str(artifact)], timeout=30, log_name=f"reverse_file_{stem}")
            record["tool_outputs"]["file"] = {"rc": rc, "stdout": stdout[:4000], "stderr": stderr[:1000]}
        if record["magic"] == "ELF" and ctx.runner.has("readelf"):
            for flag, name in (("-h", "header"), ("-l", "program_headers"), ("-S", "sections"), ("-d", "dynamic"), ("-sW", "symbols")):
                rc, stdout, stderr = ctx.runner.run(["readelf", flag, str(artifact)], timeout=60, log_name=f"reverse_readelf_{name}_{stem}")
                record["tool_outputs"][f"readelf_{name}"] = {"rc": rc, "stdout": stdout[:120000], "stderr": stderr[:2000]}
        if ctx.runner.has("objdump"):
            for args, name in ((["-f"], "file_headers"), (["-x"], "all_headers"), (["-T"], "dynamic_symbols")):
                rc, stdout, stderr = ctx.runner.run(["objdump", *args, str(artifact)], timeout=90, log_name=f"reverse_objdump_{name}_{stem}")
                record["tool_outputs"][f"objdump_{name}"] = {"rc": rc, "stdout": stdout[:150000], "stderr": stderr[:2000]}
        if ctx.runner.has("nm"):
            rc, stdout, stderr = ctx.runner.run(["nm", "-D", str(artifact)], timeout=60, log_name=f"reverse_nm_{stem}")
            record["tool_outputs"]["nm_dynamic"] = {"rc": rc, "stdout": stdout[:100000], "stderr": stderr[:2000]}
        if ctx.runner.has("floss"):
            rc, stdout, stderr = ctx.runner.run(["floss", "--json", str(artifact)], timeout=600, log_name=f"reverse_floss_{stem}")
            record["tool_outputs"]["floss"] = {"rc": rc, "stdout": stdout[:500000], "stderr": stderr[:4000]}
        if ctx.runner.has("capa"):
            rc, stdout, stderr = ctx.runner.run(["capa", "-j", str(artifact)], timeout=900, log_name=f"reverse_capa_{stem}")
            record["tool_outputs"]["capa"] = {"rc": rc, "stdout": stdout[:1000000], "stderr": stderr[:4000]}
            if rc == 0 and stdout.strip():
                try:
                    (out / f"{stem}.capa.json").write_text(json.dumps(json.loads(stdout), indent=2), encoding="utf-8")
                except Exception:
                    pass

        (out / f"{stem}.strings.txt").write_text("\n".join(strings[:5000]), encoding="utf-8", errors="ignore")
        RU.write_json(out / f"{stem}.triage.json", record)
        records.append(record)

        if record["sample_entropy"] >= 7.2:
            _emit(ctx, "[LEAD] High-entropy binary content may indicate packing or encryption", "MEDIUM", artifact,
                  f"Sample entropy: {record['sample_entropy']}/8.0; type: {record['magic']}", "CWE-656", artifact_id=artifact_id)
        if indic["secret_markers"]:
            _emit(ctx, "[LEAD] Embedded credential-like material in binary strings", "HIGH", artifact,
                  "\n".join(indic["secret_markers"][:20]), "CWE-798",
                  "If the embedded value is active and reachable, an attacker who obtains the binary may reuse it to access the associated service.", artifact_id=artifact_id)
        for item in indic["suspicious_imports"][:50]:
            _emit(ctx, f"[LEAD] Suspicious imported capability: {item['name']}", "MEDIUM", artifact,
                  json.dumps(item), item["cwe"],
                  "The import is not a vulnerability by itself; a reachable, attacker-controlled data flow to this capability could enable exploitation.", artifact_id=artifact_id)
        if indic["urls"]:
            _emit(ctx, "[LEAD] Network endpoints embedded in binary", "LOW", artifact,
                  "\n".join(indic["urls"][:30]), "CWE-200", artifact_id=artifact_id)

    RU.write_json(out / "reverse_triage_index.json", {
        "version": SEMANTIC_VERSION, "artifacts": records,
        "methodology": "file identification, cryptographic hashes, entropy, strings, imports/exports, metadata and capability triage",
        "execution_performed": False,
    })
    RT.write_md(out / "REVERSE_TRIAGE_SUMMARY.md", "Reverse Engineering Triage", [
        ("Artifacts", str(len(records))),
        ("Workflow", "Fingerprint -> hashes -> entropy -> strings -> imports/exports -> capability indicators."),
        ("Tools", "Built-in parser plus file/readelf/objdump/nm/FLOSS/capa when installed."),
        ("Safety", "No artifact was executed. All observations remain leads until correlated with code paths or controlled runtime evidence."),
    ])
    ctx.log("OK", "reverse_triage", f"triaged {len(records)} artifact(s)")
