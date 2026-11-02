"""Function-level old/new binary comparison over normalized IR."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT
from core import reverse_ir as RIR
from core.binary_diff import compare
from core.reverse_phase_utils import write_json


def _load(path):
    data = json.loads(Path(path).read_text(errors="ignore"))
    return data if data.get("schema") == RIR.SCHEMA else RIR.normalize(data)


def run(ctx):
    old_path = getattr(ctx.args, "reverse_diff_old", None)
    new_path = getattr(ctx.args, "reverse_diff_new", None)
    if not (old_path and new_path):
        return
    out = RT.evidence_dir(ctx, "25j_reverse_diff_analysis")
    result = compare(_load(old_path), _load(new_path), similarity_threshold=float(getattr(ctx.args, "reverse_diff_threshold", 0.72)))
    write_json(out / "FUNCTION_LEVEL_BINARY_DIFF.json", result)
    for row in result.get("security_deltas", [])[:1000]:
        ctx.save_finding({
            "phase": "reverse_diff_analysis", "severity": "LOW", "confidence": "MEDIUM",
            "title": f"[PATCH DELTA] Security-relevant function change: {row.get('old')} -> {row.get('new')}",
            "target": str(new_path), "url": "", "description": "Function matching found added or removed security-relevant calls/tokens between two normalized reverse IR versions.",
            "evidence": json.dumps(row, ensure_ascii=False)[:6000], "impact": "The change may add validation, remove a protection, or alter a sensitive sink; manual review is required.",
            "remediation": "Review decompiled code and call sites in both versions, identify the security intent, and create regression tests for the affected behavior.",
            "cwe": "CWE-1104", "mrs_score": 35, "finding_class": "differential_observation",
        })
    RT.write_md(out / "BINARY_DIFF_SUMMARY.md", "Function-Level Binary Diff", [
        ("Old functions", str(result.get("counts", {}).get("old", 0))), ("New functions", str(result.get("counts", {}).get("new", 0))),
        ("Changed", str(result.get("counts", {}).get("changed", 0))), ("Added", str(result.get("counts", {}).get("added", 0))),
        ("Removed", str(result.get("counts", {}).get("removed", 0))), ("Security deltas", str(len(result.get("security_deltas", [])))),
    ])
    ctx.log("OK", "reverse_diff_analysis", f"compared {result.get('counts', {}).get('old', 0)} vs {result.get('counts', {}).get('new', 0)} functions")
