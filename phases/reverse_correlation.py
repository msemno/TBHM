"""Phase 5: correlate reverse-engineering evidence and prepare report narrative (v3.9.2)."""
from __future__ import annotations

from core.version import SEMANTIC_VERSION

import json
from pathlib import Path

from core import redteam_utils as RT
from core import reverse_utils as RU

REVERSE_PHASES = {
    "reverse_triage", "reverse_static_analysis", "reverse_dynamic_evidence",
    "reverse_symbolic_analysis", "reverse_engineering_tooling", "firmware_reverse_safe",
    "firmware_tooling_extended",
}


def run(ctx):
    if not any([
        getattr(ctx.args, "binary_path", None), getattr(ctx.args, "reverse_results", None),
        getattr(ctx.args, "reverse_dynamic_results", None), getattr(ctx.args, "reverse_symbolic_results", None),
        getattr(ctx.args, "reverse_tooling", False), getattr(ctx.args, "reverse_static", False),
        getattr(ctx.args, "reverse_symbolic", False), getattr(ctx.args, "firmware", None),
        getattr(ctx.args, "firmware_rootfs", None), getattr(ctx.args, "emba_results", None),
        getattr(ctx.args, "routersploit_results", None), getattr(ctx.args, "firmware_tool_results", None),
    ]):
        return
    out = RT.evidence_dir(ctx, "25e_reverse_correlation")
    findings = [f for f in ctx.storage.all_findings() if f.get("phase") in REVERSE_PHASES]
    by_artifact = {}
    for finding in findings:
        artifact_key = (finding.get("artifact_id") or finding.get("target")
                        or finding.get("url") or "unknown")
        by_artifact.setdefault(str(artifact_key), []).append(finding)

    artifacts = []
    for artifact_key, items in by_artifact.items():
        targets = sorted({str(item.get("target") or item.get("url") or "")
                          for item in items if item.get("target") or item.get("url")})
        display_target = targets[0] if targets else artifact_key
        phases = sorted({str(item.get("phase")) for item in items})
        has_static = bool({"reverse_triage", "reverse_static_analysis", "reverse_symbolic_analysis"}.intersection(phases))
        has_dynamic = "reverse_dynamic_evidence" in phases
        confirmed_runtime = any(item.get("verified") is True for item in items if item.get("phase") == "reverse_dynamic_evidence")
        severity = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if any(item.get("severity") == s for item in items)), "INFO")
        artifacts.append({
            "artifact_id": artifact_key if artifact_key.startswith("sha256:") else "",
            "target": display_target, "evidence_targets": targets,
            "finding_count": len(items), "phases": phases,
            "static_evidence": has_static, "dynamic_evidence": has_dynamic,
            "controlled_runtime_proof": confirmed_runtime,
            "highest_severity": severity,
            "assessment": (
                "corroborated-static-and-dynamic" if has_static and has_dynamic else
                "static-only" if has_static else "dynamic-only" if has_dynamic else "imported-only"
            ),
            "finding_ids": [item.get("id") for item in items],
        })
        correlation = {
            "reverse_correlation": {
                "phases": phases, "static_evidence": has_static, "dynamic_evidence": has_dynamic,
                "controlled_runtime_proof": confirmed_runtime,
                "assessment": artifacts[-1]["assessment"],
                "artifact_id": artifacts[-1].get("artifact_id", ""),
                "evidence_targets": targets,
            }
        }
        for item in items:
            ctx.storage.enrich_finding(int(item["id"]), correlation)

    payload = {
        "version": SEMANTIC_VERSION, "artifacts": artifacts,
        "methodology": [
            "initial fingerprinting and triage", "headless static analysis and CFG export",
            "controlled sandbox evidence import", "bounded symbolic/CFG analysis",
            "cross-phase correlation and exploitability assessment",
        ],
        "confirmation_rule": "Static indicators become confirmed only when independently reproduced with controlled runtime evidence and verifier metadata.",
    }
    RU.write_json(out / "reverse_correlation.json", payload)
    lines = ["# Reverse Engineering Correlation", "", "| Artifact | Evidence | Runtime proof | Highest severity | Findings |", "|---|---|---|---|---:|"]
    for item in artifacts:
        lines.append(f"| `{str(item['target'])[:100]}` | {item['assessment']} | {item['controlled_runtime_proof']} | {item['highest_severity']} | {item['finding_count']} |")
    lines.extend(["", "Static and dynamic evidence are treated as complementary. Static-only indicators remain leads; controlled runtime proof can support confirmation after review."])
    (out / "REVERSE_CORRELATION.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    ctx.phase_state["reverse_correlation"] = payload
    ctx.log("OK", "reverse_correlation", f"correlated {len(findings)} finding(s) across {len(artifacts)} artifact(s)")
