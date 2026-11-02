"""Crash deduplication, reproduction planning and explicit isolated minimization."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT
from core.crash_triage import collect_crashes, write_plan, reproduce_and_minimize
from core.sandbox_manager import SandboxManager, parse_command_json, SandboxError
from core.reverse_phase_utils import write_json


def run(ctx):
    source = getattr(ctx.args, "reverse_crash_results", None)
    minimize = bool(getattr(ctx.args, "reverse_crash_minimize", False))
    if not source and not minimize:
        return
    out = RT.evidence_dir(ctx, "25i_reverse_crash_triage")
    result = collect_crashes(source, max_files=int(getattr(ctx.args, "reverse_crash_max_files", 10000))) if source else {
        "schema": "tbhm.crash-triage/1.0", "crashes": [], "groups": [], "counts": {"records": 0, "unique": 0}
    }
    write_json(out / "CRASH_TRIAGE.json", result)
    try:
        command = parse_command_json(getattr(ctx.args, "reverse_crash_command", None))
    except SandboxError as exc:
        raise RuntimeError(str(exc)) from exc
    write_plan(result, out / "CRASH_REPRODUCTION_PLAN.json", command)

    minimization = {}
    if minimize:
        if not getattr(ctx.args, "confirm_isolated_execution", False):
            raise RuntimeError("--reverse-crash-minimize requires --confirm-isolated-execution")
        required = {
            "--binary-path": getattr(ctx.args, "binary_path", None),
            "--reverse-crash-input": getattr(ctx.args, "reverse_crash_input", None),
            "--reverse-crash-image": getattr(ctx.args, "reverse_crash_image", None),
            "--reverse-crash-command": command,
        }
        missing = [key for key, value in required.items() if not value]
        if missing:
            raise RuntimeError("crash minimization missing: " + ", ".join(missing))
        manager = SandboxManager(out / "sandbox")
        minimization = reproduce_and_minimize(
            manager, getattr(ctx.args, "binary_path"), getattr(ctx.args, "reverse_crash_input"),
            getattr(ctx.args, "reverse_crash_image"), command,
            engine=str(getattr(ctx.args, "reverse_crash_engine", "auto")),
            timeout=max(1, min(int(getattr(ctx.args, "reverse_crash_timeout", 60)), 3600)),
            max_tests=max(1, min(int(getattr(ctx.args, "reverse_crash_max_tests", 100)), 1000)),
        )
        write_json(out / "CRASH_MINIMIZATION.json", minimization)

    for group in result.get("groups", [])[:1000]:
        ctx.save_finding({
            "phase": "reverse_crash_triage", "severity": "MEDIUM", "confidence": "MEDIUM",
            "title": f"[CRASH] Unique crash signature ({group.get('count')} occurrence(s))",
            "target": str(source), "url": "", "description": "Crash evidence was normalized and deduplicated by stable stack signature. A crash alone is not proof of exploitable security impact.",
            "evidence": json.dumps(group, ensure_ascii=False)[:7000], "impact": "May indicate availability or memory-safety impact after reproducibility and exploitability review.",
            "remediation": "Reproduce in a disposable sandbox, minimize the input while preserving the stack signature, fix the parser defect, and add the input to regression tests.",
            "cwe": "CWE-703", "mrs_score": 55, "finding_class": "runtime_observation",
        })
    RT.write_md(out / "CRASH_TRIAGE_SUMMARY.md", "Crash Triage", [
        ("Crash records", str(result.get("counts", {}).get("records", 0))),
        ("Unique signatures", str(result.get("counts", {}).get("unique", 0))),
        ("Isolated reproduction", "performed" if minimization else "not requested"),
        ("Minimization", f"{minimization.get('original', {}).get('bytes', 0)} -> {minimization.get('minimized', {}).get('bytes', 0)} bytes" if minimization.get("reproduced") else "not performed or not reproduced"),
    ])
    ctx.log("OK", "reverse_crash_triage", f"{result.get('counts', {}).get('unique', 0)} unique crash(es)")
