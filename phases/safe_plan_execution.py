"""Execute only allowlisted, structured, read-only plans."""
from __future__ import annotations

import json
from pathlib import Path

from core import redteam_utils as RT
from core.approval_gate import load_manifest, summary as approval_summary
from core.safe_plan_executor import execute, load_plan


def run(ctx):
    path = getattr(ctx.args, "safe_plan", None)
    if not path:
        return
    out = RT.evidence_dir(ctx, "106_safe_plan_execution")
    try:
        plan = load_plan(path)
    except Exception as exc:
        ctx.log("ERR", "safe_plan_execution", f"invalid plan: {exc}")
        (out / "safe_plan_error.json").write_text(json.dumps({"status": "rejected", "error": str(exc)}, indent=2), encoding="utf-8")
        return
    try:
        manifest = load_manifest(getattr(ctx.args, "approval_manifest", None))
    except Exception as exc:
        manifest = {}
        ctx.log("WARN", "safe_plan_execution", f"approval manifest unavailable: {exc}")
    result = execute(
        plan,
        output_dir=out,
        approval_manifest=manifest,
        dry_run=bool(getattr(ctx.args, "safe_plan_dry_run", False)),
        timeout=int(getattr(ctx.args, "safe_plan_timeout", 120) or 120),
        runner=ctx.runner.run,
    )
    result["approval_manifest"] = approval_summary(manifest)
    (out / "safe_plan_execution.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    RT.write_md(out / "SAFE_PLAN_EXECUTION.md", "Allowlisted Read-Only Plan Execution", [
        ("Summary", json.dumps(result.get("summary", {}), indent=2)),
        ("Boundary", "Only RDAP, approved Sherlock/Maigret username searches, and local cosign verify-blob are accepted. Arbitrary commands, executables, URLs, shell syntax, and unknown action types are rejected."),
        ("Approval", json.dumps(approval_summary(manifest), indent=2)),
    ])
    ctx.phase_state["safe_plan_execution"] = result.get("summary", {})
    ctx.log("OK", "safe_plan_execution", f"processed {len(result.get('actions', []))} allowlisted action(s)")
