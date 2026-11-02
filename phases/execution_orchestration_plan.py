"""Single-pane execution planning and result correlation (v3.9.6).

The phase closes the coordination gap without becoming an exploitation engine.
It never generates payloads or operational commands and never starts C2,
credential attacks, persistence, phishing, lateral movement, exfiltration,
wireless disruption, physical bypass, or OT writes.  It builds an auditable
state machine, verifies approval, imports external results, and tracks cleanup.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from core import redteam_utils as RT
from core.approval_gate import approved, load_manifest, summary as approval_summary
from core.execution_registry import index, load, plan_record, validate_adapter

_STAGES = [
    "initial_access_validation", "privilege_path_validation",
    "lateral_movement_validation", "collection_objective",
    "egress_or_exfiltration_control_validation", "cleanup_and_restoration",
]


def _load_obj(path):
    if not path:
        return {}
    p = Path(path)
    try:
        if p.suffix.lower() == ".json":
            return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        import yaml
        return yaml.safe_load(p.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:
        return {}


def _hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return ""


def _default_actions(findings: list[dict]) -> list[dict]:
    actions = []
    for finding in findings[:200]:
        phase = str(finding.get("phase") or "")
        target = str(finding.get("url") or finding.get("target") or "")
        if not target:
            continue
        if phase in {"access_control", "authenticated_session_model", "auth_advanced"}:
            adapter = "metasploit-import"
            stage = "initial_access_validation"
        elif phase in {"identity_security_tooling", "ad_access_assessment", "lateral_movement_paths"}:
            adapter = "identity-attack-import"
            stage = "privilege_path_validation"
        elif phase in {"cloud_posture_tooling", "cloud_identity_path_analysis"}:
            adapter = "stratus-import"
            stage = "privilege_path_validation"
        else:
            continue
        actions.append({
            "id": f"auto-{len(actions)+1}", "adapter_id": adapter,
            "stage": stage, "target": target,
            "objective": f"Validate the control impact of finding {finding.get('id') or finding.get('title')}",
            "finding_ref": finding.get("id") or finding.get("title"),
        })
    return actions


def run(ctx):
    if not (getattr(ctx.args, "execution_orchestration", False)
            or getattr(ctx.args, "execution_plan", None)
            or getattr(ctx.args, "execution_results", None)):
        return
    out = RT.evidence_dir(ctx, "99_execution_orchestration_plan")
    registry = load(getattr(ctx.args, "execution_registry", None))
    registry_errors = {}
    valid_rows = []
    for row in registry.get("adapters", []):
        errors = validate_adapter(row)
        if errors:
            registry_errors[str(row.get("id") or "unknown")] = errors
        else:
            valid_rows.append(row)
    reg_index = index({"adapters": valid_rows})
    try:
        manifest = load_manifest(getattr(ctx.args, "approval_manifest", None))
    except Exception as exc:
        manifest = {}
        ctx.log("WARN", "execution_orchestration_plan", str(exc))
    plan = _load_obj(getattr(ctx.args, "execution_plan", None))
    actions = list(plan.get("actions") or []) if isinstance(plan, dict) else []
    if not actions and getattr(ctx.args, "execution_from_findings", False):
        try:
            actions = _default_actions(ctx.storage.all_findings())
        except Exception:
            actions = []
    records = []
    stage_state = {stage: "NOT_PLANNED" for stage in _STAGES}
    for item in actions[:1000]:
        if not isinstance(item, dict):
            continue
        adapter_id = str(item.get("adapter_id") or "").strip()
        adapter = reg_index.get(adapter_id)
        if not adapter:
            records.append({"id": item.get("id"), "adapter_id": adapter_id, "status": "BLOCKED", "detail": "unknown adapter"})
            continue
        target = str(item.get("target") or "").strip()
        action_name = str(item.get("approval_action") or f"execution:{adapter_id}")
        rec = plan_record(adapter, target=target, objective=str(item.get("objective") or ""), approval=approved(manifest, action_name, target))
        rec.update({"id": item.get("id"), "stage": item.get("stage") or "initial_access_validation", "finding_ref": item.get("finding_ref")})
        stage = str(rec["stage"])
        stage_state[stage] = "AUTHORIZED_EXTERNAL" if rec["approval_verified"] else "BLOCKED"
        records.append(rec)
    imported = []
    rp = getattr(ctx.args, "execution_results", None)
    if rp:
        root = Path(rp)
        files = [root] if root.is_file() else [p for p in root.rglob("*.json") if p.is_file()] if root.is_dir() else []
        for p in files[:1000]:
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                rows = data if isinstance(data, list) else data.get("results", [data]) if isinstance(data, dict) else []
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    adapter_id = str(row.get("adapter_id") or "")
                    target = str(row.get("target") or "")
                    adapter = reg_index.get(adapter_id)
                    if not adapter:
                        imported.append({"adapter_id": adapter_id, "target": target,
                                         "source_file": p.name, "source_sha256": _hash(p),
                                         "approval_verified": False,
                                         "approval_detail": "unknown or invalid execution adapter",
                                         "cleanup_verified": False, "status": "BLOCKED"})
                        continue
                    action_name = str(row.get("approval_action") or f"execution:{adapter_id}")
                    ok, detail = approved(manifest, action_name, target)
                    clean = str(row.get("cleanup_status") or "UNKNOWN").upper()
                    imported.append({**row, "source_file": p.name, "source_sha256": _hash(p),
                                     "approval_verified": ok, "approval_detail": detail,
                                     "cleanup_verified": clean in {"COMPLETE", "COMPLETED", "VERIFIED"}})
            except Exception:
                continue
    with (out / "execution_queue.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["id", "stage", "adapter_id", "tool", "capability", "risk", "mode", "target", "objective", "approval_verified", "status"]
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader(); writer.writerows(records)
    payload = {
        "registry_version": registry.get("version"), "registry_errors": registry_errors,
        "approval": approval_summary(manifest), "stage_state": stage_state,
        "planned_actions": records, "imported_results": imported,
        "boundary": "No operational commands, payloads, credentials, C2 sessions, persistence, phishing delivery, lateral movement, or exfiltration are executed by TBHM.",
    }
    (out / "execution_orchestration.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    (out / "cleanup_register.json").write_text(json.dumps([
        {"adapter_id": x.get("adapter_id"), "target": x.get("target"), "cleanup_status": x.get("cleanup_status", "UNKNOWN"), "verified": x.get("cleanup_verified", False)} for x in imported
    ], indent=2), encoding="utf-8")
    RT.write_md(out / "EXECUTION_ORCHESTRATION.md", "Approval-Gated Execution Orchestration", [
        ("Summary", f"{len(records)} planned action(s), {len(imported)} imported result(s)."),
        ("State", json.dumps(stage_state, indent=2)),
        ("Safety boundary", payload["boundary"]),
        ("Single-pane workflow", "TBHM creates the objective/action/evidence/cleanup ledger. High-impact execution remains in separately governed operator infrastructure and returns signed evidence through --execution-results."),
    ])
    ctx.phase_state["execution_orchestration"] = {"planned": len(records), "imported": len(imported), "stage_state": stage_state}
    ctx.log("OK", "execution_orchestration_plan", f"{len(records)} planned, {len(imported)} result(s) imported")
