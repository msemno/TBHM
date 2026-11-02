"""Typed, approval-gated red-team campaign control and result import.

The complete red-team lifecycle is visible, including exploit validation,
initial access, execution, persistence, privilege escalation, credential access,
lateral movement, C2, collection, exfiltration and impact. High-impact actions
remain import-only and operator-governed. TBHM validates scope/approval bindings,
hashes, timestamps, cleanup, detection evidence and structured proof; it does
not generate or launch the high-impact operation itself.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from core.approval_gate import approved, load_manifest, summary as approval_summary
from core.assertion_engine import evaluate, confirmation_fields
from core.campaign_model import (
    load, validate_campaign, normalize_operation, result_is_complete,
    sanitize_result_record,
)


def _hash(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return ""


def _result_files(path: str | None):
    if not path:
        return []
    p = Path(path)
    if p.is_file():
        return [p]
    if p.is_dir():
        return [x for x in p.rglob("*.json") if x.is_file()][:2000]
    return []


def _artifact_refs(path: Path, row: dict) -> list[dict]:
    refs = [{"kind": "operation-result-record", "source_file": path.name,
             "sha256": str(row.get("source_record_sha256") or "")}]
    if row.get("evidence_sha256"):
        refs.append({"kind": "external-evidence-manifest", "sha256": str(row.get("evidence_sha256"))})
    return refs


def run(ctx):
    enabled = bool(
        getattr(ctx.args, "campaign_plan", None)
        or getattr(ctx.args, "campaign_results", None)
        or getattr(ctx.args, "redteam_campaign", False)
        or ctx.profile.get("name") in {"authorized_redteam", "authorized_assumed_breach"}
    )
    if not enabled:
        return

    out = ctx.output / "redteam" / "100_campaign_control"
    out.mkdir(parents=True, exist_ok=True)
    try:
        manifest = load_manifest(getattr(ctx.args, "approval_manifest", None))
    except Exception as exc:
        manifest = {}
        ctx.log("WARN", "redteam_campaign_control", str(exc))

    campaign = load(getattr(ctx.args, "campaign_plan", None)) if getattr(ctx.args, "campaign_plan", None) else {
        "campaign_id": "unplanned",
        "name": "Red-team campaign register",
        "objective": "No campaign plan supplied; high-impact coverage remains NOT_PLANNED.",
        "operations": [],
        "status": "not_planned",
    }
    errors = validate_campaign(campaign)
    if errors and getattr(ctx.args, "campaign_plan", None):
        raise ValueError("invalid campaign plan: " + ", ".join(errors))

    campaign_db_id = ctx.storage.save_campaign(campaign, approval_summary(manifest))
    operation_index: dict[str, tuple[int, dict, bool]] = {}
    operations: list[dict] = []
    for raw in campaign.get("operations", [])[:1000]:
        if not isinstance(raw, dict):
            continue
        op = normalize_operation(raw)
        action = str(raw.get("approval_action") or f"operation:{op['operation_type']}")
        ok, detail = approved(manifest, action, op["target"])
        approval_status = "approved" if ok else "blocked"
        op["approval_detail"] = detail
        op["status"] = (
            "authorized_external_execution"
            if ok and op["execution_class"] == "import_only"
            else ("ready_safe_simulation" if ok else "blocked")
        )
        db_id = ctx.storage.save_operation(campaign_db_id, op, approval_status)
        operation_index[op["operation_id"]] = (db_id, op, ok)
        operations.append(op)

    imported: list[dict] = []
    confirmed = inconclusive = control_held = blocked_results = 0
    for path in _result_files(getattr(ctx.args, "campaign_results", None)):
        try:
            if path.stat().st_size > 32 * 1024 * 1024:
                imported.append({"source_file": path.name, "import_status": "BLOCKED_FILE_TOO_LARGE",
                                 "maximum_bytes": 32 * 1024 * 1024})
                blocked_results += 1
                continue
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception as exc:
            imported.append({"source_file": path.name, "import_status": "BLOCKED_INVALID_JSON",
                             "error": str(exc)[:500]})
            blocked_results += 1
            continue
        rows = data if isinstance(data, list) else data.get("results", [data]) if isinstance(data, dict) else []
        for raw in rows[:1000]:
            if not isinstance(raw, dict):
                continue
            row = sanitize_result_record(raw)
            # This is computed by TBHM and cannot be overridden by the imported record.
            row["source_record_sha256"] = _hash(path)
            row["source_file"] = path.name
            op_id = str(row.get("operation_id") or "")
            entry = operation_index.get(op_id)
            if not entry:
                row["import_status"] = "BLOCKED_UNKNOWN_OPERATION"
                blocked_results += 1
                imported.append(row)
                continue

            op_db_id, op, was_approved = entry
            complete, missing = result_is_complete(row, op)
            if not was_approved or not complete:
                row["import_status"] = "BLOCKED"
                row["missing"] = missing if complete is False else ["operation approval"]
                blocked_results += 1
                imported.append(row)
                continue

            assertion = row.get("assertion")
            proof = row.get("proof")
            result = evaluate(assertion, proof, evidence_root=ctx.output) if isinstance(assertion, dict) and isinstance(proof, dict) else {
                "result": "inconclusive",
                "assertion_passed": False,
                "negative_control_passed": False,
                "repeatability_passed": False,
                "reasons": ["structured assertion/proof bundle missing"],
            }
            tx = ctx.storage.start_test_execution(
                test_id=str((assertion or {}).get("test_id") or f"operation-{op_id}"),
                phase="redteam_campaign_control",
                target=op["target"],
                operation=op["operation_type"],
                assertion=assertion or {},
                extra={"campaign_id": campaign.get("campaign_id"), "operation_id": op_id},
            )
            refs = _artifact_refs(path, row)
            attempt_id = ctx.storage.record_validation_attempt(
                verifier="approved-external-operation-import",
                result=result,
                assertion=assertion or {},
                proof=proof or {},
                test_execution_id=tx,
                artifact_refs=refs,
                reviewer=str(row.get("reviewer") or row.get("operator") or "external-operator"),
            )

            finding_id = None
            if result["result"] == "pass":
                fields = confirmation_fields(
                    result,
                    method="approved external operation + structured proof",
                    validation_attempt_id=attempt_id,
                )
                finding = {
                    "phase": "redteam_campaign_control",
                    "severity": str(row.get("severity") or "HIGH").upper(),
                    "confidence": "HIGH",
                    "title": str(row.get("title") or f"Red-team control failure validated: {op['operation_type']}")[:220],
                    "target": op["target"],
                    "description": str(row.get("description") or op["objective"]),
                    "evidence": json.dumps(row.get("evidence") or {}, default=str)[:12000],
                    "impact": str(row.get("impact") or "The approved operation demonstrated a control failure."),
                    "remediation": str(row.get("remediation") or "Remediate the control failure and repeat the same approved proof."),
                    "cwe": str(row.get("cwe") or "CWE-693"),
                    "campaign_id": campaign.get("campaign_id"),
                    "operation_id": op_id,
                    "attack_ids": op.get("attack_ids", []),
                    "cleanup_status": row.get("cleanup_status"),
                    "assertion": assertion or {},
                    "proof": proof or {},
                    **fields,
                }
                finding_id = ctx.save_finding(finding)
                confirmed += 1 if finding_id else 0
                test_status = "failed-security-control"
                operation_status = "validated_control_failure"
                row["import_status"] = "VALIDATED_CONTROL_FAILURE"
            elif result["result"] == "fail":
                # A contradicted vulnerability assertion means the tested security
                # invariant held. It is test coverage, not a vulnerability finding.
                ctx.storage.save_observation(
                    phase="redteam_campaign_control",
                    observation_type="approved_operation_control_held",
                    target=op["target"],
                    summary=str(row.get("outcome") or "Structured assertion was not reproduced."),
                    evidence={"operation_id": op_id, "validation_attempt_id": attempt_id},
                    test_execution_id=tx,
                    artifact_sha256=str(row.get("source_record_sha256") or ""),
                )
                control_held += 1
                test_status = "passed"
                operation_status = "control_held"
                row["import_status"] = "CONTROL_HELD"
            else:
                # Preserve incomplete external evidence as a lead, never as a
                # supported or confirmed vulnerability.
                finding = {
                    "phase": "redteam_campaign_control",
                    "severity": str(row.get("severity") or "INFO").upper(),
                    "confidence": "LOW",
                    "title": str(row.get("title") or f"[LEAD] Inconclusive red-team operation evidence: {op['operation_type']}")[:220],
                    "target": op["target"],
                    "description": str(row.get("description") or op["objective"]),
                    "evidence": json.dumps(row.get("evidence") or {}, default=str)[:12000],
                    "impact": "No control failure is confirmed; additional approved proof is required.",
                    "remediation": "Complete the versioned assertion, negative control, repeatability and cleanup evidence.",
                    "cwe": str(row.get("cwe") or "CWE-693"),
                    "campaign_id": campaign.get("campaign_id"),
                    "operation_id": op_id,
                    "attack_ids": op.get("attack_ids", []),
                    "cleanup_status": row.get("cleanup_status"),
                    "assertion": assertion or {},
                    "proof": proof or {},
                    "verified": False,
                    "finding_class": "lead",
                    "verification_state": "inconclusive",
                    "validation_attempt_id": attempt_id,
                }
                finding_id = ctx.save_finding(finding)
                inconclusive += 1
                test_status = "inconclusive"
                operation_status = "evidence_imported_inconclusive"
                row["import_status"] = "INCONCLUSIVE"

            ctx.storage.complete_test_execution(
                tx,
                status=test_status,
                result_summary="; ".join(result.get("reasons") or [])[:4000],
                artifact_refs=refs,
                extra={"finding_id": finding_id, "operation_status": operation_status},
            )
            ctx.storage.update_operation_result(op_db_id, row, status=operation_status)
            if isinstance(row.get("detection"), dict):
                ctx.storage.save_detection_outcome(op_db_id, row["detection"])
            for cleanup in row.get("cleanup_actions", []) if isinstance(row.get("cleanup_actions"), list) else []:
                if isinstance(cleanup, dict):
                    ctx.storage.save_cleanup_action(op_db_id, cleanup)
            imported.append(row)

    payload = {
        "campaign": {k: campaign.get(k) for k in ("campaign_id", "name", "objective", "status")},
        "approval": approval_summary(manifest),
        "operations": operations,
        "imported_results": imported,
        "confirmed_control_failures": confirmed,
        "control_held": control_held,
        "inconclusive": inconclusive,
        "blocked_results": blocked_results,
        "execution_boundary": (
            "High-impact red-team actions are approval-gated and import-only. "
            "TBHM does not generate payloads, steal credentials, deploy persistence, "
            "evade EDR, launch C2, laterally move, phish users, alter OT, or exfiltrate real data."
        ),
    }
    (out / "campaign_control.json").write_text(json.dumps(payload, indent=2, default=str))
    ctx.phase_state["redteam_campaign_control"] = payload
    ctx.log(
        "OK", "redteam_campaign_control",
        f"operations={len(operations)} imported={len(imported)} confirmed={confirmed} "
        f"control_held={control_held} inconclusive={inconclusive} blocked={blocked_results}",
    )
