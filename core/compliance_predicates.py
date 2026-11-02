"""Control-level compliance predicate evaluation from evidence.

The modern status is authoritative. Historical aliases are emitted only so old
report consumers continue to parse the matrix; they never convert an unknown
control into a pass.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from core.version import SEMANTIC_VERSION

STATUSES = {"pass", "fail", "unknown", "not_applicable", "not_tested"}
EVALUATOR_VERSION = SEMANTIC_VERSION


def _confirmation(finding: dict) -> str:
    from core.finding_class import classify
    return {"confirmed": "CONFIRMED", "supported": "SUPPORTED", "lead": "UNCONFIRMED"}[classify(finding)]


def _legacy_status(status: str, *, manual: bool, tested: bool) -> str:
    """Return a compatibility label without weakening the authoritative status."""
    if status == "fail":
        return "findings"
    if status == "pass":
        return "tested-clean"
    if status == "not_applicable":
        return "not-applicable"
    if status == "not_tested" and manual:
        return "manual"
    if status == "not_tested":
        return "not-tested"
    # Historical code would have called this tested-clean merely because a phase
    # ran. Keep a parseable compatibility value, but do not make that unsafe claim.
    if status == "unknown" and tested:
        return "tested-unknown"
    return "unknown"


def evaluate_control(control: dict, findings: list[dict], phase_done: Callable[[str], bool], *, framework: str) -> dict:
    phases = [str(item) for item in control.get("phases", []) if str(item)]
    tested = any(phase_done(item) for item in phases) if phases else False
    manual = bool(control.get("manual"))
    tags = {str(item).lower() for item in control.get("tags", [])}
    refs = []
    matched = []
    from core.compliance_catalog import finding_tags

    for finding in findings:
        if tags & finding_tags(finding):
            matched.append(finding)
            refs.append(finding.get("id") or finding.get("title"))

    if control.get("not_applicable") is True:
        status = "not_applicable"
        confidence = "HIGH"
        reason = "Catalog explicitly marks the control not applicable."
    elif matched:
        status = "fail"
        confidence = "HIGH" if any(_confirmation(item) in {"CONFIRMED", "REPRODUCED"} for item in matched) else "MEDIUM"
        reason = f"{len(matched)} evidence-backed finding(s) map to this control."
    elif manual and not tested:
        status = "not_tested"
        confidence = "HIGH"
        reason = "Manual/organizational evidence was not supplied."
    elif tested:
        predicate = control.get("predicate")
        positive = bool(control.get("positive_evidence"))
        if predicate == "phase_completed_without_mapped_findings" and positive:
            status = "pass"
            confidence = "LOW"
            reason = "Configured positive predicate met: relevant phase completed and no mapped finding was recorded. This is not certification evidence."
        else:
            status = "unknown"
            confidence = "MEDIUM"
            reason = "Relevant testing ran, but no explicit positive control evidence predicate was satisfied."
    else:
        status = "not_tested"
        confidence = "HIGH"
        reason = "No mapped testing or control evidence is available."

    refs = refs[:100]
    identifier = control.get("id")
    row = {
        "control_identifier": identifier,
        "framework": framework,
        "title": control.get("title"),
        "predicate": control.get("predicate") or "evidence_mapping_and_explicit_positive_evidence",
        "evidence_references": refs,
        "status": status,
        "confidence": confidence,
        "reason": reason,
        "remediation": control.get("remediation") or "Collect control-specific evidence, remediate mapped findings, and have an authorized assessor evaluate effectiveness.",
        "evaluator_version": EVALUATOR_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phases": phases,
        "evidence_required": control.get("evidence_required", []),
        "notes": control.get("notes", ""),
        # v3.9.6 consumer compatibility aliases.
        "id": identifier,
        "finding_refs": list(refs),
        "legacy_status": _legacy_status(status, manual=manual, tested=tested),
    }
    return row


def evaluate_catalog(catalog: dict, findings: list[dict], phase_done: Callable[[str], bool]) -> dict:
    frameworks = []
    for framework in catalog.get("frameworks", []):
        framework_id = str(framework.get("id") or "unknown")
        controls = [evaluate_control(control, findings, phase_done, framework=framework_id) for control in framework.get("controls", [])]
        frameworks.append({
            "id": framework_id,
            "name": framework.get("name"),
            "version": framework.get("version"),
            "scope_note": framework.get("scope_note"),
            "controls": controls,
        })
    return {"evaluator_version": EVALUATOR_VERSION, "statement": catalog.get("statement"), "frameworks": frameworks}
