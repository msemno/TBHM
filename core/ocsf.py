"""Backward-compatible, class-aware OCSF-oriented normalization facade."""
from __future__ import annotations

import hashlib
import json
from core.ocsf_export import event as class_aware_event, fingerprint


def _fingerprint(value: dict) -> str:
    """Stable v3.9.6 finding fingerprint retained for external consumers."""
    basis = "|".join(str(value.get(k) or "") for k in ("phase", "title", "target", "url", "cwe"))
    return hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()


def finding_event(finding: dict, *, tool_version: str, profile: str = "") -> dict:
    """Return the richer class-aware event while preserving v3.9.6 fields."""
    from core.ai_plane.findings import confirmation_status
    row = class_aware_event(finding, tool_version=tool_version, profile=profile)
    row["vulnerabilities"] = [{
        "cve": {"uid": str(finding.get("cve") or "")},
        "cwe": {"uid": str(finding.get("cwe") or "")},
        "cvss": finding.get("cvss") or {},
    }]
    legacy_uid = _fingerprint(finding)
    row.setdefault("unmapped", {}).update({
        "confirmation_status": confirmation_status(finding),
        "evidence": str(finding.get("evidence") or "")[:8000],
        "remediation": str(finding.get("remediation") or "")[:4000],
        "phase": finding.get("phase"),
        "fingerprint": legacy_uid,
        "legacy_uid": legacy_uid,
    })
    # v3.9.6 compatibility: findings without a stored ID used the five-field
    # fingerprint as finding_info.uid. Keep the richer class-aware fingerprint
    # under unmapped.stable_fingerprint while preserving the historical UID.
    if not finding.get("id") and not finding.get("normalized_id"):
        row.setdefault("finding_info", {})["uid"] = legacy_uid
    return row


def write_jsonl(path, events) -> int:
    rows = list(events)
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    return len(rows)


__all__ = ["finding_event", "write_jsonl", "fingerprint", "_fingerprint", "class_aware_event"]
