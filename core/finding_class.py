"""Strict lead / supported / confirmed classifier.

A vulnerability is confirmed only by an explicit verification result.  Scanner
prose, HTTP liveness, severity, or HIGH confidence are not proof.  Deterministic
signals without an independent verifier are retained as ``supported`` so useful
evidence is not flattened into low-value noise.
"""
from __future__ import annotations
import re

HEURISTIC_PHASES = {
    "business_logic", "upload_race", "access_control", "cache_deception",
    "smuggling", "api_fuzz", "backend_map", "sast_tooling",
    "code_security_tooling", "source_orchestration_tooling",
    "web_scanner_tooling", "network_firewall_tooling", "mobile_tooling",
    "ai_llm_tooling", "internal_ad_tooling", "external_perimeter_tooling",
    "reverse_engineering_tooling", "reverse_triage", "reverse_static_analysis",
    "reverse_dynamic_evidence", "reverse_symbolic_analysis", "reverse_correlation",
    "firmware_tooling_extended", "privesc_audit_tooling",
    "ad_access_assessment", "engagement_evidence_review", "lateral_movement_paths",
}

# Retained for import compatibility with pre-v4 integrations only. v4 does NOT
# confirm findings from scanner prose or evidence keywords; confirmation requires
# an explicit structured verification result. This constant is intentionally unused.
CONFIRMED_MARKERS = ("curl-verified", "reproduced", "confirmed", "verified live",
                     "introspection enabled", "200 + schema")

LEAD_TITLE_RE = re.compile(
    r"\b(possible|potential|candidate|shaped|race-prone|unverified|may be|might be|"
    r"suspected|heuristic|accepted (?:file|double))\b", re.I,
)


def _structured_confirmation(f: dict) -> bool:
    """Accept only a receipt restored from authenticated capture artifacts."""
    from core.proof_contracts import ConfirmationReceipt
    return (f.get("verified") is True and
            isinstance(f.get("_confirmation_receipt"), ConfirmationReceipt) and
            f["_confirmation_receipt"].get("verifier_version") == "tbhm-proof-v2")


def proof_authority(f: dict) -> dict:
    """Expose receipt authority to graph/report consumers without trusting JSON flags."""
    valid = _structured_confirmation(f)
    return {'verified': valid, 'test_id': f['_confirmation_receipt'].get('test_id') if valid else None,
            'evidence_state': classify(f) if f.get('finding_class') == 'confirmed' else (f.get('finding_class') or 'lead'),
            'source': 'authenticated-proof-v2' if valid else 'unverified-observation'}


def classify(f: dict) -> str:
    title = str(f.get("title") or "")
    phase = str(f.get("phase") or "").lower()
    explicit = str(f.get("finding_class") or "").lower()
    severity = str(f.get("severity") or "INFO").upper()

    if severity == "INFO":
        return "lead"
    if _structured_confirmation(f):
        return "confirmed"
    if explicit == "supported":
        return "supported"
    if explicit in {"lead", "disproved", "not_a_finding"}:
        return "lead"
    if str(f.get("verification_state") or "").lower() == "disproved":
        return "lead"
    if phase in HEURISTIC_PHASES or LEAD_TITLE_RE.search(title):
        return "lead"

    # Deterministic phase output is useful but remains supported until a
    # vulnerability-specific verifier proves the security invariant failed.
    has_evidence = bool(str(f.get("evidence") or "").strip() or f.get("response_raw"))
    return "supported" if has_evidence else "lead"


def apply(f: dict) -> dict:
    cls = classify(f)
    f["finding_class"] = cls
    if cls == "confirmed":
        f["status"] = "confirmed"
        return f
    if cls == "supported":
        f["status"] = "supported"
        f.setdefault(
            "validation_required",
            "Strong evidence is present, but a versioned assertion, negative control, "
            "repeatability proof, and independent verifier are required before confirmation.",
        )
        return f
    if not str(f.get("title") or "").startswith("[LEAD]"):
        f["title"] = "[LEAD] " + str(f.get("title") or "finding")
    if str(f.get("confidence") or "").upper() == "HIGH":
        f["confidence"] = "LOW"
    f["status"] = "lead"
    f.setdefault(
        "validation_required",
        "Unconfirmed observation or hypothesis. Define the expected invariant, failure "
        "condition, baseline, negative control and repeatability proof before reporting it.",
    )
    return f
