"""Single source of truth for a finding's confirmation status.

Recheck finding: TBHM persists the exploitability assessment nested under
    finding["enrichment"]["exploitability"]["confirmation_status"]
(via storage.enrich_finding). It is NOT a top-level field. Reading
finding["confirmation_status"] directly returns None and silently drops
everything — which is exactly the class of bug the whole-run LLM had.

This resolver prefers the persisted value (present after
exploitability_assessment has run) and otherwise computes it deterministically
with core.exploitability.assess — the same authoritative standard the report
uses. It never executes anything and never mutates the finding.
"""
from __future__ import annotations

CONFIRMED = "CONFIRMED"
SUPPORTED = "SUPPORTED"
UNCONFIRMED = "UNCONFIRMED"


def confirmation_status(finding: dict) -> str:
    from core import exploitability
    try:
        return str(exploitability.assess(finding).get("confirmation_status", UNCONFIRMED)).upper()
    except Exception:
        return UNCONFIRMED


def is_confirmed(finding: dict) -> bool:
    return confirmation_status(finding) == CONFIRMED


def is_confirmed_or_supported(finding: dict) -> bool:
    return confirmation_status(finding) in (CONFIRMED, SUPPORTED)


def counts(findings: list) -> dict:
    out = {CONFIRMED: 0, SUPPORTED: 0, UNCONFIRMED: 0}
    for f in findings:
        st = confirmation_status(f)
        out[st] = out.get(st, 0) + 1
    return out
