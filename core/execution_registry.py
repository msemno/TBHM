"""Declarative execution-adapter registry for TBHM v3.9.6.

This module intentionally contains no payload generation, credential use, C2
session creation, persistence, phishing delivery, or destructive primitives.
It turns high-impact operator work into auditable plan/import records.  Only
low-risk read-only or synthetic simulation adapters may ever be marked live.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = ROOT / "tooling" / "execution_adapter_registry_v396.json"

HIGH_IMPACT_CAPABILITIES = {
    "exploit", "payload", "credential_attack", "credential_access", "c2",
    "persistence", "lateral_movement", "exfiltration", "phishing",
    "mfa_interception", "wireless_disruption", "physical_bypass", "ot_write",
}


def load(path: str | Path | None = None) -> dict:
    p = Path(path) if path else DEFAULT_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("adapters"), list):
        raise ValueError("execution adapter registry must contain an adapters list")
    return data


def validate_adapter(row: dict) -> list[str]:
    errors: list[str] = []
    for key in ("id", "name", "capability", "mode", "risk"):
        if not str(row.get(key) or "").strip():
            errors.append(f"missing {key}")
    mode = str(row.get("mode") or "")
    if mode not in {"read_only", "simulation", "plan_import", "commercial_import"}:
        errors.append("invalid mode")
    risk = str(row.get("risk") or "").lower()
    if risk not in {"low", "medium", "high", "critical"}:
        errors.append("invalid risk")
    capability = str(row.get("capability") or "").lower()
    if capability in HIGH_IMPACT_CAPABILITIES and mode not in {"plan_import", "commercial_import"}:
        errors.append("high-impact capability must remain plan/import only")
    if mode in {"read_only", "simulation"} and risk in {"high", "critical"}:
        errors.append("live-safe adapter cannot be high or critical risk")
    return errors


def index(registry: dict) -> dict[str, dict]:
    return {str(row.get("id")): row for row in registry.get("adapters", []) if row.get("id")}


def plan_record(adapter: dict, *, target: str, objective: str, approval: tuple[bool, str]) -> dict:
    approved, detail = approval
    mode = str(adapter.get("mode") or "plan_import")
    status = "READY_FOR_READ_ONLY_OR_SIMULATION" if approved and mode in {"read_only", "simulation"} else (
        "AUTHORIZED_EXTERNAL_EXECUTION_REQUIRED" if approved else "BLOCKED"
    )
    return {
        "adapter_id": adapter.get("id"),
        "tool": adapter.get("name"),
        "capability": adapter.get("capability"),
        "risk": adapter.get("risk"),
        "mode": mode,
        "target": target,
        "objective": objective,
        "approval_verified": approved,
        "approval_detail": detail,
        "status": status,
        "required_controls": list(adapter.get("required_controls") or []),
        "evidence_schema": dict(adapter.get("evidence_schema") or {}),
        "cleanup_requirements": list(adapter.get("cleanup_requirements") or []),
        "operator_notes": str(adapter.get("operator_notes") or ""),
        "commands": [],
        "payloads": [],
    }
