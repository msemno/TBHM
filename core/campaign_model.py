"""Typed red-team campaign and imported-operation evidence records.

The complete ATT&CK lifecycle can be planned and measured here. High-impact
operations are always approval-gated and import-only: TBHM records the plan,
proof, detection and cleanup result but does not generate or launch weaponized
exploitation, credential theft, persistence, evasion, C2, lateral movement,
phishing, destructive impact, or real-data exfiltration.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ATTACK_TACTICS = (
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion",
    "credential_access", "discovery", "lateral_movement", "collection",
    "command_and_control", "exfiltration", "impact",
)

ALIASES = {
    "c2": "command_and_control",
    "command-control": "command_and_control",
    "privilege-escalation": "privilege_escalation",
    "lateral-movement": "lateral_movement",
    "credential_attack": "credential_access",
}

HIGH_IMPACT = {
    "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access",
    "lateral_movement", "collection", "command_and_control", "exfiltration",
    "impact", "exploit_validation", "exploit_delivery", "phishing",
    "social_engineering", "wireless_active", "physical_bypass", "ot_write",
}
SAFE_EXECUTION_CLASSES = {"read_only", "synthetic_simulation", "import_only"}
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_SENSITIVE_RESULT_KEYS = {
    "password", "passwd", "token", "access_token", "refresh_token", "id_token",
    "api_key", "apikey", "secret", "secret_value", "client_secret", "cookie",
    "authorization", "private_key", "credentials", "credential_value",
    "payload", "payload_bytes", "shellcode", "command", "command_output",
    "stdout", "stderr",
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def load(path: str | Path | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="ignore")
    if p.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("campaign plan must be an object")
    return data


def normalize_operation(row: dict) -> dict:
    op_type = str(row.get("operation_type") or row.get("type") or "").lower().strip()
    op_type = ALIASES.get(op_type, op_type)
    tactic = str(row.get("tactic") or (op_type if op_type in ATTACK_TACTICS else "")).lower().strip()
    tactic = ALIASES.get(tactic, tactic)
    execution_class = str(row.get("execution_class") or "import_only").lower().strip()
    risk = str(row.get("risk") or ("high" if op_type in HIGH_IMPACT or tactic in HIGH_IMPACT else "medium")).lower()
    if execution_class not in SAFE_EXECUTION_CLASSES:
        execution_class = "import_only"
    if op_type in HIGH_IMPACT or tactic in HIGH_IMPACT:
        execution_class = "import_only"
    raw = json.dumps(row, sort_keys=True, default=str)
    return {
        "operation_id": str(row.get("operation_id") or row.get("id") or hashlib.sha256(raw.encode()).hexdigest()[:16]),
        "operation_type": op_type,
        "tactic": tactic,
        "execution_class": execution_class,
        "risk": risk,
        "target": str(row.get("target") or ""),
        "objective": str(row.get("objective") or ""),
        "authorization_reference": str(row.get("authorization_reference") or ""),
        "scope_reference": str(row.get("scope_reference") or ""),
        "attack_ids": list(row.get("attack_ids") or row.get("techniques") or []),
        "expected_telemetry": list(row.get("expected_telemetry") or []),
        "stop_conditions": list(row.get("stop_conditions") or []),
        "cleanup_steps": list(row.get("cleanup_steps") or row.get("cleanup") or []),
        "side_effect_budget": str(row.get("side_effect_budget") or "no destructive side effects"),
        "evidence_required": list(row.get("evidence_required") or []),
        "status": "planned",
        "created_at": utcnow(),
    }


def validate_operation(row: dict) -> list[str]:
    op = normalize_operation(row)
    errors: list[str] = []
    for key in ("operation_id", "operation_type", "tactic", "target", "objective",
                "authorization_reference", "scope_reference"):
        if not str(op.get(key) or "").strip():
            errors.append(f"missing {key}")
    if op.get("tactic") not in ATTACK_TACTICS:
        errors.append(f"unknown ATT&CK tactic: {op.get('tactic') or '<empty>'}")
    if op.get("execution_class") not in SAFE_EXECUTION_CLASSES:
        errors.append("invalid execution_class")
    for key in ("stop_conditions", "cleanup_steps", "evidence_required"):
        if not isinstance(op.get(key), list) or not op.get(key):
            errors.append(f"{key} must be a non-empty list")
    return errors


def validate_campaign(data: dict) -> list[str]:
    errors: list[str] = []
    for key in ("campaign_id", "name", "objective", "operations"):
        if not data.get(key):
            errors.append(f"missing {key}")
    operations = data.get("operations")
    if operations is not None and not isinstance(operations, list):
        errors.append("operations must be a list")
        return errors
    if data.get("rules_of_engagement") is not None and not isinstance(data.get("rules_of_engagement"), dict):
        errors.append("rules_of_engagement must be an object")
    seen: set[str] = set()
    for index, raw in enumerate(operations or []):
        if not isinstance(raw, dict):
            errors.append(f"operation[{index}] must be an object")
            continue
        op = normalize_operation(raw)
        op_id = op["operation_id"]
        if op_id in seen:
            errors.append(f"duplicate operation_id: {op_id}")
        seen.add(op_id)
        errors.extend(f"operation[{op_id}]: {item}" for item in validate_operation(raw))
    return errors


def _redacted_marker(value) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, default=str).encode()
    except Exception:
        raw = str(value).encode()
    return f"[REDACTED; SHA256={hashlib.sha256(raw).hexdigest()}]"


def sanitize_result_record(value, *, _depth: int = 0):
    """Redact common secret/payload fields before persistence or reporting."""
    if _depth > 10:
        return "[REDACTED_MAX_DEPTH]"
    if isinstance(value, dict):
        out = {}
        for key, item in list(value.items())[:2000]:
            name = str(key)
            if name.lower().replace("-", "_") in _SENSITIVE_RESULT_KEYS:
                out[name] = _redacted_marker(item)
            else:
                out[name] = sanitize_result_record(item, _depth=_depth + 1)
        return out
    if isinstance(value, list):
        return [sanitize_result_record(x, _depth=_depth + 1) for x in value[:5000]]
    if isinstance(value, str):
        text = value[:250000]
        text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
        text = re.sub(r"(?i)\b(password|passwd|token|api[_-]?key|client[_-]?secret)=([^\s&;]+)",
                      r"\1=[REDACTED]", text)
        text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                      "[REDACTED_PRIVATE_KEY]", text, flags=re.S)
        return text
    return value


def _parse_time(value: str) -> datetime | None:
    try:
        raw = str(value or "").strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def result_is_complete(row: dict, operation: dict | None = None) -> tuple[bool, list[str]]:
    """Validate imported operation evidence before it can affect findings."""
    missing: list[str] = []
    for key in ("operation_id", "target", "outcome", "evidence", "cleanup_status"):
        if not row.get(key):
            missing.append(key)
    cleanup = str(row.get("cleanup_status") or "").upper()
    if cleanup not in {"COMPLETE", "COMPLETED", "VERIFIED", "NOT_REQUIRED"}:
        missing.append("verified cleanup")

    op = operation or {}
    op_type = str(op.get("operation_type") or row.get("operation_type") or "").lower()
    tactic = str(op.get("tactic") or row.get("tactic") or "").lower()
    strict = str(row.get("schema_version") or "") in {"2", "2.0"} or op_type in HIGH_IMPACT or tactic in HIGH_IMPACT
    digest = str(row.get("evidence_sha256") or "") if strict else str(row.get("evidence_sha256") or row.get("source_sha256") or "")
    if not _SHA256_RE.fullmatch(digest):
        missing.append("valid evidence SHA-256")
    elif row.get("evidence") is not None:
        canonical = json.dumps(row.get("evidence"), sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, default=str).encode()
        if hashlib.sha256(canonical).hexdigest().lower() != digest.lower():
            missing.append("evidence SHA-256 must match the sanitized evidence manifest")

    if op:
        if str(row.get("operation_id") or "") != str(op.get("operation_id") or ""):
            missing.append("matching operation_id")
        if str(row.get("target") or "") != str(op.get("target") or ""):
            missing.append("matching operation target")
        if row.get("operation_type") and str(row.get("operation_type")).lower() != str(op.get("operation_type") or "").lower():
            missing.append("matching operation_type")

    if strict:
        for key in ("operator", "authorization_reference", "scope_reference", "started_at", "completed_at"):
            if not row.get(key):
                missing.append(key)
        expected_auth = str(op.get("authorization_reference") or "")
        expected_scope = str(op.get("scope_reference") or "")
        if expected_auth and str(row.get("authorization_reference") or "") != expected_auth:
            missing.append("matching authorization reference")
        if expected_scope and str(row.get("scope_reference") or "") != expected_scope:
            missing.append("matching scope reference")
        started = _parse_time(str(row.get("started_at") or ""))
        completed = _parse_time(str(row.get("completed_at") or ""))
        if started is None or completed is None:
            missing.append("valid operation timestamps")
        elif completed < started:
            missing.append("completed_at must not precede started_at")
        cleanup_rows = row.get("cleanup_actions") if isinstance(row.get("cleanup_actions"), list) else []
        cleanup_proof = any(str(x.get("status") or "").upper() in {"COMPLETE", "COMPLETED", "VERIFIED"}
                            for x in cleanup_rows if isinstance(x, dict))
        cleanup_digest = str(row.get("cleanup_evidence_sha256") or "")
        if cleanup != "NOT_REQUIRED" and not cleanup_proof and not _SHA256_RE.fullmatch(cleanup_digest):
            missing.append("cleanup evidence")
    return not missing, list(dict.fromkeys(missing))
