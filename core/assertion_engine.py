"""Structured vulnerability assertion evaluation.

This module deliberately evaluates *evidence already captured by an authorised
phase*.  It does not generate payloads, expand scope, or launch exploitation.
A finding can be confirmed only when a versioned assertion, a baseline, a
mutation/proof, a negative control, and repeatability evidence all agree.

The goal is to prevent endpoint liveness, scanner prose, HTTP 200 responses, or
high confidence labels from being mistaken for proof of a security failure.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any

_ALLOWED_RESULTS = {"pass", "fail", "inconclusive"}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _body(snapshot: dict | None) -> str:
    if not isinstance(snapshot, dict):
        return ""
    value = snapshot.get("body")
    if value is None:
        value = snapshot.get("response_body")
    if value is None:
        value = snapshot.get("snippet")
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value or "")


def _status(snapshot: dict | None) -> int | None:
    if not isinstance(snapshot, dict):
        return None
    for key in ("status", "status_code", "http_status"):
        try:
            if snapshot.get(key) is not None:
                return int(snapshot[key])
        except (TypeError, ValueError):
            pass
    return None


def _headers(snapshot: dict | None) -> dict[str, str]:
    if not isinstance(snapshot, dict):
        return {}
    raw = snapshot.get("headers") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in raw.items()}


def snapshot_digest(snapshot: dict | None) -> str:
    """Stable digest of non-secret proof fields."""
    safe = {
        "status": _status(snapshot),
        "headers": _headers(snapshot),
        "body": _body(snapshot)[:200000],
        "object_identity": (snapshot or {}).get("object_identity") if isinstance(snapshot, dict) else None,
        "state": (snapshot or {}).get("state") if isinstance(snapshot, dict) else None,
    }
    return hashlib.sha256(json.dumps(safe, sort_keys=True, default=str).encode()).hexdigest()


def _json_path(value: Any, path: str) -> tuple[bool, Any]:
    """Resolve a conservative dotted JSON path (no expressions or code)."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return False, None
    current = value
    for part in [p for p in str(path or "").split(".") if p]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def _condition(condition: dict, *, baseline: dict, mutation: dict, negative: dict) -> tuple[bool | None, str]:
    """Evaluate one allowlisted condition.

    ``None`` means the evidence is insufficient rather than a security control
    passing or failing.
    """
    kind = str(condition.get("type") or "").strip().lower()
    source_name = str(condition.get("source") or "mutation").strip().lower()
    source = {"baseline": baseline, "mutation": mutation, "negative_control": negative}.get(source_name)
    if source is None:
        return None, f"unknown source: {source_name}"

    if kind == "status_equals":
        actual = _status(source)
        try:
            expected = int(condition.get("value"))
        except (TypeError, ValueError):
            return None, "status_equals requires integer value"
        return (actual == expected if actual is not None else None), f"status {actual!r} == {expected}"

    if kind == "status_not_in":
        actual = _status(source)
        try:
            denied = {int(x) for x in (condition.get("values") or [])}
        except (TypeError, ValueError):
            return None, "status_not_in requires integer values"
        return (actual not in denied if actual is not None else None), f"status {actual!r} not in {sorted(denied)}"

    if kind in {"body_contains", "body_not_contains"}:
        needle = str(condition.get("value") or "")
        if not needle:
            return None, f"{kind} requires a non-empty value"
        hit = needle in _body(source)
        result = hit if kind == "body_contains" else not hit
        return result, f"{kind}: {needle[:80]!r}"

    if kind == "header_equals":
        name = str(condition.get("name") or "").lower()
        if not name:
            return None, "header_equals requires name"
        actual = _headers(source).get(name)
        expected = str(condition.get("value") or "")
        return (actual == expected if actual is not None else None), f"header {name}={actual!r} expected {expected!r}"

    if kind == "json_path_equals":
        ok, actual = _json_path(_body(source), str(condition.get("path") or ""))
        if not ok:
            return None, "JSON path not present"
        expected = condition.get("value")
        return actual == expected, f"json path value {actual!r} expected {expected!r}"

    if kind == "json_path_present":
        ok, _ = _json_path(_body(source), str(condition.get("path") or ""))
        return ok, f"json path present={ok}"

    if kind == "body_differs_from_baseline":
        if not _body(baseline) or not _body(mutation):
            return None, "baseline and mutation bodies are required"
        return snapshot_digest(baseline) != snapshot_digest(mutation), "mutation differs from baseline"

    if kind == "object_identity_equals":
        actual = source.get("object_identity") if isinstance(source, dict) else None
        expected = condition.get("value")
        return (actual == expected if actual is not None else None), f"object identity {actual!r} expected {expected!r}"

    if kind == "state_equals":
        actual = source.get("state") if isinstance(source, dict) else None
        expected = condition.get("value")
        return (actual == expected if actual is not None else None), f"state {actual!r} expected {expected!r}"

    if kind == "timing_delta_between":
        try:
            base_ms = float(baseline.get("elapsed_ms"))
            mutation_ms = float(mutation.get("elapsed_ms"))
            minimum = float(condition.get("min_ms"))
            maximum = float(condition.get("max_ms"))
        except (TypeError, ValueError, AttributeError):
            return None, "timing evidence/min/max missing"
        delta = mutation_ms - base_ms
        return minimum <= delta <= maximum, f"timing delta={delta:.1f}ms expected [{minimum}, {maximum}]"

    if kind == "controlled_artifact_manifest":
        manifest = mutation.get("manifest") if isinstance(mutation, dict) else None
        if not isinstance(manifest, dict):
            return None, "controlled artifact manifest missing"
        digest = str(manifest.get("artifact_sha256") or manifest.get("sha256") or "")
        required = (
            manifest.get("approved") is True,
            manifest.get("controlled") is True,
            manifest.get("reproduced") is True,
            len(digest) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in digest),
            bool(manifest.get("scope_reference")),
        )
        return all(required), "approved+controlled+reproduced artifact proof"

    # Deliberately no generic "HTTP status is live" condition. Liveness is an
    # observation and can never prove a vulnerability by itself.
    return None, f"unsupported assertion condition: {kind}"


@dataclass(frozen=True)
class AssertionResult:
    result: str
    assertion_passed: bool
    negative_control_passed: bool
    repeatability_passed: bool
    reasons: list[str]
    evaluated_at: str
    verifier_version: str = "tbhm-assertion-v1"

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate(assertion: dict, proof: dict, *, evidence_root=None) -> dict:
    """Evaluate a versioned assertion/proof bundle.

    Required proof objects:
      - baseline
      - mutation
      - negative_control
      - repeatability: attempts >= 2 and successful_proofs >= 2

    The assertion contains ``failure_conditions`` (all must pass) and optional
    ``negative_control_conditions`` (all must pass).  Missing evidence produces
    ``inconclusive``; a contradicted condition produces ``fail``.
    """
    if not isinstance(assertion, dict) or not isinstance(proof, dict):
        return AssertionResult("inconclusive", False, False, False,
                               ["assertion and proof must be objects"], _utcnow()).to_dict()
    if not str(assertion.get("test_id") or "").strip():
        return AssertionResult("inconclusive", False, False, False,
                               ["assertion.test_id is required"], _utcnow()).to_dict()
    from core.proof_contracts import verify_contract, ConfirmationReceipt
    from core.strict_classes_v424 import ControlHeld
    try:
        if evidence_root is None:
            raise ValueError("authenticated local capture root required")
        base_capture, mutation_capture, control_capture, repeat_captures = verify_contract(assertion, proof, evidence_root)
    except ControlHeld as exc:
        return AssertionResult("fail", False, True, True, [str(exc)], _utcnow(),
                               verifier_version="tbhm-proof-v2").to_dict()
    except (ValueError, KeyError, TypeError, OSError, AttributeError) as exc:
        return AssertionResult("inconclusive", False, False, False,
                               [str(exc)], _utcnow()).to_dict()
    baseline = base_capture["response"]
    mutation = mutation_capture["response"]
    negative = control_capture["response"]

    conditions = assertion.get("failure_conditions") or assertion.get("conditions") or []
    negative_conditions = assertion.get("negative_control_conditions") or []
    if not isinstance(conditions, list) or not conditions:
        return AssertionResult("inconclusive", False, False, False,
                               ["at least one failure condition is required"], _utcnow()).to_dict()
    if not isinstance(negative_conditions, list) or not negative_conditions:
        return AssertionResult("inconclusive", False, False, False,
                               ["at least one negative-control condition is required"], _utcnow()).to_dict()

    reasons: list[str] = []
    main_values: list[bool | None] = []
    for row in conditions[:50]:
        if not isinstance(row, dict):
            main_values.append(None); reasons.append("malformed failure condition"); continue
        value, detail = _condition(row, baseline=baseline, mutation=mutation, negative=negative)
        main_values.append(value); reasons.append(f"failure condition: {detail} -> {value}")

    negative_values: list[bool | None] = []
    for row in negative_conditions[:50]:
        if not isinstance(row, dict):
            negative_values.append(None); reasons.append("malformed negative-control condition"); continue
        value, detail = _condition(row, baseline=baseline, mutation=mutation, negative=negative)
        negative_values.append(value); reasons.append(f"negative control: {detail} -> {value}")

    repeat_ok = all(all(_condition(row, baseline=baseline, mutation=capture["response"], negative=negative)[0] is True
                               for row in conditions) for capture in repeat_captures)
    reasons.append(f"repeatability: {len(repeat_captures)} distinct authenticated captures -> {repeat_ok}")

    main_ok = bool(main_values) and all(v is True for v in main_values)
    negative_ok = bool(negative_values) and all(v is True for v in negative_values)
    any_unknown = any(v is None for v in main_values + negative_values)
    any_false = any(v is False for v in main_values + negative_values)

    if main_ok and negative_ok and repeat_ok:
        result = "pass"
    elif any_unknown:
        result = "inconclusive"
    elif any_false and negative_ok:
        result = "fail"
    elif not repeat_ok:
        result = "inconclusive"
    else:
        result = "inconclusive"
    assert result in _ALLOWED_RESULTS
    output = AssertionResult(result, main_ok, negative_ok, repeat_ok, reasons, _utcnow(),
                             verifier_version="tbhm-proof-v2").to_dict()
    if result == "pass":
        output["_confirmation_receipt"] = ConfirmationReceipt(verifier_version="tbhm-proof-v2", test_id=assertion["test_id"])
    return output


def confirmation_fields(assertion_result: dict, *, method: str, validation_attempt_id: int | None = None) -> dict:
    """Return explicit lifecycle fields without confusing proof failure with support.

    ``pass`` means the vulnerability assertion was proven. ``fail`` means the
    assertion was contradicted and the candidate is disproved. ``inconclusive``
    means evidence was insufficient; callers should normally preserve the prior
    candidate class and record only the latest validation outcome.
    """
    result = str(assertion_result.get("result") or "inconclusive")
    from core.proof_contracts import ConfirmationReceipt
    passed = result == "pass" and isinstance(assertion_result.get("_confirmation_receipt"), ConfirmationReceipt)
    fields = {
        "verified": passed,
        "verification_method": method,
        "verified_at": _utcnow() if passed else None,
        "assertion_passed": bool(assertion_result.get("assertion_passed")),
        "negative_control_passed": bool(assertion_result.get("negative_control_passed")),
        "repeatability_passed": bool(assertion_result.get("repeatability_passed")),
        "validation_attempt_id": validation_attempt_id,
        "verification_state": "confirmed" if passed else ("disproved" if result == "fail" else "inconclusive"),
    }
    if passed:
        fields["_confirmation_receipt"] = assertion_result["_confirmation_receipt"]
        fields["finding_class"] = "confirmed"
    elif result == "fail":
        fields["finding_class"] = "lead"
    return fields

