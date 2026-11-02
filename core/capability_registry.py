"""Central, truthful capability registry for TBHM v3.9.7.5.

The registry separates *what is described* from *what can run in this environment*.
Registration never implies availability, authorization, or execution.  Runtime
checks are deterministic and never expose environment-variable values.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = ROOT / "tooling" / "capability_registry_v420.json"

IMPLEMENTATION_STATES = {"native", "adapter", "import_only", "proposal_only", "planned", "unavailable"}
EXECUTION_MODES = {"observe", "analyze", "plan", "verify", "import", "execute_read_only"}
SAFETY_CLASSES = {"passive", "read_only", "controlled", "sensitive_import", "proposal_only", "unavailable"}
_REQUIRED = {
    "capability_id", "name", "description", "domain", "action_class",
    "implementation_state", "execution_mode", "safety_class",
    "approval_required", "network_access", "external_tools",
    "python_dependencies", "supported_platforms", "input_schema",
    "output_schema", "evidence_types", "phase_association",
    "configuration_keys", "documentation_reference", "enabled_by_default",
    "failure_behavior",
}


@dataclass(frozen=True)
class CapabilityAvailability:
    capability_id: str
    available: bool
    implementation_state: str
    reasons: tuple[str, ...]
    missing_executables: tuple[str, ...]
    missing_python_dependencies: tuple[str, ...]
    missing_environment_variables: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "capability_id": self.capability_id,
            "available": self.available,
            "implementation_state": self.implementation_state,
            "reasons": list(self.reasons),
            "missing_executables": list(self.missing_executables),
            "missing_python_dependencies": list(self.missing_python_dependencies),
            "missing_environment_variables": list(self.missing_environment_variables),
        }


def load(path: str | Path | None = None) -> dict:
    source = Path(path) if path else DEFAULT_PATH
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("capabilities"), list):
        raise ValueError("capability registry must contain a capabilities list")
    errors = validate_registry(data)
    if errors:
        raise ValueError("invalid capability registry: " + "; ".join(errors[:20]))
    return data


def validate_registry(data: dict) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for idx, row in enumerate(data.get("capabilities", [])):
        if not isinstance(row, dict):
            errors.append(f"capabilities[{idx}] must be an object")
            continue
        missing = sorted(_REQUIRED - set(row))
        if missing:
            errors.append(f"capabilities[{idx}] missing: {', '.join(missing)}")
        cid = str(row.get("capability_id") or "").strip()
        if not cid:
            errors.append(f"capabilities[{idx}] has empty capability_id")
        elif cid in seen:
            errors.append(f"duplicate capability_id: {cid}")
        seen.add(cid)
        if row.get("implementation_state") not in IMPLEMENTATION_STATES:
            errors.append(f"{cid}: invalid implementation_state")
        if row.get("execution_mode") not in EXECUTION_MODES:
            errors.append(f"{cid}: invalid execution_mode")
        if row.get("safety_class") not in SAFETY_CLASSES:
            errors.append(f"{cid}: invalid safety_class")
        for key in ("external_tools", "python_dependencies", "supported_platforms", "evidence_types", "phase_association", "configuration_keys"):
            if key in row and not isinstance(row[key], list):
                errors.append(f"{cid}: {key} must be a list")
        if row.get("implementation_state") in {"planned", "unavailable"} and row.get("enabled_by_default"):
            errors.append(f"{cid}: planned/unavailable capability cannot be enabled by default")
    return errors


def by_id(registry: dict) -> dict[str, dict]:
    return {str(row["capability_id"]): row for row in registry.get("capabilities", [])}


def _platform_supported(platforms: Iterable[str], current: str | None = None) -> bool:
    current = (current or os.sys.platform).lower()
    normalized = {str(x).lower() for x in platforms}
    if not normalized or "any" in normalized:
        return True
    if current.startswith("linux"):
        return "linux" in normalized
    if current.startswith("win"):
        return "windows" in normalized
    if current.startswith("darwin"):
        return "macos" in normalized or "darwin" in normalized
    return current in normalized


def availability(row: dict, *, environ: dict[str, str] | None = None, platform: str | None = None) -> CapabilityAvailability:
    environ = environ if environ is not None else os.environ
    state = str(row.get("implementation_state") or "unavailable")
    missing_exec = tuple(sorted(x for x in row.get("external_tools", []) if x and shutil.which(str(x)) is None))
    missing_py = tuple(sorted(x for x in row.get("python_dependencies", []) if x and importlib.util.find_spec(str(x)) is None))
    required_env = [str(x) for x in row.get("required_environment_variables", []) if str(x)]
    missing_env = tuple(sorted(x for x in required_env if not str(environ.get(x, "")).strip()))
    reasons: list[str] = []
    if state in {"planned", "unavailable"}:
        reasons.append(f"implementation_state={state}")
    if not _platform_supported(row.get("supported_platforms", []), platform):
        reasons.append("unsupported platform")
    if missing_exec:
        reasons.append("missing executable(s): " + ", ".join(missing_exec))
    if missing_py:
        reasons.append("missing Python dependency/dependencies: " + ", ".join(missing_py))
    if missing_env:
        reasons.append("missing environment variable(s): " + ", ".join(missing_env))
    # Import/proposal capabilities are available when their native normalizer or
    # generator exists; they do not require the represented external product.
    available = not reasons
    return CapabilityAvailability(
        capability_id=str(row.get("capability_id") or ""),
        available=available,
        implementation_state=state,
        reasons=tuple(reasons),
        missing_executables=missing_exec,
        missing_python_dependencies=missing_py,
        missing_environment_variables=missing_env,
    )


def summary(registry: dict, *, capability_ids: Iterable[str] | None = None) -> dict:
    wanted = {str(x) for x in (capability_ids or []) if str(x)}
    rows = []
    counts: dict[str, int] = {}
    for row in registry.get("capabilities", []):
        if wanted and row.get("capability_id") not in wanted:
            continue
        status = availability(row).as_dict()
        merged = {**row, "runtime": status}
        rows.append(merged)
        key = str(row.get("implementation_state") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return {
        "registry_version": registry.get("registry_version"),
        "capabilities": rows,
        "counts_by_implementation_state": dict(sorted(counts.items())),
        "available_now": sum(1 for row in rows if row["runtime"]["available"]),
        "registered": len(rows),
        "policy": registry.get("policy", {}),
    }
