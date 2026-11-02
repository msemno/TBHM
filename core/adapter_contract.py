"""Common adapter contract for new TBHM integrations (v3.9.5).

The contract makes capability claims testable.  An adapter must describe its
execution mode, version check, inputs, bounded command, raw evidence and parser.
High-risk/approval-only adapters cannot be executed by this wrapper.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

SAFE_EXECUTION_MODES = {"safe_cli", "library", "feed"}


@dataclass(frozen=True)
class AdapterSpec:
    adapter_id: str
    tool: str
    integration_mode: str
    evidence_formats: tuple[str, ...] = ()
    timeout_s: int = 300
    read_only: bool = True
    requires_approval_action: str = ""


@dataclass
class AdapterResult:
    adapter_id: str
    status: str
    command: list[str] = field(default_factory=list)
    return_code: int | None = None
    raw_evidence: list[str] = field(default_factory=list)
    normalized_count: int = 0
    detail: str = ""
    provenance: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "adapter_id": self.adapter_id, "status": self.status,
            "command": self.command, "return_code": self.return_code,
            "raw_evidence": self.raw_evidence,
            "normalized_count": self.normalized_count,
            "detail": self.detail, "provenance": self.provenance,
        }


def binary_provenance(tool: str) -> dict:
    path = shutil.which(tool)
    if not path:
        return {"tool": tool, "installed": False}
    p = Path(path)
    sha = ""
    try:
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        sha = h.hexdigest()
    except Exception:
        pass
    return {"tool": tool, "installed": True, "path": str(p), "sha256": sha}


def validate_spec(spec: AdapterSpec) -> list[str]:
    errors = []
    if not spec.adapter_id or not spec.tool:
        errors.append("adapter_id and tool are required")
    if spec.integration_mode not in {
        "safe_cli", "library", "feed", "approval_cli", "approval_only",
        "import_only", "service_or_manual",
    }:
        errors.append("unknown integration_mode")
    if spec.timeout_s < 1 or spec.timeout_s > 7200:
        errors.append("timeout must be between 1 and 7200 seconds")
    if spec.integration_mode in SAFE_EXECUTION_MODES and not spec.read_only:
        errors.append("safe execution modes must be read-only")
    if spec.integration_mode == "approval_cli" and not spec.requires_approval_action:
        errors.append("approval_cli requires an approval action")
    return errors


def write_result(path: str | Path, result: AdapterResult) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8")
