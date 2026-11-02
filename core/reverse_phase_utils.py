"""Shared helpers for TBHM deep reverse phases."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Iterable

from core import reverse_ir as RIR


def candidate_ir_paths(output: str | Path, supplied: Iterable[str | Path] = ()) -> list[Path]:
    output = Path(output)
    candidates: list[Path] = []
    static = output / "redteam" / "25b_reverse_static_analysis"
    if static.is_dir():
        candidates.extend(static.glob("*.tbhm-ir.json"))
    for raw in supplied:
        if not raw:
            continue
        path = Path(raw).expanduser()
        if path.is_file():
            candidates.append(path)
        elif path.is_dir():
            candidates.extend(path.rglob("*.tbhm-ir.json"))
            candidates.extend(path.rglob("*.ghidra.json"))
            candidates.extend(path.rglob("*.r2.json"))
            candidates.extend(path.rglob("*.rizin.json"))
            candidates.extend(path.rglob("*.angr.json"))
    seen, result = set(), []
    for path in candidates:
        try:
            resolved = path.resolve()
        except Exception:
            continue
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        result.append(path)
    return sorted(result)


def load_ir_documents(output: str | Path, supplied: Iterable[str | Path] = ()) -> list[tuple[Path, dict]]:
    documents = []
    for path in candidate_ir_paths(output, supplied):
        try:
            data = json.loads(path.read_text(errors="ignore"))
            ir = data if data.get("schema") == RIR.SCHEMA else RIR.normalize(data)
            RIR.add_fingerprints(ir)
            documents.append((path, ir))
        except Exception:
            continue
    return documents


def write_json(path: str | Path, payload: dict | list) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
