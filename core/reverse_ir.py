"""Universal reverse-engineering intermediate representation for TBHM.

The schema intentionally keeps the common denominator across Ghidra high P-code,
IDA/Radare2 exports, and angr CFG data while preserving backend-specific fields.
It is evidence, not a claim that the decompiler recovered source perfectly.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "tbhm.reverse-ir/1.0"
_ADDR_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{4,16})$")


def parse_address(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 0)
    except Exception:
        m = _ADDR_RE.search(text)
        if not m:
            return None
        try:
            return int(m.group(1), 16)
        except Exception:
            return None


def address_text(value: Any) -> str:
    parsed = parse_address(value)
    return hex(parsed) if parsed is not None else str(value or "")


def _json_load(path_or_data: str | Path | dict) -> dict:
    if isinstance(path_or_data, dict):
        return path_or_data
    path = Path(path_or_data)
    data = json.loads(path.read_text(errors="ignore"))
    return data if isinstance(data, dict) else {"raw": data}


def _stable_list(values: Iterable[Any]) -> list:
    seen, out = set(), []
    for value in values:
        key = json.dumps(value, sort_keys=True, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def _function_common(item: dict, backend: str) -> dict:
    start = parse_address(item.get("address") or item.get("offset") or item.get("start") or item.get("entry"))
    end = parse_address(item.get("end") or item.get("max_address"))
    size = item.get("size") or item.get("realsz") or item.get("length") or 0
    try:
        size = max(0, int(size))
    except Exception:
        size = 0
    if end is None and start is not None and size:
        end = start + size
    return {
        "id": str(item.get("id") or (f"fn:{start:x}" if start is not None else f"fn:{item.get('name','unknown')}")),
        "name": str(item.get("name") or item.get("demangled_name") or item.get("label") or "unknown"),
        "start": hex(start) if start is not None else "",
        "end": hex(end) if end is not None else "",
        "size": size,
        "external": bool(item.get("external") or item.get("is_external")),
        "thunk": bool(item.get("thunk") or item.get("is_thunk")),
        "calling_convention": str(item.get("calling_convention") or item.get("cc") or ""),
        "return_type": str(item.get("return_type") or item.get("ret_type") or ""),
        "parameters": item.get("parameters") if isinstance(item.get("parameters"), list) else [],
        "locals": item.get("locals") if isinstance(item.get("locals"), list) else [],
        "calls": _stable_list(item.get("calls") or item.get("callees") or []),
        "callers": _stable_list(item.get("callers") or []),
        "strings": _stable_list(item.get("strings") or item.get("string_refs") or []),
        "globals": _stable_list(item.get("globals") or item.get("global_refs") or []),
        "basic_blocks": item.get("basic_blocks") if isinstance(item.get("basic_blocks"), list) else [],
        "pcode": item.get("pcode") if isinstance(item.get("pcode"), list) else [],
        "decompiled_c": str(item.get("decompiled_c") or item.get("decompile") or item.get("pseudocode") or ""),
        "backend": backend,
        "backend_fields": {k: v for k, v in item.items() if k not in {
            "id", "name", "demangled_name", "label", "address", "offset", "start", "entry", "end",
            "max_address", "size", "realsz", "length", "external", "is_external", "thunk", "is_thunk",
            "calling_convention", "cc", "return_type", "ret_type", "parameters", "locals", "calls", "callees",
            "callers", "strings", "string_refs", "globals", "global_refs", "basic_blocks", "pcode",
            "decompiled_c", "decompile", "pseudocode"
        }},
    }


def normalize_ghidra(data: dict) -> dict:
    functions = [_function_common(row, "ghidra") for row in data.get("functions", []) if isinstance(row, dict)]
    return {
        "schema": SCHEMA,
        "backend": "ghidra",
        "artifact": {
            "path": str(data.get("path") or data.get("program") or ""),
            "name": str(data.get("program") or data.get("name") or ""),
            "sha256": str(data.get("sha256") or ""),
            "architecture": str(data.get("architecture") or data.get("language") or ""),
            "compiler": str(data.get("compiler") or ""),
            "image_base": address_text(data.get("image_base")),
            "endianness": str(data.get("endianness") or ""),
            "format": str(data.get("format") or ""),
        },
        "functions": functions,
        "imports": data.get("imports", []) if isinstance(data.get("imports"), list) else [],
        "exports": data.get("exports", []) if isinstance(data.get("exports"), list) else [],
        "strings": data.get("strings", []) if isinstance(data.get("strings"), list) else [],
        "types": data.get("types", []) if isinstance(data.get("types"), list) else [],
        "metadata": {"source_schema": str(data.get("schema") or "ghidra-native")},
    }


def normalize_r2(data: dict, backend: str = "radare2") -> dict:
    outputs = data.get("outputs") if isinstance(data.get("outputs"), dict) else {}
    raw_functions = data.get("functions") if isinstance(data.get("functions"), list) else []
    if not raw_functions:
        raw_functions = ((outputs.get("functions") or {}).get("data") or [])
    functions = []
    for row in raw_functions:
        if not isinstance(row, dict):
            continue
        calls = []
        callrefs = row.get("callrefs") if isinstance(row.get("callrefs"), list) else []
        for ref in callrefs:
            if isinstance(ref, dict):
                calls.append({"address": address_text(ref.get("addr")), "type": ref.get("type", "call")})
        merged = dict(row)
        merged["calls"] = calls or row.get("calls") or []
        functions.append(_function_common(merged, backend))
    imports = data.get("imports") if isinstance(data.get("imports"), list) else []
    if not imports:
        imports = ((outputs.get("imports") or {}).get("data") or [])
    strings = data.get("strings") if isinstance(data.get("strings"), list) else []
    if not strings:
        strings = ((outputs.get("strings") or {}).get("data") or [])
    return {
        "schema": SCHEMA,
        "backend": backend,
        "artifact": {
            "path": str(data.get("binary") or ""),
            "name": Path(str(data.get("binary") or "artifact")).name,
            "sha256": str(data.get("artifact_id") or "").removeprefix("sha256:"),
            "architecture": "",
            "image_base": "",
        },
        "functions": functions,
        "imports": imports,
        "exports": [],
        "strings": strings,
        "types": [],
        "metadata": {"source_schema": f"{backend}-json"},
    }


def normalize_angr(data: dict) -> dict:
    functions = [_function_common(row, "angr") for row in data.get("functions", []) if isinstance(row, dict)]
    return {
        "schema": SCHEMA,
        "backend": "angr",
        "artifact": {
            "path": str(data.get("binary") or ""),
            "name": Path(str(data.get("binary") or "artifact")).name,
            "sha256": str(data.get("sha256") or ""),
            "architecture": str(data.get("architecture") or ""),
            "image_base": address_text(data.get("image_base")),
            "entry": address_text(data.get("entry")),
        },
        "functions": functions,
        "imports": data.get("imports", []) if isinstance(data.get("imports"), list) else [],
        "exports": [],
        "strings": [],
        "types": [],
        "metadata": {"source_schema": "angr"},
    }


def normalize(path_or_data: str | Path | dict, backend_hint: str = "") -> dict:
    data = _json_load(path_or_data)
    if data.get("schema") == SCHEMA:
        return data
    backend = (backend_hint or str(data.get("tool") or data.get("backend") or "")).lower()
    if "ghidra" in backend or any("pcode" in row for row in data.get("functions", []) if isinstance(row, dict)):
        return normalize_ghidra(data)
    if backend in {"r2", "radare2", "rizin"} or isinstance(data.get("outputs"), dict):
        return normalize_r2(data, "rizin" if "rizin" in backend else "radare2")
    if "angr" in backend or "architecture" in data and "entry" in data:
        return normalize_angr(data)
    functions = [_function_common(row, backend or "generic") for row in data.get("functions", []) if isinstance(row, dict)]
    return {
        "schema": SCHEMA, "backend": backend or "generic", "artifact": data.get("artifact", {}),
        "functions": functions, "imports": data.get("imports", []), "exports": data.get("exports", []),
        "strings": data.get("strings", []), "types": data.get("types", []), "metadata": {"source_schema": "generic"},
    }


def function_fingerprint(function: dict) -> str:
    pcode = []
    for op in function.get("pcode", []) if isinstance(function.get("pcode"), list) else []:
        if not isinstance(op, dict):
            continue
        pcode.append({
            "mnemonic": op.get("mnemonic") or op.get("opcode") or "",
            "inputs": [str(x.get("space") or x.get("kind") or "") if isinstance(x, dict) else "" for x in op.get("inputs", [])],
            "output": str((op.get("output") or {}).get("space") or "") if isinstance(op.get("output"), dict) else "",
            "callee": str(op.get("callee") or ""),
        })
    body = {
        "pcode": pcode,
        "calls": sorted(str(x.get("name") or x.get("address") or x) if isinstance(x, dict) else str(x)
                        for x in function.get("calls", [])),
        "strings": sorted(str(x.get("value") or x) if isinstance(x, dict) else str(x)
                          for x in function.get("strings", [])),
        "parameters": [str(x.get("type") or x.get("datatype") or "") if isinstance(x, dict) else str(x)
                       for x in function.get("parameters", [])],
        "size": int(function.get("size") or 0),
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def add_fingerprints(ir: dict) -> dict:
    for function in ir.get("functions", []):
        if isinstance(function, dict):
            function["fingerprint"] = function_fingerprint(function)
    return ir


@dataclass(frozen=True)
class FunctionRange:
    start: int
    end: int
    name: str
    function_id: str
    artifact: str = ""


def function_ranges(ir: dict) -> list[FunctionRange]:
    ranges: list[FunctionRange] = []
    artifact = str((ir.get("artifact") or {}).get("path") or "")
    for fn in ir.get("functions", []):
        if not isinstance(fn, dict):
            continue
        start = parse_address(fn.get("start"))
        if start is None:
            continue
        end = parse_address(fn.get("end"))
        if end is None or end <= start:
            end = start + max(1, int(fn.get("size") or 1))
        ranges.append(FunctionRange(start, end, str(fn.get("name") or "unknown"), str(fn.get("id") or ""), artifact))
    return sorted(ranges, key=lambda x: (x.start, x.end))


def find_function(ir: dict, address: int) -> FunctionRange | None:
    for row in function_ranges(ir):
        if row.start <= address < row.end:
            return row
    return None


def save(ir: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(add_fingerprints(ir), indent=2, ensure_ascii=False), encoding="utf-8")
    return path
