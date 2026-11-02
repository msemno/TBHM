"""Map imported runtime addresses/events to normalized reverse-IR functions.

The mapper supports absolute addresses and common ASLR/module-base evidence.  A
runtime address is rebased to the IR image base only when the event supplies a
module base and the module can be associated with one normalized artifact.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from core.reverse_ir import function_ranges, parse_address

ADDRESS_KEYS = {"address", "addr", "pc", "rip", "eip", "ip", "instruction_pointer", "callsite"}
RELATIVE_KEYS = {"offset", "rva", "module_offset", "relative_address"}
BASE_KEYS = {"module_base", "base_address", "load_address", "runtime_base", "image_runtime_base"}
MODULE_KEYS = {"module", "module_name", "image", "binary", "library", "dll", "executable", "path"}
LINE_ADDR_RE = re.compile(r"(?:\b(?:pc|rip|eip|ip|addr(?:ess)?)\s*[=:]\s*)?(0x[0-9a-fA-F]{4,16})")


def _walk(value: Any, path: str = "") -> Iterable[tuple[str, Any, dict]]:
    if isinstance(value, dict):
        yield path, value, value
        for key, child in value.items():
            yield from _walk(child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}/{index}")


def _value_for_keys(record: dict, keys: set[str]):
    for key, value in record.items():
        if str(key).lower() in keys:
            return value
    return None


def _addresses_from_record(record: dict) -> list[tuple[str, int]]:
    out = []
    for key, value in record.items():
        low = str(key).lower()
        if low in ADDRESS_KEYS:
            addr = parse_address(value)
            if addr is not None:
                out.append((str(key), addr))
        if isinstance(value, str) and low not in BASE_KEYS | RELATIVE_KEYS | MODULE_KEYS:
            for match in LINE_ADDR_RE.finditer(value):
                addr = parse_address(match.group(1))
                if addr is not None:
                    out.append((str(key), addr))
    seen = set()
    return [(key, addr) for key, addr in out if not ((key, addr) in seen or seen.add((key, addr)))]


def _module_catalog(ir_documents: list[dict]) -> list[dict]:
    rows = []
    for ir in ir_documents:
        artifact = ir.get("artifact") if isinstance(ir.get("artifact"), dict) else {}
        path = str(artifact.get("path") or artifact.get("name") or "")
        name = str(artifact.get("name") or Path(path).name or "")
        base = parse_address(artifact.get("image_base"))
        rows.append({"ir": ir, "path": path, "name": name, "basename": Path(path).name,
                     "image_base": base if base is not None else 0})
    return rows


def _select_modules(record: dict, modules: list[dict]) -> list[dict]:
    raw = _value_for_keys(record, MODULE_KEYS)
    if raw:
        needle = Path(str(raw)).name.lower()
        matches = [row for row in modules if needle in {row["name"].lower(), row["basename"].lower()}
                   or row["path"].lower().endswith(needle)]
        if matches:
            return matches
    return modules if len(modules) == 1 else []


def _candidate_addresses(record: dict, modules: list[dict]) -> list[dict]:
    selected = _select_modules(record, modules)
    runtime_base = parse_address(_value_for_keys(record, BASE_KEYS))
    raw_addresses = _addresses_from_record(record)
    # When an event supplies a runtime module base and an identifiable module,
    # the raw PC is an ASLR address rather than a static address. Avoid emitting
    # a duplicate expected-unmapped record for it.
    candidates = [] if (runtime_base is not None and selected) else [
        {"address": addr, "address_key": key, "resolution": "absolute"}
        for key, addr in raw_addresses
    ]
    relative = parse_address(_value_for_keys(record, RELATIVE_KEYS))
    if relative is not None:
        for module in selected:
            candidates.append({"address": module["image_base"] + relative, "address_key": "relative",
                               "resolution": "module_relative", "runtime_base": runtime_base,
                               "module": module["path"], "relative_offset": relative})
    if runtime_base is not None:
        for key, raw in raw_addresses:
            if raw < runtime_base:
                continue
            offset = raw - runtime_base
            for module in selected:
                candidates.append({"address": module["image_base"] + offset, "address_key": key,
                                   "resolution": "aslr_rebased", "runtime_address": raw,
                                   "runtime_base": runtime_base, "module": module["path"],
                                   "relative_offset": offset})
    seen, out = set(), []
    for candidate in candidates:
        key = (candidate["address"], candidate.get("resolution"), candidate.get("module", ""))
        if key not in seen:
            seen.add(key); out.append(candidate)
    return out


def map_events(ir_documents: list[dict], dynamic_documents: list[dict]) -> dict:
    ranges = []
    for ir in ir_documents:
        ranges.extend(function_ranges(ir))
    modules = _module_catalog(ir_documents)
    mapped, unmapped = [], []
    seen_events = set()
    for doc_index, document in enumerate(dynamic_documents):
        for path, record, _parent in _walk(document):
            if not isinstance(record, dict):
                continue
            for candidate in _candidate_addresses(record, modules):
                address = candidate["address"]
                matches = [row for row in ranges if row.start <= address < row.end and
                           (not candidate.get("module") or Path(row.artifact).name == Path(candidate["module"]).name)]
                event = {"document": doc_index, "json_path": path, "address": hex(address),
                         "record": record, **{k: v for k, v in candidate.items() if k != "address"}}
                identity = (doc_index, path, address, candidate.get("resolution"), candidate.get("module", ""))
                if identity in seen_events:
                    continue
                seen_events.add(identity)
                if matches:
                    best = min(matches, key=lambda row: row.end - row.start)
                    mapped.append({**event, "function": best.name, "function_id": best.function_id,
                                   "function_start": hex(best.start), "offset_in_function": address - best.start,
                                   "artifact": best.artifact})
                else:
                    unmapped.append(event)
    return {
        "schema": "tbhm.dynamic-map/1.1", "mapped_events": mapped, "unmapped_events": unmapped,
        "counts": {"function_ranges": len(ranges), "modules": len(modules), "mapped": len(mapped), "unmapped": len(unmapped),
                   "rebased": sum(row.get("resolution") == "aslr_rebased" for row in mapped)},
        "limitations": [
            "Module rebasing requires module identity and runtime-base metadata when multiple artifacts are present.",
            "JIT code and dynamically generated code cannot be mapped to static IR without an additional code map.",
        ],
    }


def load_json_documents(path: str | Path) -> list[dict]:
    root = Path(path)
    files = [root] if root.is_file() else list(root.rglob("*.json")) + list(root.rglob("*.jsonl")) if root.is_dir() else []
    docs = []
    for file in files:
        try:
            if file.suffix.lower() == ".jsonl":
                docs.extend(json.loads(line) for line in file.read_text(errors="ignore").splitlines() if line.strip())
            else:
                value = json.loads(file.read_text(errors="ignore"))
                docs.append(value if isinstance(value, dict) else {"items": value})
        except Exception:
            continue
    return docs
