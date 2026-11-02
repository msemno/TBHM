"""Bounded interprocedural taint analysis over TBHM's normalized reverse IR.

The engine computes function summaries to a fixed point, propagates parameter and
source labels through high P-code-like operations, follows direct calls, records
sanitizers, and emits explainable source-to-sink paths. Indirect calls and
unresolved memory aliases remain explicit uncertainty rather than false proof.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import re
from typing import Any

from core.reverse_ir import parse_address

DEFAULT_KB = {
    "sources": {
        "recv": "network", "recvfrom": "network", "read": "file_or_stream", "fread": "file",
        "getenv": "environment", "cgiFormString": "http_parameter", "websGetVar": "http_parameter",
        "mg_get_var": "http_parameter", "FCGX_GetParam": "http_parameter", "accept": "network",
        "GetEnvironmentVariableA": "environment", "GetEnvironmentVariableW": "environment",
        "ReadFile": "file_or_device", "InternetReadFile": "network", "RegQueryValueExA": "registry",
        "RegQueryValueExW": "registry", "DeviceIoControl": "ioctl_input", "copy_from_user": "user_pointer",
    },
    "sinks": {
        "system": ("command_execution", "CWE-78"), "popen": ("command_execution", "CWE-78"),
        "execl": ("command_execution", "CWE-78"), "execve": ("command_execution", "CWE-78"),
        "CreateProcessA": ("command_execution", "CWE-78"), "CreateProcessW": ("command_execution", "CWE-78"),
        "WinExec": ("command_execution", "CWE-78"), "ShellExecuteA": ("command_execution", "CWE-78"),
        "strcpy": ("memory_copy", "CWE-120"), "strcat": ("memory_copy", "CWE-120"),
        "sprintf": ("format_or_copy", "CWE-120"), "vsprintf": ("format_or_copy", "CWE-120"),
        "memcpy": ("memory_copy", "CWE-119"), "memmove": ("memory_copy", "CWE-119"),
        "printf": ("format_string", "CWE-134"), "syslog": ("format_string", "CWE-134"),
        "open": ("path_access", "CWE-22"), "fopen": ("path_access", "CWE-22"),
        "unlink": ("path_access", "CWE-22"), "remove": ("path_access", "CWE-22"),
        "dlopen": ("dynamic_loading", "CWE-114"), "LoadLibraryA": ("dynamic_loading", "CWE-114"),
        "LoadLibraryW": ("dynamic_loading", "CWE-114"), "eval": ("code_execution", "CWE-95"),
        "pickle.loads": ("deserialization", "CWE-502"), "yaml.load": ("deserialization", "CWE-502"),
        "sqlite3_exec": ("sql", "CWE-89"), "mysql_query": ("sql", "CWE-89"),
        "copy_to_user": ("kernel_data_exposure", "CWE-200"), "request_firmware": ("firmware_loading", "CWE-494"),
    },
    "sanitizers": {
        "realpath", "canonicalize_file_name", "basename", "dirname", "strtol", "strtoul", "atoi",
        "snprintf", "vsnprintf", "html_escape", "url_encode", "shell_escape", "validate", "sanitize",
        "PathCchCanonicalize", "GetFullPathNameA", "GetFullPathNameW",
    },
}

# Source APIs often return a byte count while writing attacker-controlled data
# through one or more pointer arguments.  The argument indexes below are indexes
# after the call-target varnode has been removed.
SOURCE_ARG_MODELS = {
    "recv": (1,), "recvfrom": (1,), "read": (1,), "fread": (0,),
    "ReadFile": (1,), "InternetReadFile": (1,), "FCGX_GetStr": (0,),
    "cgiFormString": (1,), "websGetVar": (), "mg_get_var": (),
    "DeviceIoControl": (5,), "copy_from_user": (0,),
}

PROPAGATE_OPS = {
    "COPY", "CAST", "MULTIEQUAL", "INDIRECT", "PIECE", "SUBPIECE", "INT_ADD", "INT_SUB", "INT_MULT",
    "PTRADD", "PTRSUB", "LOAD", "STORE", "INT_ZEXT", "INT_SEXT", "BOOL_NEGATE", "INT_AND", "INT_OR",
    "INT_XOR", "FLOAT_FLOAT2FLOAT", "FLOAT_INT2FLOAT", "FLOAT_TRUNC", "CBRANCH", "RETURN",
}


def _name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or value.get("callee") or value.get("label") or value.get("address") or "")
    return str(value or "")


def _var_id(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return str(value.get("id") or value.get("key") or value.get("repr") or value.get("address") or value.get("value") or "")
    return str(value)


def _call_name(op: dict, functions_by_addr: dict[int, str]) -> str:
    explicit = str(op.get("callee") or op.get("call_name") or "")
    if explicit:
        explicit_addr = parse_address(explicit)
        if explicit_addr is not None and explicit_addr in functions_by_addr:
            return functions_by_addr[explicit_addr]
        return explicit
    inputs = op.get("inputs") if isinstance(op.get("inputs"), list) else []
    if not inputs:
        return ""
    first = inputs[0]
    addr = parse_address(first.get("value") if isinstance(first, dict) else first)
    return functions_by_addr.get(addr, address_name(addr)) if addr is not None else _name(first)


def address_name(addr: int | None) -> str:
    return f"sub_{addr:x}" if addr is not None else "unknown"


@dataclass
class Flow:
    source: str
    sink: str
    cwe: str
    function: str
    call_path: list[str]
    source_op: str = ""
    sink_op: str = ""
    variable: str = ""
    sanitized: bool = False
    sanitizer: str = ""
    uncertainty: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source, "sink": self.sink, "cwe": self.cwe, "function": self.function,
            "call_path": self.call_path, "source_op": self.source_op, "sink_op": self.sink_op,
            "variable": self.variable, "sanitized": self.sanitized, "sanitizer": self.sanitizer,
            "uncertainty": self.uncertainty,
            "confirmation_state": "static_path_supported" if not self.sanitized else "sanitized_path_observed",
        }


@dataclass
class Summary:
    return_from_params: set[int] = field(default_factory=set)
    source_returns: set[str] = field(default_factory=set)
    sink_from_params: list[dict] = field(default_factory=list)
    direct_flows: list[Flow] = field(default_factory=list)
    unresolved_calls: set[str] = field(default_factory=set)

    def stable(self) -> tuple:
        return (
            tuple(sorted(self.return_from_params)), tuple(sorted(self.source_returns)),
            tuple(sorted(json.dumps(x, sort_keys=True) for x in self.sink_from_params)),
            tuple(sorted(json.dumps(x.to_dict(), sort_keys=True) for x in self.direct_flows)),
            tuple(sorted(self.unresolved_calls)),
        )


class IRTaintAnalyzer:
    def __init__(self, ir: dict, kb: dict | None = None, max_iterations: int = 20):
        self.ir = ir
        self.kb = kb or DEFAULT_KB
        self.max_iterations = max(1, min(max_iterations, 100))
        self.functions = [x for x in ir.get("functions", []) if isinstance(x, dict)]
        self.by_name = {str(x.get("name") or ""): x for x in self.functions if x.get("name")}
        self.by_addr = {}
        for fn in self.functions:
            addr = parse_address(fn.get("start"))
            if addr is not None:
                self.by_addr[addr] = str(fn.get("name") or address_name(addr))
        self.summaries: dict[str, Summary] = {str(fn.get("name") or "unknown"): Summary() for fn in self.functions}

    def analyze(self) -> dict:
        iterations = 0
        changed = True
        while changed and iterations < self.max_iterations:
            changed = False
            iterations += 1
            for fn in self.functions:
                name = str(fn.get("name") or "unknown")
                before = self.summaries[name].stable()
                self.summaries[name] = self._analyze_function(fn)
                if self.summaries[name].stable() != before:
                    changed = True
        flows = []
        unresolved = set()
        for summary in self.summaries.values():
            flows.extend(flow.to_dict() for flow in summary.direct_flows)
            unresolved.update(summary.unresolved_calls)
        dedup = {}
        for flow in flows:
            key = json.dumps(flow, sort_keys=True)
            dedup[key] = flow
        return {
            "schema": "tbhm.taint/1.0", "engine": "ir-fixed-point", "iterations": iterations,
            "functions_analyzed": len(self.functions), "flows": list(dedup.values()),
            "function_summaries": {
                name: {
                    "return_from_params": sorted(summary.return_from_params),
                    "source_returns": sorted(summary.source_returns),
                    "sink_from_params": summary.sink_from_params,
                    "unresolved_calls": sorted(summary.unresolved_calls),
                } for name, summary in self.summaries.items()
            },
            "unresolved_calls": sorted(unresolved),
            "limitations": [
                "Indirect calls without a resolved target remain unresolved.",
                "Pointer aliasing is conservative and field-insensitive.",
                "Static reachability does not prove runtime exploitability.",
            ],
        }

    def _analyze_function(self, fn: dict) -> Summary:
        name = str(fn.get("name") or "unknown")
        summary = Summary()
        taint: dict[str, set[str]] = {}
        memory: dict[str, set[str]] = {}
        sanitized: dict[str, str] = {}
        params = fn.get("parameters") if isinstance(fn.get("parameters"), list) else []
        for index, param in enumerate(params):
            var = _var_id(param) or f"param:{index}"
            taint[var] = {f"param:{index}"}
        pcode = fn.get("pcode") if isinstance(fn.get("pcode"), list) else []
        for op in pcode:
            if not isinstance(op, dict):
                continue
            mnemonic = str(op.get("mnemonic") or op.get("opcode") or "").upper()
            inputs = op.get("inputs") if isinstance(op.get("inputs"), list) else []
            output = _var_id(op.get("output"))
            input_labels = set()
            for value in inputs:
                input_labels.update(taint.get(_var_id(value), set()))
            if mnemonic in {"CALL", "CALLIND", "CALLOTHER"}:
                callee = _call_name(op, self.by_addr)
                short = callee.split("::")[-1].split("!")[-1]
                args = inputs[1:] if inputs else []
                arg_labels = [set(taint.get(_var_id(value), set())) for value in args]
                if short in self.kb["sources"]:
                    label = f"{self.kb['sources'][short]}:{short}"
                    if output:
                        taint[output] = {label}
                    for arg_index in SOURCE_ARG_MODELS.get(short, ()):
                        if 0 <= arg_index < len(args):
                            arg_id = _var_id(args[arg_index])
                            if arg_id:
                                taint.setdefault(arg_id, set()).add(label)
                                memory.setdefault(arg_id, set()).add(label)
                    summary.source_returns.add(label)
                elif short in self.kb["sanitizers"] or re.search(r"(?i)(sanit|validat|escape|canonical)", short):
                    if output:
                        taint[output] = set().union(*arg_labels) if arg_labels else set()
                        sanitized[output] = short
                elif short in self.kb["sinks"]:
                    sink_kind, cwe = self.kb["sinks"][short]
                    labels = set().union(*arg_labels) if arg_labels else input_labels
                    for label in sorted(labels):
                        san = next((sanitized.get(_var_id(arg)) for arg in args if sanitized.get(_var_id(arg))), "")
                        flow = Flow(
                            source=label, sink=f"{sink_kind}:{short}", cwe=cwe, function=name,
                            call_path=[name, short], source_op="", sink_op=str(op.get("address") or op.get("seq") or ""),
                            variable=next((_var_id(arg) for arg in args if label in taint.get(_var_id(arg), set())), ""),
                            sanitized=bool(san), sanitizer=san,
                            uncertainty=["CALLIND target resolution"] if mnemonic == "CALLIND" else [],
                        )
                        summary.direct_flows.append(flow)
                        if label.startswith("param:"):
                            summary.sink_from_params.append({"parameter": int(label.split(":", 1)[1]), "sink": short, "cwe": cwe})
                elif callee in self.summaries:
                    callee_summary = self.summaries[callee]
                    if output:
                        labels = set(callee_summary.source_returns)
                        for param_index in callee_summary.return_from_params:
                            if param_index < len(arg_labels):
                                labels.update(arg_labels[param_index])
                        if labels:
                            taint[output] = labels
                    for sink_row in callee_summary.sink_from_params:
                        param_index = int(sink_row.get("parameter", -1))
                        if 0 <= param_index < len(arg_labels):
                            for label in arg_labels[param_index]:
                                summary.direct_flows.append(Flow(
                                    source=label, sink=f"interprocedural:{sink_row.get('sink')}",
                                    cwe=str(sink_row.get("cwe") or "CWE-20"), function=name,
                                    call_path=[name, callee, str(sink_row.get("sink"))],
                                    sink_op=str(op.get("address") or op.get("seq") or ""),
                                    variable=_var_id(args[param_index]),
                                ))
                                if label.startswith("param:"):
                                    summary.sink_from_params.append({
                                        "parameter": int(label.split(":", 1)[1]),
                                        "sink": sink_row.get("sink"), "cwe": sink_row.get("cwe"),
                                    })
                else:
                    if mnemonic == "CALLIND" or callee.startswith("sub_") or not callee:
                        summary.unresolved_calls.add(callee or "indirect")
                    if output and input_labels:
                        taint[output] = input_labels
            elif mnemonic == "STORE":
                # High P-code STORE inputs are usually [space, pointer, value].
                if len(inputs) >= 2:
                    pointer_id = _var_id(inputs[-2])
                    value_id = _var_id(inputs[-1])
                    labels = set(taint.get(value_id, set()))
                    if labels and pointer_id:
                        memory.setdefault(pointer_id, set()).update(labels)
                        # Preserve alias evidence conservatively.
                        taint.setdefault(pointer_id, set()).update(labels)
            elif mnemonic == "LOAD" and output:
                pointer_id = _var_id(inputs[-1]) if inputs else ""
                labels = set(memory.get(pointer_id, set())) | set(taint.get(pointer_id, set()))
                if labels:
                    taint[output] = labels
                    if sanitized.get(pointer_id):
                        sanitized[output] = sanitized[pointer_id]
            elif mnemonic in PROPAGATE_OPS and output and input_labels:
                taint[output] = set(input_labels)
                san = next((sanitized.get(_var_id(value)) for value in inputs if sanitized.get(_var_id(value))), "")
                if san:
                    sanitized[output] = san
        return_ops = [op for op in pcode if isinstance(op, dict) and str(op.get("mnemonic") or "").upper() == "RETURN"]
        for op in return_ops:
            for value in op.get("inputs", [])[1:]:
                for label in taint.get(_var_id(value), set()):
                    if label.startswith("param:"):
                        summary.return_from_params.add(int(label.split(":", 1)[1]))
                    else:
                        summary.source_returns.add(label)
        return summary


def load_kb(path: str | Path | None = None) -> dict:
    if not path:
        return DEFAULT_KB
    try:
        raw = json.loads(Path(path).read_text(errors="ignore"))
        merged = {"sources": dict(DEFAULT_KB["sources"]), "sinks": dict(DEFAULT_KB["sinks"]),
                  "sanitizers": set(DEFAULT_KB["sanitizers"])}
        merged["sources"].update(raw.get("sources") or {})
        for key, value in (raw.get("sinks") or {}).items():
            if isinstance(value, list) and len(value) >= 2:
                merged["sinks"][key] = (value[0], value[1])
        merged["sanitizers"].update(raw.get("sanitizers") or [])
        return merged
    except Exception:
        return DEFAULT_KB
