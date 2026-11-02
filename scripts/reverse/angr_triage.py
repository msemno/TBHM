#!/usr/bin/env python3
"""Bounded angr CFG, symbolic reachability and seed-guided concolic replay.

The script generates only bounded concrete test inputs for analyst-supplied find
addresses. It does not generate shellcode, payloads or post-exploitation logic.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path


def _import_angr():
    try:
        import angr
        import claripy
        return angr, claripy
    except ImportError:
        tool_home = Path(os.environ.get("TBHM_TOOL_HOME", Path.home() / ".local/share/tbhm-tools"))
        candidate = tool_home / "venvs/angr/bin/python"
        if candidate.is_file() and Path(sys.executable).resolve() != candidate.resolve():
            os.execv(str(candidate), [str(candidate), *sys.argv])
        raise RuntimeError("angr is unavailable. Enable it with INSTALL_REVERSE_TOOLING=1 INSTALL_ANGR=1 ./install.sh")


def _addr(value: str) -> int:
    return int(str(value), 0)


def _trace(path: str | None) -> list[int]:
    if not path:
        return []
    raw = json.loads(Path(path).read_text(errors="ignore"))
    values = raw.get("trace", raw.get("addresses", [])) if isinstance(raw, dict) else raw
    return [_addr(x) for x in values if isinstance(x, (str, int))]


def _result_bytes(data: bytes) -> dict:
    return {
        "bytes": len(data), "hex": data.hex(), "base64": base64.b64encode(data).decode(),
        "printable": "".join(chr(x) if 32 <= x < 127 else "." for x in data),
        "sha256": __import__("hashlib").sha256(data).hexdigest(),
    }


def _cfg_payload(project, cfg, max_functions: int) -> list[dict]:
    rows = []
    for func in list(cfg.kb.functions.values())[:max(1, min(max_functions, 50000))]:
        try: blocks = list(func.blocks) if not func.is_simprocedure else []
        except Exception: blocks = []
        rows.append({
            "name": func.name, "address": hex(func.addr),
            "end": hex(max((block.addr + block.size for block in blocks), default=func.addr + 1)),
            "size": sum(block.size for block in blocks), "is_plt": bool(func.is_plt),
            "returning": func.returning, "block_count": len(blocks),
            "callers": [hex(x.addr if hasattr(x, "addr") else int(x)) for x in list(func.predecessors)[:100]],
            "callees": [hex(x.addr if hasattr(x, "addr") else int(x)) for x in list(func.successors)[:100]],
        })
    return rows


def _symbolic_state(project, claripy, args):
    size = max(1, min(args.max_input_bytes, 4096))
    seed = Path(args.seed_file).read_bytes()[:size] if args.seed_file else b""
    symbolic = claripy.BVS("tbhm_input", size * 8)
    if args.input_kind == "argv1":
        state = project.factory.full_init_state(args=[args.binary, symbolic])
    else:
        import angr
        stream = angr.SimFileStream(name="stdin", content=symbolic, has_end=True)
        state = project.factory.full_init_state(stdin=stream)
    if args.printable:
        for index in range(size):
            byte = symbolic.get_byte(index)
            state.solver.add(byte >= 0x20, byte <= 0x7e)
    if seed and args.mode != "concolic":
        # Seed-guided symbolic mode keeps a concrete prefix while leaving the rest symbolic.
        for index, byte_value in enumerate(seed[:size]):
            state.solver.add(symbolic.get_byte(index) == byte_value)
    return state, symbolic, seed


def _symbolic(project, angr, claripy, args) -> dict:
    if not args.find:
        return {"performed": False, "reason": "no --find address supplied"}
    state, symbolic, seed = _symbolic_state(project, claripy, args)
    find = [_addr(x) for x in args.find]
    avoid = [_addr(x) for x in args.avoid]
    simgr = project.factory.simgr(state, save_unconstrained=True)
    technique = "symbolic_explore"
    trace = _trace(args.trace_file)
    concolic_error = ""
    if args.mode == "concolic":
        if not seed or not trace:
            return {"performed": False, "reason": "concolic mode requires --seed-file and --trace-file"}
        try:
            # angr's preconstrainer + Tracer follows the recorded concrete path,
            # then removes seed constraints so a new satisfying input can be solved.
            state.preconstrainer.preconstrain_file(seed, state.posix.stdin, True)
            tracer = angr.exploration_techniques.Tracer(trace=trace, copy_states=True)
            simgr.use_technique(tracer)
            technique = "preconstrained_tracer"
        except Exception as exc:
            concolic_error = str(exc)
            technique = "symbolic_fallback"
    started = time.time()
    simgr.explore(find=find, avoid=avoid, n=1)
    elapsed = time.time() - started
    found = simgr.found[0] if simgr.found else None
    result = {
        "performed": True, "mode": args.mode, "technique": technique, "find": [hex(x) for x in find],
        "avoid": [hex(x) for x in avoid], "elapsed_seconds": round(elapsed, 3),
        "active": len(simgr.active), "deadended": len(simgr.deadended), "unconstrained": len(simgr.unconstrained),
        "found": bool(found), "concolic_error": concolic_error,
    }
    if found:
        if args.mode == "concolic":
            try: found.preconstrainer.remove_preconstraints()
            except Exception as exc: result["remove_preconstraints_error"] = str(exc)
        concrete = found.solver.eval(symbolic, cast_to=bytes)
        result["input"] = _result_bytes(concrete)
        result["found_address"] = hex(found.addr)
        result["constraints"] = len(found.solver.constraints)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--output", required=True)
    ap.add_argument("--max-functions", type=int, default=10000)
    ap.add_argument("--mode", choices=["cfg", "symbolic", "concolic"], default="cfg")
    ap.add_argument("--find", action="append", default=[])
    ap.add_argument("--avoid", action="append", default=[])
    ap.add_argument("--input-kind", choices=["stdin", "argv1"], default="stdin")
    ap.add_argument("--max-input-bytes", type=int, default=64)
    ap.add_argument("--printable", action="store_true")
    ap.add_argument("--seed-file")
    ap.add_argument("--trace-file")
    args = ap.parse_args()
    args.binary = str(Path(args.binary).expanduser().resolve(strict=True))
    angr, claripy = _import_angr()
    project = angr.Project(args.binary, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    functions = _cfg_payload(project, cfg, args.max_functions)
    symbolic = {"performed": False, "reason": "CFG-only mode"}
    if args.mode in {"symbolic", "concolic"}:
        symbolic = _symbolic(project, angr, claripy, args)
    payload = {
        "schema": "tbhm.angr/2.0", "tool": "angr", "binary": args.binary,
        "architecture": project.arch.name, "entry": hex(project.entry), "functions": functions,
        "imports": [{"name": name, "address": hex(symbol.rebased_addr)} for name, symbol in project.loader.main_object.imports.items()],
        "mitigations": {"nx": getattr(project.loader.main_object, "execstack", None) is False,
                        "pic": getattr(project.loader.main_object, "pic", None)},
        "symbolic": symbolic, "input_synthesis_performed": bool(symbolic.get("found")),
        "concolic_replay_performed": args.mode == "concolic" and bool(symbolic.get("performed")),
        "exploit_generation_performed": False,
    }
    Path(args.output).write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
