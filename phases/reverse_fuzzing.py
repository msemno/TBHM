"""Automatic bounded fuzz-harness proposal generation from reverse IR."""
from __future__ import annotations
from core import redteam_utils as RT
from core.fuzz_harness import generate_all
from core.reverse_phase_utils import load_ir_documents, write_json


def run(ctx):
    if not getattr(ctx.args, "reverse_fuzz_harness", False):
        return
    out = RT.evidence_dir(ctx, "25h_reverse_fuzzing")
    docs = load_ir_documents(ctx.output, [getattr(ctx.args, "reverse_ir_results", None)])
    index, total = [], 0
    max_functions = int(getattr(ctx.args, "reverse_fuzz_max_harnesses", 20))
    for n, (path, ir) in enumerate(docs):
        target = out / f"artifact_{n:04d}"
        result = generate_all(ir, target, max_functions=max_functions)
        total += result.get("count", 0)
        index.append({"ir": str(path), "directory": str(target), **result})
    write_json(out / "FUZZ_HARNESS_INDEX.json", {"schema": "tbhm.fuzz-harness-index/1.0", "artifacts": index, "total": total,
                                                  "execution_performed": False})
    RT.write_md(out / "FUZZ_HARNESS_SUMMARY.md", "Fuzz Harness Generation", [
        ("IR documents", str(len(docs))), ("Harness proposals", str(total)),
        ("Safety", "Generated source, dictionaries and manifests only. Targets and harnesses were not compiled or executed."),
    ])
    ctx.log("OK", "reverse_fuzzing", f"generated {total} harness proposal(s)")
