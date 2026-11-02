"""Validate and summarize normalized reverse-engineering IR evidence."""
from __future__ import annotations
from core import redteam_utils as RT
from core import reverse_ir as RIR
from core.reverse_phase_utils import load_ir_documents, write_json


def run(ctx):
    if not (getattr(ctx.args, "reverse_ir", False) or getattr(ctx.args, "reverse_static", False) or getattr(ctx.args, "reverse_results", None)):
        return
    out = RT.evidence_dir(ctx, "25c_reverse_ir_analysis")
    docs = load_ir_documents(ctx.output, [getattr(ctx.args, "reverse_ir_results", None), getattr(ctx.args, "reverse_results", None)])
    index, total = [], 0
    for path, ir in docs:
        functions = ir.get("functions", []) if isinstance(ir.get("functions"), list) else []
        total += len(functions)
        ranges = RIR.function_ranges(ir)
        record = {
            "source": str(path), "schema": ir.get("schema"), "backend": ir.get("backend"),
            "artifact": ir.get("artifact", {}), "functions": len(functions), "function_ranges": len(ranges),
            "with_pcode": sum(bool(x.get("pcode")) for x in functions if isinstance(x, dict)),
            "with_decompiled_c": sum(bool(x.get("decompiled_c")) for x in functions if isinstance(x, dict)),
            "imports": len(ir.get("imports", [])), "strings": len(ir.get("strings", [])),
        }
        index.append(record)
    write_json(out / "REVERSE_IR_INDEX.json", {"schema": RIR.SCHEMA, "documents": index, "counts": {"documents": len(index), "functions": total}})
    RT.write_md(out / "REVERSE_IR_SUMMARY.md", "Universal Reverse IR", [
        ("IR documents", str(len(index))), ("Functions", str(total)),
        ("Schema", RIR.SCHEMA),
        ("Interpretation", "Normalized decompiler/disassembler evidence. Recovered types and decompiled source remain estimates until reviewed."),
    ])
    ctx.log("OK", "reverse_ir_analysis", f"indexed {len(index)} IR document(s), {total} functions")
