"""Map imported runtime addresses and events back to decompiled functions."""
from __future__ import annotations
from core import redteam_utils as RT
from core.dynamic_mapper import load_json_documents, map_events
from core.reverse_phase_utils import load_ir_documents, write_json


def run(ctx):
    source = getattr(ctx.args, "reverse_dynamic_results", None)
    if not (getattr(ctx.args, "reverse_dynamic_map", False) and source):
        return
    out = RT.evidence_dir(ctx, "25g_reverse_dynamic_mapping")
    ir_docs = [ir for _path, ir in load_ir_documents(ctx.output, [getattr(ctx.args, "reverse_ir_results", None)])]
    dynamic = load_json_documents(source)
    result = map_events(ir_docs, dynamic)
    write_json(out / "DYNAMIC_TO_STATIC_MAP.json", result)
    RT.write_md(out / "DYNAMIC_MAPPING_SUMMARY.md", "Dynamic-to-Static Mapping", [
        ("IR documents", str(len(ir_docs))), ("Dynamic documents", str(len(dynamic))),
        ("Mapped events", str(result.get("counts", {}).get("mapped", 0))),
        ("Unmapped addresses", str(result.get("counts", {}).get("unmapped", 0))),
    ])
    ctx.log("OK", "reverse_dynamic_mapping", f"mapped {result.get('counts', {}).get('mapped', 0)} event(s)")
