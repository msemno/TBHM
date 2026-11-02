"""Bounded interprocedural source-to-sink analysis over universal reverse IR."""
from __future__ import annotations
import json
from core import redteam_utils as RT
from core.interprocedural_taint import IRTaintAnalyzer
from core.reverse_phase_utils import load_ir_documents, write_json


def run(ctx):
    if not getattr(ctx.args, "reverse_taint", False):
        return
    out = RT.evidence_dir(ctx, "25d_reverse_taint_analysis")
    docs = load_ir_documents(ctx.output, [getattr(ctx.args, "reverse_ir_results", None)])
    index, total_flows = [], 0
    max_iter = int(getattr(ctx.args, "reverse_taint_iterations", 20))
    for n, (path, ir) in enumerate(docs):
        result = IRTaintAnalyzer(ir, max_iterations=max_iter).analyze()
        dest = out / f"taint_{n:04d}.json"
        write_json(dest, result)
        flows = result.get("flows", [])
        total_flows += len(flows)
        index.append({"ir": str(path), "result": str(dest), "functions": result.get("functions_analyzed", 0), "flows": len(flows)})
        for flow in flows[:1000]:
            if flow.get("sanitized"):
                continue
            ctx.save_finding({
                "phase": "reverse_taint_analysis", "severity": "MEDIUM", "confidence": "MEDIUM",
                "title": f"[STATIC PATH] {flow.get('source')} reaches {flow.get('sink')}",
                "target": str((ir.get("artifact") or {}).get("path") or path), "url": "",
                "description": "Interprocedural fixed-point analysis found a static source-to-sink path in normalized reverse IR. Static reachability does not prove runtime exploitability.",
                "evidence": json.dumps(flow, ensure_ascii=False)[:6000],
                "impact": "The impact depends on whether the input is attacker controlled, the path is runtime reachable, and validation is effective.",
                "remediation": "Review the decompiled path, model wrappers and sanitizers, validate bounds/authorization, and confirm with a benign isolated runtime test.",
                "cwe": flow.get("cwe") or "CWE-20", "mrs_score": 65, "finding_class": "static_path_supported",
            })
    write_json(out / "REVERSE_TAINT_INDEX.json", {"schema": "tbhm.taint-index/1.0", "documents": index, "total_flows": total_flows})
    RT.write_md(out / "REVERSE_TAINT_SUMMARY.md", "Interprocedural Taint Analysis", [
        ("IR documents", str(len(docs))), ("Static paths", str(total_flows)),
        ("Method", "Bounded fixed-point function summaries over high P-code-like operations, sources, sinks, sanitizers, direct calls and parameter/return propagation."),
        ("Limits", "Indirect calls and pointer aliases can remain unresolved; static paths require runtime validation."),
    ])
    ctx.log("OK", "reverse_taint_analysis", f"analyzed {len(docs)} IR document(s); {total_flows} static flow(s)")
