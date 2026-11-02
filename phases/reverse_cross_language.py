"""JavaScript-to-Java/Kotlin-to-JNI-to-native static correlation."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT
from core.cross_language_flow import collect_mobile_bridges, collect_js_calls, collect_native_functions, correlate, save
from core.reverse_phase_utils import load_ir_documents


def run(ctx):
    root_value = getattr(ctx.args, "reverse_cross_language_root", None) or getattr(ctx.args, "mobile_src", None)
    if not (getattr(ctx.args, "reverse_cross_language", False) and root_value):
        return
    root = Path(root_value).expanduser().resolve()
    out = RT.evidence_dir(ctx, "25e_reverse_cross_language")
    bridges = collect_mobile_bridges(root)
    js_paths = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".js", ".mjs", ".ts", ".jsx", ".tsx"}][:20000]
    js_calls = collect_js_calls(js_paths)
    docs = load_ir_documents(ctx.output, [getattr(ctx.args, "reverse_ir_results", None)])
    native = collect_native_functions([ir for _path, ir in docs])
    taint = []
    taint_dir = ctx.output / "redteam" / "25d_reverse_taint_analysis"
    for p in taint_dir.glob("taint_*.json") if taint_dir.is_dir() else []:
        try: taint.extend(json.loads(p.read_text(errors="ignore")).get("flows", []))
        except Exception: pass
    result = correlate(bridges, js_calls, native, taint)
    save(result, out / "CROSS_LANGUAGE_FLOW.json")
    for row in result.get("paths", [])[:1000]:
        if not row.get("native_reached"):
            continue
        ctx.save_finding({
            "phase": "reverse_cross_language", "severity": "MEDIUM", "confidence": "MEDIUM",
            "title": "[STATIC PATH] JavaScript bridge reaches JNI/native code",
            "target": str(root), "url": "", "description": "A WebView JavaScript bridge was correlated through an annotated Java/Kotlin method and native declaration to a JNI/native function.",
            "evidence": json.dumps(row, ensure_ascii=False)[:7000],
            "impact": "If untrusted content can invoke the bridge, native memory-safety or command/file sinks may become reachable.",
            "remediation": "Restrict loaded origins, avoid exposing sensitive bridges, validate every argument, and confirm the exact runtime registration and call path.",
            "cwe": "CWE-749", "mrs_score": 62, "finding_class": "static_path_supported",
        })
    RT.write_md(out / "CROSS_LANGUAGE_SUMMARY.md", "Cross-Language Data Flow", [
        ("Source files", str(bridges.get("source_files", 0))), ("JS calls", str(len(js_calls))),
        ("Native functions", str(len(native))), ("Correlated paths", str(len(result.get("paths", [])))),
        ("Limits", "Reflection, obfuscation and dynamic RegisterNatives tables may require manual review."),
    ])
    ctx.log("OK", "reverse_cross_language", f"correlated {len(result.get('paths', []))} path(s)")
