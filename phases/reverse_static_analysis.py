"""Headless static analysis plus normalization into the TBHM universal reverse IR."""
from __future__ import annotations

from core.version import SEMANTIC_VERSION

import json
import os
import re
from pathlib import Path

from core import redteam_utils as RT
from core import reverse_utils as RU
from core import reverse_ir as RIR
from core.scanner_normalizer import parse_file, save_items


def _emit_import(ctx, artifact: Path, tool: str, item: dict, artifact_id: str = ""):
    name = str(item.get("name") or item.get("title") or item.get("rule") or "analysis result")
    text = json.dumps(item, ensure_ascii=False)[:4000]
    ctx.save_finding({
        "phase": "reverse_static_analysis", "severity": "MEDIUM", "confidence": "LOW",
        "title": f"[LEAD] {tool} static-analysis observation: {name}"[:180],
        "target": str(artifact), "url": "",
        "description": f"Static result exported by {tool}. A function/import match is not proof that attacker-controlled data reaches it.",
        "evidence": text,
        "impact": "If the referenced code path is reachable with attacker-controlled input, it may contribute to memory corruption, command execution, insecure cryptography, or malicious behavior.",
        "remediation": "Review the decompiled function and cross-references, trace sources to sinks, add bounds and authorization checks, and confirm the behavior in an isolated sandbox.",
        "cwe": str(item.get("cwe") or "CWE-912"), "mrs_score": 50,
        "finding_class": "lead", "artifact_id": artifact_id,
    })


def _run_r2(ctx, binary: Path, out_dir: Path, tool: str) -> dict:
    stem = RU.safe_stem(binary)
    command_map = {
        "info": "ij", "functions": "aflj", "imports": "iij", "symbols": "isj",
        "strings": "izj", "callgraph": "agCj", "sections": "iSj",
    }
    result = {"tool": tool, "binary": str(binary), "artifact_id": RU.artifact_id(binary), "outputs": {}}
    for name, command in command_map.items():
        rc, stdout, stderr = ctx.runner.run(
            [tool, "-2", "-A", "-q", "-c", command, str(binary)],
            timeout=600, log_name=f"reverse_{tool}_{name}_{stem}",
        )
        try:
            parsed = json.loads(stdout) if stdout.strip() else []
        except Exception:
            parsed = {"raw": stdout[:500000]}
        result["outputs"][name] = {"rc": rc, "data": parsed, "stderr": stderr[:2000]}
    RU.write_json(out_dir / f"{stem}.{tool}.json", result)
    return result


def _find_ghidra_headless(args) -> str | None:
    explicit = getattr(args, "reverse_ghidra_home", None) or os.environ.get("GHIDRA_HOME")
    candidates = []
    if explicit:
        candidates.append(Path(explicit) / "support" / "analyzeHeadless")
        candidates.append(Path(explicit) / "analyzeHeadless")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return "analyzeHeadless"


def run(ctx):
    if not (getattr(ctx.args, "reverse_static", False) or getattr(ctx.args, "reverse_tooling", False) or getattr(ctx.args, "reverse_results", None)):
        return
    out = RT.evidence_dir(ctx, "25b_reverse_static_analysis")
    tools = [x.strip().lower() for x in str(getattr(ctx.args, "reverse_backends", "auto") or "auto").split(",") if x.strip()]
    if "auto" in tools:
        tools = [name for name in ("ghidra", "r2", "rizin", "ida") if name == "ghidra" or ctx.runner.has(name)]
    artifacts = list(RU.iter_files(
        getattr(ctx.args, "binary_path", None),
        getattr(ctx.args, "reverse_max_files", 50),
        getattr(ctx.args, "reverse_max_file_mb", 200),
    ))
    index = []
    root = Path(__file__).resolve().parents[1]
    artifact_ids_by_stem = {RU.safe_stem(binary): RU.artifact_id(binary) for binary in artifacts}
    default_artifact_id = RU.artifact_id(artifacts[0]) if len(artifacts) == 1 else ""

    for binary in artifacts:
        stem = RU.safe_stem(binary)
        artifact_id = artifact_ids_by_stem.get(stem, "")
        record = {"binary": str(binary), "artifact_id": artifact_id, "backends": {}, "execution_performed": False}
        if "r2" in tools and ctx.runner.has("r2"):
            record["backends"]["radare2"] = _run_r2(ctx, binary, out, "r2")
        if "rizin" in tools and ctx.runner.has("rizin"):
            record["backends"]["rizin"] = _run_r2(ctx, binary, out, "rizin")
        if "ghidra" in tools:
            headless = _find_ghidra_headless(ctx.args)
            if ctx.runner.has(headless) or Path(headless).is_file():
                project_dir = out / "ghidra_projects"
                project_dir.mkdir(parents=True, exist_ok=True)
                dest = out / f"{stem}.ghidra.json"
                script_dir = root / "scripts" / "ghidra"
                project_name = "TBHM_" + re.sub(r"\W+", "_", stem)
                rc, stdout, stderr = ctx.runner.run([
                    headless, str(project_dir), project_name,
                    "-import", str(binary), "-scriptPath", str(script_dir),
                    "-postScript", "ExportTbhmAnalysis.java", str(dest),
                    str(max(1, int(getattr(ctx.args, "reverse_ir_max_functions", 20000)))),
                    str(max(1, int(getattr(ctx.args, "reverse_decompile_timeout", 60)))),
                    "-deleteProject",
                ], timeout=3600, log_name=f"reverse_ghidra_{stem}")
                record["backends"]["ghidra"] = {"rc": rc, "output": str(dest), "stdout": stdout[-10000:], "stderr": stderr[-10000:]}
        if "ida" in tools:
            ida_path = getattr(ctx.args, "reverse_ida_path", None)
            if ida_path and Path(ida_path).is_file():
                dest = out / f"{stem}.ida.json"
                script = root / "scripts" / "ida" / "export_tbhm.py"
                rc, stdout, stderr = ctx.runner.run([
                    str(ida_path), "-A", f"-S{script} --out={dest}", str(binary)
                ], timeout=3600, log_name=f"reverse_ida_{stem}", env={"TBHM_IDA_OUT": str(dest)})
                record["backends"]["ida"] = {"rc": rc, "output": str(dest), "stdout": stdout[-10000:], "stderr": stderr[-10000:]}
        index.append(record)

    import_count = 0
    ir_outputs = []
    result_paths = []
    supplied = getattr(ctx.args, "reverse_results", None)
    if supplied:
        p = Path(supplied)
        result_paths.extend([p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else [])
    result_paths.extend([f for f in out.glob("*.json") if f.is_file()])
    seen = set()
    for result in result_paths:
        if result in seen or result.name == "reverse_static_index.json":
            continue
        seen.add(result)
        try:
            data = json.loads(result.read_text(errors="ignore"))
        except Exception:
            continue
        try:
            suffix_hint = result.suffixes[-2].lstrip(".") if len(result.suffixes) > 1 else result.stem
            backend_hint = str(data.get("tool") or data.get("backend") or suffix_hint)
            normalized = RIR.normalize(data, backend_hint=backend_hint)
            ir_path = out / f"{result.stem}.tbhm-ir.json"
            RIR.save(normalized, ir_path)
            ir_outputs.append({
                "source": str(result), "ir": str(ir_path),
                "backend": normalized.get("backend", ""),
                "functions": len(normalized.get("functions", [])),
                "artifact": normalized.get("artifact", {}),
            })
        except Exception as exc:
            ctx.log("WARN", "reverse_static_analysis", f"IR normalization failed for {result.name}: {exc}")
        result_artifact_id = default_artifact_id
        for stem, candidate_id in artifact_ids_by_stem.items():
            if result.name.startswith(stem + ".") or result.stem == stem:
                result_artifact_id = candidate_id
                break
        # Scanner/SARIF exports get normalized through the shared parser.
        parsed = parse_file(result, source=result.stem, max_items=5000)
        if parsed:
            import_count += save_items(
                ctx, "reverse_static_analysis", parsed, result.stem,
                extra_fields={"artifact_id": result_artifact_id} if result_artifact_id else None)
        # Native Ghidra/IDA/r2 exports need direct function/import handling.
        candidates = []
        if isinstance(data, dict):
            candidates.extend(data.get("functions", []) if isinstance(data.get("functions"), list) else [])
            candidates.extend(data.get("imports", []) if isinstance(data.get("imports"), list) else [])
            for backend in (data.get("outputs") or {}).values() if isinstance(data.get("outputs"), dict) else []:
                value = backend.get("data") if isinstance(backend, dict) else None
                if isinstance(value, list): candidates.extend(value)
        for item in candidates[:5000]:
            if isinstance(item, dict):
                _emit_import(ctx, result, result.stem, item, result_artifact_id); import_count += 1

    RU.write_json(out / "reverse_static_index.json", {
        "version": SEMANTIC_VERSION, "artifacts": index, "normalized_observations": import_count,
        "reverse_ir_outputs": ir_outputs, "reverse_ir_schema": RIR.SCHEMA,
        "backends": tools, "execution_performed": False,
        "interoperability": ["JSON", "JSONL", "SARIF 2.1.0", "Ghidra headless", "IDA batch", "Radare2/Rizin JSON", RIR.SCHEMA],
    })
    RT.write_md(out / "REVERSE_STATIC_SUMMARY.md", "Reverse Static Analysis", [
        ("Artifacts", str(len(artifacts))), ("Backends", ", ".join(tools) or "none"),
        ("Observations", str(import_count)), ("Universal IR files", str(len(ir_outputs))),
        ("Methodology", "Headless disassembly/decompilation exports, Ghidra decompiled C/high P-code, CFG/function/import/cross-reference collection, and normalization into the TBHM reverse IR."),
        ("Safety", "Static analysis only. No target binary was executed, patched, or instrumented."),
    ])
    ctx.log("OK", "reverse_static_analysis", f"processed {len(artifacts)} artifact(s); normalized {import_count} observation(s)")
