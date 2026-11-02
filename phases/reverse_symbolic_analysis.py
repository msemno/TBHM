"""Bounded CFG, symbolic input synthesis and seed-guided concolic replay."""
from __future__ import annotations

from core.version import SEMANTIC_VERSION

import json
import sys
from pathlib import Path

from core import redteam_utils as RT
from core import reverse_utils as RU
from core.scanner_normalizer import parse_file, save_items


def run(ctx):
    supplied = getattr(ctx.args, "reverse_symbolic_results", None)
    enabled = bool(getattr(ctx.args, "reverse_symbolic", False))
    if not (supplied or enabled):
        return
    out = RT.evidence_dir(ctx, "25d_reverse_symbolic_analysis")
    root = Path(__file__).resolve().parents[1]
    artifacts = list(RU.iter_files(
        getattr(ctx.args, "binary_path", None),
        getattr(ctx.args, "reverse_max_files", 50),
        getattr(ctx.args, "reverse_max_file_mb", 200),
    )) if enabled else []
    runs = []

    for binary in artifacts:
        stem = RU.safe_stem(binary)
        artifact_id = RU.artifact_id(binary)
        dest = out / f"{stem}.angr.json"
        script = root / "scripts" / "reverse" / "angr_triage.py"
        command = [
            sys.executable, str(script), str(binary), "--output", str(dest),
            "--max-functions", str(getattr(ctx.args, "reverse_symbolic_max_functions", 10000)),
            "--mode", str(getattr(ctx.args, "reverse_symbolic_mode", "cfg")),
            "--input-kind", str(getattr(ctx.args, "reverse_symbolic_input_kind", "stdin")),
            "--max-input-bytes", str(getattr(ctx.args, "reverse_symbolic_max_input_bytes", 64)),
        ]
        for address in (getattr(ctx.args, "reverse_symbolic_find", None) or []):
            command += ["--find", str(address)]
        for address in (getattr(ctx.args, "reverse_symbolic_avoid", None) or []):
            command += ["--avoid", str(address)]
        if getattr(ctx.args, "reverse_symbolic_printable", False):
            command.append("--printable")
        if getattr(ctx.args, "reverse_symbolic_seed", None):
            command += ["--seed-file", str(getattr(ctx.args, "reverse_symbolic_seed"))]
        if getattr(ctx.args, "reverse_symbolic_trace", None):
            command += ["--trace-file", str(getattr(ctx.args, "reverse_symbolic_trace"))]
        rc, stdout, stderr = ctx.runner.run(
            command, timeout=max(60, min(int(getattr(ctx.args, "reverse_symbolic_timeout", 1800)), 7200)),
            log_name=f"reverse_angr_{stem}")
        runs.append({"binary": str(binary), "artifact_id": artifact_id, "rc": rc, "output": str(dest), "stderr": stderr[-4000:]})
        if dest.is_file():
            try:
                data = json.loads(dest.read_text())
                functions = data.get("functions", [])
                sensitive = [f for f in functions if str(f.get("name", "")).lower() in {
                    "strcpy", "gets", "sprintf", "system", "popen", "execve", "memcpy"
                }]
                for item in sensitive[:100]:
                    ctx.save_finding({
                        "phase": "reverse_symbolic_analysis", "severity": "MEDIUM", "confidence": "LOW",
                        "title": f"[LEAD] CFG contains sensitive function: {item.get('name')}",
                        "target": str(binary), "url": "", "artifact_id": artifact_id,
                        "description": "Bounded angr CFG analysis identified a sensitive function or import. No exploit input was synthesized.",
                        "evidence": json.dumps(item, ensure_ascii=False)[:3000],
                        "impact": "If attacker-controlled input can reach this function without adequate validation, exploitation may be possible.",
                        "remediation": "Trace callers and data flow, add bounds and validation, and confirm reachability with a benign controlled test in a sandbox.",
                        "cwe": "CWE-119", "mrs_score": 45, "finding_class": "lead",
                    })
                symbolic = data.get("symbolic") if isinstance(data.get("symbolic"), dict) else {}
                if symbolic.get("found") and isinstance(symbolic.get("input"), dict):
                    ctx.save_finding({
                        "phase": "reverse_symbolic_analysis", "severity": "INFO", "confidence": "HIGH",
                        "title": "[TEST INPUT] Bounded symbolic/concolic path input synthesized",
                        "target": str(binary), "url": "", "artifact_id": artifact_id,
                        "description": "angr reached an analyst-supplied address and produced a bounded concrete test input. This demonstrates path reachability in the model, not exploitability.",
                        "evidence": json.dumps(symbolic, ensure_ascii=False)[:7000],
                        "impact": "The input can be used for controlled regression or runtime validation in a disposable sandbox.",
                        "remediation": "Review the path constraints and decompiled code, then validate the input in an isolated environment without production data or networking.",
                        "cwe": "CWE-20", "mrs_score": 20, "finding_class": "generated_test_case",
                    })
            except Exception:
                pass

    imported = 0
    default_artifact_id = RU.artifact_id(artifacts[0]) if len(artifacts) == 1 else ""
    if supplied:
        p = Path(supplied)
        files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else []
        for file in files:
            if file.suffix.lower() not in {".json", ".jsonl", ".sarif"}:
                continue
            imported += save_items(
                ctx, "reverse_symbolic_analysis", parse_file(file, file.stem), file.stem,
                extra_fields={"artifact_id": default_artifact_id} if default_artifact_id else None)

    RU.write_json(out / "reverse_symbolic_index.json", {
        "version": SEMANTIC_VERSION, "runs": runs, "imported_observations": imported,
        "scope": "CFG, bounded symbolic reachability, seed-guided concolic replay and imported angr/Triton/Unicorn evidence",
        "mode": str(getattr(ctx.args, "reverse_symbolic_mode", "cfg")),
        "exploit_generation_performed": False,
    })
    RT.write_md(out / "REVERSE_SYMBOLIC_SUMMARY.md", "Reverse Symbolic Analysis", [
        ("Runs", str(len(runs))), ("Imported observations", str(imported)),
        ("Methodology", "Bounded CFGFast plus optional analyst-address symbolic exploration or seed/trace-guided concolic replay."),
        ("Safety", "Only bounded test inputs are synthesized. No shellcode, reverse shell, persistence or post-exploitation payload is generated."),
    ])
    ctx.log("OK", "reverse_symbolic_analysis", f"completed {len(runs)} bounded run(s); imported {imported} observation(s)")
