"""Additive source-security orchestrator adapters.

Live execution is limited to deterministic, local, read-only repository scans.
s0-cli is run with ``--no-llm`` so TBHM can keep model selection and data-flow
control in the separate local_llm_triage phase. Argus, Mega-Linter,
SonarQube, CodeQL, DefectDojo, and other platform outputs can be imported from
JSON/JSONL/SARIF without coupling TBHM to a specific deployment.
"""
from __future__ import annotations

import json
from pathlib import Path

from core import redteam_utils as RT
from core.scanner_normalizer import iter_result_files, parse_file, save_items


def _run_s0(ctx, src: Path, out: Path) -> Path | None:
    dest = out / "s0.sarif"
    if ctx.runner.has("s0"):
        cmd = ["s0", "scan", str(src), "--no-llm", "--format", "sarif", "--out", str(dest)]
        rc, stdout, stderr = ctx.runner.run(cmd, timeout=3600, log_name="source_orchestrator_s0")
        if rc != 0:
            ctx.log("WARN", "source_orchestration_tooling", f"s0 exited {rc}: {(stderr or stdout)[:220]}")
        return dest if dest.exists() else None

    s0_dir = getattr(ctx.args, "s0_dir", None)
    if s0_dir and ctx.runner.has("uv"):
        root = Path(s0_dir).expanduser().resolve()
        if (root / "pyproject.toml").is_file():
            cmd = ["uv", "run", "--project", str(root), "s0", "scan", str(src),
                   "--no-llm", "--format", "sarif", "--out", str(dest)]
            rc, stdout, stderr = ctx.runner.run(cmd, timeout=3600, log_name="source_orchestrator_s0_uv")
            if rc != 0:
                ctx.log("WARN", "source_orchestration_tooling", f"s0/uv exited {rc}: {(stderr or stdout)[:220]}")
            return dest if dest.exists() else None

    ctx.log("WARN", "source_orchestration_tooling", "s0-cli not found; provide --s0-dir or import its SARIF/JSON output")
    return None


def run(ctx):
    if not (getattr(ctx.args, "source_orchestration", False) or
            getattr(ctx.args, "source_orchestration_results", None)):
        return

    out = RT.evidence_dir(ctx, "30_source_orchestration_tooling")
    total = 0
    executed = []
    imported = []
    src_raw = getattr(ctx.args, "code_dir", None)
    selected = [x.strip().lower() for x in str(
        getattr(ctx.args, "source_orchestration_tools", "s0") or "s0"
    ).split(",") if x.strip()]

    if getattr(ctx.args, "source_orchestration", False):
        if not src_raw or not Path(src_raw).is_dir():
            ctx.log("WARN", "source_orchestration_tooling", "--source-orchestration requires --code-dir")
        else:
            src = Path(src_raw).resolve()
            for name in selected:
                if name == "s0":
                    result = _run_s0(ctx, src, out)
                    if result:
                        items = parse_file(result, "s0-cli")
                        total += save_items(ctx, "source_orchestration_tooling", items, "s0-cli")
                        executed.append({"tool": "s0-cli", "output": str(result), "mode": "--no-llm"})
                elif name in {"argus", "mega-linter", "sonarqube", "codeql", "defectdojo"}:
                    ctx.log(
                        "INFO", "source_orchestration_tooling",
                        f"{name} live execution is deployment/version-specific; use --source-orchestration-results to import JSON/SARIF",
                    )
                else:
                    ctx.log("WARN", "source_orchestration_tooling", f"unknown orchestrator '{name}' skipped")

    results_path = getattr(ctx.args, "source_orchestration_results", None)
    if results_path:
        for file in iter_result_files(results_path):
            source = file.stem
            items = parse_file(file, source)
            total += save_items(ctx, "source_orchestration_tooling", items, source)
            imported.append(str(file))

    summary = {
        "normalized_findings": total,
        "executed": executed,
        "imported": imported,
        "supported_live": ["s0-cli deterministic --no-llm repository scan"],
        "supported_import": [
            "s0-cli", "Argus", "Mega-Linter", "SonarQube", "CodeQL",
            "DefectDojo", "SARIF/JSON/JSONL compatible orchestrators",
        ],
        "safety": {
            "local_source_only": True,
            "repository_writes": False,
            "cloud_llm_called": False,
            "s0_llm_disabled": True,
            "scanner_observations_are_leads": True,
        },
    }
    (out / "source_orchestration_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    RT.write_md(out / "SOURCE_ORCHESTRATION_SUMMARY.md", "Source Orchestration Tooling Summary", [
        ("Normalized observations", str(total)),
        ("Live execution", json.dumps(executed, ensure_ascii=False) if executed else "None"),
        ("Imported results", "\n".join(f"- {x}" for x in imported) if imported else "None"),
        ("Argus/platform handling", "Argus, Mega-Linter, SonarQube, CodeQL and DefectDojo are accepted through JSON/SARIF import. TBHM does not automatically enable Argus sandbox exploit validation or cloud LLM calls."),
        ("Safety boundary", "Read-only source scans only; all normalized scanner records remain unconfirmed leads until manually validated."),
    ])
    ctx.log("OK", "source_orchestration_tooling", f"{total} orchestrator observation(s) normalized")
