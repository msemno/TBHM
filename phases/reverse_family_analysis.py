"""Managed UEFI, driver, protocol, mobile and hardware-evidence workflows."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT
from core.reverse_families import (
    detect_family, analyze_uefi, analyze_driver, analyze_protocol_capture,
    analyze_hardware_evidence, analyze_mobile_package,
)
from core.reverse_phase_utils import write_json


def run(ctx):
    source = getattr(ctx.args, "reverse_family_path", None)
    if not source:
        return
    execute_tools = bool(getattr(ctx.args, "reverse_family_tooling", False))
    if execute_tools and not getattr(ctx.args, "confirm_isolated_execution", False):
        raise RuntimeError("--reverse-family-tooling requires --confirm-isolated-execution")
    out = RT.evidence_dir(ctx, "25l_reverse_family_analysis")
    root = Path(source).expanduser().resolve()
    if root.is_file() or (root.is_dir() and root.suffix.lower() == ".kext"):
        files = [root]
    elif root.is_dir():
        kext_roots = {p.resolve() for p in root.rglob("*.kext") if p.is_dir() and not p.is_symlink()}
        files = list(sorted(kext_roots, key=str))
        for candidate in root.rglob("*"):
            if not candidate.is_file() or candidate.is_symlink():
                continue
            resolved = candidate.resolve()
            if any(bundle in resolved.parents for bundle in kext_roots):
                continue
            files.append(candidate)
    else:
        files = []
    records = []
    max_files = max(1, min(int(getattr(ctx.args, "reverse_family_max_files", 5000)), 100000))
    for n, path in enumerate(files[:max_files]):
        detected = detect_family(path)
        family = detected.get("family")
        detail = None
        artifact_out = out / f"artifact_{n:05d}_{path.stem[:80]}"
        if family == "uefi":
            detail = analyze_uefi(path, ctx.runner, artifact_out, execute_tools)
        elif family in {"windows_driver", "linux_kernel_module", "macos_kernel_extension"}:
            detail = analyze_driver(path, ctx.runner, artifact_out, execute_tools)
        elif family == "mobile":
            detail = analyze_mobile_package(path, ctx.runner, artifact_out, execute_tools)
        elif family == "protocol_capture":
            detail = analyze_protocol_capture(path, ctx.runner, int(getattr(ctx.args, "reverse_protocol_max_packets", 10000)))
        elif family == "hardware_or_firmware_dump":
            detail = analyze_hardware_evidence(path, max_files=1)
        records.append({"detection": detected, "analysis": detail})
    write_json(out / "REVERSE_FAMILY_INDEX.json", {
        "schema": "tbhm.reverse-family-index/1.1", "records": records,
        "external_static_tooling_requested": execute_tools,
        "safety": "No driver, mobile application, firmware module or hardware dump was loaded into the host kernel or executed.",
    })
    counts = {}
    tool_runs = 0
    for row in records:
        f = row["detection"].get("family", "unknown"); counts[f] = counts.get(f, 0) + 1
        tool_runs += len((row.get("analysis") or {}).get("tool_runs", []))
    RT.write_md(out / "REVERSE_FAMILY_SUMMARY.md", "Managed Reverse Families", [
        ("Artifacts", str(len(records))), ("Families", json.dumps(counts, sort_keys=True)),
        ("External static parser runs", str(tool_runs)),
        ("Coverage", "UEFI volumes/capsules, Windows/Linux/macOS driver indicators, Android/iOS packages, packet captures and raw boot/UART/JTAG-style evidence."),
        ("Boundary", "Static parsing/decompilation only; no host kernel loading, flashing, mobile installation or hardware writes."),
    ])
    ctx.log("OK", "reverse_family_analysis", f"analyzed {len(records)} family artifact(s)")
