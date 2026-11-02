"""Extended firmware-tool adapters for TBHM v3.9.7.5.

Supported integrations:
- EMBA static scan execution (explicit --emba) and report import.
- RouterSploit module-catalog inventory and operator-result import.
- Generic import of FirmAE/FIRMADYNE/FAT/FACT/QEMU and other firmware evidence.

RouterSploit exploit, credential and payload modules are never executed by this
phase.  Positive imported results remain leads until independently reproduced
and reviewed.  EMBA emulation/full requires an explicit isolation confirmation and an already-present locked-down container image.
"""
from __future__ import annotations

from core.version import SEMANTIC_VERSION

import ast
import json
import os
import re
import shutil
from pathlib import Path

from core import redteam_utils as RT
from core import reverse_utils as RU
from core.sandbox_manager import SandboxManager, SandboxError

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RS_MODULE_RE = re.compile(r"\b(?:exploits|scanners|creds|generic|payloads)/[A-Za-z0-9_./-]+")
RS_POSITIVE_RE = re.compile(r"(?i)(?:\[\+\]|vulnerable|success(?:ful)?|exploit(?:ed|able)?|credential(?:s)? found)")
RS_NEGATIVE_RE = re.compile(r"(?i)(?:\[-\]|not vulnerable|failed|no credentials found)")
SENSITIVE_RE = re.compile(r"(?i)(hard.?coded password|private key|default credential|command injection|path traversal|buffer overflow|authentication bypass)")
TEXT_SUFFIXES = {".txt", ".log", ".csv", ".json", ".jsonl", ".sarif", ".xml", ".html", ".htm", ".md", ".yaml", ".yml"}


def _iter_evidence(path: Path, max_files: int = 10_000, max_total_mb: int = 300):
    candidates = [path] if path.is_file() else path.rglob("*") if path.is_dir() else []
    total, count, limit = 0, 0, max_total_mb * 1024 * 1024
    for item in candidates:
        try:
            if not item.is_file() or item.is_symlink():
                continue
            size = item.stat().st_size
        except OSError:
            continue
        if size > 100 * 1024 * 1024 or total + size > limit or count >= max_files:
            break
        total += size; count += 1
        yield item


def _read_text(path: Path, limit: int = 5_000_000) -> str:
    try:
        return path.read_text(errors="ignore")[:limit]
    except OSError:
        return ""


def _find_emba(args) -> Path | None:
    raw = getattr(args, "emba_path", None) or os.environ.get("EMBA_HOME", "")
    candidates = []
    if raw:
        path = Path(raw).expanduser()
        candidates.extend([path, path / "emba", path / "emba.sh"] if path.is_dir() else [path])
    for command in ("emba", "emba.sh"):
        which = shutil.which(command)
        if which:
            candidates.append(Path(which))
    candidates.extend([
        Path("/opt/emba/emba"), Path("/opt/emba/emba.sh"),
        Path.home() / "emba" / "emba", Path.home() / "emba" / "emba.sh",
    ])
    for candidate in candidates:
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
        except OSError:
            continue
    return None


def _emba_mode(args) -> str:
    mode = str(getattr(args, "emba_mode", "static") or "static").lower()
    if getattr(args, "emba_emulation", False):
        mode = "emulation"
    return mode if mode in {"static", "sbom", "emulation", "full", "import"} else "static"




def _emba_profile_name(args) -> str:
    return {
        "static": "default-scan.emba",
        "sbom": "default-sbom.emba",
        "emulation": "default-scan-emulation.emba",
        "full": "default-scan-emulation.emba",
    }.get(_emba_mode(args), "default-scan.emba")

def _emba_profile(executable: Path, args) -> Path | None:
    supplied = getattr(args, "emba_profile", None)
    if supplied:
        path = Path(supplied).expanduser()
        return path.resolve() if path.is_file() else None
    home = executable.parent
    mode = _emba_mode(args)
    name = _emba_profile_name(args)
    candidate = home / "scan-profiles" / name
    return candidate.resolve() if candidate.is_file() else None


def _run_emba(ctx, out: Path) -> Path | None:
    if not getattr(ctx.args, "emba", False):
        return None
    mode = _emba_mode(ctx.args)
    if mode == "import":
        return None
    firmware = getattr(ctx.args, "firmware", None)
    if not firmware:
        ctx.log("WARN", "firmware_tooling_extended", "--emba requires --firmware")
        return None
    try:
        fw = Path(firmware).expanduser().resolve(strict=True)
    except Exception as exc:
        ctx.log("WARN", "firmware_tooling_extended", f"EMBA firmware path rejected: {exc}")
        return None
    sandbox_image = str(getattr(ctx.args, "emba_sandbox_image", "") or "").strip()
    isolated_required = mode in {"emulation", "full"}
    if isolated_required and not getattr(ctx.args, "confirm_isolated_execution", False):
        ctx.log("WARN", "firmware_tooling_extended", f"EMBA {mode} mode refused: add --confirm-isolated-execution")
        return None
    if isolated_required and not sandbox_image:
        ctx.log("WARN", "firmware_tooling_extended",
                f"EMBA {mode} mode refused: --emba-sandbox-image is required; host execution is not allowed")
        return None
    timeout = max(600, min(int(getattr(ctx.args, "emba_timeout", 14400)), 86400))
    if sandbox_image:
        if not getattr(ctx.args, "confirm_isolated_execution", False):
            ctx.log("WARN", "firmware_tooling_extended", "isolated EMBA mode requires --confirm-isolated-execution")
            return None
        manager = SandboxManager(out / "emba-sandbox")
        profile_name = _emba_profile_name(ctx.args)
        guest_cmd = ["emba", "-l", "/output", "-f", "/input/artifact", "-y",
                     "-p", f"/opt/emba/scan-profiles/{profile_name}"]
        try:
            result = manager.run_container(
                fw, sandbox_image, guest_cmd, engine=str(getattr(ctx.args, "emba_sandbox_engine", "auto")),
                timeout=timeout, memory_mb=8192 if isolated_required else 4096, cpus=4.0 if isolated_required else 2.0,
                pids=1024 if isolated_required else 512, network="none")
        except SandboxError as exc:
            ctx.log("WARN", "firmware_tooling_extended", f"isolated EMBA start failed: {exc}")
            RU.write_json(out / "EMBA_RUN.json", {"mode": mode, "sandboxed": True, "error": str(exc)})
            return None
        log_dir = Path(result.workspace)
        RU.write_json(out / "EMBA_RUN.json", {
            "command": guest_cmd, "returncode": result.returncode, "firmware": str(fw),
            "log_dir": str(log_dir), "profile": profile_name, "mode": mode,
            "sandboxed": True, "sandbox_policy": result.policy,
            "isolated_execution_confirmed": True, "stderr_tail": result.stderr[-4000:],
        })
        if result.returncode != 0:
            ctx.log("WARN", "firmware_tooling_extended", f"sandboxed EMBA returned {result.returncode}; importing partial evidence")
        return log_dir if log_dir.exists() else None

    executable = _find_emba(ctx.args)
    if executable is None:
        ctx.log("WARN", "firmware_tooling_extended", "EMBA executable not found; set --emba-path or EMBA_HOME")
        return None
    log_dir = out / "emba-run"
    log_dir.mkdir(parents=True, exist_ok=True)
    profile = _emba_profile(executable, ctx.args)
    cmd = [str(executable), "-l", str(log_dir), "-f", str(fw), "-y"]
    if profile:
        cmd += ["-p", str(profile)]
    ctx.log("INFO", "firmware_tooling_extended", f"starting host EMBA {mode} profile")
    rc, _stdout, stderr = ctx.runner.run(cmd, timeout=timeout, cwd=executable.parent, log_name="rt_firmware_emba")
    RU.write_json(out / "EMBA_RUN.json", {
        "command": cmd, "returncode": rc, "firmware": str(fw), "log_dir": str(log_dir),
        "profile": str(profile or ""), "mode": mode, "sandboxed": False,
        "emulation_requested": False, "isolated_execution_confirmed": False, "stderr_tail": stderr[-4000:],
    })
    if rc != 0:
        ctx.log("WARN", "firmware_tooling_extended", f"EMBA returned {rc}; importing any partial evidence")
    return log_dir if log_dir.exists() else None


def _summarize_emba(ctx, source: Path, out: Path) -> dict:
    records, cves, sensitive, reports, sboms = [], set(), set(), [], []
    for item in _iter_evidence(source):
        try:
            rel = item.relative_to(source).as_posix() if source.is_dir() else item.name
            size = item.stat().st_size
        except (OSError, ValueError):
            continue
        low = rel.lower()
        if low.endswith((".html", ".htm")) and ("report" in low or "index" in low):
            reports.append(rel)
        if any(token in low for token in ("cyclonedx", "spdx", "sbom")):
            sboms.append(rel)
        row = {"path": rel, "size": size}
        if size <= 20 * 1024 * 1024:
            try:
                row["sha256"] = RU.hashes(item)["sha256"]
            except OSError:
                pass
        records.append(row)
        if item.suffix.lower() in TEXT_SUFFIXES and size <= 10 * 1024 * 1024:
            text = _read_text(item)
            cves.update(x.upper() for x in CVE_RE.findall(text))
            sensitive.update(m.group(1).lower() for m in SENSITIVE_RE.finditer(text))
    summary = {
        "source": str(source), "files_indexed": len(records), "cves_referenced": sorted(cves)[:5000],
        "security_topics": sorted(sensitive), "html_reports": reports[:100], "sbom_files": sboms[:100],
        "execution_performed_by_tbhm": bool(getattr(ctx.args, "emba", False)),
        "confirmation_state": "lead_only",
    }
    RU.write_json(out / "EMBA_IMPORT_SUMMARY.json", summary)
    RT.write_csv(out / "emba-evidence-index.csv", records)
    if cves or sensitive:
        ctx.save_finding({
            "phase": "firmware_tooling_extended", "severity": "INFO", "confidence": "LOW",
            "title": "EMBA firmware-analysis leads imported",
            "target": str(source), "url": "",
            "description": "EMBA evidence contains vulnerability identifiers or security topics. Applicability and exploitability are not confirmed by import alone.",
            "evidence": f"CVE references={len(cves)}; topics={', '.join(sorted(sensitive)[:20])}",
            "impact": "Prioritization input for manual firmware validation.",
            "remediation": "Correlate each result to the exact component/version and reproduce the path before confirmation.",
            "cwe": "CWE-1104", "mrs_score": 20, "finding_class": "lead",
        })
    return summary


def _routersploit_root(args) -> Path | None:
    raw = getattr(args, "routersploit_root", None) or os.environ.get("ROUTERSPLOIT_HOME", "")
    candidates = []
    if raw:
        candidates.append(Path(raw).expanduser())
    candidates.extend([Path("/opt/routersploit"), Path("/usr/share/routersploit"), Path.home() / "routersploit"])
    for root in candidates:
        try:
            resolved = root.resolve()
            if (resolved / "routersploit" / "modules").is_dir():
                return resolved
        except OSError:
            continue
    return None


def _literal_info(tree: ast.AST) -> dict:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__info__":
                    try:
                        value = ast.literal_eval(node.value)
                        return value if isinstance(value, dict) else {}
                    except Exception:
                        return {}
    return {}


def _catalog_routersploit(root: Path, out: Path) -> dict:
    modules_root = root / "routersploit" / "modules"
    rows = []
    for item in modules_root.rglob("*.py"):
        if item.name == "__init__.py" or item.is_symlink():
            continue
        rel = item.relative_to(modules_root).with_suffix("").as_posix()
        category = rel.split("/", 1)[0]
        text = _read_text(item, 1_000_000)
        try:
            info = _literal_info(ast.parse(text, filename=str(item)))
        except SyntaxError:
            info = {}
        rows.append({
            "module": rel, "category": category, "name": str(info.get("name", "")),
            "description": str(info.get("description", "")),
            "cves": sorted({x.upper() for x in CVE_RE.findall(text)}),
            "sha256": RU.hashes(item)["sha256"],
            "active_execution_allowed": False,
        })
    summary = {
        "root": str(root), "modules": rows,
        "counts": {cat: sum(1 for row in rows if row["category"] == cat)
                   for cat in sorted({row["category"] for row in rows})},
        "policy": "catalog-only; exploit, credential, payload and scanner modules are not executed",
    }
    RU.write_json(out / "ROUTERSPLOIT_CATALOG.json", summary)
    RT.write_csv(out / "routersploit-module-catalog.csv", [{
        "module": r["module"], "category": r["category"], "name": r["name"],
        "description": r["description"], "cves": ",".join(r["cves"]), "sha256": r["sha256"],
    } for r in rows])
    return summary


def _import_routersploit_results(ctx, source: Path, out: Path) -> dict:
    positives, negatives, modules, sources = [], [], set(), []
    for item in _iter_evidence(source, max_files=2000, max_total_mb=200):
        if item.suffix.lower() not in TEXT_SUFFIXES and item.suffix:
            continue
        text = _read_text(item)
        if not text:
            continue
        sources.append(str(item))
        modules.update(RS_MODULE_RE.findall(text))
        for line in text.splitlines():
            if RS_POSITIVE_RE.search(line) and not RS_NEGATIVE_RE.search(line):
                positives.append({"source": str(item), "line": line[:1000]})
            elif RS_NEGATIVE_RE.search(line):
                negatives.append({"source": str(item), "line": line[:1000]})
    summary = {"source": str(source), "files": sources, "positive_lines": positives[:5000],
               "negative_lines": negatives[:5000], "modules_referenced": sorted(modules),
               "active_execution_performed_by_tbhm": False, "confirmation_state": "lead_only"}
    RU.write_json(out / "ROUTERSPLOIT_RESULTS_IMPORT.json", summary)
    if positives:
        ctx.save_finding({
            "phase": "firmware_tooling_extended", "severity": "MEDIUM", "confidence": "LOW",
            "title": "RouterSploit reported a potentially vulnerable embedded target",
            "target": str(source), "url": "",
            "description": "Positive RouterSploit output was imported. TBHM did not execute RouterSploit and does not treat scanner/exploit output as confirmation.",
            "evidence": "\n".join(row["line"] for row in positives[:40]),
            "impact": "Potential known router/IoT weakness requiring controlled reproduction and exact model/version validation.",
            "remediation": "Validate the module check in an authorized isolated lab, update firmware, disable exposed management services, and retest.",
            "cwe": "CWE-1104", "mrs_score": 45, "finding_class": "lead", "verified": False,
        })
    return summary


def _import_generic(source: Path, out: Path) -> dict:
    records, tool_hints, cves = [], set(), set()
    hints = {"firmae": "FirmAE", "firmadyne": "FIRMADYNE", "firmware-analysis-toolkit": "FAT",
             "fact": "FACT", "qemu": "QEMU", "avatar": "Avatar", "panda": "PANDA",
             "ghidra": "Ghidra", "binwalk": "Binwalk", "unblob": "unblob"}
    for item in _iter_evidence(source):
        try:
            rel = item.relative_to(source).as_posix() if source.is_dir() else item.name
            size = item.stat().st_size
        except (OSError, ValueError):
            continue
        low = rel.lower()
        for needle, label in hints.items():
            if needle in low:
                tool_hints.add(label)
        if item.suffix.lower() in TEXT_SUFFIXES and size <= 10 * 1024 * 1024:
            text = _read_text(item)
            cves.update(x.upper() for x in CVE_RE.findall(text))
        records.append({"path": rel, "size": size})
    summary = {"source": str(source), "files_indexed": len(records),
               "tool_hints": sorted(tool_hints), "cves_referenced": sorted(cves)[:5000],
               "confirmation_state": "observation"}
    RU.write_json(out / "EXTERNAL_FIRMWARE_EVIDENCE.json", summary)
    RT.write_csv(out / "external-firmware-evidence-index.csv", records)
    return summary


def run(ctx):
    out = RT.evidence_dir(ctx, "12b_firmware_tooling_extended")
    readiness = {
        "emba": str(_find_emba(ctx.args) or ""),
        "routersploit_root": str(_routersploit_root(ctx.args) or ""),
        "unblob": shutil.which("unblob") or "",
        "binwalk": shutil.which("binwalk") or "",
        "unsquashfs": shutil.which("unsquashfs") or "",
        "sasquatch": shutil.which("sasquatch") or "",
        "qemu_user": [x for x in (shutil.which("qemu-mipsel-static"), shutil.which("qemu-arm-static"),
                                    shutil.which("qemu-aarch64-static")) if x],
    }
    RU.write_json(out / "FIRMWARE_TOOL_READINESS.json", readiness)

    emba_source = _run_emba(ctx, out)
    supplied_emba = getattr(ctx.args, "emba_results", None)
    if supplied_emba:
        p = Path(supplied_emba).expanduser()
        if p.exists():
            emba_source = p.resolve()
    emba_summary = _summarize_emba(ctx, emba_source, out) if emba_source and emba_source.exists() else {}

    rs_root = _routersploit_root(ctx.args)
    catalog = _catalog_routersploit(rs_root, out) if rs_root and getattr(ctx.args, "routersploit_catalog", False) else {}
    rs_results = {}
    supplied_rs = getattr(ctx.args, "routersploit_results", None)
    if supplied_rs:
        p = Path(supplied_rs).expanduser()
        if p.exists():
            rs_results = _import_routersploit_results(ctx, p.resolve(), out)

    generic = {}
    supplied_generic = getattr(ctx.args, "firmware_tool_results", None)
    if supplied_generic:
        p = Path(supplied_generic).expanduser()
        if p.exists():
            generic = _import_generic(p.resolve(), out)

    index = {
        "version": SEMANTIC_VERSION, "readiness": readiness, "emba": emba_summary,
        "emba_mode": _emba_mode(ctx.args),
        "routersploit_catalog": {"modules": len(catalog.get("modules", [])), "counts": catalog.get("counts", {})},
        "routersploit_results": {"positives": len(rs_results.get("positive_lines", [])),
                                  "modules": len(rs_results.get("modules_referenced", []))},
        "generic_import": generic,
        "safety": {
            "routersploit_active_execution": False,
            "emba_emulation_requires_confirmation": True,
            "emba_emulation_requires_sandbox_image": True,
            "emba_host_execution_limited_to_static_or_sbom": True,
            "imported_tool_output_is_not_confirmation": True,
        },
    }
    RU.write_json(out / "FIRMWARE_TOOLING_INDEX.json", index)
    RT.write_md(out / "FIRMWARE_TOOLING_SUMMARY.md", "Extended Firmware Tooling", [
        ("EMBA", f"ready={bool(readiness['emba'])}; evidence imported={bool(emba_summary)}"),
        ("RouterSploit", f"catalog modules={len(catalog.get('modules', []))}; imported positive lines={len(rs_results.get('positive_lines', []))}"),
        ("Other evidence", f"tool hints={', '.join(generic.get('tool_hints', [])) or 'none'}"),
        ("Safety", "RouterSploit is catalog/import-only. EMBA host execution is limited to static/SBOM; emulation/full requires an already-present sandbox image plus explicit isolation confirmation. Tool output remains a lead until independently verified."),
    ])
    ctx.log("OK", "firmware_tooling_extended", "firmware tool readiness and supplied evidence normalized")
