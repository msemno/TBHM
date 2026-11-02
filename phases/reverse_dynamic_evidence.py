"""Phase 3: normalize dynamic-analysis evidence from approved sandboxes (v3.9.2).

This phase never launches the supplied artifact. It imports logs/exports from GDB,
WinDbg, x64dbg, Frida, CAPE/Cuckoo, QEMU, Unicorn, ANY.RUN, Hybrid Analysis,
Joe Sandbox, VirusTotal, or equivalent controlled environments.
"""
from __future__ import annotations

from core.version import SEMANTIC_VERSION

import csv
import json
import re
from pathlib import Path

from core import redteam_utils as RT
from core import reverse_utils as RU

CRASH_RE = re.compile(r"(?i)(segmentation fault|access violation|stack smashing|heap corruption|signal 11|sigsegv|exception code\s*0xc0000005)")
CONTROL_RE = re.compile(r"(?i)(?:eip|rip|pc)\s*(?:=|:)\s*(?:0x)?(?:41414141|42424242|43434343|[a-f0-9]{8,16}).{0,120}(?:controlled|pattern|cyclic)")
API_RE = re.compile(r"(?i)\b(CreateProcess[AW]?|WriteProcessMemory|CreateRemoteThread|VirtualAlloc(?:Ex)?|VirtualProtect|InternetOpenUrl[AW]?|WinHttpOpenRequest|RegSetValueEx[AW]?|NtCreateFile|CreateFile[AW]?|connect|send|recv|execve|system|popen)\b")
NETWORK_RE = re.compile(r"(?i)\b(?:https?://[^\s\"']+|(?:\d{1,3}\.){3}\d{1,3}:\d{1,5})")
FILE_RE = re.compile(r"(?i)(?:[A-Z]:\\[^\r\n\"']+|/(?:tmp|etc|var|home|root|proc|sys)/[^\s\"']+)")
REG_RE = re.compile(r"(?i)HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS)|HKLM\\|HKCU\\")


def _text_files(path: Path, max_files: int, max_mb: int):
    candidates = [path] if path.is_file() else path.rglob("*") if path.is_dir() else []
    total = 0
    count = 0
    max_bytes = max_mb * 1024 * 1024
    for item in candidates:
        if not item.is_file():
            continue
        try:
            size = item.stat().st_size
        except OSError:
            continue
        if size > 100_000_000 or total + size > max_bytes or count >= max_files:
            break
        total += size; count += 1
        yield item


def _flatten_json(value, out, prefix=""):
    if isinstance(value, dict):
        for key, child in value.items():
            _flatten_json(child, out, f"{prefix}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _flatten_json(child, out, f"{prefix}/{index}")
    elif isinstance(value, (str, int, float, bool)):
        out.append(f"{prefix}: {value}")


def _load_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl", ".sarif"}:
        lines = []
        try:
            if suffix == ".jsonl":
                for line in path.read_text(errors="ignore").splitlines()[:20000]:
                    try: _flatten_json(json.loads(line), lines)
                    except Exception: lines.append(line)
            else:
                _flatten_json(json.loads(path.read_text(errors="ignore")), lines)
            return "\n".join(lines)[:5_000_000]
        except Exception:
            return path.read_text(errors="ignore")[:5_000_000]
    if suffix == ".csv":
        try:
            rows = []
            with path.open("r", errors="ignore", newline="") as handle:
                for row in list(csv.reader(handle))[:20000]: rows.append(" | ".join(row))
            return "\n".join(rows)[:5_000_000]
        except Exception:
            pass
    return path.read_text(errors="ignore")[:5_000_000]




def _load_verification_manifest(path_value) -> dict[str, dict]:
    """Load explicit operator-reviewed verification decisions keyed by SHA-256.

    Accepted schema:
      {"evidence": [{"sha256": "...", "controlled": true,
                     "reproduced": true, "approved": true,
                     "verification_method": "..."}]}

    Merely containing crash/control text is never enough to confirm an imported
    result; a matching hash-bound decision is also required.
    """
    if not path_value:
        return {}
    path = Path(path_value)
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return {}
    items = raw.get("evidence", []) if isinstance(raw, dict) else raw if isinstance(raw, list) else []
    out: dict[str, dict] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        digest = str(item.get("sha256") or item.get("source_sha256") or "").lower().strip()
        method = str(item.get("verification_method") or "").strip()
        if (re.fullmatch(r"[a-f0-9]{64}", digest) and item.get("controlled") is True
                and item.get("reproduced") is True and item.get("approved") is True and method):
            out[digest] = item
    return out

def _emit(ctx, title, severity, target, evidence, cwe, verified=False, method="", artifact_id=""):
    finding = {
        "phase": "reverse_dynamic_evidence", "severity": severity,
        "confidence": "HIGH" if verified else "LOW", "title": title[:180],
        "target": str(target), "url": "",
        "description": "Dynamic behavior observed in imported sandbox/debugger/instrumentation evidence. TBHM did not execute the artifact.",
        "evidence": str(evidence)[:5000],
        "impact": "Runtime evidence may confirm a reachable crash, unsafe API behavior, persistence, file/registry modification, or network communication. Security impact depends on attacker control and process privileges.",
        "remediation": "Fix the reachable code path, enable exploit mitigations, validate inputs and lengths, remove unauthorized persistence/network behavior, then repeat the controlled sandbox test.",
        "cwe": cwe, "mrs_score": 70 if verified else 45,
        "finding_class": "confirmed" if verified else "lead",
        "verified": bool(verified), "verification_method": method,
        "artifact_id": artifact_id,
    }
    return ctx.save_finding(finding)


def run(ctx):
    supplied = getattr(ctx.args, "reverse_dynamic_results", None)
    if not supplied:
        return
    out = RT.evidence_dir(ctx, "25c_reverse_dynamic_evidence")
    root = Path(supplied)
    max_files = max(1, min(int(getattr(ctx.args, "reverse_max_files", 50)), 1000))
    max_mb = max(1, min(int(getattr(ctx.args, "reverse_evidence_max_mb", 200)), 4096))
    records = []
    findings = 0
    manifest_path = getattr(ctx.args, "reverse_verification_manifest", None)
    verification = _load_verification_manifest(manifest_path)
    manifest_resolved = Path(manifest_path).resolve() if manifest_path and Path(manifest_path).is_file() else None
    artifacts = list(RU.iter_files(
        getattr(ctx.args, "binary_path", None),
        getattr(ctx.args, "reverse_max_files", 50),
        getattr(ctx.args, "reverse_max_file_mb", 200),
    ))
    default_artifact_id = RU.artifact_id(artifacts[0]) if len(artifacts) == 1 else ""

    for source in _text_files(root, max_files, max_mb):
        if manifest_resolved and source.resolve() == manifest_resolved:
            continue
        text = _load_text(source)
        crashes = [m.group(0) for m in CRASH_RE.finditer(text)][:50]
        controls = [m.group(0) for m in CONTROL_RE.finditer(text)][:20]
        apis = sorted({m.group(1) for m in API_RE.finditer(text)})[:200]
        networks = sorted({m.group(0)[:500] for m in NETWORK_RE.finditer(text)})[:200]
        files = sorted({m.group(0)[:500] for m in FILE_RE.finditer(text)})[:200]
        registry = sorted({m.group(0)[:500] for m in REG_RE.finditer(text)})[:100]
        source_hash = RU.hashes(source)["sha256"]
        manifest_entry = verification.get(source_hash.lower())
        artifact_id = default_artifact_id
        if manifest_entry:
            digest = str(manifest_entry.get("artifact_sha256") or "").lower().strip()
            explicit_id = str(manifest_entry.get("artifact_id") or "").strip()
            if re.fullmatch(r"[a-f0-9]{64}", digest):
                artifact_id = "sha256:" + digest
            elif re.fullmatch(r"sha256:[a-f0-9]{64}", explicit_id.lower()):
                artifact_id = explicit_id.lower()
        record = {
            "source": str(source), "sha256": source_hash, "artifact_id": artifact_id,
            "crash_markers": crashes, "instruction_control_markers": controls,
            "api_calls": apis, "network_indicators": networks,
            "file_indicators": files, "registry_indicators": registry,
            "verification_manifest_match": bool(manifest_entry),
            "verification_manifest_metadata": {
                "reviewer": manifest_entry.get("reviewer"),
                "timestamp": manifest_entry.get("timestamp"),
                "scope_reference": manifest_entry.get("scope_reference"),
                "verification_method": manifest_entry.get("verification_method"),
            } if manifest_entry else {},
            "source_excerpt": text[:10000], "execution_performed_by_tbhm": False,
        }
        records.append(record)
        stem = RU.safe_stem(source)
        RU.write_json(out / f"{stem}.dynamic.json", record)

        if crashes:
            control_marker = bool(controls)
            verified = bool(control_marker and manifest_entry)
            if verified:
                title = "Controlled instruction-pointer/crash evidence independently approved"
            elif control_marker:
                title = "[LEAD] Controlled crash marker in imported evidence (verification manifest required)"
            else:
                title = "[LEAD] Runtime crash observed in sandbox evidence"
            findings += 1
            evidence_parts = crashes + controls
            if manifest_entry:
                evidence_parts.append("Hash-bound verification manifest: " + json.dumps({
                    "reviewer": manifest_entry.get("reviewer"),
                    "timestamp": manifest_entry.get("timestamp"),
                    "scope_reference": manifest_entry.get("scope_reference"),
                    "verification_method": manifest_entry.get("verification_method"),
                }, ensure_ascii=False))
            _emit(ctx, title, "HIGH" if verified else "MEDIUM", source,
                  "\n".join(evidence_parts[:31]), "CWE-119", verified=verified,
                  method=str(manifest_entry.get("verification_method")) if verified else "",
                  artifact_id=artifact_id)
        if apis:
            findings += 1
            _emit(ctx, "[LEAD] Sensitive runtime API calls observed", "MEDIUM", source,
                  ", ".join(apis), "CWE-912", artifact_id=artifact_id)
        if networks:
            findings += 1
            _emit(ctx, "[LEAD] Runtime network communication indicators", "MEDIUM", source,
                  "\n".join(networks[:50]), "CWE-319", artifact_id=artifact_id)
        if registry:
            findings += 1
            _emit(ctx, "[LEAD] Runtime registry modification indicators", "LOW", source,
                  "\n".join(registry[:50]), "CWE-732", artifact_id=artifact_id)
        if files:
            findings += 1
            _emit(ctx, "[LEAD] Runtime filesystem access/modification indicators", "LOW", source,
                  "\n".join(files[:50]), "CWE-73", artifact_id=artifact_id)

    RU.write_json(out / "reverse_dynamic_index.json", {
        "version": SEMANTIC_VERSION, "sources": records, "findings": findings,
        "supported_evidence": ["Frida", "GDB/pwndbg/gef", "WinDbg", "x64dbg", "CAPE/Cuckoo", "QEMU/Unicorn", "ANY.RUN", "Hybrid Analysis", "Joe Sandbox", "VirusTotal"],
        "verification_manifest": str(manifest_path or ""),
        "verification_entries_accepted": len(verification),
        "execution_performed_by_tbhm": False,
    })
    RT.write_md(out / "REVERSE_DYNAMIC_SUMMARY.md", "Reverse Dynamic Evidence", [
        ("Sources", str(len(records))), ("Findings", str(findings)),
        ("Methodology", "Import and normalize debugger, instrumentation, sandbox, filesystem, registry, API-call, network, and crash evidence."),
        ("Confirmation rule", "A crash is confirmed only when the evidence includes a controlled instruction-pointer/pattern marker and a matching SHA-256-bound verification manifest entry marked controlled, reproduced, and approved."),
        ("Safety", "TBHM did not execute the artifact. Dynamic execution must occur in an operator-controlled isolated sandbox."),
    ])
    ctx.log("OK", "reverse_dynamic_evidence", f"normalized {len(records)} dynamic evidence source(s)")
