"""Crash evidence normalization, deduplication, reproduction planning and input minimization."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, Callable

STACK_RE = re.compile(r"(?im)^\s*(?:#\d+\s+|at\s+|frame\s+#?\d+\s*:?)?(?:0x[0-9a-f]+\s+)?(?:in\s+)?([A-Za-z_?$][\w:<>~?$@.\-+]+)")
CRASH_RE = re.compile(r"(?i)(addresssanitizer|undefinedbehaviorsanitizer|segmentation fault|sigsegv|access violation|stack smashing|heap corruption|abort|signal\s+(?:6|11))")


def stack_signature(text: str) -> dict:
    frames = []
    for match in STACK_RE.finditer(text):
        frame = match.group(1).rstrip(":")
        lowered = frame.lower()
        if lowered in {"error", "warning", "thread", "program"} or CRASH_RE.fullmatch(frame):
            continue
        frames.append(frame)
        if len(frames) >= 12:
            break
    crash = CRASH_RE.search(text)
    normalized = "|".join(frames) or (crash.group(1).lower() if crash else text[:500])
    return {"hash": hashlib.sha256(normalized.encode(errors="ignore")).hexdigest(),
            "frames": frames, "crash_marker": crash.group(1) if crash else ""}


def collect_crashes(path: str | Path, max_files: int = 10000) -> dict:
    root = Path(path)
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.is_dir() else []
    records, groups = [], {}
    for file in files[:max_files]:
        if file.stat().st_size > 50_000_000:
            continue
        try:
            text = file.read_text(errors="ignore")
        except Exception:
            continue
        if not CRASH_RE.search(text) and not STACK_RE.search(text):
            continue
        signature = stack_signature(text)
        record = {"source": str(file), "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                  "size": file.stat().st_size, **signature, "excerpt": text[:10000]}
        records.append(record)
        groups.setdefault(signature["hash"], []).append(record)
    return {
        "schema": "tbhm.crash-triage/1.0", "crashes": records,
        "groups": [{"signature": key, "count": len(rows), "representative": rows[0],
                    "sources": [row["source"] for row in rows]} for key, rows in groups.items()],
        "counts": {"records": len(records), "unique": len(groups)},
    }


def delta_minimize(data: bytes, reproduces: Callable[[bytes], bool], max_tests: int = 500) -> tuple[bytes, int]:
    """Generic ddmin-style reducer. The caller must execute reproduces in a sandbox."""
    if not data:
        return data, 0
    current = data
    n = 2
    tests = 0
    while len(current) >= 2 and tests < max_tests:
        chunk = max(1, len(current) // n)
        reduced = False
        for start in range(0, len(current), chunk):
            if tests >= max_tests:
                break
            candidate = current[:start] + current[min(len(current), start + chunk):]
            tests += 1
            if candidate and reproduces(candidate):
                current = candidate
                n = max(2, n - 1)
                reduced = True
                break
        if not reduced:
            if n >= len(current):
                break
            n = min(len(current), n * 2)
    return current, tests


def reproduce_and_minimize(manager, artifact: str | Path, case_path: str | Path, image: str, command: list[str], *,
                           engine: str = "auto", timeout: int = 60, max_tests: int = 100,
                           memory_mb: int = 1024, cpus: float = 1.0, pids: int = 128) -> dict:
    """Reproduce and ddmin one crash input inside a locked-down container.

    The guest command must consume ``/input/case``.  A candidate is retained only
    when it preserves the baseline stack signature; when no stack is available,
    the same crash marker and non-zero process status are required.
    """
    artifact = Path(artifact).expanduser().resolve(strict=True)
    original = Path(case_path).expanduser().resolve(strict=True)
    if not original.is_file() or original.is_symlink():
        raise ValueError("crash input must be a regular non-symlink file")
    if not command or not any("/input/case" in str(arg) for arg in command):
        raise ValueError("crash command must reference /input/case")
    baseline = manager.run_container(artifact, image, command, engine=engine, timeout=timeout,
                                     memory_mb=memory_mb, cpus=cpus, pids=pids, network="none",
                                     case_file=original)
    baseline_text = (baseline.stdout or "") + "\n" + (baseline.stderr or "")
    baseline_sig = stack_signature(baseline_text)
    baseline_crashed = baseline.returncode != 0 or bool(CRASH_RE.search(baseline_text))
    if not baseline_crashed:
        return {"schema": "tbhm.crash-minimization/1.0", "reproduced": False,
                "reason": "baseline input did not reproduce a crash", "baseline": baseline.to_dict()}
    temp_root = Path(manager.output) / "crash-minimization"
    temp_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidate_path = temp_root / "candidate.bin"
    executions = []

    def reproduces(data: bytes) -> bool:
        candidate_path.write_bytes(data)
        result = manager.run_container(artifact, image, command, engine=engine, timeout=timeout,
                                       memory_mb=memory_mb, cpus=cpus, pids=pids, network="none",
                                       case_file=candidate_path)
        text = (result.stdout or "") + "\n" + (result.stderr or "")
        signature = stack_signature(text)
        crashed = result.returncode != 0 or bool(CRASH_RE.search(text))
        same = crashed and (signature["hash"] == baseline_sig["hash"] if baseline_sig["frames"] else
                            signature.get("crash_marker", "").lower() == baseline_sig.get("crash_marker", "").lower())
        executions.append({"bytes": len(data), "returncode": result.returncode, "timed_out": result.timed_out,
                           "signature": signature, "preserved": same})
        return same

    data = original.read_bytes()
    minimized, tests = delta_minimize(data, reproduces, max_tests=max(1, min(int(max_tests), 1000)))
    minimized_path = temp_root / "minimized.bin"
    minimized_path.write_bytes(minimized)
    return {
        "schema": "tbhm.crash-minimization/1.0", "reproduced": True,
        "baseline_signature": baseline_sig, "baseline_returncode": baseline.returncode,
        "original": {"path": str(original), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "minimized": {"path": str(minimized_path), "bytes": len(minimized), "sha256": hashlib.sha256(minimized).hexdigest()},
        "tests": tests, "reduction_percent": round((1 - len(minimized) / max(1, len(data))) * 100, 2),
        "executions": executions, "sandbox_policy": baseline.policy,
    }


def write_plan(result: dict, out: str | Path, command: list[str] | None = None) -> Path:
    out = Path(out)
    plan = {
        "schema": "tbhm.crash-reproduction-plan/1.0", "unique_crashes": result.get("counts", {}).get("unique", 0),
        "command": command or [], "requires_disposable_sandbox": True,
        "steps": [
            "Bind the target artifact and one crash input read-only into the sandbox.",
            "Disable network unless the parser strictly requires an isolated test service.",
            "Capture exit status, signal, stderr, stack trace, module bases and input SHA-256.",
            "Re-run at least three times before marking reproducible.",
            "Use delta minimization only when the same stack signature is preserved.",
        ],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return out
