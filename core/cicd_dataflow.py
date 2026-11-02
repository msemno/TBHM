"""Native static CI/CD workflow and build-file dataflow/trust checks.

The scanner is deliberately static: it inventories and reads bounded local files,
but never executes workflow commands, build scripts, package scripts, or images.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

UNTRUSTED = [
    re.compile(r"\$\{\{\s*github\.event\.(?:pull_request|issue|comment|discussion|review|head_commit)[^}]*\}\}"),
    re.compile(r"\$\{\{\s*inputs\.[^}]+\}\}"),
]
SINKS = [
    (re.compile(r"(?m)^\s*(?:-\s*)?run:\s*(.+)$"), "shell_execution"),
    (re.compile(r"(?m)^\s*(?:-\s*)?script:\s*(.+)$"), "script_execution"),
    (re.compile(r"(?m)^\s*(?:-\s*)?command:\s*(.+)$"), "command_execution"),
]

# Union of the v3.9.6 pipeline/build rules and the v3.9.7.2 trust/dataflow rules.
# Rules remain observations/leads; none asserts exploitability by itself.
STATIC_RULES = [
    (re.compile(r"\bpull_request_target\b"), "pull_request_target trust boundary requires review", "HIGH", "CWE-829"),
    (re.compile(r"uses:\s*[^\s]+@(main|master|latest|dev)\b", re.I), "Third-party action uses a mutable reference", "MEDIUM", "CWE-494"),
    (re.compile(r"(?m)^\s*permissions:\s*write-all\s*$", re.I), "Workflow grants write-all permissions", "HIGH", "CWE-732"),
    (re.compile(r"persist-credentials:\s*true", re.I), "Checkout persists repository credentials", "MEDIUM", "CWE-522"),
    (re.compile(r"\$\{\{\s*github\.event\.[^}]+\}\}"), "Untrusted event context may reach a workflow script", "HIGH", "CWE-94"),
    (re.compile(r"runs-on:\s*\[?[^\n]*self-hosted", re.I), "Workflow uses a self-hosted runner", "MEDIUM", "CWE-250"),
    (re.compile(r"id-token:\s*write", re.I), "Workflow can request an OIDC token; trust conditions require review", "MEDIUM", "CWE-284"),
    (re.compile(r"privileged\s*:\s*true", re.I), "CI job/container runs privileged", "HIGH", "CWE-250"),
    (re.compile(r"/var/run/docker\.sock", re.I), "Build job mounts the Docker daemon socket", "HIGH", "CWE-250"),
    (re.compile(r"(?i)(?:curl|wget)[^\n|]+\|\s*(?:sh|bash)"), "Build script executes remotely downloaded shell content", "HIGH", "CWE-494"),
    (re.compile(r"(?i)artifact[^\n]*(?:extract|unzip|tar)"), "Artifact extraction path requires traversal and trust validation", "MEDIUM", "CWE-22"),
]

BUILD_FILE_NAMES = {
    "Jenkinsfile",
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "Dockerfile",
    "Makefile",
    "package.json",
    "pyproject.toml",
}
WORKFLOW_PREFIXES = (".github/workflows/", ".circleci/")
WORKFLOW_SUFFIXES = (".workflow.yml", ".workflow.yaml")


def workflow_files(root: Path):
    """Yield bounded workflow and build-definition files in stable path order."""
    base = Path(root)
    candidates = []
    for path in base.rglob("*"):
        try:
            if not path.is_file() or path.stat().st_size > 3_000_000:
                continue
            rel = path.relative_to(base).as_posix()
        except (OSError, ValueError):
            continue
        if (
            path.name in BUILD_FILE_NAMES
            or rel.startswith(WORKFLOW_PREFIXES)
            or rel.endswith(WORKFLOW_SUFFIXES)
        ):
            candidates.append(path)
    yield from sorted(candidates, key=lambda item: item.relative_to(base).as_posix())


def _context(text: str, start: int, end: int, *, radius: int = 250, limit: int = 1600) -> str:
    return text[max(0, start - radius):min(len(text), end + radius)][:limit]


def analyze_text(text: str, *, path: str) -> list[dict]:
    rows = []
    for regex, title, severity, cwe in STATIC_RULES:
        for match in list(regex.finditer(text))[:100]:
            rows.append({
                "path": path,
                "title": title,
                "severity": severity,
                "cwe": cwe,
                "line": text.count("\n", 0, match.start()) + 1,
                "evidence": _context(text, match.start(), match.end()),
                "matched_text": match.group(0)[:1000],
                "kind": "static_rule",
                "status": "lead",
                "confirmed": False,
            })
    untrusted = []
    for regex in UNTRUSTED:
        untrusted.extend(regex.finditer(text))
    sinks = []
    for regex, kind in SINKS:
        sinks.extend((match, kind) for match in regex.finditer(text))
    for source in untrusted[:200]:
        source_line = text.count("\n", 0, source.start()) + 1
        for sink, kind in sinks[:300]:
            sink_line = text.count("\n", 0, sink.start()) + 1
            # Conservative YAML-level flow: same step/nearby block and the exact
            # untrusted expression is present in the command-bearing line.
            if 0 <= sink_line - source_line <= 20 and source.group(0) in sink.group(0):
                rows.append({
                    "path": path,
                    "title": "Untrusted workflow context reaches a command sink",
                    "severity": "HIGH",
                    "cwe": "CWE-94",
                    "line": sink_line,
                    "evidence": _context(text, sink.start(), sink.end(), radius=350, limit=1800),
                    "source": source.group(0),
                    "sink": kind,
                    "kind": "dataflow",
                    "status": "supported_static",
                    "prerequisites": [
                        "attacker can influence the referenced event/input field",
                        "workflow trigger and effective permissions permit the step to run",
                    ],
                    "confirmed": False,
                })
    seen = set()
    out = []
    for row in rows:
        fp = hashlib.sha256(
            f"{row.get('path')}|{row.get('title')}|{row.get('line')}|{row.get('evidence')}".encode()
        ).hexdigest()
        if fp in seen:
            continue
        seen.add(fp)
        row["fingerprint"] = fp
        out.append(row)
    return out


def analyze_tree(root: str | Path, *, max_files: int = 5000) -> dict:
    base = Path(root)
    files = list(workflow_files(base))[:max_files]
    findings = []
    provenance = []
    read_errors = []
    for path in files:
        rel = path.relative_to(base).as_posix()
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8", errors="replace")
        except OSError as exc:
            read_errors.append({"path": rel, "error": f"{type(exc).__name__}: {exc}"})
            continue
        findings.extend(analyze_text(text, path=rel))
        provenance.append({
            "path": rel,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "file_class": "build" if path.name in {"Dockerfile", "Makefile", "package.json", "pyproject.toml"} else "workflow",
        })
    return {
        "schema_version": "1",
        "files": provenance,
        "findings": findings,
        "read_errors": read_errors,
        "summary": {"files": len(files), "readable_files": len(provenance), "findings": len(findings), "read_errors": len(read_errors)},
        "boundary": "Static analysis only. Workflow and build commands are never executed.",
    }
