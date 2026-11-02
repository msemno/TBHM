#!/usr/bin/env python3
"""Build the deterministic TBHM v3.9.7.4 release manifest."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

RELEASE = "3.9.7.4-universal-reverse"
ROOT_NAME = "TBHM-v3.9.7.4-universal-reverse"
EXCLUDED_DIRS = {"__pycache__", ".git", ".pytest_cache", "results"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".swp", ".tmp"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def files(root: Path, output_name: str):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix in EXCLUDED_SUFFIXES or path.name == output_name:
            continue
        yield path


def cli_flags_from_file(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, SyntaxError):
        return set()
    flags = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "add_argument":
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("-"):
                flags.add(arg.value)
    return flags


def phase_names(root: Path) -> list[str]:
    namespace = {}
    source = (root / "tbhm.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "PHASE_ORDER" for t in node.targets):
            return list(ast.literal_eval(node.value))
    return []


def build(root: Path, output: Path) -> dict:
    rows = []
    ext_counts = Counter()
    project_flags = set()
    for path in files(root, output.name):
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower().lstrip(".") or "no_extension"
        ext_counts[suffix] += 1
        rows.append({
            "path": rel,
            "size": path.stat().st_size,
            "sha256": sha256(path),
            "executable": bool(path.stat().st_mode & 0o111),
            "type": suffix,
        })
        if path.suffix == ".py":
            project_flags.update(cli_flags_from_file(path))
    primary_flags = sorted(cli_flags_from_file(root / "tbhm.py"))
    phases = phase_names(root)
    return {
        "release": RELEASE,
        "generated_at": datetime.now(timezone(timedelta(hours=3))).isoformat(timespec="seconds"),
        "root_name": ROOT_NAME,
        "summary": {
            "files": len(rows),
            "bytes": sum(row["size"] for row in rows),
            "primary_cli_options": len(primary_flags),
            "project_wide_cli_option_strings": len(project_flags),
            "phase_modules": len(phases),
        },
        "counts_by_extension": dict(sorted(ext_counts.items())),
        "primary_cli_options": primary_flags,
        "project_wide_cli_option_strings": sorted(project_flags),
        "phase_modules": phases,
        "files": rows,
        "notes": [
            "Manifest excludes itself, generated caches, test result directories and bytecode.",
            "Historical release manifests remain packaged as immutable compatibility records.",
            "RouterSploit integration is catalog/import-only; no RouterSploit module execution is implemented.",
            "EMBA execution is explicit; EMBA emulation additionally requires isolated-execution confirmation.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output", default="RELEASE_MANIFEST-v3.9.7.4.json")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve(strict=True)
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    data = build(root, output)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {output} ({data['summary']['files']} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
