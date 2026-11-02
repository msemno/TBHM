#!/usr/bin/env python3
"""Build a local compatibility baseline from previously extracted TBHM trees.

This developer utility never downloads or executes anything. It inventories CLI
flags, orchestrator phases, public module symbols, and retained source/config
paths so later releases can detect accidental deletion during refactors.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    yaml = None
from pathlib import Path

MEANINGFUL_EXTENSIONS = {
    ".py", ".sh", ".yaml", ".yml", ".json", ".md", ".txt", ".toml",
    ".ini", ".cfg", ".sql", ".html", ".j2", ".csv",
}
IGNORE_PARTS = {"__pycache__", ".git", ".pytest_cache", "results", "result", "output", "outputs"}


def python_tree(path: Path):
    try:
        return ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, SyntaxError):
        return None


def cli_flags(root: Path) -> set[str]:
    flags: set[str] = set()
    for path in root.rglob("*.py"):
        if any(part in IGNORE_PARTS for part in path.parts):
            continue
        tree = python_tree(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "add_argument":
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("-"):
                    flags.add(arg.value)
    return flags


def phase_order(root: Path) -> list[str]:
    path = root / "tbhm.py"
    tree = python_tree(path)
    if tree is None:
        return []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "PHASE_ORDER" for target in targets):
                value = node.value
                try:
                    result = ast.literal_eval(value)
                except Exception:
                    return []
                return [str(item) for item in result if isinstance(item, str)]
    return []


def public_symbols(root: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for path in root.rglob("*.py"):
        if any(part in IGNORE_PARTS for part in path.parts):
            continue
        tree = python_tree(path)
        if tree is None:
            continue
        names: set[str] = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
                if isinstance(node, ast.ClassDef):
                    names.update(
                        child.name for child in node.body
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    )
        if names:
            result[path.relative_to(root).as_posix()] = sorted(names)
    return result



IDENTIFIER_KEYS = {
    "id", "name", "phase", "tool", "adapter_id", "framework",
    "slug", "capability", "bundle", "tag", "rule_id", "key",
}


def load_structured(path: Path):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.suffix.lower() == ".json":
            return json.loads(text)
        if yaml is not None and path.suffix.lower() in {".yaml", ".yml"}:
            return yaml.safe_load(text)
    except Exception:
        return None
    return None


def collect_identifiers(value) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in IDENTIFIER_KEYS and isinstance(child, (str, int, float, bool)):
                result.add(f"{str(key).lower()}={child}")
            result.update(collect_identifiers(child))
    elif isinstance(value, list):
        for child in value:
            result.update(collect_identifiers(child))
    return result


def structured_identifiers(root: Path) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for pattern in ("*.json", "*.yaml", "*.yml"):
        for path in root.rglob(pattern):
            if any(part in IGNORE_PARTS for part in path.parts):
                continue
            identifiers = collect_identifiers(load_structured(path))
            if identifiers:
                result[path.relative_to(root).as_posix()] = identifiers
    return result


def line_item_sets(root: Path) -> dict[str, set[str]]:
    """Preserve payload and wordlist entries while allowing comments/reordering."""
    result: dict[str, set[str]] = {}
    for directory in ("payloads", "wordlists"):
        base = root / directory
        if not base.is_dir():
            continue
        for path in base.rglob("*.txt"):
            values = {
                line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
            result[path.relative_to(root).as_posix()] = values
    return result


def meaningful_paths(root: Path) -> set[str]:
    paths: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in MEANINGFUL_EXTENSIONS:
            continue
        rel = path.relative_to(root)
        if any(part in IGNORE_PARTS for part in rel.parts):
            continue
        if rel.as_posix().startswith(("reports/", "evidence/")):
            continue
        paths.add(rel.as_posix())
    return paths


def roots_from(work: Path) -> list[tuple[str, Path]]:
    roots: list[tuple[str, Path]] = []
    for archive in sorted(path for path in work.iterdir() if path.is_dir()):
        candidates = sorted(path for path in archive.iterdir() if path.is_dir() and path.name.startswith("TBHM-v"))
        if candidates:
            roots.append((archive.name, candidates[0]))
    return roots


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True, help="Directory containing extracted version folders")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    archives = roots_from(args.work)
    all_flags: set[str] = set()
    all_phases: set[str] = set()
    all_paths: set[str] = set()
    all_symbols: dict[str, set[str]] = {}
    all_identifiers: dict[str, set[str]] = {}
    all_line_items: dict[str, set[str]] = {}
    versions = []
    for name, root in archives:
        flags = cli_flags(root)
        phases = phase_order(root)
        paths = meaningful_paths(root)
        symbols = public_symbols(root)
        identifiers = structured_identifiers(root)
        line_items = line_item_sets(root)
        all_flags.update(flags)
        all_phases.update(phases)
        all_paths.update(paths)
        for rel, names in symbols.items():
            all_symbols.setdefault(rel, set()).update(names)
        for rel, values in identifiers.items():
            all_identifiers.setdefault(rel, set()).update(values)
        for rel, values in line_items.items():
            all_line_items.setdefault(rel, set()).update(values)
        versions.append({
            "archive": name,
            "root": root.name,
            "cli_flags": len(flags),
            "phases": len(phases),
            "meaningful_paths": len(paths),
        })

    payload = {
        "schema": "tbhm-compatibility-baseline/v1",
        "release": "3.9.6.1-regression-restored",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_versions": versions,
        "cli_flags": sorted(all_flags),
        "phase_names": sorted(all_phases),
        "meaningful_paths": sorted(all_paths),
        "public_symbols": {rel: sorted(names) for rel, names in sorted(all_symbols.items())},
        "structured_identifiers": {rel: sorted(values) for rel, values in sorted(all_identifiers.items())},
        "payload_wordlist_entries": {rel: sorted(values) for rel, values in sorted(all_line_items.items())},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["content_sha256"] = hashlib.sha256(canonical).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"wrote {args.output}: {len(all_flags)} flags, {len(all_phases)} phases, "
        f"{len(all_paths)} paths, {sum(len(v) for v in all_identifiers.values())} structured IDs, "
        f"{sum(len(v) for v in all_line_items.values())} payload/wordlist entries"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
