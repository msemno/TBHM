#!/usr/bin/env python3
"""Validate the TBHM v4 tree before packaging or shipping.

Runs, in order: Python compileall, core+phase import sweep, RELEASE_MANIFEST
verification via the package_verifier, and a phase-coverage check (every
dispatched phase resolves to a module with run()). Prints a PASS/FAIL summary
and exits non-zero on any failure. Run from the package root:

    python3 scripts/validate_v4_release.py
"""
from __future__ import annotations

import ast
import compileall
import importlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def check_compile() -> tuple[bool, str]:
    ok = compileall.compile_dir(str(ROOT), quiet=1, force=True, rx=re.compile(r"/(?:\.venv|\.git|__pycache__)/"))
    return bool(ok), "python compileall"


def check_imports() -> tuple[bool, str]:
    fails = []
    for sub in ("core", "phases"):
        for p in sorted((ROOT / sub).rglob("*.py")):
            if p.stem == "__init__":
                continue
            rel = p.relative_to(ROOT).with_suffix("")
            mod = ".".join(rel.parts)
            try:
                importlib.import_module(mod)
            except Exception as exc:  # noqa: BLE001
                fails.append(f"{mod}: {exc}")
    return (not fails), (f"{len(fails)} import failures: {fails[:5]}" if fails else "all modules import")


def check_manifest() -> tuple[bool, str]:
    from core.package_verifier import verify_tree
    r = verify_tree(str(ROOT), None, True, require_manifest=True)
    return bool(r["passed"]), (f"issues: {r['issues'][:5]}" if r["issues"]
                               else f"{r['manifest_entries_checked']} entries verified")


def check_phase_coverage() -> tuple[bool, str]:
    src = (ROOT / "tbhm.py").read_text()
    tree = ast.parse(src)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "PHASE_ORDER":
                    names |= {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
                if isinstance(t, ast.Name) and t.id == "EXTENSION_PHASE_ANCHORS":
                    names |= {k.value for k in node.value.keys}
    phase_files = {p.stem for p in (ROOT / "phases").glob("*.py")}
    missing = [n for n in names if n not in phase_files and n != "preflight"]
    no_run = []
    for n in names:
        f = ROOT / "phases" / f"{n}.py"
        if f.is_file() and "def run" not in f.read_text():
            no_run.append(n)
    if missing or no_run:
        return False, f"missing modules={missing} no run()={no_run}"
    return True, f"{len(names)} phases resolve to modules with run()"


def main() -> int:
    checks = [("compile", check_compile), ("imports", check_imports),
              ("manifest", check_manifest), ("phase_coverage", check_phase_coverage)]
    failed = 0
    for name, fn in checks:
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"raised {exc}"
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
        failed += 0 if ok else 1
    print(f"\n{'ALL PASS' if not failed else f'{failed} CHECK(S) FAILED'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
