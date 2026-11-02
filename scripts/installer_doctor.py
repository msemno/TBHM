#!/usr/bin/env python3
"""Offline installer/environment diagnostics for TBHM v3.9.7.5."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.version import VERSION as RELEASE
PYTHON_TOOL_EXECUTABLES = (
    "arjun", "semgrep", "bandit", "ruff", "njsscan", "checkov",
    "detect-secrets", "safety", "capa", "floss", "frida", "playwright",
    "giskard", "modelscan", "whylogs", "suzieq",
)


def _run(argv: list[str], timeout: int = 30) -> dict:
    try:
        cp = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
        return {
            "argv": argv,
            "return_code": cp.returncode,
            "stdout": cp.stdout.strip()[-4000:],
            "stderr": cp.stderr.strip()[-4000:],
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"argv": argv, "return_code": -1, "stdout": "", "stderr": str(exc)}


def _classify_path(path: str, tool_home: Path) -> str:
    if not path:
        return "missing"
    p = Path(path)
    try:
        resolved = p.resolve()
    except OSError:
        resolved = p
    value = str(resolved)
    if value.startswith(str(tool_home / "venvs")):
        return "tbhm-isolated"
    if "/pipx/venvs/" in value:
        return "pipx-isolated"
    if str(p).startswith("/usr/bin/"):
        return "distro-managed"
    if p.parent == Path.home() / ".local/bin":
        return "legacy-shared-user-launcher"
    return "external"


def collect(tool_home: Path | None = None) -> dict:
    tool_home = (tool_home or Path(os.environ.get("TBHM_TOOL_HOME", Path.home() / ".local/share/tbhm-tools"))).expanduser()
    pip_check = _run([sys.executable, "-m", "pip", "check"], timeout=60)
    tools = []
    for name in PYTHON_TOOL_EXECUTABLES:
        path = shutil.which(name) or ""
        tools.append({"name": name, "path": path, "environment": _classify_path(path, tool_home)})
    interpreters = []
    for name in ("python3.13", "python3.12", "python3.11", "python3.10", "python3.9", "python3.8"):
        path = shutil.which(name)
        if path:
            result = _run([path, "-c", "import sys; print(sys.version.split()[0])"])
            interpreters.append({"name": name, "path": path, "version": result["stdout"], "usable": result["return_code"] == 0})
    npm = _run(["npm", "config", "get", "prefix"]) if shutil.which("npm") else None
    return {
        "release": RELEASE,
        "python": {"executable": sys.executable, "version": sys.version.split()[0]},
        "tool_home": str(tool_home),
        "local_bin": str(Path.home() / ".local/bin"),
        "local_bin_on_path": str(Path.home() / ".local/bin") in os.environ.get("PATH", "").split(os.pathsep),
        "pip_check": pip_check,
        "shared_environment_healthy": pip_check["return_code"] == 0,
        "interpreters": interpreters,
        "npm": {
            "available": bool(shutil.which("npm")),
            "prefix": npm["stdout"] if npm else "",
            "user_prefix_expected": str(Path.home() / ".local"),
        },
        "cargo": {"available": bool(shutil.which("cargo")), "rustc": shutil.which("rustc") or ""},
        "apt": {"available": bool(shutil.which("apt-get") and shutil.which("apt-cache"))},
        "tools": tools,
        "legacy_shared_launchers": [row for row in tools if row["environment"] == "legacy-shared-user-launcher"],
        "guidance": [
            "Re-run ./install.sh to migrate detected shared-user Python launchers into isolated TBHM environments.",
            "Expected unsupported tools are reported as skipped-incompatible or skipped-unavailable, not as installed.",
            "Do not manually combine Semgrep, Checkov, angr, capa, pyATS and data-analysis packages in one Python environment.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--tool-home", default="")
    ns = parser.parse_args()
    payload = collect(Path(ns.tool_home) if ns.tool_home else None)
    if ns.json:
        print(json.dumps(payload, indent=2))
    else:
        state = "healthy" if payload["shared_environment_healthy"] else "contains pre-existing conflicts"
        print(f"TBHM installer doctor {RELEASE}")
        print(f"Python: {payload['python']['version']} ({payload['python']['executable']})")
        print(f"Shared Python environment: {state}")
        print(f"TBHM tool home: {payload['tool_home']}")
        for row in payload["tools"]:
            print(f"[{row['environment']}] {row['name']}: {row['path'] or 'missing'}")
        if payload["pip_check"]["stderr"] or payload["pip_check"]["stdout"]:
            print("pip check:")
            print(payload["pip_check"]["stdout"] or payload["pip_check"]["stderr"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
