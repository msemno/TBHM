#!/usr/bin/env python3
"""Plan or perform a conservative cleanup of legacy TBHM shared-user tools.

The v3.9.7.2 installer placed optional applications in the same user Python
site. This helper removes only known top-level optional distributions when:

1. the distribution is physically installed in the current user's site; and
2. a replacement isolated TBHM environment has already been installed.

Dependencies such as pydantic/protobuf/networkx/packaging are never guessed or
automatically downgraded. The post-cleanup ``pip check`` output is preserved so
an operator can review any unrelated/pre-existing conflicts.
"""
from __future__ import annotations

import argparse
import importlib.metadata as metadata
import json
import os
import site
import subprocess
import sys
from pathlib import Path

RELEASE = "4.0.0-unified-safe"
DISTRIBUTIONS = {
    "arjun": "arjun",
    "semgrep": "semgrep",
    "bandit": "bandit",
    "ruff": "ruff",
    "njsscan": "njsscan",
    "checkov": "checkov",
    "detect-secrets": "detect-secrets",
    "safety": "safety",
    "flare-capa": "flare-capa",
    "flare-floss": "flare-floss",
    "frida-tools": "frida-tools",
    "angr": "angr",
    "playwright": "playwright",
}


def _distribution_location(name: str) -> Path | None:
    try:
        dist = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        return None
    try:
        return Path(dist.locate_file("")).resolve()
    except OSError:
        return Path(dist.locate_file(""))


def _run(argv: list[str], timeout: int = 300) -> dict:
    try:
        cp = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
        return {"argv": argv, "return_code": cp.returncode,
                "stdout": cp.stdout.strip()[-6000:], "stderr": cp.stderr.strip()[-6000:]}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"argv": argv, "return_code": -1, "stdout": "", "stderr": str(exc)}


def plan(tool_home: Path) -> list[dict]:
    user_site = Path(site.getusersitepackages()).resolve()
    rows = []
    for tool_id, distribution in DISTRIBUTIONS.items():
        location = _distribution_location(distribution)
        marker = tool_home / "venvs" / tool_id / ".tbhm-install.json"
        in_user_site = bool(location and (location == user_site or user_site in location.parents))
        rows.append({
            "tool_id": tool_id,
            "distribution": distribution,
            "location": str(location or ""),
            "in_shared_user_site": in_user_site,
            "isolated_replacement": marker.is_file(),
            "eligible_for_cleanup": in_user_site and marker.is_file(),
            "reason": (
                "isolated replacement present; shared top-level package may be removed"
                if in_user_site and marker.is_file()
                else "not installed in shared user site" if not in_user_site
                else "install the isolated replacement before cleanup"
            ),
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="uninstall eligible known top-level distributions")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--tool-home", default=os.environ.get("TBHM_TOOL_HOME", str(Path.home() / ".local/share/tbhm-tools")))
    ns = parser.parse_args()
    tool_home = Path(ns.tool_home).expanduser().resolve()
    rows = plan(tool_home)
    actions = []
    if ns.apply:
        for row in rows:
            if not row["eligible_for_cleanup"]:
                continue
            result = _run([sys.executable, "-m", "pip", "uninstall", "--yes", row["distribution"]])
            actions.append({"distribution": row["distribution"], **result})
    pip_check = _run([sys.executable, "-m", "pip", "check"], timeout=60)
    payload = {
        "release": RELEASE,
        "apply": ns.apply,
        "tool_home": str(tool_home),
        "eligible": sum(bool(x["eligible_for_cleanup"]) for x in rows),
        "rows": rows,
        "actions": actions,
        "pip_check": pip_check,
        "warning": (
            "This helper never downgrades shared dependency libraries. Review pip_check before changing "
            "pydantic, protobuf, networkx, ruamel.yaml, packaging, or other packages used by Kali applications."
        ),
    }
    if ns.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Legacy shared-user cleanup candidates: {payload['eligible']}")
        for row in rows:
            print(f"[{'eligible' if row['eligible_for_cleanup'] else 'keep'}] {row['distribution']}: {row['reason']}")
        if ns.apply:
            for action in actions:
                print(f"[{action['return_code']}] removed {action['distribution']}")
        print(payload["warning"])
        if pip_check["return_code"] != 0:
            print("pip check still reports:")
            print(pip_check["stdout"] or pip_check["stderr"])
    return 1 if any(x["return_code"] != 0 for x in actions) else 0


if __name__ == "__main__":
    raise SystemExit(main())
