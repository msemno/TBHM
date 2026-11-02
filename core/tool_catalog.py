"""Versioned external-tool catalog and readiness helpers for TBHM v3.9.7.5.

The catalog is intentionally broader than the set of tools TBHM executes.  It
records every tool/service requested in the supplied corporate gap-analysis
material, but distinguishes:

* safe_cli / library / feed: may be installed or invoked in bounded read-only use;
* approval_cli: can be invoked only with an explicit engagement approval manifest;
* approval_only: catalog/import/planning only; TBHM never auto-runs it;
* import_only / service_or_manual: evidence/API/manual integration, not installation.

This prevents "registered" from being mistaken for "autonomously operational".
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "tooling" / "tool_catalog_v3975.json"

_PY_MODULE_OVERRIDES = {
    "great-expectations": "great_expectations",
    "pyarrow": "pyarrow",
    "pyelftools": "elftools",
    "stix-2-1": "stix2",
    "taxii-2": "taxii2client",
    "flare-capa": "capa",
    "flare-floss": "floss",
    "detect-secrets": "detect_secrets",
    "quark-engine": "quark",
    "volatility-3": "volatility3",
    "scoutsuite": "ScoutSuite",
    "pyats": "pyats",
    "sigma": "sigma",
}


def _python_status(item: dict) -> tuple[bool, str]:
    tool_id = str(item.get("id") or "").strip().lower()
    tool_home = Path(os.environ.get("TBHM_TOOL_HOME", Path.home() / ".local/share/tbhm-tools")).expanduser()
    marker = tool_home / "venvs" / tool_id / ".tbhm-install.json"
    if marker.is_file():
        return True, str(marker.parent)
    module = _PY_MODULE_OVERRIDES.get(tool_id, tool_id.replace("-", "_"))
    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, ModuleNotFoundError, ValueError):
        spec = None
    if spec is not None:
        return True, str(spec.origin or "current Python environment")
    return False, ""


def load(path: str | Path | None = None) -> dict:
    p = Path(path) if path else DEFAULT_CATALOG
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
        raise ValueError(f"invalid tool catalog: {p}")
    return data


def by_id(catalog: dict) -> dict[str, dict]:
    return {str(t.get("id")): t for t in catalog.get("tools", []) if t.get("id")}


def select(catalog: dict, categories: Iterable[str] | None = None,
           names: Iterable[str] | None = None) -> list[dict]:
    cats = {str(x).strip().lower() for x in (categories or []) if str(x).strip()}
    wanted = {str(x).strip().lower() for x in (names or []) if str(x).strip()}
    out = []
    for item in catalog.get("tools", []):
        if cats and str(item.get("category", "")).lower() not in cats:
            continue
        if wanted and not ({str(item.get("id", "")).lower(), str(item.get("name", "")).lower()} & wanted):
            continue
        out.append(item)
    return out


def executable_status(item: dict) -> dict:
    exe = str(item.get("executable") or "").strip()
    installer = str(item.get("installer") or "").lower()
    candidates = [exe] if exe and exe != "python3" else []
    candidates.extend(
        str(x).strip() for x in item.get("executable_candidates", [])
        if str(x).strip() and str(x).strip() not in candidates
    )
    path = next((shutil.which(name) for name in candidates if shutil.which(name)), None)
    installed = bool(path)
    environment = "executable" if installed else "missing"
    if installer in {"pip", "pipx"} and (exe == "python3" or not exe):
        installed, python_path = _python_status(item)
        path = python_path or None
        environment = "python-module-or-isolated-venv" if installed else "missing"
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "category": item.get("category"),
        "integration_mode": item.get("integration_mode"),
        "risk": item.get("risk"),
        "installer": item.get("installer"),
        "executable": exe,
        "installed": installed,
        "path": path or "",
        "environment": environment,
        "install_hint": item.get("install_hint", ""),
        "notes": item.get("notes", ""),
    }


def readiness(catalog: dict, categories: Iterable[str] | None = None) -> dict:
    rows = [executable_status(x) for x in select(catalog, categories=categories)]
    executable_rows = [r for r in rows if r["executable"]]
    return {
        "catalog_version": catalog.get("catalog_version"),
        "registered": len(rows),
        "executable_entries": len(executable_rows),
        "installed_executables": sum(1 for r in executable_rows if r["installed"]),
        "missing_executables": sum(1 for r in executable_rows if not r["installed"]),
        "by_category": _group(rows, "category"),
        "by_mode": _group(rows, "integration_mode"),
        "rows": rows,
        "policy": catalog.get("policy", {}),
    }


def _group(rows: list[dict], key: str) -> dict:
    out: dict[str, dict] = {}
    for row in rows:
        name = str(row.get(key) or "unknown")
        bucket = out.setdefault(name, {"registered": 0, "executable": 0, "installed": 0})
        bucket["registered"] += 1
        if row.get("executable"):
            bucket["executable"] += 1
            if row.get("installed"):
                bucket["installed"] += 1
    return dict(sorted(out.items()))


def is_high_risk(item: dict) -> bool:
    return str(item.get("integration_mode")) in {"approval_cli", "approval_only"} or str(item.get("risk")) in {"high", "critical"}
