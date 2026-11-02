#!/usr/bin/env python3
"""Safely install optional TBHM integrations without contaminating system Python.

v3.9.7.5 changes the installer contract:

* optional Python tools are installed into one isolated virtual environment per
  catalog entry (never into the distro or shared ``--user`` site-packages);
* npm packages use a user-owned prefix instead of ``/usr/local``;
* known Python-version constraints are checked before invoking installers;
* apt recipes are preflighted and expected repository/platform conflicts are
  reported as explicit skips instead of noisy generic failures;
* deprecated or invalid recipes are not executed;
* all subprocesses use argument vectors, timeouts, and captured diagnostics.

The helper still installs only low/medium-risk ``safe_cli``, ``library`` and
``feed`` catalog entries. Approval-only or high-risk tools remain planning and
import surfaces only.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.tool_catalog import load, select  # noqa: E402

SAFE_MODES = {"safe_cli", "library", "feed"}
SAFE_INSTALLERS = {"pip", "pipx", "go", "npm", "cargo", "gem", "composer", "apt"}
EXPECTED_SKIP_STATUSES = {
    "skipped-policy-or-no-vetted-recipe",
    "skipped-incompatible",
    "skipped-unavailable",
    "skipped-deprecated",
    "skipped-platform",
}

# Official/current package metadata and upstream documentation establish these
# interpreter ranges. Do not try unsupported combinations in the operator's
# primary environment.
PYTHON_COMPAT: dict[str, tuple[tuple[int, int], tuple[int, int]]] = {
    "giskard": ((3, 9), (3, 11)),
    "modelscan": ((3, 10), (3, 12)),
    "whylogs": ((3, 9), (3, 12)),
    # SuzieQ's published installation documentation targets older interpreters.
    "suzieq": ((3, 8), (3, 9)),
}

PYTHON_PREFERENCE: dict[str, tuple[str, ...]] = {
    "giskard": ("python3.11", "python3.10", "python3.9"),
    "modelscan": ("python3.12", "python3.11", "python3.10"),
    "whylogs": ("python3.12", "python3.11", "python3.10", "python3.9"),
    "suzieq": ("python3.9", "python3.8"),
}

DEPRECATED_RECIPES = {
    "kubeaudit": (
        "The historical Shopify kubeaudit repository is archived/deprecated and "
        "the catalog's root-module 'go install' recipe is not a main package. "
        "TBHM keeps evidence import/compatibility but will not auto-install it; "
        "use a reviewed release binary or a maintained alternative such as kube-bench."
    )
}

TRANSIENT_APT_MARKERS = (
    "temporary failure resolving",
    "could not connect",
    "connection failed",
    "connection timed out",
    "failed to fetch",
    "network is unreachable",
)
APT_INCOMPAT_MARKERS = (
    "unmet dependencies",
    "held broken packages",
    "but it is not installable",
    "depends:",
    "conflicts:",
)

RunFn = Callable[..., subprocess.CompletedProcess[str]]
_PY_VERSION_CACHE: dict[str, tuple[int, int] | None] = {}


def _allowed_argv(item: dict) -> list[str] | None:
    """Return a catalog recipe only when it matches the strict command allowlist.

    This public helper is retained for v3.9.5/v3.9.6 compatibility tests. Recipe
    normalization and compatibility decisions happen later; returning an argv
    here does not mean the command will be executed verbatim.
    """
    if str(item.get("integration_mode")) not in SAFE_MODES:
        return None
    if str(item.get("risk", "")).lower() not in {"low", "medium"}:
        return None
    if str(item.get("installer", "")).lower() not in SAFE_INSTALLERS:
        return None
    hint = str(item.get("install_hint") or "").strip()
    if not hint or any(x in hint for x in (";", "&&", "||", "|", "`", "$(", ">", "<")):
        return None
    argv = shlex.split(hint)
    if not argv:
        return None
    normalized = argv[1:] if argv[0] == "sudo" else argv
    valid = (
        normalized[:4] == ["python3", "-m", "pip", "install"]
        or normalized[:2] == ["pipx", "install"]
        or normalized[:2] == ["go", "install"]
        or normalized[:3] == ["npm", "install", "-g"]
        or normalized[:2] == ["cargo", "install"]
        or normalized[:2] == ["gem", "install"]
        or normalized[:3] == ["composer", "global", "require"]
        or normalized[:3] == ["apt", "install", "-y"]
        or normalized[:4] == ["apt-get", "install", "-y", "--fix-missing"]
    )
    return argv if valid else None


def _version_tuple(python: str, run: RunFn = subprocess.run) -> tuple[int, int] | None:
    use_cache = run is subprocess.run
    if use_cache and python in _PY_VERSION_CACHE:
        return _PY_VERSION_CACHE[python]
    value: tuple[int, int] | None = None
    try:
        cp = run(
            [python, "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        if cp.returncode == 0:
            major, minor = cp.stdout.strip().split(".", 1)
            value = (int(major), int(minor))
    except (OSError, ValueError, subprocess.SubprocessError):
        value = None
    if use_cache:
        _PY_VERSION_CACHE[python] = value
    return value


def _in_range(version: tuple[int, int], bounds: tuple[tuple[int, int], tuple[int, int]]) -> bool:
    return bounds[0] <= version <= bounds[1]


def _find_compatible_python(tool_id: str, run: RunFn = subprocess.run) -> tuple[str | None, str]:
    bounds = PYTHON_COMPAT.get(tool_id)
    candidates: Iterable[str]
    if bounds:
        candidates = PYTHON_PREFERENCE.get(tool_id, ())
    else:
        candidates = (sys.executable, "python3")
    seen: set[str] = set()
    observed: list[str] = []
    for candidate in candidates:
        path = shutil.which(candidate) if not os.path.isabs(candidate) else candidate
        if not path or path in seen:
            continue
        seen.add(path)
        version = _version_tuple(path, run)
        if version is None:
            continue
        observed.append(f"{Path(path).name}={version[0]}.{version[1]}")
        if not bounds or _in_range(version, bounds):
            return path, f"selected {Path(path).name} {version[0]}.{version[1]}"
    if bounds:
        lo, hi = bounds
        actual = ", ".join(observed) or "no matching interpreter installed"
        return None, (
            f"requires Python {lo[0]}.{lo[1]}–{hi[0]}.{hi[1]}; {actual}. "
            "Install a compatible side-by-side interpreter; TBHM will keep it isolated."
        )
    return None, "python3 executable is unavailable"


def _tail(text: str | None, limit: int = 4000) -> str:
    value = (text or "").strip()
    return value[-limit:]


def _run(argv: Sequence[str], *, timeout: int, run: RunFn = subprocess.run,
         cwd: Path = ROOT, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return run(
        list(argv),
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _package_tokens(argv: Sequence[str]) -> list[str]:
    """Extract package specs from a vetted pip/pipx recipe."""
    if "install" not in argv:
        return []
    start = list(argv).index("install") + 1
    packages: list[str] = []
    skip_next = False
    options_with_value = {"--python", "--index-url", "--extra-index-url", "-i", "-r", "--requirement"}
    for token in argv[start:]:
        if skip_next:
            skip_next = False
            continue
        if token in options_with_value:
            skip_next = True
            continue
        if token in {"--user", "--break-system-packages", "--force", "--include-deps"}:
            continue
        if token.startswith("-"):
            continue
        packages.append(token)
    return packages


def _safe_id(value: object) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", str(value or "tool").strip().lower()).strip("-") or "tool"


def _venv_paths(tool_id: str, home: Path) -> tuple[Path, Path]:
    venv = home / "venvs" / _safe_id(tool_id)
    py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return venv, py


def _install_isolated_python(item: dict, source_argv: list[str], *, timeout: int,
                             tool_home: Path, bin_dir: Path, run: RunFn,
                             env: dict[str, str]) -> dict:
    tool_id = _safe_id(item.get("id"))
    python, reason = _find_compatible_python(tool_id, run)
    if not python:
        return {"status": "skipped-incompatible", "reason": reason, "command": []}
    packages = _package_tokens(source_argv)
    if not packages:
        return {"status": "failed", "reason": "no package spec found in vetted recipe", "command": []}
    venv, vpy = _venv_paths(tool_id, tool_home)
    commands = [
        [python, "-m", "venv", str(venv)],
        [str(vpy), "-m", "pip", "install", "--disable-pip-version-check", "--upgrade", "pip", "setuptools", "wheel"],
        [str(vpy), "-m", "pip", "install", "--disable-pip-version-check", *packages],
    ]
    outputs: list[str] = []
    for command in commands:
        cp = _run(command, timeout=timeout, run=run, env=env)
        outputs.extend([_tail(cp.stdout, 1500), _tail(cp.stderr, 2500)])
        if cp.returncode != 0:
            return {
                "status": "failed",
                "reason": f"isolated Python installation failed ({reason})",
                "command": command,
                "return_code": cp.returncode,
                "diagnostic": "\n".join(x for x in outputs if x),
                "environment": str(venv),
            }
    executable = str(item.get("executable") or "").strip()
    candidates = [str(x).strip() for x in item.get("executable_candidates", []) if str(x).strip()]
    if executable and executable != "python3" and executable not in candidates:
        candidates.insert(0, executable)
    exposed = ""
    found_candidate = ""
    for candidate_name in candidates:
        candidate = venv / (f"Scripts/{candidate_name}.exe" if os.name == "nt" else f"bin/{candidate_name}")
        if not candidate.is_file():
            continue
        found_candidate = candidate_name
        # Expose the canonical executable name. This preserves the catalog's
        # public command contract even when upstream ships a secondary alias.
        public_name = executable or candidate_name
        bin_dir.mkdir(parents=True, exist_ok=True)
        link = bin_dir / public_name
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(candidate)
            exposed = str(link)
        except OSError as exc:
            return {
                "status": "failed",
                "reason": f"installed but could not expose executable: {exc}",
                "command": commands[-1],
                "environment": str(venv),
            }
        break
    if str(item.get("integration_mode") or "") == "safe_cli" and executable not in {"", "python3"} and not exposed:
        expected = ", ".join(candidates or [executable])
        return {
            "status": "failed",
            "reason": f"package installed but expected CLI executable was not found: {expected}",
            "command": commands[-1],
            "environment": str(venv),
            "diagnostic": "\n".join(x for x in outputs if x)[-4000:],
        }
    marker = venv / ".tbhm-install.json"
    marker.write_text(json.dumps({
        "tool_id": tool_id,
        "packages": packages,
        "python": python,
        "installed_at": int(time.time()),
        "executable": exposed,
        "upstream_executable": found_candidate,
    }, indent=2), encoding="utf-8")
    return {
        "status": "installed",
        "reason": f"isolated environment created; {reason}",
        "command": commands[-1],
        "environment": str(venv),
        "executable_path": exposed,
        "diagnostic": "\n".join(x for x in outputs if x)[-4000:],
    }


def _normalized_npm(source_argv: list[str], prefix: Path) -> list[str]:
    packages = [x for x in source_argv[3:] if x not in {"--global", "-g"}]
    return ["npm", "install", "--global", "--prefix", str(prefix), *packages]


def _normalized_cargo(source_argv: list[str]) -> list[str]:
    argv = list(source_argv)
    if "--locked" not in argv:
        argv.append("--locked")
    return argv


def _normalized_gem(source_argv: list[str]) -> list[str]:
    argv = list(source_argv)
    if "--user-install" not in argv:
        argv.append("--user-install")
    return argv


def _user_tool_bin(installer: str, *, run: RunFn, env: dict[str, str], timeout: int) -> Path | None:
    if installer == "gem" and shutil.which("ruby"):
        cp = _run(["ruby", "-e", "require 'rubygems'; print Gem.user_dir"],
                  timeout=min(timeout, 30), run=run, env=env)
        if cp.returncode == 0 and cp.stdout.strip():
            return Path(cp.stdout.strip()) / "bin"
    if installer == "composer" and shutil.which("composer"):
        cp = _run(["composer", "global", "config", "bin-dir", "--absolute"],
                  timeout=min(timeout, 30), run=run, env=env)
        if cp.returncode == 0 and cp.stdout.strip():
            return Path(cp.stdout.strip().splitlines()[-1])
    return None


def _expose_executable(item: dict, source_dir: Path | None, bin_dir: Path) -> str:
    executable = str(item.get("executable") or "").strip()
    if not executable or not source_dir:
        return ""
    candidate = source_dir / executable
    if not candidate.is_file():
        return ""
    bin_dir.mkdir(parents=True, exist_ok=True)
    link = bin_dir / executable
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(candidate)
    return str(link)


def _apt_packages(source_argv: Sequence[str]) -> list[str]:
    ignored = {"sudo", "apt", "apt-get", "install", "-y", "--fix-missing"}
    return [x for x in source_argv if x not in ignored and not x.startswith("-o")]


def _install_apt(item: dict, source_argv: list[str], *, timeout: int, run: RunFn,
                 env: dict[str, str]) -> dict:
    if platform.system().lower() != "linux":
        return {"status": "skipped-platform", "reason": "apt recipe requires Linux", "command": []}
    if not shutil.which("apt-cache") or not shutil.which("apt-get"):
        return {"status": "skipped-unavailable", "reason": "apt-cache/apt-get unavailable", "command": []}
    packages = _apt_packages(source_argv)
    if not packages:
        return {"status": "failed", "reason": "no apt package found", "command": []}
    for package in packages:
        cp = _run(["apt-cache", "show", package], timeout=min(timeout, 60), run=run, env=env)
        if cp.returncode != 0 or not cp.stdout.strip():
            return {
                "status": "skipped-unavailable",
                "reason": f"package '{package}' is not available in configured apt repositories",
                "command": ["apt-cache", "show", package],
                "diagnostic": _tail(cp.stderr or cp.stdout),
            }
    prefix = ["sudo"] if os.geteuid() != 0 and shutil.which("sudo") else []
    simulate = [*prefix, "apt-get", "-s", "install", "-y", *packages]
    cp = _run(simulate, timeout=min(timeout, 180), run=run, env=env)
    if cp.returncode != 0:
        diagnostic = (_tail(cp.stdout) + "\n" + _tail(cp.stderr)).strip()
        low = diagnostic.lower()
        status = "skipped-incompatible" if any(x in low for x in APT_INCOMPAT_MARKERS) else "failed"
        return {
            "status": status,
            "reason": "apt dependency preflight failed" if status == "failed" else "apt dependencies are incompatible on this distribution",
            "command": simulate,
            "return_code": cp.returncode,
            "diagnostic": diagnostic,
        }
    install = [*prefix, "apt-get", "-o", "Acquire::ForceIPv4=true", "install", "-y", "--fix-missing", *packages]
    attempts = 2
    diagnostics: list[str] = []
    for attempt in range(1, attempts + 1):
        cp = _run(install, timeout=timeout, run=run, env=env)
        diagnostic = (_tail(cp.stdout, 1500) + "\n" + _tail(cp.stderr, 2500)).strip()
        diagnostics.append(diagnostic)
        if cp.returncode == 0:
            return {"status": "installed", "reason": f"apt installation completed on attempt {attempt}",
                    "command": install, "return_code": 0, "diagnostic": "\n".join(diagnostics)[-4000:]}
        if attempt == attempts or not any(x in diagnostic.lower() for x in TRANSIENT_APT_MARKERS):
            break
    return {
        "status": "failed",
        "reason": "apt installation failed after bounded retry",
        "command": install,
        "return_code": cp.returncode,
        "diagnostic": "\n".join(diagnostics)[-5000:],
    }


def _already_installed(item: dict, tool_home: Path) -> tuple[bool, str]:
    marker = tool_home / "venvs" / _safe_id(item.get("id")) / ".tbhm-install.json"
    if marker.is_file():
        return True, str(marker.parent)
    exe = str(item.get("executable") or "").strip()
    executable_names = [exe] if exe and exe != "python3" else []
    executable_names.extend(
        str(x).strip() for x in item.get("executable_candidates", [])
        if str(x).strip() and str(x).strip() not in executable_names
    )
    for executable_name in executable_names:
        found = shutil.which(executable_name)
        if found:
            path = Path(found)
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            installer = str(item.get("installer") or "").lower()
            local_bin = Path.home() / ".local/bin"
            # A regular pip-generated launcher in ~/.local/bin is precisely the
            # legacy shared-site layout v3.9.7.5 is repairing. pipx and TBHM
            # venv symlinks are already isolated and may be retained.
            if installer in {"pip", "pipx"} and path.parent == local_bin:
                if str(resolved).startswith(str(tool_home / "venvs")) or "/pipx/venvs/" in str(resolved):
                    return True, str(path)
                return False, ""
            return True, str(path)
    return False, ""


def install_item(item: dict, *, apply: bool, timeout: int, tool_home: Path,
                 bin_dir: Path, run: RunFn = subprocess.run,
                 environ: dict[str, str] | None = None) -> dict:
    """Plan or install one catalog entry and return a truthful status record."""
    source_argv = _allowed_argv(item)
    tool_id = _safe_id(item.get("id"))
    installed, installed_path = _already_installed(item, tool_home)
    record = {
        "id": item.get("id"),
        "name": item.get("name"),
        "category": item.get("category"),
        "mode": item.get("integration_mode"),
        "risk": item.get("risk"),
        "installer": item.get("installer"),
        "installed": installed,
        "installed_path": installed_path,
        "eligible": bool(source_argv),
        "source_command": source_argv or [],
        "command": [],
        "status": "planned",
        "reason": "",
    }
    if not source_argv:
        record.update(status="skipped-policy-or-no-vetted-recipe",
                      reason="catalog entry is high-risk, non-installable, or lacks a vetted argument-vector recipe")
        return record
    if installed:
        record.update(status="already-installed", reason=f"executable/environment found at {installed_path}")
        return record
    if tool_id in DEPRECATED_RECIPES:
        record.update(status="skipped-deprecated", reason=DEPRECATED_RECIPES[tool_id])
        return record

    installer = str(item.get("installer") or "").lower()
    env = dict(os.environ if environ is None else environ)
    env["PATH"] = os.pathsep.join([str(bin_dir), str(Path.home() / "go" / "bin"),
                                  str(Path.home() / ".cargo" / "bin"), env.get("PATH", "")])

    # Resolve incompatibility even in plan mode so the plan is honest.
    if installer in {"pip", "pipx"}:
        python, reason = _find_compatible_python(tool_id, run)
        if not python:
            record.update(status="skipped-incompatible", reason=reason)
            return record
        packages = _package_tokens(source_argv)
        venv, vpy = _venv_paths(tool_id, tool_home)
        record["command"] = [str(vpy), "-m", "pip", "install", *packages]
        record["reason"] = f"will install in isolated environment {venv}; {reason}"
        if not apply:
            return record
        result = _install_isolated_python(item, source_argv, timeout=timeout, tool_home=tool_home,
                                          bin_dir=bin_dir, run=run, env=env)
        record.update(result)
        return record

    if installer == "npm":
        if not shutil.which("npm"):
            record.update(status="skipped-unavailable", reason="npm executable is unavailable")
            return record
        command = _normalized_npm(source_argv, Path.home() / ".local")
    elif installer == "cargo":
        if not shutil.which("cargo"):
            record.update(status="skipped-unavailable", reason="cargo executable is unavailable")
            return record
        command = _normalized_cargo(source_argv)
    elif installer == "go":
        if not shutil.which("go"):
            record.update(status="skipped-unavailable", reason="go executable is unavailable")
            return record
        command = source_argv
    elif installer == "gem":
        if not shutil.which("gem") or not shutil.which("ruby"):
            record.update(status="skipped-unavailable", reason="Ruby/RubyGems is unavailable")
            return record
        command = _normalized_gem(source_argv)
    elif installer == "composer":
        if not shutil.which("composer"):
            record.update(status="skipped-unavailable", reason="Composer is unavailable")
            return record
        command = source_argv
    elif installer == "apt":
        record["command"] = source_argv
        if not apply:
            return record
        result = _install_apt(item, source_argv, timeout=timeout, run=run, env=env)
        record.update(result)
        return record
    else:
        command = source_argv

    record["command"] = command
    if not apply:
        return record
    try:
        cp = _run(command, timeout=timeout, run=run, env=env)
        record["return_code"] = cp.returncode
        record["diagnostic"] = (_tail(cp.stdout, 1500) + "\n" + _tail(cp.stderr, 2500)).strip()
        record["status"] = "installed" if cp.returncode == 0 else "failed"
        record["reason"] = "installer completed" if cp.returncode == 0 else "installer returned a non-zero exit code"
        if cp.returncode == 0 and installer in {"gem", "composer"}:
            source_dir = _user_tool_bin(installer, run=run, env=env, timeout=timeout)
            exposed = _expose_executable(item, source_dir, bin_dir)
            if exposed:
                record["executable_path"] = exposed
            elif str(item.get("executable") or "").strip():
                record["reason"] += "; executable was not found in the installer user bin directory"
    except subprocess.TimeoutExpired as exc:
        record.update(status="failed", reason=f"installer timed out after {timeout}s",
                      diagnostic=_tail(str(exc)))
    except OSError as exc:
        record.update(status="failed", reason=f"installer could not start: {exc}")
    return record


def build_summary(plan: list[dict], *, catalog_version: object, apply: bool, strict: bool) -> dict:
    counts: dict[str, int] = {}
    for row in plan:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {
        "release": "4.0.0-unified-safe",
        "catalog_version": catalog_version,
        "apply": apply,
        "strict": strict,
        "selected": len(plan),
        "eligible": sum(bool(x["eligible"]) for x in plan),
        "installed_or_present": sum(x["status"] in {"installed", "already-installed"} for x in plan),
        "failed": counts.get("failed", 0),
        "skipped": sum(v for k, v in counts.items() if k.startswith("skipped")),
        "status_counts": dict(sorted(counts.items())),
        "policy": (
            "approval_cli, approval_only, import_only, service/manual, high-risk and unvetted recipes are never "
            "auto-installed; expected platform/repository/version limitations are explicit skips"
        ),
        "rows": plan,
    }


def _progress_run(argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess[str]:
    """Show liveness on stderr while keeping captured installer output intact."""
    command = Path(argv[0]).name
    if command == "sudo" and len(argv) > 1:
        command = Path(argv[1]).name
    elif "-m" in argv:
        index = list(argv).index("-m")
        if index + 1 < len(argv):
            command += f" -m {argv[index + 1]}"
    started = time.monotonic()
    stopped = threading.Event()

    def heartbeat() -> None:
        while not stopped.wait(30):
            print(f"    {command} still running ({int(time.monotonic() - started)}s)",
                  file=sys.stderr, flush=True)

    print(f"    starting {command}", file=sys.stderr, flush=True)
    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        result = subprocess.run(list(argv), **kwargs)
        print(f"    {command} exited {result.returncode} after "
              f"{int(time.monotonic() - started)}s", file=sys.stderr, flush=True)
        return result
    finally:
        stopped.set()
        thread.join()


def _write_state(path: Path, summary: dict) -> None:
    """Keep a usable checkpoint if a long optional installation is interrupted."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".tmp")
    pending.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    os.replace(pending, path)


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default=str(ROOT / "tooling" / "tool_catalog_v3975.json"))
    ap.add_argument("--bundle", default="all-safe", help="all-safe or comma-separated catalog categories")
    ap.add_argument("--tools", default="", help="optional comma-separated tool IDs/names")
    ap.add_argument("--apply", action="store_true", help="execute vetted recipes; default is plan only")
    ap.add_argument("--strict", action="store_true", help="also fail when an eligible tool is skipped")
    ap.add_argument("--timeout", type=int, default=1800, help="per installer command timeout (60–7200 seconds)")
    ap.add_argument("--tool-home", default=os.environ.get("TBHM_TOOL_HOME", str(Path.home() / ".local/share/tbhm-tools")))
    ap.add_argument("--state-file", default="", help="optional JSON result path")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    timeout = max(60, min(int(ns.timeout), 7200))
    tool_home = Path(ns.tool_home).expanduser().resolve()
    bin_dir = Path.home() / ".local" / "bin"
    catalog = load(ns.catalog)
    categories = [] if ns.bundle == "all-safe" else [x.strip() for x in ns.bundle.split(",") if x.strip()]
    names = [x.strip().lower() for x in ns.tools.split(",") if x.strip()]
    rows = select(catalog, categories=categories or None, names=names or None)
    state = Path(ns.state_file).expanduser() if ns.state_file else None
    plan: list[dict] = []
    for index, item in enumerate(rows, 1):
        report_progress = ns.apply and _allowed_argv(item) is not None
        if report_progress:
            print(f"[{index}/{len(rows)}] installing {item.get('id')}",
                  file=sys.stderr, flush=True)
        try:
            row = install_item(item, apply=ns.apply, timeout=timeout,
                               tool_home=tool_home, bin_dir=bin_dir,
                               run=_progress_run if ns.apply else subprocess.run)
        except KeyboardInterrupt:
            partial = build_summary(plan, catalog_version=catalog.get("catalog_version"),
                                    apply=ns.apply, strict=ns.strict)
            partial.update(complete=False, selected_total=len(rows),
                           interrupted_tool=item.get("id"))
            if state:
                _write_state(state, partial)
            print(f"Interrupted during {item.get('id')}; completed {len(plan)}/{len(rows)} "
                  f"entries" + (f"; checkpoint: {state}" if state else ""),
                  file=sys.stderr, flush=True)
            if ns.json:
                print(json.dumps(partial, indent=2))
            return 130
        plan.append(row)
        if report_progress:
            print(f"[{index}/{len(rows)}] {item.get('id')}: {row['status']}",
                  file=sys.stderr, flush=True)
        if ns.apply and state and report_progress:
            checkpoint = build_summary(plan, catalog_version=catalog.get("catalog_version"),
                                       apply=True, strict=ns.strict)
            checkpoint.update(complete=False, selected_total=len(rows))
            _write_state(state, checkpoint)
    summary = build_summary(plan, catalog_version=catalog.get("catalog_version"), apply=ns.apply, strict=ns.strict)
    if state:
        _write_state(state, summary)
    if ns.json:
        print(json.dumps(summary, indent=2))
    else:
        print(
            f"Selected {summary['selected']} | eligible {summary['eligible']} | "
            f"present/installed {summary['installed_or_present']} | failed {summary['failed']} | "
            f"skipped {summary['skipped']}"
        )
        for row in plan:
            cmd = " ".join(shlex.quote(str(x)) for x in row.get("command", []))
            reason = f" — {row.get('reason')}" if row.get("reason") else ""
            print(f"[{row['status']}] {row['id']}" + (f" :: {cmd}" if cmd else "") + reason)
            if row.get("diagnostic") and row["status"] == "failed":
                print("    " + str(row["diagnostic"]).replace("\n", "\n    "))
        print("Policy: " + summary["policy"])
    if summary["failed"]:
        return 1
    if ns.strict and summary["skipped"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
