"""Honest environment and dependency diagnostics for TBHM v3.9.7.5."""
from __future__ import annotations

import importlib.util
import json
import os
import platform
import socket
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from core import capability_registry
from core.version import VERSION

ROOT = Path(__file__).resolve().parents[1]


def _check(name: str, ok: bool, detail: str, remediation: str = "", required: bool = False) -> dict:
    return {"name": name, "ok": bool(ok), "required": bool(required), "detail": detail, "remediation": remediation}


def _package_name(requirement: str) -> str:
    text = requirement.split("#", 1)[0].strip()
    for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "["):
        text = text.split(sep, 1)[0]
    return text.strip().replace("-", "_")


_IMPORT_NAMES = {"PyYAML": "yaml", "pyyaml": "yaml"}


def _requirements(path: Path) -> list[tuple[str, str, bool]]:
    """Return (distribution, import_name, required). Inline comments containing
    ``optional`` are honored instead of turning recommended adapters into hard
    application failures.
    """
    if not path.is_file():
        return []
    rows: list[tuple[str, str, bool]] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(('-r ', '--requirement ')):
            include = path.parent / stripped.split(None, 1)[1]
            if include.resolve() != path.resolve():
                rows.extend(_requirements(include))
            continue
        if stripped.startswith('-'):
            continue
        package = _package_name(raw.split(' --hash=', 1)[0])
        if not package:
            continue
        import_name = _IMPORT_NAMES.get(package, package.replace("-", "_"))
        required = "optional" not in raw.lower()
        rows.append((package, import_name, required))
    return rows


def _writable_directory(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".tbhm-doctor-", dir=path, delete=True) as handle:
            handle.write(b"ok"); handle.flush()
        return True, str(path.resolve())
    except Exception as exc:
        return False, f"{path}: {type(exc).__name__}: {exc}"


def _json_valid(path: Path) -> tuple[bool, str]:
    try:
        json.loads(path.read_text(encoding="utf-8")); return True, str(path)
    except Exception as exc:
        return False, f"{path}: {type(exc).__name__}: {exc}"


def _yaml_valid(path: Path) -> tuple[bool, str]:
    try:
        import yaml
        yaml.safe_load(path.read_text(encoding="utf-8")); return True, str(path)
    except Exception as exc:
        return False, f"{path}: {type(exc).__name__}: {exc}"


def _service_state(url: str, probe: bool) -> dict:
    parsed = urlparse(url)
    if not probe:
        return {"url": url, "state": "not_checked", "detail": "service probing disabled"}
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=0.7):
            return {"url": url, "state": "reachable", "detail": f"TCP {host}:{port} reachable"}
    except Exception as exc:
        return {"url": url, "state": "unreachable", "detail": f"{type(exc).__name__}: {exc}"}


def run(*, output_dir: str | Path | None = None, capability_path: str | Path | None = None,
        policy_files: list[str | Path] | None = None, evidence_store: str | Path | None = None,
        probe_services: bool = False) -> dict:
    checks: list[dict] = []
    py_ok = sys.version_info[:2] == (3, 12)
    checks.append(_check("python_version", py_ok, platform.python_version(), "Use the packaged Python 3.12 runtime.", required=True))
    checks.append(_check("operating_system", True, f"{platform.system()} {platform.release()} ({sys.platform})"))

    for package, import_name, required in _requirements(ROOT / "requirements.txt"):
        try:
            ok = importlib.util.find_spec(import_name) is not None
        except (ImportError, ValueError, AttributeError):
            ok = False
        checks.append(_check(f"python_package:{package}", ok, "installed" if ok else "missing", f"Install with: python3 -m pip install {package}", required=required))

    firmware_tools = [
        ("file", "file identification", "apt install file"),
        ("strings", "printable-string extraction", "apt install binutils"),
        ("readelf", "ELF metadata and hardening", "apt install binutils"),
        ("binwalk", "firmware signature scan/extraction", "apt install binwalk"),
        ("unblob", "recursive firmware extraction", "apt install unblob or isolated pip install unblob"),
        ("unsquashfs", "SquashFS extraction", "apt install squashfs-tools"),
        ("sasquatch", "vendor SquashFS extraction fallback", "install a maintained sasquatch build"),
        ("qemu-mipsel-static", "MIPS little-endian user-mode emulation", "apt install qemu-user-static"),
        ("qemu-mips-static", "MIPS big-endian user-mode emulation", "apt install qemu-user-static"),
        ("qemu-arm-static", "ARM user-mode emulation", "apt install qemu-user-static"),
        ("qemu-aarch64-static", "AArch64 user-mode emulation", "apt install qemu-user-static"),
        ("r2", "Radare2 static reverse engineering", "apt install radare2"),
        ("rizin", "Rizin static reverse engineering", "install rizin"),
        ("analyzeHeadless", "Ghidra headless export", "install Ghidra and add support/ to PATH"),
        ("capa", "capability classification", "install capa in an isolated environment"),
        ("floss", "obfuscated-string extraction", "install FLOSS in an isolated environment"),
        ("podman", "rootless disposable container sandbox", "apt install podman"),
        ("docker", "disposable container fallback", "install Docker Engine with least privilege"),
        ("qemu-img", "copy-on-write VM overlay creation", "apt install qemu-utils"),
        ("qemu-system-x86_64", "disposable full-system VM execution", "apt install qemu-system-x86"),
        ("tshark", "offline packet-capture protocol analysis", "apt install tshark"),
        ("katana", "in-scope web and JavaScript discovery", "install ProjectDiscovery Katana"),
        ("paramspider", "historical URL and parameter discovery", "install ParamSpider in an isolated environment"),
        ("zap-baseline.py", "OWASP ZAP baseline/AJAX spider adapter", "install OWASP ZAP or its official container"),
        ("UEFIExtract", "UEFI firmware-volume extraction", "install UEFITool and expose UEFIExtract"),
        ("uefi-firmware-parser", "UEFI static parsing", "install uefi-firmware-parser in an isolated environment"),
        ("apkanalyzer", "Android package manifest/component analysis", "install Android SDK command-line tools"),
        ("jadx", "Android DEX decompilation", "install JADX"),
    ]
    for tool, purpose, remediation in firmware_tools:
        path = shutil.which(tool)
        checks.append(_check(f"tool:{tool}", bool(path), f"{purpose}: {path or 'missing'}", remediation, required=False))

    angr_available = importlib.util.find_spec("angr") is not None
    checks.append(_check("python_module:angr", angr_available, "installed" if angr_available else "missing",
                         "Install angr in an isolated environment and set TBHM_TOOL_HOME if needed.", required=False))

    emba_candidates = [
        shutil.which("emba"), shutil.which("emba.sh"), "/opt/emba/emba", "/opt/emba/emba.sh",
        str(Path.home() / "emba" / "emba"), str(Path.home() / "emba" / "emba.sh"),
    ]
    emba_path = next((str(Path(x).expanduser()) for x in emba_candidates if x and Path(x).expanduser().is_file()), "")
    checks.append(_check("tool:emba", bool(emba_path), f"EMBA firmware analyzer: {emba_path or 'missing'}",
                         "Clone EMBA into an isolated analysis VM, run its installer, then set EMBA_HOME or --emba-path.", required=False))
    rs_candidates = [os.environ.get("ROUTERSPLOIT_HOME", ""), "/opt/routersploit", "/usr/share/routersploit", str(Path.home() / "routersploit")]
    rs_root = next((str(Path(x).expanduser()) for x in rs_candidates if x and (Path(x).expanduser() / "routersploit" / "modules").is_dir()), "")
    checks.append(_check("tool:routersploit_catalog", bool(rs_root), f"RouterSploit module root: {rs_root or 'missing'}",
                         "Install or clone RouterSploit and set ROUTERSPLOIT_HOME or --routersploit-root. TBHM uses catalog/import mode only.", required=False))

    out = Path(output_dir) if output_dir else Path.cwd() / "results"
    ok, detail = _writable_directory(out)
    checks.append(_check("writable_output_directory", ok, detail, "Choose a writable --output directory.", required=True))

    profiles = sorted((ROOT / "profiles").glob("*.y*ml"))
    for path in profiles:
        ok, detail = _yaml_valid(path)
        checks.append(_check(f"profile:{path.name}", ok, detail, "Correct the YAML syntax.", required=True))

    for path in [ROOT / "tooling" / "capability_registry_v3971.json", ROOT / "tooling" / "execution_adapter_registry_v396.json", ROOT / "tooling" / "tool_catalog_v3975.json", ROOT / "tooling" / "tool_catalog_v396.json"]:
        ok, detail = _json_valid(path)
        checks.append(_check(f"configuration:{path.name}", ok, detail, "Restore or correct the JSON file.", required=True))

    for raw in policy_files or []:
        path = Path(raw)
        validator = _json_valid if path.suffix.lower() == ".json" else _yaml_valid
        ok, detail = validator(path)
        checks.append(_check(f"policy:{path.name}", ok, detail, "Correct the policy file before use.", required=True))

    if evidence_store:
        ep = Path(evidence_store)
        ok = ep.exists() and os.access(ep, os.R_OK)
        checks.append(_check("evidence_store", ok, str(ep), "Provide a readable evidence store path."))

    try:
        registry = capability_registry.load(capability_path)
        cap_summary = capability_registry.summary(registry)
        checks.append(_check("capability_registry", True, f"{cap_summary['registered']} capabilities registered"))
    except Exception as exc:
        cap_summary = {"error": str(exc), "capabilities": []}
        checks.append(_check("capability_registry", False, str(exc), "Correct the capability registry.", required=True))

    ai_home = Path(os.environ.get("TBHM_AI_HOME", "~/.local/share/tbhm-ai")).expanduser()
    ai_config = ai_home / "config"
    checks.append(_check("ai_home", True, f"{ai_home} ({'initialized' if ai_config.exists() else 'not initialized'})"))
    env_names = sorted({name for row in cap_summary.get("capabilities", []) for name in row.get("required_environment_variables", [])})
    environment = [{"name": name, "present": bool(str(os.environ.get(name, "")).strip()), "value": "[REDACTED]" if os.environ.get(name) else ""} for name in env_names]
    services = [_service_state(os.environ.get("TBHM_LOCAL_LLM_URL", "http://127.0.0.1:11434"), probe_services)]

    required_failures = [x for x in checks if x["required"] and not x["ok"]]
    optional_failures = [x for x in checks if not x["required"] and not x["ok"]]
    return {
        "release": VERSION,
        "ok": not required_failures,
        "summary": {"checks": len(checks), "required_failures": len(required_failures), "optional_failures": len(optional_failures)},
        "checks": checks,
        "capability_summary": cap_summary,
        "environment_variables": environment,
        "optional_services": services,
    }
