"""Allowlisted, read-only structured plan executor for TBHM v3.9.7.5.

No action accepts an arbitrary executable, raw command line, shell fragment, or
URL. Every argument is validated and subprocesses are launched with argv lists,
timeouts, and ``shell=False`` semantics.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from core.approval_gate import approved
from core.osint_collectors import collect as collect_osint

_ALLOWED_ACTIONS = {"rdap_lookup", "sherlock_username", "maigret_username", "cosign_verify_blob"}
_USERNAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_DOMAIN_OR_IP = re.compile(r"^[A-Za-z0-9:.-]{1,253}$")
_SHELL_META = re.compile(r"[;&|`$<>\n\r\x00]")


def load_plan(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_plan(data)
    return data


def validate_plan(plan: dict) -> None:
    if not isinstance(plan, dict):
        raise ValueError("plan must be an object")
    if str(plan.get("schema_version") or "1") not in {"1", "1.0"}:
        raise ValueError("unsupported plan schema_version")
    actions = plan.get("actions")
    if not isinstance(actions, list) or not actions:
        raise ValueError("plan.actions must be a non-empty list")
    if len(actions) > 100:
        raise ValueError("plan contains more than 100 actions")
    for idx, action in enumerate(actions):
        if not isinstance(action, dict):
            raise ValueError(f"actions[{idx}] must be an object")
        kind = str(action.get("action_type") or "")
        if kind not in _ALLOWED_ACTIONS:
            raise ValueError(f"actions[{idx}] uses unknown or prohibited action_type: {kind}")
        if any(key in action for key in ("command", "shell", "executable", "argv")):
            raise ValueError(f"actions[{idx}] may not provide command/shell/executable/argv")
        args = action.get("arguments")
        if not isinstance(args, dict):
            raise ValueError(f"actions[{idx}].arguments must be an object")
        _validated_arguments(kind, args)


def _clean(value: object, *, label: str, regex: re.Pattern[str]) -> str:
    text = str(value or "").strip()
    if not text or _SHELL_META.search(text) or not regex.fullmatch(text):
        raise ValueError(f"invalid {label}")
    return text


def _existing_file(value: object, *, label: str) -> str:
    text = str(value or "").strip()
    if not text or _SHELL_META.search(text):
        raise ValueError(f"invalid {label}")
    path = Path(text).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"{label} not found: {path}")
    return str(path)


def _validated_arguments(kind: str, args: dict) -> dict:
    allowed: dict[str, set[str]] = {
        "rdap_lookup": {"query", "query_type", "redact_pii"},
        "sherlock_username": {"username"},
        "maigret_username": {"username"},
        "cosign_verify_blob": {"blob", "signature", "certificate", "key"},
    }
    unknown = set(args) - allowed[kind]
    if unknown:
        raise ValueError(f"unsupported arguments for {kind}: {', '.join(sorted(unknown))}")
    if kind == "rdap_lookup":
        query_type = str(args.get("query_type") or "domain")
        if query_type not in {"domain", "ip"}:
            raise ValueError("query_type must be domain or ip")
        return {"query": _clean(args.get("query"), label="RDAP query", regex=_DOMAIN_OR_IP), "query_type": query_type, "redact_pii": bool(args.get("redact_pii", True))}
    if kind in {"sherlock_username", "maigret_username"}:
        return {"username": _clean(args.get("username"), label="username", regex=_USERNAME)}
    normalized = {
        "blob": _existing_file(args.get("blob"), label="blob"),
        "signature": _existing_file(args.get("signature"), label="signature"),
    }
    certificate = args.get("certificate")
    key = args.get("key")
    if bool(certificate) == bool(key):
        raise ValueError("cosign verification requires exactly one of certificate or key")
    normalized["certificate" if certificate else "key"] = _existing_file(certificate or key, label="certificate" if certificate else "key")
    return normalized


def _stable_id(action: dict) -> str:
    canonical = json.dumps({"action_type": action.get("action_type"), "arguments": action.get("arguments")}, sort_keys=True, separators=(",", ":"))
    return "act-" + hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _tool_version(executable: str) -> str:
    path = shutil.which(executable)
    if not path:
        return "unavailable"
    for flag in ("--version", "version", "-version"):
        try:
            result = subprocess.run([path, flag], capture_output=True, text=True, timeout=5, check=False)
            value = (result.stdout or result.stderr).strip().splitlines()
            if value:
                return value[0][:300]
        except Exception:
            continue
    return "installed-version-unknown"


def _command(kind: str, args: dict) -> list[str]:
    if kind == "sherlock_username":
        return ["sherlock", args["username"], "--print-found", "--no-color"]
    if kind == "maigret_username":
        return ["maigret", args["username"], "--no-progressbar"]
    if kind == "cosign_verify_blob":
        cmd = ["cosign", "verify-blob", "--signature", args["signature"]]
        if "certificate" in args:
            cmd += ["--certificate", args["certificate"]]
        else:
            cmd += ["--key", args["key"]]
        return cmd + [args["blob"]]
    raise ValueError(f"no command for {kind}")


def execute(plan: dict, *, output_dir: str | Path, approval_manifest: dict | None = None,
            dry_run: bool = False, timeout: int = 120, runner: Callable | None = None,
            osint_transport: Callable | None = None) -> dict:
    validate_plan(plan)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    timeout = max(1, min(int(timeout), 900))
    rows: list[dict] = []
    approval_manifest = approval_manifest or {}
    for action in plan["actions"]:
        kind = str(action["action_type"])
        args = _validated_arguments(kind, action["arguments"])
        action_id = str(action.get("action_id") or _stable_id(action))
        start = datetime.now(timezone.utc)
        row = {"action_id": action_id, "action_type": kind, "arguments": args, "started_at": start.isoformat(), "dry_run": dry_run, "status": "pending", "stdout": "", "stderr": "", "exit_code": None, "tool_version": "native-python" if kind == "rdap_lookup" else _tool_version(_command(kind, args)[0])}
        if kind in {"sherlock_username", "maigret_username"}:
            ok, detail = approved(approval_manifest, "osint_person_exposure")
            row["approval"] = {"verified": ok, "detail": detail}
            if not ok:
                row.update({"status": "blocked", "stderr": detail})
                row["ended_at"] = datetime.now(timezone.utc).isoformat(); rows.append(row); continue
        else:
            row["approval"] = {"verified": True, "detail": "not required by capability policy"}
        if dry_run:
            row["status"] = "dry_run"
            row["planned_argv"] = [] if kind == "rdap_lookup" else _command(kind, args)
            row["ended_at"] = datetime.now(timezone.utc).isoformat(); rows.append(row); continue
        try:
            if kind == "rdap_lookup":
                result = collect_osint("rdap", args["query"], query_type=args["query_type"], timeout=timeout, transport=osint_transport, redact_pii=args["redact_pii"])
                row["stdout"] = json.dumps(result, ensure_ascii=False)[:4_000_000]
                row["exit_code"] = 0 if result.get("status") == "ok" else 1
                row["status"] = "completed" if row["exit_code"] == 0 else "failed"
            else:
                cmd = _command(kind, args)
                if shutil.which(cmd[0]) is None:
                    row.update({"status": "unavailable", "exit_code": 127, "stderr": f"executable not found: {cmd[0]}"})
                elif runner:
                    rc, stdout, stderr = runner(cmd, timeout=timeout, log_name=f"safe_plan_{action_id}")
                    row.update({"status": "completed" if rc == 0 else "failed", "exit_code": rc, "stdout": stdout[:4_000_000], "stderr": stderr[:1_000_000]})
                else:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
                    row.update({"status": "completed" if proc.returncode == 0 else "failed", "exit_code": proc.returncode, "stdout": proc.stdout[:4_000_000], "stderr": proc.stderr[:1_000_000]})
        except subprocess.TimeoutExpired:
            row.update({"status": "timeout", "exit_code": 124, "stderr": f"timeout after {timeout}s"})
        except Exception as exc:
            row.update({"status": "failed", "exit_code": 1, "stderr": f"{type(exc).__name__}: {exc}"})
        row["ended_at"] = datetime.now(timezone.utc).isoformat()
        row["evidence_sha256"] = hashlib.sha256((row["stdout"] + "\n" + row["stderr"]).encode("utf-8", errors="replace")).hexdigest()
        rows.append(row)
    payload = {"schema_version": "1", "executor": "TBHM-safe-plan-v4.0.0", "actions": rows, "summary": {status: sum(1 for row in rows if row["status"] == status) for status in sorted({row["status"] for row in rows})}}
    (out / "safe_plan_execution.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload
