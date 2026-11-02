"""Shared helpers for TBHM v3 add-on phases."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from tbhm_addons.logging_core import RedTeamLogger, RunContext


def evidence_dir(ctx: Any, name: str) -> Path:
    out = Path(ctx.output) / "evidence" / "v3_addons" / name
    out.mkdir(parents=True, exist_ok=True)
    return out


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def write_md(path: Path, title: str, sections: list[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}", ""]
    for h, body in sections:
        lines += [f"## {h}", str(body).strip() or "-", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def make_logger(ctx: Any, phase_id: str, target: str = "") -> RedTeamLogger:
    rc = RunContext(
        engagement=(getattr(ctx.args, "bug_bounty_program", "") or ctx.profile.get("name", "UNSPECIFIED")),
        target=target or (ctx.targets[0] if getattr(ctx, "targets", None) else ""),
        pivot_host=getattr(ctx.args, "pivot_host", "") if hasattr(ctx, "args") else "",
        session_handle=(getattr(ctx.args, "ad_user", "") or getattr(ctx.args, "session_handle", "") or ""),
        roe_ref=(getattr(ctx.args, "bug_bounty_program", "") or "authorized-run"),
    )
    # Best effort environment snapshot. It never stores AD passwords.
    try:
        rc.snapshot_environment()
    except Exception:
        pass
    return RedTeamLogger(str(ctx.output), ctx=rc, capture_background=True)


def domain_to_base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


def severity(v: str, default: str = "INFO") -> str:
    m = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
    return m.get((v or "").lower(), default)


def confidence(v: str, default: str = "MEDIUM") -> str:
    m = {"firm": "HIGH", "high": "HIGH", "medium": "MEDIUM", "tentative": "MEDIUM", "low": "LOW"}
    return m.get((v or "").lower(), default)


def now_iso() -> str:
    return datetime.utcnow().isoformat()
