"""
tbhm_addons.logging_core
========================

Logging subsystem for TBHM v2.24 red-team orchestration.

Design goals (from the operator's request):
  * Log EVERYTHING: phase start/stop, sub-topic invocation, every tool spawn.
  * Exception-only channel: a separate file that contains only failures, with
    full traceback + the exact input state that triggered them, so a bug is
    REPRODUCIBLE rather than "phase X failed".
  * "No-log / silent" mode per operation for OPSEC-sensitive steps, but even
    silent mode writes a minimal AUDIT STUB (timestamp + correlation id +
    phase id) so chain-of-custody survives for an authorized engagement.
  * Background-detail capture: interface, route, resolver, operator host,
    target, session handle (NOT the secret), pivot host — the conditions
    needed to replay a scenario.
  * Correlation IDs so one scenario is traceable end-to-end across many tools.

No third-party dependencies. Pure stdlib so it runs on a stock Kali box.

Channels (all under <run_root>/logs/):
  full.jsonl        every event, structured JSON lines
  full.log          same events, human-readable
  exceptions.jsonl  ONLY events with an exception, full traceback + repro state
  audit.jsonl       minimal stub for EVERY operation incl. silent ones
                    (timestamp, corr_id, phase, verb, target) — never suppressed
  background.json    point-in-time environment snapshot(s) for replay
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
import socket
import getpass
import platform
import threading
import traceback
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _new_corr_id() -> str:
    # short, greppable, collision-safe enough for a single engagement
    return uuid.uuid4().hex[:12]


@dataclass
class RunContext:
    """Background detail needed to replay a scenario. Secrets are referenced by
    handle, never stored. session_handle is e.g. 'roe-ticket-4412/acct-lowpriv'
    — an identifier, not a credential."""
    engagement: str = "UNSPECIFIED"
    operator: str = field(default_factory=lambda: getpass.getuser())
    host: str = field(default_factory=lambda: socket.gethostname())
    os_info: str = field(default_factory=lambda: platform.platform())
    target: str = ""
    pivot_host: str = ""
    session_handle: str = ""          # identifier only, never the secret
    roe_ref: str = ""
    interfaces: str = ""
    routes: str = ""
    resolver: str = ""

    def snapshot_environment(self) -> None:
        """Populate the volatile network fields. Best-effort; never raises."""
        self.interfaces = _safe_cmd(["ip", "-br", "addr"])
        self.routes = _safe_cmd(["ip", "route"])
        try:
            self.resolver = Path("/etc/resolv.conf").read_text(errors="replace")
        except Exception:
            self.resolver = "<unavailable>"


def _safe_cmd(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return (out.stdout or out.stderr or "").strip()
    except Exception as exc:  # noqa: BLE001 - snapshot must never break logging
        return f"<{cmd[0]} unavailable: {exc}>"


class RedTeamLogger:
    """Thread-safe multi-channel logger.

    Usage:
        log = RedTeamLogger(run_root="~/engagements/acme", ctx=RunContext(...))
        with log.phase("BR06-KERB", "kerberoast SPN review") as ph:
            ph.event("enumerate", "ldapsearch SPNs", target="dc01")
            ph.tool("ldapsearch", ["ldapsearch","-x",...], returncode=0)
            # on failure, ph.fail(...) or just let the exception propagate
    """

    def __init__(
        self,
        run_root: str | os.PathLike,
        ctx: Optional[RunContext] = None,
        capture_background: bool = True,
    ) -> None:
        self.root = Path(os.path.expanduser(str(run_root)))
        self.log_dir = self.root / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.ctx = ctx or RunContext()
        if capture_background:
            self.ctx.snapshot_environment()
        self._lock = threading.Lock()

        self._full_jsonl = self.log_dir / "full.jsonl"
        self._full_log = self.log_dir / "full.log"
        self._exc_jsonl = self.log_dir / "exceptions.jsonl"
        self._audit_jsonl = self.log_dir / "audit.jsonl"
        self._bg_json = self.log_dir / "background.json"

        self._write_background()
        self._emit(
            corr_id=_new_corr_id(), phase="RUN", verb="start",
            what="logger initialized", silent=False,
            extra={"log_dir": str(self.log_dir)},
        )

    # -- background ---------------------------------------------------------
    def _write_background(self) -> None:
        rec = {"captured": _utc_iso(), "context": asdict(self.ctx)}
        with self._bg_json.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # -- low-level emit -----------------------------------------------------
    def _emit(
        self,
        corr_id: str,
        phase: str,
        verb: str,
        what: str,
        silent: bool,
        extra: Optional[dict[str, Any]] = None,
        exc: Optional[BaseException] = None,
        repro: Optional[dict[str, Any]] = None,
    ) -> None:
        ts = _utc_iso()
        record: dict[str, Any] = {
            "ts": ts,
            "corr_id": corr_id,
            "phase": phase,
            "verb": verb,
            "what": what,
            "target": self.ctx.target,
            "operator": self.ctx.operator,
        }
        if extra:
            record["extra"] = extra

        # AUDIT STUB — written for EVERY operation, silent or not. Minimal by
        # design so silent mode leaks nothing sensitive but chain-of-custody
        # survives.
        audit = {"ts": ts, "corr_id": corr_id, "phase": phase,
                 "verb": verb, "target": self.ctx.target}

        with self._lock:
            # audit is never suppressed
            self._append(self._audit_jsonl, audit)

            if not silent:
                self._append(self._full_jsonl, record)
                self._append_text(
                    self._full_log,
                    f"{ts} [{corr_id}] {phase:<14} {verb:<10} {what}"
                    + (f"  target={self.ctx.target}" if self.ctx.target else ""),
                )

            if exc is not None:
                exc_rec = dict(record)
                exc_rec["exception"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": "".join(
                        traceback.format_exception(type(exc), exc, exc.__traceback__)
                    ),
                }
                # Reproduction state: the exact inputs that triggered the bug.
                exc_rec["repro"] = repro or {}
                exc_rec["context"] = asdict(self.ctx)
                # exceptions ALWAYS recorded, even under silent mode — a failure
                # you can't see is a failure you can't fix.
                self._append(self._exc_jsonl, exc_rec)
                # also surface into full channel so the timeline is complete
                self._append(self._full_jsonl, exc_rec)
                self._append_text(
                    self._full_log,
                    f"{ts} [{corr_id}] {phase:<14} EXCEPTION  "
                    f"{type(exc).__name__}: {exc}",
                )

    @staticmethod
    def _append(path: Path, obj: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")

    @staticmethod
    def _append_text(path: Path, line: str) -> None:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    # -- public phase API ---------------------------------------------------
    @contextmanager
    def phase(self, phase_id: str, description: str = "", silent: bool = False
              ) -> Iterator["PhaseLogger"]:
        """Context manager wrapping one phase/objective. Times it, logs
        start/stop, and captures any exception (with repro state) without
        swallowing it — the exception re-raises after logging."""
        corr_id = _new_corr_id()
        started = time.monotonic()
        self._emit(corr_id, phase_id, "phase_start", description, silent)
        ph = PhaseLogger(self, phase_id, corr_id, silent)
        try:
            yield ph
        except BaseException as exc:  # noqa: BLE001 - log then re-raise
            self._emit(
                corr_id, phase_id, "phase_error",
                f"unhandled exception in phase: {description}",
                silent=False,  # a crash is never silent
                exc=exc, repro=ph.repro_state(),
            )
            raise
        finally:
            dur = round(time.monotonic() - started, 3)
            self._emit(corr_id, phase_id, "phase_stop",
                       f"duration={dur}s", silent)


class PhaseLogger:
    """Handle passed into a `with logger.phase(...)` block. Accumulates the
    repro state (inputs seen) so that if anything throws, the exception log
    contains the exact conditions to repeat the bug."""

    def __init__(self, parent: RedTeamLogger, phase_id: str,
                 corr_id: str, silent: bool) -> None:
        self._p = parent
        self.phase_id = phase_id
        self.corr_id = corr_id
        self.silent = silent
        self._repro: dict[str, Any] = {"inputs": [], "last_tool": None}

    def repro_state(self) -> dict[str, Any]:
        return dict(self._repro)

    def event(self, verb: str, what: str, silent: Optional[bool] = None,
              **extra: Any) -> None:
        s = self.silent if silent is None else silent
        if extra:
            self._repro["inputs"].append({verb: extra})
        self._p._emit(self.corr_id, self.phase_id, verb, what, s,
                      extra=extra or None)

    def tool(self, name: str, argv: list[str], returncode: Optional[int] = None,
             stdout_tail: str = "", stderr_tail: str = "",
             silent: Optional[bool] = None) -> None:
        """Record a tool spawn. argv is the exact command — this is the spine
        of reproducibility. stdout/stderr tails are truncated on purpose; full
        output belongs in the evidence folder, not the log."""
        s = self.silent if silent is None else silent
        payload = {
            "tool": name,
            "argv": argv,
            "returncode": returncode,
            "stdout_tail": stdout_tail[-800:],
            "stderr_tail": stderr_tail[-800:],
        }
        self._repro["last_tool"] = {"tool": name, "argv": argv}
        self._p._emit(self.corr_id, self.phase_id, "tool", name, s,
                      extra=payload)

    def fail(self, what: str, exc: BaseException, **repro: Any) -> None:
        """Explicitly record a handled failure with repro state, without
        re-raising. Use when you catch an exception and continue."""
        merged = dict(self._repro)
        merged.update(repro)
        self._p._emit(self.corr_id, self.phase_id, "handled_error", what,
                      silent=False, exc=exc, repro=merged)

    def run(self, name: str, argv: list[str], timeout: int = 300,
            silent: Optional[bool] = None,
            input_text: Optional[str] = None) -> subprocess.CompletedProcess:
        """Convenience: spawn a subprocess AND log it in one call. Captures
        output, logs argv+returncode, and on non-zero or exception records it
        to the exception channel with the full command as repro state."""
        try:
            cp = subprocess.run(argv, capture_output=True, text=True,
                                timeout=timeout, input=input_text)
            self.tool(name, argv, returncode=cp.returncode,
                      stdout_tail=cp.stdout or "", stderr_tail=cp.stderr or "",
                      silent=silent)
            if cp.returncode != 0:
                self.event("tool_nonzero",
                           f"{name} exited {cp.returncode}",
                           silent=False, argv=argv, rc=cp.returncode)
            return cp
        except Exception as exc:  # noqa: BLE001
            self.fail(f"tool spawn failed: {name}", exc, argv=argv)
            raise


# -- module self-test -------------------------------------------------------
if __name__ == "__main__":
    import tempfile
    tmp = tempfile.mkdtemp(prefix="tbhm_log_")
    ctx = RunContext(engagement="SELFTEST", target="10.0.0.5",
                     roe_ref="ticket-0001", session_handle="acct-lowpriv")
    log = RedTeamLogger(tmp, ctx=ctx)

    with log.phase("BR06-KERB", "kerberoast SPN review") as ph:
        ph.event("enumerate", "list SPNs via LDAP", dn="CN=svc,DC=x")
        ph.tool("ldapsearch", ["ldapsearch", "-x", "-b", "DC=x"], returncode=0,
                stdout_tail="sAMAccountName: svc_sql")

    # exercise the exception path
    try:
        with log.phase("BR09-SQLI", "intentional failure") as ph:
            ph.event("probe", "trigger bug", url="http://t/x?id=1")
            raise ValueError("simulated parser crash")
    except ValueError:
        pass

    # silent phase — should still leave an audit stub + exception if any
    with log.phase("OPSEC-01", "sensitive step", silent=True) as ph:
        ph.event("quiet", "this line is suppressed from full.log")

    print("Log dir:", os.path.join(tmp, "logs"))
    for f in ["full.jsonl", "exceptions.jsonl", "audit.jsonl", "full.log"]:
        p = Path(tmp) / "logs" / f
        n = sum(1 for _ in p.open()) if p.exists() else 0
        print(f"  {f}: {n} lines")
