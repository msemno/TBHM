"""
Safety layer:
  HardLimits (K1) — pre-flight checks on every payload / target
  ResourceMonitor (H3) — self-throttle on RAM/CPU/disk pressure
  ScopeChecker (K2) — enforce in-scope / out-of-scope decisions
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time


class HardLimits:
    """K1: Hard Limits coded into the tool. Cannot be disabled by config."""

    def __init__(self, profile: dict):
        hl = profile.get("hard_limits", {})
        self.forbidden = [s.lower() for s in hl.get("forbidden_payload_substrings", [])]
        self.forbidden_methods = set(m.upper() for m in hl.get("forbidden_methods_unless_explicit", []))
        self.max_records = hl.get("max_records_per_idor_test", 3)
        self.max_response_kb = hl.get("max_response_kb_to_store", 2048)
        self.profile = profile

    def is_payload_safe(self, payload: str) -> tuple[bool, str]:
        """Returns (safe, reason)."""
        if not payload:
            return True, ""
        p = payload.lower()
        for forbidden in self.forbidden:
            if forbidden in p:
                return False, f"contains forbidden pattern: {forbidden}"
        return True, ""

    def is_method_allowed(self, method: str) -> bool:
        m = method.upper()
        if m in self.forbidden_methods:
            return False
        return True

    def cap_response(self, body: bytes) -> bytes:
        cap = self.max_response_kb * 1024
        if len(body) > cap:
            return body[:cap] + b"\n[... truncated by HardLimits ...]"
        return body


class ScopeChecker:
    """K2: scope drift detection. Flags out-of-scope findings as banner_red."""

    def __init__(self, in_scope: list[str], excludes: list[str]):
        self.in_scope = in_scope
        self.excludes = excludes
        self._in_re = self._compile(in_scope)
        self._ex_re = self._compile(excludes)

    @staticmethod
    def _compile(patterns):
        if not patterns:
            return None
        # Treat each pattern as glob-ish: escape, then sub * → .*
        regexes = []
        for p in patterns:
            esc = re.escape(p).replace(r"\*", ".*")
            regexes.append(esc)
        return re.compile("|".join(regexes), re.I)

    def in_scope_check(self, target: str) -> str:
        """Returns 'in_scope', 'out_of_scope', or 'unknown'."""
        if self._ex_re and self._ex_re.search(target):
            return "out_of_scope"
        if self._in_re and self._in_re.search(target):
            return "in_scope"
        if self.in_scope:
            return "out_of_scope"  # explicit scope provided + no match = OOS
        return "unknown"


class ResourceMonitor:
    """H3: prevent resource suicide. Auto-throttle on pressure."""

    def __init__(self):
        self._psutil = None
        try:
            import psutil  # type: ignore
            self._psutil = psutil
        except ImportError:
            pass
        self.pressure_until = 0.0  # if time.time() < this, we're under pressure

    def under_pressure(self) -> tuple[bool, str]:
        """Returns (yes_pressure, reason). Falls back to OK if psutil missing."""
        if not self._psutil:
            return False, ""
        # Cache check for 2 sec to avoid hot-loop psutil calls
        if time.time() < self.pressure_until + 2:
            if time.time() < self.pressure_until:
                return True, "cached_pressure"
        try:
            ram = self._psutil.virtual_memory().percent
            if ram > 85:
                self.pressure_until = time.time() + 5
                return True, f"RAM at {ram:.0f}%"
            cpu = self._psutil.cpu_percent(interval=0.05)
            if cpu > 92:
                self.pressure_until = time.time() + 5
                return True, f"CPU at {cpu:.0f}%"
            disk = shutil.disk_usage("/").free / (1024**3)
            if disk < 0.5:
                self.pressure_until = time.time() + 30
                return True, f"disk free only {disk:.2f} GB"
        except Exception:
            return False, ""
        return False, ""

    def wait_if_pressured(self, max_wait_sec: int = 30):
        """Block briefly when system is under pressure."""
        waited = 0
        while waited < max_wait_sec:
            yes, reason = self.under_pressure()
            if not yes:
                return
            time.sleep(2)
            waited += 2


def tool_available(name: str) -> bool:
    """Is a binary on $PATH?"""
    return shutil.which(name) is not None


def tool_version(name: str) -> str:
    """Best-effort version string for a tool."""
    if not tool_available(name):
        return "missing"
    for flag in ("-version", "--version", "-V", "version"):
        try:
            r = subprocess.run([name, flag], capture_output=True, text=True, timeout=5)
            out = (r.stdout + r.stderr).strip().split("\n")[0]
            if out:
                return out[:80]
        except Exception:
            continue
    return "available"
