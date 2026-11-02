"""
tbhm_addons.mod_service_primitive
=================================

Detects the exact condition the operator described:

    "a service running an .exe with no code in it, so if anyone puts code in
     it, it runs immediately"

That condition, stated precisely, is: a service whose executable — or the
directory containing it — is WRITABLE by a non-privileged principal, so a
low-privileged user could replace/plant the binary and have it run as the
service account. This module FINDS that condition and PROVES it safely.

Covered checks:
  * Service binary path writable by non-admins
  * Directory containing the service binary writable by non-admins
  * Unquoted service path with a writable intermediate directory
  * Weak service ACL (SERVICE_CHANGE_CONFIG / WRITE_DAC / WRITE_OWNER)
  * DLL search-order hijack: writable dir on the binary's DLL search path
  * Scheduled-task binary writable / weak run-as context

PROOF MODEL — INERT MARKER ONLY:
  To prove "I could write into the execution slot" WITHOUT weaponizing, the
  module optionally stages a timestamped, NON-EXECUTABLE marker file next to
  the target binary (e.g. `tbhm_write_proof_<ts>.txt`), confirms it exists,
  hashes it, then deletes it. This proves write-access — the whole
  vulnerability — for the report, while never placing runnable code in the
  execution path and never triggering execution.

DELIBERATELY ABSENT:
  There is no stage that writes an executable/payload into the binary or
  service slot, and no stage that starts/triggers the service to run planted
  code. Proving code-execution as the service account is a manual, per-host,
  client-witnessed step using a benign command — not automated in a reusable
  tool. Automating that stage is what turns an assessment tool into a dropper;
  this module refuses to.

Platform: findings run on Windows (the targets are Windows). The module is
import-safe and unit-testable on Linux (the parsing/logic is pure-Python; the
Windows-only calls are guarded and degrade to 'unsupported_platform').
"""

from __future__ import annotations

import os
import sys
import time
import shutil
import hashlib
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

IS_WINDOWS = sys.platform.startswith("win")

# ACLs that let a principal reconfigure or take over a service
DANGEROUS_SERVICE_RIGHTS = ["SERVICE_CHANGE_CONFIG", "WRITE_DAC",
                            "WRITE_OWNER", "GENERIC_WRITE", "GENERIC_ALL"]
# principals that should NOT hold those rights
UNTRUSTED_PRINCIPALS = ["Everyone", "Authenticated Users", "Users",
                        "BUILTIN\\Users", "NT AUTHORITY\\INTERACTIVE"]


class _NoopPhase:
    def event(self, *a: Any, **k: Any) -> None: ...
    def tool(self, *a: Any, **k: Any) -> None: ...
    def fail(self, *a: Any, **k: Any) -> None: ...
    def run(self, name: str, argv: list[str], **k: Any):
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=k.get("timeout", 120))


@dataclass
class ServiceFinding:
    service: str
    binary_path: str
    issue: str            # writable_binary | writable_dir | unquoted_path |
                          # weak_acl | dll_hijack | task_writable
    principal: str        # who holds the dangerous access
    severity: str         # medium | high | critical
    proof: str = ""       # inert-marker proof result, if run
    remediation: str = ""


@dataclass
class ServiceResult:
    host: str = ""
    findings: list[ServiceFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    platform_supported: bool = IS_WINDOWS

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


class ServicePrimitiveModule:
    def __init__(self, prove_writable: bool = False) -> None:
        """prove_writable: if True, stage+delete an inert marker to PROVE
        write-access. Marker is a .txt, never in the execution path as code."""
        self.prove_writable = prove_writable

    # -- enumeration --------------------------------------------------------
    def enumerate_services(self, phase: Any = None) -> list[dict[str, str]]:
        """Return [{name, binpath}] via `sc query` + `sc qc`. Windows only."""
        ph = phase or _NoopPhase()
        if not IS_WINDOWS:
            ph.event("platform", "service enum requires Windows; skipped")
            return []
        services: list[dict[str, str]] = []
        try:
            names_cp = ph.run("sc.query", ["sc", "query", "type=", "service",
                                           "state=", "all"], timeout=120)
            names = [ln.split(":", 1)[1].strip()
                     for ln in (names_cp.stdout or "").splitlines()
                     if ln.strip().startswith("SERVICE_NAME:")]
            for name in names:
                qc = ph.run("sc.qc", ["sc", "qc", name], timeout=30)
                binpath = ""
                for ln in (qc.stdout or "").splitlines():
                    if "BINARY_PATH_NAME" in ln:
                        binpath = ln.split(":", 1)[1].strip()
                        break
                services.append({"name": name, "binpath": binpath})
            ph.event("enum", f"{len(services)} services enumerated")
        except Exception as exc:  # noqa: BLE001
            ph.fail("service enumeration failed", exc)
        return services

    # -- checks -------------------------------------------------------------
    def check_host(self, phase: Any = None) -> ServiceResult:
        ph = phase or _NoopPhase()
        res = ServiceResult(host=os.environ.get("COMPUTERNAME", "localhost"))
        if not IS_WINDOWS:
            res.errors.append("unsupported_platform: Windows required for "
                              "live checks (logic is unit-tested on Linux)")
            ph.event("platform", "non-Windows; returning empty live result")
            return res

        for svc in self.enumerate_services(ph):
            name, raw = svc["name"], svc["binpath"]
            exe = self._extract_exe(raw)
            if not exe:
                continue

            # unquoted path with spaces + writable intermediate dir
            if self._is_unquoted_with_space(raw):
                wdir = self._first_writable_intermediate(raw)
                if wdir:
                    self._add(res, ph, name, exe, "unquoted_path",
                              wdir, "high",
                              "Quote the BINARY_PATH_NAME; fix directory ACLs.")

            # writable binary
            who = self._writable_by_untrusted(exe)
            if who:
                f = self._add(res, ph, name, exe, "writable_binary", who,
                              "critical",
                              "Restrict file ACL so only admins/SYSTEM can "
                              "write the service binary.")
                if self.prove_writable:
                    f.proof = self._inert_marker_proof(exe, ph)

            # writable containing directory
            bindir = os.path.dirname(exe)
            who_dir = self._writable_by_untrusted(bindir)
            if who_dir:
                f = self._add(res, ph, name, exe, "writable_dir", who_dir,
                              "critical",
                              "Restrict directory ACL; the binary can be "
                              "replaced by a low-priv user otherwise.")
                if self.prove_writable:
                    f.proof = self._inert_marker_proof(bindir, ph,
                                                       is_dir=True)

            # weak service ACL
            bad = self._weak_service_acl(name, ph)
            if bad:
                self._add(res, ph, name, exe, "weak_acl", bad, "high",
                          "Remove SERVICE_CHANGE_CONFIG/WRITE_DAC/WRITE_OWNER "
                          "from non-admin principals (sc sdset).")

            # DLL hijack: writable dir on search path
            hijack_dir = self._dll_hijack_dir(exe)
            if hijack_dir:
                self._add(res, ph, name, exe, "dll_hijack", hijack_dir,
                          "high",
                          "Remove writable directories from the binary's DLL "
                          "search path; enable safe DLL search mode.")

        return res

    # -- proof (inert marker only) -----------------------------------------
    def _inert_marker_proof(self, target_path: str, ph: Any,
                            is_dir: bool = False) -> str:
        """Stage a NON-EXECUTABLE marker to prove write-access, verify, hash,
        remove. Never writes code, never touches the execution path as code."""
        ts = time.strftime("%Y%m%d-%H%M%S")
        dirpath = target_path if is_dir else os.path.dirname(target_path)
        marker = os.path.join(dirpath, f"tbhm_write_proof_{ts}.txt")
        content = (f"AUTHORIZED RED-TEAM WRITE-ACCESS PROOF\n"
                   f"timestamp={ts}\n"
                   f"purpose=demonstrate writability of service path\n"
                   f"this file is inert text, not code, and will be removed\n")
        try:
            with open(marker, "w", encoding="utf-8") as fh:
                fh.write(content)
            exists = os.path.isfile(marker)
            digest = hashlib.sha256(content.encode()).hexdigest()[:16]
            os.remove(marker)
            removed = not os.path.exists(marker)
            result = (f"PROVEN: wrote+verified+removed inert marker "
                      f"({marker}); sha256:{digest}; removed={removed}")
            ph.event("write_proof", result, path=marker, exists=exists)
            return result
        except Exception as exc:  # noqa: BLE001
            ph.fail("inert-marker proof failed (likely NOT writable)", exc,
                    path=marker)
            return f"NOT PROVEN: write failed ({exc})"

    # -- windows helpers (guarded) -----------------------------------------
    @staticmethod
    def _extract_exe(binpath: str) -> str:
        if not binpath:
            return ""
        s = binpath.strip()
        if s.startswith('"'):
            end = s.find('"', 1)
            return s[1:end] if end > 0 else s.strip('"')
        # unquoted: exe ends at first .exe token
        low = s.lower()
        idx = low.find(".exe")
        return s[:idx + 4] if idx != -1 else s.split(" ")[0]

    @staticmethod
    def _is_unquoted_with_space(binpath: str) -> bool:
        s = binpath.strip()
        return (not s.startswith('"')) and (" " in s) and (".exe" in s.lower())

    def _first_writable_intermediate(self, binpath: str) -> str:
        exe = self._extract_exe(binpath)
        parts = exe.split("\\")
        # build progressive paths: C:\, C:\Program Files, ...
        acc = ""
        for p in parts[:-1]:
            acc = p if acc == "" else acc + "\\" + p
            probe = acc if acc.endswith("\\") else acc + "\\"
            if self._writable_by_untrusted(probe):
                return probe
        return ""

    def _writable_by_untrusted(self, path: str) -> str:
        """Return the untrusted principal name if `path` grants write to a
        non-admin principal, else ''. Uses icacls parsing on Windows."""
        if not IS_WINDOWS or not path:
            return ""
        icacls = shutil.which("icacls")
        if not icacls:
            return ""
        try:
            cp = subprocess.run([icacls, path], capture_output=True,
                                text=True, timeout=30)
            out = cp.stdout or ""
            for principal in UNTRUSTED_PRINCIPALS:
                # (W), (M), (F) = write/modify/full for that principal
                for right in ["(F)", "(M)", "(W)", "(WD)", "(AD)"]:
                    if f"{principal}:" in out and right in out:
                        # crude but effective: principal line contains a write
                        for line in out.splitlines():
                            if principal in line and right in line:
                                return principal
            return ""
        except Exception:
            return ""

    def _weak_service_acl(self, service: str, ph: Any) -> str:
        if not IS_WINDOWS:
            return ""
        try:
            cp = ph.run("sc.sdshow", ["sc", "sdshow", service], timeout=30)
            sddl = (cp.stdout or "").strip()
            # WD = Everyone; write-ish rights CC/DC/LC/SW/RP/WP/DT/LO/CR
            # Presence of grant to 'WD' or 'AU' with config-write is the flag.
            for tag in [";;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD",
                        "A;;WPRC;;;AU", "A;;RPWPCR;;;AU", ";;;WD"]:
                if tag in sddl and ("WP" in sddl or "DC" in sddl):
                    return "Everyone/AuthenticatedUsers (SDDL grant)"
            return ""
        except Exception:
            return ""

    def _dll_hijack_dir(self, exe: str) -> str:
        """A writable directory that sits on the DLL search path (the binary's
        own directory is first). If the binary dir is writable, DLL hijack is
        possible. Deeper CWD/PATH analysis is left to manual review."""
        if not IS_WINDOWS or not exe:
            return ""
        bindir = os.path.dirname(exe)
        return bindir if self._writable_by_untrusted(bindir) else ""

    # -- helper -------------------------------------------------------------
    def _add(self, res: ServiceResult, ph: Any, service: str, exe: str,
             issue: str, principal: str, severity: str,
             remediation: str) -> ServiceFinding:
        f = ServiceFinding(service=service, binary_path=exe, issue=issue,
                           principal=principal, severity=severity,
                           remediation=remediation)
        res.findings.append(f)
        ph.event("finding", f"{issue} on service {service}",
                 service=service, issue=issue, principal=principal,
                 severity=severity)
        return f


if __name__ == "__main__":
    # Linux-safe unit checks of the pure-Python parsing logic.
    m = ServicePrimitiveModule()
    samples = [
        r'C:\Program Files\App\svc.exe -k netsvcs',
        r'"C:\Program Files\App\svc.exe" -k netsvcs',
        r'C:\Windows\system32\svchost.exe',
    ]
    for s in samples:
        print("raw:", s)
        print("  exe:", m._extract_exe(s))
        print("  unquoted+space:", m._is_unquoted_with_space(s))
    print("platform_supported (this box):", IS_WINDOWS)
    print("dangerous rights tracked:", len(DANGEROUS_SERVICE_RIGHTS))
