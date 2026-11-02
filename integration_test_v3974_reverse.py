#!/usr/bin/env python3
"""Regression and safety tests for TBHM v3.9.7.4 universal reverse update."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import tbhm
from core import firmware_safety as FS
from core import reverse_utils as RU
from phases import firmware_reverse_safe as FW
from phases import firmware_tooling_extended as FT


class FakeRunner:
    def __init__(self, tools=(), handler=None):
        self.tools = set(tools)
        self.handler = handler
        self.calls = []

    def has(self, name):
        return name in self.tools

    def run(self, cmd, timeout=0, cwd=None, log_name=None, **kwargs):
        row = {"cmd": [str(x) for x in cmd], "timeout": timeout,
               "cwd": str(cwd) if cwd else "", "log_name": log_name or ""}
        self.calls.append(row)
        if self.handler:
            return self.handler(row)
        return 127, "", "missing"


class FakeCtx:
    def __init__(self, output, runner=None, **args):
        defaults = dict(
            firmware=None, firmware_rootfs=None, firmware_extract=False,
            emba=False, emba_path=None, emba_profile=None, emba_results=None,
            emba_timeout=600, emba_emulation=False, confirm_isolated_execution=False,
            routersploit_root=None, routersploit_catalog=False, routersploit_results=None,
            firmware_tool_results=None, silent=True,
        )
        defaults.update(args)
        self.args = SimpleNamespace(**defaults)
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.runner = runner or FakeRunner()
        self.findings = []
        self.logs = []
        self.phase_state = {}

    def save_finding(self, finding):
        self.findings.append(dict(finding))
        return len(self.findings)

    def log(self, level, phase, message):
        self.logs.append((level, phase, str(message)))


def make_rootfs(root: Path) -> Path:
    for rel in ("etc", "bin", "sbin", "usr/lib", "var/lib/dpkg", "www/cgi-bin"):
        (root / rel).mkdir(parents=True, exist_ok=True)
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")
    (root / "etc/shadow").write_text("root:!:19000:0:99999:7:::\n", encoding="utf-8")
    (root / "etc/inittab").write_text("# telnetd disabled\n", encoding="utf-8")
    (root / "bin/busybox").write_bytes(b"\x7fELF" + b"\x01\x01" + b"\x00" * 10 + b"\x02\x00\x08\x00" + b"busybox\x00")
    (root / "sbin/httpd").write_bytes(b"\x7fELF" + b"\x01\x01" + b"\x00" * 10 + b"\x02\x00\x08\x00" + b"system\x00http://127.0.0.1\x00")
    (root / "usr/lib/libsample.so").write_bytes(b"\x7fELF" + b"\x01\x01" + b"\x00" * 10 + b"\x03\x00\x08\x00")
    (root / "www/cgi-bin/status.cgi").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    (root / "var/lib/dpkg/status").write_text(
        "Package: busybox\nVersion: 1.36.1\nArchitecture: mipsel\nDescription: Utilities\n\n",
        encoding="utf-8",
    )
    return root


class V3974ReverseTests(unittest.TestCase):
    def test_release_identity(self):
        self.assertEqual(tbhm.VERSION, "4.2.7")
        self.assertIn("firmware_tooling_extended", tbhm.PHASE_ORDER)
        self.assertTrue(Path("tooling/tool_catalog_v3974.json").is_file())

    def test_container_magic_beyond_4k(self):
        with tempfile.TemporaryDirectory() as td:
            image = Path(td) / "vendor.bin"
            image.write_bytes(b"A" * 8192 + b"hsqs" + b"B" * 100)
            self.assertEqual(RU.container_type(image), "SquashFS (little-endian)")

    def test_hardening_failure_is_unknown(self):
        result = RU.parse_hardening(valid={"header": False, "program_headers": False,
                                           "dynamic": False, "symbols": False, "sections": False})
        self.assertFalse(result["analysis_valid"])
        self.assertIsNone(result["nx"])
        self.assertIsNone(result["pie"])
        self.assertEqual(RU.hardening_gaps(result), [])

    def test_rootfs_symlink_cannot_read_host_file(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = make_rootfs(base / "root")
            outside = base / "outside-passwd"
            outside.write_text("hostroot:x:0:0::/:/bin/sh\n", encoding="utf-8")
            (root / "etc/passwd").unlink()
            (root / "etc/passwd").symlink_to(outside)
            self.assertIsNone(FS.safe_read_text(root, "etc/passwd"))
            (root / "etc/passwd").unlink()
            (root / "etc/passwd").symlink_to("../../outside-passwd")
            self.assertIsNone(FS.safe_read_text(root, "etc/passwd"))

    def test_relative_firmware_path_and_binwalk_root_compatibility(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fw = base / "fw.bin"
            fw.write_bytes(b"firmware")
            out = base / "out"

            def handler(call):
                cmd = call["cmd"]
                if cmd[:2] == ["binwalk", "--help"]:
                    return 0, "--run-as USER", ""
                if cmd and cmd[0] == "binwalk":
                    dest = Path(call["cwd"])
                    make_rootfs(dest / "_fw.bin.extracted" / "squashfs-root")
                    return 0, "ok", ""
                return 127, "", "missing"

            runner = FakeRunner({"binwalk"}, handler)
            ctx = FakeCtx(base / "ctx", runner)
            old = Path.cwd()
            try:
                os.chdir(base)
                root, attempts = FW._extract(ctx, Path("fw.bin"), out)
            finally:
                os.chdir(old)
            self.assertIsNotNone(root)
            extraction_call = next(c for c in runner.calls if c["cmd"][:2] == ["binwalk", "-Me"])
            self.assertTrue(Path(extraction_call["cmd"][-1]).is_absolute())
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                self.assertIn("--run-as=root", extraction_call["cmd"])
            self.assertEqual(attempts[-1]["returncode"], 0)

    def test_failed_unsquashfs_uses_sasquatch_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fw = base / "fw.bin"
            fw.write_bytes(b"A" * 100 + b"hsqs" + b"payload")

            def handler(call):
                cmd = call["cmd"]
                dest = Path(cmd[cmd.index("-d") + 1])
                if cmd[0] == "unsquashfs":
                    dest.mkdir(parents=True, exist_ok=True)
                    return 1, "", "vendor compression unsupported"
                if cmd[0] == "sasquatch":
                    make_rootfs(dest)
                    return 0, "ok", ""
                return 127, "", "missing"

            runner = FakeRunner({"unsquashfs", "sasquatch"}, handler)
            ctx = FakeCtx(base / "ctx", runner)
            attempts = []
            root = FW._carve_and_unsquash(ctx, fw, base / "work", attempts)
            self.assertIsNotNone(root)
            self.assertEqual([c["cmd"][0] for c in runner.calls], ["unsquashfs", "sasquatch"])
            self.assertEqual(attempts[0]["returncode"], 1)
            self.assertEqual(attempts[1]["returncode"], 0)

    def test_rootfs_audit_cert_service_sbom_update_and_priorities(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = make_rootfs(base / "root")
            (root / "etc/ca.pem").write_text(
                "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n", encoding="utf-8")
            (root / "sbin/upgrade.sh").write_text("#!/bin/sh\nmtd write /tmp/fw.bin firmware\n", encoding="utf-8")
            os.chmod(root / "sbin/httpd", (root / "sbin/httpd").stat().st_mode | stat.S_ISUID)
            ctx = FakeCtx(base / "ctx", FakeRunner())
            out = base / "evidence"
            out.mkdir()
            summary = FW._rootfs_audit(ctx, root, out)
            self.assertEqual(summary["services_started"], [])
            self.assertEqual(summary["key_material"]["private_keys"], [])
            self.assertEqual(summary["key_material"]["certificates"], ["etc/ca.pem"])
            self.assertEqual(summary["components"]["sbom_components"], 1)
            self.assertEqual(summary["web"]["command_execution_leads"], [])
            self.assertIn("sbin/upgrade.sh", summary["update_chain"]["unverified"])
            self.assertEqual(summary["binary_priorities"][0]["path"], "sbin/httpd")
            self.assertTrue((out / "FIRMWARE_SBOM.cdx.json").is_file())
            self.assertTrue((out / "FIRMWARE_ATTACK_SURFACE.json").is_file())
            self.assertFalse(any("service startup" in f.get("title", "").lower() for f in ctx.findings))
            self.assertFalse(any("private key material" in f.get("title", "").lower() for f in ctx.findings))

    def test_emba_static_command_and_emulation_gate(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            emba = base / "emba/emba"
            profiles = emba.parent / "scan-profiles"
            profiles.mkdir(parents=True)
            emba.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            emba.chmod(0o755)
            (profiles / "default-scan.emba").write_text("STATIC=1\n", encoding="utf-8")
            (profiles / "default-scan-emulation.emba").write_text("EMULATION=1\n", encoding="utf-8")
            fw = base / "fw.bin"; fw.write_bytes(b"firmware")
            runner = FakeRunner(handler=lambda call: (0, "ok", ""))
            ctx = FakeCtx(base / "ctx", runner, firmware=str(fw), emba=True,
                          emba_path=str(emba.parent))
            source = FT._run_emba(ctx, base / "evidence")
            self.assertIsNotNone(source)
            cmd = runner.calls[-1]["cmd"]
            self.assertEqual(cmd[0], str(emba.resolve()))
            self.assertIn(str(fw.resolve()), cmd)
            self.assertIn(str((profiles / "default-scan.emba").resolve()), cmd)

            denied_runner = FakeRunner(handler=lambda call: (0, "ok", ""))
            denied = FakeCtx(base / "denied", denied_runner, firmware=str(fw), emba=True,
                             emba_path=str(emba.parent), emba_emulation=True,
                             confirm_isolated_execution=False)
            self.assertIsNone(FT._run_emba(denied, base / "denied-evidence"))
            self.assertEqual(denied_runner.calls, [])

            # v3.9.7.5 tightens the old confirmation-only gate: host EMBA
            # emulation is no longer allowed.  A separately prepared sandbox
            # image is mandatory, so confirmation without an image is refused.
            allowed_runner = FakeRunner(handler=lambda call: (0, "ok", ""))
            allowed = FakeCtx(base / "allowed", allowed_runner, firmware=str(fw), emba=True,
                              emba_path=str(emba.parent), emba_emulation=True,
                              confirm_isolated_execution=True, emba_sandbox_image="")
            self.assertIsNone(FT._run_emba(allowed, base / "allowed-evidence"))
            self.assertEqual(allowed_runner.calls, [])

    def test_routersploit_catalog_is_static_only(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            module = base / "routersploit/modules/exploits/routers/test.py"
            module.parent.mkdir(parents=True)
            module.write_text(
                "__info__ = {'name': 'Test', 'description': 'CVE-2024-12345 check'}\n"
                "raise RuntimeError('must never import or execute')\n",
                encoding="utf-8",
            )
            out = base / "out"; out.mkdir()
            result = FT._catalog_routersploit(base, out)
            self.assertEqual(len(result["modules"]), 1)
            self.assertEqual(result["modules"][0]["cves"], ["CVE-2024-12345"])
            self.assertFalse(result["modules"][0]["active_execution_allowed"])

    def test_local_firmware_inputs_need_no_fake_target(self):
        base = dict(phases="", silent=True)
        args = SimpleNamespace(**base, firmware="/tmp/fw.bin")
        self.assertEqual(tbhm._local_only_target(args), "local-analysis.invalid")
        self.assertIn("firmware_reverse_safe", args.phases)
        args = SimpleNamespace(**base, firmware="/tmp/fw.bin", emba=True)
        self.assertEqual(tbhm._local_only_target(args), "local-analysis.invalid")
        self.assertIn("firmware_reverse_safe", args.phases)
        self.assertIn("firmware_tooling_extended", args.phases)
        args = SimpleNamespace(**base, firmware_rootfs="/tmp/rootfs")
        self.assertEqual(tbhm._local_only_target(args), "local-analysis.invalid")
        self.assertIn("firmware_reverse_safe", args.phases)
        args = SimpleNamespace(**base, routersploit_root="/opt/routersploit")
        self.assertEqual(tbhm._local_only_target(args), "local-analysis.invalid")
        self.assertIn("firmware_tooling_extended", args.phases)


if __name__ == "__main__":
    unittest.main(verbosity=2)
