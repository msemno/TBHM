#!/usr/bin/env python3
"""Offline regression tests for v3.9.7.4 installer stability fixes."""
from __future__ import annotations

import json
import io
import os
import subprocess
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent


def cp(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class InstallerRecipeTests(unittest.TestCase):
    def setUp(self):
        from core.tool_catalog import load, by_id
        self.catalog = by_id(load())

    def test_apply_interruption_writes_partial_state_without_traceback(self):
        from scripts import install_extended_tools as inst
        first = self.catalog["paramspider"]
        second = dict(first, id="paramspider-second")
        completed = {
            "id": first["id"], "status": "already-installed", "eligible": True,
        }
        output, errors = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst, "load", return_value={"catalog_version": "test"}), \
             mock.patch.object(inst, "select", return_value=[first, second]), \
             mock.patch.object(inst, "install_item", side_effect=[completed, KeyboardInterrupt]), \
             redirect_stdout(output), redirect_stderr(errors):
            state = Path(td) / "partial.json"
            code = inst.main(["--apply", "--json", "--state-file", str(state)])
            checkpoint = json.loads(state.read_text())
        self.assertEqual(code, 130)
        self.assertEqual(checkpoint["selected_total"], 2)
        self.assertEqual(checkpoint["selected"], 1)
        self.assertFalse(checkpoint["complete"])
        self.assertEqual(checkpoint["interrupted_tool"], second["id"])
        self.assertEqual(checkpoint["rows"][0]["status"], "already-installed")
        self.assertEqual(json.loads(output.getvalue()), checkpoint)
        self.assertIn("installing paramspider-second", errors.getvalue())
        self.assertIn("Interrupted during paramspider-second", errors.getvalue())

    def test_apply_progress_goes_to_stderr_without_exposing_command_args(self):
        from scripts import install_extended_tools as inst
        errors = io.StringIO()
        with mock.patch.object(inst.subprocess, "run", return_value=cp(0)), \
             redirect_stderr(errors):
            result = inst._progress_run(["python", "-m", "pip", "install", "secret-spec"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("starting python -m pip", errors.getvalue())
        self.assertIn("exited 0", errors.getvalue())
        self.assertNotIn("secret-spec", errors.getvalue())

    def test_paramspider_uses_upstream_source_in_isolated_venv(self):
        from scripts import install_extended_tools as inst
        vcs_spec = "git+https://github.com/devanshbatham/ParamSpider.git"
        self.assertEqual(self.catalog["paramspider"]["install_hint"], f"pipx install {vcs_spec}")
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            if "-c" in argv:
                return cp(0, "3.12\n", "")
            if argv[1:3] == ["-m", "venv"]:
                venv = Path(argv[-1])
                script = venv / "bin/paramspider"
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_text("#!/bin/sh\n", encoding="utf-8")
                script.chmod(0o755)
            return cp()

        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst, "_already_installed", return_value=(False, "")):
            tool_home = Path(td) / "tools"
            bin_dir = Path(td) / "bin"
            planned = inst.install_item(self.catalog["paramspider"], apply=False,
                                        timeout=60, tool_home=tool_home, bin_dir=bin_dir,
                                        run=fake_run)
            self.assertEqual(planned["command"][-1], vcs_spec)
            installed = inst.install_item(self.catalog["paramspider"], apply=True,
                                          timeout=60, tool_home=tool_home, bin_dir=bin_dir,
                                          run=fake_run)
            self.assertEqual(installed["status"], "installed")
            self.assertEqual(installed["command"][-1], vcs_spec)
            self.assertTrue((bin_dir / "paramspider").is_symlink())
            marker = tool_home / "venvs/paramspider/.tbhm-install.json"
            self.assertEqual(json.loads(marker.read_text())["packages"], [vcs_spec])
        self.assertFalse(any(x == "paramspider" for argv in calls for x in argv))

    def test_npm_recipes_use_user_prefix(self):
        from scripts import install_extended_tools as inst
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}" if name == "npm" else None):
            row = inst.install_item(
                self.catalog["promptfoo"], apply=False, timeout=60,
                tool_home=Path(td) / "tools", bin_dir=Path(td) / "bin",
            )
        self.assertEqual(row["status"], "planned")
        self.assertEqual(row["command"][:5], ["npm", "install", "--global", "--prefix", str(Path.home() / ".local")])
        self.assertNotIn("/usr/local", " ".join(row["command"]))

    def test_cargo_audit_is_locked(self):
        from scripts import install_extended_tools as inst
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst.shutil, "which", side_effect=lambda name: "/usr/bin/cargo" if name == "cargo" else None):
            row = inst.install_item(
                self.catalog["cargo-audit"], apply=False, timeout=60,
                tool_home=Path(td) / "tools", bin_dir=Path(td) / "bin",
            )
        self.assertEqual(row["status"], "planned")
        self.assertIn("--locked", row["command"])

    def test_python_313_incompatible_tools_are_skipped_before_pip(self):
        from scripts import install_extended_tools as inst
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(args[0])
            return cp(0, "3.13\n", "")
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst.shutil, "which", return_value=None):
            for tool_id in ("giskard", "modelscan", "whylogs", "suzieq"):
                row = inst.install_item(
                    self.catalog[tool_id], apply=True, timeout=60,
                    tool_home=Path(td) / "tools", bin_dir=Path(td) / "bin", run=fake_run,
                )
                self.assertEqual(row["status"], "skipped-incompatible", tool_id)
        self.assertFalse(any("pip" in command for command in calls))

    def test_safe_cli_install_fails_when_upstream_executable_is_missing(self):
        from scripts import install_extended_tools as inst
        item = dict(self.catalog["modelscan"])
        item["id"] = "fixture-missing-cli"
        item["executable"] = "expected-cli"
        item.pop("executable_candidates", None)

        with tempfile.TemporaryDirectory() as td:
            tool_home = Path(td) / "tools"
            bin_dir = Path(td) / "bin"

            def fake_run(argv, **kwargs):
                if "-c" in argv:
                    return cp(0, "3.13\n", "")
                if argv[1:3] == ["-m", "venv"]:
                    venv = Path(argv[-1])
                    py = venv / "bin/python"
                    py.parent.mkdir(parents=True, exist_ok=True)
                    py.write_text("#!/bin/sh\n", encoding="utf-8")
                    py.chmod(0o755)
                return cp(0, "", "")

            row = inst.install_item(
                item, apply=True, timeout=60, tool_home=tool_home, bin_dir=bin_dir, run=fake_run
            )
        self.assertEqual(row["status"], "failed")
        self.assertIn("expected CLI executable", row["reason"])

    def test_library_install_does_not_require_a_cli_executable(self):
        from scripts import install_extended_tools as inst
        item = dict(self.catalog["whylogs"])
        item["id"] = "fixture-library"

        with tempfile.TemporaryDirectory() as td:
            tool_home = Path(td) / "tools"
            bin_dir = Path(td) / "bin"

            def fake_run(argv, **kwargs):
                if "-c" in argv:
                    return cp(0, "3.12\n", "")
                if argv[1:3] == ["-m", "venv"]:
                    venv = Path(argv[-1])
                    py = venv / "bin/python"
                    py.parent.mkdir(parents=True, exist_ok=True)
                    py.write_text("#!/bin/sh\n", encoding="utf-8")
                    py.chmod(0o755)
                return cp(0, "", "")

            with mock.patch.object(inst.shutil, "which", side_effect=lambda name: "/opt/python3.12" if name == "python3.12" else None):
                row = inst.install_item(
                    item, apply=True, timeout=60, tool_home=tool_home, bin_dir=bin_dir, run=fake_run
                )
        self.assertEqual(row["status"], "installed")
        self.assertEqual(row["executable_path"], "")

    def test_suzieq_catalog_uses_real_cli_name_and_aliases(self):
        item = self.catalog["suzieq"]
        self.assertEqual(item["executable"], "suzieq-cli")
        self.assertIn("sq-poller", item["executable_candidates"])

    def test_compatible_side_python_is_selected_for_isolated_plan(self):
        from scripts import install_extended_tools as inst
        def fake_which(name):
            return "/opt/python3.12" if name == "python3.12" else None
        def fake_run(argv, **kwargs):
            self.assertEqual(argv[0], "/opt/python3.12")
            return cp(0, "3.12\n", "")
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst.shutil, "which", side_effect=fake_which):
            row = inst.install_item(
                self.catalog["modelscan"], apply=False, timeout=60,
                tool_home=Path(td) / "tools", bin_dir=Path(td) / "bin", run=fake_run,
            )
        self.assertEqual(row["status"], "planned")
        self.assertIn("isolated environment", row["reason"])
        self.assertIn("modelscan", row["command"])



    def test_python3_catalog_placeholder_does_not_mean_library_is_installed(self):
        from core import tool_catalog
        item = self.catalog["giskard"]
        with tempfile.TemporaryDirectory() as td,              mock.patch.dict(os.environ, {"TBHM_TOOL_HOME": td}),              mock.patch.object(tool_catalog.importlib.util, "find_spec", return_value=None):
            row = tool_catalog.executable_status(item)
        self.assertFalse(row["installed"])
        self.assertEqual(row["environment"], "missing")

    def test_ruby_and_composer_user_binaries_are_normalized(self):
        from scripts import install_extended_tools as inst
        def fake_which(name):
            return f"/usr/bin/{name}" if name in {"gem", "ruby", "composer"} else None
        with tempfile.TemporaryDirectory() as td, mock.patch.object(inst.shutil, "which", side_effect=fake_which):
            ruby = inst.install_item(self.catalog["bundler-audit"], apply=False, timeout=60,
                                     tool_home=Path(td)/"tools", bin_dir=Path(td)/"bin")
            composer = inst.install_item(self.catalog["phpstan"], apply=False, timeout=60,
                                         tool_home=Path(td)/"tools", bin_dir=Path(td)/"bin")
        self.assertIn("--user-install", ruby["command"])
        self.assertEqual(self.catalog["bundler-audit"]["executable"], "bundle-audit")
        self.assertEqual(composer["command"][:3], ["composer", "global", "require"])

    def test_invalid_archived_kubeaudit_recipe_is_never_executed(self):
        from scripts import install_extended_tools as inst
        runner = mock.Mock(side_effect=AssertionError("must not run"))
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst.shutil, "which", side_effect=lambda name: "/usr/bin/go" if name == "go" else None):
            row = inst.install_item(
                self.catalog["kubeaudit"], apply=True, timeout=60,
                tool_home=Path(td) / "tools", bin_dir=Path(td) / "bin", run=runner,
            )
        self.assertEqual(row["status"], "skipped-deprecated")
        runner.assert_not_called()


class AptPreflightTests(unittest.TestCase):
    def setUp(self):
        from core.tool_catalog import load, by_id
        self.catalog = by_id(load())

    @staticmethod
    def _which(name):
        if name in {"apt-cache", "apt-get", "sudo"}:
            return f"/usr/bin/{name}"
        return None

    def test_missing_apt_package_is_unavailable_not_failed(self):
        from scripts import install_extended_tools as inst
        def fake_run(argv, **kwargs):
            self.assertEqual(argv[:2], ["apt-cache", "show"])
            return cp(100, "", "N: Unable to locate package")
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst.platform, "system", return_value="Linux"), \
             mock.patch.object(inst.shutil, "which", side_effect=self._which):
            row = inst.install_item(
                self.catalog["osquery"], apply=True, timeout=60,
                tool_home=Path(td) / "tools", bin_dir=Path(td) / "bin", run=fake_run,
            )
        self.assertEqual(row["status"], "skipped-unavailable")

    def test_dependency_conflict_is_incompatible_not_generic_failure(self):
        from scripts import install_extended_tools as inst
        calls = []
        def fake_run(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ["apt-cache", "show"]:
                return cp(0, "Package: zeek\n", "")
            return cp(100, "", "The following packages have unmet dependencies: zeek depends: libc6 (< 2.38)")
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst.platform, "system", return_value="Linux"), \
             mock.patch.object(inst.shutil, "which", side_effect=self._which), \
             mock.patch.object(inst.os, "geteuid", return_value=1000):
            row = inst.install_item(
                self.catalog["zeek"], apply=True, timeout=60,
                tool_home=Path(td) / "tools", bin_dir=Path(td) / "bin", run=fake_run,
            )
        self.assertEqual(row["status"], "skipped-incompatible")
        self.assertTrue(any("-s" in command for command in calls))

    def test_transient_apt_failure_retries_with_ipv4_and_fix_missing(self):
        from scripts import install_extended_tools as inst
        calls = []
        def fake_run(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ["apt-cache", "show"]:
                return cp(0, "Package: rtl-433\n", "")
            if "-s" in argv:
                return cp(0, "Inst rtl-433", "")
            install_count = sum("Acquire::ForceIPv4=true" in x for x in calls)
            if install_count == 1:
                return cp(100, "", "Could not connect to mirror; Failed to fetch")
            return cp(0, "installed", "")
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(inst.platform, "system", return_value="Linux"), \
             mock.patch.object(inst.shutil, "which", side_effect=self._which), \
             mock.patch.object(inst.os, "geteuid", return_value=1000):
            row = inst.install_item(
                self.catalog["rtl-433"], apply=True, timeout=60,
                tool_home=Path(td) / "tools", bin_dir=Path(td) / "bin", run=fake_run,
            )
        self.assertEqual(row["status"], "installed")
        installs = [x for x in calls if "Acquire::ForceIPv4=true" in x]
        self.assertEqual(len(installs), 2)
        self.assertIn("--fix-missing", installs[0])


class SourceAndRuntimeTests(unittest.TestCase):
    def test_install_script_has_isolation_and_exact_dpkg_check(self):
        text = (ROOT / "docs" / "history" / "install-v4.0.0.sh").read_text(encoding="utf-8")
        self.assertIn("TBHM v4.0.0-unified-safe installer starting", text)
        self.assertIn("$TOOL_HOME/venvs/$tool_id", text)
        self.assertIn("dpkg-query -W -f='${Status}'", text)
        self.assertIn("npm install --global --prefix", text)
        self.assertNotRegex(text, r"pip install --user[^\n]*(semgrep|checkov|angr|flare-capa|frida-tools)")
        self.assertNotIn("npm install -g", text)

    def test_optional_absence_is_not_rendered_as_failure(self):
        text = (ROOT / "docs" / "history" / "install-v4.0.0.sh").read_text(encoding="utf-8")
        self.assertIn('[–] $name (optional/unavailable)', text)
        self.assertIn('not set (optional coverage reduction)', text)


    def test_duckdb_isolated_subprocess_contract(self):
        from phases import data_analysis_intelligence as phase
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            tool_home = base / "tools"
            vpy = tool_home / "venvs/duckdb/bin/python"
            vpy.parent.mkdir(parents=True)
            vpy.write_text("fixture", encoding="utf-8")
            out = base / "out"; out.mkdir()
            def fake_run(argv, **kwargs):
                result_path = Path(argv[argv.index("--result") + 1])
                result_path.write_text(json.dumps({"available": True, "execution_environment": "isolated"}), encoding="utf-8")
                return cp(0, "", "")
            with mock.patch.dict(os.environ, {"TBHM_TOOL_HOME": str(tool_home)}),                  mock.patch.dict(__import__("sys").modules, {"duckdb": None}),                  mock.patch.object(phase.subprocess, "run", side_effect=fake_run):
                result = phase._duckdb_export(out, [], [])
        self.assertTrue(result["available"])
        self.assertEqual(result["execution_environment"], "isolated")

    def test_playwright_system_chromium_fallback(self):
        from phases import smart_crawl
        browser = object()
        chromium = mock.Mock()
        chromium.launch.side_effect = [RuntimeError("managed browser absent"), browser]
        fake = types.SimpleNamespace(chromium=chromium)
        with mock.patch.object(smart_crawl.shutil if hasattr(smart_crawl, "shutil") else __import__("shutil"), "which", return_value="/usr/bin/chromium"):
            result, source = smart_crawl._launch_chromium(fake)
        self.assertIs(result, browser)
        self.assertEqual(source, "system:/usr/bin/chromium")
        self.assertEqual(chromium.launch.call_args_list[1].kwargs["executable_path"], "/usr/bin/chromium")

    def test_release_version_and_installer_doctor(self):
        import tbhm
        from scripts import installer_doctor
        self.assertEqual(tbhm.VERSION, "4.2.7")
        with tempfile.TemporaryDirectory() as td:
            payload = installer_doctor.collect(Path(td))
        self.assertEqual(payload["release"], "4.2.7")
        self.assertIn("pip_check", payload)


    def test_legacy_cleanup_is_plan_only_by_default(self):
        from scripts import repair_legacy_python_environment as repair
        with tempfile.TemporaryDirectory() as td:
            rows = repair.plan(Path(td))
        self.assertEqual({row["tool_id"] for row in rows}, set(repair.DISTRIBUTIONS))
        self.assertFalse(any(row["eligible_for_cleanup"] for row in rows))

    def test_no_unrestricted_shell_execution_in_install_helpers(self):
        for rel in ("scripts/install_extended_tools.py", "scripts/installer_doctor.py", "scripts/repair_legacy_python_environment.py"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
