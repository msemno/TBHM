"""Owned local regression fixtures for the independent review collector."""
import argparse
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote, quote_plus

SCRIPT = Path(__file__).resolve().parents[1]/"scripts/tbhm_collect_review_bundle.py"
spec = importlib.util.spec_from_file_location("tbhm_review_collector", SCRIPT)
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.run = self.base / "run"
        self.run.mkdir()
        self.write("execution_ledger.json", {"schema": "tbhm.execution/1", "events": [{"phase": "recon", "status": "tool-error", "returncode": 2}]})
        self.write("report.json", {"findings": [{"id": 1, "cwe": "CWE-78", "severity": "LOW", "evidence_class": "supported", "confirmation": "UNCONFIRMED"}]})
        self.write("run.log", "Synthetic fixture log\n")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, content):
        path = self.run / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content) if isinstance(content, (dict, list)) else content)
        return path

    def args(self, **changes):
        result = dict(run=str(self.run), output_home=str(self.base / "reviews"), run_alias="lab-01", tool_home=None,
                      extra=[], redact_file=None, alias_map=None, include_evidence=False, include_tool_logs=False,
                      max_file_mb=10, max_total_mb=100, max_files=256, archive=False)
        result.update(changes)
        return argparse.Namespace(**result)

    def collect(self, **changes):
        result = C.collect(self.args(**changes))
        bundle = Path(result["bundle"])
        return result, bundle, json.loads((bundle / "manifest.json").read_text())

    def artifact(self, bundle, manifest, rel):
        item = next(x for x in manifest["files"] if x["source_relative"] == rel)
        return bundle / item["destination"]

    def test_read_only_source_and_preserved_outcome(self):
        before = {p.relative_to(self.run): p.read_bytes() for p in self.run.rglob("*") if p.is_file()}
        result, bundle, manifest = self.collect()
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(before, {p.relative_to(self.run): p.read_bytes() for p in self.run.rglob("*") if p.is_file()})
        value = json.loads(self.artifact(bundle, manifest, "report.json").read_text())["findings"][0]
        self.assertEqual(value["cwe"], "CWE-78")
        self.assertEqual(value["confirmation"], "UNCONFIRMED")
        self.assertFalse(manifest["privacy_certified"])
        self.assertFalse(manifest["original_evidence_authority"])

    def test_minimal_omits_json_evidence_but_not_verdict(self):
        self.write("report.json", {"evidence": "private source", "verdict": "needs_validation", "password": "CANARY_PASS_123"})
        _, b, m = self.collect()
        value = json.loads(self.artifact(b, m, "report.json").read_text())
        self.assertIn("OMITTED", value["evidence"])
        self.assertEqual(value["verdict"], "needs_validation")
        self.assertNotIn("CANARY_PASS_123", json.dumps(value))

    def test_include_evidence_retains_benign_context_and_removes_secret(self):
        self.write("report.json", {"evidence": {"source_excerpt": "os.system(value)", "api_key": "CANARY_KEY_123"}})
        _, b, m = self.collect(include_evidence=True)
        text = self.artifact(b, m, "report.json").read_text()
        self.assertIn("os.system(value)", text)
        self.assertNotIn("CANARY_KEY_123", text)

    def test_header_pairs(self):
        r = C.Redactor()
        value = r.value({"headers": [{"name": "Authorization", "value": "CANARY_HDR_123"}, {"name": "Cookie", "value": "sid=CANARY_COOKIE_123"}]})
        self.assertNotIn("CANARY_", json.dumps(value))

    def test_cli_argv_keeps_tbhm_target_and_removes_curl_login(self):
        r = C.Redactor()
        target = r.value({"argv": ["tbhm.py", "-u", "https://app.example.test/", "--password", "CANARY_PASS_123"]})
        curl = r.value({"argv": ["curl", "-u", "name:CANARY_PASS_456", "-b", "sid=CANARY_COOKIE_456"]})
        self.assertIn("https://app.example.test/", target["argv"])
        self.assertNotIn("CANARY_", json.dumps(target) + json.dumps(curl))

    def test_private_key_complete_and_incomplete(self):
        for text in ("-----BEGIN PRIVATE KEY-----\nCANARY_KEY_DATA\n-----END PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\nCANARY_KEY_DATA"):
            self.assertNotIn("CANARY_KEY_DATA", C.Redactor().text(text))

    def test_known_value_encoded_forms(self):
        secret = 'CANARY A/+?Z'
        values = [secret, quote(secret, safe=""), quote_plus(secret), json.dumps(secret)[1:-1]]
        clean = C.Redactor([secret]).text(" ".join(values))
        self.assertTrue(all(x not in clean for x in values))

    def test_embedded_json_quoted_assignment(self):
        clean = C.Redactor(include_evidence=True).text('{"password":"CANARY_PASSWORD", "token": "CANARY_TOKEN"}')
        self.assertNotIn("CANARY_", clean)

    def test_jsonl_remains_parseable(self):
        self.write("evidence/events.jsonl", '{"id":1,"token":"CANARY_TOKEN_123"}\n{"id":2,"status":"inconclusive"}\n')
        _, b, m = self.collect()
        text = self.artifact(b, m, "evidence/events.jsonl").read_text()
        self.assertEqual([json.loads(x)["id"] for x in text.splitlines()], [1, 2])
        self.assertNotIn("CANARY_TOKEN_123", text)

    def test_invalid_json_is_not_silently_copied(self):
        self.write("evidence/broken.json", "{invalid")
        r, _, m = self.collect()
        self.assertEqual(r["exit_code"], 3)
        self.assertTrue(any(x["source_relative"] == "evidence/broken.json" for x in m["skipped"]))

    def test_invalid_utf8_is_held_back(self):
        self.write("evidence/bad.txt", "").write_bytes(b'\xff\x00')
        r, _, m = self.collect()
        self.assertEqual(r["exit_code"], 3)
        self.assertTrue(m["skipped"])

    def test_symbolic_link_file_is_rejected(self):
        target = self.base / "outside.json"
        target.write_text('{"value":"CANARY_OUTSIDE"}')
        (self.run / "report.json").unlink()
        (self.run / "report.json").symlink_to(target)
        r, b, m = self.collect()
        self.assertEqual(r["exit_code"], 3)
        self.assertTrue(any("symlink" in x["reason"] for x in m["skipped"]))
        self.assertNotIn("CANARY_OUTSIDE", "".join(p.read_text() for p in b.rglob("*") if p.is_file()))

    def test_hard_link_file_is_rejected(self):
        os.link(self.run / "report.json", self.base / "hardlink.json")
        r, _, m = self.collect()
        self.assertEqual(r["exit_code"], 3)
        self.assertTrue(any("Single-link" in x["reason"] for x in m["skipped"]))

    def test_fifo_is_not_opened(self):
        (self.run / "run.log").unlink()
        os.mkfifo(self.run / "run.log")
        r, _, m = self.collect()
        self.assertEqual(r["exit_code"], 3)
        self.assertTrue(any(x["source_relative"] == "run.log" for x in m["skipped"]))

    def test_symlink_directory_is_rejected(self):
        external = self.base / "outside"
        external.mkdir()
        (external / "item.json").write_text('{}')
        (self.run / "evidence").symlink_to(external, target_is_directory=True)
        r, _, m = self.collect()
        self.assertEqual(r["exit_code"], 3)
        self.assertTrue(any(x["source_relative"] == "evidence" for x in m["skipped"]))

    def test_output_inside_source_is_rejected(self):
        with self.assertRaises(C.CollectionError):
            self.collect(output_home=str(self.run / "bad-output"))
        self.assertFalse((self.run / "bad-output").exists())

    def test_symlink_output_parent_does_not_write_through(self):
        alias = self.base / "alias"
        alias.symlink_to(self.run, target_is_directory=True)
        with self.assertRaises(OSError):
            self.collect(output_home=str(alias / "new-output"))
        self.assertFalse((self.run / "new-output").exists())

    def test_symlink_input_parent_is_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.run, target_is_directory=True)
        with self.assertRaises(OSError):
            C.read_regular(alias, "report.json", 100000)

    def test_oversize_file_is_not_truncated_to_success(self):
        self.write("evidence/large.txt", "x" * (1024 * 1024 + 1))
        r, _, m = self.collect(max_file_mb=1)
        self.assertEqual(r["exit_code"], 3)
        self.assertTrue(any("file byte limit" in x["reason"] for x in m["skipped"]))

    def test_total_budget_is_enforced(self):
        self.write("evidence/a.txt", "a" * 700000)
        self.write("evidence/b.txt", "b" * 700000)
        r, _, m = self.collect(max_file_mb=1, max_total_mb=1)
        self.assertEqual(r["exit_code"], 3)
        self.assertLessEqual(m["review_bytes"], 1024 * 1024)

    def test_file_count_limit_and_priority(self):
        r, _, m = self.collect(max_files=1)
        self.assertEqual(r["exit_code"], 3)
        self.assertEqual(m["files"][0]["source_relative"], "execution_ledger.json")

    def test_tamper_is_detected(self):
        _, b, m = self.collect()
        self.artifact(b, m, "report.json").write_text('{}')
        self.assertFalse(C.verify_directory(b)["integrity_matches"])

    def test_extra_unrecorded_file_is_detected(self):
        _, b, _ = self.collect()
        (b / "extra.txt").write_text("unrecorded")
        self.assertEqual(C.verify_directory(b)["unexpected_files"], ["extra.txt"])

    def test_alias_map_is_not_copied(self):
        mapping = self.base / "aliases.json"
        mapping.write_text(json.dumps({"customer.example.test": "asset-01.invalid"}))
        self.write("report.json", {"url": "https://customer.example.test/item"})
        _, b, m = self.collect(alias_map=str(mapping))
        text = self.artifact(b, m, "report.json").read_text()
        self.assertIn("asset-01.invalid", text)
        self.assertNotIn("customer.example.test", text)
        self.assertFalse((b / "aliases.json").exists())

    def test_bad_alias_map_is_rejected(self):
        mapping = self.base / "aliases.json"
        mapping.write_text('[]')
        with self.assertRaises(C.CollectionError):
            self.collect(alias_map=str(mapping))

    def test_source_identity_is_read_without_execution(self):
        tool = self.base / "tool"
        (tool / "core").mkdir(parents=True)
        (tool / "core/version.py").write_text('VERSION="4.2.5"\nraise RuntimeError("must not execute")\n')
        self.assertEqual(C.build_snapshot(tool)["declared_version"]["VERSION"], "4.2.5")

    def test_private_permissions_and_archive_members(self):
        r, b, _ = self.collect(run_alias="lab.01", archive=True)
        archive = Path(r["archive"])
        self.assertEqual(archive.name, b.name + ".tar.gz")
        self.assertEqual(stat.S_IMODE(b.stat().st_mode), 0o700)
        for p in b.rglob("*"):
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700 if p.is_dir() else 0o600)
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        with tarfile.open(archive) as tf:
            for item in tf.getmembers():
                self.assertTrue(item.isfile())
                self.assertFalse(item.name.startswith("/"))
                self.assertNotIn("..", Path(item.name).parts)
                self.assertEqual(item.mode, 0o600)

    def test_no_network_or_subprocess_is_used(self):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network")), patch.object(subprocess, "run", side_effect=AssertionError("subprocess")), patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")):
            self.collect(archive=True)

    def test_manifest_path_traversal_is_rejected(self):
        _, b, _ = self.collect()
        m = json.loads((b / "manifest.json").read_text())
        m["files"][0]["destination"] = "../outside.json"
        (b / "manifest.json").write_text(json.dumps(m))
        with self.assertRaises(C.CollectionError):
            C.verify_directory(b)

    def test_file_replacement_or_mutation_is_detected(self):
        source = self.run / "run.log"
        original_read = os.read
        changed = False
        def mutate(fd, amount):
            nonlocal changed
            value = original_read(fd, amount)
            if not changed and value:
                source.write_text("changed fixture input")
                changed = True
            return value
        with patch.object(os, "read", side_effect=mutate):
            with self.assertRaises(C.CollectionError):
                C.read_regular(self.run, "run.log", 10000)

    def test_inventory_budget_is_enforced_before_unbounded_listing(self):
        for i in range(10):
            self.write(f"evidence/entry-{i}.json", {})
        with patch.object(C, "MAX_VISITED", 5):
            with self.assertRaises(C.CollectionError):
                self.collect()

    def test_database_html_and_raw_secret_reports_are_excluded(self):
        for rel in ("state.sqlite3", "OPERATOR.html", "code/gitleaks_raw.json", "models/weights.txt"):
            self.write(rel, "CANARY_EXCLUDED_DATA")
        _, b, m = self.collect(include_tool_logs=True, include_evidence=True)
        self.assertFalse(any("gitleaks" in x["source_relative"] for x in m["files"]))
        self.assertNotIn("CANARY_EXCLUDED_DATA", "".join(p.read_text() for p in b.rglob("*") if p.is_file()))

    def test_cli_empty_path_returns_error_not_current_directory(self):
        with redirect_stdout(io.StringIO()) as output:
            rc = C.main(["collect", "--run", "", "--output-home", str(self.base / "out")])
        self.assertEqual(rc, 2)
        self.assertIn("nonempty", output.getvalue())

    def test_missing_primary_is_disclosed_as_partial(self):
        (self.run / "report.json").unlink()
        r, _, m = self.collect()
        self.assertEqual(r["exit_code"], 3)
        self.assertEqual(m["missing_primary"], ["report.json"])
        self.assertFalse(m["collection_complete"])

    def test_recon_and_ai_artifacts_are_collected(self):
        self.write("recon/alive.txt", "https://app.example.test/\n")
        self.write("llm_analysis/ai_plane_next_steps.json", {"phases": [], "status": "pending"})
        _, _, m = self.collect()
        names = {x["source_relative"] for x in m["files"]}
        self.assertIn("recon/alive.txt", names)
        self.assertIn("llm_analysis/ai_plane_next_steps.json", names)

    def test_ordinary_tool_logs_need_explicit_option(self):
        self.write("logs/httpx_json.log", "flag provided but not defined: -jsonl\n")
        _, _, a = self.collect()
        _, _, b = self.collect(include_tool_logs=True)
        self.assertNotIn("logs/httpx_json.log", {x["source_relative"] for x in a["files"]})
        self.assertIn("logs/httpx_json.log", {x["source_relative"] for x in b["files"]})

    def test_short_or_whitespace_only_known_values_are_rejected(self):
        for value in ("abc", "    ", "hello\nworld"):
            with self.assertRaises(C.CollectionError):
                C.Redactor([value])


if __name__ == "__main__":
    unittest.main(verbosity=2)
