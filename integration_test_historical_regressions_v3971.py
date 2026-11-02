#!/usr/bin/env python3
"""Offline historical-behavior regression suite for TBHM v3.9.7.2.

No network request or target binary execution is performed. The fixtures prove
selected v2.16-v3.8 contracts that were historically vulnerable to regression.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent


def response(status: int, body: str, content_type: str = "text/html", **headers) -> str:
    reason = {200: "OK", 206: "Partial Content", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests"}.get(status, "Result")
    lines = [f"HTTP/1.1 {status} {reason}", f"Content-Type: {content_type}"]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    return "\r\n".join(lines) + "\r\n\r\n" + body


class CurlProbeHistoricalTests(unittest.TestCase):
    def test_plain_405_is_not_method_override(self):
        from core import curl_probes
        ordinary = response(405, "Method Not Allowed")
        injected = response(405, "Method Not Allowed")
        with mock.patch.object(curl_probes, "_run_curl", side_effect=[(0, ordinary, ""), (0, injected, "")]):
            vulnerable, *_ = curl_probes.probe_method_override("https://example.test/")
        self.assertFalse(vulnerable)

    def test_injected_method_reference_is_method_override_signal(self):
        from core import curl_probes
        ordinary = response(200, "normal page")
        injected = response(405, "Unsupported request method DEBUG")
        with mock.patch.object(curl_probes, "_run_curl", side_effect=[(0, ordinary, ""), (0, injected, "")]):
            vulnerable, severity, evidence, command = curl_probes.probe_method_override("https://example.test/")
        self.assertTrue(vulnerable)
        self.assertEqual(severity, "MEDIUM")
        self.assertIn("DEBUG", evidence)
        self.assertIn("X-HTTP-Method-Override", command)

    def test_sensitive_file_rejects_generic_soft_404_html(self):
        from core import curl_probes
        generic = response(200, "<html>Documentation example: APP_KEY=example_value</html>", "text/html")
        with mock.patch.object(curl_probes, "_run_curl", return_value=(0, generic, "")):
            vulnerable, *_ = curl_probes.probe_sensitive_files("https://example.test/")
        self.assertFalse(vulnerable)

    def test_sensitive_file_requires_distinctive_non_html_body(self):
        from core import curl_probes
        def fake(args, timeout=18):
            url = args[-1]
            if "__tbhm_missing_" in url:
                return 0, response(200, "application shell", "text/html"), ""
            if url.endswith("/.env"):
                return 0, response(200, "APP_ENV=production\nAPP_KEY=base64:realistic_fixture\nDB_PASSWORD=fixture_password", "text/plain"), ""
            return 0, response(404, "not found", "text/plain"), ""
        with mock.patch.object(curl_probes, "_run_curl", side_effect=fake):
            vulnerable, severity, evidence, _ = curl_probes.probe_sensitive_files("https://example.test/")
        self.assertTrue(vulnerable)
        self.assertEqual(severity, "CRITICAL")
        self.assertIn("/.env", evidence)

    def test_admin_bypass_requires_direct_control_differential(self):
        from core import curl_probes
        direct = response(403, "Access denied")
        bypass = response(200, "<h1>Admin Panel</h1><div>users list</div>")
        with mock.patch.object(curl_probes, "_run_curl", side_effect=[(0, direct, ""), (0, bypass, "")]):
            vulnerable, severity, *_ = curl_probes.probe_admin_bypass("https://example.test/")
        self.assertTrue(vulnerable)
        self.assertEqual(severity, "HIGH")
        # Same content for both requests is not a bypass.
        with mock.patch.object(curl_probes, "_run_curl", side_effect=[(0, bypass, ""), (0, bypass, "")]):
            self.assertFalse(curl_probes.probe_admin_bypass("https://example.test/")[0])

    def test_server_status_requires_recognizable_distinct_content(self):
        from core import curl_probes
        def fake(args, timeout=18):
            url = args[-1]
            if "__tbhm_missing_" in url:
                return 0, response(200, "generic shell"), ""
            if url.endswith("/server-status"):
                return 0, response(200, "Apache Server Status for localhost"), ""
            return 0, response(404, "not found"), ""
        with mock.patch.object(curl_probes, "_run_curl", side_effect=fake):
            self.assertTrue(curl_probes.probe_server_status("https://example.test/")[0])

    def test_range_probe_is_bounded_non_destructive_indicator(self):
        from core import curl_probes
        captured = {}
        def fake(args, timeout=18):
            captured["args"] = args; captured["timeout"] = timeout
            return 0, response(206, "partial", "application/octet-stream"), ""
        with mock.patch.object(curl_probes, "_run_curl", side_effect=fake):
            vulnerable, severity, _, command = curl_probes.probe_range_overflow("https://example.test/file")
        self.assertTrue(vulnerable)
        self.assertEqual(severity, "MEDIUM")
        header = captured["args"][captured["args"].index("-H") + 1]
        self.assertEqual(header.count(","), 19)
        self.assertEqual(captured["timeout"], 20)
        self.assertNotIn("--data", command)

    def test_curl_runner_throttles_times_out_and_quotes(self):
        from core import curl_probes
        curl_probes.set_rate(2.0)
        curl_probes._LAST_CALL[0] = 100.0
        completed = types.SimpleNamespace(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(curl_probes._time, "monotonic", side_effect=[100.1, 100.6]), \
             mock.patch.object(curl_probes._time, "sleep") as sleeper, \
             mock.patch.object(curl_probes.subprocess, "run", return_value=completed) as runner:
            curl_probes._run_curl(["curl", "https://example.test/a b"], timeout=7)
        sleeper.assert_called_once()
        self.assertEqual(runner.call_args.kwargs["timeout"], 7)
        self.assertFalse(runner.call_args.kwargs.get("shell", False))
        self.assertIn("'https://example.test/a b'", curl_probes._curl_str(["curl", "https://example.test/a b"]))
        curl_probes.set_rate(0)


class NucleiAndInstallerHistoricalTests(unittest.TestCase):
    def test_missing_nuclei_is_explicit(self):
        from core import bootstrap
        with mock.patch.object(bootstrap, "_have", return_value=False):
            result = bootstrap.ensure_nuclei_templates()
        self.assertEqual(result, {"installed": False, "count": -1, "action": "skip-no-nuclei"})

    def test_valid_empty_and_malformed_template_stores(self):
        from core import bootstrap
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            good = root / "good.yaml"
            bad = root / "bad.yaml"
            good.write_text("id: fixture-template\ninfo:\n  name: Fixture\n  severity: info\nhttp:\n  - method: GET\n", encoding="utf-8")
            bad.write_text("id: [unterminated\ninfo: nope", encoding="utf-8")
            with mock.patch.object(bootstrap, "DEFAULT_NUCLEI_TEMPLATE_DIRS", [root]), \
                 mock.patch.object(bootstrap, "_have", return_value=True), \
                 mock.patch.object(bootstrap.subprocess, "run", return_value=
                     subprocess.CompletedProcess([], 0, "", "")) as fallback:
                self.assertEqual(bootstrap.nuclei_template_count(), 1)
                self.assertEqual(bootstrap.nuclei_templates_root(), root)
                good.unlink()
                self.assertEqual(bootstrap.nuclei_template_count(), 0)
                self.assertIsNone(bootstrap.nuclei_templates_root())
                fallback.assert_called_once()

    def test_template_listing_fallback_is_counted_only_on_success(self):
        from core import bootstrap
        for code, expected in ((0, 2), (2, 0)):
            with self.subTest(code=code), \
                 mock.patch.object(bootstrap, "DEFAULT_NUCLEI_TEMPLATE_DIRS", []), \
                 mock.patch.object(bootstrap, "_have", return_value=True), \
                 mock.patch.object(bootstrap.subprocess, "run", return_value=
                     subprocess.CompletedProcess([], code, "one.yaml\ntwo.yaml\n", "")):
                self.assertEqual(bootstrap.nuclei_template_count(), expected)

    def test_failed_update_is_not_silent_success(self):
        from core import bootstrap
        result = types.SimpleNamespace(returncode=2, stdout="", stderr="update denied")
        logs = []
        with mock.patch.object(bootstrap, "_have", return_value=True), \
             mock.patch.object(bootstrap, "nuclei_template_count", side_effect=[0, 0]), \
             mock.patch.object(bootstrap.subprocess, "run", return_value=result):
            value = bootstrap.ensure_nuclei_templates(log=lambda level, phase, msg: logs.append((level, msg)))
        self.assertEqual(value["action"], "update-failed")
        self.assertIn("update denied", value["error"])
        self.assertTrue(any("exited 2" in message for _, message in logs))

    def test_workflow_paths_are_absolute_and_fallback_to_tags(self):
        from phases.nuclei_extended import _resolve_sweep_args
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); workflows = root / "workflows"; workflows.mkdir()
            (workflows / "fixture.yaml").write_text("id: workflow-fixture", encoding="utf-8")
            resolved = _resolve_sweep_args(["__TECH_STACK_WORKFLOWS__"], root)
            self.assertEqual(resolved[:2], ["-w", str(workflows)])
            (workflows / "fixture.yaml").unlink()
            fallback = _resolve_sweep_args(["__TECH_STACK_WORKFLOWS__"], root)
            self.assertNotIn("-w", fallback)
            self.assertIn("-tags", fallback)

    def test_installer_preserves_go_v2_names_and_rejects_wrong_httpx(self):
        text = (ROOT / "docs" / "history" / "install-v4.0.0.sh").read_text(encoding="utf-8")
        self.assertIn('if [[ "$base" =~ ^v[0-9]+$ ]]', text)
        self.assertIn('base="$(basename "$(dirname "$mod")")"', text)
        self.assertIn('if [ "$name" = "httpx" ]', text)
        self.assertRegex(text, r"httpx -version.*projectdiscovery")
        self.assertNotIn("sudo pip install", text)


class FalsePositiveHistoricalTests(unittest.TestCase):
    def test_endpoint_vs_wildcard_and_custom_404(self):
        from core.api_baseline import classify, make_signature
        wildcard = make_signature(200, "<html>same application shell</html>", {"Content-Type": "text/html"})
        identical = make_signature(200, "<html>same application shell</html>", {"Content-Type": "text/html"})
        self.assertFalse(classify(identical, wildcard)[0])
        true_endpoint = make_signature(200, '{"user":{"id":1}}', {"Content-Type": "application/json"})
        self.assertTrue(classify(true_endpoint, wildcard)[0])
        custom_404 = make_signature(404, "custom missing page")
        self.assertFalse(classify(custom_404, wildcard)[0])

    def test_redirect_json_and_status_body_controls(self):
        from core.api_baseline import classify, make_signature
        redirect_base = make_signature(302, "", {"Location": "/login"})
        redirect_same = make_signature(302, "", {"Location": "/login"})
        self.assertFalse(classify(redirect_same, redirect_base)[0])
        json_base = make_signature(200, '{"code":"invalid_endpoint","message":"unknown"}')
        json_same = make_signature(200, '{"code":"invalid_endpoint","message":"unknown"}')
        self.assertFalse(classify(json_same, json_base)[0])
        same_body_other_status = make_signature(202, '{"code":"invalid_endpoint","message":"unknown"}')
        self.assertFalse(classify(same_body_other_status, json_base)[0])
        auth = make_signature(401, '{"code":"unauthorized"}')
        deviates, label, severity = classify(auth, json_base)
        self.assertTrue(deviates); self.assertIn("unverified", label); self.assertEqual(severity, "INFO")
        rate_limited = make_signature(429, '{"code":"rate_limited"}')
        self.assertTrue(classify(rate_limited, json_base)[0])

    def test_soft404_body_and_length_similarity(self):
        from core.fp_engine import Baseline, is_soft_404_match
        import hashlib
        body = b"<html>application shell</html>"
        baseline = Baseline(200, len(body), "text/html", hashlib.sha256(body).hexdigest(), body[:500], {})
        self.assertTrue(is_soft_404_match(200, body, "text/html", baseline))
        self.assertTrue(is_soft_404_match(200, body + b" ", "text/html", baseline))
        self.assertFalse(is_soft_404_match(200, b'{"real":true}', "application/json", baseline))


class ScannerNormalizerHistoricalTests(unittest.TestCase):
    def test_json_jsonl_sarif_nested_cwe_and_dedup(self):
        from core import scanner_normalizer as sn
        nested = {"results": [{"rule_id": "R1", "severity": "high", "path": "app.py", "line": 7, "message": "CWE-79 reflected value", "cwe": "CWE-79"}]}
        items = sn.parse_json_value(nested, "fixture")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["severity"], "HIGH")
        self.assertEqual(items[0]["target"], "app.py")
        self.assertEqual(items[0]["cwe"], "CWE-79")
        self.assertEqual(items[0]["source"], "fixture")
        sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "S1", "properties": {"tags": ["security", "CWE-22"]}}]}}, "results": [{"ruleId": "S1", "level": "error", "message": {"text": "Traversal"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": 4}}}]}]}]}
        sarif_items = sn.parse_json_value(sarif, "sarif")
        self.assertEqual(len(sarif_items), 1)
        self.assertEqual(sarif_items[0]["cwe"], "CWE-22")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.jsonl"
            line = json.dumps(nested)
            p.write_text(line + "\nnot-json\n" + line + "\n", encoding="utf-8")
            self.assertEqual(len(sn.parse_file(p)), 1)

    def test_bounded_recursion_malformed_input_and_max_items(self):
        from core import scanner_normalizer as sn
        deep = current = {}
        for index in range(200):
            current["child"] = {}; current = current["child"]
        current.update({"rule_id": "TOO-DEEP", "severity": "high"})
        self.assertEqual(sn.parse_json_value(deep, "deep"), [])
        records = [{"rule_id": f"R{i}", "severity": "low"} for i in range(20)]
        self.assertEqual(len(sn.parse_json_value(records, "bounded", max_items=5)), 5)
        with tempfile.TemporaryDirectory() as td:
            malformed = Path(td) / "broken.json"
            malformed.write_text("{not json", encoding="utf-8")
            self.assertEqual(sn.parse_file(malformed), [])


class ReverseFallbackHistoricalTests(unittest.TestCase):
    def test_hashes_magic_entropy_strings_short_imports_and_redaction(self):
        from core import reverse_utils as ru
        fixture = b"MZ" + b"\x00" * 8 + b"gets\x00system\x00https://example.test/path\x00192.0.2.8\x00999.999.999.999\x00API_KEY=fixture_secret_value\x00"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.bin"; path.write_bytes(fixture)
            hashes = ru.hashes(path)
            self.assertEqual(len(hashes["sha256"]), 64)
            self.assertEqual(len(hashes["md5"]), 32)
            self.assertEqual(ru.artifact_id(path), "sha256:" + hashes["sha256"])
            self.assertEqual(ru.magic_type(path), "PE")
            self.assertGreaterEqual(ru.sample_entropy(path), 0.0)
            strings = ru.extract_strings(path, minimum=8)
            found = ru.indicators(strings)
            short = ru.raw_short_imports(path)
            self.assertIn("https://example.test/path", found["urls"])
            self.assertIn("192.0.2.8", found["ips"])
            self.assertNotIn("999.999.999.999", found["ips"])
            self.assertTrue(any(item["name"] == "gets" for item in short))
            candidates = ru.secret_candidates(strings)
            self.assertTrue(candidates)
            self.assertEqual(candidates[0]["value"], "fixture_secret_value")
            self.assertNotIn("fixture_secret_value", candidates[0]["redacted"])

    def test_file_and_string_limits_are_bounded(self):
        from core import reverse_utils as ru
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for i in range(5):
                (root / f"{i}.bin").write_bytes(b"A" * 100)
            self.assertEqual(len(list(ru.iter_files(root, max_files=2, max_file_mb=1))), 2)
            huge = root / "huge.bin"; huge.write_bytes(b"A" * 2048 + b"UNREACHED_MARKER")
            strings = ru.extract_strings(huge, minimum=4, max_bytes=1024)
            self.assertFalse(any("UNREACHED_MARKER" in item for item in strings))


class Storage:
    def __init__(self, findings): self._findings = findings
    def all_findings(self): return list(self._findings)


class ReporterHistoricalTests(unittest.TestCase):
    def test_report_outputs_qualified_posture_and_compatibility_aliases(self):
        from core.reporter import Reporter
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            ctx = types.SimpleNamespace(
                output=out,
                args=types.SimpleNamespace(confidence_threshold=0.0, dep_filter=None, no_html=False, allow_writes=False, bug_bounty_program=None, roe_ticket=None),
                targets=["example.test"],
                profile={"name": "safe", "active_probes": False, "rate_limit": {"global_rps": 1}, "hard_limits": {}},
                start_ts="2026-07-19T00:00:00+00:00",
                storage=Storage([]),
            )
            Reporter(ctx).write_all()
            expected = {
                "REPORT.html", "REPORT_final.html", "REPORT_final.md", "REPORT_confirmed.md",
                "REPORT_leads.md", "REPORT_executive.md", "REPORT_manager.md", "REPORT_developer.md",
                "REPORT_defender.md", "REPORT.json", "REPORT.csv", "REPORT.sarif",
                "report.json", "report.csv", "report.sarif", "METHODOLOGY_AUDIT.md",
            }
            self.assertTrue(expected.issubset({p.name for p in out.iterdir()}))
            final = (out / "REPORT_final.md").read_text(encoding="utf-8")
            self.assertIn("does not mean the target is safe", final)
            self.assertEqual(json.loads((out / "REPORT.json").read_text()), json.loads((out / "report.json").read_text()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
