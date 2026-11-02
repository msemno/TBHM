#!/usr/bin/env python3
"""Offline capability-depth and backward-compatibility tests for TBHM v3.9.7.2."""
from __future__ import annotations

import ast
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class V3971Tests(unittest.TestCase):
    def test_registry_is_truthful_and_valid(self):
        from core import capability_registry
        registry = capability_registry.load()
        self.assertEqual(capability_registry.validate_registry(registry), [])
        rows = capability_registry.by_id(registry)
        self.assertEqual(rows["evidence.session_beacon_import"]["implementation_state"], "import_only")
        self.assertEqual(rows["integration.adapter_proposal"]["implementation_state"], "proposal_only")
        self.assertFalse(rows["integration.adapter_proposal"]["enabled_by_default"])
        summary = capability_registry.summary(registry)
        self.assertEqual(summary["registered"], len(registry["capabilities"]))
        unavailable = [x for x in summary["capabilities"] if x["implementation_state"] == "unavailable"]
        self.assertTrue(unavailable)
        self.assertTrue(all(not x["runtime"]["available"] for x in unavailable))

    def test_doctor_never_prints_secret_values(self):
        from core import doctor
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            registry = json.loads((ROOT / "tooling/capability_registry_v3971.json").read_text())
            registry["capabilities"][0]["required_environment_variables"] = ["TBHM_TEST_SECRET"]
            reg = td / "registry.json"; reg.write_text(json.dumps(registry))
            old = os.environ.get("TBHM_TEST_SECRET")
            os.environ["TBHM_TEST_SECRET"] = "do-not-leak-this-value"
            try:
                result = doctor.run(output_dir=td / "out", capability_path=reg)
            finally:
                if old is None: os.environ.pop("TBHM_TEST_SECRET", None)
                else: os.environ["TBHM_TEST_SECRET"] = old
            encoded = json.dumps(result)
            self.assertNotIn("do-not-leak-this-value", encoded)
            env = next(x for x in result["environment_variables"] if x["name"] == "TBHM_TEST_SECRET")
            self.assertEqual(env["value"], "[REDACTED]")

    def test_safe_plan_rejects_arbitrary_commands_and_shell_metacharacters(self):
        from core.safe_plan_executor import validate_plan
        bad = {"schema_version":"1","actions":[{"action_type":"rdap_lookup","arguments":{"query":"example.com"},"command":"id"}]}
        with self.assertRaises(ValueError): validate_plan(bad)
        bad2 = {"schema_version":"1","actions":[{"action_type":"rdap_lookup","arguments":{"query":"example.com;id"}}]}
        with self.assertRaises(ValueError): validate_plan(bad2)
        bad3 = {"schema_version":"1","actions":[{"action_type":"arbitrary_shell","arguments":{"value":"id"}}]}
        with self.assertRaises(ValueError): validate_plan(bad3)

    def test_safe_plan_rdap_mock_and_username_approval(self):
        from core.safe_plan_executor import execute
        def transport(url, *, timeout, headers):
            return 200, {"objectClassName":"domain","ldhName":"example.com","entities":[{"handle":"PERSON-1","roles":["registrant"],"vcardArray":["vcard", [["fn",{},"text","Alice"]]]}]}, {}
        with tempfile.TemporaryDirectory() as td:
            plan={"schema_version":"1","actions":[{"action_type":"rdap_lookup","arguments":{"query":"example.com","query_type":"domain","redact_pii":True}}]}
            result=execute(plan,output_dir=td,osint_transport=transport)
            self.assertEqual(result["actions"][0]["status"],"completed")
            self.assertNotIn("Alice",result["actions"][0]["stdout"])
            user_plan={"schema_version":"1","actions":[{"action_type":"sherlock_username","arguments":{"username":"alice_admin"}}]}
            blocked=execute(user_plan,output_dir=td,dry_run=True)
            self.assertEqual(blocked["actions"][0]["status"],"blocked")
            approved=execute(user_plan,output_dir=td,dry_run=True,approval_manifest={"authorized_actions":["osint_person_exposure"]})
            self.assertEqual(approved["actions"][0]["status"],"dry_run")
            self.assertEqual(approved["actions"][0]["planned_argv"][0],"sherlock")

    def test_session_import_dedup_malformed_and_redaction(self):
        from core.session_importer import import_evidence
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"sessions.json"
            path.write_text(json.dumps([{"tool":"approved-tool","session_id":"S1","host":"WS1","user":"Alice"},{"tool":"approved-tool","session_id":"S1","host":"WS1","user":"Alice"},{"tool":"approved-tool"}]))
            result=import_evidence(path,redact_usernames=True)
            self.assertEqual(result["summary"]["normalized"],1)
            self.assertEqual(result["summary"]["deduplicated"],1)
            self.assertEqual(result["summary"]["malformed"],1)
            self.assertEqual(result["records"][0]["username"],"[REDACTED]")
            self.assertIn("username_sha256",result["records"][0])

    def test_rdap_retry_redaction_and_unknown_provider(self):
        from core.osint_collectors import collect, provider_status
        calls=[]
        def transport(url, *, timeout, headers):
            calls.append(url)
            if len(calls)==1: raise TimeoutError("fixture timeout")
            return 200,{"ldhName":"example.com","entities":[{"handle":"X","vcardArray":["vcard",[["email",{},"text","person@example.com"]]]}]},{}
        result=collect("rdap","example.com",transport=transport,retries=1,sleep=lambda _:None,redact_pii=True)
        self.assertEqual(result["status"],"ok")
        self.assertEqual(len(calls),2)
        self.assertNotIn("vcard_array",result["result"]["entities"][0])
        self.assertFalse(provider_status("invented-provider")["available"])

    def test_cloud_graph_detects_required_indicators_without_claiming_exploitability(self):
        from core.cloud_iam_graph import analyze
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/"aws.json").write_text(json.dumps({"UserName":"alice","Action":["iam:CreateAccessKey"]}))
            (root/"azure.json").write_text(json.dumps({"principalName":"svc","roleDefinitionName":"Application Administrator","scope":"tenant"}))
            result=analyze(root)
            text=json.dumps(result).lower()
            self.assertIn("iam:createaccesskey",text)
            self.assertIn("application administrator",text)
            self.assertTrue(all(x.get("exploitability")=="not asserted" for x in result["paths"]))
            self.assertGreaterEqual(result["summary"]["edges"],2)

    def test_compliance_phase_completion_alone_is_not_pass(self):
        from core.compliance_predicates import evaluate_control
        control={"id":"AC-1","title":"Access control","phases":["access_control"],"tags":["access-control"]}
        row=evaluate_control(control,[],lambda name: name=="access_control",framework="test")
        self.assertEqual(row["status"],"unknown")
        positive={**control,"predicate":"phase_completed_without_mapped_findings","positive_evidence":True}
        self.assertEqual(evaluate_control(positive,[],lambda _:True,framework="test")["status"],"pass")

    def test_cicd_native_dataflow_and_no_execution(self):
        from core.cicd_dataflow import analyze_text
        text='''on:\n  issue_comment:\njobs:\n  build:\n    permissions: write-all\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n      - uses: vendor/action@main\n'''
        rows=analyze_text(text,path=".github/workflows/build.yml")
        titles={x["title"] for x in rows}
        self.assertIn("Workflow grants write-all permissions",titles)
        self.assertIn("Third-party action uses a mutable reference",titles)
        self.assertIn("Untrusted workflow context reaches a command sink",titles)
        self.assertTrue(all(x.get("confirmed") is not True for x in rows))

    def test_ocsf_fingerprint_repeatability_and_classes(self):
        from core.ocsf_export import event
        base={"id":"F-1","title":"IAM path","domain":"cloud iam","severity":"HIGH","target":"alice","confidence":"MEDIUM","timestamp":"2026-01-01T00:00:00Z"}
        one=event(base,tool_version="3.9.7.2",class_hint="cloud_iam",observed_time="2026-01-01T00:00:00Z")
        two=event({**base,"timestamp":"2026-07-19T00:00:00Z"},tool_version="3.9.7.2",class_hint="cloud_iam",observed_time="2026-07-19T00:00:00Z")
        self.assertEqual(one["unmapped"]["stable_fingerprint"],two["unmapped"]["stable_fingerprint"])
        self.assertNotEqual(one["class_uid"],2004)

    def test_passive_wireless_inventory_boundary(self):
        from core.wireless_inventory import import_observations
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"wifi.csv"
            path.write_text("ESSID,BSSID,Privacy,channel\nGuest,aa:bb:cc:dd:ee:ff,OPN,6\n")
            result=import_observations(path,location_label="Lab")
            self.assertEqual(result["summary"]["observations"],1)
            self.assertIn("Open",result["observations"][0]["risk_notes"][0])
            self.assertIn("No capture automation",result["boundary"])

    def test_adapter_generator_is_unapproved_proposal_only(self):
        from core.adapter_proposals import generate
        result=generate({"name":"Safe Scanner","executable":"safe-scanner","output_formats":["json","sarif"],"risk":"medium","command_template":"safe-scanner {input}"})
        self.assertEqual(result["status"],"UNAPPROVED_PROPOSAL")
        self.assertFalse(result["activation"]["approved"])
        self.assertFalse(result["activation"]["automatic_install"])
        self.assertFalse(result["activation"]["automatic_execution"])
        self.assertNotIn("safe-scanner {input}",json.dumps(result))

    def test_cli_and_phase_backward_compatibility(self):
        import tbhm
        baseline=json.loads((ROOT/"knowledge/compatibility_baseline_v3961.json").read_text())
        flags=set()
        for source in ROOT.rglob("*.py"):
            if any(part in {"__pycache__", ".git", ".pytest_cache", "results"} for part in source.parts):
                continue
            tree=ast.parse(source.read_text(encoding="utf-8",errors="ignore"))
            for node in ast.walk(tree):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=="add_argument":
                    for arg in node.args:
                        if isinstance(arg,ast.Constant) and isinstance(arg.value,str) and arg.value.startswith("-"):
                            flags.add(arg.value)
        self.assertFalse(set(baseline["cli_flags"])-flags)
        self.assertFalse(set(baseline["phase_names"])-set(tbhm.PHASE_ORDER))
        self.assertGreaterEqual(len(tbhm.PHASE_ORDER),129)
        self.assertEqual(len(tbhm.PHASE_ORDER),len(set(tbhm.PHASE_ORDER)))
        self.assertEqual(tbhm.PHASE_ORDER[0],"preflight")
        self.assertEqual(tbhm.PHASE_ORDER[-1],"evidence_finalize")
        self.assertLess(tbhm.PHASE_ORDER.index("report"),tbhm.PHASE_ORDER.index("evidence_finalize"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
