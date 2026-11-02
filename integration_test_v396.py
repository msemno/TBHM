#!/usr/bin/env python3
"""Offline regression suite for TBHM v3.9.6 enterprise-control-plane.

The suite verifies that new depth modules are operational while high-impact
execution remains approval-gated plan/import only. No network or external
operator tooling is required.
"""
from __future__ import annotations

import json
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


class FakeRunner:
    threads = 4
    def has(self, _name): return False
    def run(self, *_a, **_kw): return 127, "", "missing"
    @staticmethod
    def read_lines(path):
        p = Path(path)
        return p.read_text(errors="ignore").splitlines() if p.exists() else []


class FakeStorage:
    def __init__(self, findings=None, done=None):
        self._findings = findings or []
        self._done = set(done or [])
        self.scores = []
    def all_findings(self): return list(self._findings)
    def is_phase_done(self, phase): return phase in self._done
    def save_endpoint_score(self, url, score, components): self.scores.append((url, score, components))


class FakeCtx:
    def __init__(self, output, *, args=None, targets=None, findings=None, done=None, profile=None):
        from core.scope import Scope
        self.output = Path(output); self.output.mkdir(parents=True, exist_ok=True)
        self.args = args or ns()
        self.targets = targets or ["example.com"]
        self.profile = profile or {"name":"authorized_redteam", "active_probes":True,
                                   "rate_limit":{"global_rps":3,"per_target_rps":2}}
        self.scope = Scope(["example.com"], [])
        self.scope_includes = ["example.com"]; self.scope_excludes = []
        self.runner = FakeRunner(); self.storage = FakeStorage(findings, done)
        self.phase_state = {}; self.saved = []; self.logs = []
        self.start_ts = "2026-07-18T00:00:00+00:00"
    def save_finding(self, row): self.saved.append(row); return len(self.saved)
    def log(self, level, phase, message): self.logs.append((level, phase, message))


def ns(**kwargs):
    defaults = dict(
        agentic_manifest=False, ai_supervise=False, tool_catalog=None,
        execution_orchestration=False, execution_registry=None, execution_plan=None,
        execution_results=None, execution_from_findings=False, approval_manifest=None,
        social_engineering=False, social_engineering_plan=None, social_engineering_results=None,
        osint_depth=False, osint_depth_results=None, osint_favicon_urls=None,
        osint_google_dorks=False, osint_axfr=False, osint_request_budget=50,
        osint_live=False, osint_person_collection=False, osint_pii_policy=None,
        osint_usernames=None,
        cicd_security=False, cicd_results=None, attestation_dir=None, code_dir=None,
        cloud_identity_paths=False, cloud_iam_input=None,
        compliance_catalog=None, compliance_frameworks=None, no_ocsf=False,
        confidence_threshold=0.0, dep_filter=None, no_html=False,
    )
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


class V396Tests(unittest.TestCase):
    def test_phase_order_profiles_and_version(self):
        import tbhm
        self.assertGreaterEqual(len(tbhm.PHASE_ORDER), 129)
        expected = {
            "agentic_control_manifest", "osint_depth_collectors",
            "social_engineering_governance", "ci_cd_supply_chain_security",
            "cloud_identity_path_analysis", "execution_orchestration_plan",
            "compliance_reporting_extended", "ocsf_normalization",
        }
        self.assertTrue(expected.issubset(tbhm.PHASE_ORDER))
        import yaml
        for profile in ("authorized_redteam.yaml", "authorized_assumed_breach.yaml"):
            data = yaml.safe_load((Path("profiles")/profile).read_text())
            self.assertTrue(expected.issubset(set(data["phases"])))
        from core import reporter
        self.assertEqual(reporter.VERSION, "4.2.7")

    def test_execution_registry_enforces_plan_import_boundary(self):
        from core.execution_registry import load, validate_adapter, HIGH_IMPACT_CAPABILITIES
        registry = load()
        self.assertGreaterEqual(len(registry["adapters"]), 10)
        for row in registry["adapters"]:
            self.assertEqual(validate_adapter(row), [], row.get("id"))
            if row.get("capability") in HIGH_IMPACT_CAPABILITIES:
                self.assertIn(row.get("mode"), {"plan_import", "commercial_import"})

    def test_execution_plan_is_approval_gated_and_contains_no_commands(self):
        from phases import execution_orchestration_plan
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            plan = td/"plan.yaml"
            plan.write_text("""actions:\n  - id: A1\n    stage: initial_access_validation\n    adapter_id: metasploit-import\n    target: app.example.com\n    objective: Evidence-led validation\n""")
            approval = td/"approval.json"
            approval.write_text(json.dumps({
                "engagement_id":"E1", "approved_by":"client",
                "expires_at":(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),
                "authorized_actions":["execution:metasploit-import"],
                "targets":["example.com"],
            }))
            ctx = FakeCtx(td/"run", args=ns(execution_orchestration=True,
                                             execution_plan=str(plan),
                                             approval_manifest=str(approval)))
            execution_orchestration_plan.run(ctx)
            payload = json.loads((ctx.output/"redteam/99_execution_orchestration_plan/execution_orchestration.json").read_text())
            row = payload["planned_actions"][0]
            self.assertTrue(row["approval_verified"])
            self.assertEqual(row["commands"], [])
            self.assertEqual(row["payloads"], [])
            self.assertNotIn("EXECUTED", row["status"])


    def test_invalid_high_impact_registry_override_is_blocked(self):
        from phases import execution_orchestration_plan
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            registry = td/"registry.json"
            registry.write_text(json.dumps({"version":"test","adapters":[{
                "id":"unsafe", "name":"unsafe", "capability":"c2",
                "mode":"read_only", "risk":"low", "required_controls":[],
                "evidence_schema":{}, "cleanup_requirements":[]
            }]}))
            plan = td/"plan.json"
            plan.write_text(json.dumps({"actions":[{"id":"X","adapter_id":"unsafe",
                                                     "target":"example.com","objective":"x"}]}))
            ctx = FakeCtx(td/"run", args=ns(execution_orchestration=True,
                                             execution_registry=str(registry),
                                             execution_plan=str(plan)))
            execution_orchestration_plan.run(ctx)
            payload = json.loads((ctx.output/"redteam/99_execution_orchestration_plan/execution_orchestration.json").read_text())
            self.assertIn("unsafe", payload["registry_errors"])
            self.assertEqual(payload["planned_actions"][0]["status"], "BLOCKED")

    def test_social_engineering_unsafe_plan_is_blocked(self):
        from phases import social_engineering_governance
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            plan = td/"plan.json"
            plan.write_text(json.dumps({"exercises":[{
                "id":"S1", "type":"phishing_simulation", "scope_target":"example.com",
                "target_group":"staff", "synthetic_credentials_only":False,
                "real_password_collection_disabled":False, "notification_plan":True,
                "takedown_plan":True, "max_recipients":10,
            }]}))
            approval = td/"approval.json"
            approval.write_text(json.dumps({
                "engagement_id":"E1", "approved_by":"client",
                "expires_at":(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),
                "authorized_actions":["social_engineering:phishing_simulation"],
                "targets":["example.com"],
            }))
            ctx = FakeCtx(td/"run", args=ns(social_engineering=True,
                                             social_engineering_plan=str(plan),
                                             approval_manifest=str(approval)))
            social_engineering_governance.run(ctx)
            rows = (ctx.output/"redteam/27_social_engineering_governance/exercise_register.csv").read_text()
            self.assertIn("BLOCKED", rows)
            self.assertEqual(ctx.saved, [])

    def test_osint_depth_generates_plan_and_hashes_username(self):
        from phases import osint_depth_collectors
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            users = td/"users.txt"; users.write_text("Alice.Admin\n")
            ctx = FakeCtx(td/"run", args=ns(osint_depth=True, osint_google_dorks=True,
                                             osint_usernames=str(users),
                                             osint_person_collection=True,
                                             osint_pii_policy=str(td/"pii.yaml")))
            osint_depth_collectors.run(ctx)
            payload = json.loads((ctx.output/"redteam/11_osint_depth_collectors/osint_depth_summary.json").read_text())
            self.assertTrue(payload["google_dork_plan"])
            person = payload["person_collection_plan"][0]
            self.assertNotIn("Alice.Admin", json.dumps(person))
            self.assertEqual(len(person["username_hash"]), 64)

    def test_ci_cd_static_review_and_attestation_inventory(self):
        from phases import ci_cd_supply_chain_security
        with tempfile.TemporaryDirectory() as td:
            td = Path(td); repo=td/"repo"; wf=repo/".github/workflows"; wf.mkdir(parents=True)
            (wf/"build.yml").write_text("permissions: write-all\nsteps:\n - uses: actions/checkout@main\n")
            att=td/"att"; att.mkdir(); (att/"provenance.json").write_text("{}")
            ctx=FakeCtx(td/"run", args=ns(cicd_security=True, code_dir=str(repo), attestation_dir=str(att)))
            ci_cd_supply_chain_security.run(ctx)
            self.assertGreaterEqual(len(ctx.saved), 2)
            payload=json.loads((ctx.output/"redteam/47_ci_cd_supply_chain_security/ci_cd_supply_chain_summary.json").read_text())
            self.assertEqual(payload["scanned_pipeline_files"], 1)
            self.assertEqual(len(payload["attestation_inventory"]), 1)

    def test_cloud_identity_analysis_is_read_only_lead(self):
        from phases import cloud_identity_path_analysis
        with tempfile.TemporaryDirectory() as td:
            td=Path(td); inp=td/"iam.json"
            inp.write_text(json.dumps({"Action":["iam:PassRole","lambda:CreateFunction"]}))
            ctx=FakeCtx(td/"run", args=ns(cloud_identity_paths=True, cloud_iam_input=str(inp)))
            cloud_identity_path_analysis.run(ctx)
            self.assertGreaterEqual(len(ctx.saved), 2)
            self.assertTrue(all(not x["verified"] and x["finding_class"]=="lead" for x in ctx.saved))

    def test_compliance_matrix_is_policy_driven_not_certification(self):
        from phases import compliance_reporting_extended
        finding={"id":1,"phase":"authenticated_session_model","severity":"HIGH",
                 "title":"Broken authorization", "description":"IDOR access control"}
        with tempfile.TemporaryDirectory() as td:
            ctx=FakeCtx(Path(td)/"run", args=ns(compliance_frameworks="pci-dss,nist-800-53"),
                        findings=[finding], done={"authenticated_session_model"})
            compliance_reporting_extended.run(ctx)
            payload=json.loads((ctx.output/"redteam/104_compliance_reporting_extended/compliance_framework_matrix.json").read_text())
            self.assertEqual({x["id"] for x in payload["frameworks"]}, {"pci-dss","nist-800-53"})
            self.assertIn("not a certification", payload["statement"].lower())

    def test_ocsf_and_mcp_manifests_are_non_authoritative(self):
        from phases import ocsf_normalization, agentic_control_manifest
        finding={"id":7,"phase":"code_intel","severity":"HIGH","title":"Static lead",
                 "description":"example", "target":"src/app.py", "cwe":"CWE-78"}
        with tempfile.TemporaryDirectory() as td:
            ctx=FakeCtx(Path(td)/"run", args=ns(agentic_manifest=True), findings=[finding])
            agentic_control_manifest.run(ctx); ocsf_normalization.run(ctx)
            m=json.loads((ctx.output/"redteam/03_agentic_control_manifest/mcp_capability_manifest.json").read_text())
            self.assertFalse(m["network_server_started"])
            self.assertFalse(any(x["ai_callable"] for x in m["tool_resources"] if str(x.get("risk")).lower() in {"high","critical"}))
            line=(ctx.output/"redteam/108_ocsf_normalization/ocsf_findings.jsonl").read_text().splitlines()[0]
            event=json.loads(line)
            self.assertEqual(event["class_uid"], 2004)
            self.assertEqual(event["metadata"]["product"]["version"], "4.2.7")

    def test_richer_sarif_has_provenance_and_fingerprint(self):
        from core.reporter import Reporter
        finding={"id":1,"phase":"code_intel","severity":"HIGH","title":"Command injection",
                 "description":"lead", "target":"src/app.py", "cwe":"CWE-78"}
        with tempfile.TemporaryDirectory() as td:
            ctx=FakeCtx(Path(td), args=ns(), findings=[finding])
            Reporter(ctx)._write_sarif([finding])
            sarif=json.loads((Path(td)/"report.sarif").read_text())
            run=sarif["runs"][0]
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertIn("automationDetails", run)
            self.assertIn("invocations", run)
            self.assertIn("partialFingerprints", run["results"][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
