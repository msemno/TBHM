#!/usr/bin/env python3
"""Offline regression/integration suite for TBHM v3.9.5.

The suite validates the new corporate-intelligence, standards, analytical,
approval and supervised-learning boundaries without network or external tools.
"""
from __future__ import annotations

import csv
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
        p = Path(path); return p.read_text(errors="ignore").splitlines() if p.exists() else []


class FakeStorage:
    def __init__(self, findings=None):
        self._findings = findings or []
        self.enrichments = []
        self.scores = []
        self.conn = None
    def all_findings(self): return self._findings
    def enrich_finding(self, finding_id, enrichment, cwe="", cvss=""):
        self.enrichments.append((finding_id, enrichment, cwe, cvss)); return True
    def save_endpoint_score(self, url, score, components): self.scores.append((url, score, components))


class FakeCtx:
    def __init__(self, output, *, args=None, targets=None, findings=None, profile=None):
        from core.scope import Scope
        self.output = Path(output); self.output.mkdir(parents=True, exist_ok=True)
        self.args = args or types.SimpleNamespace()
        self.targets = targets or ["example.com"]
        self.profile = profile or {"name": "authorized_safe", "active_probes": True,
                                   "rate_limit": {"global_rps": 5, "per_target_rps": 5}}
        self.scope = Scope(["example.com"], [])
        self.scope_includes = ["example.com"]; self.scope_excludes = []
        self.runner = FakeRunner(); self.storage = FakeStorage(findings)
        self.phase_state = {}; self.saved = []; self.logs = []
    def save_finding(self, finding): self.saved.append(finding); return len(self.saved)
    def log(self, level, phase, message): self.logs.append((level, phase, message))


def ns(**kwargs):
    defaults = dict(
        corporate_osint=False, osint_results=None, osint_seeds=None,
        organization_domains_file=None, organization_name="", organization_aliases="",
        osint_person_collection=False, osint_pii_policy=None, osint_usernames=None,
        osint_emails=None, osint_live=False, osint_tools="asnmap,theharvester",
        osint_max_domains=200, osint_docs=None, approval_manifest=None,
        data_analysis=False, data_input=None, redteam=False,
        no_exploitability_assessment=False, intel_enrichment=False, intel_dir=None,
        dep_filter=None, confidence_threshold=0.0,
    )
    defaults.update(kwargs); return types.SimpleNamespace(**defaults)


class V395Tests(unittest.TestCase):
    def test_phase_order_and_profiles(self):
        import tbhm
        self.assertGreaterEqual(len(tbhm.PHASE_ORDER), 116)
        for name in ("corporate_osint", "data_analysis_intelligence", "ai_supervision",
                     "controlled_validation_plane", "vulnerability_intelligence_enrichment"):
            self.assertIn(name, tbhm.PHASE_ORDER)
        import yaml
        redteam = yaml.safe_load(Path("profiles/authorized_redteam.yaml").read_text())
        phases = redteam["phases"]
        self.assertIn("corporate_osint", phases)
        self.assertIn("ai_supervision", phases)
        self.assertTrue(redteam.get("ai_observe"))
        assumed = yaml.safe_load(Path("profiles/authorized_assumed_breach.yaml").read_text())
        self.assertEqual(assumed["name"], "authorized_assumed_breach")
        self.assertTrue(assumed.get("ai_observe"))

    def test_catalog_and_safe_installer_policy(self):
        from core.tool_catalog import load
        from scripts.install_extended_tools import _allowed_argv
        catalog = load()
        self.assertGreaterEqual(len(catalog["tools"]), 480)
        for item in catalog["tools"]:
            argv = _allowed_argv(item)
            if str(item.get("risk")) in {"high", "critical"} or str(item.get("integration_mode")) in {"approval_cli", "approval_only"}:
                self.assertIsNone(argv, item.get("id"))

    def test_adapter_contract_and_provenance(self):
        from core.adapter_contract import AdapterSpec, validate_spec, binary_provenance
        good = AdapterSpec("example", "python3", "safe_cli", ("json",), read_only=True)
        self.assertEqual(validate_spec(good), [])
        bad = AdapterSpec("bad", "tool", "safe_cli", (), read_only=False)
        self.assertTrue(validate_spec(bad))
        self.assertTrue(binary_provenance("python3")["installed"])

    def test_approval_domain_url_ip_and_cidr(self):
        from core.approval_gate import load_manifest, approved
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "approval.json"
            p.write_text(json.dumps({
                "engagement_id": "E1", "approved_by": "client",
                "expires_at": (datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),
                "authorized_actions": ["corporate_osint"],
                "targets": ["example.com", "192.0.2.0/24"],
            }))
            m = load_manifest(p)
            self.assertTrue(approved(m, "corporate_osint", "https://api.example.com/x")[0])
            self.assertTrue(approved(m, "corporate_osint", "192.0.2.55")[0])
            self.assertFalse(approved(m, "corporate_osint", "evil.invalid")[0])

    def test_corporate_osint_hashes_email_without_pii_policy(self):
        from phases import corporate_osint
        with tempfile.TemporaryDirectory() as td:
            result = Path(td) / "input.txt"
            result.write_text("Contact alice@example.com and api.example.com at https://api.example.com/v1")
            args = ns(corporate_osint=True, osint_results=str(result), organization_name="Example")
            ctx = FakeCtx(Path(td)/"run", args=args)
            corporate_osint.run(ctx)
            entities = json.loads((ctx.output/"redteam/10_corporate_osint/exports/entities.json").read_text())
            values = [row["value"] for row in entities]
            kinds = [row["type"] for row in entities]
            self.assertNotIn("alice@example.com", values)
            self.assertIn("email_hash", kinds)
            self.assertEqual(ctx.targets, ["example.com"])
            self.assertTrue((ctx.output/"redteam/10_corporate_osint/exports/entity_graph.stix.json").exists())

    def test_authenticated_har_role_matrix_is_offline_supported_lead(self):
        from phases import authenticated_session_model
        with tempfile.TemporaryDirectory() as td:
            har_dir = Path(td)/"har"; har_dir.mkdir()
            def write(role, status):
                (har_dir/f"{role}.har").write_text(json.dumps({"log":{"entries":[{
                    "request":{"method":"GET","url":"https://example.com/api/users/10"},
                    "response":{"status":status,"content":{"size":10}}
                }]}}))
            write("admin", 200); write("user", 200)
            matrix = Path(td)/"roles.yaml"
            matrix.write_text("routes:\n  'GET /api/users/{id}':\n    admin: allow\n    user: deny\n")
            args = ns(session_har=str(har_dir), role_matrix=str(matrix))
            ctx = FakeCtx(Path(td)/"run", args=args)
            authenticated_session_model.run(ctx)
            self.assertEqual(len(ctx.saved), 1)
            self.assertEqual(ctx.saved[0]["finding_class"], "supported")
            self.assertFalse(ctx.saved[0]["verified"])

    def test_vulnerability_enrichment_local_feeds_never_confirms(self):
        from phases import vulnerability_intelligence_enrichment
        with tempfile.TemporaryDirectory() as td:
            feed = Path(td)/"feeds"; feed.mkdir()
            (feed/"known_exploited_vulnerabilities.json").write_text(json.dumps({
                "vulnerabilities":[{"cveID":"CVE-2024-12345","dueDate":"2026-01-01"}]}))
            (feed/"epss.csv").write_text("cve,epss,percentile\nCVE-2024-12345,0.8,0.99\n")
            finding = {"id":1,"title":"Component CVE-2024-12345", "description":"", "evidence":"",
                       "severity":"HIGH", "phase":"code_intel", "extra":{}}
            ctx = FakeCtx(Path(td)/"run", args=ns(intel_enrichment=True, intel_dir=str(feed), dep_filter="kev"), findings=[finding])
            vulnerability_intelligence_enrichment.run(ctx)
            self.assertEqual(len(ctx.storage.enrichments), 1)
            payload = ctx.storage.enrichments[0][1]["vulnerability_intelligence"]
            self.assertTrue(payload["records"][0]["kev"])
            self.assertTrue(payload["records"][0]["dep_filter_match"])
            self.assertTrue(payload["non_authoritative"])

    def test_data_analysis_hashes_email_and_exports_graph(self):
        from phases import data_analysis_intelligence
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td)/"rows.jsonl"
            inp.write_text(json.dumps({"email":"alice@example.com","domain":"example.com","cve":"CVE-2024-12345"})+"\n")
            ctx = FakeCtx(Path(td)/"run", args=ns(data_analysis=True, data_input=str(inp)), findings=[])
            data_analysis_intelligence.run(ctx)
            entities = json.loads((ctx.output/"redteam/105_data_analysis_intelligence/graph_exports/entities.json").read_text())
            self.assertFalse(any(e["value"] == "alice@example.com" for e in entities))
            self.assertTrue(any(e["type"] == "email_hash" for e in entities))
            self.assertTrue((ctx.output/"redteam/105_data_analysis_intelligence/graph_exports/entity_graph.stix.json").exists())


    def test_controlled_validation_requires_matching_approval_for_findings(self):
        from phases import controlled_validation_plane
        with tempfile.TemporaryDirectory() as td:
            result = Path(td)/"result.json"
            result.write_text(json.dumps({"results":[{
                "action":"approved_external_validation_import",
                "target":"app.example.com", "outcome":"validated",
                "evidence":"benign marker returned", "cleanup_status":"COMPLETE"
            }]}))
            args = ns(controlled_validation=True, validation_plan=None, validation_results=str(result))
            ctx = FakeCtx(Path(td)/"run1", args=args)
            controlled_validation_plane.run(ctx)
            self.assertEqual(ctx.saved, [])

            approval = Path(td)/"approval.json"
            approval.write_text(json.dumps({
                "engagement_id":"E1", "approved_by":"client",
                "expires_at":(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),
                "authorized_actions":["approved_external_validation_import"],
                "targets":["example.com"]
            }))
            args2 = ns(controlled_validation=True, validation_plan=None, validation_results=str(result), approval_manifest=str(approval))
            ctx2 = FakeCtx(Path(td)/"run2", args=args2)
            controlled_validation_plane.run(ctx2)
            self.assertEqual(len(ctx2.saved), 1)
            self.assertEqual(ctx2.saved[0]["finding_class"], "supported")
            self.assertFalse(ctx2.saved[0]["verified"])

    def test_run_learning_redacts_untrusted_secret(self):
        from core.ai_plane.run_learning import _chunks
        rows = _chunks("api_key=sk_live_123456789012345678901234567890", phase="x", rel="a.txt")
        blob = "".join(x["text"] for x in rows)
        self.assertNotIn("sk_live_123456789012345678901234567890", blob)
        self.assertIn("UNTRUSTED", blob.upper())

    def test_report_confidence_and_dependency_gates_demote_not_delete(self):
        from core.reporter import Reporter
        args = ns(confidence_threshold=0.9, dep_filter="kev")
        ctx = FakeCtx(tempfile.mkdtemp(), args=args)
        report = Reporter(ctx)
        confirmed_low = {"title":"Finding", "confidence":"HIGH", "severity":"HIGH",
                         "exploitability":{"confirmation_status":"CONFIRMED"}}
        dep = {"title":"Vulnerable dependency CVE-2024-1", "phase":"code_intel", "severity":"HIGH",
               "confidence":"HIGH", "exploitability":{"confirmation_status":"SUPPORTED"},
               "enrichment":{"vulnerability_intelligence":{"records":[{"dep_filter_match":False}]}}}
        from test_support import verified_fields
        with tempfile.TemporaryDirectory() as td:
            confirmed_low.update(verified_fields(td))
        c, s, l = report._groups([confirmed_low, dep])
        self.assertEqual(c, [])
        self.assertIn(confirmed_low, s)
        self.assertIn(dep, l)

    def test_thread_clamp_and_test_path_policy(self):
        import tbhm
        from core import code_intel
        args = types.SimpleNamespace(threads=999, silent=True)
        profile = {"name":"authorized_full", "active_probes":True,
                   "rate_limit":{"global_rps":10}, "hard_limits":{"max_threads":12}}
        self.assertEqual(tbhm._apply_thread_override(args, profile), 12)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"src").mkdir(); (root/"tests").mkdir()
            (root/"src/app.py").write_text("print('prod')")
            (root/"tests/test_app.py").write_text("print('test')")
            code_intel.configure_scan_policy(True)
            prod=[x[1] for x in code_intel.iter_source_files(root)]
            self.assertTrue(any("src/app.py" in x for x in prod)); self.assertFalse(any("test_app.py" in x for x in prod))
            code_intel.configure_scan_policy(False)
            noisy=[x[1] for x in code_intel.iter_source_files(root)]
            self.assertTrue(any("test_app.py" in x for x in noisy))

    def test_notifier_rejects_insecure_remote_http(self):
        from core.notifier import send_completion
        ok, detail = send_completion("http://example.com/hook", version="x", profile="p", status="done", counts={})
        self.assertFalse(ok); self.assertIn("HTTPS", detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
