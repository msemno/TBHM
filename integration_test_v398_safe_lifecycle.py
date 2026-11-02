#!/usr/bin/env python3
"""Offline regression tests for strict evidence lifecycle and safe campaign controls."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path


class _Monitor:
    def wait_if_pressured(self, max_wait_sec=15):
        return None


class StrictLifecycleTests(unittest.TestCase):
    def test_high_confidence_or_liveness_cannot_confirm(self):
        from core.finding_class import classify
        high = {
            "severity": "HIGH", "confidence": "HIGH", "phase": "audit",
            "title": "Authorization response observed", "evidence": "HTTP 200",
            "response_raw": "HTTP/1.1 200 OK\r\n\r\nnormal page",
        }
        self.assertNotEqual(classify(high), "confirmed")
        self.assertEqual(classify(high), "supported")
        legacy_words = {**high, "title": "Verified and confirmed issue", "evidence": "reproduced"}
        self.assertNotEqual(classify(legacy_words), "confirmed")

    def test_structured_assertion_requires_negative_control_and_repeatability(self):
        from core.assertion_engine import evaluate, confirmation_fields
        from test_support import captured_access_proof
        with tempfile.TemporaryDirectory() as td:
            assertion, proof = captured_access_proof(td)
            result = evaluate(assertion, proof, evidence_root=td)
            self.assertEqual(result["result"], "pass")
            self.assertTrue(confirmation_fields(result, method="v2 capture verifier")["verified"])
            proof["captures"]["repeats"] = proof["captures"]["repeats"][:1]
            incomplete = evaluate(assertion, proof, evidence_root=td)
            self.assertEqual(incomplete["result"], "inconclusive")
            self.assertFalse(confirmation_fields(incomplete, method="v2 capture verifier")["verified"])

    def test_unsupported_liveness_assertion_is_inconclusive(self):
        from core.assertion_engine import evaluate
        assertion = {
            "test_id": "bad.liveness.v1",
            "failure_conditions": [{"type": "endpoint_is_live", "source": "mutation"}],
            "negative_control_conditions": [{"type": "status_equals", "source": "negative_control", "value": 404}],
        }
        proof = {
            "baseline": {"status": 200}, "mutation": {"status": 200},
            "negative_control": {"status": 404},
            "repeatability": {"attempts": 2, "successful_proofs": 2},
        }
        self.assertEqual(evaluate(assertion, proof)["result"], "inconclusive")

    def test_storage_separates_test_observation_candidate_validation_and_finding(self):
        from core.storage import Storage
        from core.assertion_engine import evaluate, confirmation_fields
        with tempfile.TemporaryDirectory() as td:
            store = Storage(Path(td) / "tbhm.db")
            store.save_run({"started_at": "2026-07-26T00:00:00", "profile": "test", "targets": ["example.test"]})
            test_id = store.start_test_execution(test_id="T-1", phase="unit", target="example.test")
            obs_id = store.save_observation(phase="unit", observation_type="differential-response",
                                            target="example.test", summary="candidate", test_execution_id=test_id)
            finding = {
                "phase": "unit", "severity": "HIGH", "confidence": "HIGH",
                "title": "Cross-object authorization failure", "target": "example.test",
                "description": "candidate", "evidence": "structured evidence pending",
                "discovered_at": "2026-07-26T00:00:01",
            }
            fid = store.save_finding(finding)
            cid = store.save_candidate(finding_id=fid, observation_id=obs_id, finding=finding,
                                       required_validation="structured assertion")
            assertion = {
                "test_id": "T-1",
                "failure_conditions": [{"type": "object_identity_equals", "source": "mutation", "value": "B"}],
                "negative_control_conditions": [{"type": "status_equals", "source": "negative_control", "value": 404}],
            }
            proof = {
                "baseline": {"object_identity": "A", "status": 200},
                "mutation": {"object_identity": "B", "status": 200},
                "negative_control": {"status": 404},
                "repeatability": {"attempts": 2, "successful_proofs": 2},
            }
            from test_support import captured_access_proof
            assertion, proof = captured_access_proof(td, "T-1")
            result = evaluate(assertion, proof, evidence_root=td)
            aid = store.record_validation_attempt(verifier="unit", result=result, assertion=assertion,
                                                  proof=proof, finding_id=fid, candidate_id=cid,
                                                  test_execution_id=test_id)
            store.update_finding_verification(fid, confirmation_fields(result, method="unit", validation_attempt_id=aid))
            store.complete_test_execution(test_id, status="failed-security-control", result_summary="assertion passed")
            row = store.all_findings()[0]
            self.assertTrue(row["verified"])
            self.assertEqual(row["candidate_id"], cid) if "candidate_id" in row else None
            self.assertEqual(store.all_test_executions()[0]["status"], "failed-security-control")
            counts = {
                table: store.conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
                for table in ("observations", "candidates", "validation_attempts", "findings")
            }
            self.assertEqual(counts, {"observations": 1, "candidates": 1, "validation_attempts": 1, "findings": 1})
            store.close()

    def test_program_policy_fails_closed_for_unclear_scope_and_methods(self):
        from core.program_policy import evaluate_asset, evaluate_action, evaluate_vulnerability
        policy = {
            "policy_id": "P-1", "included_assets": ["*.example.test"],
            "excluded_assets": ["admin.example.test"],
            "allowed_http_methods": ["GET"],
            "eligible_vulnerability_types": ["idor"],
            "ineligible_vulnerability_types": ["dos"],
            "prohibited_actions": ["credential_attack"],
        }
        self.assertEqual(evaluate_asset(policy, "api.example.test")["decision"], "in_scope")
        self.assertEqual(evaluate_asset(policy, "admin.example.test")["decision"], "out_of_scope")
        self.assertEqual(evaluate_asset(policy, "example.net")["decision"], "unclear")
        self.assertFalse(evaluate_action(policy, "scan", method="POST")["allowed"])
        self.assertFalse(evaluate_action(policy, "credential_attack")["allowed"])
        self.assertIsNone(evaluate_vulnerability(policy, "xss")["eligible"])


    def test_report_assessment_uses_strict_confirmation(self):
        from core.exploitability import assess
        bare = {
            "severity": "HIGH", "confidence": "HIGH", "phase": "audit",
            "title": "Verified issue", "evidence": "reproduced successfully",
            "verified": True, "verification_method": "generic curl",
        }
        self.assertNotEqual(assess(bare)["confirmation_status"], "CONFIRMED")
        strict = {**bare, "verification_state": "confirmed",
                  "assertion_passed": True, "negative_control_passed": True,
                  "repeatability_passed": True}
        self.assertNotEqual(assess(strict)["confirmation_status"], "CONFIRMED")
        from test_support import verified_fields
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(assess({**bare, **verified_fields(td)})["confirmation_status"], "CONFIRMED")

    def test_request_workspace_redacts_url_headers_and_bodies(self):
        from core.request_model import normalize_request
        row = normalize_request({
            "method": "POST",
            "url": "https://api.example.test/login?token=secret-value&view=full",
            "headers": {"Authorization": "Bearer secret", "Content-Type": "application/json"},
            "body": {"username": "alice", "password": "secret", "nested": {"access_token": "abc"}},
        })
        encoded = json.dumps(row)
        self.assertNotIn("secret-value", encoded)
        self.assertNotIn("Bearer secret", encoded)
        self.assertNotIn('"password": "secret"', encoded)
        self.assertIn("[REDACTED]", encoded)
        self.assertEqual(len(row["body_sha256"]), 64)

    def test_high_impact_redteam_operations_are_import_only(self):
        from core.campaign_model import normalize_operation, result_is_complete
        for op_type in ("exploit_validation", "credential_access", "c2", "persistence",
                        "lateral_movement", "exfiltration", "defense_evasion"):
            row = normalize_operation({"operation_id": op_type, "operation_type": op_type,
                                       "execution_class": "read_only", "target": "lab-host"})
            self.assertEqual(row["execution_class"], "import_only")
        evidence = {"artifact": "evidence.json"}
        evidence_sha = hashlib.sha256(json.dumps(
            evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        ok, missing = result_is_complete({
            "operation_id": "op-1", "target": "lab-host", "outcome": "control validated",
            "evidence": evidence, "evidence_sha256": evidence_sha,
            "cleanup_status": "VERIFIED",
        })
        self.assertTrue(ok, missing)
        bad, missing = result_is_complete({"operation_id": "op-1", "target": "lab-host"})
        self.assertFalse(bad)
        self.assertIn("valid evidence SHA-256", missing)

    def test_runner_streams_bounded_output_times_out_and_runs_parallel(self):
        from core.runner import Runner
        with tempfile.TemporaryDirectory() as td:
            profile = {"runtime": {"threads": 4, "max_parallel_tools": 2,
                                   "capture_tail_bytes": 65536, "executor_backend": "auto"},
                       "rate_limit": {"global_rps": 1000}}
            runner = Runner(profile, object(), _Monitor(), Path(td))
            rc, out, err = runner.run([sys.executable, "-c", "print('x'*200000)"], timeout=10, log_name="large", capture_mode="tail")
            self.assertEqual(rc, 0, err)
            self.assertLessEqual(len(out.encode()), 65536 + 16)
            self.assertGreater((Path(td) / "logs" / "large.log").stat().st_size, len(out))
            rc, _, err = runner.run([sys.executable, "-c", "import time; time.sleep(3)"], timeout=1, log_name="timeout", capture_mode="tail")
            self.assertEqual(rc, 124)
            self.assertIn("timeout", err.lower())
            start = time.monotonic()
            rows = runner.run_many([
                {"job_id": "a", "cmd": [sys.executable, "-c", "import time;time.sleep(1.3);print('a')"], "timeout": 5},
                {"job_id": "b", "cmd": [sys.executable, "-c", "import time;time.sleep(1.3);print('b')"], "timeout": 5},
            ], max_workers=2)
            elapsed = time.monotonic() - start
            self.assertEqual({x["returncode"] for x in rows}, {0})
            self.assertLess(elapsed, 2.25)

            # Cancellation must stop the optional Go helper and its child rather
            # than leaving an orphaned long-running process.
            result = {}
            def _long_job():
                result["value"] = runner.run(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    timeout=40, log_name="cancel-go", capture_mode="tail")
            worker = threading.Thread(target=_long_job)
            worker.start()
            time.sleep(0.35)
            cancel_start = time.monotonic()
            runner.cancel()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result["value"][0], 130)
            self.assertLess(time.monotonic() - cancel_start, 4.0)
            runner.reset_cancel()

            # Common secret flags are redacted even if a caller forgets to pass
            # an explicit log_redactions list.
            secret = "TBHM-SHOULD-NOT-BE-IN-HEADER"
            rc, _, err = runner.run(
                [sys.executable, "-c", "pass", "--token", secret],
                timeout=5, log_name="redaction", capture_mode="tail")
            self.assertEqual(rc, 0, err)
            log_text = (Path(td) / "logs" / "redaction.log").read_text(errors="replace")
            self.assertNotIn(secret, log_text)
            self.assertIn("[REDACTED]", log_text)

    def test_request_url_userinfo_and_fragment_are_redacted(self):
        from core.request_model import normalize_request
        row = normalize_request({
            "method": "GET",
            "url": "https://alice:super-secret@api.example.test:8443/path?view=full#access_token=fragment-secret",
        })
        encoded = json.dumps(row)
        self.assertNotIn("super-secret", encoded)
        self.assertNotIn("fragment-secret", encoded)
        self.assertIn("[REDACTED]@api.example.test:8443", row["url"])
        self.assertIn("[REDACTED_FRAGMENT]", row["url"])

    def test_disproved_assertion_is_a_lead_not_supported(self):
        from core.assertion_engine import evaluate, confirmation_fields
        from core.finding_class import classify
        from test_support import captured_access_proof
        with tempfile.TemporaryDirectory() as td:
            assertion, proof = captured_access_proof(td)
            assertion["failure_conditions"][1]["value"] = 403
            result = evaluate(assertion, proof, evidence_root=td)
            self.assertEqual(result["result"], "fail")
            fields = confirmation_fields(result, method="v2 capture verifier")
            self.assertEqual(fields["verification_state"], "disproved")
            self.assertEqual(classify({"severity": "HIGH", "phase": "audit", "evidence": "old signal", **fields}), "lead")

    def test_campaign_templates_bind_proof_and_redact_imported_secrets(self):
        from core.campaign_model import load, validate_campaign, normalize_operation, result_is_complete, sanitize_result_record
        root = Path(__file__).resolve().parent
        campaign = load(root / "templates" / "redteam_campaign.example.yaml")
        self.assertEqual(validate_campaign(campaign), [])
        operation = normalize_operation(next(x for x in campaign["operations"] if x["operation_id"] == "op-exploit-validation-01"))
        result = json.loads((root / "templates" / "redteam_operation_result.example.json").read_text())
        ok, missing = result_is_complete(result, operation)
        self.assertTrue(ok, missing)
        wrong_target = {**result, "target": "different-target"}
        ok, missing = result_is_complete(wrong_target, operation)
        self.assertFalse(ok)
        self.assertIn("matching operation target", missing)
        source_hash_only = dict(result)
        source_hash_only.pop("evidence_sha256")
        source_hash_only["source_sha256"] = "d" * 64
        ok, missing = result_is_complete(source_hash_only, operation)
        self.assertFalse(ok)
        self.assertIn("valid evidence SHA-256", missing)
        sanitized = sanitize_result_record({
            "token": "secret-token", "payload": "opaque-bytes",
            "note": "Authorization: Bearer abc.def.ghi password=hello",
            "authorization_reference": "ROE-1",
        })
        encoded = json.dumps(sanitized)
        for secret in ("secret-token", "opaque-bytes", "abc.def.ghi", "password=hello"):
            self.assertNotIn(secret, encoded)
        self.assertEqual(sanitized["authorization_reference"], "ROE-1")


    def test_reverse_metadata_cache_and_bounded_embedding_workers(self):
        import numpy as np
        from unittest.mock import patch
        from core import reverse_utils
        from core.ai_plane.embeddings import Embedder

        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "sample.bin"
            artifact.write_bytes(b"\x7fELF" + b"A" * 4096 + b" system ")
            reverse_utils.clear_artifact_cache()
            first = reverse_utils.hashes(artifact)
            before = reverse_utils._hashes_cached.cache_info()
            second = reverse_utils.hashes(artifact)
            after = reverse_utils._hashes_cached.cache_info()
            self.assertEqual(first, second)
            self.assertEqual(after.hits, before.hits + 1)
            with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read forbidden")):
                self.assertEqual(reverse_utils.magic_type(artifact), "ELF")
                names = {row["name"] for row in reverse_utils.raw_short_imports(artifact)}
                self.assertIn("system", names)

        embedder = Embedder(max_workers=3)
        active = 0
        maximum = 0
        lock = threading.Lock()

        def probe(text):
            return np.asarray([1.0, 0.0], dtype=np.float32)

        def worker(text):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.08)
            with lock:
                active -= 1
            return np.asarray([1.0, float(len(text))], dtype=np.float32)

        embedder._remote = probe
        embedder._remote_worker = worker
        started = time.monotonic()
        matrix, mode = embedder.embed_many(["a", "bb", "ccc", "dddd", "eeeee"])
        elapsed = time.monotonic() - started
        self.assertEqual(mode, "ollama")
        self.assertEqual(matrix.shape, (5, 2))
        self.assertGreater(maximum, 1)
        self.assertLessEqual(maximum, 3)
        self.assertLess(elapsed, 0.25)

    def test_bug_bounty_workspace_and_campaign_phase_integration(self):
        from core.storage import Storage
        from core.program_policy import load as load_policy
        from core.request_model import import_har
        from core.finding_class import apply as classify_apply
        from phases import bug_bounty_workspace, redteam_campaign_control
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            store = Storage(base / "tbhm.db")
            store.save_run({"started_at": "2026-07-26T00:00:00Z", "profile": "test", "targets": ["api.example.test"]})

            policy_path = base / "policy.yaml"
            policy_path.write_text((root / "templates" / "program_policy.example.yaml").read_text())
            identity_path = base / "identities.yaml"
            identity_path.write_text((root / "templates" / "identity_plan.example.yaml").read_text())
            har_path = base / "session.har"
            har = {"log": {"entries": [{"request": {
                "method": "POST", "url": "https://api.example.test/v1/objects/A?token=har-secret",
                "headers": [
                    {"name": "Authorization", "value": "Bearer har-secret"},
                    {"name": "Content-Type", "value": "application/json"},
                ],
                "postData": {"text": json.dumps({"object_id": "A", "password": "har-secret"})},
            }}]}}
            har_path.write_text(json.dumps(har))
            request_id = import_har(har_path)[0]["request_id"]
            workflow_path = base / "workflow.yaml"
            workflow_path.write_text("\n".join([
                "workflows:",
                "  - workflow_id: authz",
                "    name: Authorization",
                "    invariant: Account A cannot read Account B object.",
                "    tests:",
                "      - test_id: authz-v1",
                "        identity_id: account-a-member",
                f"        request_id: {request_id}",
                "        action: workflow_test",
                "        failure_conditions:",
                "          - type: object_identity_equals",
                "            source: mutation",
                "            value: object-b",
                "        negative_control_conditions:",
                "          - type: status_equals",
                "            source: negative_control",
                "            value: 404",
            ]) + "\n")
            logs = []
            ctx = types.SimpleNamespace(
                output=base / "out", storage=store, phase_state={}, logs=logs,
                program_policy=load_policy(policy_path),
                profile={"name": "authorized_safe"},
                args=types.SimpleNamespace(
                    program_policy=str(policy_path), identity_plan=str(identity_path),
                    workflow_plan=str(workflow_path), session_har=str(har_path),
                    workspace_max_requests=100, campaign_plan=None,
                    campaign_results=None, redteam_campaign=False,
                    approval_manifest=None,
                ),
            )
            ctx.output.mkdir()
            ctx.log = lambda level, phase, message: logs.append((level, phase, message))
            def _save_finding(finding):
                finding = dict(finding)
                finding.setdefault("phase", "test")
                finding.setdefault("severity", "INFO")
                finding.setdefault("confidence", "MEDIUM")
                finding.setdefault("discovered_at", "2026-07-26T00:00:00Z")
                return store.save_finding(classify_apply(finding))
            ctx.save_finding = _save_finding
            bug_bounty_workspace.run(ctx)
            summary = json.loads((ctx.output / "evidence" / "bug_bounty_workspace" / "workspace_summary.json").read_text())
            self.assertEqual(summary["ready"], 1)
            workspace_text = "".join(
                p.read_text(errors="replace")
                for p in (ctx.output / "evidence" / "bug_bounty_workspace").iterdir()
                if p.is_file()
            )
            self.assertNotIn("har-secret", workspace_text)

            approval_path = base / "approval.json"
            approval_path.write_text(json.dumps({
                "engagement_id": "ENG-1", "approved_by": "reviewer",
                "expires_at": "2099-01-01T00:00:00Z",
                "authorized_actions": ["operation:exploit_validation"],
                "targets": ["approved-isolated-clone"],
            }))
            result = json.loads((root / "templates" / "redteam_operation_result.example.json").read_text())
            result["token"] = "must-not-persist"
            result_path = base / "operation-result.json"
            result_path.write_text(json.dumps(result))
            ctx.args.campaign_plan = str(root / "templates" / "redteam_campaign.example.yaml")
            ctx.args.campaign_results = str(result_path)
            ctx.args.redteam_campaign = True
            ctx.args.approval_manifest = str(approval_path)
            ctx.profile = {"name": "authorized_redteam"}
            redteam_campaign_control.run(ctx)
            payload = json.loads((ctx.output / "redteam" / "100_campaign_control" / "campaign_control.json").read_text())
            self.assertEqual(payload["confirmed_control_failures"], 0)  # Unsigned v1 import remains a lead.
            self.assertEqual(payload["blocked_results"], 0)
            self.assertNotIn("must-not-persist", json.dumps(payload))
            self.assertEqual(store.conn.execute("SELECT COUNT(*) c FROM detection_outcomes").fetchone()["c"], 1)
            self.assertEqual(store.conn.execute("SELECT COUNT(*) c FROM cleanup_actions").fetchone()["c"], 1)
            finding = store.all_findings()[0]
            self.assertFalse(finding["verified"])
            store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
