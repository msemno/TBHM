"""Release-level owned-account workflow through the real CLI and reports."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from core.evidence_manifest import verify_manifest
from core.storage import Storage
from core.finding_class import classify


class WorkflowTests(unittest.TestCase):
    def test_cli_account_replay_reaches_database_report_and_sealed_delivery(self):
        spec = importlib.util.spec_from_file_location('runtime_fixture', ROOT/'tests/test_api_authz_v422.py')
        fixture_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture_module)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = fixture_module.AuthorizationFixture(root)
            try:
                fixture.path.write_text(json.dumps(fixture.plan))
                policy = root/'policy.json'; policy.write_text(json.dumps(fixture.ctx.program_policy))
                output = root/'cli-run'
                env = os.environ.copy()
                env.update(TBHM_TEST_OWNER='Bearer owner-fixture-449283',
                           TBHM_TEST_CHALLENGER='Bearer challenger-fixture-77523')
                command = [sys.executable, str(ROOT/'tbhm.py'), '-u', fixture.url,
                    '--api-authz-plan', str(fixture.path), '--program-policy', str(policy),
                    '--approve-api-authz', '--no-ai-observe', '--no-bootstrap', '-y', '--silent', '-o', str(output)]
                result = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True, timeout=35)
                self.assertEqual(result.returncode, 0, result.stdout[-3500:]+result.stderr[-2000:])
                with_store = Storage(output/'tbhm.db')
                try:
                    findings = with_store.all_findings()
                    confirmed = [finding for finding in findings if classify(finding) == 'confirmed']
                    self.assertEqual(len(confirmed), 1)
                    self.assertEqual(confirmed[0]['phase'], 'authenticated_session_model')
                finally: with_store.close()
                self.assertEqual(len(fixture.server.seen), 6)
                self.assertTrue((output/'REPORT_final.html').is_file())
                self.assertTrue((output/'OPERATOR.html').is_file())
                coverage = json.loads((output/'compliance'/'test_id_coverage.json').read_text())
                self.assertGreaterEqual(coverage['counts']['executed'], 3)
                self.assertTrue(verify_manifest(output)['passed'])
                ledger = json.loads((output/'execution_ledger.json').read_text())
                self.assertNotIn('recon', ledger['planned_phases'])
                self.assertIn('authenticated_session_model', ledger['planned_phases'])
            finally: fixture.close()


if __name__ == '__main__': unittest.main(verbosity=2)
