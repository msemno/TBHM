"""Real CLI workflows with local inputs and an isolated loopback model fixture."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from core.evidence_manifest import verify_manifest
from scripts.regression_support import regression_environment, fixture_failure_details


class WorkflowTests(unittest.TestCase):
    def command(self, *args, tool_path=None):
        # These fixtures exercise built-in local analysis and a loopback model,
        # not whichever optional analyzers happen to be on the operator's PATH.
        # A separate case below deliberately injects a failing external tool.
        with tempfile.TemporaryDirectory(prefix='tbhm-workflow-tools-') as empty_bin:
            env = regression_environment(Path(empty_bin)/'state')
            env['PATH'] = str(tool_path) if tool_path is not None else empty_bin
            result = subprocess.run([sys.executable, str(ROOT/'tbhm.py'), *map(str, args)], cwd=ROOT,
                                    capture_output=True, text=True, env=env, timeout=55)
            if result.returncode and '-o' in args:
                result.stderr += fixture_failure_details(args[args.index('-o')+1])
            return result

    def fixtures(self, root):
        src = root/'src'; src.mkdir()
        (src/'app.py').write_text('import os\nfrom flask import request\ndef route():\n x=request.args["x"]\n os.system("echo "+x)\n')
        mobile = root/'mobile'; mobile.mkdir()
        (mobile/'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:debuggable="false"><activity android:name=".Main" android:exported="true"/></application></manifest>')
        contract = root/'api.json'; contract.write_text(json.dumps({'openapi': '3.1.0', 'paths': {'/users/{id}': {'get': {'security': [], 'responses': {}}}}}))
        slither = root/'slither.json'; slither.write_text(json.dumps({'success': True, 'results': {'detectors': [{'check': 'reentrancy-eth', 'impact': 'High', 'confidence': 'Medium', 'description': 'Fixture static candidate; no runtime contract execution.'}]}}))
        return src, mobile, contract, slither

    def test_combined_local_inputs_reach_report_operator_view_and_sealed_delivery(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); src, mobile, contract, slither = self.fixtures(root); out = root/'run'
            result = self.command('--offline', '--profile', 'passive_only', '--code-dir', src,
                '--mobile-src', mobile, '--openapi-input', contract, '--web3-results', slither,
                '--no-ai-observe', '--silent', '-o', out)
            self.assertEqual(result.returncode, 0, result.stdout[-2500:]+result.stderr[-2500:])
            for name in ('OPERATOR.html', 'operator_queue.json', 'evidence_graph.json', 'REPORT_final.html',
                         'spec/contract_review.json', 'web3/slither_import.json', 'evidence_manifest.json'):
                self.assertTrue((out/name).is_file(), name)
            self.assertTrue(list((out/'mobile').glob('manifest_*.json')))
            ledger = json.loads((out/'execution_ledger.json').read_text())
            for phase in ('code_scan', 'code_intel', 'mobile_scan', 'spec_scan', 'web3'):
                self.assertIn(phase, ledger['planned_phases'])
            manifest = verify_manifest(out)
            self.assertTrue(manifest['passed'], manifest)
            self.assertIn('OPERATOR.html', (out/'REPORT_final.html').read_text())

    def test_optional_analyzer_failure_remains_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); src, mobile, contract, slither = self.fixtures(root); out = root/'run'
            tools = root/'tools'; tools.mkdir()
            semgrep = tools/'semgrep'
            semgrep.write_text('#!/bin/sh\necho "controlled failing analyzer" >&2\nexit 2\n')
            semgrep.chmod(0o755)
            result = self.command('--offline', '--profile', 'passive_only', '--code-dir', src,
                '--mobile-src', mobile, '--openapi-input', contract, '--web3-results', slither,
                '--no-ai-observe', '--silent', '-o', out, tool_path=tools)
            self.assertEqual(result.returncode, 2)
            ledger = json.loads((out/'execution_ledger.json').read_text())
            self.assertTrue(any(row.get('phase') == 'code_scan' and row.get('status') == 'tool-error'
                                for row in ledger['events']))
            self.assertTrue(any(row.get('kind') == 'run' and row.get('status') == 'incomplete'
                                for row in ledger['events']))
            self.assertTrue(verify_manifest(out)['passed'])

    def test_malformed_contract_keeps_partial_report_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root/'api.json'; source.write_text('{broken'); out = root/'run'
            result = self.command('--offline', '--profile', 'passive_only', '--openapi-input', source, '--silent', '--no-ai-observe', '-o', out)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads((out/'spec'/'contract_review.json').read_text())['status'], 'error')
            self.assertTrue((out/'REPORT_final.html').is_file())
            self.assertTrue(verify_manifest(out)['passed'])

    def test_offline_maintenance_conflicts_fail_before_downloads(self):
        for flag in ('--setup', '--update', '--local-llm-setup'):
            with self.subTest(flag=flag):
                result = self.command('--offline', flag)
                self.assertEqual(result.returncode, 2)
                self.assertIn('offline', result.stderr.lower())

    def test_targetless_evaluation_cli_and_undefined_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); labels = root/'labels.json'; preds = root/'preds.json'
            labels.write_text('[{"id":"secure","vulnerable":false,"category":"CWE-89"}]')
            preds.write_text('[{"id":"secure","detected":false}]')
            result = self.command('--evaluate-labels', labels, '--evaluate-predictions', preds)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data['overall']['TN'], 1); self.assertIsNone(data['overall']['precision'])

    def test_local_model_http_contract_refutation_persists_advice_only(self):
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def send_json(self, value):
                body = json.dumps(value).encode(); self.send_response(200)
                self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_GET(self): self.send_json({'models': [{'name': 'fixture:latest'}]})
            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                system, user = [m['content'] for m in data['messages']]
                calls.append(self.path)
                if 'Review the supplied evidence for counterexamples' in system:
                    finding = json.loads(user)
                    reply = {'finding_id': finding['finding_id'], 'verdict': 'needs_validation', 'evidence_ids': ['E1'],
                             'rationale': 'Static evidence alone is insufficient', 'missing_evidence': 'controlled runtime proof'}
                else:
                    batch = json.loads(user.split('\n', 1)[1])
                    reply = {'items': [{'finding_id': f['finding_id'], 'assessment': 'needs-review', 'cwe': 'CWE-999', 'cvss_score': '10.0'} for f in batch]}
                self.send_json({'message': {'content': json.dumps(reply)}})
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td); src, _, _, _ = self.fixtures(root); out = root/'run'
                # Kernel-offline mode now denies sockets, including local model
                # services. Passive target analysis still permits this explicit
                # loopback model fixture without contacting application targets.
                result = self.command('--profile', 'passive_only', '--code-dir', src, '--llm-refute',
                    '--local-llm-url', f'http://127.0.0.1:{server.server_port}', '--local-llm-model', 'fixture:latest',
                    '--local-llm-max-findings', '2', '--llm-refute-max-findings', '2', '--local-llm-required',
                    '--no-ai-observe', '--silent', '-o', out)
                self.assertEqual(result.returncode, 0, result.stdout[-2500:]+result.stderr[-2500:])
                review = json.loads((out/'redteam'/'31_local_llm_triage'/'refutation_review.json').read_text())
                self.assertTrue(review['results']); self.assertEqual(review['errors'], [])
                queue = json.loads((out/'operator_queue.json').read_text())
                self.assertFalse(any(f['proof_verified'] for f in queue['queue']))
                self.assertTrue(any(f['refutation_verdict'] == 'needs_validation' for f in queue['queue']))
                self.assertGreaterEqual(len(calls), 2)
                self.assertTrue(verify_manifest(out)['passed'])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)


if __name__ == '__main__': unittest.main(verbosity=2)
