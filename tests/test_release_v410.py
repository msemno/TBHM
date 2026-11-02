"""4.1.0 acceptance cases: proof provenance, sealed delivery and real HTTP guards."""
import copy
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.assertion_engine import evaluate, confirmation_fields
from core.finding_class import classify
from core.proof_contracts import SCHEMA, capture_snapshot
from core.storage import Storage
from core.scope import Scope
from core.execution_ledger import ExecutionLedger
from core.evidence_manifest import build_manifest, verify_manifest
from test_support import captured_access_proof


class ReleaseTests(unittest.TestCase):
    def test_legacy_flags_status_only_and_counters_never_confirm(self):
        f = {'severity': 'HIGH', 'phase': 'verify', 'title': 'Legacy claim', 'evidence': '200 OK',
             'verified': True, 'verification_method': 'claimed', 'finding_class': 'confirmed',
             'verification_state': 'confirmed', 'assertion_passed': True,
             'negative_control_passed': True, 'repeatability_passed': True}
        self.assertNotEqual(classify(f), 'confirmed')
        with tempfile.TemporaryDirectory() as td:
            assertion, proof = captured_access_proof(td)
            assertion['failure_conditions'] = [{'type': 'status_equals', 'value': 200}]
            self.assertEqual(evaluate(assertion, proof, evidence_root=td)['result'], 'inconclusive')
            self.assertFalse(confirmation_fields({'result': 'pass'}, method='forged')['verified'])

    def test_real_capture_contract_survives_database_reopen(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            assertion, proof = captured_access_proof(root)
            store = Storage(root / 'tbhm.db')
            store.save_run({'started_at': 'now', 'profile': 'test', 'targets': ['example.test']})
            fid = store.save_finding({'phase': 'verify', 'title': 'Cross-object proof', 'severity': 'HIGH',
                'confidence': 'HIGH', 'discovered_at': 'now', 'url': 'https://example.test/api/users/2', 'evidence': 'captured'})
            result = evaluate(assertion, proof, evidence_root=root)
            self.assertEqual(result['result'], 'pass', result)
            aid = store.record_validation_attempt(verifier='test-v2', result=result, assertion=assertion, proof=proof, finding_id=fid)
            store.update_finding_verification(fid, confirmation_fields(result, method='test-v2', validation_attempt_id=aid))
            store.close()
            store = Storage(root / 'tbhm.db')
            self.assertEqual(classify(store.all_findings()[0]), 'confirmed')
            ref = proof['captures']['mutation']; path = root / ref['path']; path.chmod(0o600); path.write_text('{}')
            self.assertNotEqual(classify(store.all_findings()[0]), 'confirmed')
            store.close()

    def test_replayed_tampered_unsigned_and_wrong_class_proof_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            assertion, proof = captured_access_proof(td)
            for alteration in ['replay', 'digest', 'signature', 'class', 'counters']:
                a, p = copy.deepcopy(assertion), copy.deepcopy(proof)
                if alteration == 'replay': p['captures']['repeats'][1] = p['captures']['repeats'][0]
                if alteration == 'digest': p['captures']['mutation']['sha256'] = '0' * 64
                if alteration == 'signature': p['captures']['mutation']['signature'] = '0' * 64
                if alteration == 'class': a['vulnerability_class'] = 'arbitrary-imported-claim'
                if alteration == 'counters': p = {'schema': SCHEMA, 'repeatability': {'attempts': 50, 'successful_proofs': 50}}
                with self.subTest(alteration=alteration):
                    self.assertEqual(evaluate(a, p, evidence_root=td)['result'], 'inconclusive')

    def test_raw_json_cannot_restore_confirmation_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            a, p = captured_access_proof(td)
            fields = confirmation_fields(evaluate(a, p, evidence_root=td), method='captured')
            finding = {'severity': 'HIGH', 'phase': 'verify', 'evidence': 'proof', **fields}
            self.assertEqual(classify(finding), 'confirmed')
            self.assertNotEqual(classify(json.loads(json.dumps(finding))), 'confirmed')

    def test_sealed_snapshot_includes_consistent_database_and_survives_later_writes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); store = Storage(root / 'tbhm.db')
            store.conn.execute('PRAGMA journal_mode=WAL')
            store.save_run({'started_at': 'now', 'profile': 'fixture', 'targets': ['example.test']})
            (root / 'tbhm.log').write_text('finished\n')
            first = build_manifest(root)
            snapshot = root / first['snapshot_dir']
            with sqlite3.connect(snapshot / 'tbhm.db') as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0], 1)
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            (root / 'tbhm.log').write_text('later producer wrote again\n')
            store.save_run({'started_at': 'later', 'profile': 'fixture', 'targets': []})
            self.assertTrue(verify_manifest(root)['passed'])
            second = build_manifest(root)
            self.assertNotEqual(first['snapshot_dir'], second['snapshot_dir'])
            self.assertEqual((snapshot / 'tbhm.log').read_text(), 'finished\n')
            self.assertTrue(verify_manifest(root)['passed'])
            store.close()

    def test_snapshot_reports_tampering_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / 'proof.txt').write_text('captured')
            manifest = build_manifest(root); target = root / manifest['files'][0]['path']
            target.chmod(0o600); target.write_text('tampered')
            self.assertFalse(verify_manifest(root)['passed'])
            (root / 'external-link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): build_manifest(root)

    def test_observation_validation_enrichment_and_notes_are_redacted(self):
        with tempfile.TemporaryDirectory() as td:
            store = Storage(Path(td) / 'tbhm.db')
            secret = 'opaque-release-fixture-credential'
            store.save_observation(phase='test', observation_type='request', evidence={'authorization': secret, 'nested': {'password': secret}})
            store.record_validation_attempt(verifier='test', result={'result': 'inconclusive', 'reasons': ['password=' + secret]},
                proof={'token': secret, 'request': {'Cookie': secret}})
            store.record_decision('fingerprint', 'unsure', note='api_key=' + secret)
            text = '\n'.join(store.conn.iterdump())
            self.assertNotIn(secret, text)
            self.assertIn('REDACTED', text)
            store.close()

    def test_native_http_guard_applies_before_transport_and_caps_responses(self):
        import requests
        from core.request_guard import activate, deactivate
        from core.http_policy import RequestBlocked
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(self.path)
                self.send_response(302 if self.path == '/redirect' else 200)
                if self.path == '/redirect': self.send_header('Location', 'http://outside.invalid/')
                self.end_headers(); self.wfile.write(b'x' * (64 if self.path == '/large' else 2))
            def do_POST(self):
                calls.append('POST'); self.send_response(200); self.end_headers()
            def log_message(self, *_): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        with tempfile.TemporaryDirectory() as td:
            base = f'http://127.0.0.1:{server.server_port}'
            ctx = SimpleNamespace(targets=[base], scope=Scope([], []), scope_excludes=[],
                profile={'name': 'test', 'active_probes': True, 'rate_limit': {'global_rps': 50, 'per_target_rps': 20},
                         'http_policy': {'request_budget': 6, 'max_response_bytes': 32}}, program_policy=None,
                args=SimpleNamespace(offline=False, proxy=None, allow_writes=False, local_llm=False, no_ai_observe=True),
                execution_ledger=ExecutionLedger(td))
            try:
                activate(ctx)
                self.assertEqual(requests.get(base + '/small').content, b'xx')
                self.assertEqual(requests.get(base + '/redirect').status_code, 302)
                with self.assertRaises(RequestBlocked): requests.get('http://outside.invalid/')
                with self.assertRaises(RequestBlocked): requests.post(base + '/write')
                with self.assertRaises(RequestBlocked): requests.get(base + '/large')
                ctx.args.offline = True
                with self.assertRaises(RequestBlocked): requests.get(base + '/offline')
                self.assertEqual(calls, ['/small', '/redirect', '/large'])
            finally:
                deactivate(); server.shutdown(); server.server_close(); thread.join()

    def test_provider_credentials_are_never_in_live_argv(self):
        from phases.recon import _chaos, _github_subdomains
        commands = []
        class Runner:
            def has(self, _): return True
            def run_lines(self, argv, **kwargs): commands.append((argv, kwargs)); return []
        ctx = SimpleNamespace(runner=Runner(), log=lambda *args: None)
        with patch.dict('os.environ', {'CHAOS_KEY': 'opaque-chaos-key', 'GITHUB_TOKEN': 'opaque-github-token'}):
            _chaos(ctx, 'example.test'); _github_subdomains(ctx, 'example.test')
        self.assertNotIn('opaque-chaos-key', str(commands[0][0]))
        self.assertNotIn('opaque-github-token', str(commands[1][0]))
        self.assertEqual(commands[0][1]['env']['PDCP_API_KEY'], 'opaque-chaos-key')
        self.assertEqual(commands[1][1]['env']['GITHUB_TOKEN'], 'opaque-github-token')

    def test_resume_detects_changed_source_even_with_preserved_mtime(self):
        from core.execution_ledger import input_fingerprint
        import os
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'app.py'; source.write_text('first')
            stamp = source.stat()
            args = SimpleNamespace(code_dir=td, resume=False, output='/results')
            first = input_fingerprint(args, {'name': 'test'}, [])
            args.resume = True
            self.assertEqual(first, input_fingerprint(args, {'name': 'test'}, []))
            source.write_text('other'); os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            self.assertNotEqual(first, input_fingerprint(args, {'name': 'test'}, []))

    def test_recovered_sources_are_analyzed_raw_and_exported_redacted(self):
        from core.sourcemaps import reconstruct_dir
        from core.code_patterns import find_secrets
        secret = 'npm_' + 'aB6cD7eF8gH9jK0mN1pQ2rS3tU4vW5xY6zA7'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); inputs = root / 'inputs'; inputs.mkdir()
            (inputs / 'bundle.js.map').write_text(json.dumps({'sources': ['src/app.js'], 'sourcesContent': ['const token = "' + secret + '";']}))
            raw = root / 'private'; public = root / 'public'
            self.assertEqual(reconstruct_dir(inputs, raw, redact=False), 1)
            self.assertTrue(find_secrets((raw / 'src/app.js').read_text()))
            self.assertEqual(reconstruct_dir(inputs, public), 1)
            self.assertNotIn(secret, (public / 'src/app.js').read_text())

    def test_native_redirect_verifier_creates_a_linked_confirmed_finding(self):
        from phases import injections
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); store = Storage(root / 'tbhm.db')
            store.save_run({'started_at': 'now', 'profile': 'test', 'targets': ['example.test']})
            def save(finding):
                finding['discovered_at'] = 'now'
                return store.save_finding(finding)
            ctx = SimpleNamespace(output=root, storage=store, targets=['example.test'],
                                  log=lambda *args: None, save_finding=save)
            def response(url, **kwargs):
                redirect = 'evil.example.com' in url
                return SimpleNamespace(status_code=302, text='',
                    request=SimpleNamespace(url=url, headers={}),
                    headers={'Location': 'https://evil.example.com/' if redirect else '/'})
            with patch.object(injections.requests, 'get', side_effect=response):
                injections._open_redirect(ctx, ['https://example.test/go?next=/home'])
            findings = store.all_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(classify(findings[0]), 'confirmed', findings[0])
            self.assertEqual(len(store.all_test_executions()), 1)
            store.close()

    def test_other_confirmation_contracts_accept_captured_positive_pairs(self):
        for kind in ('sensitive_data_exposure', 'open_redirect'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as td:
                url = 'https://example.test/resource'
                marker = 'CONTROLLED_PRIVATE_CANARY'
                def capture(role):
                    private = kind == 'sensitive_data_exposure'
                    request = {'url': url, 'method': 'GET', 'headers': {}, 'body': ''}
                    if private and role == 'baseline': request['headers'] = {'Authorization': 'Bearer owner-control'}
                    if role == 'negative_control': request['url'] += '/missing'
                    mutation = role in {'mutation', 'repeat'}
                    response = {'status': 404 if role == 'negative_control' else 200,
                                'headers': {}, 'body': marker if private and role != 'negative_control' else ''}
                    if not private and mutation:
                        response.update(status=302, headers={'Location': 'https://canary.invalid/'})
                    return capture_snapshot(td, test_id='class-pair', vulnerability_class=kind,
                        role=role, actor_id='owner' if private and role == 'baseline' else 'anonymous',
                        request=request, response=response)
                assertion = {'schema': SCHEMA, 'test_id': 'class-pair', 'vulnerability_class': kind,
                    'private_marker': marker, 'redirect_host': 'canary.invalid',
                    'failure_conditions': [{'type': 'body_contains', 'value': marker}] if kind == 'sensitive_data_exposure'
                        else [{'type': 'header_equals', 'name': 'Location', 'value': 'https://canary.invalid/'}],
                    'negative_control_conditions': [{'type': 'status_equals', 'source': 'negative_control', 'value': 404}]}
                proof = {'schema': SCHEMA, 'captures': {role: capture(role) for role in ('baseline', 'mutation', 'negative_control')}}
                proof['captures']['repeats'] = [capture('repeat'), capture('repeat')]
                result = evaluate(assertion, proof, evidence_root=td)
                self.assertEqual(result['result'], 'pass', result)
                assertion['vulnerability_class'] = 'open_redirect' if kind != 'open_redirect' else 'sensitive_data_exposure'
                self.assertEqual(evaluate(assertion, proof, evidence_root=td)['result'], 'inconclusive')


if __name__ == '__main__':
    unittest.main(verbosity=2)
