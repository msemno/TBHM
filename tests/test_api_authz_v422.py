"""Actual local HTTP paired-account tests; no mocked response proof."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import api_authorization
from core.assertion_engine import evaluate
from core.finding_class import classify
from core.storage import Storage


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append((self.path, self.headers.get('Authorization'), self.headers.get('Cookie')))
        owner = self.headers.get('Authorization') == 'Bearer owner-fixture-449283'
        body = {'id': 'obj-7', 'owner': 'owner'}
        status = 200
        if self.path == '/missing':
            status = 404
            body = body if self.server.mode == 'leaking_control' else {'error': 'missing'}
        elif self.server.mode == 'secure' and not owner:
            status, body = 403, {'error': 'denied'}
        elif self.server.mode == 'same_owner':
            body['owner'] = 'challenger'
        elif self.server.mode == 'denied_echo':
            status = 403
        elif self.server.mode == 'redirect':
            status, body = 302, {}
        elif self.server.mode == 'nested':
            body = {'data': body}
        elif self.server.mode == 'numeric_owner':
            body['owner'] = 17
        elif self.server.mode == 'echoed_credential':
            body['echo'] = self.headers.get('Authorization', '').partition(' ')[2]
        elif self.server.mode == 'expired':
            status, body = 401, {'error': 'expired'}
        elif self.server.mode == 'lookalike':
            body = {'id': 'obj-other', 'owner': 'owner'}
        if self.path != '/missing' and not self.headers.get('Authorization') and self.server.mode != 'public':
            status, body = 403, {'error': 'private object'}
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        if owner: self.send_header('Set-Cookie', 'session=owner-cookie-private; HttpOnly')
        if status == 302: self.send_header('Location', '/must-not-be-followed')
        self.end_headers(); self.wfile.write(raw)
    def log_message(self, *_): pass


class AuthorizationFixture:
    def __init__(self, root, mode='vulnerable', budget=100):
        self.root = Path(root)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.mode, self.server.seen = mode, []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:'+str(self.server.server_port)
        self.store = Storage(self.root/'tbhm.db')
        self.store.save_run({'started_at': 'fixture', 'profile': 'fixture', 'targets': [self.url]})
        self.plan = {'schema': 'tbhm.api-authz/1', 'accounts': [
            {'id': 'owner', 'credential_env': 'TBHM_TEST_OWNER', 'owned_test_account': True},
            {'id': 'challenger', 'credential_env': 'TBHM_TEST_CHALLENGER', 'owned_test_account': True}],
            'cases': [{'test_id': 'private-object', 'owner': 'owner', 'challenger': 'challenger',
                       'url': self.url+'/private', 'negative_control_url': self.url+'/missing',
                       'object_id': 'obj-7', 'owned_test_object': True, 'expected_challenger_access': 'deny'}]}
        if mode == 'nested': self.plan['cases'][0].update(object_path='data.id', owner_path='data.owner')
        if mode == 'numeric_owner': self.plan['cases'][0]['owner_value'] = 17
        self.path = self.root/'plan.json'
        policy = {'policy_id': 'local-fixture', 'included_assets': ['127.0.0.1'], 'excluded_assets': [],
                  'allowed_actions': ['api_authorization_read'], 'allowed_http_methods': ['GET'],
                  'max_requests_per_second': 100000}
        def save(finding):
            finding['discovered_at'] = 'fixture'
            return self.store.save_finding(finding)
        self.ctx = SimpleNamespace(output=self.root, storage=self.store, targets=[self.url],
            args=SimpleNamespace(api_authz_plan=str(self.path), approve_api_authz=True, offline=False, proxy=None),
            profile={'name': 'fixture', 'active_probes': True,
                'rate_limit': {'global_rps': 100000, 'per_target_rps': 100000},
                'http_policy': {'request_budget': budget}},
            program_policy=policy, log=lambda *_: None, save_finding=save)
    def run(self):
        self.path.write_text(json.dumps(self.plan))
        with patch.dict(os.environ, {'TBHM_TEST_OWNER': 'Bearer owner-fixture-449283',
                                    'TBHM_TEST_CHALLENGER': 'Bearer challenger-fixture-77523'}):
            return api_authorization.run(self.ctx)
    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        self.store.close()


class AuthzTests(unittest.TestCase):
    def fixture(self, **kwargs):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        fixture = AuthorizationFixture(temp.name, **kwargs); self.addCleanup(fixture.close)
        return fixture

    def test_actual_cross_actor_capture_persists_confirmation(self):
        fixture = self.fixture()
        report = fixture.run()
        self.assertEqual(report['cases'][0]['result'], 'pass', report)
        self.assertEqual(report['requests_used'], 6)
        self.assertEqual(classify(fixture.store.all_findings()[0]), 'confirmed')
        self.assertTrue(all(cookie is None for _, _, cookie in fixture.server.seen))
        self.assertEqual(len(fixture.server.seen), 6)
        # All durable evidence is sanitized, including the database bytes.
        for path in fixture.root.rglob('*'):
            if path.is_file() and path.name != '.proof-capture.key':
                data = path.read_bytes()
                for secret in (b'owner-fixture-449283', b'challenger-fixture-77523', b'owner-cookie-private'):
                    self.assertNotIn(secret, data, str(path))

    def test_benign_and_adversarial_runtime_pairs_do_not_confirm(self):
        for mode in ('secure', 'same_owner', 'denied_echo', 'leaking_control', 'redirect', 'expired', 'lookalike', 'public'):
            with self.subTest(mode=mode):
                fixture = self.fixture(mode=mode)
                report = fixture.run()
                self.assertEqual(report['cases'][0]['result'], 'inconclusive', report)
                self.assertEqual(fixture.store.all_findings(), [])
                self.assertTrue(all(path != '/must-not-be-followed' for path, _, _ in fixture.server.seen))

    def test_nested_object_paths_and_tamper_refusal(self):
        fixture = self.fixture(mode='nested')
        report = fixture.run()
        self.assertEqual(report['cases'][0]['result'], 'pass', report)
        finding = fixture.store.all_findings()[0]
        for attack in ('signature', 'digest', 'duplicate_repeat', 'wrong_class', 'counter_only'):
            assertion, proof = copy.deepcopy(finding['assertion']), copy.deepcopy(finding['proof'])
            if attack in {'signature', 'digest'}:
                proof['captures']['mutation']['signature' if attack == 'signature' else 'sha256'] = '0'*64
            elif attack == 'duplicate_repeat': proof['captures']['repeats'][1] = proof['captures']['repeats'][0]
            elif attack == 'wrong_class': assertion['vulnerability_class'] = 'sqli'
            else: proof = {'schema': 'tbhm.proof/2', 'repeatability': {'successful_proofs': 99}}
            self.assertEqual(evaluate(assertion, proof, evidence_root=fixture.root)['result'], 'inconclusive')

    def test_numeric_owner_identifier_is_bound_to_explicit_plan(self):
        fixture = self.fixture(mode='numeric_owner')
        report = fixture.run()
        self.assertEqual(report['cases'][0]['result'], 'pass', report)
        self.assertEqual(classify(fixture.store.all_findings()[0]), 'confirmed')

    def test_opaque_bearer_echo_is_redacted_from_captures(self):
        fixture = self.fixture(mode='echoed_credential')
        report = fixture.run()
        self.assertEqual(report['cases'][0]['result'], 'pass', report)
        for capture in (fixture.root/'evidence/captures').glob('*.json'):
            data = capture.read_text()
            self.assertNotIn('owner-fixture-449283', data)
            self.assertNotIn('challenger-fixture-77523', data)

    def test_preflight_validates_whole_plan_before_network(self):
        changes = ('approval', 'offline', 'same_identity', 'outside_origin', 'unowned', 'duplicate', 'bad_second')
        for change in changes:
            with self.subTest(change=change):
                fixture = self.fixture()
                case = fixture.plan['cases'][0]
                if change == 'approval': fixture.ctx.args.approve_api_authz = False
                elif change == 'offline': fixture.ctx.args.offline = True
                elif change == 'same_identity': case['challenger'] = 'owner'
                elif change == 'outside_origin': case['negative_control_url'] = 'https://example.test/missing'
                elif change == 'unowned': case['owned_test_object'] = False
                elif change == 'duplicate': fixture.plan['cases'].append(copy.deepcopy(case))
                else: fixture.plan['cases'].append({'test_id': 'invalid'})
                self.assertEqual(fixture.run()['status'], 'blocked')
                self.assertEqual(fixture.server.seen, [])

    def test_shared_request_budget_prevents_proof_completion(self):
        fixture = self.fixture(budget=4)
        report = fixture.run()
        self.assertEqual(report['requests_used'], 4)
        self.assertEqual(len(fixture.server.seen), 4)
        self.assertEqual(report['cases'][0]['status'], 'inconclusive')
        self.assertEqual(fixture.store.all_findings(), [])


if __name__ == '__main__': unittest.main(verbosity=2)
