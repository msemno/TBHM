import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.brokered_http import Broker, SharedLedger, pipe_replay, run


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        body = b'x'*100 if self.path == '/long' else b'ok'
        self.send_response(429 if self.path == '/rate' else 200)
        if self.path == '/rate': self.send_header('Retry-After', '60')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *_): pass


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler); self.server.hits = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.url = 'http://127.0.0.1:'+str(self.server.server_port)
        self.ctx = self.context()
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2); self.temp.cleanup()
    def context(self):
        return SimpleNamespace(output=self.root, targets=[self.url],
            args=SimpleNamespace(offline=False, proxy=None, approve_brokered_http=True),
            profile={'name':'test','active_probes':True,'rate_limit':{'global_rps':100,'per_target_rps':100}},
            program_policy={'policy_id':'loopback','included_assets':[{'host':'127.0.0.1','ports':[self.server.server_port]}],
                'excluded_assets':[], 'allowed_actions':['brokered_http_read'], 'allowed_http_methods':['GET'], 'max_requests_per_second':100},
            storage=SimpleNamespace(save_observation=lambda **_:None), log=lambda *_:None)
    def ledger(self, requests=10, body=1024):
        ledger = SharedLedger(self.root/'ledger.sqlite3', requests, body); self.addCleanup(ledger.close); return ledger
    def broker(self, ledger, cap=8, ctx=None):
        broker = Broker(ctx or self.ctx, ledger, max_body_bytes=cap); self.addCleanup(broker.close); return broker
    def job(self, identity, path='/ok'): return {'id':identity,'url':self.url+path}

    def test_native_and_actual_isolated_child_share_counter_and_budget(self):
        ledger = self.ledger(requests=2); broker = self.broker(ledger)
        self.assertEqual(broker.request(self.job('native'), 'native')['status'], 'observed')
        results, worker = pipe_replay(broker, [self.job('child1'), self.job('child2')], deadline_seconds=8)
        self.assertEqual([r['status'] for r in results], ['observed','blocked'])
        self.assertEqual(worker['isolation_check'], 'network_socket_denied')
        report = ledger.report()
        self.assertEqual(report['quota']['request_slots_used'], 2)
        self.assertEqual(report['quota']['accepted_body_bytes'], 4)
        self.assertEqual(report['quota']['reserved_body_bytes'], 0)
        self.assertEqual(report['quota']['denied'], 1)
        self.assertEqual(len(self.server.hits), 2)
        self.assertFalse(report['hard_wire_egress_guarantee'])

    def test_denied_origin_and_method_never_contact_target(self):
        ledger = self.ledger(); broker = self.broker(ledger)
        for job in ({'id':'outside','url':'http://127.0.0.2:1/outside'},
                    {'id':'port','url':'http://127.0.0.1:1/other-port'},
                    {**self.job('write'), 'method':'POST'}):
            self.assertEqual(broker.request(job,'native')['status'], 'blocked')
        self.assertEqual(self.server.hits, [])
        self.assertEqual(ledger.report()['quota']['denied'], 3)

    def test_response_reservation_aborts_before_second_dispatch(self):
        ledger = self.ledger(body=8); broker = self.broker(ledger, cap=8)
        self.assertEqual(broker.request(self.job('one'),'native')['status'], 'observed')
        self.assertEqual(broker.request(self.job('two'),'native')['status'], 'blocked')
        self.assertEqual(self.server.hits, ['/ok'])

    def test_cooldown_is_shared_across_new_contexts(self):
        ledger = self.ledger(); first = self.broker(ledger)
        self.assertEqual(first.request(self.job('rate','/rate'),'native')['status'], 'observed')
        second = self.broker(ledger, ctx=self.context())
        self.assertEqual(second.request(self.job('next'),'native')['status'], 'blocked')
        self.assertEqual(self.server.hits, ['/rate'])

    def test_large_body_is_incomplete_and_not_proof(self):
        ledger = self.ledger(); broker = self.broker(ledger)
        result = broker.request(self.job('large','/long'),'native')
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(ledger.report()['quota']['reserved_body_bytes'], 0)

    def test_unsupported_driver_and_offline_never_spawn(self):
        plan = self.root/'plan.json'; plan.write_text(json.dumps({'schema':'tbhm.brokered-http/1',
            'requests':[{**self.job('browser'), 'driver':'browser'}]}))
        self.ctx.args.brokered_http_plan = str(plan)
        with patch('core.brokered_http.subprocess.Popen', side_effect=AssertionError('must not spawn')):
            with self.assertRaises(ValueError): run(self.ctx)
            self.ctx.args.offline = True
            with self.assertRaises(PermissionError): run(self.ctx)
        self.assertEqual(self.server.hits, [])

    def test_cross_process_reservations_are_atomic(self):
        path = self.root/'shared.sqlite3'
        seed = SharedLedger(path, 3, 100); seed.close()
        code = ('import sys;from core.brokered_http import SharedLedger;'
                'from core.http_policy import RequestBlocked;'
                'l=SharedLedger(sys.argv[1],3,100);\n'
                'for i in range(5):\n'
                ' try:l.reserve("child","http://127.0.0.1/",1)\n'
                ' except RequestBlocked:pass\n'
                'l.close()')
        children = [subprocess.Popen([sys.executable,'-c',code,str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(3)]
        for child in children:
            _, err = child.communicate(timeout=10); self.assertEqual(child.returncode,0,err)
        ledger = SharedLedger(path,3,100)
        try:
            self.assertEqual(ledger.report()['quota']['request_slots_used'],3)
            self.assertEqual(ledger.report()['quota']['denied'],12)
        finally:ledger.close()


if __name__ == '__main__':unittest.main(verbosity=2)
