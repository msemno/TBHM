"""Proof-oriented local callback oracle tests, no third-party network access."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.oast import LocalOAST, MAX_EVENTS_PER_CHALLENGE, verify_export


class TestLocalOAST(unittest.TestCase):
    def test_explicit_approval_and_offline_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(PermissionError): LocalOAST(td)
            with self.assertRaises(PermissionError): LocalOAST(td, approved=True, offline=True)

    def test_per_attempt_correlation_negative_and_bound(self):
        with tempfile.TemporaryDirectory() as td:
            with LocalOAST(td, approved=True, max_challenges=4) as server:
                base = server.issue(test_id='fixture-A', role='baseline')
                mutation = server.issue(test_id='fixture-A', role='mutation')
                control = server.issue(test_id='fixture-A', role='negative_control')
                repeat = server.issue(test_id='fixture-A', role='repeat')
                self.assertEqual(len({x['token'] for x in [base, mutation, control, repeat]}), 4)
                self.assertEqual(urlopen(mutation['url'], timeout=2).status, 204)
                self.assertEqual(urlopen(repeat['url'], timeout=2).status, 204)
                with self.assertRaises(HTTPError):
                    urlopen(mutation['url'].replace(mutation['token'], 'unguessed'), timeout=2)
                with self.assertRaises(ValueError): server.issue(test_id='fixture-A', role='repeat')
                before = server.result('fixture-A')
                self.assertEqual(before['callbacks_observed'], 2)
                self.assertEqual({a['role']: a['callback_count'] for a in before['attempts']},
                                 {'baseline': 0, 'mutation': 1, 'negative_control': 0, 'repeat': 1})
                with self.assertRaises(RuntimeError): server.export()
            path = server.export()
            saved = json.loads(path.read_text())
            self.assertEqual(len(saved['record']['events']), 2)
            self.assertNotIn(mutation['token'], path.read_text())
            self.assertEqual(saved['record']['classification'], 'corroborating_observation_not_confirmation')
            self.assertEqual(verify_export(td, path)['callbacks_observed'], 2)
            path.chmod(0o600)
            altered = path.read_text().replace('corroboration_only_not_confirmed', 'not_authentic')
            path.write_text(altered.replace('loopback-http-listener', 'untrusted-actor'))
            with self.assertRaises(ValueError): verify_export(td, path)
            with self.assertRaises(RuntimeError): server.issue(test_id='fixture-A', role='repeat')

    def test_callback_budget_and_method_filter(self):
        with tempfile.TemporaryDirectory() as td:
            with LocalOAST(td, approved=True) as server:
                item = server.issue(test_id='fixture-B', role='mutation')
                for _ in range(MAX_EVENTS_PER_CHALLENGE):
                    self.assertEqual(urlopen(item['url'], timeout=2).status, 204)
                with self.assertRaises(HTTPError): urlopen(item['url'], timeout=2)
                self.assertEqual(server.result('fixture-B')['callbacks_observed'], MAX_EVENTS_PER_CHALLENGE)


if __name__ == '__main__': unittest.main()
