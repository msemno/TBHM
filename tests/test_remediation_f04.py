"""F04/S01: calibration, scope, zero budgets and worker rate ceilings."""
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from core.scope import Scope
from phases import api_fuzz


class Session:
    def __init__(self): self.headers = {}; self.calls = []
    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return SimpleNamespace(status_code=404, text='missing', headers={})
    def close(self): pass


def context(root, **args):
    defaults = dict(api_base='https://allowed.invalid', api_rate=10000,
                    api_budget=1, api_methods='GET,HEAD,OPTIONS', allow_writes=False)
    defaults.update(args)
    return SimpleNamespace(output=root, targets=['allowed.invalid'], scope=Scope([], []),
        scope_excludes=[], profile={'active_probes': True,
        'rate_limit': {'global_rps': 0.5, 'per_target_rps': 0.25}},
        args=SimpleNamespace(**defaults), log=lambda *a: None, save_finding=lambda *a: None)


class ApiBoundaryTests(unittest.TestCase):
    def test_denied_and_zero_and_calibration_budget(self):
        for args, count in [({'api_base': 'https://denied.invalid'}, 0),
                            ({'api_budget': 0}, 0), ({'api_rate': 0}, 0), ({}, 1)]:
            with self.subTest(args=args), tempfile.TemporaryDirectory() as td:
                ctx = context(Path(td), **args); session = Session()
                with patch.object(api_fuzz.requests, 'Session', return_value=session), \
                     patch.object(api_fuzz, '_load_wordlist', return_value=['one', 'two']), \
                     patch.object(api_fuzz.AB.RateLimiter, 'wait'):
                    api_fuzz.run(ctx)
                self.assertEqual(len(session.calls), count)
                self.assertTrue(all(not c[2]['allow_redirects'] for c in session.calls))

    def test_shared_fractional_rate_and_budget_across_workers(self):
        from core.http_policy import BudgetedSession
        import core.http_policy as hp
        with tempfile.TemporaryDirectory() as td:
            ctx = context(Path(td)); raw = Session(); now = [0.0]; times = []
            old_request = raw.request
            def send(*a, **kw): times.append(now[0]); return old_request(*a, **kw)
            raw.request = send
            transport = BudgetedSession(ctx, raw, budget=3, max_rps=10000)
            def attempt(_):
                try: transport.request('GET', 'https://allowed.invalid/x')
                except api_fuzz.requests.RequestException: pass
            with patch.object(hp.time, 'monotonic', side_effect=lambda: now[0]), \
                 patch.object(hp.time, 'sleep', side_effect=lambda t: now.__setitem__(0, now[0]+t)):
                with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(attempt, range(20)))
            self.assertEqual(transport.used, 3)
            self.assertEqual(times, [0.0, 4.0, 8.0])

    def test_policy_methods_assets_and_zero_ceiling(self):
        from core.http_policy import BudgetedSession
        with tempfile.TemporaryDirectory() as td:
            ctx = context(Path(td)); raw = Session()
            ctx.program_policy = {'included_assets': ['allowed.invalid'],
                'excluded_assets': [{'pattern': 'allowed.invalid', 'paths': ['/denied*']}],
                'allowed_http_methods': ['GET'], 'max_requests_per_second': 0.25}
            transport = BudgetedSession(ctx, raw, budget=10, max_rps=10000)
            for method, url in [('POST', 'https://allowed.invalid'),
                                ('GET', 'https://allowed.invalid/denied'),
                                ('GET', 'https://sibling.invalid')]:
                with self.assertRaises(api_fuzz.requests.RequestException): transport.request(method, url)
            ctx.program_policy['max_requests_per_second'] = 0
            with self.assertRaises(api_fuzz.requests.RequestException):
                transport.request('GET', 'https://allowed.invalid')
            self.assertEqual(raw.calls, [])
            self.assertEqual(transport.used, 0)


if __name__ == '__main__': unittest.main(verbosity=2)
