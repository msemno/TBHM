"""F02/F03: recon cannot widen target authority or restore denied seeds."""
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from core.scope import Scope
from phases import recon


class Files:
    def has(self, name): return False
    def read_lines(self, p): return Path(p).read_text().splitlines()
    def write_lines(self, p, lines): Path(p).write_text('\n'.join(sorted(lines)))


class ReconAuthorityTests(unittest.TestCase):
    def test_sibling_and_denied_seed(self):
        for rules, expected in [([], ['api.example.invalid']), (['=allowed.invalid'], [])]:
            with self.subTest(rules=rules), tempfile.TemporaryDirectory() as td:
                root = Path(td); (root/'recon').mkdir()
                ctx = SimpleNamespace(output=root, targets=['api.example.invalid'],
                    scope=Scope(rules, []), scope_excludes=[], runner=Files(),
                    # R03: exercise active scope here; passive runs now deny all
                    # transports before the mocked liveness boundary. Assertions
                    # and the restrictive allowed/denied expectations are retained.
                    profile={'active_probes': True}, phase_state={},
                    log=lambda *a: None, save_finding=lambda *a: None)
                captured = []
                def alive(c, subs, *args):
                    captured.extend(Path(subs).read_text().splitlines()); return []
                with ExitStack() as stack:
                    for name in ['_report_recon_capabilities', '_dns_basics']:
                        stack.enter_context(patch.object(recon, name))
                    for name in ['_crtsh', '_subfinder', '_assetfinder', '_chaos',
                                 '_github_subdomains', '_amass_passive']:
                        stack.enter_context(patch.object(recon, name,
                            return_value={'admin.example.invalid'}))
                    stack.enter_context(patch.object(recon, '_alive_check', side_effect=alive))
                    recon.run(ctx)
                self.assertEqual(captured, expected)
                if not expected:
                    self.assertEqual(ctx.phase_state['alive_hosts'], [])
                    self.assertEqual((root/'recon/alive.txt').read_text(), '')

    def test_direct_liveness_filters_urls_and_file_before_child(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); subs = root/'subs'; subs.write_text('api.example.invalid\nadmin.example.invalid\n')
            runner = Files(); runner.has = lambda name: True
            inputs = []
            def child(cmd, **kwargs):
                inputs.extend(subs.read_text().splitlines())
                self.assertNotIn('-follow-redirects', cmd)
                return 0, '', ''
            runner.run = child
            ctx = SimpleNamespace(targets=['api.example.invalid'], scope=Scope([], []),
                scope_excludes=[], runner=runner, profile={}, log=lambda *a: None)
            alive = recon._alive_check(ctx, subs, root/'alive', root/'tech',
                ['https://admin.example.invalid', 'https://api.example.invalid'])
            self.assertEqual(set(inputs), {'api.example.invalid'})
            self.assertEqual(alive, ['https://api.example.invalid'])

    def test_blocked_redirect_still_marks_authorized_origin_live(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); subs = root/'subs'; subs.write_text('api.example.invalid\n')
            calls = []
            def open_url(req, **kwargs):
                calls.append(req.full_url)
                raise HTTPError(req.full_url, 302, 'redirect', {'Location': 'https://denied.invalid'}, None)
            ctx = SimpleNamespace(targets=['api.example.invalid'], scope=Scope([], []),
                scope_excludes=[], runner=Files())
            with patch.object(recon.urllib.request, 'build_opener',
                              return_value=SimpleNamespace(open=open_url)):
                self.assertEqual(recon._python_alive_fallback(ctx, subs), ['https://api.example.invalid'])
            self.assertEqual(calls, ['https://api.example.invalid'])

    def test_no_child_dispatch_for_an_empty_authorized_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); subs = root/'subs'; subs.write_text('denied.invalid\n')
            runner = Files(); runner.has = lambda name: True
            runner.run = lambda *a, **kw: self.fail('empty authorization must skip child')
            ctx = SimpleNamespace(targets=['allowed.invalid'], scope=Scope([], []),
                scope_excludes=[], runner=runner, profile={}, log=lambda *a: None)
            self.assertEqual(recon._alive_check(ctx, subs, root/'alive', root/'tech', []), [])


if __name__ == '__main__': unittest.main(verbosity=2)
