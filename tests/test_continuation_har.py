"""Offline HAR URL credentials must not reach any generated matrix artifact."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from phases import authenticated_session_model as har_phase


class HarRedactionTests(unittest.TestCase):
    def test_url_credentials_are_removed_while_route_and_status_survive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); har = root/'member.har'; output = root/'out'; output.mkdir()
            har.write_text(json.dumps({'log': {'entries': [{'request': {
                'method': 'GET', 'url': 'https://synthetic-userinfo@example.invalid/users/12?token=synthetic-query&%74oken=synthetic-encoded-query&view=full#jwt=synthetic-fragment'},
                'response': {'status': 200, 'content': {'size': 12}}}]}}))
            ctx = SimpleNamespace(output=output, args=SimpleNamespace(session_har=str(har), role_matrix=None),
                                  log=lambda *a: None, save_finding=lambda *a: None)
            har_phase.run(ctx)
            text = '\n'.join(p.read_text() for p in output.rglob('*') if p.is_file())
            for secret in ('synthetic-userinfo', 'synthetic-query', 'synthetic-encoded-query', 'synthetic-fragment'):
                self.assertNotIn(secret, text)
            self.assertIn('/users/{id}', text)
            self.assertIn('200', text)
            self.assertIn('view=full', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
