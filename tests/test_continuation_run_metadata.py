"""Run argument persistence must not become a credential copy."""
import json
import tempfile
import unittest
from pathlib import Path
from core.storage import Storage


class RunMetadataTests(unittest.TestCase):
    def test_arguments_targets_and_program_urls_are_redacted_without_mutating_input(self):
        run = {'started_at': 'fixture', 'profile': 'authorized_safe',
               'targets': ['https://synthetic-userinfo@example.invalid/?token=synthetic-query'],
               'args': {'jwt': 'synthetic-opaque-jwt', 'threads': 3,
                        'github_token_env': 'TBHM_TEST_TOKEN_ENV'},
               'bug_bounty_program': 'https://example.invalid/?api_key=synthetic-program-key'}
        with tempfile.TemporaryDirectory() as td:
            storage = Storage(Path(td)/'run.db')
            try:
                run_id = storage.save_run(run)
                row = dict(storage.conn.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone())
                encoded = json.dumps(row)
                for secret in ('synthetic-userinfo', 'synthetic-query', 'synthetic-opaque-jwt', 'synthetic-program-key'):
                    self.assertNotIn(secret, encoded)
                self.assertEqual(json.loads(row['args'])['threads'], 3)
                self.assertEqual(json.loads(row['args'])['github_token_env'], 'TBHM_TEST_TOKEN_ENV')
                self.assertEqual(run['args']['jwt'], 'synthetic-opaque-jwt')
            finally:
                storage.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
