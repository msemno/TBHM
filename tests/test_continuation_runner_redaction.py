"""Both executors must pass ordinary evidence through the Python redactor."""
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from core.runner import Runner


class RunnerRedactionTests(unittest.TestCase):
    def test_split_scanner_secret_absent_from_tails_logs_and_artifacts(self):
        for backend in ('python', 'go'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                runner = Runner({'runtime': {'executor_backend': backend}}, None,
                                SimpleNamespace(wait_if_pressured=lambda **kw: None), root)
                secret = 'ghp_' + uuid.uuid4().hex
                code = ('import os,sys,time; s=sys.argv[-1].encode(); '
                        'os.write(1,s[:12]);time.sleep(.02);os.write(1,s[12:]+b"\\n");'
                        'os.write(2,b"Authorization: "+s+b"\\n")')
                rc, out, err = runner.run([sys.executable, '-c', code, '--token', secret],
                    capture_mode='tail', timeout=5, log_name='scanner',
                    stdout_path=root/'stdout.txt', stderr_path=root/'stderr.txt')
                self.assertEqual(rc, 0, err)
                if backend == 'go':
                    self.assertTrue(runner._go_evidence_protocol, 'Go evidence bridge must actually execute')
                for content in (out, err, (root/'logs/scanner.log').read_text(),
                                (root/'stdout.txt').read_text(), (root/'stderr.txt').read_text()):
                    self.assertNotIn(secret, content)
                    self.assertIn('REDACTED', content)

    def test_provider_short_flags_and_clean_output_remain_usable(self):
        with tempfile.TemporaryDirectory() as td:
            runner = Runner({}, None, SimpleNamespace(wait_if_pressured=lambda **kw: None), Path(td))
            for tool, flag in (('chaos', '-key'), ('github-subdomains', '-t')):
                self.assertNotIn('opaque-provider-value', ' '.join(runner._safe_command(
                    [tool, flag, 'opaque-provider-value'], [])))
            rc, out, err = runner.run([sys.executable, '-c', 'print("clean")'], timeout=3)
            self.assertEqual((rc, out, err), (0, 'clean\n', ''))


if __name__ == '__main__':
    unittest.main(verbosity=2)
