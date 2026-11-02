"""Git credential transport is synthetic: no repository network calls occur."""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from phases import code_intel, code_scan


class GitIntakeTests(unittest.TestCase):
    def test_private_clone_uses_environment_askpass_and_cleans_it_up(self):
        secret = 'synthetic-private-clone-token'
        for phase in (code_intel, code_scan):
            with self.subTest(phase=phase.__name__), tempfile.TemporaryDirectory() as td:
                root=Path(td); helpers=[]; calls=[]
                ctx=SimpleNamespace(args=SimpleNamespace(github_token_env='TBHM_CLONE_FIXTURE'), log=lambda *a: None)
                def clone(argv, **kwargs):
                    calls.append(argv)
                    self.assertNotIn(secret, '\n'.join(argv))
                    env=kwargs['env']; helper=Path(env['GIT_ASKPASS']); helpers.append(helper)
                    self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o700)
                    self.assertNotIn(secret, helper.read_text())
                    proc=subprocess.Popen([str(helper), 'Password'], env=env, stdout=subprocess.PIPE)
                    stdout,_=proc.communicate(timeout=2)
                    self.assertEqual(stdout.decode().strip(), secret)
                    target=Path(argv[-1]); (target/'.git').mkdir(parents=True)
                    (target/'.git/config').write_text('url=' + argv[-2])
                    return SimpleNamespace(returncode=0)
                with patch.dict(os.environ, {'TBHM_CLONE_FIXTURE':secret}), \
                     patch.object(phase.subprocess, 'run', side_effect=clone):
                    result=phase._clone(ctx, ['https://github.com/owned/repo.git'], root/'repos')
                self.assertEqual(len(result),1)
                self.assertEqual(len(calls),1)
                self.assertIn('--', calls[0])
                self.assertTrue(all(not path.exists() for path in helpers))
                self.assertNotIn(secret, (result[0]/'.git/config').read_text())

    def test_credential_urls_options_and_external_helpers_never_reach_git(self):
        bad=['https://synthetic-token@github.com/owned/repo.git',
             'ext::sh -c unsafe', '--upload-pack=/tmp/unsafe', 'file:///tmp/repo',
             'https://github.com/owned/%2e%2e.git']
        for phase in (code_intel, code_scan):
            with self.subTest(phase=phase.__name__), tempfile.TemporaryDirectory() as td:
                ctx=SimpleNamespace(args=SimpleNamespace(github_token_env=None), log=lambda *a: None)
                with patch.object(phase.subprocess, 'run') as run:
                    result=phase._clone(ctx, bad, Path(td)/'repos')
                self.assertEqual(result,[])
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
