"""Reproduce operator environment contamination without using operator services."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.regression_support import regression_environment, unavailable_model_endpoint
from scripts.run_tests import run_owned, select_tests


class RegressionEnvironment(unittest.TestCase):
    def test_private_state_removes_operator_model_keys_and_proxy_without_mutating_parent(self):
        with tempfile.TemporaryDirectory() as td:
            supplied={'PATH':'/bin','HOME':'/operator-home','TBHM_AI_HOME':'/operator-ai',
                      'TBHM_LOCAL_LLM_MODEL':'operator-model','GITHUB_TOKEN':'operator-secret',
                      'HTTPS_PROXY':'http://operator-proxy','PYTHONPATH':'/old/source'}
            original=dict(supplied);env=regression_environment(td,supplied)
            self.assertEqual(supplied,original)
            for key in ('TBHM_LOCAL_LLM_MODEL','GITHUB_TOKEN','HTTPS_PROXY','PYTHONPATH'):
                self.assertNotIn(key,env)
            self.assertEqual(env['TBHM_RESPECT_PATH'],'1')
            self.assertEqual(env['TBHM_AI_HOME'],str(Path(td)/'ai-home'))
            self.assertTrue(Path(env['HOME']).is_dir())

    def test_path_discovery_is_preserved_by_default_and_can_respect_explicit_path(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td);tool=home/'go/bin/fixture-marker';tool.parent.mkdir(parents=True)
            tool.write_text('#!/bin/sh\nexit 0\n');tool.chmod(0o755)
            env=regression_environment(home/'state');env['HOME']=str(home);env['PATH']=''
            code='import tbhm,shutil; print(shutil.which("fixture-marker"))'
            blocked=subprocess.run([sys.executable,'-c',code],cwd=ROOT,env=env,capture_output=True,text=True,timeout=15)
            self.assertEqual(blocked.returncode,0,blocked.stderr);self.assertEqual(blocked.stdout.strip(),'None')
            env.pop('TBHM_RESPECT_PATH')
            normal=subprocess.run([sys.executable,'-c',code],cwd=ROOT,env=env,capture_output=True,text=True,timeout=15)
            self.assertEqual(normal.returncode,0,normal.stderr);self.assertEqual(normal.stdout.strip(),str(tool))

    def test_unavailable_model_uses_an_exclusively_reserved_private_endpoint(self):
        with unavailable_model_endpoint() as endpoint:
            port=int(endpoint.rsplit(':',1)[1])
            with self.assertRaises(OSError):socket.create_connection(('127.0.0.1',port),timeout=.2)
            with socket.socket() as other:
                with self.assertRaises(OSError):other.bind(('127.0.0.1',port))

    def test_contract_probe_is_canonical_but_runtime_honors_the_operator_model(self):
        from scripts.compare_release_contracts import probe
        import tbhm
        with patch.dict(os.environ,{'TBHM_LOCAL_LLM_MODEL':'operator-model'}):
            with patch.object(sys,'argv',['tbhm']):self.assertEqual(tbhm.parse_args().local_llm_model,'operator-model')
            self.assertEqual(probe(ROOT)['actions']['--local-llm-model']['default'],'qwen3-cybersec:4b')

    def test_missing_inputs_return_actionable_error_without_scan_or_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);env=regression_environment(root/'state')
            cases=[['-l',str(root/'missing-targets.txt')],
                   ['-u','https://owned.invalid/','--scope',str(root/'missing-scope.txt')],
                   ['-u','https://owned.invalid/','--exclude',str(root/'missing-excludes.txt')]]
            for args in cases:
                result=subprocess.run([sys.executable,str(ROOT/'tbhm.py'),*args,'--no-bootstrap','--no-ai-observe',
                    '--silent','-o',str(root/'no-run')],cwd=ROOT,env=env,capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,2)
                self.assertIn('Cannot read target/scope input',result.stderr)
                self.assertNotIn('Traceback',result.stderr)
                self.assertFalse((root/'no-run').exists())

    def test_failed_group_selection_never_converts_empty_or_unknown_work_into_pass(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'prior.json';path.write_text(json.dumps([{'test':'a.py','returncode':0},{'test':'b.py','returncode':124}]))
            self.assertEqual(select_tests(['a.py','b.py'],failures=path),['b.py'])
            with self.assertRaises(ValueError):select_tests(['a.py'],failures=path)
            with self.assertRaises(ValueError):select_tests(['a.py'],names=['missing.py'])

    def test_timeout_retains_failure_and_does_not_kill_an_unrelated_process(self):
        unrelated=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])
        try:
            code='import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print(os.getpid(),flush=True); time.sleep(30)'
            rc,out,err=run_owned([sys.executable,'-c',code],cwd=ROOT,env=os.environ.copy(),timeout=.3)
            self.assertEqual(rc,124);self.assertIn('deadline exceeded',err)
            self.assertIsNone(unrelated.poll())
            with self.assertRaises(ProcessLookupError):os.kill(int(out.strip()),0)
        finally:
            unrelated.terminate();unrelated.wait(timeout=3)


if __name__=='__main__':unittest.main(verbosity=2)
