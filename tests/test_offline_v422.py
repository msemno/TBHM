"""Kernel-enforced offline boundary tested in disposable child processes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.runner import Runner

ROOT = Path(__file__).resolve().parents[1]
PROBE = '''
import ctypes, errno, json, socket, subprocess, sys, threading
from core.offline_isolation import install
ready=threading.Event(); go=threading.Event(); result={}
def check():
 ready.set(); go.wait()
 try: socket.socket(); result['thread']=False
 except PermissionError: result['thread']=True
t=threading.Thread(target=check); t.start(); ready.wait()
install(); go.set(); t.join()
for name,family,kind in [('tcp',socket.AF_INET,socket.SOCK_STREAM),('udp',socket.AF_INET,socket.SOCK_DGRAM),('v6',socket.AF_INET6,socket.SOCK_STREAM)]:
 try: socket.socket(family,kind); result[name]=False
 except PermissionError: result[name]=True
libc=ctypes.CDLL(None,use_errno=True)
for name,number in [('raw_socket',41),('io_uring',425)]:
 result[name]=libc.syscall(number,2,1,0)==-1 and ctypes.get_errno()==errno.EPERM
r=subprocess.run([sys.executable,'-c','import socket;socket.socket()'],capture_output=True,text=True)
result['exec_child']=r.returncode!=0 and 'PermissionError' in r.stderr
print(json.dumps(result))
'''


class OfflineTests(unittest.TestCase):
    def test_threads_raw_syscalls_and_exec_inherit_filter(self):
        result = subprocess.run([sys.executable, '-c', PROBE], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(json.loads(result.stdout).values()), result.stdout)

    def test_approved_adapter_is_isolated_in_both_executors(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tool = root/'semgrep'
            tool.write_text('#!'+sys.executable+'\nimport socket\ntry:\n socket.socket()\n print("BYPASS")\nexcept PermissionError:\n print("NETWORK_BLOCKED")\n')
            tool.chmod(0o755)
            for backend in ('python', 'go'):
                runner = Runner({'runtime': {'offline': True, 'executor_backend': backend}}, None,
                    SimpleNamespace(wait_if_pressured=lambda **_: None), root)
                rc, out, err = runner.run([str(tool)], capture_mode='tail', timeout=5)
                self.assertEqual(rc, 0, err)
                self.assertIn('NETWORK_BLOCKED', out)
                self.assertNotIn('BYPASS', out)
                if backend == 'go': self.assertTrue(runner._go_evidence_protocol)
            rc, _, _ = runner.run([sys.executable, '-c', 'print("unapproved")'])
            self.assertEqual(rc, 77)

    def test_inherited_socket_and_unsupported_platform_fail_closed(self):
        for code in (
            'import socket; s=socket.socket(); from core.offline_isolation import install; install()',
            'from unittest.mock import patch; from core.offline_isolation import install; '\
            'p=patch("platform.machine",return_value="unvalidated");p.start();install()'):
            result = subprocess.run([sys.executable, '-c', code], cwd=ROOT,
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('RuntimeError', result.stderr)


if __name__ == '__main__': unittest.main(verbosity=2)
