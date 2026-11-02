"""Actual child-process backpressure under the Runner's own deadline."""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from core.runner import Runner


class RunnerDuplexTests(unittest.TestCase):
    def make_runner(self, root, backend='python', helper=None):
        runtime = {'executor_backend': backend, 'capture_tail_bytes': 65536}
        if helper: runtime['go_executor_path'] = str(helper)
        return Runner({'runtime': runtime}, None,
                      SimpleNamespace(wait_if_pressured=lambda **kw: None), root)

    def test_writes_before_reading_still_times_out_in_both_backends(self):
        code = "import os,time;os.write(1,b'x'*1048576);os.write(2,b'y'*1048576);time.sleep(60)"
        for backend in ('python', 'go'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as td:
                runner = self.make_runner(Path(td), backend)
                start = time.monotonic()
                rc, out, err = runner.run([sys.executable, '-c', code], input_data='z'*1048576,
                                          timeout=1, capture_mode='tail', log_name='duplex')
                self.assertEqual(rc, 124, err)
                self.assertLess(time.monotonic()-start, 3)
                self.assertIn('timeout', err.lower())

    def test_successful_bidirectional_transfer_loses_no_bytes(self):
        code = "import os,sys;os.write(1,b'x'*262144);os.write(2,b'y'*262144);d=sys.stdin.buffer.read();print('INPUT_BYTES='+str(len(d)))"
        for backend in ('python', 'go'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as td:
                runner = self.make_runner(Path(td), backend)
                rc, out, err = runner.run([sys.executable, '-c', code], input_data='z'*1048576,
                                          timeout=5, capture_mode='tail', log_name='duplex-ok')
                self.assertEqual(rc, 0, err)
                self.assertIn('INPUT_BYTES=1048576', out)

    def test_nonreading_helper_cannot_block_parent_job_input(self):
        if os.name != 'posix': self.skipTest('POSIX executable helper fixture')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); helper = root/'nonreader'
            helper.write_text('#!' + sys.executable + '\nimport sys,time\n'
                'if "--evidence-protocol" in sys.argv:\n print("2");sys.exit(0)\n'
                'time.sleep(60)\n')
            helper.chmod(0o700)
            runner = self.make_runner(root, 'go', helper)
            start = time.monotonic()
            rc, _, err = runner.run(['fixture'], input_data='z'*1048576, timeout=1,
                                    capture_mode='tail', log_name='helper')
            self.assertEqual(rc, 124, err)
            self.assertLess(time.monotonic()-start, 3)

    def test_cancel_during_blocked_input_stops_feeder_and_process(self):
        with tempfile.TemporaryDirectory() as td:
            runner = self.make_runner(Path(td))
            result = []
            thread = threading.Thread(target=lambda: result.append(runner.run(
                [sys.executable, '-c', "import time;time.sleep(60)"], input_data='z'*1048576,
                timeout=40, capture_mode='tail', log_name='cancel')))
            thread.start(); time.sleep(0.2); runner.cancel(); thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result[0][0], 130)


if __name__ == '__main__':
    unittest.main(verbosity=2)
