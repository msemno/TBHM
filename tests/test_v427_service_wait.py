"""A real loopback model request lasting beyond the old 15-second ceiling."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace as NS
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import requests
from core import request_guard
from core.execution_ledger import ExecutionLedger


class ModelWaitRegression(unittest.TestCase):
    def test_explicit_inference_budget_allows_slow_valid_response(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                time.sleep(15.3)
                body=b'{"message":{"content":"{\\"ready\\":true}"},"done":true}'
                self.send_response(200);self.send_header('Content-Length',str(len(body)))
                self.end_headers();self.wfile.write(body)
            def log_message(self,*a):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        with tempfile.TemporaryDirectory() as td:
            ctx=NS(args=NS(local_llm=True,local_llm_url=f'http://127.0.0.1:{server.server_port}',
                local_llm_timeout=30,no_ai_observe=False,offline=False,proxy=None),
                runner=NS(_cancel_event=threading.Event()),
                profile={'name':'authorized_safe','runtime':{'service_timeout_seconds':15}},
                execution_ledger=ExecutionLedger(td))
            started=time.monotonic()
            try:
                request_guard.activate(ctx)
                response=requests.post(ctx.args.local_llm_url+'/api/chat',json={'model':'fixture'},timeout=30)
                elapsed=time.monotonic()-started
                self.assertEqual(response.status_code,200)
                self.assertTrue(response.json()['done'])
                self.assertGreaterEqual(elapsed,15)
                self.assertLess(elapsed,25)
                self.assertEqual(ctx.execution_ledger.rows[-1]['status'],'executed')
                if os.environ.get('TBHM_VALIDATION_OUTPUT'):
                    root=Path(os.environ['TBHM_VALIDATION_OUTPUT']);root.mkdir(parents=True,exist_ok=True)
                    (root/'slow-model-service.json').write_text(json.dumps({'seconds':round(elapsed,3),
                        'http':response.status_code,'explicit_timeout':30,'old_profile_ceiling':15,
                        'real_model_quality_evaluated':False},indent=2))
            finally:
                request_guard.deactivate();server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=='__main__':unittest.main()
