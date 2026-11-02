import sys,unittest,tempfile,threading,json,os
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,sys.argv.pop(1))
from core.brokered_http import Broker,SharedLedger
from core.evidence_graph import build
from core.evidence_manifest import build_manifest
from core.delivery_privacy_audit import audit
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'x'*100 if self.path=='/rate' else b'ok';self.send_response(429 if self.path=='/rate' else 200);self.send_header('Content-Length',str(len(body)));self.send_header('Retry-After','60');self.end_headers();self.wfile.write(body)
 def log_message(self,*_):pass
class Defects(unittest.TestCase):
 def test_untrusted_graph_flags_cannot_verify_proof(self):
  graph=build([{'id':1,'url':'https://example.test/a','verified':True,'finding_class':'confirmed'}]);self.assertFalse(next(n for n in graph['nodes'] if n['kind']=='finding')['proof_verified'])
 def test_oversized_429_still_persists_shared_cooldown(self):
  with tempfile.TemporaryDirectory() as td:
   server=ThreadingHTTPServer(('127.0.0.1',0),H);th=threading.Thread(target=server.serve_forever,daemon=True);th.start();url='http://127.0.0.1:'+str(server.server_port)
   def context():return SimpleNamespace(args=SimpleNamespace(offline=False,proxy=None),targets=[url],profile={'name':'test','active_probes':True,'rate_limit':{'global_rps':100,'per_target_rps':100}},program_policy={'included_assets':[{'host':'127.0.0.1','ports':[server.server_port]}],'excluded_assets':[],'allowed_actions':['brokered_http_read'],'allowed_http_methods':['GET'],'max_requests_per_second':100})
   ledger=SharedLedger(Path(td)/'ledger.sqlite3',5,1024);a=Broker(context(),ledger,max_body_bytes=8);b=Broker(context(),ledger,max_body_bytes=8)
   try:
    self.assertEqual(a.request({'id':'large','url':url+'/rate'},'native')['status'],'incomplete');self.assertEqual(b.request({'id':'next','url':url+'/ok'},'native')['status'],'blocked')
   finally:a.close();b.close();ledger.close();server.shutdown();server.server_close();th.join()
 def test_canary_in_filename_is_a_delivery_leak(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);marker='fixture-filename-canary-2026';(root/(marker+'.txt')).write_text('harmless');build_manifest(root)
   with patch.dict(os.environ,{'TBHM_AUDIT_MARKER':marker}):self.assertEqual(audit(root,['TBHM_AUDIT_MARKER'])['status'],'fail')
 def test_operator_queue_cannot_trust_imported_flags(self):
     from core.operator_view import write
     with tempfile.TemporaryDirectory() as td:
         finding={'id':1,'url':'https://example.test/a','severity':'HIGH','verified':True,'finding_class':'confirmed'}
         ctx=SimpleNamespace(output=Path(td),storage=SimpleNamespace(all_findings=lambda:[finding]))
         result=write(ctx)
         self.assertFalse(result['queue'][0]['proof_verified'])
         self.assertNotEqual(result['queue'][0]['evidence_state'],'confirmed')
if __name__=='__main__':unittest.main(verbosity=2)
