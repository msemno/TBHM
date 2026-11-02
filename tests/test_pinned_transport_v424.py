import gzip
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]));sys.path.insert(0,str(Path(__file__).resolve().parent))
from fixtures_v424 import Fixture
from core.brokered_http import Broker,SharedLedger,pipe_replay
from core.http_policy import RequestBlocked
from core.pinned_transport import DestinationPins,serial_dispatch

class PinnedTransport(unittest.TestCase):
    def fixture(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);f=Fixture(t.name);self.addCleanup(f.close);return f
    def broker(self,f,pins=None,cap=1024):
        ledger=SharedLedger(f.root/('ledger-'+str(len(list(f.root.glob('ledger*'))))+'.sqlite3'),20,10000)
        self.addCleanup(ledger.close);broker=Broker(f.ctx,ledger,max_body_bytes=cap,destination_pins=pins or {f.url:['127.0.0.1']})
        self.addCleanup(broker.close);return broker
    def test_pinned_native_and_real_socket_isolated_pipe_driver(self):
        f=self.fixture();b=self.broker(f)
        job={'id':'native','url':f.url+'/download?file=public.txt'}
        self.assertEqual(b.request(job,'native')['status'],'observed')
        rows,worker=pipe_replay(b,[dict(job,id='pipe')],deadline_seconds=8)
        self.assertEqual(rows[0]['status'],'observed');self.assertEqual(worker['isolation_check'],'network_socket_denied')
        self.assertEqual(b.ledger.report()['quota']['request_slots_used'],2)
    def test_dns_rebinding_and_mixed_answers_fail_before_contact(self):
        f=self.fixture();url=f.url.replace('127.0.0.1','pin.test');f.ctx.targets=[url]
        f.ctx.program_policy['included_assets']=[{'host':'pin.test','ports':[f.server.server_port]}]
        b=self.broker(f,{url:['127.0.0.1']});answer=lambda ip:[(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,'',(ip,f.server.server_port))]
        for answers in ([answer('127.0.0.1'),answer('127.0.0.2')],[answer('127.0.0.1')+answer('127.0.0.2')]):
            with patch('core.pinned_transport.socket.getaddrinfo',side_effect=answers):self.assertNotEqual(b.request({'id':'dns','url':url+'/admin-audit'},'native')['status'],'observed')
        self.assertEqual(f.hits,[])
    def test_numeric_connect_keeps_host_without_dns_at_socket_connect(self):
        f=self.fixture();url=f.url.replace('127.0.0.1','pin.test');f.ctx.targets=[url];f.ctx.program_policy['included_assets']=['pin.test']
        b=self.broker(f,{url:['127.0.0.1']});answer=[(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,'',('127.0.0.1',f.server.server_port))]
        with patch('core.pinned_transport.socket.getaddrinfo',return_value=answer) as resolver:
            self.assertEqual(b.request({'id':'dns','url':url+'/download?file=public.txt'},'native')['status'],'observed')
            self.assertEqual(resolver.call_count,2)  # preflight + adapter; no connect-time resolution
    def test_cross_origin_redirect_is_not_followed(self):
        f=self.fixture();other=self.fixture();f.redirect=other.url+'/admin-audit';b=self.broker(f)
        result=b.request({'id':'redirect','url':f.url+'/redirect'},'native');self.assertEqual(result['http_status'],302)
        self.assertFalse(result['redirect_followed']);self.assertEqual(other.hits,[])
    def test_compressed_chunked_and_aborted_bodies_do_not_escape_cap(self):
        f=self.fixture();b=self.broker(f,cap=16)
        for path in ('/gzip','/chunked','/partial'):
            self.assertEqual(b.request({'id':path,'url':f.url+path},'native')['status'],'incomplete')
        self.assertEqual(b.ledger.report()['quota']['reserved_body_bytes'],0)
        self.assertLessEqual(b.ledger.report()['quota']['accepted_body_bytes'],48)
    def test_concurrent_process_lock_blocks_before_http(self):
        f=self.fixture();b=self.broker(f)
        code='from core.pinned_transport import serial_dispatch;from pathlib import Path;import sys;\nwith serial_dispatch(sys.argv[1]):\n Path(sys.argv[2]).write_text("ready")\n sys.stdin.readline()'
        ready=f.root/'ready';p=subprocess.Popen([sys.executable,'-c',code,str(b.ledger.path),str(ready)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            import time
            until=time.monotonic()+5
            while not ready.exists() and time.monotonic()<until:time.sleep(.01)
            self.assertTrue(ready.exists());self.assertEqual(b.request({'id':'concurrent','url':f.url+'/admin-audit'},'native')['status'],'blocked');self.assertEqual(f.hits,[])
        finally:
            out,err=p.communicate('\n',timeout=5);self.assertEqual(p.returncode,0,err)
    def test_offline_unsupported_driver_proxy_and_unreviewed_pins_fail_closed(self):
        f=self.fixture();b=self.broker(f);job={'id':'bad','url':f.url+'/admin-audit'}
        self.assertEqual(b.request(job,'browser')['status'],'blocked')
        f.ctx.args.offline=True;self.assertEqual(b.request(job,'native')['status'],'blocked')
        f.ctx.args.offline=False;f.ctx.args.proxy='http://127.0.0.1:8080'
        with self.assertRaises(RequestBlocked):self.broker(f)
        for value in ('0.0.0.0','169.254.169.254','::ffff:127.0.0.1'):
            with self.assertRaises(ValueError):DestinationPins({f.url:[value]})
        self.assertEqual(f.hits,[])
    def test_tls_certificate_and_hostname_validation_survive_ip_pinning(self):
        f=self.fixture();f.server.shutdown();f.thread.join();ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        data=Path(__file__).parent/'data/v424';ctx.load_cert_chain(data/'loopback-cert.pem',data/'loopback-key.pem')
        f.server.socket=ctx.wrap_socket(f.server.socket,server_side=True)
        import threading
        f.thread=threading.Thread(target=f.server.serve_forever,daemon=True);f.thread.start()
        url=f.url.replace('http:','https:').replace('127.0.0.1','pin.test');f.ctx.targets=[url];f.ctx.program_policy['included_assets']=['pin.test','wrong.test']
        f.ctx.profile['http_policy']={'ca_bundle':str(data/'loopback-cert.pem')}
        answer=[(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,'',('127.0.0.1',f.server.server_port))]
        with patch('core.pinned_transport.socket.getaddrinfo',return_value=answer):
            b=self.broker(f,{url:['127.0.0.1']});self.assertEqual(b.request({'id':'tls','url':url+'/download?file=public.txt'},'native')['status'],'observed')
            wrong=url.replace('pin.test','wrong.test');f.ctx.targets=[wrong];bad=self.broker(f,{wrong:['127.0.0.1']})
            self.assertEqual(bad.request({'id':'wrong','url':wrong+'/admin-audit'},'native')['status'],'incomplete')
    def test_ipv6_numeric_destination(self):
        from http.server import ThreadingHTTPServer
        class V6(ThreadingHTTPServer):address_family=socket.AF_INET6
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        try:f=Fixture(t.name,server_class=V6,address=('::1',0))
        except OSError:self.skipTest('IPv6 loopback unavailable')
        self.addCleanup(f.close);b=self.broker(f,{f.url:['::1']})
        self.assertEqual(b.request({'id':'v6','url':f.url+'/download?file=public.txt'},'native')['status'],'observed')

if __name__=='__main__':unittest.main(verbosity=2)
