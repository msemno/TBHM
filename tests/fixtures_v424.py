"""Owned local HTTP fixtures with real filesystem reads and role-gated functions."""
import hashlib
import json
import os
from pathlib import Path
import threading
from types import SimpleNamespace
from urllib.parse import urlsplit,parse_qs,urlencode
import uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
from core.storage import Storage

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        app=self.server.app;app.hits.append((self.path,self.headers.get('Authorization','')))
        u=urlsplit(self.path);status=200
        if u.path=='/download':
            name=parse_qs(u.query).get('file',[''])[0];file=app.public/name
            if app.mode=='secure' and not file.resolve().is_relative_to(app.public):status,body=403,b'denied'
            else:
                try:body=file.read_bytes()
                except OSError:status,body=404,b'not found'
        elif u.path=='/admin-audit':
            token=self.headers.get('Authorization','')
            allowed=(token=='Bearer privileged-fixture-674315' or (app.mode=='vulnerable' and token=='Bearer member-fixture-234579'))
            if app.mode=='public':allowed=True
            if app.mode=='expired':allowed=False
            if allowed:body=json.dumps({'function_id':'audit.read','proof_canary':app.marker}).encode()
            else:status,body=403,b'denied'
        elif u.path=='/redirect':status,body=302,b''
        elif u.path=='/gzip':
            import gzip
            body=gzip.compress(b'x'*500);self.send_response(200);self.send_header('Content-Encoding','gzip');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
        elif u.path=='/chunked':
            self.send_response(200);self.send_header('Transfer-Encoding','chunked');self.end_headers();self.wfile.write(b'20\r\n'+b'x'*32+b'\r\n0\r\n\r\n');return
        elif u.path=='/partial':
            self.send_response(200);self.send_header('Content-Length','100');self.end_headers();self.wfile.write(b'abc');self.close_connection=True;return
        else:status,body=404,b'not found'
        self.send_response(status)
        if status==302:self.send_header('Location',app.redirect)
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*_):pass

class Fixture:
    def __init__(self,root,mode='vulnerable',server_class=ThreadingHTTPServer,address=('127.0.0.1',0)):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.mode=mode;self.hits=[]
        self.marker='TBHM_'+uuid.uuid4().hex;self.public=self.root/'public';self.public.mkdir()
        (self.public/'public.txt').write_text('owned-public-baseline')
        self.secret_name='tbhm-proof-'+uuid.uuid4().hex+'.txt';(self.root/self.secret_name).write_text(self.marker)
        self.server=server_class(address,Handler);self.server.app=self
        host='['+address[0]+']' if ':' in address[0] else address[0]
        self.url='http://'+host+':'+str(self.server.server_port);self.redirect='http://127.0.0.2:1/denied'
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.runroot=self.root/'run';self.runroot.mkdir();self.store=Storage(self.runroot/'tbhm.db');self.store.save_run({'started_at':'fixture','profile':'test','targets':[self.url]})
        policy={'policy_id':'owned-fixture','included_assets':[{'host':address[0],'ports':[self.server.server_port]}],'excluded_assets':[],
                'allowed_actions':['brokered_http_read','strict_read_validation'],'allowed_http_methods':['GET'],'max_requests_per_second':100}
        self.ctx=SimpleNamespace(output=self.runroot,storage=self.store,targets=[self.url],args=SimpleNamespace(offline=False,proxy=None,approve_strict_replay=True),
            profile={'name':'test','active_probes':True,'rate_limit':{'global_rps':100,'per_target_rps':100}},program_policy=policy,
            log=lambda *_:None,save_finding=lambda finding:self.store.save_finding(dict(finding,discovered_at='fixture')))
        self.plan={'schema':'tbhm.strict-replay/1','destination_pins':{self.url:[address[0]]},'cases':[]}
        self.path=self.root/'plan.json';self.ctx.args.strict_replay_plan=str(self.path)
    def case(self,kind):
        case={'test_id':kind,'vulnerability_class':kind,'controlled_fixture':True,'scope_reference':'owned local fixture',
              'canary':self.marker,'actors':{'member':{'owned_test_account':True,'credential_env':'TBHM_FIXTURE_MEMBER'}}}
        if kind=='path_traversal':
            base='public.txt';traversal='../'+self.secret_name;missing='../tbhm-missing-'+uuid.uuid4().hex+'.txt'
            case.update(parameter='file',baseline_value=base,traversal_value=traversal,missing_value=missing,
                        baseline_sha256=hashlib.sha256(b'owned-public-baseline').hexdigest(),
                        **{key:self.url+'/download?'+urlencode({'file':value}) for key,value in [('baseline_url',base),('mutation_url',traversal),('negative_control_url',missing)]})
        else:
            case['actors']['admin']={'owned_test_account':True,'credential_env':'TBHM_FIXTURE_ADMIN'}
            case.update(privileged_actor='admin',limited_actor='member',expected_limited_access='deny',function_id='audit.read',
                        baseline_url=self.url+'/admin-audit',mutation_url=self.url+'/admin-audit',negative_control_url=self.url+'/missing-function')
        return case
    def run(self,classes=('path_traversal','bfla')):
        from core.strict_replay import run
        self.plan['cases']=[self.case(k) for k in classes];self.path.write_text(json.dumps(self.plan))
        with patch.dict(os.environ,self.env()):return run(self.ctx)
    def env(self):return {'TBHM_FIXTURE_ADMIN':'Bearer privileged-fixture-674315','TBHM_FIXTURE_MEMBER':'Bearer member-fixture-234579'}
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join(timeout=2);self.store.close()
