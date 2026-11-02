"""Synthetic, owned, loopback-only BOLA and scenario-learning fixtures."""
import hashlib,json,uuid
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit
from fixtures_v424 import Fixture,Handler as OldHandler

class Handler(OldHandler):
    def do_GET(self):
        app=self.server.app;path=urlsplit(self.path).path
        if path not in {'/objects/owned-a','/objects/owned-b'}:return super().do_GET()
        token=self.headers.get('Authorization','');app.hits.append((self.path,token));own=path.endswith('owned-b')
        allowed=(token==('Bearer member-fixture-234579' if own else 'Bearer privileged-fixture-674315'))
        if not own and app.mode=='vulnerable' and token=='Bearer member-fixture-234579':allowed=True
        if app.mode=='public':allowed=True
        if app.mode=='expired' and own:allowed=False
        body={'object_id':'object-b' if own else 'object-a','owner_id':'member' if own else 'admin',
              'tenant_id':'tenant-b' if own else 'tenant-a','proof_canary':app.challenger_marker if own else app.marker}
        status=200 if allowed else 403;raw=json.dumps(body).encode() if allowed else b'denied'
        if app.mode=='echo' and not own and token=='Bearer member-fixture-234579':status=200;raw=self.path.encode()
        if app.mode=='wrong_tenant' and not own:body['tenant_id']='tenant-b';raw=json.dumps(body).encode()
        self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
class Server(ThreadingHTTPServer):
    def __init__(self,address,unused):super().__init__(address,Handler)
class BolaFixture(Fixture):
    def __init__(self,root,mode='vulnerable'):
        super().__init__(root,mode,server_class=Server);self.challenger_marker='TBHM_'+uuid.uuid4().hex
    def case(self,kind='bola'):
        if kind!='bola':return super().case(kind)
        return {'test_id':'bola-owned-tenants','vulnerability_class':'bola','controlled_fixture':True,
          'owned_two_tenant_fixture':True,'scope_reference':'owned loopback two-tenant JSON canary fixture',
          'canary':self.marker,'challenger_canary':self.challenger_marker,'owner_actor':'admin','challenger_actor':'member',
          'owner_tenant':'tenant-a','challenger_tenant':'tenant-b','object_id':'object-a','challenger_object_id':'object-b',
          'expected_cross_tenant_access':'deny','actors':{'admin':{'owned_test_account':True,'credential_env':'TBHM_FIXTURE_ADMIN'},
          'member':{'owned_test_account':True,'credential_env':'TBHM_FIXTURE_MEMBER'}},
          'baseline_url':self.url+'/objects/owned-a','mutation_url':self.url+'/objects/owned-a',
          'actor_control_url':self.url+'/objects/owned-b','negative_control_url':self.url+'/objects/missing-owned'}
    def run(self,classes=('bola',)):return super().run(classes)

def scenario(sid='case-a',project='project-a',split='train',**changes):
    record={'scenario_id':sid,'project_id':project,'run_id':'run-'+project,'split':split,
     'scope_reference':'owned-lab-permission','vulnerability_class':'access_control','test_objective':'Validate owned object authorization',
     'observation_summary':'Private object content is returned after changing the authenticated actor',
     'evidence':[{'id':'E1','sha256':hashlib.sha256((sid+'evidence').encode()).hexdigest(),
                  'summary':'Owned sanitized observation '+sid,'kind':'controlled_observation'}],
     'root_cause_id':'root-'+sid,'source_license':'operator-owned synthetic fixture',
     'permission_reference':'synthetic-test-permission','reuse_approved':True,'training_allowed':True,
     'technology':'json-api','control_failure':'anonymous control missing','verification_method':'owned canary and independent negative controls'}
    record.update(changes);return record

def review(memory,sid,project='project-a',validity='confirmed',**changes):
    r=memory.get(sid,project)
    fields={'expected_sha256':r['content_sha256'],'reviewer':'independent-fixture-author','technical_validity':validity,
     'decision':'accepted','note':'Independently specified fixture outcome with controlled evidence','evidence_ids':['E1'],'approved':True}
    fields.update(changes);return memory.review(sid,project,**fields)

def response(verdict='positive',**changes):
    r={'verdict':verdict,'confidence':.8 if verdict=='positive' else .2,'vulnerability_class':'access_control',
     'evidence_ids':['E1'],'scenario_ids':[],'observed':'Owned object response','unproven':'Independent proof remains required',
     'benign_explanation':'Public object may explain the observation','missing_control':'Verify anonymous object access',
     'safe_next_step':'Review existing authenticated captures and ownership','falsifier':'Anonymous access with the same content would contradict private-object impact'}
    r.update(changes);return r
