import copy,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.assertion_engine import evaluate
from core.proof_contracts import capture_snapshot
from core.finding_class import classify
from fixtures_v425 import BolaFixture
class Bola(unittest.TestCase):
 def fixture(self,mode='vulnerable'):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);f=BolaFixture(t.name,mode);self.addCleanup(f.close);return f
 def bundle(self,f):
  report=f.run();r=f.store.conn.execute('SELECT assertion_json,proof_json FROM validation_attempts').fetchone();return report,json.loads(r[0]),json.loads(r[1])
 def test_vulnerable_and_patched_end_to_end_proof_and_seven_requests(self):
  for mode,expected in [('vulnerable','pass'),('secure','fail')]:
   f=self.fixture(mode);r,a,p=self.bundle(f);self.assertEqual(r['cases'][0]['result'],expected);self.assertEqual(len(f.hits),7)
   findings=f.store.all_findings();self.assertEqual(len(findings),int(mode=='vulnerable'))
   if findings:self.assertEqual(classify(findings[0]),'confirmed')
 def test_public_expired_echo_wrong_tenant_stay_inconclusive(self):
  for mode in ('public','expired','echo','wrong_tenant'):
   f=self.fixture(mode);r,a,p=self.bundle(f);self.assertEqual(r['cases'][0]['result'],'inconclusive',mode)
 def test_tampered_replayed_wrong_class_and_missing_controls(self):
  f=self.fixture();r,a,p=self.bundle(f)
  for variant in ('tampered','replayed','wrong_class','missing_actor','missing_privacy','missing_negative'):
   x,y=copy.deepcopy(a),copy.deepcopy(p)
   if variant=='tampered':y['captures']['mutation']['signature']='0'*64
   if variant=='replayed':y['captures']['repeats'][1]=y['captures']['repeats'][0]
   if variant=='wrong_class':x['vulnerability_class']='bfla'
   if variant.startswith('missing_'):y['captures'].pop({'missing_actor':'actor_control','missing_privacy':'privacy_control','missing_negative':'negative_control'}[variant])
   self.assertEqual(evaluate(x,y,evidence_root=f.runroot)['result'],'inconclusive',variant)
 def test_signed_identity_and_tenant_substitution_rejected(self):
  f=self.fixture();r,a,p=self.bundle(f)
  for field in ('challenger_actor','challenger_tenant','object_id','canary','owner_tenant'):
   x=copy.deepcopy(a);x[field]='TBHM_'+'0'*32 if field=='canary' else 'substitution'
   self.assertEqual(evaluate(x,p,evidence_root=f.runroot)['result'],'inconclusive',field)
 def test_preflight_refuses_unowned_same_credentials_scope_and_writes(self):
  from core.strict_replay import prepare
  f=self.fixture();base=f.case()
  for change in ('unowned','same_credentials','scope','write_url','fragment','no_approval','offline'):
   case=copy.deepcopy(base);f.ctx.args.approve_strict_replay=True;f.ctx.args.offline=False;env=f.env()
   if change=='unowned':case['owned_two_tenant_fixture']=False
   if change=='same_credentials':env['TBHM_FIXTURE_MEMBER']=env['TBHM_FIXTURE_ADMIN']
   if change=='scope':case['actor_control_url']='http://outside.invalid/owned'
   if change=='write_url':case['mutation_url']=f.url+'/different'
   if change=='fragment':case['mutation_url']+='#fragment'
   if change=='no_approval':f.ctx.args.approve_strict_replay=False
   if change=='offline':f.ctx.args.offline=True
   f.plan['cases']=[case];f.path.write_text(json.dumps(f.plan))
   with patch.dict(os.environ,env),self.assertRaises((ValueError,PermissionError)):prepare(f.ctx,f.path)
  self.assertEqual(f.hits,[])
 def test_graph_binds_owned_object_to_explicit_tenant_and_origin(self):
  from core.evidence_graph import build
  f=self.fixture();self.bundle(f);finding=f.store.all_findings()[0]
  other=copy.deepcopy(finding);other['id']=2;other['assertion']['owner_tenant']='different-tenant'
  graph=build([finding,other]);objects=[n for n in graph['relationship_nodes'] if n['kind']=='object']
  self.assertEqual(len(objects),2);self.assertTrue(all(n['authority']=='operator_declaration' for n in objects))
  self.assertFalse(any(e['confirms_exploit_edge'] for e in graph['relationship_edges']))
if __name__=='__main__':unittest.main(verbosity=2)
