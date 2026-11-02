"""Installed-style cross-process CLI persistence, import, consent and dashboard."""
import json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'tests'))
from fixtures_v425 import scenario
from scripts.regression_support import regression_environment, unavailable_model_endpoint, fixture_failure_details
ROOT=Path(__file__).resolve().parent
class LearningCLI(unittest.TestCase):
 def test_full_operator_cli_persistence_review_retrieval_export_dashboard(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);home=root/'ai-home'
   def call(plan,approve=False,output=None):
    path=root/'operation.json';path.write_text(json.dumps({'schema':'tbhm.learning-operation/1','project_id':'project-a',**plan}))
    argv=[sys.executable,str(ROOT/'tbhm.py'),'--offline','--ai-home',str(home),'--ai-learning',str(path)]
    if approve:argv+=['--approve-ai-learning']
    if output:argv+=['--ai-learning-output',str(output)]
    result=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True,timeout=20)
    return result,json.loads(result.stdout)
   result,data=call({'operation':'ingest','record':scenario()});self.assertEqual(result.returncode,2)
   result,data=call({'operation':'ingest','record':scenario()},True);self.assertEqual(result.returncode,0,result.stdout);sha=data['content_sha256']
   result,data=call({'operation':'review','scenario_id':'case-a','review':{'expected_sha256':sha,'reviewer':'operator','technical_validity':'confirmed','decision':'accepted','note':'Independent local fixture label','evidence_ids':['E1'],'program_outcome':'duplicate'}},True)
   self.assertEqual(result.returncode,0,result.stdout);self.assertFalse(data['proof_authority'])
   result,data=call({'operation':'retrieve','query':'object authorization'});self.assertEqual(data['hits'][0]['scenario_id'],'case-a')
   result,data=call({'operation':'export_training'},True);self.assertEqual(len(data['examples']),1);self.assertFalse(data['training_executed'])
   page=root/'LEARNING.html';result,data=call({'operation':'dashboard'},output=page);self.assertEqual(result.returncode,0,result.stdout);self.assertIn('case-a',page.read_text());self.assertNotIn('technical proof confirmed',page.read_text())
   result,data=call({'operation':'dashboard'},output=page);self.assertEqual(result.returncode,2)
   result,data=call({'operation':'revoke','scenario_id':'case-a'},True);self.assertEqual(result.returncode,0)
   result,data=call({'operation':'retrieve','query':'object'});self.assertFalse(data['hits'])
 def test_run_capture_is_pending_and_failures_are_recorded(self):
  from types import SimpleNamespace
  from core.ai_plane.store import Store
  from core.ai_plane.scenarios import ScenarioMemory
  from core.ai_plane.scenario_import import capture_findings,ingest_run
  from core.ai_plane.observer import RunObserver
  from core.storage import Storage
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);s=Store(root/'ai.db');self.addCleanup(s.close);m=ScenarioMemory(s)
   findings=[{'id':1,'title':'Potential API flaw','evidence':'Authorization: Bearer private-token-value'}]
   ctx=SimpleNamespace(args=SimpleNamespace(ai_scenario_context=None),storage=SimpleNamespace(all_findings=lambda:findings),output=root)
   settings={'schema':'tbhm.run-learning-permission/1','project_id':'project-a','scope_reference':'owned lab',
    'source_license':'operator synthetic','permission_reference':'explicit test permission','reuse_approved':True}
   r=capture_findings(m,ctx,'run-capture',settings);self.assertEqual(r['captured_pending'],1);self.assertFalse(m.retrieve('project-a','API')['hits']);self.assertNotIn('private-token-value',m.get('run-capture-finding-1','project-a')['record']['evidence'][0]['summary'])
   observer=RunObserver(store=s,embedder=None,vector_index=None,advisor=None,proposal_gate=None,audit=None,runtime=None)
   observer.run_id=s.start_run(run_uid='failed-capture',tbhm_version='test',profile='test',intensity='',target_count=0)
   ctx.args.ai_scenario_context=str(root/'missing.json');observer._capture_scenarios(ctx)
   self.assertEqual(s.one("SELECT event FROM phase_events WHERE event='learning_failed'")[0],'learning_failed')
 def test_closed_run_sqlite_import_keeps_forged_labels_untrusted(self):
  from core.storage import Storage
  from core.ai_plane.store import Store
  from core.ai_plane.scenarios import ScenarioMemory
  from core.ai_plane.scenario_import import ingest_run
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);run=Storage(root/'run.db');run.save_finding({'phase':'test','title':'unverified finding','severity':'LOW','confidence':'LOW','evidence':'sanitized body','cwe':'CWE-639','discovered_at':'now'});run.close()
   s=Store(root/'ai.db');self.addCleanup(s.close);m=ScenarioMemory(s)
   plan={'run_database':str(root/'run.db'),'run_id':'import-run','vulnerability_class':'access_control','scope_reference':'owned',
    'test_objective':'Independent control validation','source_license':'owned synthetic','permission_reference':'operator consent','reuse_approved':True,'split':'train'}
   r=ingest_run(m,'project-a',plan);self.assertFalse(r['trusted_labels_imported']);self.assertEqual(r['imported'][0]['state'],'pending')
 def test_live_bola_and_learning_capture_reach_sealed_operator_delivery(self):
  from fixtures_v425 import BolaFixture
  from core.ai_plane.store import Store
  from core.ai_plane.scenarios import ScenarioMemory
  from core.evidence_manifest import verify_manifest
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);f=BolaFixture(root/'fixture');self.addCleanup(f.close)
   f.plan['cases']=[f.case()];f.path.write_text(json.dumps(f.plan))
   policy=root/'policy.json';policy.write_text(json.dumps(f.ctx.program_policy))
   permission=root/'permission.json';permission.write_text(json.dumps({'schema':'tbhm.run-learning-permission/1','project_id':'owned-live-lab',
    'scope_reference':'owned two-tenant loopback fixture','source_license':'operator-owned synthetic fixture','permission_reference':'explicit fixture-author approval','reuse_approved':True,'vulnerability_class':'bola'}))
   out=root/'run';ai=root/'ai-home'
   argv=[sys.executable,str(ROOT/'tbhm.py'),'-u',f.url,'--strict-replay-plan',str(f.path),'--approve-strict-replay',
    '--program-policy',str(policy),'-o',str(out),'-y','--silent','--ai-observe','--ai-home',str(ai),'--ai-scenario-context',str(permission),'--no-bootstrap']
   env=regression_environment(root/'test-state');env.update(f.env())
   with unavailable_model_endpoint() as endpoint:
    argv+=['--local-llm-url',endpoint,'--local-llm-model','fixture-unavailable']
    run=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,text=True,timeout=50)
   if run.returncode:run.stderr+=fixture_failure_details(out)
   self.assertEqual(run.returncode,0,run.stdout[-3500:]+run.stderr[-1000:])
   self.assertTrue((out/'LEARNING.html').is_file());self.assertIn('LEARNING.html',(out/'OPERATOR.html').read_text())
   self.assertTrue(verify_manifest(out)['passed'])
   store=Store(ai/'database/memory.sqlite3')
   try:
    overview=ScenarioMemory(store).overview('owned-live-lab');self.assertGreaterEqual(overview['states'].get('pending',0),1)
    self.assertFalse(ScenarioMemory(store).retrieve('owned-live-lab','object')['hits'])
   finally:store.close()
if __name__=='__main__':unittest.main(verbosity=2)
