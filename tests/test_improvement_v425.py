import copy,json,sys,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.ai_plane.store import Store
from core.ai_plane.scenarios import ScenarioMemory
from core.ai_plane.proposals import Audit,ProposalGate
from core.ai_plane.home import get
from core.ai_plane.learning_jobs import LearningJobs
from core.ai_plane.improvement import Improvements,configuration
from fixtures_v425 import scenario,review,response
class Improvement(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.h=get(self.t.name,create=True);self.s=Store(self.h.db_path);self.addCleanup(self.s.close);self.m=ScenarioMemory(self.s,Audit(self.s,self.h));self.jobs=LearningJobs(self.m)
  self.m.ingest(scenario());review(self.m,'case-a')
 def test_complete_synthetic_comparative_workflow_promote_rollback(self):
  from scripts.evaluate_learning_v425 import execute
  r=execute(Path(self.t.name)/'benchmark');self.assertTrue(r['passed']);self.assertEqual(r['retrieval_top_1'],{'baseline':0,'candidate':1});self.assertFalse(r['real_model_executed'])
 def test_unavailable_model_job_failure_retry_cancel(self):
  j=self.jobs.enqueue('project-a','case-a')['job_id'];r=self.jobs.run_one('project-a',j,None,model_version='absent');self.assertEqual(r['status'],'failed')
  self.assertIn('model unavailable',r['error']);self.jobs.change('project-a',j,'retry');self.assertEqual(self.jobs.change('project-a',j,'cancel')['status'],'cancelled')
 def test_cancel_event_discards_model_response(self):
  event=threading.Event();event.set();j=self.jobs.enqueue('project-a','case-a')['job_id']
  r=self.jobs.run_one('project-a',j,None,model_version='absent',cancel=event);self.assertEqual(r['status'],'cancelled');self.assertFalse(self.s.query('SELECT * FROM learning_predictions'))
 def test_queue_backpressure_config_boundary_and_foreign_jobs(self):
  for _ in range(32):self.jobs.enqueue('project-a','case-a')
  with self.assertRaises(ValueError):self.jobs.enqueue('project-a','case-a')
  with self.assertRaises(ValueError):configuration({'feedback':True,'k':1,'max_chars':1000,'proof_override':True})
  with self.assertRaises(ValueError):self.jobs.change('other','job-fake','cancel')
 def test_disk_pressure_records_retryable_failure(self):
  from collections import namedtuple
  disk=namedtuple('disk','total used free')(100,99,1);j=self.jobs.enqueue('project-a','case-a')['job_id']
  with patch('core.ai_plane.learning_jobs.shutil.disk_usage',return_value=disk):r=self.jobs.run_one('project-a',j,None,model_version='none')
  self.assertEqual(r['status'],'failed');self.assertIn('resource budget',r['error'])
 def test_retrieved_data_does_not_execute_commands(self):
  class Malicious:
   def available(self):return True,''
   def chat_json(self,*_):return response(commands=['touch /tmp/never-execute-this'])
  j=self.jobs.enqueue('project-a','case-a')['job_id'];r=self.jobs.run_one('project-a',j,Malicious(),model_version='malicious');self.assertEqual(r['status'],'failed');self.assertFalse(self.s.query('SELECT * FROM learning_predictions'))
 def test_promotion_requires_candidate_existing_approval_and_no_authority_changes(self):
  imp=Improvements(self.m,ProposalGate(self.s,self.h,Audit(self.s,self.h)))
  with self.assertRaises(PermissionError):imp.promote('project-a','config-fake')
  with self.assertRaises(ValueError):imp.promote('project-a','config-fake',approved=True)
  self.assertEqual(imp.active('project-a')['config_id'],'baseline')
 def test_proposal_traversal_and_symlink_rejected(self):
  gate=ProposalGate(self.s,self.h,Audit(self.s,self.h));self.assertFalse(gate.decide('../outside',True)['ok'])
  (self.h.proposals_pending/'AI-PROP-ABCDEF01').symlink_to(self.h.config_dir,target_is_directory=True)
  self.assertFalse(gate.decide('AI-PROP-ABCDEF01',True)['ok'])
 def test_comparative_gate_rejects_false_negatives_and_fabricated_citations(self):
  from core.ai_plane.self_evaluation import Evaluator
  ev=Evaluator(self.m);gate=ProposalGate(self.s,self.h,Audit(self.s,self.h));imp=Improvements(self.m,gate)
  self.m.ingest(scenario('isolated-eval',project='eval-project',split='test',test_objective='Separate binary artifact review',observation_summary='Independent held-out packet record',technology='',control_failure=''))
  review(self.m,'isolated-eval','eval-project')
  for eid in ('base','regressed','fabricated'):ev.freeze(eid,'eval-project',['isolated-eval'],approved=True)
  for eid,resp in [('base',response()),('regressed',response('negative')),('fabricated',response(evidence_ids=['invented']))]:
   prediction=ev.record_prediction('isolated-eval','eval-project',resp,model_version='synthetic')
   ev.evaluate(eid,'eval-project',[prediction['prediction_id']])
  self.assertFalse(imp.compare('eval-project','base','regressed')['passed'])
  self.assertFalse(imp.compare('eval-project','base','fabricated')['passed'])
 def test_global_single_worker_claim_and_interrupted_recovery(self):
  import sqlite3,time
  first=self.jobs.enqueue('project-a','case-a')['job_id'];second=self.jobs.enqueue('project-a','case-a')['job_id']
  self.s.conn.execute("UPDATE learning_jobs SET status='running' WHERE job_id=?",(first,));self.s.conn.commit()
  with self.assertRaises(sqlite3.IntegrityError):self.jobs.run_one('project-a',second,None,model_version='none')
  self.s.conn.rollback();self.assertEqual(self.jobs.change('project-a',first,'recover')['status'],'interrupted')
  self.assertEqual(self.jobs.run_one('project-a',second,None,model_version='none')['status'],'failed')
if __name__=='__main__':unittest.main(verbosity=2)
