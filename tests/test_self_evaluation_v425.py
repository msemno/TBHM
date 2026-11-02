import copy,json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.ai_plane.store import Store
from core.ai_plane.scenarios import ScenarioMemory
from core.ai_plane.self_evaluation import Evaluator,check_leakage
from fixtures_v425 import scenario,review,response
class Evaluation(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.s=Store(Path(self.t.name)/'m.db');self.addCleanup(self.s.close);self.m=ScenarioMemory(self.s);self.e=Evaluator(self.m)
 def make(self,sid='test-a',validity='confirmed',**kw):
  self.m.ingest(scenario(sid,project='evaluation',split='test',**kw));review(self.m,sid,'evaluation',validity);return sid
 def test_four_cells_and_missing_predictions_full_denominator(self):
  ids=[];preds=[]
  for i,(label,pred) in enumerate([('confirmed','positive'),('refuted','positive'),('refuted','negative'),('confirmed','negative'),('confirmed',None)]):
   sid=self.make('case-'+str(i),label,observation_summary='independent case '+str(i));ids.append(sid)
   if pred:preds.append(self.e.record_prediction(sid,'evaluation',response(pred),model_version='synthetic')['prediction_id'])
  self.e.freeze('eval','evaluation',ids,approved=True);r=self.e.evaluate('eval','evaluation',preds);m=r['metrics']['by_stage_class'][0]
  self.assertEqual([m[k] for k in ('TP','FP','TN','FN','inconclusive')],[1,1,1,1,1]);self.assertEqual(m['sample_size'],5);self.assertEqual(r['missing_predictions'],1);self.assertEqual(m['conditional_precision'],.5);self.assertEqual(m['recall_bounds'],[1/3,2/3])
 def test_fabricated_citation_is_abstention_and_measured(self):
  sid=self.make();p=self.e.record_prediction(sid,'evaluation',response(evidence_ids=['E999']),model_version='fake')
  self.assertEqual(p['verdict'],'inconclusive');self.assertEqual(p['invalid_citations'],1)
  self.e.freeze('eval','evaluation',[sid],approved=True);r=self.e.evaluate('eval','evaluation',[p['prediction_id']]);self.assertEqual(r['evidence_citation_validity'],0);self.assertEqual(r['abstention_rate'],1)
 def test_model_cannot_emit_proof_or_grade_itself(self):
  sid=self.make()
  for r in (response(verified=True),response(verdict='confirmed'),response(confidence=float('nan'))):
   with self.assertRaises(ValueError):self.e.record_prediction(sid,'evaluation',r,model_version='fake')
  p=self.e.record_prediction(sid,'evaluation',response(),model_version='fake');self.assertFalse(p['proof_authority'])
 def test_frozen_dataset_immutable_and_revocation_invalidates(self):
  sid=self.make();self.e.freeze('eval','evaluation',[sid],approved=True)
  self.make('other')
  with self.assertRaises(ValueError):self.e.freeze('eval','evaluation',['other'],approved=True)
  self.m.revoke(sid,'evaluation',approved=True)
  with self.assertRaises(ValueError):self.e.evaluate('eval','evaluation',[])
 def test_project_root_fixture_source_and_duplicate_leakage(self):
  self.m.ingest(scenario('train'));review(self.m,'train')
  self.make(observation_summary='Copied source case with totally different contents',root_cause_id='root-train')
  with self.assertRaises(ValueError):self.e.freeze('eval','evaluation',['test-a'],approved=True)
 def test_near_duplicate_detection(self):
  self.m.ingest(scenario('train',observation_summary='alpha beta gamma delta epsilon zeta eta theta iota kappa lambda'))
  self.make(observation_summary='alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu')
  with self.assertRaises(ValueError):self.e.freeze('eval','evaluation',['test-a'],approved=True)
 def test_prompt_does_not_expose_current_labels_or_private_other_project(self):
  self.make();self.m.ingest(scenario('train',observation_summary='PRIVATE_OTHER_PROJECT_MARKER'));review(self.m,'train')
  prompt=self.e.prompt('test-a','evaluation');self.assertNotIn('technical_validity',json.dumps(prompt));self.assertNotIn('PRIVATE_OTHER_PROJECT_MARKER',json.dumps(prompt))
 def test_independent_unknown_label_and_classification_error(self):
  sid=self.make(validity='inconclusive');p=self.e.record_prediction(sid,'evaluation',response(vulnerability_class='sqli'),model_version='fake')
  self.e.freeze('eval','evaluation',[sid],approved=True);r=self.e.evaluate('eval','evaluation',[p['prediction_id']]);self.assertEqual(r['metrics']['sample_size'],0);self.assertEqual(r['independent_unknown_labels'],1);self.assertEqual(r['classification_accuracy'],0)
 def test_evaluation_rejects_duplicate_and_foreign_predictions(self):
  sid=self.make();self.e.freeze('eval','evaluation',[sid],approved=True);p=self.e.record_prediction(sid,'evaluation',response(),model_version='fake')['prediction_id']
  with self.assertRaises(ValueError):self.e.evaluate('eval','evaluation',[p,p])
  with self.assertRaises(ValueError):self.e.evaluate('eval','other',[])
 def test_bounded_context_and_hidden_reference_refusal(self):
  evidence=[{'id':'E'+str(i),'sha256':'a'*64,'summary':'sanitized evidence detail '*50,'kind':'controlled'} for i in range(1,9)]
  sid=self.make(evidence=evidence,observation_summary='Observed fields '*70)
  context=self.e.prompt(sid,'evaluation',max_context_chars=1500)
  self.assertLessEqual(len(json.dumps(context,separators=(',',':'))),1500)
  p=self.e.record_prediction(sid,'evaluation',response(evidence_ids=['E8']),model_version='synthetic',context=context)
  self.assertEqual(p['verdict'],'inconclusive')
if __name__=='__main__':unittest.main(verbosity=2)
