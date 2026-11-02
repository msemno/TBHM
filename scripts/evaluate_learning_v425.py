#!/usr/bin/env python3
"""Reproducible synthetic retrieval comparison and complete governance exercise.

This is not a model benchmark: a deterministic surrogate consumes the selected
reviewed label to exercise plumbing. The measured learning improvement is actual
ranked retrieval on eight intentionally ambiguous synthetic queries.
"""
import argparse,json,resource,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from core.ai_plane.store import Store
from core.ai_plane.scenarios import ScenarioMemory
from core.ai_plane.proposals import Audit,ProposalGate
from core.ai_plane.home import get
from core.ai_plane.self_evaluation import Evaluator
from core.ai_plane.improvement import Improvements
from core.ai_plane.learning_jobs import LearningJobs
from fixtures_v425 import scenario,review,response

class SyntheticSurrogate:
 def available(self):return True,'explicit deterministic synthetic test double; no LLM'
 def chat_json(self,system,user):
  context=json.loads(user);hits=context['history']['hits'];hit=hits[0] if hits else None
  verdict='inconclusive' if not hit else 'positive' if hit['technical_validity']=='confirmed' else 'negative'
  return response(verdict,scenario_ids=[hit['scenario_id']] if hit else [],
   observed='Synthetic surrogate uses the first retrieved reviewed case; this is a workflow test.',
   confidence=.8 if verdict=='positive' else .2)

def execute(output):
 start=time.perf_counter();output.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='tbhm-learning-benchmark-') as td:
  home=get(td,create=True);store=Store(home.db_path);audit=Audit(store,home);m=ScenarioMemory(store,audit)
  gate=ProposalGate(store,home,audit);ev=Evaluator(m);jobs=LearningJobs(m);imp=Improvements(m,gate)
  try:
   expected={};cases=[]
   for i in range(8):
    label='confirmed' if i%2==0 else 'refuted';project='history';relevant='b-reviewed-'+str(i);decoy='a-decoy-'+str(i)
    for sid,observation,validity,mistake in [(decoy,f'family{i} objecttoken{i}','refuted' if label=='confirmed' else 'confirmed',''),
         (relevant,f'family{i}',label,'A prior review identified the missing authorization control')]:
     m.ingest(scenario(sid,project=project,observation_summary=observation,test_objective='',control_failure='',technology='',
      shared=True,data_sensitivity='public',false_positive_reason=mistake));review(m,sid,project,validity)
    sid='evaluation-'+str(i);query=f'family{i} objecttoken{i}'
    m.ingest(scenario(sid,project='evaluation',split='test',test_objective=query,
      observation_summary=f'novel-observation-{i} independent target response',control_failure='',technology=''))
    review(m,sid,'evaluation',label);expected[sid]=relevant;cases.append(sid)
   for eid in ('baseline','candidate'):ev.freeze(eid,'evaluation',cases,approved=True)
   ranked=[];predictions={'baseline':[],'candidate':[]};reports={}
   configs={'baseline':{'feedback':False,'k':5,'max_chars':10000},'candidate':{'feedback':True,'k':5,'max_chars':10000}}
   client=SyntheticSurrogate()
   for variant,config in configs.items():
    for sid in cases:
     current=m.get(sid,'evaluation')['record'];retrieval=m.retrieve('evaluation',current['test_objective']+' '+current['observation_summary'],vulnerability_class='access_control',**config)
     top=retrieval['hits'][0]['scenario_id'] if retrieval['hits'] else None
     ranked.append({'scenario_id':sid,'variant':variant,'expected_relevant':expected[sid],'actual_top_1':top,'correct':top==expected[sid]})
     job=jobs.enqueue('evaluation',sid,config=config);result=jobs.run_one('evaluation',job['job_id'],client,model_version='synthetic-surrogate-v1')
     if result['status']!='completed':raise RuntimeError(result)
     predictions[variant].append(result['prediction_id'])
    reports[variant]=ev.evaluate(variant,'evaluation',predictions[variant],scope='Eight synthetic cases with independently fixture-authored labels. Deterministic surrogate; NOT real-model quality or field accuracy.')
   proposal=imp.propose('evaluation',config=configs['candidate'],baseline='baseline',candidate='candidate',scenario_ids=cases,
       problem='Synthetic lexical ranking selects high-overlap decoys ahead of reviewed mistake cases')
   gate.decide(proposal['proposal_id'],True,'Synthetic operator approval in isolated temporary benchmark')
   promoted=imp.promote('evaluation',proposal['config_id'],approved=True);rolled=imp.rollback('evaluation',approved=True)
   top1={v:sum(r['correct'] for r in ranked if r['variant']==v)/len(cases) for v in configs}
   report={'schema':'tbhm.learning-benchmark/1','scope':'Synthetic retrieval-ranking experiment only, eight ambiguous queries and sixteen reviewed historical cases. Expected relevant IDs are defined before evaluating the two fixed configurations.',
    'real_model_effectiveness':'UNVERIFIED','real_model_executed':False,'field_calibration':'DEFERRED: licensed independently labeled representative projects required',
    'retrieval_top_1':top1,'queries':ranked,'surrogate_workflow_evaluations':reports,
    'surrogate_warning':'The surrogate copies the first historical label solely to exercise independent evaluation and promotion gates. These metrics do not estimate LLM effectiveness.',
    'governance':{'proposal_created':True,'approved':True,'promoted':promoted['config_id']==proposal['config_id'],'rollback_restored_baseline':rolled['config_id']=='baseline','audit_intact':audit.verify_chain()[0]},
    'resource_measurement':{'elapsed_ms':(time.perf_counter()-start)*1000,'peak_process_ram_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
       'vram_bytes':None,'environment':'current Linux Python 3.12 process; not a measured 6 GB Kali VM'},
    'training_executed':False}
   report['passed']=top1['candidate']>top1['baseline'] and all(report['governance'].values())
   (output/'learning_evaluation.json').write_text(json.dumps(report,indent=2)+'\n')
   (output/'learning_evaluation.md').write_text('# Learning evaluation — synthetic scope\n\nActual top-1 retrieval: baseline '+str(top1['baseline'])+'; reviewed-feedback candidate '+str(top1['candidate'])+' across eight synthetic ambiguous queries.\n\nReal-model effectiveness is UNVERIFIED. The triage tables use a deterministic surrogate, not an LLM; they validate evaluation/governance plumbing. No field accuracy or training claim follows.\n\nPromotion, rollback, audit, source permissions and project isolation run through the production APIs.\n')
   return report
  finally:store.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args();r=execute(a.output_dir)
 print(json.dumps({'passed':r['passed'],'retrieval_top_1':r['retrieval_top_1'],'governance':r['governance'],'resources':r['resource_measurement']}));raise SystemExit(0 if r['passed'] else 1)
