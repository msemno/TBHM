#!/usr/bin/env python3
"""Paired class/behavior evaluation on authenticated owned-loopback captures."""
import argparse,copy,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from fixtures_v425 import BolaFixture
from fixtures_v424 import Fixture
from core.assertion_engine import evaluate
from core.quality_evaluation import score
PROBE='''import json,sys
sys.path.insert(0,sys.argv[1])
from core.assertion_engine import evaluate
items=json.load(open(sys.argv[2]));out=[]
for i in items:
 r=evaluate(i['assertion'],i['proof'],evidence_root=i['root']);out.append({k:r[k] for k in ('result','assertion_passed','negative_control_passed','repeatability_passed','reasons')}|{'receipt_issued':'_confirmation_receipt' in r})
print(json.dumps(out))
'''
def probe(source,items,path):
 path.write_text(json.dumps(items));p=subprocess.run([sys.executable,'-c',PROBE,str(source.resolve()),str(path)],capture_output=True,text=True,timeout=30)
 if p.returncode:raise RuntimeError(p.stderr)
 return json.loads(p.stdout)
def execute(baseline,output):
 output.mkdir(parents=True,exist_ok=True);old_records=[];new_records=[];examples=[];vectors=[];legacy=[]
 with tempfile.TemporaryDirectory() as td:
  root=Path(td)
  for mode in ('vulnerable','secure','public','expired','echo','wrong_tenant'):
   f=BolaFixture(root/mode,mode)
   try:
    report=f.run();row=f.store.conn.execute('SELECT assertion_json,proof_json FROM validation_attempts').fetchone();a,p=json.loads(row[0]),json.loads(row[1])
    item={'assertion':a,'proof':p,'root':str(f.runroot)};old=probe(baseline,[item],root/'bundle.json')[0];new=evaluate(a,p,evidence_root=f.runroot)
    prediction=lambda result:'positive' if result=='pass' else 'negative' if result=='fail' else 'inconclusive'
    common={'id':'bola-'+mode,'stage':'confirmation','class':'bola','label':mode=='vulnerable'}
    old_records.append(dict(common,prediction=prediction(old['result'])));new_records.append(dict(common,prediction=prediction(new['result'])))
    examples.append({'mode':mode,'baseline':old['result'],'candidate':new['result'],'requests':len(f.hits),'candidate_receipt':'_confirmation_receipt' in new})
    for variant in ('golden','missing_control','missing_actor','missing_privacy','tampered','replayed','unrelated_class'):
     x,y=copy.deepcopy(a),copy.deepcopy(p)
     if variant.startswith('missing_'):y['captures'].pop({'missing_control':'negative_control','missing_actor':'actor_control','missing_privacy':'privacy_control'}[variant])
     if variant=='tampered':y['captures']['mutation']['signature']='0'*64
     if variant=='replayed':y['captures']['repeats'][1]=y['captures']['repeats'][0]
     if variant=='unrelated_class':x['vulnerability_class']='bfla'
     r=evaluate(x,y,evidence_root=f.runroot);vectors.append({'id':mode+'-'+variant,'class':'bola','mode':mode,'variant':variant,'result':r['result'],'receipt_issued':'_confirmation_receipt' in r})
   finally:f.close()
  for mode in ('vulnerable','secure'):
   f=Fixture(root/('legacy-'+mode),mode)
   try:
    f.run();items=[]
    for row in f.store.conn.execute('SELECT assertion_json,proof_json FROM validation_attempts'):
     a,p=json.loads(row[0]),json.loads(row[1])
     for variant in ('golden','missing_control','tampered','replayed','unrelated_class'):
      x,y=copy.deepcopy(a),copy.deepcopy(p)
      if variant=='missing_control':y['captures'].pop('negative_control')
      if variant=='tampered':y['captures']['mutation']['signature']='0'*64
      if variant=='replayed':y['captures']['repeats'][1]=y['captures']['repeats'][0]
      if variant=='unrelated_class':x['vulnerability_class']='sqli'
      items.append({'assertion':x,'proof':y,'root':str(f.runroot)})
    old,new=probe(baseline,items,root/'old.json'),probe(ROOT,items,root/'new.json')
    for i,(b,c) in enumerate(zip(old,new)):legacy.append({'id':mode+'-'+str(i),'baseline':b,'candidate':c,'equal':b==c})
   finally:f.close()
  original={}
  for name,source in [('baseline',baseline),('candidate',ROOT)]:
   path=output/(name+'-original-vectors.json');p=subprocess.run([sys.executable,str(ROOT/'scripts/proof_vectors_v424.py'),'--source',str(source),'--output',str(path)],capture_output=True,text=True,timeout=30)
   if p.returncode:raise RuntimeError(p.stderr)
   original[name]=json.loads(path.read_text())
  legacy_equal=all(r['equal'] for r in legacy) and original['baseline']==original['candidate']
 report={'schema':'tbhm.proof-comparison/1','baseline':'4.2.4','candidate':'4.2.5','scope':'Six synthetic owned-loopback two-tenant fixtures. Confirmation, not discovery or representative field accuracy.',
   'cases':examples,'baseline_metrics':score(old_records),'candidate_metrics':score(new_records),
   'legacy_behavior':{'vectors':len(legacy)+len(original['baseline']),'all_equal':legacy_equal},'legacy_extended_vectors':legacy,
   'new_vectors':vectors,'passed':legacy_equal and examples[0]['candidate']=='pass' and examples[1]['candidate']=='fail' and all(r['candidate']=='inconclusive' for r in examples[2:])}
 (output/'proof_evaluation.json').write_text(json.dumps(report,indent=2)+'\n')
 (ROOT/'knowledge/proof_behavior_v425.json').write_text(json.dumps({'schema':'tbhm.proof-behavior/1','class':'bola','vectors':vectors,'scope':'owned two-tenant controlled JSON canary read only'},indent=2)+'\n')
 print(json.dumps({'passed':report['passed'],'legacy_behavior':report['legacy_behavior'],'new_vectors':len(vectors),'cases':examples}));return report
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--baseline',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args();raise SystemExit(0 if execute(a.baseline,a.output_dir)['passed'] else 1)
