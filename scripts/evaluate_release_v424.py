#!/usr/bin/env python3
"""Paired local confirmation evaluation against 4.2.3; never field discovery metrics."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from fixtures_v424 import Fixture
from core.quality_evaluation import score

PROBE='''import json,sys
sys.path.insert(0,sys.argv[1])
from core.assertion_engine import evaluate
item=json.load(open(sys.argv[2]))
r=evaluate(item['assertion'],item['proof'],evidence_root=sys.argv[3])
print(json.dumps({'result':r['result'],'receipt_issued':'_confirmation_receipt' in r,'reasons':r['reasons']}))
'''

def execute(baseline,output):
    output.mkdir(parents=True,exist_ok=True);examples=[];old_records=[];new_records=[]
    for mode in ('vulnerable','secure'):
        with tempfile.TemporaryDirectory(prefix='tbhm-paired-') as td:
            f=Fixture(td,mode)
            try:
                report=f.run();rows=f.store.conn.execute('SELECT assertion_json,proof_json FROM validation_attempts ORDER BY id').fetchall()
                for row,case in zip(rows,report['cases']):
                    item={'assertion':json.loads(row[0]),'proof':json.loads(row[1])};source=Path(td)/'bundle.json';source.write_text(json.dumps(item))
                    p=subprocess.run([sys.executable,'-c',PROBE,str(baseline.resolve()),str(source),str(f.runroot)],capture_output=True,text=True,timeout=15)
                    if p.returncode:raise RuntimeError(p.stderr)
                    old=json.loads(p.stdout);kind=case['vulnerability_class'];identity=mode+'-'+kind
                    label=mode=='vulnerable';prediction=lambda r:'positive' if r=='pass' else 'negative' if r=='fail' else 'inconclusive'
                    common={'id':identity,'stage':'confirmation','class':kind,'label':label,'project':'owned-synthetic-'+kind,'split':'test'}
                    old_records.append(dict(common,prediction=prediction(old['result'])));new_records.append(dict(common,prediction=prediction(case['result'])))
                    examples.append({'id':identity,'class':kind,'fixture':mode,'requests':5 if kind=='path_traversal' else 6,
                        'baseline_result':old['result'],'candidate_result':case['result'],'baseline_receipt':old['receipt_issued'],
                        'candidate_finding_id':case['finding_id'],'bundle_sha256':hashlib.sha256(source.read_bytes()).hexdigest()})
            finally:f.close()
    vectors={}
    for name,source in [('baseline',baseline),('candidate',ROOT)]:
        path=output/(name+'-legacy-vectors.json');p=subprocess.run([sys.executable,str(ROOT/'scripts/proof_vectors_v424.py'),'--source',str(source),'--output',str(path)],capture_output=True,text=True,timeout=20)
        if p.returncode:raise RuntimeError(p.stderr)
        vectors[name]=json.loads(path.read_text())
    result={'schema':'tbhm.paired-confirmation-evaluation/1','baseline':'4.2.3','candidate':'4.2.4',
        'scope':'Four synthetic controlled-fixture HTTP cases, two per new class. Repeats belong to each proof and are not independent samples. This measures confirmation only, not vulnerability discovery or representative field accuracy.',
        'cases':examples,'baseline_metrics':score(old_records),'candidate_metrics':score(new_records),
        'legacy_vectors':{'count':len(vectors['baseline']),'behavior_equal':vectors['baseline']==vectors['candidate']},
        'source_hashes':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['core/strict_classes_v424.py','core/strict_replay.py','core/pinned_transport.py','tests/fixtures_v424.py','core/proof_contracts.py','core/assertion_engine.py','core/finding_class.py','core/evidence_graph.py','core/operator_view.py']},
        'not_evaluated':['field discovery','independent held-out projects','LLM triage quality','model RAM/VRAM/latency','live browsers','real bounty acceptance']}
    result['passed']=result['legacy_vectors']['behavior_equal'] and all(c['candidate_result']==('pass' if c['fixture']=='vulnerable' else 'fail') and c['baseline_result']=='inconclusive' for c in examples)
    (output/'paired_evaluation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':result['passed'],'cases':len(examples),'legacy_vectors':result['legacy_vectors']},indent=2));return result['passed']

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--baseline',type=Path,required=True);parser.add_argument('--output-dir',type=Path,required=True);a=parser.parse_args()
    raise SystemExit(0 if execute(a.baseline,a.output_dir) else 1)
