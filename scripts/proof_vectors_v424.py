#!/usr/bin/env python3
"""Run identical legacy proof vectors against a selected source tree."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile

def execute(source):
    sys.path.insert(0,str(Path(source).resolve()))
    from scripts.evaluate_proof_fixtures_v421 import make_case
    from core.assertion_engine import evaluate
    rows=[]
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        for kind in ('access_control','sensitive_data_exposure','open_redirect'):
            for vulnerable in (False,True):
                a,p=make_case(root,kind+'-'+str(vulnerable),kind,vulnerable)
                for variant in ('golden','missing_control','tampered_signature','duplicate_repeat','counter_only','condition_false','unrelated_class'):
                    x,y=copy.deepcopy(a),copy.deepcopy(p)
                    if variant=='missing_control':y['captures'].pop('negative_control')
                    elif variant=='tampered_signature':y['captures']['mutation']['signature']='0'*64
                    elif variant=='duplicate_repeat':y['captures']['repeats'][1]=y['captures']['repeats'][0]
                    elif variant=='counter_only':y={'schema':'tbhm.proof/2','repeatability':{'successful_proofs':20}}
                    elif variant=='condition_false':x['failure_conditions']=[{'type':'body_contains','value':'absent-controlled-condition-string'}]
                    elif variant=='unrelated_class':x['vulnerability_class']='sqli'
                    result=evaluate(x,y,evidence_root=root)
                    rows.append({'id':kind+'-'+str(vulnerable)+'-'+variant,'kind':kind,'vulnerable':vulnerable,'variant':variant,
                                 'result':{k:result[k] for k in ('result','assertion_passed','negative_control_passed','repeatability_passed','reasons')},
                                 'receipt_issued':'_confirmation_receipt' in result})
    return rows

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
    result=execute(a.source);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print('Evaluated',len(result),'legacy proof vectors')
