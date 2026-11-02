#!/usr/bin/env python3
"""Compare old/new proof control decisions on constructed signed evidence."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

PROBE = r'''
import json,tempfile
from core.proof_contracts import SCHEMA,capture_snapshot
from core.assertion_engine import evaluate
results=[]
for case in ('positive_control','denied_echo','leaking_control','same_request_control','public_object'):
 with tempfile.TemporaryDirectory() as root:
  def capture(role):
   actor='owner' if role=='baseline' else 'anonymous' if role=='privacy_control' else 'challenger'
   headers={} if actor=='anonymous' else {'Authorization':'Bearer fixture-'+actor+'-credential'}
   target='https://example.test/objects/1'
   status=200;body={'id':'B','owner':'owner'}
   if role=='negative_control':
    target=target if case=='same_request_control' else 'https://example.test/objects/missing'
    status=404;body=body if case=='leaking_control' else {}
   if role=='privacy_control':
    status=200 if case=='public_object' else 403
    body=body if case=='public_object' else {}
   if role in {'mutation','repeat'} and case=='denied_echo': status=403
   return capture_snapshot(root,test_id='controls.'+case,vulnerability_class='access_control',role=role,actor_id=actor,
    request={'url':target,'method':'GET','headers':headers,'body':''},
    response={'status':status,'headers':{},'body':json.dumps(body)})
  assertion={'schema':SCHEMA,'test_id':'controls.'+case,'vulnerability_class':'access_control',
   'object_id':'B','private_object_required':True,
   'failure_conditions':[{'type':'json_path_equals','path':'id','value':'B'}],
   'negative_control_conditions':[{'type':'status_equals','source':'negative_control','value':404}]}
  proof={'schema':SCHEMA,'captures':{role:capture(role) for role in ('baseline','mutation','negative_control','privacy_control')}}
  proof['captures']['repeats']=[capture('repeat'),capture('repeat')]
  value=evaluate(assertion,proof,evidence_root=root)
  results.append({'case':case,'result':value['result']})
print(json.dumps(results))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    outcomes = {}
    for name, root in [('baseline', args.baseline), ('candidate', args.candidate)]:
        result = subprocess.run([sys.executable, '-c', PROBE], cwd=root, capture_output=True, text=True, timeout=15)
        if result.returncode: raise RuntimeError(result.stderr)
        outcomes[name] = json.loads(result.stdout)
    result = {'scope': 'Five constructed authenticated capture bundles per version, not a detector benchmark or live HTTP evaluation.',
              **outcomes, 'candidate_refused_invalid_controls': sum(row['result'] != 'pass' for row in outcomes['candidate'] if row['case'] != 'positive_control')}
    result['passed'] = result['candidate_refused_invalid_controls'] == 4 and outcomes['candidate'][0]['result'] == 'pass'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
