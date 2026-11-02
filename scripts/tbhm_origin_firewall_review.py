#!/usr/bin/env python3
"""Offline analysis of operator-provided origin candidates and WAF response pairs."""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.origin_firewall_analysis import review_origin_candidates,review_firewall_pairs

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True,help='JSON containing candidates, authorized_ips and response_pairs')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.input.resolve()==a.output.resolve():p.error('output cannot overwrite input')
    if a.input.stat().st_size>4_000_000:p.error('input is over the 4MB limit')
    data=json.loads(a.input.read_text(encoding='utf8'))
    if not isinstance(data,dict):p.error('expected JSON object')
    output={'schema':'tbhm.origin-firewall-review/1',
            'network_requests_executed':0, 'auto_bypass_enabled':False,
            'origin_candidates':review_origin_candidates(data.get('candidates',[]), data.get('authorized_ips',[])),
            'firewall_observations':review_firewall_pairs(data.get('response_pairs',[]))}
    a.output.write_text(json.dumps(output,indent=2)+'\n',encoding='utf8')
    a.output.chmod(0o600)
    print(json.dumps({'output':str(a.output),'candidates':len(output['origin_candidates']),
                      'firewall_pairs':len(output['firewall_observations'])}))
if __name__=='__main__':main()
