#!/usr/bin/env python3
"""Measured acceptance for this incremental release, never all-milestone closure."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(name):return json.loads((ROOT/name).read_text())
def main():
 base='docs/research-v4.2.5/';tests=read(base+'TEST_RESULTS.json');compat=read(base+'COMPATIBILITY.json')
 proof=read(base+'benchmarks/proof_evaluation.json');learning=read(base+'benchmarks/learning_evaluation.json')
 before,after=read(base+'SECURITY_BEFORE.json'),read(base+'SECURITY_AFTER.json')
 checks={'all_regression_groups_pass':len(tests)>=72 and all(r['returncode']==0 for r in tests),
  'compatible':compat['passed'] and compat['baseline_cli_actions']==463 and compat['dispatched_phases']==145,
  'reproduced_defects_closed':bool(before) and set(before)==set(after) and all(before.values()) and not any(after.values()),
  'legacy_proof_behavior_preserved':proof['passed'] and proof['legacy_behavior']['all_equal'],
  'learning_measured':learning['passed'] and learning['retrieval_top_1']['candidate']>learning['retrieval_top_1']['baseline'],
  'real_model_claim_honest':learning['real_model_executed'] is False and learning['real_model_effectiveness']=='UNVERIFIED'}
 print(json.dumps({'incremental_release_accepted':all(checks.values()),'checks':checks},indent=2));return int(not all(checks.values()))
if __name__=='__main__':raise SystemExit(main())
