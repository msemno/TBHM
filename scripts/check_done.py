#!/usr/bin/env python3
"""Evidence-grounded high-level scanner completion gate; never release QA."""
from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.version import VERSION
FLAGS=('external_scanner_traffic_globally_metered','global_wire_enforcement',
       'offline_is_os_network_namespace','all_sensitive_writers_reviewed',
       'all_vulnerability_classes_auto_confirmable')

def _load(path):
    try: return json.loads(path.read_text(encoding='utf8'))
    except (OSError,ValueError): return None

def main():
    info=_load(ROOT/f'RELEASE_INFO-v{VERSION}.json')
    failures=[]
    if not isinstance(info,dict):
        info={};failures.append('missing valid release-info metadata')
    safety=info.get('safety_model') if isinstance(info.get('safety_model'),dict) else {}
    evidence=_load(ROOT/f'docs/research-v{VERSION}/VERIFICATION.json')
    for flag in FLAGS:
        if safety.get(flag) is not True:
            failures.append(flag+' remains open')
        # Boolean values are not sufficient: current-build test evidence required.
        elif not isinstance(evidence,dict) or evidence.get('build_version')!=VERSION or not evidence.get('passed'):
            failures.append(flag+': no verified tests for the current build')
    if not isinstance(evidence,dict):
        failures.append('current-release verification missing')
    else:
        for cls in safety.get('strict_classes',[]):
            record=(evidence.get('strict_class_evidence') or {}).get(cls,{})
            for key in ('fixtures','vectors','matrix','behavioral_guard'):
                filename=record.get(key)
                if not isinstance(filename,str) or filename.startswith('/') or '..' in Path(filename).parts or not (ROOT/filename).is_file():
                    failures.append(f'{cls}: {key} missing')
        held=evidence.get('representative_held_out',{})
        if held.get('status')!='COMPLETE' or not held.get('record'):
            failures.append('independent representative held-out evaluation not complete')
    standards=_load(ROOT/f'docs/research-v{VERSION}/STANDARDS_EXECUTION.json')
    if not isinstance(standards,dict) or standards.get('full_requirement_level_coverage') is not True:
        failures.append('requirement-level standards execution remains open')
    result={'high_level_scanner_done':not failures,'release_status':info.get('status',info.get('release_status','unknown')),
            'failures':failures}
    print(json.dumps(result,indent=2))
    return int(bool(failures))
if __name__=='__main__':raise SystemExit(main())
