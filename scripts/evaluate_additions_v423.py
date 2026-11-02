#!/usr/bin/env python3
"""Reproduce local transport counters and known-canary gate outcomes."""
import argparse
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from unittest.mock import patch
import uuid
import zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.brokered_http import SharedLedger,Broker,pipe_replay
from core.delivery_privacy_audit import audit
from core.evidence_manifest import build_manifest


def fixtures():
    spec=importlib.util.spec_from_file_location('broker_fixture',ROOT/'tests/test_brokered_http_v423.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();args.output_dir.mkdir(parents=True,exist_ok=True)
    module=fixtures();transport=[]
    first=module.BrokerTests();second=module.BrokerTests();first.setUp();second.setUp()
    try:
        for name,request_limit,body_limit,cap in [('shared_request_budget',2,1024,8),('denied_origin',10,1024,8),
                                               ('body_reservation',10,8,8),('oversized_body',10,1024,8),('host_cooldown',10,1024,8)]:
            first.server.hits.clear();second.server.hits.clear()
            ledger=SharedLedger(first.root/(name+'.sqlite3'),request_limit,body_limit)
            broker=Broker(first.ctx,ledger,max_body_bytes=cap)
            # Independent HTTP state per scenario; no inherited cooldown.
            if hasattr(first.ctx,'_http_policy_state'):del first.ctx._http_policy_state
            broker.close();broker=Broker(first.ctx,ledger,max_body_bytes=cap)
            worker={}
            try:
                if name=='shared_request_budget':
                    outcomes=[broker.request(first.job('native'),'native')]
                    rows,worker=pipe_replay(broker,[first.job('child-1'),first.job('child-2')]);outcomes.extend(rows)
                elif name=='denied_origin':
                    job={'id':'denied-native','url':second.url+'/outside'}
                    outcomes=[broker.request(job,'native')]
                    rows,worker=pipe_replay(broker,[dict(job,id='denied-child')]);outcomes.extend(rows)
                elif name=='body_reservation':outcomes=[broker.request(first.job('one'),'native'),broker.request(first.job('two'),'native')]
                elif name=='oversized_body':outcomes=[broker.request(first.job('large','/long'),'native')]
                else:
                    outcomes=[broker.request(first.job('rate','/rate'),'native')]
                    another=Broker(first.context(),ledger,max_body_bytes=cap)
                    try:outcomes.append(another.request(first.job('after-rate'),'native'))
                    finally:another.close()
                transport.append({'case':name,'result_states':[r['status'] for r in outcomes],**ledger.report(),
                    'approved_target_contacts':len(first.server.hits),'denied_origin_contacts':len(second.server.hits),'worker':worker})
            finally:broker.close();ledger.close()
    finally:
        first.tearDown();first.doCleanups();second.tearDown();second.doCleanups()
    privacy=[]
    for name in ('clean_text','utf8_canary','zip_utf16_canary','gzip_tar_canary','opaque_image'):
        with tempfile.TemporaryDirectory(prefix='tbhm-privacy-eval-') as td:
            root=Path(td);canary='fixture-'+uuid.uuid4().hex
            if name=='clean_text':(root/'notes.txt').write_text('Controlled harmless text.')
            elif name=='utf8_canary':(root/'notes.txt').write_text(canary)
            elif name=='zip_utf16_canary':
                with zipfile.ZipFile(root/'archive.zip','w',zipfile.ZIP_DEFLATED) as archive:archive.writestr('data.bin',canary.encode('utf-16le'))
            elif name=='gzip_tar_canary':
                buffer=io.BytesIO()
                with tarfile.open(fileobj=buffer,mode='w') as archive:
                    data=canary.encode();info=tarfile.TarInfo('data.txt');info.size=len(data);archive.addfile(info,io.BytesIO(data))
                (root/'bundle.tar.gz').write_bytes(gzip.compress(buffer.getvalue()))
            else:(root/'image.png').write_bytes(b'\x89PNG\r\n\x1a\nopaque pixels')
            build_manifest(root)
            with patch.dict(os.environ,{'TBHM_EVALUATION_CANARY':canary}):report=audit(root,['TBHM_EVALUATION_CANARY'])
            expected='pass' if name=='clean_text' else 'incomplete' if name=='opaque_image' else 'fail'
            privacy.append({'case':name,'expected':expected,'observed':report['status'],'matched':report['status']==expected,
                            'known_canary_hits':len(report['hits']),'incomplete_surfaces':len(report['incomplete'])})
    expected_states={'shared_request_budget':['observed','observed','blocked'],'denied_origin':['blocked','blocked'],
                     'body_reservation':['observed','blocked'],'oversized_body':['incomplete'],'host_cooldown':['observed','blocked']}
    passed=all(row['result_states']==expected_states[row['case']] and row['denied_origin_contacts']==0 for row in transport) and all(r['matched'] for r in privacy)
    result={'schema':'tbhm.additive-capability-evaluation/1','passed':passed,'transport':transport,'privacy':privacy,
        'scope':'Five synthetic loopback transport scenarios and five known-canary/container cases. This measures the optional capabilities only; no public target, live browser, all-wire meter, unknown-secret recall, real-model quality or bounty acceptance was evaluated.'}
    (args.output_dir/'additions_evaluation.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':passed,'transport_cases':len(transport),'privacy_cases':len(privacy)},indent=2))
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
