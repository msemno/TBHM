#!/usr/bin/env python3
"""Read-only loopback inference diagnostics; never installs or controls processes."""
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import requests
from core.llm_local import is_loopback_url


def diagnose(endpoint, *, model, embedding_model, probe=False, timeout=5):
    from urllib.parse import urlsplit
    parsed=urlsplit(endpoint)
    if (parsed.scheme not in {'http','https'} or not is_loopback_url(endpoint)
            or parsed.username or parsed.password or parsed.path not in {'','/'}
            or parsed.query or parsed.fragment):
        raise ValueError('use an unauthenticated loopback service origin')
    endpoint=endpoint.rstrip('/')
    session=requests.Session();session.trust_env=False
    def call(path, body=None):
        start=time.monotonic()
        try:
            response=session.request('GET' if body is None else 'POST',endpoint+path,
                json=body,timeout=max(.1,min(float(timeout),30)),allow_redirects=False,stream=True)
            raw=bytearray()
            try:
                for chunk in response.iter_content(65536):
                    if len(raw)+len(chunk)>1024*1024:
                        raise ValueError('diagnostic response exceeds 1 MiB')
                    raw.extend(chunk)
            finally:response.close()
            if response.status_code!=200:
                return None,{'status':'HTTP_ERROR','http_status':response.status_code}
            value=json.loads(raw)
            if not isinstance(value,dict):raise ValueError('expected JSON object')
            return value,{'status':'RESPONSIVE','seconds':round(time.monotonic()-start,3)}
        except (requests.RequestException,ValueError) as exc:
            return None,{'status':'UNAVAILABLE','error_type':type(exc).__name__}
    try:
        tags,service=call('/api/tags')
        names=[row.get('name') or row.get('model') for row in (tags or {}).get('models',[]) if isinstance(row,dict)]
        present=lambda name:any(value==name or (isinstance(value,str) and value.split(':')[0]==name.split(':')[0]) for value in names)
        ps,placement_status=call('/api/ps') if tags is not None else (None,{'status':'NOT_PROBED'})
        placements=[]
        for row in (ps or {}).get('models',[]):
            if not isinstance(row,dict):continue
            vram=row.get('size_vram')
            placements.append({'model':row.get('name') or row.get('model'),
                'placement':'GPU_OBSERVED' if type(vram) is int and vram>0 else ('CPU_OBSERVED' if vram==0 else 'UNVERIFIED'),
                'size_vram':vram if type(vram) is int and vram>=0 else None})
        result={'schema':'tbhm.connection-doctor/1','endpoint':endpoint,'service':service,
            'advisor_model_installed':present(model),'embedding_model_installed':present(embedding_model),
            'model_names':names,'placement_api':placement_status,'loaded_model_placement':placements,
            'generation':{'status':'NOT_PROBED'},'embedding':{'status':'NOT_PROBED'},
            'ssh_transport':'UNVERIFIED; an API response does not identify its tunnel owner',
            'security_reasoning_accepted':False,'training_executed':False,'host_configuration_changed':False}
        if probe:
            generated,status=call('/api/generate',{'model':model,'prompt':'Reply only READY.','stream':False,'options':{'num_predict':8}})
            result['generation']={**status,'ready_reply':bool(generated and str(generated.get('response','')).strip()=='READY')}
            embedded,status=call('/api/embeddings',{'model':embedding_model,'prompt':'owned diagnostic fixture'})
            values=(embedded or {}).get('embedding')
            valid=isinstance(values,list) and bool(values) and all(type(v) in (int,float) and math.isfinite(v) for v in values)
            result['embedding']={**status,'valid_finite_vector':valid,'dimension':len(values) if valid else None}
        return result
    finally:session.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--endpoint',default='http://127.0.0.1:11435')
    p.add_argument('--model',default='qwen3-cybersec:4b')
    p.add_argument('--embedding-model',default='nomic-embed-text')
    p.add_argument('--probe-inference',action='store_true')
    p.add_argument('--timeout',type=float,default=5)
    args=p.parse_args()
    try:result=diagnose(args.endpoint,model=args.model,embedding_model=args.embedding_model,probe=args.probe_inference,timeout=args.timeout)
    except ValueError as exc:p.error(str(exc))
    print(json.dumps(result,indent=2))
    return 0 if result['service']['status']=='RESPONSIVE' else 2


if __name__=='__main__':raise SystemExit(main())
