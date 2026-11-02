"""Offline multi-role HAR/session authorization matrix (v3.9.5).

No request is replayed.  The phase compares captured, operator-authorized flows
and optional expected role rules to identify BOLA/BFLA candidates for manual or
approved validation.
"""
from __future__ import annotations
import json,re
from pathlib import Path
from urllib.parse import urlparse
from core import redteam_utils as RT
from core.evidence_redaction import redact_text, redact_value
try:
    import yaml
except Exception: yaml=None

UUID=re.compile(r'\b[0-9a-f]{8}-[0-9a-f-]{27,}\b',re.I); NUM=re.compile(r'(?<=/)\d+(?=/|$)')
def norm_path(url):
    p=urlparse(url).path or '/'; p=UUID.sub('{uuid}',p); p=NUM.sub('{id}',p); return p

def _role_rules(path):
    if not path:return {}
    p=Path(path)
    try:
        data=json.loads(p.read_text()) if p.suffix.lower()=='.json' else yaml.safe_load(p.read_text())
        return data if isinstance(data,dict) else {}
    except Exception:return {}

def run(ctx):
    if getattr(ctx.args, 'api_authz_plan', None):
        from core.api_authorization import run as replay_owned_accounts
        result = replay_owned_accounts(ctx)
        if result and result.get('status') == 'blocked':
            raise PermissionError('owned-account authorization replay blocked: '+result.get('reason', 'plan invalid'))
    source=getattr(ctx.args,'session_har',None)
    if not source:return
    q=Path(source); files=[q] if q.is_file() else list(q.rglob('*.har')) if q.is_dir() else []
    out=RT.evidence_dir(ctx,'42_authenticated_session_model'); rows=[]
    for p in files[:100]:
        role=p.stem.split('.')[0].split('_')[0]
        try:data=json.loads(p.read_text(errors='ignore'))
        except Exception:continue
        for e in ((data.get('log') or {}).get('entries') or [])[:10000]:
            req=e.get('request') or {}; resp=e.get('response') or {}; url=req.get('url','')
            if not url:continue
            rows.append(redact_value({'role':role,'method':req.get('method','GET'),'url':redact_text(url),'route':norm_path(url),'status':int(resp.get('status') or 0),'size':int((resp.get('content') or {}).get('size') or resp.get('bodySize') or 0),'source':p.name}))
    rules=_role_rules(getattr(ctx.args,'role_matrix',None)); grouped={}
    for r in rows: grouped.setdefault((r['method'],r['route']),[]).append(r)
    candidates=[]
    for (method,route),vals in grouped.items():
        roles={v['role'] for v in vals}; statuses={v['role']:v['status'] for v in vals}
        expected=(rules.get('routes') or {}).get(f'{method} {route}',{}) if isinstance(rules,dict) else {}
        unexpected=[]
        for role,expect in expected.items() if isinstance(expected,dict) else []:
            status=statuses.get(role)
            if expect in ('deny','denied') and status and status<400: unexpected.append(f'{role} expected deny but captured {status}')
            if expect in ('allow','allowed') and status and status>=400: unexpected.append(f'{role} expected allow but captured {status}')
        if unexpected or len(roles)>1 and len(set(statuses.values()))>1:
            c={'method':method,'route':route,'roles':sorted(roles),'statuses':statuses,'unexpected':unexpected,'classification':'authorization-matrix-candidate'}; candidates.append(c)
            if unexpected:
                ctx.save_finding({'phase':'authenticated_session_model','severity':'MEDIUM','confidence':'MEDIUM','title':f'Captured authorization matrix differs from expected policy — {method} {route}'[:180],'target':route,'description':'Offline comparison of operator-supplied HAR captures found a role/policy mismatch. This is a supported lead, not proof of unauthorized access.','evidence':json.dumps(c)[:2200],'impact':'Potential broken object- or function-level authorization across roles or tenants.','remediation':'Verify the expected policy, reproduce with approved test accounts, enforce server-side authorization for every object/function, and add regression tests.','cwe':'CWE-862','finding_class':'supported','status':'lead','verified':False,'verification_method':'offline-role-matrix'})
    RT.write_csv(out/'session_matrix.csv',rows)
    (out/'authorization_candidates.json').write_text(json.dumps(candidates,indent=2),encoding='utf-8')
    RT.write_md(out/'AUTHENTICATED_SESSION_MODEL.md','Authenticated Multi-Role Session Model',[("Captured entries",str(len(rows))),("Candidate route matrices",str(len(candidates))),("Safety",'Offline HAR analysis only. Cookies, tokens and request bodies are not copied into the report and no request is replayed.'),("Next step",'Use dedicated test accounts and an approved validation plan for baseline-versus-mutated reproduction.')])
    ctx.log('OK','authenticated_session_model',f'{len(rows)} captured requests across {len(grouped)} normalized routes; {len(candidates)} candidates')
