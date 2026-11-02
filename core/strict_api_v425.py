"""Owned two-tenant, read-only BOLA proof. No inferred production object IDs.

Seven authenticated captures bind the protected object, real owned actors,
separate tenants, valid challenger session, missing object and anonymous denial.
This contract is for an explicit controlled JSON canary fixture, not generic APIs.
"""
import json
import re
from urllib.parse import urlsplit
from core.strict_classes_v424 import _require,_success,_status,_text,_identity,_object,ControlHeld
from core.proof_contracts import _read_capture,_same_request
from core.pinned_transport import origin

KIND='bola'

def verify(assertion,proof,root):
    a=assertion
    _require(a.get('controlled_fixture') is True and a.get('owned_two_tenant_fixture') is True and
      isinstance(a.get('scope_reference'),str) and 1<=len(a['scope_reference'])<=300,'owned two-tenant fixture/scope approval required')
    for field in ('owner_actor','challenger_actor','owner_tenant','challenger_tenant','object_id','challenger_object_id'):
        _require(isinstance(a.get(field),str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',a[field]),'explicit bounded owned actor/tenant/object identity required')
    _require(a['owner_actor']!=a['challenger_actor'] and a['owner_tenant']!=a['challenger_tenant'] and a['object_id']!=a['challenger_object_id'], 'two distinct owned actors, tenants and objects required')
    _require(a.get('expected_cross_tenant_access')=='deny','reviewed cross-tenant deny expectation required')
    for name in ('canary','challenger_canary'):
        _require(isinstance(a.get(name),str) and re.fullmatch(r'TBHM_[0-9a-f]{32}',a[name]),'dedicated 128-bit controlled canaries required')
    _require(a['canary']!=a['challenger_canary'],'distinct object canaries required')
    refs=proof.get('captures') or {};tid=a['test_id']
    roles=('baseline','mutation','negative_control','actor_control','privacy_control')
    b,m,n,own,anon=[_read_capture(root,refs[k],tid,k,KIND) for k in roles]
    repeats=[_read_capture(root,r,tid,'repeat',KIND) for r in refs.get('repeats',[])]
    rows=[b,m,n,own,anon]+repeats
    _require(2<=len(repeats)<=10 and len({r['capture_id'] for r in rows})==len(rows),'distinct capture IDs and two repeats required')
    for row in rows:
        req=row['request'];url=urlsplit(req['url'])
        _require(origin(req['url'])==origin(m['request']['url']) and req.get('method')=='GET' and req.get('body','')=='' and not url.fragment and url.username is None,'same-origin read-only GET capture required')
        _require(all(v not in req['url'] and v not in str(req.get('headers',{})) for v in (a['canary'],a['challenger_canary'])),'response canary cannot be supplied by the request')
    _require(_same_request(b,m) and b['actor_id']==a['owner_actor'] and m['actor_id']==a['challenger_actor'] and
      b['identity_sha256'] and m['identity_sha256'] and b['identity_sha256']!=m['identity_sha256'],'separate authenticated owner/challenger identities required')
    _require(all(_identity(m,r) and _same_request(m,r) for r in repeats),'repeat request/credential mismatch')
    _require(_identity(m,n) and _identity(m,own) and not _same_request(m,n) and not _same_request(m,own) and not _same_request(n,own),'distinct missing-object and valid challenger-object controls required')
    expected={'object_id':a['object_id'],'owner_id':a['owner_actor'],'tenant_id':a['owner_tenant'],'proof_canary':a['canary']}
    own_expected={'object_id':a['challenger_object_id'],'owner_id':a['challenger_actor'],'tenant_id':a['challenger_tenant'],'proof_canary':a['challenger_canary']}
    exposes=lambda r:_success(r) and _object(r)==expected
    _require(exposes(b),'owner baseline must return exact owned protected-object representation')
    _require(_success(own) and _object(own)==own_expected,'challenger session must independently read its own tenant object')
    _require(_status(n) in {401,403,404} and a['canary'] not in _text(n),'missing-object negative control required')
    _require(_same_request(m,anon) and not anon['identity_sha256'] and anon['actor_id']=='anonymous' and
      _status(anon) in {401,403,404} and a['canary'] not in _text(anon),'anonymous same-object denial required')
    checks=[exposes(r) for r in [m]+repeats]
    if not any(checks):
        if all(_status(r) in {401,403,404} and a['canary'] not in _text(r) for r in [m]+repeats):raise ControlHeld('exact owned cross-tenant object access and both repeats denied')
        raise ValueError('ambiguous response; no controlled object disclosure proof')
    _require(all(checks),'unstable object disclosure across repeats')
    return b,m,n,repeats


def prepare_case(ctx,case,pins,policy):
    """Validate every explicit request and credential before DNS/dispatch."""
    import os
    import requests
    from core import program_policy
    from core.targets import target_scope_allows
    a=case
    _require(a.get('owned_two_tenant_fixture') is True and a.get('controlled_fixture') is True and
      isinstance(a.get('scope_reference'),str) and 1<=len(a['scope_reference'])<=300,'owned-fixture scope required')
    for k in ('owner_actor','challenger_actor','owner_tenant','challenger_tenant','object_id','challenger_object_id'):
        _require(isinstance(a.get(k),str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',a[k]),'owned identity required')
    _require(a['owner_actor']!=a['challenger_actor'] and a['owner_tenant']!=a['challenger_tenant'] and a['object_id']!=a['challenger_object_id'] and a.get('expected_cross_tenant_access')=='deny','explicit cross-tenant deny contract required')
    for k in ('canary','challenger_canary'):_require(re.fullmatch(r'TBHM_[0-9a-f]{32}',str(a.get(k,''))),'controlled canary required')
    _require(a['canary']!=a['challenger_canary'],'distinct canaries required')
    actors=a.get('actors');_require(isinstance(actors,dict) and set(actors)=={a['owner_actor'],a['challenger_actor']},'exact owned actor map required')
    creds=[]
    for actor in actors.values():
        _require(isinstance(actor,dict) and actor.get('owned_test_account') is True,'owned account declaration required')
        env=actor.get('credential_env');_require(isinstance(env,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,120}',env),'credential environment required')
        value=os.environ.get(env,'');_require(1<=len(value)<=8192 and not any(c in value for c in '\r\n'),'valid actor credential required');creds.append(value)
    _require(len(set(creds))==2,'distinct actor credentials required')
    urls={}
    for key in ('baseline_url','mutation_url','negative_control_url','actor_control_url'):
        value=a.get(key);_require(isinstance(value,str) and len(value)<=4096,'bounded explicit owned object URL required')
        parsed=urlsplit(value);_require(parsed.username is None and not parsed.fragment,'URL authority denied')
        value=requests.Request('GET',value).prepare().url;o=origin(value)
        _require(o in pins.mapping and target_scope_allows(ctx,value) and program_policy.evaluate_asset(policy,value)['decision']=='in_scope','URL outside explicit scope/pins')
        _require(o[0]=='https' or o[1] in {'127.0.0.1','::1'},'credentialed replay requires HTTPS except numeric loopback')
        _require(all(c not in value for c in (a['canary'],a['challenger_canary'])),'canary supplied in request')
        urls[key]=value
    _require(len({origin(v) for v in urls.values()})==1 and urls['baseline_url']==urls['mutation_url'] and len(set(urls.values()))==3,'same-origin owner/challenger/missing object requests required')
    a.update(urls)
