"""Approved controlled-canary traversal and owned-role read-only function replay."""
from __future__ import annotations
import hashlib
import json
import os
import re
from urllib.parse import urlsplit, parse_qsl
import requests
from core import program_policy
from core.assertion_engine import evaluate, confirmation_fields
from core.brokered_http import Broker, SharedLedger, ACTION
from core.evidence_redaction import redact_value
from core.http_policy import RequestBlocked
from core.pinned_transport import DestinationPins, origin
from core.proof_contracts import capture_snapshot, SCHEMA
from core.research_input import load
from core.scoped_http import effective_rps
from core.targets import target_scope_allows


def prepare(ctx, path):
    if not getattr(ctx.args, 'approve_strict_replay', False) or getattr(ctx.args, 'offline', False):
        raise PermissionError('strict replay requires --approve-strict-replay and online mode')
    policy = getattr(ctx, 'program_policy', None)
    if not policy or any(not program_policy.evaluate_action(policy, action, method='GET')['allowed']
                         for action in (ACTION, 'strict_read_validation')):
        raise PermissionError('reviewed policy must allow strict_read_validation and brokered_http_read GET')
    if getattr(ctx.args, 'proxy', None): raise PermissionError('strict replay does not support proxies')
    plan = load(path, 1024*1024)
    if not isinstance(plan, dict) or plan.get('schema') != 'tbhm.strict-replay/1':
        raise ValueError('expected tbhm.strict-replay/1')
    pins = DestinationPins(plan.get('destination_pins'))  # Syntax only; no DNS during preflight.
    cases = plan.get('cases')
    if not isinstance(cases, list) or not 1 <= len(cases) <= 10: raise ValueError('1–10 explicit cases required')
    seen = set()
    for case in cases:
        if not isinstance(case, dict): raise ValueError('case must be an object')
        if not isinstance(case.get('test_id'), str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', case['test_id']) or case['test_id'] in seen:
            raise ValueError('bounded unique test_id required')
        seen.add(case['test_id'])
        kind = case.get('vulnerability_class')
        if kind == 'bola':
            from core.strict_api_v425 import prepare_case
            prepare_case(ctx, case, pins, policy)
            continue
        if kind not in {'path_traversal', 'bfla'}: raise ValueError('unsupported strict replay class')
        if case.get('controlled_fixture') is not True or not isinstance(case.get('scope_reference'), str) or not 1 <= len(case['scope_reference']) <= 300:
            raise ValueError('controlled-fixture declaration and scope reference required')
        if not re.fullmatch(r'TBHM_[0-9a-f]{32}', str(case.get('canary', ''))): raise ValueError('128-bit TBHM canary required')
        actors = case.get('actors')
        if not isinstance(actors, dict) or not 1 <= len(actors) <= 2: raise ValueError('explicit owned actor map required')
        credentials = []
        for actor, entry in actors.items():
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', actor) or not isinstance(entry, dict) or entry.get('owned_test_account') is not True:
                raise ValueError('bounded owned actor required')
            env = entry.get('credential_env')
            if env is not None:
                if not isinstance(env, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,120}', env): raise ValueError('invalid credential environment name')
                value = os.environ.get(env, '')
                if not 1 <= len(value) <= 8192 or any(c in value for c in '\r\n'): raise ValueError('missing/malformed actor credential')
                credentials.append(value)
        if kind == 'bfla' and (len(actors) != 2 or len(credentials) != 2 or len(set(credentials)) != 2 or
                               case.get('privileged_actor') not in actors or case.get('limited_actor') not in actors or
                               case['privileged_actor'] == case['limited_actor'] or case.get('expected_limited_access') != 'deny'):
            raise ValueError('distinct credentialed privileged/limited owned actors and expected deny required')
        if kind == 'path_traversal' and len(actors) != 1: raise ValueError('one traversal test actor required')
        urls = {}
        for field in ('baseline_url', 'mutation_url', 'negative_control_url'):
            value = case.get(field)
            if not isinstance(value, str) or len(value) > 4096: raise ValueError('bounded explicit case URL required')
            value = requests.Request('GET', value).prepare().url
            key = origin(value)
            if (key not in pins.mapping or not target_scope_allows(ctx, value) or
                    program_policy.evaluate_asset(policy, value)['decision'] != 'in_scope'):
                raise PermissionError('case URL outside explicit target/program/destination-pin scope')
            if credentials and key[0] != 'https' and key[1] not in {'127.0.0.1', '::1'}:
                raise ValueError('credentialed replay requires HTTPS except numeric loopback lab')
            if case['canary'] in value: raise ValueError('expected canary may not be sent to the target')
            urls[field] = value
        if len({origin(v) for v in urls.values()}) != 1 or urls['negative_control_url'] == urls['mutation_url']:
            raise ValueError('same-origin distinct missing/denied control required')
        if kind == 'bfla':
            if urls['baseline_url'] != urls['mutation_url'] or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',str(case.get('function_id',''))):
                raise ValueError('same protected-function URL and bounded function_id required')
        else:
            parameter = case.get('parameter')
            if not isinstance(parameter, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,60}',parameter): raise ValueError('bounded query parameter required')
            rules = [('baseline_value', r'[A-Za-z0-9_-]{1,80}\.txt'),
                     ('traversal_value', r'(?:\.\./){1,8}tbhm-proof-[0-9a-f]{32}\.txt'),
                     ('missing_value', r'(?:\.\./){1,8}tbhm-missing-[0-9a-f]{32}\.txt')]
            common = None; endpoint = urlsplit(urls['baseline_url']).path
            for (name, rule), field in zip(rules, urls):
                if not re.fullmatch(rule,str(case.get(name,''))): raise ValueError('dedicated controlled filename required')
                parsed=urlsplit(urls[field]);query=parse_qsl(parsed.query,keep_blank_values=True)
                if parsed.path!=endpoint or [v for k,v in query if k==parameter]!=[case[name]]:raise ValueError('URL is not bound to controlled filename mutation')
                rest=[(k,v) for k,v in query if k!=parameter]
                if common is None:common=rest
                if rest!=common:raise ValueError('unrelated parameters changed')
            if not re.fullmatch('[0-9a-f]{64}',str(case.get('baseline_sha256',''))): raise ValueError('known public-file hash required')
        case.update(urls)
    return plan


def run(ctx):
    source = getattr(ctx.args, 'strict_replay_plan', None)
    if not source: return None
    plan = prepare(ctx, source)  # Validate all cases before any DNS, HTTP or child launch.
    out = ctx.output/'evidence'/'strict_replay'; out.mkdir(parents=True, exist_ok=True)
    capacity = sum(7 if c['vulnerability_class']=='bola' else 6 for c in plan['cases'])
    ledger = SharedLedger(out/'ledger.sqlite3', capacity, 200000*capacity, effective_rps(ctx))
    summaries = []
    def observed(job, response, body):
        return capture_snapshot(ctx.output, test_id=job['test_id'], vulnerability_class=job['kind'],
            role=job['role'], actor_id=job['actor_id'],
            request={'url':response.request.url,'method':'GET','headers':dict(response.request.headers),'body':''},
            response={'status':response.status_code,'headers':dict(response.headers),'body':body.decode('utf-8',errors='strict')})
    broker = Broker(ctx, ledger, max_body_bytes=200000, destination_pins=plan['destination_pins'], capture_observer=observed)
    try:
        for case in plan['cases']:
            kind, test_id = case['vulnerability_class'], 'strict.'+case['test_id']
            assertion = {k:v for k,v in case.items() if k not in {'actors','baseline_url','mutation_url','negative_control_url','actor_control_url'}}
            assertion.update(schema=SCHEMA, test_id=test_id,
                failure_conditions=[{'type':'body_contains','value':case['canary']}],
                negative_control_conditions=[{'type':'body_not_contains','source':'negative_control','value':case['canary']}])
            tx = ctx.storage.start_test_execution(test_id=test_id,test_version='2.4',phase='controlled_validation_plane',
                target=case['mutation_url'],operation='strict_read_validation',assertion=assertion,scope_decision='in_scope',policy_id=ctx.program_policy.get('policy_id',''))
            refs = {}; errors = []
            owner = case.get('owner_actor',case.get('privileged_actor',next(iter(case['actors']))))
            challenger = case.get('challenger_actor',case.get('limited_actor',owner))
            jobs = [('baseline',owner,case['baseline_url']),('mutation',challenger,case['mutation_url']),
                    ('negative_control',challenger,case['negative_control_url'])]
            if kind=='bfla':jobs.append(('privacy_control','anonymous',case['mutation_url']))
            if kind=='bola':
                jobs.append(('actor_control',challenger,case['actor_control_url']))
                jobs.append(('privacy_control','anonymous',case['mutation_url']))
            jobs += [('repeat',challenger,case['mutation_url'])]*2
            for number,(role,actor,url) in enumerate(jobs):
                entry=case['actors'].get(actor,{})
                job={'id':test_id+'-'+str(number),'url':url,'role':role,'actor_id':actor,'test_id':test_id,'kind':kind}
                if entry.get('credential_env'):job['credential_env']=entry['credential_env']
                result=broker.request(job,'native')
                if 'capture_ref' not in result:
                    errors.append(result.get('reason','capture incomplete'));break
                if role=='repeat':refs.setdefault('repeats',[]).append(result['capture_ref'])
                else:refs[role]=result['capture_ref']
            proof={'schema':SCHEMA,'captures':refs}; result=evaluate(assertion,proof,evidence_root=ctx.output)
            finding_id=None
            if result['result']=='pass':
                finding_id=ctx.save_finding({'phase':'controlled_validation_plane','severity':'MEDIUM','confidence':'HIGH',
                    'title':'Owned cross-tenant object read' if kind=='bola' else 'Controlled file traversal' if kind=='path_traversal' else 'Owned-role protected read function exposed to limited actor',
                    'url':case['mutation_url'],'target':case['mutation_url'],'method':'GET',
                    'cwe':'CWE-639' if kind=='bola' else 'CWE-22' if kind=='path_traversal' else 'CWE-862',
                    'description':'Read-only controlled-fixture proof; baseline, denied/missing controls and two authenticated repeats satisfy the class contract.',
                    'evidence':'Authenticated proof-v2 captures; no scanner/model judgment used.','assertion':assertion,'proof':proof,
                    'parameter':case.get('parameter',''),
                    'impact':'The challenger obtained the exact reviewed private object of the other owned tenant.' if kind=='bola' else 'The exact reviewed outside-root canary file was read.' if kind=='path_traversal' else 'The limited owned role obtained the exact reviewed privileged read-function result.',
                    'remediation':'Enforce server-side object ownership and tenant authorization on every read.' if kind=='bola' else 'Resolve filenames under the permitted root and enforce containment after canonicalization.' if kind=='path_traversal' else 'Enforce server-side function authorization for each authenticated role; deny by default.',
                    **confirmation_fields(result,method='strict read replay')})
            attempt=ctx.storage.record_validation_attempt(verifier='strict-read-proof-v2.4',result=result,assertion=assertion,proof=proof,finding_id=finding_id,test_execution_id=tx)
            if finding_id:ctx.storage.update_finding_verification(finding_id,confirmation_fields(result,method='strict read replay',validation_attempt_id=attempt))
            ctx.storage.complete_test_execution(tx,status='failed-security-control' if result['result']=='pass' else 'passed' if result['result']=='fail' else 'inconclusive',result_summary='; '.join(result['reasons']))
            summaries.append({'test_id':test_id,'vulnerability_class':kind,'result':result['result'],'finding_id':finding_id,'validation_attempt_id':attempt,'capture_refs':refs,'reasons':result['reasons'],'transport_errors':errors})
        report={'schema':'tbhm.strict-replay-results/1','cases':summaries,**ledger.report(),
                'status':'complete' if all(r['result']!='inconclusive' for r in summaries) else 'partial',
                'scope':'Only the explicit controlled canary files/read functions; denied tests are not an application-wide clean result.'}
        (out/'results.json').write_text(json.dumps(redact_value(report),indent=2)+'\n')
        ctx.log('OK' if report['status']=='complete' else 'WARN','controlled_validation_plane','Strict read replay: '+report['status'])
        if any(r['transport_errors'] for r in summaries):raise RequestBlocked('strict replay transport incomplete; report retained')
        return report
    finally:broker.close();ledger.close()
