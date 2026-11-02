"""Explicit, read-only two-account object authorization replay.

Accounts and objects must be operator-owned; credentials are read from named
environment variables. Plans are data, not proof. Only actual scoped HTTP
responses can enter the authenticated capture/confirmation pipeline.
"""
from __future__ import annotations
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit
import requests
from core import program_policy
from core.assertion_engine import evaluate, confirmation_fields
from core.evidence_redaction import register_secrets, redact_value
from core.http_policy import BudgetedSession
from core.proof_contracts import SCHEMA, capture_snapshot
from core.scoped_http import effective_rps
from core.targets import target_scope_allows

ACTION = 'api_authorization_read'
MAX_BYTES = 200000


def _url(value):
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError('bounded explicit HTTP(S) URL required')
    parsed = urlsplit(value)
    if (parsed.scheme not in {'https', 'http'} or not parsed.hostname or
            parsed.username is not None or parsed.fragment):
        raise ValueError('invalid URL authority, scheme or fragment')
    if parsed.scheme == 'http' and parsed.hostname not in {'127.0.0.1', '::1'}:
        raise ValueError('credentials require HTTPS; HTTP is restricted to numeric loopback fixtures')
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)


def prepare(ctx, path):
    if not getattr(ctx.args, 'approve_api_authz', False):
        raise PermissionError('--approve-api-authz is required for owned-account replay')
    if getattr(ctx.args, 'offline', False):
        raise PermissionError('offline mode forbids authorization replay')
    policy = getattr(ctx, 'program_policy', None)
    if not policy or not program_policy.evaluate_action(policy, ACTION, method='GET')['allowed']:
        raise PermissionError('reviewed program policy must permit api_authorization_read and GET')
    with Path(path).open('rb') as handle:
        raw = handle.read(1024*1024+1)
    if len(raw) > 1024*1024:
        raise ValueError('authorization plan exceeds 1 MiB')
    plan = json.loads(raw)
    if not isinstance(plan, dict) or plan.get('schema') != 'tbhm.api-authz/1':
        raise ValueError('expected tbhm.api-authz/1 plan')
    accounts, cases = plan.get('accounts'), plan.get('cases')
    if not isinstance(accounts, list) or not 2 <= len(accounts) <= 20:
        raise ValueError('2–20 explicitly owned test accounts required')
    if not isinstance(cases, list) or not 1 <= len(cases) <= 20:
        raise ValueError('1–20 bounded object cases required')
    identities = {}
    for account in accounts:
        if not isinstance(account, dict) or account.get('owned_test_account') is not True:
            raise ValueError('every account must declare owned_test_account=true')
        identity, env = account.get('id'), account.get('credential_env')
        if (not isinstance(identity, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', identity)
                or identity in identities or not isinstance(env, str)
                or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,120}', env)):
            raise ValueError('invalid/duplicate account id or credential environment name')
        credential = os.environ.get(env, '')
        if not credential or len(credential) > 8192 or any(c in credential for c in '\r\n'):
            raise ValueError('account credential missing or malformed in its environment variable')
        scheme, separator, payload = credential.partition(' ')
        register_secrets([credential, payload] if separator and scheme.lower() in {'bearer', 'basic'} else [credential])
        identities[identity] = credential
    normalized, seen = [], set()
    # Validate the complete plan before sending any requests.
    for case in cases:
        if not isinstance(case, dict) or case.get('owned_test_object') is not True:
            raise ValueError('each case must declare owned_test_object=true')
        if case.get('expected_challenger_access') != 'deny':
            raise ValueError('each case must explicitly expect challenger access to be denied')
        test_id, owner, challenger = (case.get(k) for k in ('test_id', 'owner', 'challenger'))
        if (not isinstance(test_id, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', test_id)
                or test_id in seen):
            raise ValueError('bounded unique test_id required')
        seen.add(test_id)
        if (owner not in identities or challenger not in identities or owner == challenger
                or identities[owner] == identities[challenger]):
            raise ValueError('owner/challenger require distinct owned accounts and credentials')
        target, control = case.get('url'), case.get('negative_control_url')
        if _url(target) != _url(control) or target == control:
            raise ValueError('control must be a distinct URL on the exact target origin')
        target, control = (requests.Request('GET', value).prepare().url for value in (target, control))
        if target == control:
            raise ValueError('control URL normalizes to the mutation URL')
        for url in (target, control):
            if (not target_scope_allows(ctx, url)
                    or program_policy.evaluate_asset(policy, url)['decision'] != 'in_scope'):
                raise PermissionError('authorization plan URL denied by explicit target/program scope')
        if not isinstance(case.get('object_id'), (str, int)) or isinstance(case['object_id'], bool):
            raise ValueError('explicit object_id string/integer required')
        if 'owner_value' in case and (not isinstance(case['owner_value'], (str, int)) or isinstance(case['owner_value'], bool)):
            raise ValueError('owner_value must be the expected owner string/integer')
        for field in ('object_path', 'owner_path'):
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,120}', case.get(field, 'id' if field == 'object_path' else 'owner')):
                raise ValueError('invalid dotted JSON object/owner path')
        normalized.append(dict(case, url=target, negative_control_url=control))
    return identities, normalized


def run(ctx):
    source = getattr(ctx.args, 'api_authz_plan', None)
    if not source:
        return None
    out = ctx.output/'evidence'/'api_authorization'
    out.mkdir(parents=True, exist_ok=True)
    summary = {'schema': 'tbhm.api-authz-results/1', 'cases': [], 'mode': 'owned-account-read-only'}
    try:
        identities, cases = prepare(ctx, source)
    except (ValueError, KeyError, TypeError, OSError, PermissionError) as exc:
        summary.update(status='blocked', reason=str(exc))
        ctx.log('WARN', 'authenticated_session_model', str(exc))
        (out/'results.json').write_text(json.dumps(redact_value(summary), indent=2)+'\n')
        return summary

    session = requests.Session()
    session._tbhm_action = ACTION
    session.headers.clear()  # No inherited authentication/default headers.
    broker = BudgetedSession(ctx, session, budget=6*len(cases), max_rps=effective_rps(ctx))
    try:
        for case in cases:
            test_id = 'api.authz.'+case['test_id']
            assertion = {'schema': SCHEMA, 'test_id': test_id, 'vulnerability_class': 'access_control',
                         'test_version': '2', 'object_id': case['object_id'], 'private_object_required': True,
                         'owner_value': case.get('owner_value', case['owner']),
                         'object_path': case.get('object_path', 'id'), 'owner_path': case.get('owner_path', 'owner'),
                         'failure_conditions': [{'type': 'json_path_equals', 'path': case.get('object_path', 'id'),
                                                 'value': case['object_id']}],
                         'negative_control_conditions': [{'type': 'status_not_in', 'source': 'negative_control',
                                                          'values': list(range(200, 300))}]}
            # The class contract independently checks success statuses and
            # proves the control does not return the protected owner/object.
            tx = ctx.storage.start_test_execution(test_id=test_id, test_version='2',
                phase='strict_finding_validation', target=case['url'],
                operation=ACTION, assertion=assertion, scope_decision='in_scope',
                policy_id=ctx.program_policy.get('policy_id', ''))
            row = {'test_id': test_id, 'url': case['url'], 'owner': case['owner'], 'challenger': case['challenger']}
            refs = {}
            try:
                def capture(role, actor, url):
                    # Redirects never followed; cookies cannot cross identities.
                    session.cookies.clear()
                    headers = {'Accept': 'application/json'}
                    if actor != 'anonymous': headers['Authorization'] = identities[actor]
                    response = broker.request('GET', url, timeout=(5, 15), stream=True, headers=headers)
                    with response:
                        body = bytearray()
                        for chunk in response.iter_content(32768):
                            body.extend(chunk)
                            if len(body) > MAX_BYTES:
                                raise ValueError('authorization response exceeds proof byte budget')
                        text = bytes(body).decode('utf-8', errors='strict')
                        return capture_snapshot(ctx.output, test_id=test_id, vulnerability_class='access_control',
                            role=role, actor_id=actor,
                            request={'url': response.request.url, 'method': 'GET',
                                     'headers': dict(response.request.headers), 'body': ''},
                            response={'status': response.status_code, 'headers': dict(response.headers), 'body': text})
                refs['baseline'] = capture('baseline', case['owner'], case['url'])
                refs['mutation'] = capture('mutation', case['challenger'], case['url'])
                refs['negative_control'] = capture('negative_control', case['challenger'], case['negative_control_url'])
                refs['privacy_control'] = capture('privacy_control', 'anonymous', case['url'])
                refs['repeats'] = [capture('repeat', case['challenger'], case['url']) for _ in range(2)]
                proof = {'schema': SCHEMA, 'captures': refs}
                result = evaluate(assertion, proof, evidence_root=ctx.output)
                finding_id = None
                if result['result'] == 'pass':
                    finding_id = ctx.save_finding({'phase': 'authenticated_session_model', 'severity': 'HIGH',
                        'confidence': 'HIGH', 'title': 'Cross-account access to an owned private API object',
                        'url': case['url'], 'target': case['url'], 'method': 'GET', 'cwe': 'CWE-639',
                        'description': 'A distinct owned challenger identity received the owner’s explicit test object.',
                        'evidence': 'Authenticated owner/challenger captures, denied/non-object control and two repeats.',
                        'impact': 'An account can read the specified private object belonging to another account.',
                        'remediation': 'Enforce object-level authorization for the authenticated principal on every read.',
                        'assertion': assertion, 'proof': proof})
                attempt = ctx.storage.record_validation_attempt(verifier='api-owned-account-proof-v2',
                    result=result, assertion=assertion, proof=proof, finding_id=finding_id, test_execution_id=tx)
                if finding_id:
                    ctx.storage.update_finding_verification(finding_id, confirmation_fields(result,
                        method='owned-account replay + control + two repeats', validation_attempt_id=attempt))
                status = 'failed-security-control' if result['result'] == 'pass' else 'inconclusive'
                ctx.storage.complete_test_execution(tx, status=status, result_summary='; '.join(result['reasons']))
                row.update(status=status, result=result['result'], finding_id=finding_id, validation_attempt_id=attempt,
                           capture_refs=refs, reasons=result['reasons'])
            except (requests.RequestException, ValueError, TypeError, OSError) as exc:
                ctx.storage.complete_test_execution(tx, status='inconclusive', error=str(exc))
                row.update(status='inconclusive', reason=str(exc))
            summary['cases'].append(row)
    finally:
        broker.close()
    summary['status'] = 'complete' if all(r['result'] == 'pass' for r in summary['cases'] if 'result' in r) and all('result' in r for r in summary['cases']) else 'partial'
    summary['requests_used'] = broker.used
    summary['meaning'] = 'Only the listed owned objects were tested. Denial, missing evidence and errors are inconclusive, never an application-wide clean result.'
    (out/'results.json').write_text(json.dumps(redact_value(summary), indent=2)+'\n')
    ctx.log('OK', 'authenticated_session_model', 'owned-account authorization cases: '+str(len(summary['cases'])))
    return summary
