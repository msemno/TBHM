#!/usr/bin/env python3
"""Measured synthetic proof-contract regression, NOT vulnerability detection recall."""
from __future__ import annotations
import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.assertion_engine import evaluate
from core.evaluation import evaluate as confusion_matrix
from core.proof_contracts import SCHEMA, capture_snapshot
from test_support import captured_access_proof


def make_case(root, name, kind, vulnerable):
    root.mkdir(parents=True, exist_ok=True)
    if kind == 'access_control':
        assertion, proof = captured_access_proof(root, test_id=name)
        if not vulnerable:
            # Both suspect requests and repeats are denied under the policy.
            for role in ['mutation', 'repeat', 'repeat']:
                pass
            refs = proof['captures']
            def capture(role):
                return capture_snapshot(root, test_id=name, vulnerability_class=kind,
                    role=role, actor_id='other',
                    request={'url': 'https://example.test/api/users/2', 'method': 'GET',
                             'headers': {'Authorization': 'Bearer other-fixture-identity'}, 'body': ''},
                    response={'status': 403, 'headers': {}, 'body': '{}'})
            refs['mutation'] = capture('mutation')
            refs['repeats'] = [capture('repeat') for _ in range(2)]
        return assertion, proof

    url = 'https://fixture.example.test/check'
    def capture(role, actor, credential, status, body='', headers=None):
        return capture_snapshot(root, test_id=name, vulnerability_class=kind, role=role, actor_id=actor,
            request={'url': url, 'method': 'GET',
                     'headers': {'Authorization': credential} if credential else {}, 'body': ''},
            response={'status': status, 'headers': headers or {}, 'body': body})
    if kind == 'sensitive_data_exposure':
        marker = 'FAKE_PRIVATE_MARKER_8765'
        base = capture('baseline', 'owner', 'Bearer controlled-fixture', 200, marker)
        body = marker if vulnerable else 'not authorized'
        mutation = capture('mutation', 'anonymous', '', 200 if vulnerable else 403, body)
        control = capture('negative_control', 'anonymous', '', 403, 'not authorized')
        repeats = [capture('repeat', 'anonymous', '', 200 if vulnerable else 403, body) for _ in range(2)]
        assertion = {'schema': SCHEMA, 'test_id': name, 'vulnerability_class': kind,
            'private_marker': marker,
            'failure_conditions': [{'type': 'body_contains', 'source': 'mutation', 'value': marker}],
            'negative_control_conditions': [{'type': 'body_not_contains', 'source': 'negative_control', 'value': marker}]}
    elif kind == 'open_redirect':
        dest = 'https://controlled.example.test/'
        base = capture('baseline', 'owner', '', 200, 'normal')
        headers = {'Location': dest} if vulnerable else {'Location': '/home'}
        mutation = capture('mutation', 'owner', '', 302, '', headers)
        control = capture('negative_control', 'owner', '', 302, '', {'Location': '/home'})
        repeats = [capture('repeat', 'owner', '', 302, '', headers) for _ in range(2)]
        assertion = {'schema': SCHEMA, 'test_id': name, 'vulnerability_class': kind,
            'redirect_host': 'controlled.example.test',
            'failure_conditions': [{'type': 'header_equals', 'source': 'mutation', 'name': 'location', 'value': dest}],
            'negative_control_conditions': [{'type': 'header_equals', 'source': 'negative_control', 'name': 'location', 'value': '/home'}]}
    else:
        raise ValueError('unknown fixture kind')
    return assertion, {'schema': SCHEMA, 'captures': {'baseline': base, 'mutation': mutation,
                                                       'negative_control': control, 'repeats': repeats}}


def execute(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = output / 'signed-captures'
    labels, predictions, tamper = [], [], []
    for kind in ('access_control', 'sensitive_data_exposure', 'open_redirect'):
        for vulnerable in (False, True):
            for replicate in (1, 2):
                test_id = f'{kind}-{int(vulnerable)}-{replicate}'
                assertion, proof = make_case(cases, test_id, kind, vulnerable)
                result = evaluate(assertion, proof, evidence_root=cases)
                labels.append({'id': test_id, 'category': kind, 'vulnerable': vulnerable})
                predictions.append({'id': test_id, 'detected': result['result'] == 'pass'})
                if vulnerable:
                    # Proof tampering is a different metric from genuine detection accuracy.
                    for attack in ('bad_signature', 'replayed_capture', 'wrong_class', 'counter_only'):
                        a, p = copy.deepcopy(assertion), copy.deepcopy(proof)
                        if attack == 'bad_signature': p['captures']['mutation']['signature'] = '0'*64
                        elif attack == 'replayed_capture': p['captures']['repeats'][1] = p['captures']['repeats'][0]
                        elif attack == 'wrong_class': a['vulnerability_class'] = 'unknown_vuln'
                        else: p = {'schema': SCHEMA, 'repeatability': {'successful_proofs': 10}}
                        ret = evaluate(a, p, evidence_root=cases)
                        tamper.append({'class': kind, 'attack': attack, 'rejected': ret['result'] != 'pass'})
    lp, pp = output/'labels.json', output/'predictions.json'
    lp.write_text(json.dumps(labels, indent=2)+'\n')
    pp.write_text(json.dumps(predictions, indent=2)+'\n')
    scores = confusion_matrix(lp, pp)
    result = {'schema': 'tbhm.proof-fixture-evaluation/1',
              'scope': '12 generated local authenticated-capture cases (6 positive, 6 benign) for three existing strict proof classes. Does not measure real-world detector recall or false-positive rates.',
              'matrices': scores,
              'tamper_tests': {'tested': len(tamper), 'rejected': sum(t['rejected'] for t in tamper),
                               'examples': tamper},
              'unsupported_classes': ['sqli','reflected_xss','stored_xss','dom_xss','ssrf','ssti','path_traversal','deserialization','auth_session','csrf'],
              'unresolved_not_clean': True}
    (output/'proof_evaluation.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    result = execute(args.output_dir)
    print(json.dumps({'by_category': result['matrices']['by_category'],
                      'tamper_tests': result['tamper_tests']['tested'],
                      'tamper_rejected': result['tamper_tests']['rejected']}, indent=2))


if __name__ == '__main__': main()
