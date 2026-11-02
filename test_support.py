"""Local behavioral fixtures for the packaged regression suite; no network use."""
import json
from pathlib import Path
from core.proof_contracts import capture_snapshot, SCHEMA
from core.assertion_engine import evaluate, confirmation_fields


def captured_access_proof(root, test_id='authz.cross-object.v2'):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    url = 'https://example.test/api/users/2'
    body = json.dumps({'id': 'B', 'owner': 'owner'})
    def capture(role, actor, authorization, target=url, response_body=body, status=200):
        return capture_snapshot(root, test_id=test_id, vulnerability_class='access_control', role=role, actor_id=actor,
            request={'url': target, 'method': 'GET', 'headers': {'Authorization': authorization}, 'body': ''},
            response={'status': status, 'headers': {'Content-Type': 'application/json'}, 'body': response_body})
    refs = {'baseline': capture('baseline', 'owner', 'Bearer owner-fixture-identity'),
            'mutation': capture('mutation', 'other', 'Bearer other-fixture-identity'),
            'negative_control': capture('negative_control', 'other', 'Bearer other-fixture-identity',
                                        target='https://example.test/api/users/missing', response_body='{}', status=404),
            'repeats': [capture('repeat', 'other', 'Bearer other-fixture-identity') for _ in range(2)]}
    assertion = {'schema': SCHEMA, 'test_id': test_id, 'vulnerability_class': 'access_control',
                 'object_id': 'B', 'object_path': 'id', 'owner_path': 'owner',
                 'failure_conditions': [{'type': 'json_path_equals', 'source': 'mutation', 'path': 'id', 'value': 'B'},
                                        {'type': 'status_equals', 'source': 'mutation', 'value': 200}],
                 'negative_control_conditions': [{'type': 'status_equals', 'source': 'negative_control', 'value': 404}]}
    return assertion, {'schema': SCHEMA, 'captures': refs}


def verified_fields(root):
    assertion, proof = captured_access_proof(root)
    result = evaluate(assertion, proof, evidence_root=root)
    if result['result'] != 'pass':
        raise AssertionError(result)
    return confirmation_fields(result, method='authenticated capture contract v2')
