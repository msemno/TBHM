"""Versioned confirmation contracts over authenticated local captures.

Imported JSON and legacy flags remain useful evidence, but cannot issue a
confirmation receipt. Captures are authenticated with a run-local 0600 key;
this protects against remote/imported evidence substitution, not a hostile local
operator who controls that key or the scanner process.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urljoin
from core.evidence_redaction import redact_value

SCHEMA = 'tbhm.proof/2'

class ConfirmationReceipt(dict):
    """An in-process capability; JSON round trips deliberately lose its type."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _key(root, create=False):
    path = Path(root) / '.proof-capture.key'
    if path.is_symlink():
        raise ValueError('capture key is a symlink')
    if create and not path.exists():
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'wb') as f:
                f.write(os.urandom(32))
    if path.stat().st_mode & 0o077:
        raise ValueError('capture key must have mode 0600')
    value = path.read_bytes()
    if len(value) != 32:
        raise ValueError('invalid capture key')
    return value


def capture_snapshot(root, *, test_id, vulnerability_class, role, actor_id, request, response):
    """Trusted adapter API: record a response it actually captured, before redaction.

    request has method/url/headers/body; response has status/headers/body. Never
    call this on an untrusted imported proof and describe it as a live capture.
    """
    root = Path(root).resolve(strict=True)
    headers = request.get('headers') or {}
    credentials = {str(k).lower(): str(v) for k, v in headers.items()
                   if str(k).lower() in {'authorization', 'cookie', 'x-api-key'}}
    row = redact_value({'schema': SCHEMA, 'capture_id': uuid.uuid4().hex,
                        'test_id': str(test_id), 'vulnerability_class': str(vulnerability_class),
                        'role': str(role), 'actor_id': str(actor_id),
                        'request': request, 'response': response,
                        'identity_sha256': hmac.new(_key(root, True), _canonical(credentials), hashlib.sha256).hexdigest()
                        if credentials else ''})
    data = _canonical(row)
    digest = hashlib.sha256(data).hexdigest()
    folder = root / 'evidence' / 'captures'
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (row['capture_id'] + '.json')
    with path.open('xb') as f:
        f.write(data)
    path.chmod(0o400)
    return {'path': path.relative_to(root).as_posix(), 'sha256': digest,
            'signature': hmac.new(_key(root, True), data, hashlib.sha256).hexdigest()}


def _read_capture(root, reference, test_id, role, vulnerability_class=None):
    root = Path(root).resolve(strict=True)
    path = root / str(reference['path'])
    if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root) or not path.resolve().is_relative_to(root / 'evidence' / 'captures'):
        raise ValueError('capture path outside capture directory')
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('capture exceeds proof budget')
    data = path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), str(reference['sha256'])):
        raise ValueError('capture digest mismatch')
    if not hmac.compare_digest(hmac.new(_key(root), data, hashlib.sha256).hexdigest(), str(reference['signature'])):
        raise ValueError('capture authentication failed')
    row = json.loads(data)
    if (row['schema'] != SCHEMA or row['test_id'] != test_id or row['role'] != role
            or (vulnerability_class and row['vulnerability_class'] != vulnerability_class)):
        raise ValueError('capture class/test/role binding mismatch')
    req = row['request']
    url = urlsplit(req['url'])
    if url.scheme not in {'http', 'https'} or not url.hostname:
        raise ValueError('invalid capture request URL')
    return row


def _body(row):
    body = row['response'].get('body', '')
    return json.loads(body) if isinstance(body, str) else body


def _same_request(a, b):
    return all(a['request'].get(k) == b['request'].get(k) for k in ('url', 'method', 'body'))


def _path_value(body, path):
    current = body
    for key in path.split('.'):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def verify_contract(assertion, proof, root):
    if assertion.get('schema') != SCHEMA or proof.get('schema') != SCHEMA:
        raise ValueError('version 2 captured proof required; legacy evidence needs revalidation')
    kind = assertion.get('vulnerability_class')
    if kind == 'bola':
        from core.strict_api_v425 import verify as verify_bola
        return verify_bola(assertion, proof, root)
    from core.strict_classes_v424 import CLASSES, verify
    if kind in CLASSES:
        return verify(assertion, proof, root)
    allowed = {'access_control', 'sensitive_data_exposure', 'open_redirect'}
    if kind not in allowed:
        raise ValueError('no audited confirmation contract for this vulnerability class')
    refs = proof.get('captures') or {}
    test_id = assertion['test_id']
    base = _read_capture(root, refs['baseline'], test_id, 'baseline', kind)
    mutation = _read_capture(root, refs['mutation'], test_id, 'mutation', kind)
    negative = _read_capture(root, refs['negative_control'], test_id, 'negative_control', kind)
    repeats = [_read_capture(root, ref, test_id, 'repeat', kind) for ref in refs.get('repeats', [])]
    rows = [base, mutation, negative] + repeats
    privacy = None
    if kind == 'access_control' and assertion.get('private_object_required') is True:
        privacy = _read_capture(root, refs['privacy_control'], test_id, 'privacy_control', kind)
        rows.append(privacy)
    if len(repeats) < 2 or len(repeats) > 10 or len({r['capture_id'] for r in rows}) != len(rows):
        raise ValueError('two distinct repeat captures required; counters are not proof')
    origin = urlsplit(mutation['request']['url'])
    origin = (origin.scheme, origin.hostname, origin.port)
    for row in rows:
        u = urlsplit(row['request']['url'])
        if (u.scheme, u.hostname, u.port) != origin:
            raise ValueError('proof requests must bind to the same target origin')
    if not all(_same_request(mutation, r) and r['actor_id'] == mutation['actor_id']
               and r['identity_sha256'] == mutation['identity_sha256'] for r in repeats):
        raise ValueError('repeat request/actor binding mismatch')
    if negative['actor_id'] != mutation['actor_id'] or negative['identity_sha256'] != mutation['identity_sha256']:
        raise ValueError('negative control must use the mutation identity')
    main = assertion.get('failure_conditions') or []
    controls = assertion.get('negative_control_conditions') or []
    if not main or not controls or len(main) > 50 or len(controls) > 50:
        raise ValueError('finite failure and negative-control assertions required')
    if any(c.get('source', 'mutation') != 'mutation' for c in main):
        raise ValueError('failure conditions must bind to the mutation')
    if any(c.get('source') != 'negative_control' for c in controls):
        raise ValueError('control conditions must bind to the negative control')
    if not any(c.get('type') not in {'status_equals', 'status_not_in'} for c in main):
        raise ValueError('HTTP status alone cannot prove a vulnerability')
    if kind == 'access_control':
        key = str(assertion.get('object_path') or 'id')
        owner_key = str(assertion.get('owner_path') or 'owner')
        owner_value = assertion.get('owner_value', base['actor_id'])
        expected = assertion.get('object_id')
        if expected is None or not _same_request(base, mutation):
            raise ValueError('owner baseline and mutation must request the same explicit object')
        if (not base['identity_sha256'] or not mutation['identity_sha256']
                or base['identity_sha256'] == mutation['identity_sha256']
                or base['actor_id'] == mutation['actor_id']):
            raise ValueError('distinct authenticated owner and mutation identities required')
        for r in [base, mutation] + repeats:
            body = _body(r)
            if (not 200 <= int(r['response'].get('status', 0)) < 300
                    or not isinstance(body, dict) or _path_value(body, key) != expected
                    or _path_value(body, owner_key) != owner_value):
                raise ValueError('response object/owner does not prove cross-actor access')
        if (_same_request(mutation, negative)
                or negative['request'].get('method') != mutation['request'].get('method')
                or int(negative['response'].get('status', 0)) not in {401, 403, 404}):
            raise ValueError('distinct denied/missing-object negative control required')
        try:
            control_body = _body(negative)
        except (ValueError, TypeError):
            control_body = None
        if (isinstance(control_body, dict) and _path_value(control_body, key) == expected
                and _path_value(control_body, owner_key) == owner_value):
            raise ValueError('negative control also exposes the protected object')
        if privacy:
            if (privacy['identity_sha256'] or not _same_request(base, privacy)
                    or int(privacy['response'].get('status', 0)) not in {401, 403, 404}):
                raise ValueError('anonymous same-resource control must deny access to the private object')
            try:
                privacy_body = _body(privacy)
            except (ValueError, TypeError):
                privacy_body = None
            if isinstance(privacy_body, dict) and _path_value(privacy_body, key) == expected:
                raise ValueError('anonymous control also returns the protected object')
    elif kind == 'sensitive_data_exposure':
        marker = str(assertion.get('private_marker') or '')
        if (not marker or not base['identity_sha256'] or mutation['identity_sha256']
                or not _same_request(base, mutation)):
            raise ValueError('authenticated baseline and anonymous same-resource mutation required')
        if any(marker not in str(r['response'].get('body', '')) for r in [base, mutation] + repeats):
            raise ValueError('private baseline marker missing in proof')
        if marker in str(negative['response'].get('body', '')):
            raise ValueError('negative control also exposes private marker')
    else:
        host = str(assertion.get('redirect_host') or '').lower()
        if not host:
            raise ValueError('explicit controlled redirect host required')
        for r in [mutation] + repeats:
            headers = {str(k).lower(): v for k, v in r['response'].get('headers', {}).items()}
            dest = urlsplit(urljoin(r['request']['url'], str(headers.get('location', '')))).hostname
            if not 300 <= int(r['response'].get('status', 0)) < 400 or dest != host:
                raise ValueError('mutation is not a redirect to the controlled host')
        for r in (base, negative):
            headers = {str(k).lower(): v for k, v in r['response'].get('headers', {}).items()}
            if urlsplit(urljoin(r['request']['url'], str(headers.get('location', '')))).hostname == host:
                raise ValueError('redirect also appears in baseline/control')
    return base, mutation, negative, repeats


def restore_confirmation(store, finding):
    finding.pop('_confirmation_receipt', None)
    attempt_id = finding.get('validation_attempt_id')
    if not attempt_id:
        finding['verified'] = False
        return
    row = store.conn.execute('SELECT * FROM validation_attempts WHERE id=? AND finding_id=?',
                             (attempt_id, finding['id'])).fetchone()
    if not row or row['run_id'] != finding.get('run_id'):
        finding['verified'] = False
        return
    try:
        assertion = json.loads(row['assertion_json'])
        proof = json.loads(row['proof_json'])
        mutation = _read_capture(store.db_path.parent, proof['captures']['mutation'], assertion['test_id'], 'mutation', assertion.get('vulnerability_class'))
        finding_url = str(finding.get('url') or '')
        if finding_url and finding_url != mutation['request']['url']:
            raise ValueError('finding/request target mismatch')
    except (KeyError, ValueError, TypeError, OSError):
        finding['verified'] = False
        return
    from core.assertion_engine import evaluate
    result = evaluate(json.loads(row['assertion_json']), json.loads(row['proof_json']),
                      evidence_root=store.db_path.parent)
    receipt = result.get('_confirmation_receipt')
    if isinstance(receipt, ConfirmationReceipt) and result['result'] == 'pass':
        finding['_confirmation_receipt'] = receipt
        finding['verified'] = True
        finding['verification_state'] = 'confirmed'
    else:
        finding['verified'] = False
        if finding.get('finding_class') == 'confirmed':
            finding['finding_class'] = 'supported'
        finding['validation_required'] = '; '.join(result.get('reasons', []))
