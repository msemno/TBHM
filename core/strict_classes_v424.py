"""Narrow, read-only proof extensions. Captures, never imported flags, are authority."""
from __future__ import annotations
import hashlib
import json
import re
from urllib.parse import urlsplit, parse_qsl

CLASSES = frozenset({'path_traversal', 'bfla'})


class ControlHeld(ValueError):
    """Complete, stable negative evidence for this exact approved test."""


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _status(row):
    value = row['response'].get('status')
    _require(type(value) is int, 'integer captured status required')
    return value


def _text(row):
    value = row['response'].get('body')
    _require(isinstance(value, str) and len(value.encode()) <= 200000, 'bounded captured UTF-8 text required')
    return value


def _success(row):
    return 200 <= _status(row) < 300


def _identity(a, b):
    return (a['actor_id'], a['identity_sha256']) == (b['actor_id'], b['identity_sha256'])


def _object(row):
    try:
        value = json.loads(_text(row))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def verify(assertion, proof, root):
    # Imported lazily to keep the original three contracts independent.
    from core.proof_contracts import _read_capture, _same_request
    kind, test_id = assertion['vulnerability_class'], assertion['test_id']
    _require(assertion.get('controlled_fixture') is True and
             isinstance(assertion.get('scope_reference'), str) and
             1 <= len(assertion['scope_reference']) <= 300, 'reviewed controlled-fixture/scope declaration required')
    refs = proof.get('captures') or {}
    base, mutation, negative = [_read_capture(root, refs[k], test_id, k, kind)
                                for k in ('baseline', 'mutation', 'negative_control')]
    repeats = [_read_capture(root, r, test_id, 'repeat', kind) for r in refs.get('repeats', [])]
    _require(2 <= len(repeats) <= 10, 'two distinct repeat captures required')
    rows = [base, mutation, negative]+repeats
    anonymous = None
    if kind == 'bfla':
        anonymous = _read_capture(root, refs['privacy_control'], test_id, 'privacy_control', kind)
        rows.append(anonymous)
    _require(len({r['capture_id'] for r in rows}) == len(rows), 'capture replay/duplicate refused')
    origin = urlsplit(mutation['request']['url'])
    origin = (origin.scheme, origin.hostname, origin.port or (443 if origin.scheme == 'https' else 80))
    for row in rows:
        req = row['request']; url = urlsplit(req['url'])
        _require((url.scheme, url.hostname, url.port or (443 if url.scheme == 'https' else 80)) == origin,
                 'all captures must use the same explicit origin')
        _require(req.get('method') == 'GET' and req.get('body', '') == '' and not url.fragment and url.username is None,
                 'read-only GET capture without credentials in URL required')
    _require(all(_same_request(mutation, r) and _identity(mutation, r) for r in repeats), 'repeat request/identity mismatch')
    _require(_identity(mutation, negative), 'control identity mismatch')
    _require(_status(negative) in {401, 403, 404}, 'distinct denied/missing control required')
    _require(not _same_request(mutation, negative), 'negative control must be a distinct request')
    marker = assertion.get('canary')
    _require(isinstance(marker, str) and re.fullmatch(r'TBHM_[0-9a-f]{32}', marker), 'explicit 128-bit controlled canary required')
    _require(marker not in _text(negative), 'negative control also exposes controlled canary')
    _require(all(marker not in r['request']['url'] and marker not in str(r['request'].get('headers', {})) for r in rows),
             'canary must not be supplied in a request')
    positive = [mutation]+repeats
    if kind == 'path_traversal':
        _require(all(_identity(base, r) for r in rows), 'traversal requests must use one identity')
        parameter = assertion.get('parameter')
        _require(isinstance(parameter, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,60}', parameter), 'explicit query parameter required')
        names = [assertion.get(k) for k in ('baseline_value', 'traversal_value', 'missing_value')]
        normal, traversal, missing = names
        _require(isinstance(normal, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}\.txt', normal), 'owned public baseline filename required')
        _require(isinstance(traversal, str) and re.fullmatch(r'(?:\.\./){1,8}tbhm-proof-[0-9a-f]{32}\.txt', traversal),
                 'only a dedicated outside-root TBHM canary file is verifiable')
        _require(isinstance(missing, str) and re.fullmatch(r'(?:\.\./){1,8}tbhm-missing-[0-9a-f]{32}\.txt', missing),
                 'dedicated nonexistent traversal control required')
        expected_path = urlsplit(base['request']['url']).path
        common = None
        for row, expected in [(base, normal), (mutation, traversal), (negative, missing)]+[(r, traversal) for r in repeats]:
            url = urlsplit(row['request']['url']); query = parse_qsl(url.query, keep_blank_values=True)
            _require(url.path == expected_path and [v for k, v in query if k == parameter] == [expected], 'query mutation is not bound to the reviewed traversal')
            rest = [(k, v) for k, v in query if k != parameter]
            if common is None: common = rest
            _require(rest == common, 'unrelated query parameters changed')
        digest = assertion.get('baseline_sha256')
        _require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest) and _success(base) and
                 hashlib.sha256(_text(base).encode()).hexdigest() == digest and marker not in _text(base),
                 'known public-file baseline hash required')
        checks = [_success(r) and _text(r) == marker for r in positive]
    else:
        _require(_same_request(base, mutation) and _success(base), 'privileged baseline must use the exact same endpoint')
        _require(base['identity_sha256'] and mutation['identity_sha256'] and
                 base['identity_sha256'] != mutation['identity_sha256'] and base['actor_id'] != mutation['actor_id'],
                 'distinct authenticated privileged and limited accounts required')
        _require(assertion.get('privileged_actor') == base['actor_id'] and assertion.get('limited_actor') == mutation['actor_id'] and
                 assertion.get('expected_limited_access') == 'deny', 'reviewed role separation and expected deny required')
        function_id = assertion.get('function_id')
        _require(isinstance(function_id, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', function_id), 'explicit protected read function required')
        expected = {'function_id': function_id, 'proof_canary': marker}
        exposes = lambda r: _success(r) and _object(r) == expected
        _require(exposes(base), 'privileged baseline lacks the controlled protected-function result')
        _require(_same_request(base, anonymous) and not anonymous['identity_sha256'] and
                 _status(anonymous) in {401, 403, 404} and marker not in _text(anonymous), 'anonymous same-function control must deny access')
        checks = [exposes(r) for r in positive]
    if not any(checks):
        # Only explicit stable denials disprove this case; echo/errors stay unknown.
        if all(_status(r) in {401, 403, 404} and marker not in _text(r) for r in positive):
            raise ControlHeld('reviewed mutation and both repeats were denied; this exact control held')
        raise ValueError('controlled impact absent or ambiguous; no confirmation')
    _require(all(checks), 'unstable/incomplete controlled impact across repeats')
    return base, mutation, negative, repeats
