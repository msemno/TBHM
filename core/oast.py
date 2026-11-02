"""Opt-in, loopback-only out-of-band callback oracle for controlled labs.

A callback is **corroborating evidence**, not by itself a vulnerability or
confirmation receipt. No public listener, DNS service, external collaborator,
automatic network probe or implicit scan permission is provided by this module.
Every attempt uses a distinct random challenge; callbacks are bound to the
challenge and test-id. The ledger contains no request body or secret headers.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

MAX_EVENTS_PER_CHALLENGE = 8


def _iso():
    return datetime.now(timezone.utc).isoformat()


def _stable(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


class LocalOAST:
    """One approved, bounded local OAST experiment with immutable export."""

    def __init__(self, root, *, approved=False, offline=False, max_challenges=64):
        if not approved:
            raise PermissionError('explicit local-OAST testing approval required')
        if offline:
            raise PermissionError('offline mode forbids even local callback listeners')
        self.root = Path(root).resolve(strict=True)
        self.max_challenges = min(256, max(1, int(max_challenges)))
        from core.proof_contracts import _key
        self._key = _key(self.root, create=True)
        self._lock = threading.RLock()
        self._challenges = {}
        self._events = []
        self._closed = False
        self._server = None
        self._thread = None

    def __enter__(self):
        oracle = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                # Only a random path is accepted; no body/header is recorded.
                part = urlsplit(self.path).path.split('/')
                token = part[2] if len(part) == 3 and part[1] == 't' else ''
                accepted = oracle._receive(token, self.client_address[0])
                self.send_response(204 if accepted else 404)
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', '0')
                self.end_headers()
            def do_POST(self):
                self.send_error(405)
            def log_message(self, fmt, *args):
                pass

        self._server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def issue(self, *, test_id, role):
        if not isinstance(test_id, str) or not 1 <= len(test_id) <= 128:
            raise ValueError('bounded test_id required')
        if role not in {'baseline', 'mutation', 'negative_control', 'repeat'}:
            raise ValueError('unrecognized OAST proof role')
        with self._lock:
            if self._closed or self._server is None:
                raise RuntimeError('listener not running')
            if len(self._challenges) >= self.max_challenges:
                raise ValueError('challenge budget exhausted')
            token = secrets.token_urlsafe(24)
            self._challenges[token] = {'test_id': test_id, 'role': role,
                                       'issued_at': _iso(), 'events': 0}
            return {'test_id': test_id, 'role': role, 'token': token,
                    'url': f'http://127.0.0.1:{self._server.server_port}/t/{token}'}

    def _receive(self, token, remote_address):
        with self._lock:
            item = self._challenges.get(token)
            if (self._closed or not item or remote_address != '127.0.0.1'
                    or item['events'] >= MAX_EVENTS_PER_CHALLENGE):
                return False
            item['events'] += 1
            self._events.append({'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
                                 'test_id': item['test_id'], 'role': item['role'],
                                 'received_at': _iso(), 'listener': '127.0.0.1',
                                 'source': 'loopback-http-listener'})
            return True

    def result(self, test_id):
        """Read-only current correlations; never labels security impact."""
        with self._lock:
            rows = []
            for token, item in self._challenges.items():
                if item['test_id'] == test_id:
                    rows.append({'role': item['role'],
                                 'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
                                 'callback_count': item['events']})
            return {'test_id': test_id, 'status': 'correlation_only', 'attempts': rows,
                    'callbacks_observed': sum(r['callback_count'] for r in rows),
                    'meaning': 'A callback does not, by itself, prove SSRF or authorize confirmation.'}

    def export(self):
        """Export authenticated metadata only. No token or callback payload is stored."""
        with self._lock:
            if not self._closed:
                raise RuntimeError('close the observation window before exporting')
            data = {'schema': 'tbhm.oast/1', 'collection': 'loopback-controlled-lab',
                    'closed_at': _iso(), 'challenges': [
                        {'test_id': item['test_id'], 'role': item['role'],
                         'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
                         'issued_at': item['issued_at'], 'callback_count': item['events']}
                        for token, item in self._challenges.items()],
                    'events': list(self._events),
                    'classification': 'corroborating_observation_not_confirmation'}
            raw = _stable(data)
            receipt = {'sha256': hashlib.sha256(raw).hexdigest(),
                       'hmac_sha256': hmac.new(self._key, raw, hashlib.sha256).hexdigest()}
            out = self.root / 'evidence' / 'oast'
            out.mkdir(parents=True, exist_ok=True)
            path = out / ('session-' + secrets.token_hex(12) + '.json')
            with path.open('xb') as handle:
                handle.write(json.dumps({'record': data, 'receipt': receipt}, indent=2).encode())
            os.chmod(path, 0o400)
            return path

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def __exit__(self, *_):
        self.close()


def verify_export(root, artifact_path):
    """Verify the original sealed local callback ledger (not an SSRF verdict).

    The run-local signing key stays private and is not exported in delivery
    snapshots. Thus the exported artifact alone has a digest but is not
    independently attestable without access to the trusted original run.
    """
    from core.proof_contracts import _key
    root = Path(root).resolve(strict=True)
    path = Path(artifact_path)
    path = (root / path).absolute() if not path.is_absolute() else path
    allowed_dir = root / 'evidence' / 'oast'
    if not path.resolve().is_relative_to(allowed_dir) or path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('OAST artifact path or size rejected')
    payload = json.loads(path.read_text())
    record, receipt = payload['record'], payload['receipt']
    if record.get('schema') != 'tbhm.oast/1' or record.get('classification') != 'corroborating_observation_not_confirmation':
        raise ValueError('unsupported OAST report schema/classification')
    data = _stable(record)
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), str(receipt['sha256'])):
        raise ValueError('OAST record checksum mismatch')
    if not hmac.compare_digest(hmac.new(_key(root), data, hashlib.sha256).hexdigest(), str(receipt['hmac_sha256'])):
        raise ValueError('OAST report authentication failed')
    totals = {}
    for challenge in record['challenges']:
        fingerprint = challenge['token_sha256']
        if fingerprint in totals:
            raise ValueError('duplicate OAST token')
        totals[fingerprint] = int(challenge['callback_count'])
    counts = {fingerprint: 0 for fingerprint in totals}
    for event in record['events']:
        fingerprint = event['token_sha256']
        if fingerprint not in totals:
            raise ValueError('event without issued challenge')
        counts[fingerprint] += 1
    if counts != totals:
        raise ValueError('OAST callback counts inconsistent')
    return {'integrity': 'valid_run_local_signature',
            'callbacks_observed': len(record['events']),
            'classification': 'corroboration_only_not_confirmed'}
