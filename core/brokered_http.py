"""Opt-in read-only HTTP replay through a parent-owned broker and shared ledger.

Only native calls and the packaged socket-isolated pipe protocol are supported.
Arbitrary scanners/browsers are incompatible. Budgets measure dispatched
requests and accepted decoded response-body bytes, not TLS/kernel/wire bytes.
The existing TBHM HTTP scope, rate, policy and cooldown gates remain in use.
"""
from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import subprocess
import sys
import time
from urllib.parse import urlsplit
import requests
from core import program_policy
from core.evidence_redaction import redact_text, redact_value, register_secrets
from core.http_policy import BudgetedSession, RequestBlocked
from core.offline_isolation import child_argv
from core.research_input import load, loads
from core.scoped_http import effective_rps
from core.targets import target_scope_allows

ACTION = 'brokered_http_read'


class SharedLedger:
    def __init__(self, path, request_limit, body_limit, requests_per_second=1000):
        if not math.isfinite(requests_per_second) or not .05 <= requests_per_second <= 1000:
            raise ValueError('broker pacing must fit the bounded .05–1000 rps range; lower program ceilings are incompatible')
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.path = Path(path)
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS quota(id INTEGER PRIMARY KEY, request_limit INTEGER, body_limit INTEGER,
          request_slots_used INTEGER DEFAULT 0, accepted_body_bytes INTEGER DEFAULT 0, reserved_body_bytes INTEGER DEFAULT 0, denied INTEGER DEFAULT 0,
          rate REAL, next_dispatch_epoch REAL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, source TEXT, target TEXT, outcome TEXT,
          reason TEXT, reserved INTEGER DEFAULT 0, body_bytes INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS cooldown(host TEXT PRIMARY KEY, until_epoch REAL);
        ''')
        self.db.execute('INSERT OR IGNORE INTO quota(id,request_limit,body_limit,rate) VALUES(1,?,?,?)', (request_limit, body_limit, requests_per_second))
        row = self.db.execute('SELECT request_limit,body_limit FROM quota WHERE id=1').fetchone()
        if row != (request_limit, body_limit): raise ValueError('shared ledger budget mismatch; cannot reset existing counters')
        self.db.execute('UPDATE quota SET rate=MIN(rate,?) WHERE id=1', (requests_per_second,))

    def deny(self, source, url, reason):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('UPDATE quota SET denied=denied+1 WHERE id=1')
            cursor = self.db.execute('INSERT INTO attempts(source,target,outcome,reason) VALUES(?,?,?,?)',
                (source, redact_text(url), 'blocked', redact_text(reason)))
            self.db.execute('COMMIT'); return cursor.lastrowid
        except BaseException: self.db.execute('ROLLBACK'); raise

    def reserve(self, source, url, maximum):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.db.execute('SELECT request_limit,body_limit,request_slots_used,accepted_body_bytes,reserved_body_bytes,next_dispatch_epoch,rate FROM quota WHERE id=1').fetchone()
            cooldown = self.db.execute('SELECT until_epoch FROM cooldown WHERE host=?', (urlsplit(url).hostname,)).fetchone()
            reason = ('shared host cooldown' if cooldown and cooldown[0] > time.time() else
                      'shared request budget exhausted' if row[2] >= row[0] else
                      'shared decoded-body reservation budget exhausted' if row[3]+row[4]+maximum > row[1] else
                      'shared pacing delay exceeds bounded wait' if row[5]-time.time() > 30 else '')
            if reason:
                self.db.execute('ROLLBACK'); self.deny(source, url, reason); raise RequestBlocked(reason)
            delay = max(0, row[5]-time.time())
            if delay: time.sleep(delay)
            self.db.execute('UPDATE quota SET request_slots_used=request_slots_used+1,reserved_body_bytes=reserved_body_bytes+?,next_dispatch_epoch=? WHERE id=1',
                (maximum, time.time()+1/row[6]))
            cursor = self.db.execute('INSERT INTO attempts(source,target,outcome,reason,reserved) VALUES(?,?,\'reserved\',\'\',?)',
                                     (source, redact_text(url), maximum))
            self.db.execute('COMMIT'); return cursor.lastrowid
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise

    def finish(self, identity, outcome, body_bytes, reason='', cooldown_url=None, cooldown_seconds=0):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.db.execute('SELECT reserved,outcome FROM attempts WHERE id=?', (identity,)).fetchone()
            if not row or row[1] != 'reserved' or not 0 <= body_bytes <= row[0]: raise ValueError('invalid/double ledger settlement')
            self.db.execute('UPDATE quota SET reserved_body_bytes=reserved_body_bytes-?,accepted_body_bytes=accepted_body_bytes+? WHERE id=1', (row[0], body_bytes))
            self.db.execute('UPDATE attempts SET outcome=?,reason=?,body_bytes=? WHERE id=?',
                            (outcome, redact_text(reason), body_bytes, identity))
            if cooldown_url:
                self.db.execute('INSERT INTO cooldown VALUES(?,?) ON CONFLICT(host) DO UPDATE SET until_epoch=MAX(until_epoch,excluded.until_epoch)',
                    (urlsplit(cooldown_url).hostname, time.time()+min(300, max(1, cooldown_seconds))))
            self.db.execute('COMMIT')
        except BaseException: self.db.execute('ROLLBACK'); raise

    def pause(self, url, seconds):
        self.db.execute('INSERT INTO cooldown VALUES(?,?) ON CONFLICT(host) DO UPDATE SET until_epoch=MAX(until_epoch,excluded.until_epoch)',
                        (urlsplit(url).hostname, time.time()+min(300, max(1, seconds))))

    def report(self):
        self.db.row_factory = sqlite3.Row
        quota = dict(self.db.execute('SELECT * FROM quota WHERE id=1').fetchone())
        rows = [dict(row) for row in self.db.execute('SELECT * FROM attempts ORDER BY id')]
        return {'quota': quota, 'attempts': rows, 'byte_unit': 'accepted decoded response-body bytes',
                'hard_wire_egress_guarantee': False, 'all_legacy_traffic_covered': False}

    def close(self): self.db.close()


class Broker:
    def __init__(self, ctx, ledger, *, max_body_bytes=65536, destination_pins=None, capture_observer=None):
        self.ctx, self.ledger, self.maximum = ctx, ledger, max_body_bytes
        self.capture_observer = capture_observer
        session = requests.Session(); session.headers.clear(); session._tbhm_action = ACTION
        session._tbhm_response_cap = max_body_bytes
        self.pins = None
        if destination_pins is not None:
            if getattr(ctx.args, 'proxy', None):
                raise RequestBlocked('proxy is unsupported in destination-pinned mode')
            from core.pinned_transport import install
            self.pins = install(session, destination_pins)
        session.hooks['response'].append(self._observe_headers)
        self.http = BudgetedSession(ctx, session, budget=1000, max_rps=effective_rps(ctx))

    def _observe_headers(self, response, *args, **kwargs):
        # Persist before body consumption: oversized/aborted 429/503 still pauses the host.
        if response.status_code in {429, 503}:
            from email.utils import parsedate_to_datetime
            from datetime import datetime, timezone
            raw = response.headers.get('Retry-After', '30')
            try: pause = float(raw)
            except ValueError:
                try:
                    date = parsedate_to_datetime(raw)
                    if date.tzinfo is None: date = date.replace(tzinfo=timezone.utc)
                    pause = (date-datetime.now(timezone.utc)).total_seconds()
                except (ValueError, TypeError, OverflowError): pause = 30
            self.ledger.pause(response.url, pause if math.isfinite(pause) else 30)

    def request(self, job, source):
        if self.pins is not None:
            from core.pinned_transport import serial_dispatch
            try:
                with serial_dispatch(self.ledger.path): return self._request(job, source)
            except RequestBlocked as exc:
                self.ledger.deny(source, job['url'], str(exc))
                return {'id': job['id'], 'status': 'blocked', 'reason': str(exc)}
        return self._request(job, source)

    def _request(self, job, source):
        url, method = job['url'], job.get('method', 'GET')
        def block(reason):
            self.ledger.deny(source, url, reason)
            return {'id': job['id'], 'status': 'blocked', 'reason': reason}
        if source not in {'native', 'pipe-v1'}: return block('driver incompatible with brokered mode')
        if getattr(self.ctx.args, 'offline', False): return block('offline mode forbids broker HTTP')
        if method not in {'GET', 'HEAD', 'OPTIONS'}: return block('only read-only HTTP methods supported')
        parsed = urlsplit(url)
        if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username is not None
                or parsed.fragment or not target_scope_allows(self.ctx, url)):
            return block('target URL scope/authority denied')
        policy = getattr(self.ctx, 'program_policy', None)
        if (not policy or program_policy.evaluate_asset(policy, url)['decision'] != 'in_scope'
                or not program_policy.evaluate_action(policy, ACTION, method=method)['allowed']):
            return block('reviewed program asset/action/method policy denied')
        if self.pins is not None:
            try: self.pins.resolve(url)
            except (ValueError, RequestBlocked) as exc: return block(str(exc))
        headers = {'Accept': '*/*'}
        credential_env = job.get('credential_env')
        if credential_env:
            value = os.environ.get(credential_env, '')
            if not value or any(c in value for c in '\r\n'): return block('credential environment value missing/invalid')
            if parsed.scheme != 'https' and parsed.hostname not in {'127.0.0.1', '::1'}:
                return block('credentialed request requires HTTPS')
            register_secrets([value, value.partition(' ')[2]])
            headers['Authorization'] = value
        try: identity = self.ledger.reserve(source, url, self.maximum)
        except RequestBlocked as exc: return {'id': job['id'], 'status': 'blocked', 'reason': str(exc)}
        count, digest, response = 0, hashlib.sha256(), None
        captured = bytearray() if self.capture_observer else None
        try:
            self.http.session.cookies.clear()
            response = self.http.request(method, url, headers=headers, timeout=(5, 15), stream=True)
            raw_length = response.headers.get('Content-Length')
            if method != 'HEAD' and raw_length and int(raw_length) > self.maximum:
                raise RequestBlocked('declared response body exceeds accepted-body cap')
            for chunk in response.iter_content(chunk_size=min(4096, self.maximum+1)):
                if count+len(chunk) > self.maximum: raise RequestBlocked('response body exceeds accepted-body cap')
                count += len(chunk); digest.update(chunk)
                if captured is not None: captured.extend(chunk)
            status = response.status_code
            pause = 0
            if status in {429, 503}:
                try: pause = min(300, max(1, int(response.headers.get('Retry-After', 30))))
                except (ValueError, TypeError): pause = 30
            capture_ref = self.capture_observer(job, response, bytes(captured)) if self.capture_observer else None
            self.ledger.finish(identity, 'observed', count, cooldown_url=url if pause else None, cooldown_seconds=pause)
            result = {'id': job['id'], 'status': 'observed', 'http_status': status, 'body_bytes': count,
                    'body_sha256': digest.hexdigest(), 'redirect_followed': False, 'finding_confirmed': False}
            if capture_ref is not None:
                result['capture_ref'] = capture_ref
            return result
        except (requests.RequestException, ValueError, OSError) as exc:
            self.ledger.finish(identity, 'incomplete', count, str(exc))
            return {'id': job['id'], 'status': 'incomplete', 'reason': redact_text(exc)}
        finally:
            if response is not None: response.close()

    def close(self): self.http.close()


def pipe_replay(broker, jobs, *, deadline_seconds=120):
    """Only the packaged protocol worker executes; direct sockets are denied."""
    worker = Path(__file__).resolve().parents[1]/'scripts'/'broker_pipe_worker.py'
    command = child_argv([sys.executable, '-I', '-S', str(worker)])
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, start_new_session=True, close_fds=True,
        env={'PATH': os.defpath, 'LANG': 'C.UTF-8', 'PYTHONNOUSERSITE': '1'})
    results, completed, isolation = [], set(), False
    selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
    until = time.monotonic()+min(300, max(1, deadline_seconds))
    try:
        lookup = {job['id']: job for job in jobs}
        while len(completed) < len(jobs) or not isolation:
            remaining = until-time.monotonic()
            if remaining <= 0: raise TimeoutError('pipe worker deadline')
            if not selector.select(timeout=min(5, remaining)): continue
            line = process.stdout.readline(8193)
            if not line or len(line) > 8192: raise ValueError('pipe worker closed or exceeded protocol budget')
            message = loads(line)
            if message == {'type': 'isolation', 'network_socket_denied': True} and not isolation:
                isolation = True
                process.stdin.write(json.dumps({'ids': [job['id'] for job in jobs]})+'\n'); process.stdin.flush()
                continue
            if not isolation or not isinstance(message, dict) or set(message) != {'id'}:
                raise ValueError('invalid pipe worker protocol')
            identity = message['id']
            if identity not in lookup or identity in completed: raise ValueError('unapproved/replayed worker request id')
            result = broker.request(lookup[identity], 'pipe-v1'); results.append(result); completed.add(identity)
            process.stdin.write(json.dumps({'id': identity, 'status': result['status']})+'\n'); process.stdin.flush()
        process.stdin.close(); process.wait(timeout=3)
        if process.returncode: raise ValueError('pipe worker unsuccessful')
        return results, {'isolation_check': 'network_socket_denied', 'worker_sha256': hashlib.sha256(worker.read_bytes()).hexdigest()}
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=3)
        for pipe in (process.stdin, process.stdout):
            if pipe and not pipe.closed: pipe.close()


def run(ctx):
    source = getattr(ctx.args, 'brokered_http_plan', None)
    if not source: return None
    if not getattr(ctx.args, 'approve_brokered_http', False) or getattr(ctx.args, 'offline', False):
        raise PermissionError('brokered replay requires --approve-brokered-http and online mode')
    plan = load(source, 1024*1024)
    if not isinstance(plan, dict) or plan.get('schema') != 'tbhm.brokered-http/1': raise ValueError('expected tbhm.brokered-http/1')
    jobs = plan.get('requests')
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= 100: raise ValueError('1–100 bounded requests required')
    seen = set()
    import re
    for job in jobs:
        if not isinstance(job, dict) or not isinstance(job.get('id'), str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', job['id']) or job['id'] in seen:
            raise ValueError('bounded unique broker request id required')
        seen.add(job['id'])
        if not isinstance(job.get('url'), str) or len(job['url']) > 4096: raise ValueError('bounded request URL required')
        job['url'] = requests.Request(job.get('method', 'GET'), job['url']).prepare().url
        if job.get('credential_env') and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,120}', job['credential_env']): raise ValueError('invalid credential environment name')
        if job.get('driver', 'native') not in {'native', 'pipe-v1'}: raise ValueError('driver is strict-mode-incompatible; no scanner/browser launched')
    request_limit, body_limit, cap = (plan.get(key, default) for key, default in [('request_limit', 20), ('body_limit', 1024*1024), ('max_response_body_bytes', 65536)])
    if any(type(v) is not int for v in (request_limit, body_limit, cap)) or not (1 <= request_limit <= 1000 and 1 <= cap <= 1024*1024 and cap <= body_limit <= 64*1024*1024):
        raise ValueError('invalid finite broker request/body budgets')
    out = ctx.output/'evidence'/'brokered_http'; out.mkdir(parents=True, exist_ok=True)
    ledger = SharedLedger(out/'ledger.sqlite3', request_limit, body_limit, effective_rps(ctx))
    broker = Broker(ctx, ledger, max_body_bytes=cap, destination_pins=plan.get('destination_pins'))
    results, worker = [], {}
    try:
        deadline = time.monotonic()+120
        for job in jobs:
            if job.get('driver', 'native') == 'native':
                if time.monotonic() >= deadline:
                    ledger.deny('native', job['url'], 'capability deadline exhausted')
                    results.append({'id': job['id'], 'status': 'blocked', 'reason': 'capability deadline exhausted'})
                else: results.append(broker.request(job, 'native'))
        child_jobs = [job for job in jobs if job.get('driver') == 'pipe-v1']
        if child_jobs:
            try:
                rows, worker = pipe_replay(broker, child_jobs, deadline_seconds=max(1, int(deadline-time.monotonic()))); results.extend(rows)
            except (ValueError, OSError, TimeoutError, subprocess.SubprocessError) as exc:
                worker = {'status': 'incomplete', 'reason': redact_text(exc)}
                results.extend({'id': job['id'], 'status': 'incomplete', 'reason': 'worker incomplete; inspect transactional attempt ledger'} for job in child_jobs)
        report = {'schema': 'tbhm.brokered-http-results/1', 'results': results, 'worker': worker,
                  'status': 'complete' if all(r['status'] == 'observed' for r in results) else 'partial', **ledger.report()}
        report['meaning'] = 'Read-only application observations through this capability only. No vulnerability proof is issued. Accepted decoded-body quotas are not a global wire/download meter; existing scanners and browser traffic remain outside this ledger.'
        (out/'results.json').write_text(json.dumps(redact_value(report), indent=2)+'\n')
        ctx.storage.save_observation(phase='controlled_validation_plane', observation_type='brokered_http_replay', target='explicit-plan',
            summary=report['status'], evidence={'request_slots_used': report['quota']['request_slots_used'], 'denied': report['quota']['denied'], 'worker': worker})
        ctx.log('OK', 'controlled_validation_plane', 'Brokered read replay: '+report['status'])
        if report['status'] != 'complete':
            raise RequestBlocked('brokered replay incomplete; inspect the persisted results and shared ledger')
        return report
    finally: broker.close(); ledger.close()
