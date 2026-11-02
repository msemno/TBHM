"""Scope/policy/budget boundary for explicitly migrated HTTP adapters.

NEW transport adapter for S01. API and scoped discovery GETs are migrated;
browser and child processes are not covered by this class.
"""
from __future__ import annotations

import math
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import requests
from core.targets import target_scope_allows
from core import program_policy

_STATE_LOCK = threading.Lock()
_DISPATCH = threading.local()


class RequestBlocked(requests.RequestException):
    """A request was refused locally before transport or budget consumption."""


def _ceiling(value):
    try:
        value = float(value)
        return value if math.isfinite(value) and value > 0 else 0.0
    except (TypeError, ValueError):
        return 0.0


def _budget(value):
    try:
        return max(0, int(value))
    except (ValueError, TypeError, OverflowError):
        return 0


class BudgetedSession:
    """Shared per-context pacing and budget, plus an adapter attempt budget.

    The lock covers pacing and dispatch so workers cannot reserve slots then
    send together. Failed network attempts consume budget; local denials do not.
    Automatic redirects are always disabled. No retries or downloads are added.
    """
    def __init__(self, ctx, session, *, budget, max_rps):
        self.ctx = ctx
        self.session = session
        self.budget = _budget(budget)
        self.max_rps = _ceiling(max_rps)
        self.used = 0
        self._last = float('-inf')
        self._service_used = 0
        self._service_last = float('-inf')
        with _STATE_LOCK:
            state = getattr(ctx, '_http_policy_state', None)
            if state is None:
                config = (getattr(ctx, 'profile', {}) or {}).get('http_policy', {}) or {}
                state = {'lock': threading.RLock(), 'last': float('-inf'), 'hosts': {},
                         'budget': _budget(config.get('request_budget', 6000)), 'used': 0}
                ctx._http_policy_state = state
            self._state = state
            service_state = getattr(ctx, '_service_http_policy_state', None)
            if service_state is None:
                config = (getattr(ctx, 'profile', {}) or {}).get('http_policy', {}) or {}
                service_state = {'lock': threading.RLock(), 'last': float('-inf'), 'hosts': {},
                    'budget': _budget(config.get('service_request_budget', 2048)), 'used': 0}
                ctx._service_http_policy_state = service_state
            self._service_state = service_state
        if hasattr(session, 'trust_env'):
            session.trust_env = False

    @property
    def remaining(self):
        return max(0, min(self.budget - self.used,
                          self._state['budget'] - self._state['used']))

    def wait(self):
        # Compatibility with _request's existing limiter parameter. Pacing is
        # atomic with the actual dispatch below, not an independent pre-sleep.
        pass

    def _record_cooldown(self, host, reason):
        ledger = getattr(self.ctx, 'execution_ledger', None)
        if ledger is not None:
            key = (ledger.current_phase, host)
            notices = self._state.setdefault('cooldown_notices', set())
            if key not in notices:
                notices.add(key)
                ledger.record(kind='http_cooldown', status='partial', host=host, reason=reason)

    def request(self, method, url, **kwargs):
        from core.lifecycle import check
        check(self.ctx)
        parsed = urlparse(url)
        service = bool(getattr(self.session, '_tbhm_service', False))
        if service:
            from core.request_guard import permitted_service
            service = permitted_service(self.ctx, url)
        # Only the explicitly configured loopback inference service has a
        # separate budget. External enrichment retains the target budget.
        from core.llm_local import is_loopback_url
        local_service = service and is_loopback_url(url)
        state = self._service_state if local_service else self._state
        with state['lock']:
            cancelled = getattr(getattr(self.ctx, 'runner', None), '_cancel_event', None)
            if cancelled is not None and cancelled.is_set():
                raise RequestBlocked('scan cancelled; request not dispatched')
            if getattr(getattr(self.ctx, 'args', None), 'offline', False) and not service:
                raise RequestBlocked('offline mode forbids network requests')
            if (parsed.scheme not in {'http', 'https'} or not parsed.hostname
                    or parsed.username is not None or (not service and not target_scope_allows(self.ctx, url))):
                raise RequestBlocked('scope or URL authority denied')
            profile = getattr(self.ctx, 'profile', {}) or {}
            if not service and (profile.get('active_probes') is False or profile.get('name') == 'passive_only'):
                raise RequestBlocked('network probes disabled by profile')
            rate = profile.get('rate_limit', {}) or {}
            hard = profile.get('hard_limits', {}) or {}
            global_rps = min(_ceiling(rate.get('global_rps', 1)),
                             _ceiling(rate.get('hard_cap', float('1e9'))),
                             _ceiling(hard.get('max_global_rps', 50)))
            if service:
                global_rps = 1.0
            target_rps = min(_ceiling(rate.get('per_target_rps', global_rps)),
                             _ceiling(hard.get('max_per_target_rps', 20)))
            if service:
                target_rps = 1.0
            policy = getattr(self.ctx, 'program_policy', None)
            if policy and not service:
                if program_policy.evaluate_asset(policy, url)['decision'] != 'in_scope':
                    raise RequestBlocked('program asset policy denied')
                action = getattr(self.session, '_tbhm_action', 'api_fuzz')
                if not program_policy.evaluate_action(policy, action, method=method)['allowed']:
                    raise RequestBlocked('program action or method policy denied')
                global_rps = min(global_rps, _ceiling(policy.get('max_requests_per_second', 0)))
            if not min(global_rps, target_rps, self.max_rps):
                raise RequestBlocked('zero or invalid request rate')
            used = self._service_used if local_service else self.used
            if min(self.budget-used, state['budget']-state['used']) <= 0:
                raise RequestBlocked('local inference request budget exhausted' if local_service else 'request budget exhausted')
            now = time.monotonic()
            host = parsed.hostname.lower()
            if state.get('cooldowns', {}).get(host, 0) > now:
                self._record_cooldown(host, 'host cooldown blocked work after HTTP 429/503')
                raise RequestBlocked('host cooldown after HTTP 429/503; no automatic retry')
            last = self._service_last if local_service else self._last
            delay = max(0.0, state['last'] + 1/global_rps - now,
                        state['hosts'].get(host, float('-inf')) + 1/target_rps - now,
                        last + 1/self.max_rps - now)
            if delay:
                if cancelled is not None:
                    if cancelled.wait(delay):
                        raise RequestBlocked('scan cancelled during pacing; request not dispatched')
                else:
                    time.sleep(delay)
            now = time.monotonic()
            state['last'] = now
            state['hosts'][host] = now
            if local_service:
                self._service_last = now
                self._service_used += 1
            else:
                self._last = now
                self.used += 1
            state['used'] += 1
            kwargs['allow_redirects'] = False
            phase_deadline = getattr(self.ctx, '_phase_deadline', None)
            if phase_deadline is not None:
                remaining = max(.01, phase_deadline-time.monotonic())
                timeout = kwargs.get('timeout') or 30
                kwargs['timeout'] = tuple(min(float(v), remaining) for v in timeout) if isinstance(timeout, tuple) else min(float(timeout), remaining)
            # NEW secure policy defaults. The retained verify argument cannot
            # disable verification; interception requires an approved CA bundle.
            config = profile.get('http_policy', {}) or {}
            kwargs['verify'] = config.get('ca_bundle') or True
            headers = dict(getattr(self.session, 'headers', {}) or {})
            headers.update(kwargs.get('headers') or {})
            headers = {k: v for k, v in headers.items() if str(k).lower() != 'user-agent'}
            headers['User-Agent'] = config.get('user_agent') or 'Mozilla/5.0'
            kwargs['headers'] = headers
            proxy = getattr(getattr(self.ctx, 'args', None), 'proxy', None)
            if proxy:
                kwargs['proxies'] = {'http': proxy, 'https': proxy}
            previous = getattr(_DISPATCH, 'authorized', False)
            _DISPATCH.authorized = (str(method).upper(), str(url))
            try:
                response = self.session.request(method, url, **kwargs)
                if not service and getattr(response, 'status_code', 0) in (429, 503):
                    raw = str((getattr(response, 'headers', {}) or {}).get('Retry-After', ''))
                    try:
                        seconds = float(raw)
                    except ValueError:
                        try:
                            date = parsedate_to_datetime(raw)
                            if date.tzinfo is None:
                                date = date.replace(tzinfo=timezone.utc)
                            seconds = (date-datetime.now(timezone.utc)).total_seconds()
                        except (ValueError, TypeError, OverflowError):
                            seconds = 30
                    if not math.isfinite(seconds):
                        seconds = 30
                    self._state.setdefault('cooldowns', {})[host] = time.monotonic()+min(300, max(1, seconds))
                    self._record_cooldown(host, 'HTTP '+str(response.status_code)+' paused host; coverage incomplete')
                return response
            finally:
                _DISPATCH.authorized = previous

    def close(self):
        close = getattr(self.session, 'close', None)
        if close is not None:
            close()
