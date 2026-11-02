"""Run-scoped guard for native Requests callers, including legacy adapters.

The CLI owns one active context per process. Browser and subprocess adapters
have separate contracts; this guard does not claim to sandbox arbitrary tools.
"""
from __future__ import annotations
import io
import threading
import time
from urllib.parse import urlsplit
import requests
from core.http_policy import BudgetedSession, RequestBlocked, _DISPATCH
from core.safe_writes import ctx_gate

_SEND = requests.Session.send
_REQUEST = requests.Session.request
_ACTIVE = None


def permitted_service(ctx, url):
    from core.llm_local import is_loopback_url
    u = urlsplit(url)
    args = ctx.args
    local = urlsplit(getattr(args, 'local_llm_url', None) or 'http://127.0.0.1:11434')
    if (is_loopback_url(url) and (u.scheme, u.hostname, u.port) == (local.scheme, local.hostname, local.port)
            and (getattr(args, 'local_llm', False) or not getattr(args, 'no_ai_observe', False))
            and u.path in {'/api/tags', '/api/ps', '/api/generate', '/api/chat', '/api/embeddings', '/api/embed'}):
        return True
    return (getattr(args, 'allow_external_enrichment', False) and not getattr(args, 'offline', False)
            and u.scheme == 'https' and u.netloc == 'api.osv.dev' and u.path == '/v1/querybatch')


def _bounded_send(ctx, session, prepared, kwargs):
    kwargs['allow_redirects'] = False
    kwargs['stream'] = True
    cfg = ctx.profile.get('http_policy', {}) or {}
    kwargs['verify'] = cfg.get('ca_bundle') or True
    # Local inference is an explicitly permitted loopback service. A scanner
    # interception proxy must never receive its prompts or override its bounded
    # inference timeout. Target traffic keeps the existing 30-second cap.
    from core.llm_local import is_loopback_url
    local_model = permitted_service(ctx, prepared.url) and is_loopback_url(prepared.url)
    cancelled = getattr(getattr(ctx, 'runner', None), '_cancel_event', None)
    if local_model and cancelled is not None and cancelled.is_set():
        raise RequestBlocked('scan cancelled; local inference deferred')
    proxy = None if local_model else getattr(ctx.args, 'proxy', None)
    kwargs['proxies'] = {'http': proxy, 'https': proxy} if proxy else {}
    timeout = kwargs.get('timeout') or (5, 20)
    ceiling = max(30, min(int(getattr(ctx.args, 'local_llm_timeout', 180) or 180), 900)) if local_model else 30
    # The old default profile ceiling silently shortened --local-llm-timeout
    # to 15 seconds. The explicit bounded inference budget is authoritative;
    # the caller's shorter deadline and phase lifecycle limits still apply.
    kwargs['timeout'] = tuple(min(max(float(v or 20), .1), ceiling) for v in timeout) if isinstance(timeout, tuple) else min(max(float(timeout), .1), ceiling)
    limit = min(int(cfg.get('max_response_bytes', 2 * 1024 * 1024)), 16 * 1024 * 1024)
    # An adapter may lower, never raise, the run-wide cap before buffering.
    limit = min(limit, max(1, int(getattr(session, '_tbhm_response_cap', limit))))
    from urllib3.util.retry import Retry
    for adapter in session.adapters.values():
        adapter.max_retries = Retry(total=0, redirect=0, connect=0, read=0, status=0)
    response = _SEND(session, prepared, **kwargs)
    data = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=65536):
            if local_model and cancelled is not None and cancelled.is_set():
                raise RequestBlocked('scan cancelled; local inference deferred')
            if len(data) + len(chunk) > limit:
                raise RequestBlocked('response byte budget exceeded; results incomplete')
            data.extend(chunk)
    finally:
        response.close()
    response._content = bytes(data)
    response._content_consumed = True
    response.raw = io.BytesIO(data)
    return response


def activate(ctx):
    global _ACTIVE
    _ACTIVE = ctx
    from core.soft404 import _CACHE
    _CACHE.clear()  # Calibration belongs to this run, not a prior auth/context.
    service_failures = {}

    def guarded_request(session, method, url, **kwargs):
        session.trust_env = False
        return _REQUEST(session, method, url, **kwargs)

    def send_recorded(session, prepared, options):
        started = time.monotonic()
        family = 'service_http' if permitted_service(ctx, prepared.url) else 'http'
        path = urlsplit(prepared.url).path
        purpose = ('generation' if path in {'/api/chat', '/api/generate'} else
                   'embedding' if path in {'/api/embed', '/api/embeddings'} else 'health')
        local_inference = family == 'service_http' and purpose != 'health'
        if local_inference and service_failures.get(purpose, 0) >= 3:
            reason = f'local {purpose} circuit open after 3 failures; review deferred until next run'
            ctx.execution_ledger.record(kind=family, status='blocked', url=prepared.url,
                required=bool(getattr(ctx.args, 'local_llm_required', False)), reason=reason)
            raise RequestBlocked(reason)
        try:
            response = _bounded_send(ctx, session, prepared, options)
        except Exception as exc:
            if local_inference and isinstance(exc, (requests.Timeout, requests.ConnectionError)):
                service_failures[purpose] = service_failures.get(purpose, 0) + 1
            ctx.execution_ledger.record(kind=family, status='network-error', url=prepared.url,
                required=bool(getattr(ctx.args, 'local_llm_required', False)),
                method=prepared.method, reason=str(exc)[:300], seconds=round(time.monotonic()-started, 3))
            raise
        if local_inference:
            service_failures[purpose] = (service_failures.get(purpose, 0) + 1
                                        if response.status_code >= 500 else 0)
        ctx.execution_ledger.record(kind=family, status='executed', method=prepared.method,
            required=bool(getattr(ctx.args, 'local_llm_required', False)),
            url=prepared.url, http_status=response.status_code,
            decoded_response_bytes=len(response.content), seconds=round(time.monotonic()-started, 3))
        return response

    def guarded_send(session, prepared, **kwargs):
        if getattr(_DISPATCH, 'authorized', None) == (prepared.method.upper(), prepared.url):
            _DISPATCH.authorized = None  # One dispatch; hooks must acquire their own budget.
            return send_recorded(session, prepared, kwargs)
        if getattr(ctx.args, 'offline', False) and not permitted_service(ctx, prepared.url):
            _blocked(ctx, prepared.url, 'offline mode forbids network requests')
        if not permitted_service(ctx, prepared.url):
            allowed, reason = ctx_gate(ctx, prepared.method, prepared.url, prepared.body)
            if not allowed:
                _blocked(ctx, prepared.url, reason)
        class Transport:
            _tbhm_action = ctx.execution_ledger.current_phase
            _tbhm_service = permitted_service(ctx, prepared.url)
            headers = {}
            def request(self, method, url, **options):
                prepared.headers.update(options.get('headers', {}))
                send_options = {k: v for k, v in options.items() if k != 'headers'}
                send_options.update({k: v for k, v in kwargs.items() if k not in {'verify', 'proxies', 'allow_redirects'}})
                _DISPATCH.authorized = None
                return send_recorded(session, prepared, send_options)
        try:
            return BudgetedSession(ctx, Transport(), budget=6000, max_rps=50).request(
                prepared.method, prepared.url, timeout=kwargs.get('timeout'), headers=dict(prepared.headers))
        except RequestBlocked as exc:
            _blocked(ctx, prepared.url, str(exc))
    requests.Session.request = guarded_request
    requests.Session.send = guarded_send


def _blocked(ctx, url, reason):
    ctx.execution_ledger.record(kind='service_http' if permitted_service(ctx, url) else 'http',
        status='blocked', url=url, reason=reason,
        required=bool(getattr(ctx.args, 'local_llm_required', False)))
    raise RequestBlocked(reason)


def deactivate():
    global _ACTIVE
    requests.Session.send = _SEND
    requests.Session.request = _REQUEST
    _ACTIVE = None
