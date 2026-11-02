"""Shared scope-safe HTTP helpers for read-only discovery phases.

The key safety rule is enforced *before every request*, including redirects.
`requests`' automatic redirect handling is deliberately disabled because a
post-response check is too late: an out-of-scope redirect target has already
been contacted by then.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from core.targets import target_scope_allows
from core.http_policy import BudgetedSession, _ceiling


def network_discovery_enabled(ctx) -> bool:
    """Return False for passive/zero-touch profiles and zero request budgets."""
    profile = getattr(ctx, "profile", {}) or {}
    if str(profile.get("name", "")).lower() == "passive_only":
        return False
    if profile.get("active_probes") is False:
        return False
    return effective_rps(ctx) > 0


def effective_rps(ctx, default: float = 1.0) -> float:
    """Resolve the profile request rate without converting an explicit zero to 2."""
    profile = getattr(ctx, "profile", {}) or {}
    rate = profile.get("rate_limit", {}) or {}
    hard = profile.get('hard_limits', {}) or {}
    global_rps = _ceiling(rate.get('global_rps', default))
    ceilings = [global_rps, _ceiling(rate.get('per_target_rps', global_rps)),
                _ceiling(rate.get('hard_cap', 1e9)),
                _ceiling(hard.get('max_global_rps', 50)),
                _ceiling(hard.get('max_per_target_rps', 20)), 10.0]
    policy = getattr(ctx, 'program_policy', None)
    if policy:
        ceilings.append(_ceiling(policy.get('max_requests_per_second', 0)))
    return min(ceilings)


class _GetAdapter:
    """Keep the injected GET transport used by existing plugins and fixtures."""
    _tbhm_action = 'discovery'

    def __init__(self, transport): self.transport = transport

    def request(self, method, url, **kwargs):
        return self.transport.get(url, **kwargs)


def safe_get(ctx, requests_module, url: str, *, headers=None, timeout=15,
             verify=False, rate_limiter=None, max_redirects: int = 5):
    """Perform an in-scope GET with manually scope-checked redirects.

    Returns ``(response, final_url, redirect_chain)``.  Raises ``ValueError``
    before any out-of-scope request is sent. ``verify`` remains accepted for
    compatibility; the broker requires TLS verification or http_policy.ca_bundle.
    """
    current = str(url or "").strip()
    chain: list[str] = []
    broker = BudgetedSession(ctx, _GetAdapter(requests_module),
                             budget=max(0, int(max_redirects)) + 1,
                             max_rps=effective_rps(ctx))
    for _ in range(max(0, int(max_redirects)) + 1):
        parsed = urlparse(current)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"unsupported URL scheme: {parsed.scheme or 'none'}")
        if not target_scope_allows(ctx, current):
            raise ValueError(f"out-of-scope URL blocked before request: {current}")
        # The broker owns dispatch pacing; the legacy limiter parameter remains
        # accepted but cannot reserve separate slots or round fractional rates.
        response = broker.request(
            'GET', current, headers=headers or {}, timeout=timeout, verify=verify,
            allow_redirects=False,
        )
        chain.append(current)
        status = int(getattr(response, "status_code", 0) or 0)
        location = (getattr(response, "headers", {}) or {}).get("Location")
        if 300 <= status < 400 and location:
            nxt = urljoin(current, str(location))
            if not target_scope_allows(ctx, nxt):
                raise ValueError(f"out-of-scope redirect blocked before request: {nxt}")
            current = nxt
            continue
        return response, current, chain
    raise ValueError(f"redirect limit exceeded for {url}")
