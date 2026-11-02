"""
core/ratelimit.py   (v2.14)

Makes --rate-limit an AUTHORITATIVE ceiling. When the user passes --rate-limit N,
config sets rate_limit.hard_cap = N. Every phase that computes a tool rate runs it
through cap() so no wrapped tool (nuclei, ffuf, naabu, httpx) can exceed N req/sec.

Without --rate-limit, hard_cap is unset and cap() returns the phase's own value, so
default behaviour is unchanged.
"""
from __future__ import annotations


def cap(profile: dict, computed: int) -> int:
    """Clamp a phase's computed rate to the user's hard cap, if one is set."""
    hc = (profile or {}).get("rate_limit", {}).get("hard_cap")
    if hc:
        try:
            return max(1, min(int(computed), int(hc)))
        except (TypeError, ValueError):
            return computed
    return computed
