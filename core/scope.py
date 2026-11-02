"""
core/scope.py   (v2.15)

Enforced scope filtering. Previously --scope (in-scope allowlist) was parsed but
never applied to the scan, so out-of-scope hosts could still receive traffic.
This module is wired into recon/discovery/crawl so:

  - --exclude patterns   -> host is dropped (denylist; excludes always win)
  - --scope patterns set  -> ONLY hosts matching an in-scope pattern are kept;
                             everything else is dropped (allowlist)
  - --scope not set       -> everything kept except excludes

Patterns are typed (see _compile): '=host' EXACT, '*.d' WILDCARD (no apex),
'.d'/'d' apex+subdomains. Matching is host-boundary anchored so 'domain.com'
never matches 'notdomain.com' or 'domain.com.evil.com'.
"""
from __future__ import annotations

import re


def _compile(patterns):
    """Compile scope patterns into one regex. Pattern grammar (typed):

      =api.example.com   EXACT host — matches ONLY api.example.com. No subdomains,
                         no apex. Use when a program lists a single hostname.
      *.example.com      WILDCARD — any subdomain (api., a.b.) but NOT the bare
                         apex example.com. Standard HackerOne wildcard semantics.
      .example.com       apex + subdomains (explicit form of the bare default).
      example.com        BARE (default) — apex + subdomains (subdomain-inclusive),
                         unchanged for backward compatibility.
      static*.example.com  '*' is a glob inside a label ([^/]*); combines with the
                         above (e.g. static1.example.com, *.sip.*.twilio.com).
    Excludes use the same grammar; excludes always win in Scope.allows().
    """
    if not patterns:
        return None
    parts = []
    for p in patterns:
        p = p.strip().lower()
        if not p or p.startswith("#"):
            continue
        if p.startswith("="):
            # EXACT host: anchor BOTH ends, no start-or-dot prefix -> no subdomains.
            esc = re.escape(p[1:]).replace(r"\*", "[^/]*")
            parts.append(rf"^{esc}(?::\d+)?/$")
        else:
            # Existing behavior (bare, leading-dot, and *. wildcard all handled by
            # the start-or-dot anchor + glob expansion — verified unchanged).
            body = p[1:] if p.startswith(".") else p
            esc = re.escape(body).replace(r"\*", "[^/]*")
            parts.append(rf"(?:^|\.){esc}(?::\d+)?(?:/|$)")
    if not parts:
        return None
    return re.compile("|".join(parts), re.I)


def _norm(host: str) -> str:
    """Reduce a URL or host[:port] to a comparable host string with a trailing /."""
    h = host.strip().lower()
    h = re.sub(r"^[a-z]+://", "", h)
    h = h.split("/")[0]
    return h + "/"


class Scope:
    def __init__(self, includes: list[str] | None, excludes: list[str] | None):
        self._inc = _compile(includes or [])
        self._exc = _compile(excludes or [])
        self.has_includes = self._inc is not None

    def allows(self, host: str) -> bool:
        h = _norm(host)
        if self._exc and self._exc.search(h):
            return False
        if self._inc:
            return self._inc.search(h) is not None
        return True

    def filter(self, hosts):
        """Filter an iterable of hosts/URLs, preserving type (set in, set out)."""
        if isinstance(hosts, set):
            return {h for h in hosts if self.allows(h)}
        return [h for h in hosts if self.allows(h)]
