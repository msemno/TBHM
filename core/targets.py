"""
Unified target accessors and conservative network-scope helpers.

Every network phase should derive hosts/URLs through this module.  The
registrable-domain resolver is deliberately offline and conservative: it uses
`tldextract`'s bundled Public Suffix List snapshot when available, then a
well-known multi-label suffix table plus a ccTLD heuristic.  IP literals are
never collapsed into pseudo-domains.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def _bare_host(value: str) -> str:
    """Strip scheme/port/path from a string and return a lower-case host.

    Handles IPv4, bracketed IPv6, host:port and full URLs.  Invalid/empty input
    returns an empty string rather than raising.
    """
    s = str(value or "").strip()
    if not s:
        return ""
    # A bare IPv6 literal must be recognized before URL parsing interprets its
    # colons as a host:port separator.
    try:
        ipaddress.ip_address(s.strip("[]"))
        return s.strip("[]").lower()
    except ValueError:
        pass
    try:
        parsed = urlparse(s if "://" in s else "//" + s)
        if parsed.hostname:
            return parsed.hostname.rstrip(".").lower()
    except Exception:
        pass
    return s.split("/", 1)[0].split(":", 1)[0].rstrip(".").lower()


def get_domains(ctx) -> list[str]:
    """Return de-duplicated hostnames/IPs from every configured target."""
    out: list[str] = []
    seen: set[str] = set()
    for target in getattr(ctx, "targets", []) or []:
        host = _bare_host(target)
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def get_url_targets(ctx) -> list[str]:
    """Return only explicit HTTP(S) URL inputs."""
    return [
        str(t) for t in (getattr(ctx, "targets", []) or [])
        if str(t).startswith(("http://", "https://"))
    ]


# Common delegated public suffixes used as an offline fallback.  The heuristic
# below covers additional ccTLD category forms (co.id, com.my, gov.xx, ...)
# without ever reducing them to the public suffix itself.
_MULTI_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "sch.uk", "police.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz", "geek.nz", "school.nz",
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk", "idv.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "k12.tr",
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr",
    "co.il", "org.il", "net.il", "gov.il", "ac.il", "muni.il", "k12.il",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg", "sci.eg",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa", "med.sa", "sch.sa",
    "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    "com.co", "net.co", "org.co", "gov.co", "edu.co",
    "co.id", "web.id", "or.id", "ac.id", "sch.id", "go.id", "mil.id",
    "com.my", "net.my", "org.my", "gov.my", "edu.my", "mil.my", "name.my",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk", "gob.pk", "gok.pk",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd", "ac.bd",
    "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
    "com.ec", "net.ec", "org.ec", "gob.ec", "edu.ec",
})

# Delegated category labels commonly used immediately below country-code TLDs.
_CCTLD_SECOND_LEVEL = frozenset({
    "ac", "co", "com", "edu", "gov", "gob", "go", "id", "mil", "net",
    "org", "or", "ne", "nom", "sch", "school", "web", "gen", "firm",
    "ind", "asn", "k12", "med", "name", "lg", "gr", "ad", "ed",
})


def _registrable_domain(host: str) -> str:
    """Return a safe registrable-domain approximation for *host*.

    `tldextract` is configured with `suffix_list_urls=()` so no network fetch is
    attempted.  If it is unavailable, the fallback never returns a public suffix
    such as ``co.uk`` or ``co.id`` as the target root.
    """
    host = _bare_host(host)
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if host == "localhost" or "." not in host:
        return host

    parts = [p for p in host.split(".") if p]
    try:
        import tldextract  # optional dependency
        extractor = tldextract.TLDExtract(suffix_list_urls=())
        ext = extractor(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass

    if len(parts) < 2:
        return host
    suffix2 = ".".join(parts[-2:])
    # Explicit table first; then a conservative ccTLD category heuristic.
    if len(parts) >= 3 and (
        suffix2 in _MULTI_LABEL_SUFFIXES
        or (len(parts[-1]) == 2 and parts[-2] in _CCTLD_SECOND_LEVEL)
    ):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def get_root_domains(ctx) -> list[str]:
    """Return de-duplicated registrable roots for all targets."""
    out: list[str] = []
    seen: set[str] = set()
    for domain in get_domains(ctx):
        root = _registrable_domain(domain)
        if root and root not in seen:
            seen.add(root)
            out.append(root)
    return out


def target_scope_allows(ctx, value: str) -> bool:
    """Conservative pre-request/pre-persistence scope decision.

    Explicit ``ctx.scope`` include/exclude rules always win.  When no explicit
    allowlist is configured, the host must still be the configured target, its
    subdomain, or share the safely resolved registrable root.  This prevents an
    arbitrary URL discovered in JavaScript/source data from being contacted just
    because the generic Scope object has no include list.
    """
    host = _bare_host(value)
    if not host:
        return False

    scope = getattr(ctx, "scope", None)
    # v4-fix: an explicit allowlist is the SOLE authority ONLY when it actually has
    # include patterns. TBHM always constructs ctx.scope, and Scope([], []).allows()
    # returns True for EVERYTHING (empty include list = allow-all) — so keying on
    # "scope is not None" would authorize arbitrary external hosts (google.com) when
    # no --scope file was given. Gate on scope.has_includes instead.
    if scope is not None and getattr(scope, "has_includes", False):
        try:
            return bool(scope.allows(value))
        except Exception:
            return False
    # No real allowlist: still honor excludes via scope.allows (excludes work even
    # with an empty include set), then restrict to the configured targets only.
    if scope is not None:
        try:
            if not scope.allows(value):
                return False
        except Exception:
            return False

    # No explicit allowlist configured. Apply substring excludes, then authorize
    # ONLY the exact configured targets — NOT arbitrary siblings under the shared
    # registrable root. Auto-authorizing every *.apex host from a single exact
    # target (e.g. api.example.com -> admin.example.com) is out-of-scope contact.
    lowered = str(value or "").lower()
    for pattern in getattr(ctx, "scope_excludes", []) or []:
        if pattern and str(pattern).lower() in lowered:
            return False

    domains = get_domains(ctx)
    if host in domains:
        return True
    # Allow a subdomain of an EXPLICITLY configured target host (api.example.com
    # covers v2.api.example.com), but do not expand to the bare registrable root.
    return any(host == d or host.endswith("." + d) for d in domains)


def primary_label(ctx) -> str:
    """First target host, used only for display labels."""
    targets = getattr(ctx, "targets", []) or []
    return _bare_host(targets[0]) if targets else ""
