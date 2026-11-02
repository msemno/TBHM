"""
core/soft404.py   (v2.20)

Shared catch-all / soft-404 guard for phases that probe a FIXED path and decide
"exists" from the status code. On SPAs (200 + app shell) and API gateways
(200 + {"invalid_endpoint"}) every such probe fires. This lazily calibrates each
host once (two random paths) and caches the wildcard signature, then tells a
phase whether a given response is indistinguishable from that wildcard.

    from core import soft404
    if soft404.is_catch_all(base_url, resp.status_code, resp.text):
        continue   # drop — the host answers everything the same way

Fail-open: if calibration can't run (offline, no requests), returns False so real
behaviour is unchanged.
"""
from __future__ import annotations

import hashlib
import re
import secrets

try:
    import requests
except Exception:
    requests = None

_CACHE: dict[str, dict] = {}   # base -> {"status":int, "hash":str, "json_code":str} | None
_RAND = re.compile(r"[a-f0-9]{12,}", re.I)


def _sig(status: int, body: str) -> dict:
    # Arbitrary long hex strings can be meaningful object IDs or credentials.
    # Normalizing them away could hide a real, different response.
    norm = body or ''
    code = ""
    b = (body or "").strip()
    if b[:1] == "{":
        m = re.search(r'"code"\s*:\s*"([^"]+)"', b)
        if m:
            code = m.group(1).lower()
    return {"status": status,
            "hash": hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()[:16],
            "json_code": code}


def _calibrate(base: str) -> dict | None:
    if requests is None:
        return None
    sigs = []
    for _ in range(2):
        url = base.rstrip("/") + "/" + secrets.token_hex(10)
        try:
            r = requests.get(url, timeout=8, verify=False, allow_redirects=False)
        except Exception:
            return None
        sigs.append(_sig(r.status_code, r.text))
    # catch-all only if the two random paths look the same
    if sigs[0] == sigs[1]:
        return sigs[0]
    return None


def _base_of(url: str) -> str:
    m = re.match(r"(https?://[^/]+)", url or "")
    return m.group(1) if m else url


def is_catch_all(url: str, status: int, body: str) -> bool:
    """True if this response is indistinguishable from the host's wildcard."""
    base = _base_of(url)
    if base not in _CACHE:
        _CACHE[base] = _calibrate(base)
    wc = _CACHE[base]
    if not wc:
        return False
    cand = _sig(status, body)
    if wc.get("hash"):
        if cand["status"] == wc["status"] and cand["hash"] == wc["hash"]:
            return True
    # gateway JSON-code match (invalid_endpoint etc.)
    if (wc.get("json_code") and cand["json_code"] == wc["json_code"]
            and cand['status'] == wc['status'] and cand['hash'] == wc.get('hash')):
        return True
    return False
