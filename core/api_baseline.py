"""
core/api_baseline.py   (v2.13)

Defeats the catch-all / wildcard API gateway problem.

Some APIs answer EVERY path with HTTP 200 and an identical error envelope, e.g.
    {"status":false,"message":"Invalid endpoint.","code":"invalid_endpoint"}
That makes status-code and naive size fuzzing useless — every guess looks "found".

The fix here:
  1. CALIBRATE — fire a few random nonsense paths and fingerprint the catch-all
     response (status, length, body hash, and the JSON status/code/message fields).
  2. COMPARE  — for each candidate, only flag responses that DEVIATE from that
     baseline. The strongest signal is the JSON `code` field changing
     (invalid_endpoint -> method_not_allowed / unauthorized / validation_error),
     which is an inventory hint; gateway/WAF policy can also cause deviations.

Pure logic (signature/compare/classify) is separated from HTTP so it is unit
testable without a network. The HTTP layer is rate-limited (default 2 req/sec,
matching the "automated tool" limit programs commonly require).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field

# JSON code/message tokens suggesting different routing or gateway behavior.
# These are observations, not proof of an exposed asset or vulnerability.
AUTH_TOKENS = {
    "unauthorized", "authentication_required", "authentication_failed",
    "auth_required", "token_required", "token_invalid", "token_expired",
    "invalid_token", "missing_token", "forbidden", "access_denied",
    "permission_denied", "not_authenticated", "login_required",
}
METHOD_TOKENS = {
    "method_not_allowed", "method_not_supported", "invalid_method",
    "http_method_not_allowed",
}
PARAM_TOKENS = {
    "validation_error", "validation_failed", "missing_parameter",
    "missing_field", "missing_required_field", "invalid_request",
    "bad_request", "invalid_parameter", "invalid_input", "required",
    "invalid_payload", "malformed", "unprocessable_entity",
}
RAND_RE = re.compile(r"[a-z0-9]{16,}", re.I)


@dataclass
class Signature:
    status: int = 0
    length: int = 0
    body_hash: str = ""
    json_status: object = None      # the JSON "status" field, if present
    json_code: str = ""             # the JSON "code" field, if present
    json_message: str = ""          # the JSON "message" field, if present
    is_json: bool = False
    location: str = ""              # redirect target, if any

    def key(self) -> tuple:
        # Identity used to decide "are these two responses the same kind?"
        return (self.status, self.json_code, self.body_hash)


def make_signature(status: int, body: str, headers: dict | None = None,
                   strip_token: str | None = None) -> Signature:
    """Build a normalised fingerprint of a response."""
    headers = headers or {}
    norm = body or ""
    # Remove a reflected random token so the hash is stable across probes.
    if strip_token:
        norm = norm.replace(strip_token, "<RAND>")
    norm = RAND_RE.sub("<RAND>", norm)
    sig = Signature(
        status=status,
        length=len(body or ""),
        body_hash=hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()[:16],
        location=headers.get("Location", "") or headers.get("location", ""),
    )
    stripped = (body or "").strip()
    if stripped[:1] in ("{", "["):
        try:
            obj = json.loads(stripped)
            sig.is_json = True
            if isinstance(obj, dict):
                sig.json_status = obj.get("status", obj.get("success"))
                sig.json_code = str(obj.get("code", obj.get("error", obj.get("error_code", "")))).lower()
                sig.json_message = str(obj.get("message", obj.get("msg", obj.get("detail", ""))))[:200]
        except Exception:
            pass
    return sig


@dataclass
class Baseline:
    """Catch-all fingerprint for one host (+ method-specific variants)."""
    host: str = ""
    detected: bool = False           # True if the host behaves as a catch-all
    per_method: dict = field(default_factory=dict)   # method -> Signature

    def sig_for(self, method: str) -> Signature | None:
        return self.per_method.get(method.upper())


def detect_catch_all(signatures: list[Signature]) -> bool:
    """All nonsense paths returned the same kind of response => catch-all."""
    if len(signatures) < 2:
        return False
    keys = {s.key() for s in signatures}
    return len(keys) == 1


def classify(cand: Signature, base: Signature) -> tuple[bool, str, str]:
    """
    Compare a candidate response to the catch-all baseline.
    Returns (deviates, classification, severity).
    """
    # 404/410 are NOT-FOUND — never an endpoint discovery, regardless of baseline.
    if cand.status in (404, 410):
        return False, "", "INFO"

    if base is None:
        # No baseline: treat 2xx/4xx-with-content as a normal hit.
        if cand.status and cand.status < 500 and cand.status != 404:
            return True, "endpoint responded", "INFO"
        return False, "", "INFO"

    # If the body is byte-identical to the catch-all, it's not real even if the
    # status differs (SPA that serves the same shell under 200 and, say, 202).
    if cand.body_hash and cand.body_hash == base.body_hash:
        return False, "", "INFO"

    # 1) Different status code is interesting (except the not-found codes above).
    if cand.status != base.status:
        if cand.status in (401, 403):
            return True, "Access denied; endpoint existence unverified", "INFO"
        if cand.status == 405:
            return True, "Routing hint — method not allowed (try other verbs)", "INFO"
        if cand.status in (400, 422):
            return True, "Routing hint — needs parameters (validation error)", "INFO"
        if cand.status >= 500:
            return True, "Inconclusive server/gateway error; retry or validate manually", "INFO"
        if cand.status in (301, 302, 307, 308):
            return True, f"redirect -> {cand.location or '?'}", "INFO"
        if cand.status == 200:
            return True, "Response differs from baseline; review content", "INFO"
        return True, f"different status {cand.status}", "INFO"

    # 2) Same status (the hard case: gateway always 200). Use the JSON code.
    if cand.json_code and cand.json_code != base.json_code:
        if cand.json_code in AUTH_TOKENS:
            return True, f"Access denied response (code: {cand.json_code}); existence unverified", "INFO"
        if cand.json_code in METHOD_TOKENS:
            return True, f"Routing hint — wrong method (code: {cand.json_code})", "INFO"
        if cand.json_code in PARAM_TOKENS:
            return True, f"Routing hint — needs parameters (code: {cand.json_code})", "INFO"
        return True, f"Different error code: {cand.json_code}; validate routing", "INFO"

    # 3) Same status + same/empty code, but the body itself differs.
    if cand.body_hash != base.body_hash:
        # tolerate tiny deltas (reflected values) — require a real difference
        if abs(cand.length - base.length) > 8 or cand.json_message != base.json_message:
            return True, "Body differs from catch-all baseline; inventory only", "INFO"

    return False, "", "INFO"


class RateLimiter:
    """Simple global min-interval limiter. Default 2 req/sec."""
    def __init__(self, rps: float = 2.0):
        self.min_interval = 1.0 / max(0.1, rps)
        self._last = 0.0

    def wait(self):
        now = time.monotonic()
        delta = now - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.monotonic()
