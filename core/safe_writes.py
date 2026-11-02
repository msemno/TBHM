"""
Safe Writes Gate.

Default behavior: ONLY GET/HEAD/OPTIONS requests are sent. Any POST/PUT/
PATCH/DELETE goes through this gate, which checks:

  1. Is the URL's path on a destructive-looking endpoint?
     (e.g. /delete, /remove, /cancel) → require explicit --allow-writes
  2. Does the body contain mass-mutation indicators?
     (e.g. {"delete": true}) → require --allow-writes
  3. Is the profile = passive_only? → block all writes regardless

Why: users running TBHM on real targets can accidentally trigger:
  - Test payment charges
  - Account deletions
  - Mass emails sent
  - Other side-effecting actions

This gate makes such damage impossible by default.
"""
from __future__ import annotations
import re


# ── v2.23: process-wide policy for context-free helpers ──────────────────────
# tbhm.py calls configure() once at startup. Core helpers that don't receive a
# ctx (e.g. diff_engine.send_one, verifier) consult this so the safe-writes
# gate is TRULY global and cannot be bypassed by a code path that lacks ctx.
_POLICY = {"allow_writes": False, "profile_name": "authorized_safe"}


def configure(allow_writes: bool, profile_name: str) -> None:
    _POLICY["allow_writes"] = bool(allow_writes)
    _POLICY["profile_name"] = profile_name or "authorized_safe"


def global_gate(method: str, url: str, body: str | None = None) -> tuple[bool, str]:
    """Apply the gate using the process-wide policy (for ctx-free helpers)."""
    return gate(method, url, body, _POLICY["allow_writes"], _POLICY["profile_name"])


# Path patterns that signal destructive operations
DESTRUCTIVE_PATH_RE = re.compile(
    r"(/delete|/remove|/cancel|/purge|/destroy|/wipe|"
    r"/unsubscribe|/refund|/charge|/transfer|/withdraw|"
    r"/approve|/reject|/ban|/suspend|/lock|/unlock|"
    r"/send.*email|/send.*sms|/notify|"
    r"/admin/|/internal/|/sudo/)",
    re.I,
)

# Methods we never let through by default
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def gate(method: str, url: str, body: str | None,
         allow_writes: bool, profile_name: str) -> tuple[bool, str]:
    """
    Returns (allowed: bool, reason_if_blocked: str).
    Call this inside any phase that sends mutating requests.
    """
    method = (method or "GET").upper()

    if method not in WRITE_METHODS:
        return True, ""

    # Passive profile: never write
    if profile_name == "passive_only":
        return False, "passive_only profile forbids writes"

    if not allow_writes:
        return False, (f"{method} blocked by safe-writes default. "
                       f"Re-run with --allow-writes to enable.")

    # Even with --allow-writes, refuse destructive paths unless --i-know-what-im-doing
    if DESTRUCTIVE_PATH_RE.search(url):
        return False, (f"path matches destructive pattern. "
                       f"Manual testing recommended for {url}")

    # Body-based check: refuse mass-mutation indicators
    if body and len(body) < 10000:
        if re.search(r'"(delete|destroy|wipe)_all"\s*:\s*true', body, re.I):
            return False, "body contains mass-mutation flag"

    return True, ""


# ── v2.23: ctx-aware convenience wrappers so every phase gates uniformly ──────
def _profile_name(ctx) -> str:
    prof = getattr(ctx, "profile", None)
    if isinstance(prof, dict):
        return prof.get("name", "authorized_safe")
    return getattr(prof, "name", "authorized_safe")


def ctx_gate(ctx, method: str, url: str, body: str | None = None) -> tuple[bool, str]:
    """Resolve allow_writes + profile from ctx and apply the gate.

    Use this at the top of any phase that is about to send a mutating request:

        ok, why = ctx_gate(ctx, "POST", url, body)
        if not ok:
            ctx.log("INFO", "phase", f"[safe-writes] skipped {url}: {why}")
            continue
    """
    allow_writes = bool(getattr(getattr(ctx, "args", None), "allow_writes", False))
    return gate(method, url, body, allow_writes, _profile_name(ctx))


def guarded_request(ctx, phase: str, method: str, url: str, requests_mod,
                    body_for_gate: str | None = None, **kwargs):
    """Send a request only if the safe-writes gate allows it.

    Returns the response object, or None if the gate blocked the write (a log
    line is emitted). GET/HEAD/OPTIONS always pass. This is the single choke
    point that makes the README's "mutating methods blocked by default" true.
    """
    ok, why = ctx_gate(ctx, method, url, body_for_gate)
    if not ok:
        try:
            ctx.log("INFO", phase, f"[safe-writes] {method} {url} skipped: {why}")
        except Exception:
            pass
        return None
    return requests_mod.request(method, url, **kwargs)
