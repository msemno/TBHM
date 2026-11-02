"""Sanitized one-shot completion notifications.

This module intentionally does not stream findings, evidence, targets, URLs,
credentials or filesystem paths.  It emits one bounded end-of-run status
message to an operator-supplied HTTPS webhook (or loopback HTTP for local
testing).  Redirects are rejected so credentials embedded in webhook URLs are
not forwarded to another origin.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlparse


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _allowed(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "invalid webhook URL"
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https" and host:
        return True, ""
    if parsed.scheme == "http" and host in {"127.0.0.1", "localhost", "::1"}:
        return True, ""
    return False, "webhook must use HTTPS (HTTP is allowed only for loopback testing)"


def send_completion(url: str, *, version: str, profile: str, status: str,
                    counts: dict[str, int]) -> tuple[bool, str]:
    ok, reason = _allowed(str(url or ""))
    if not ok:
        return False, reason
    safe_counts = {k: int(counts.get(k, 0) or 0)
                   for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    total = sum(safe_counts.values())
    message = (
        f"TBHM {version} run {status}. Profile={profile}; findings={total}; "
        + ", ".join(f"{k}={v}" for k, v in safe_counts.items())
        + ". No targets or evidence are included in this notification."
    )[:1800]
    body = json.dumps({"content": message, "text": message}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "TBHM-Notifier/3.9.6"},
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=10) as response:
            code = int(getattr(response, "status", 200) or 200)
        if 200 <= code < 300:
            return True, f"delivered (HTTP {code})"
        return False, f"webhook returned HTTP {code}"
    except urllib.error.HTTPError as exc:
        return False, f"webhook returned HTTP {exc.code}"
    except Exception as exc:
        return False, f"notification failed: {type(exc).__name__}"
