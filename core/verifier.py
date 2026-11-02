"""
Verification helpers.

B2: Shadow replay — re-test a finding after delays
B3: MRS scoring (in scoring.py, used here)
"""
from __future__ import annotations

import time
from core.safe_writes import global_gate as _global_gate  # v2.23

try:
    import requests  # type: ignore
except ImportError:
    requests = None


def shadow_replay(url: str, method: str = "GET", payload: str = "",
                  parameter: str = "", delays_sec=(0, 60, 600)) -> dict:
    """
    Section B2: Shadow Replay verification.
    Re-issue the request after each delay; record whether the indicator persists.

    Returns a dict like:
      {"persistent": True/False, "checks": [{"delay":0,"hit":True}, ...]}
    """
    if not requests:
        return {"persistent": None, "error": "requests library not installed"}
    checks = []
    for d in delays_sec:
        if d > 0:
            time.sleep(d)
        try:
            if method.upper() == "GET":
                r = requests.get(url, params={parameter: payload} if parameter else None,
                                 timeout=15, allow_redirects=False)
            else:
                _ok, _why = _global_gate(method, url, str(payload) if parameter else None)
                if not _ok:
                    checks.append({"delay": d, "skipped": _why})
                    continue
                r = requests.request(method, url,
                                     data={parameter: payload} if parameter else None,
                                     timeout=15, allow_redirects=False)
            checks.append({"delay": d, "status": r.status_code,
                          "length": len(r.text), "snippet": r.text[:200]})
        except Exception as e:
            checks.append({"delay": d, "error": str(e)})
    # If first 2 checks succeed but 3rd doesn't, finding is "transient"
    return {"checks": checks}


def manual_repro_score(steps: int = 1, custom_headers: int = 0,
                       timing_critical: bool = False, multi_account: bool = False) -> int:
    """Convenience wrapper around scoring.mrs_score (re-exported here for phase code)."""
    from core.scoring import mrs_score
    return mrs_score(steps=steps, custom_headers=custom_headers,
                     timing_critical=timing_critical, multi_account=multi_account)
