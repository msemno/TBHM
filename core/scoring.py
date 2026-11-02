"""
Section 3.1 — Endpoint Scoring Algebra
Section 3.2 — Decay function (server fatigue model)
Section B3 — Manual Reproducibility Score (MRS)

These produce numbers used to PRIORITIZE which endpoints get tested first
and to PREDICT how reproducible a finding will be by hand.
"""
from __future__ import annotations

import math
import re
import time
from urllib.parse import urlparse, parse_qs


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint Scoring (3.1)
# Score range: roughly 0–100. Higher = more interesting / higher priority.
# ──────────────────────────────────────────────────────────────────────────────

SENSITIVITY_PATTERNS = [
    (r"/admin\b|/internal\b|/private\b|/dashboard\b|/console\b|/manage\b", 30, "admin/internal"),
    (r"/(pay|payment|billing|invoice|charge|refund|stripe|paypal|wallet|balance)\b", 25, "financial"),
    (r"/(user|profile|account|me|settings|email|phone|address|ssn|dob)\b", 20, "PII"),
    (r"/(upload|file|attachment|document|image|avatar|export|import|backup)\b", 15, "file ops"),
    (r"/(login|signin|auth|register|signup|password|reset|token|2fa|otp|oauth)\b", 10, "auth"),
    (r"/(api|graphql|webhook|callback|integration)\b", 8, "api"),
]

INPUT_HEAVY_HINTS = [
    (r"\.json($|\?|/)", 5, "json"),
    (r"\.xml($|\?|/)", 10, "xml"),
    (r"/(graphql|gql)\b", 15, "graphql"),
    (r"/(upload|file)\b", 15, "file_upload"),
]


def score_endpoint(url: str, method: str = "GET",
                   params: list[str] | None = None,
                   requires_auth: bool = False,
                   tech_stack: str = "") -> tuple[float, dict]:
    """
    Return (score, components_breakdown).
    components is a dict suitable for storage.save_endpoint_score.
    """
    components = {"sensitivity": 0, "auth_complexity": 0, "input_surface": 0,
                  "state_mutation": 0, "exposure": 0, "tags": []}

    parsed = urlparse(url)
    path = parsed.path.lower()

    # Sensitivity_Weight (×0.40)
    for pattern, weight, tag in SENSITIVITY_PATTERNS:
        if re.search(pattern, path):
            components["sensitivity"] += weight
            components["tags"].append(tag)
            break  # only one sensitivity bucket

    # Auth_Complexity (×0.20)
    if requires_auth:
        components["auth_complexity"] += 15
    if re.search(r"/oauth|/saml|/sso", path):
        components["auth_complexity"] += 10
    if re.search(r"/v[1-9]/", path):
        components["auth_complexity"] += 5

    # Input_Surface (×0.15)
    if params is None:
        # extract from URL query
        params = list(parse_qs(parsed.query).keys())
    components["input_surface"] += min(len(params), 10) * 2  # cap at 20
    for pattern, weight, tag in INPUT_HEAVY_HINTS:
        if re.search(pattern, url, re.I):
            components["input_surface"] += weight
            components["tags"].append(tag)

    # State_Mutation (×0.15)
    m = method.upper()
    if m in ("POST", "PUT", "PATCH", "DELETE"):
        components["state_mutation"] += 20
    if re.search(r"/(send|email|sms|notify|push)\b", path):
        components["state_mutation"] += 15
    if re.search(r"/(charge|pay|transfer|withdraw|buy|order)\b", path):
        components["state_mutation"] += 25

    # Exposure_Level (×0.10)
    if not requires_auth:
        components["exposure"] += 20
    if re.search(r"/(public|open|external)\b", path):
        components["exposure"] += 10

    raw_score = (
        components["sensitivity"]      * 0.40 +
        components["auth_complexity"]  * 0.20 +
        components["input_surface"]    * 0.15 +
        components["state_mutation"]   * 0.15 +
        components["exposure"]         * 0.10
    )
    # Cap at 100 for sanity
    score = min(raw_score, 100.0)
    components["raw_score"] = round(raw_score, 2)
    return score, components


# ──────────────────────────────────────────────────────────────────────────────
# Decay (3.2) — endpoint priority drops temporarily after recent scans
# ──────────────────────────────────────────────────────────────────────────────
def real_priority(base_score: float, scans_in_last_5min: int,
                  decay_lambda: float = 0.30) -> float:
    """
    Section 3.2: Real_Priority(endpoint, t) = Score × exp(-λ × scans_recent)
    Default λ = 0.3 means after 5 scans, priority is ~22% of original.
    """
    return base_score * math.exp(-decay_lambda * scans_in_last_5min)


# ──────────────────────────────────────────────────────────────────────────────
# Manual Reproducibility Score (B3)
# ──────────────────────────────────────────────────────────────────────────────
def mrs_score(steps: int = 1, custom_headers: int = 0,
              timing_critical: bool = False, multi_account: bool = False,
              non_default_method: bool = False) -> int:
    """
    100 = trivially reproducible (one curl). 0 = practically impossible.

    MRS = 100 - (steps × 5) - (headers × 3)
              - (timing_critical × 20) - (multi_account × 15) - (non_default_method × 5)
    """
    s = 100
    s -= max(steps - 1, 0) * 5
    s -= custom_headers * 3
    if timing_critical:  s -= 20
    if multi_account:    s -= 15
    if non_default_method: s -= 5
    return max(s, 0)


# ──────────────────────────────────────────────────────────────────────────────
# Scan tracker — for decay function. Cheap in-memory counter.
# ──────────────────────────────────────────────────────────────────────────────
class ScanTracker:
    def __init__(self):
        self._hits: dict[str, list[float]] = {}

    def record(self, url: str):
        self._hits.setdefault(url, []).append(time.time())

    def recent(self, url: str, window_sec: int = 300) -> int:
        now = time.time()
        hits = [t for t in self._hits.get(url, []) if now - t < window_sec]
        self._hits[url] = hits
        return len(hits)
