"""
Diff Engine — Burp/ZAP-style baseline-vs-mutation comparison.

The single biggest reason why pro DAST tools have low false-positive rate:
> They establish a STATISTICAL BASELINE (N requests) before testing,
> then compare each mutation against the baseline's variance,
> not against a single reference response.

Why: modern apps have dynamic content (timestamps, CSRF tokens, ads, A/B tests).
A single-reference comparison fails on EVERY request. A statistical baseline
absorbs the noise.

This module:
  1. Collects baselines (3-5 requests, gathers status/length/timing distributions)
  2. Computes "stable parts" of the response (parts that don't change between baselines)
  3. Compares mutations against baselines using:
     - Status code shift
     - Length deviation (% from baseline mean)
     - Timing deviation (ms from baseline P95)
     - Content similarity (Jaccard on stable tokens)
     - New tokens introduced (reflection detection)
"""
from __future__ import annotations

import difflib
import re
import statistics
import time
from dataclasses import dataclass, field
from core.safe_writes import global_gate as _global_gate  # v2.23

try:
    import requests
except ImportError:
    requests = None


@dataclass
class ResponseSample:
    status: int
    length: int
    elapsed_ms: float
    body: str = ""
    headers: dict = field(default_factory=dict)


@dataclass
class Baseline:
    samples: list[ResponseSample] = field(default_factory=list)
    status_mode: int = 0                # most common status
    length_mean: float = 0
    length_stdev: float = 0
    time_mean: float = 0
    time_p95: float = 0
    stable_tokens: set = field(default_factory=set)  # tokens that appear in ALL samples
    dynamic_tokens: set = field(default_factory=set) # tokens that varied between samples
    
    @property
    def is_valid(self) -> bool:
        return len(self.samples) >= 2 and self.status_mode != 0


# ──────────────────────────────────────────────────────────────────────────────
# Token extraction for content similarity
# ──────────────────────────────────────────────────────────────────────────────
_WORD_RE = re.compile(r"\w{3,}")


def _tokens(s: str, max_tokens: int = 5000) -> set:
    """Extract bag of words for Jaccard comparison."""
    if not s:
        return set()
    return set(_WORD_RE.findall(s.lower())[:max_tokens])


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ──────────────────────────────────────────────────────────────────────────────
# Baseline collection
# ──────────────────────────────────────────────────────────────────────────────
def collect_baseline(method: str, url: str, headers: dict | None = None,
                     body: str | None = None, n: int = 3,
                     timeout: int = 15, verify: bool = False) -> Baseline:
    """
    Send the same request N times and build a statistical baseline.
    Returns Baseline object (.is_valid == False if requests failed).
    """
    if not requests:
        return Baseline()
    _ok, _why = _global_gate(method, url, body)
    if not _ok:
        return Baseline()  # v2.23: safe-writes gate blocked a mutating baseline
    samples = []
    for _ in range(n):
        try:
            t0 = time.time()
            r = requests.request(method, url, headers=headers or {},
                                 data=body, timeout=timeout, verify=verify,
                                 allow_redirects=False)
            elapsed = (time.time() - t0) * 1000
            samples.append(ResponseSample(
                status=r.status_code,
                length=len(r.content),
                elapsed_ms=elapsed,
                body=r.text[:50000],   # cap to 50KB for diffing
                headers=dict(r.headers),
            ))
        except Exception:
            continue
        time.sleep(0.1)   # tiny delay to avoid rate-limiting our own baseline

    if not samples:
        return Baseline()

    b = Baseline(samples=samples)
    # Status mode
    statuses = [s.status for s in samples]
    b.status_mode = statistics.mode(statuses) if len(set(statuses)) == 1 \
                    else max(set(statuses), key=statuses.count)

    # Length stats
    lengths = [s.length for s in samples]
    b.length_mean = statistics.mean(lengths)
    b.length_stdev = statistics.pstdev(lengths) if len(lengths) > 1 else 0

    # Timing stats
    times = sorted([s.elapsed_ms for s in samples])
    b.time_mean = statistics.mean(times)
    p95_idx = max(0, int(len(times) * 0.95) - 1)
    b.time_p95 = times[p95_idx]

    # Stable vs dynamic tokens
    if len(samples) >= 2:
        token_sets = [_tokens(s.body) for s in samples]
        b.stable_tokens = set.intersection(*token_sets) if token_sets else set()
        all_tokens = set.union(*token_sets) if token_sets else set()
        b.dynamic_tokens = all_tokens - b.stable_tokens

    return b


# ──────────────────────────────────────────────────────────────────────────────
# Comparison
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class DiffResult:
    # Raw measurements
    status: int = 0
    length: int = 0
    elapsed_ms: float = 0

    # Deltas vs baseline
    status_changed: bool = False
    length_pct_change: float = 0      # negative = shorter
    time_delta_ms: float = 0          # positive = slower than baseline P95
    content_similarity: float = 1.0   # 1.0 = identical, 0.0 = completely different
    new_tokens: set = field(default_factory=set)   # tokens NOT in baseline (potential reflection)
    reflected_payload: bool = False   # did the payload itself appear?

    # Verdicts (heuristic)
    error_indicators: list[str] = field(default_factory=list)
    suspicious_score: float = 0       # 0-100, higher = more suspicious

    response_body: str = ""           # captured for evidence


# Common error indicators across SQL engines, runtimes, frameworks
ERROR_PATTERNS = [
    # SQL
    (r"you have an error in your sql syntax",            "MySQL syntax error"),
    (r"warning: mysql",                                  "MySQL warning"),
    (r"unclosed quotation mark",                         "MSSQL error"),
    (r"quoted string not properly terminated",           "Oracle error"),
    (r"ora-0\d{4}",                                       "Oracle ORA error"),
    (r"postgresql.*error",                                "PostgreSQL error"),
    (r"sqlite_error",                                     "SQLite error"),
    (r"sqlstate\[\w+\]",                                  "PDO/SQLSTATE error"),
    # Runtime
    (r"stack trace:",                                     "Generic stack trace"),
    (r"java\.lang\.\w+exception",                         "Java exception"),
    (r"at\s+\w+\.\w+\.\w+\(\w+\.java:\d+\)",              "Java stack frame"),
    (r"traceback \(most recent call last\)",              "Python traceback"),
    (r"warning:\s*\w+\(\)\s*:",                           "PHP warning"),
    (r"<b>fatal error</b>:",                              "PHP fatal"),
    (r"system\.\w+\.\w+exception",                        ".NET exception"),
    # XML / XXE
    (r"system identifier .* failed",                      "XML SystemId failure"),
    # SSTI
    (r"jinja2\.exceptions",                               "Jinja2 error"),
    (r"freemarker\.template",                             "FreeMarker error"),
    # Path traversal targets
    (r"root:x:0:0:",                                      "Linux /etc/passwd content"),
    (r"\[boot loader\]",                                  "Windows boot.ini content"),
    (r"for 16-bit app support",                           "Windows win.ini content"),
]


def compare(baseline: Baseline, response: ResponseSample, payload: str = "") -> DiffResult:
    """Compare a response against a baseline. Compute deltas + suspicious score."""
    d = DiffResult(
        status=response.status,
        length=response.length,
        elapsed_ms=response.elapsed_ms,
        response_body=response.body[:5000],
    )

    if not baseline.is_valid:
        return d

    # Status change
    if response.status != baseline.status_mode:
        d.status_changed = True
        d.suspicious_score += 25  # status change is a strong signal

    # Length deviation
    if baseline.length_mean > 0:
        d.length_pct_change = (response.length - baseline.length_mean) / baseline.length_mean * 100
        if abs(d.length_pct_change) > 15:  # > 15% from mean
            d.suspicious_score += min(30, abs(d.length_pct_change) / 2)

    # Timing
    d.time_delta_ms = response.elapsed_ms - baseline.time_p95
    if d.time_delta_ms > 3000:  # > 3 sec slower than P95 → time-based
        d.suspicious_score += 40

    # Content similarity (Jaccard on stable tokens only)
    resp_tokens = _tokens(response.body)
    if baseline.stable_tokens:
        # Only count stable tokens (those that always appeared in baselines)
        kept = baseline.stable_tokens & resp_tokens
        d.content_similarity = len(kept) / len(baseline.stable_tokens) if baseline.stable_tokens else 1.0
        if d.content_similarity < 0.7:
            d.suspicious_score += 20

    # New tokens (potential reflection)
    all_baseline_tokens = baseline.stable_tokens | baseline.dynamic_tokens
    d.new_tokens = resp_tokens - all_baseline_tokens

    # Reflection: does the payload itself appear in the response?
    if payload and len(payload) >= 3:
        if payload in response.body:
            d.reflected_payload = True
            d.suspicious_score += 15

    # Error pattern matching
    body_lower = response.body.lower()
    for pattern, label in ERROR_PATTERNS:
        if re.search(pattern, body_lower, re.I):
            d.error_indicators.append(label)
            d.suspicious_score += 30  # strong signal

    d.suspicious_score = min(d.suspicious_score, 100)
    return d


# ──────────────────────────────────────────────────────────────────────────────
# Single-request helper
# ──────────────────────────────────────────────────────────────────────────────
def send_one(method: str, url: str, headers: dict | None = None,
             body: str | None = None, timeout: int = 15,
             verify: bool = False) -> ResponseSample | None:
    if not requests:
        return None
    _ok, _why = _global_gate(method, url, body)
    if not _ok:
        return None  # v2.23: safe-writes gate blocked a mutating request
    try:
        t0 = time.time()
        r = requests.request(method, url, headers=headers or {},
                             data=body, timeout=timeout, verify=verify,
                             allow_redirects=False)
        return ResponseSample(
            status=r.status_code, length=len(r.content),
            elapsed_ms=(time.time() - t0) * 1000,
            body=r.text[:50000], headers=dict(r.headers))
    except Exception:
        return None
