"""
FP Engine — central False-Positive reduction utilities.

These are shared by any phase that wants higher-confidence findings:
  - soft_404_baseline() / is_soft_404_match()    — kill HTML 404-via-200 noise
  - boolean_differential()                        — AND 1=1 vs AND 1=2 SQLi proof
  - math_time_validate()                          — sleep(N) vs sleep(2N) ratio
  - waf_fingerprint()                             — Cloudflare/Akamai/Imperva/F5/AWS
  - confidence_score()                            — multi-signal 0-100 score

Design principle: every probe is gentle (1-3 requests max). No brute force.
No aggressive payloads. Used as a "second opinion" after a candidate is
found, not as a primary scanner.
"""
from __future__ import annotations
import hashlib
import re
import statistics
import time
import uuid
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs

try:
    import requests
except ImportError:
    requests = None


# ──────────────────────────────────────────────────────────────────────────────
# Soft 404 baseline
# ──────────────────────────────────────────────────────────────────────────────
class Baseline:
    """A fingerprint of how the server responds to a nonsense path/param."""
    __slots__ = ("status", "length", "content_type", "body_hash",
                 "body_prefix", "headers")

    def __init__(self, status: int, length: int, content_type: str,
                 body_hash: str, body_prefix: bytes, headers: dict):
        self.status = status
        self.length = length
        self.content_type = content_type
        self.body_hash = body_hash
        self.body_prefix = body_prefix
        self.headers = headers

    def to_dict(self) -> dict:
        return {
            "status": self.status, "length": self.length,
            "content_type": self.content_type, "body_hash": self.body_hash,
        }


def soft_404_baseline(base_url: str, method: str = "GET",
                      session=None, timeout: int = 10) -> Optional[Baseline]:
    """
    Hit a deliberately-nonexistent path on the same host. Returns Baseline
    so callers can compare their actual response against it.

    Idea: if a real 404 returns 200+HTML (the SPA's catch-all), every
    "200 OK" we see later needs to be compared against THIS baseline.
    """
    if not requests:
        return None
    s = session or requests.Session()
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    random_path = f"/__tbhm_probe_{uuid.uuid4().hex}_404"
    try:
        r = s.request(method, root + random_path, timeout=timeout,
                      verify=False, allow_redirects=False)
        body = r.content[:8000]
        return Baseline(
            status=r.status_code,
            length=len(r.content),
            content_type=(r.headers.get("Content-Type", "").split(";")[0].strip().lower()),
            body_hash=hashlib.sha256(body).hexdigest(),
            body_prefix=body[:500],
            headers=dict(r.headers),
        )
    except Exception:
        return None


def is_soft_404_match(response_status: int, response_body: bytes,
                      response_content_type: str,
                      baseline: Optional[Baseline],
                      tolerance: float = 0.08) -> bool:
    """
    True if the response looks identical to the soft-404 baseline,
    meaning it's almost certainly a false positive.
    """
    if baseline is None:
        return False
    if response_status != baseline.status:
        return False
    # Same content-type required
    rc = (response_content_type or "").split(";")[0].strip().lower()
    if rc and baseline.content_type and rc != baseline.content_type:
        return False
    body = response_body or b""
    # Identical body hash → definitely the same response
    h = hashlib.sha256(body[:8000]).hexdigest()
    if h == baseline.body_hash:
        return True
    # Length within tolerance + same content-type + HTML = almost certainly SPA fallback
    if baseline.length > 0:
        diff_ratio = abs(len(body) - baseline.length) / baseline.length
        if diff_ratio <= tolerance and "html" in rc:
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Boolean differential (SQLi-style)
# ──────────────────────────────────────────────────────────────────────────────
def boolean_differential(url: str, param: str, payload_true: str,
                         payload_false: str, baseline_url: str = None,
                         session=None, timeout: int = 15) -> dict:
    """
    Sends 3 requests: baseline (param=1), TRUE payload, FALSE payload.
    A real boolean-based SQLi has:  baseline ≈ TRUE  AND  baseline ≠ FALSE.

    Returns dict {confirmed, baseline_len, true_len, false_len,
                  true_similar, false_similar, confidence}.

    Confidence levels:
      HIGH:  TRUE matches baseline AND FALSE differs significantly (>10% length)
      MED:   FALSE differs but TRUE also differs a bit
      LOW:   no meaningful difference
    """
    if not requests:
        return {"confirmed": False, "confidence": "LOW",
                "reason": "requests unavailable"}
    s = session or requests.Session()
    base = baseline_url or url   # caller can pass a control URL

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    def _send(payload):
        qs2 = {k: v for k, v in qs.items()}
        qs2[param] = [payload]
        rebuilt = parsed._replace(query=urlencode(qs2, doseq=True)).geturl()
        try:
            r = s.get(rebuilt, timeout=timeout, verify=False)
            return len(r.content), r.text[:5000]
        except Exception:
            return None, None

    # 1. Baseline (no payload)
    base_len, base_body = _send("")
    if base_len is None:
        return {"confirmed": False, "confidence": "LOW",
                "reason": "baseline request failed"}

    # 2. TRUE
    t_len, t_body = _send(payload_true)
    # 3. FALSE
    f_len, f_body = _send(payload_false)
    if t_len is None or f_len is None:
        return {"confirmed": False, "confidence": "LOW",
                "reason": "payload request failed"}

    # Compute similarities (rough: shared 200-char chunks)
    def _similarity(a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        chunks_a = {a[i:i+50] for i in range(0, min(len(a), 4000), 50)}
        chunks_b = {b[i:i+50] for i in range(0, min(len(b), 4000), 50)}
        if not chunks_a:
            return 0.0
        return len(chunks_a & chunks_b) / max(len(chunks_a), len(chunks_b))

    t_similar = _similarity(base_body, t_body)
    f_similar = _similarity(base_body, f_body)
    len_diff_true  = abs(t_len - base_len) / max(base_len, 1)
    len_diff_false = abs(f_len - base_len) / max(base_len, 1)

    # Confirmed if: TRUE close to baseline (sim > 0.85) AND FALSE differs (sim < 0.70 OR length diff > 10%)
    confirmed = False
    confidence = "LOW"
    if t_similar > 0.85 and (f_similar < 0.70 or len_diff_false > 0.10):
        confirmed = True
        confidence = "HIGH"
    elif t_similar > 0.70 and f_similar < 0.50:
        confirmed = True
        confidence = "MEDIUM"

    return {
        "confirmed": confirmed,
        "confidence": confidence,
        "baseline_len": base_len,
        "true_len":  t_len,
        "false_len": f_len,
        "true_similar":  round(t_similar, 3),
        "false_similar": round(f_similar, 3),
        "len_diff_false_pct": round(len_diff_false * 100, 1),
        "reason": (f"TRUE similar to baseline ({t_similar:.2f}), "
                  f"FALSE differs (sim={f_similar:.2f}, lenΔ={len_diff_false*100:.1f}%)"
                  if confirmed else
                  f"signals inconclusive (TRUE sim={t_similar:.2f}, FALSE sim={f_similar:.2f})"),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Math time-based validation
# ──────────────────────────────────────────────────────────────────────────────
def math_time_validate(url: str, param: str, payload_template_n: callable,
                       session=None, base_timeout: int = 30) -> dict:
    """
    Validate a time-based SQLi/cmd-injection candidate using ratio proof.

    Args:
      payload_template_n: callable taking int N → payload string with sleep(N)
        Example: lambda n: f"' OR SLEEP({n})--"

    Sends 4 requests:
      A. baseline (no payload) — record T_base
      B. sleep(0) — record T_zero
      C. sleep(5) — record T_5
      D. sleep(10) — record T_10

    A real time-based vuln satisfies:
      T_5  ≈ T_base + 5
      T_10 ≈ T_base + 10
      (T_10 - T_5) ≈ 5  ←  THIS IS THE PROOF (network jitter cancels out)

    Returns dict {confirmed, t_base, t_5, t_10, delta, confidence, reason}.

    Mathematical proof: if (T_10 - T_5) is within [4, 6] seconds, the server
    is actually executing sleep(). Jitter from network can't produce this
    exact ratio coincidentally.
    """
    if not requests:
        return {"confirmed": False, "confidence": "LOW",
                "reason": "requests unavailable"}
    s = session or requests.Session()
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    def _timed_send(payload, timeout):
        qs2 = {k: v for k, v in qs.items()}
        if payload is not None:
            qs2[param] = [payload]
        rebuilt = parsed._replace(query=urlencode(qs2, doseq=True)).geturl()
        t0 = time.time()
        try:
            s.get(rebuilt, timeout=timeout, verify=False)
            return time.time() - t0
        except requests.exceptions.Timeout:
            return time.time() - t0
        except Exception:
            return None

    # A. baseline (no payload)
    t_base = _timed_send(None, base_timeout)
    if t_base is None:
        return {"confirmed": False, "confidence": "LOW",
                "reason": "baseline request failed"}

    # B-D. sleep(5) and sleep(10) — skip sleep(0) since it's just a syntax check
    payload_5  = payload_template_n(5)
    payload_10 = payload_template_n(10)
    t_5  = _timed_send(payload_5,  base_timeout + 6)
    t_10 = _timed_send(payload_10, base_timeout + 12)

    if t_5 is None or t_10 is None:
        return {"confirmed": False, "confidence": "LOW",
                "reason": "timed requests failed"}

    delta = t_10 - t_5
    # Strong confirmation: delta is between 4 and 7 seconds (5 ± 2 jitter)
    # AND both timed requests are slower than baseline by reasonable amount
    confirmed = False
    confidence = "LOW"
    if 4.0 <= delta <= 7.0 and t_5 >= t_base + 3.5 and t_10 >= t_base + 8.0:
        confirmed = True
        confidence = "HIGH"
    elif 3.0 <= delta <= 8.0 and t_5 >= t_base + 2.5:
        confirmed = True
        confidence = "MEDIUM"

    return {
        "confirmed": confirmed,
        "confidence": confidence,
        "t_base": round(t_base, 2),
        "t_5":    round(t_5, 2),
        "t_10":   round(t_10, 2),
        "delta":  round(delta, 2),
        "reason": (f"sleep(10) - sleep(5) = {delta:.2f}s "
                  f"(expected ~5s for real vuln, baseline={t_base:.2f}s)"
                  + (" — CONFIRMED" if confirmed else " — inconclusive")),
    }


# ──────────────────────────────────────────────────────────────────────────────
# WAF fingerprint
# ──────────────────────────────────────────────────────────────────────────────
WAF_SIGNATURES = [
    # (vendor, header_pattern, body_pattern)
    ("Cloudflare",       re.compile(r"^cf-(ray|cache-status)|cloudflare", re.I),
                         re.compile(r"cloudflare|cf-ray|attention required", re.I)),
    ("Akamai",           re.compile(r"akamaighost|akamai-grn|x-akamai", re.I),
                         re.compile(r"reference&#32;#\d+\.[a-f0-9]+", re.I)),
    ("Imperva/Incapsula", re.compile(r"x-iinfo|x-cdn.*incapsula", re.I),
                         re.compile(r"incident id|incapsula incident|_incapsula_resource", re.I)),
    ("F5 BIG-IP / ASM",  re.compile(r"x-waf-event-info|bigipserver|f5-trafficshield", re.I),
                         re.compile(r"The requested URL was rejected|support id is:", re.I)),
    ("AWS WAF",          re.compile(r"x-amzn-requestid|x-amzn-errortype.*WAF", re.I),
                         re.compile(r"AWS WAF|the request could not be satisfied", re.I)),
    ("Sucuri",           re.compile(r"x-sucuri-id|sucuri/cloudproxy", re.I),
                         re.compile(r"sucuri website firewall|access denied - sucuri", re.I)),
    ("Wordfence",        re.compile(r"wordfence", re.I),
                         re.compile(r"generated by wordfence|wordfence.*blocked", re.I)),
    ("ModSecurity",      re.compile(r"mod_security|modsecurity", re.I),
                         re.compile(r"mod_security|not acceptable.*apache", re.I)),
    ("Fastly",           re.compile(r"fastly-debug|x-fastly", re.I), None),
    ("Barracuda",        re.compile(r"barracuda", re.I),
                         re.compile(r"barracuda.*reference id", re.I)),
]


def waf_fingerprint(response_headers: dict, response_body: str) -> dict:
    """
    Identify if a response is a WAF challenge / block page. Returns:
      {is_waf: bool, vendor: str, confidence: HIGH|MEDIUM|LOW, evidence: str}
    """
    headers_str = " ".join(f"{k}: {v}" for k, v in response_headers.items())
    body_sample = (response_body or "")[:5000]
    for vendor, h_pat, b_pat in WAF_SIGNATURES:
        h_hit = h_pat and h_pat.search(headers_str)
        b_hit = b_pat and b_pat.search(body_sample)
        if h_hit and b_hit:
            return {"is_waf": True, "vendor": vendor, "confidence": "HIGH",
                    "evidence": f"both header ({h_hit.group(0)[:30]}) "
                               f"and body ({b_hit.group(0)[:30]}) match {vendor}"}
        if h_hit:
            return {"is_waf": True, "vendor": vendor, "confidence": "MEDIUM",
                    "evidence": f"header match: {h_hit.group(0)[:50]}"}
        if b_hit:
            return {"is_waf": True, "vendor": vendor, "confidence": "MEDIUM",
                    "evidence": f"body match: {b_hit.group(0)[:50]}"}
    return {"is_waf": False, "vendor": "", "confidence": "NONE", "evidence": ""}


# ──────────────────────────────────────────────────────────────────────────────
# Multi-signal confidence score
# ──────────────────────────────────────────────────────────────────────────────
def confidence_score(signals: dict) -> int:
    """
    Combine multiple signals into a 0-100 confidence score.

    Signal weights:
      baseline_differs:        +25  (response differs from soft-404 baseline)
      boolean_diff_confirmed:  +25  (1=1 vs 1=2 boolean SQLi proven)
      time_diff_confirmed:     +30  (sleep(5)/sleep(10) ratio proven)
      reflection_unencoded:    +20  (payload appears unescaped in body)
      browser_executed:        +30  (real alert() fired in headless browser)
      oob_callback:            +35  (out-of-band interaction received)
      live_key_validated:      +35  (API key actually works against service)
      waf_blocked:             -40  (response is a WAF challenge — likely FP)
      soft_404_match:          -50  (response matches baseline — definitely FP)
      content_type_mismatch:   -15  (returns HTML when API expected)

    Returns int in [0, 100].
    """
    weights = {
        "baseline_differs":       +25,
        "boolean_diff_confirmed": +25,
        "time_diff_confirmed":    +30,
        "reflection_unencoded":   +20,
        "browser_executed":       +30,
        "oob_callback":           +35,
        "live_key_validated":     +35,
        "differential_response":  +15,
        "waf_blocked":            -40,
        "soft_404_match":         -50,
        "content_type_mismatch":  -15,
        "third_party_host":       -25,
    }
    score = 0
    for k, v in signals.items():
        if v and k in weights:
            score += weights[k]
    return max(0, min(100, score))


def severity_from_score(score: int) -> str:
    """Translate a 0-100 confidence into HIGH/MEDIUM/LOW labels."""
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"
