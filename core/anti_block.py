"""
Anti-block Engine.

When a target's WAF / rate-limiter starts pushing back, this module:
  1. Detects the pushback (429, 403 with challenge body, captcha redirects)
  2. Slows down the global request rate
  3. Rotates User-Agent / Accept-Language to look more like a real browser

How phases use it:
  before = anti_block.headers_for(target_host)        # browser-like headers
  resp = requests.get(url, headers=before, ...)
  anti_block.observe(target_host, resp.status_code, len(resp.content))
  delay = anti_block.next_delay(target_host)
  time.sleep(delay)
"""
from __future__ import annotations
import random
import threading
import time
from collections import defaultdict, deque


# Real Chrome/Firefox/Safari user-agent strings (rotate to avoid pattern match)
USER_AGENTS = [
    # Chrome on macOS/Win/Linux
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Safari (iOS-like fingerprint kept short — avoid bot patterns)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,es;q=0.6",
]


class _HostState:
    """Per-host throttle + UA rotation state."""
    __slots__ = ("ua", "lang", "delay_ms", "consecutive_blocks", "last_request",
                 "recent_statuses")

    def __init__(self):
        self.ua = random.choice(USER_AGENTS)
        self.lang = random.choice(ACCEPT_LANGUAGES)
        self.delay_ms = 100               # 100ms baseline = 10 req/sec
        self.consecutive_blocks = 0
        self.last_request = 0.0
        self.recent_statuses = deque(maxlen=20)


_states: dict[str, _HostState] = defaultdict(_HostState)
_lock = threading.Lock()


def headers_for(host: str, extra: dict | None = None) -> dict:
    """Return browser-realistic headers for a request to `host`."""
    with _lock:
        s = _states[host]
    h = {
        "User-Agent":        s.ua,
        "Accept":            "text/html,application/xhtml+xml,application/xml;q=0.9,"
                              "image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":   s.lang,
        "Accept-Encoding":   "gzip, deflate, br",
        "DNT":               "1",
        "Connection":        "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest":    "document",
        "Sec-Fetch-Mode":    "navigate",
        "Sec-Fetch-Site":    "none",
        "Sec-Fetch-User":    "?1",
        "Cache-Control":     "max-age=0",
    }
    if extra:
        h.update(extra)
    return h


def observe(host: str, status: int, body_len: int = 0,
            body_snippet: str = "") -> None:
    """Phase callback: tell anti_block what the server replied with."""
    with _lock:
        s = _states[host]
        s.recent_statuses.append(status)

        # Detect a block / challenge
        is_block = (
            status in (429, 418, 503) or
            (status == 403 and (
                "challenge-platform" in body_snippet.lower() or
                "captcha" in body_snippet.lower() or
                "cf-ray" in body_snippet.lower() or
                "access denied" in body_snippet.lower()
            ))
        )

        if is_block:
            s.consecutive_blocks += 1
            # Exponential backoff: 1s, 2s, 4s, ... capped at 60s
            s.delay_ms = min(60_000, max(s.delay_ms * 2, 1000))
            # Rotate fingerprint after 3 consecutive blocks
            if s.consecutive_blocks >= 3:
                s.ua = random.choice(USER_AGENTS)
                s.lang = random.choice(ACCEPT_LANGUAGES)
                s.consecutive_blocks = 0
        else:
            # Successful request — relax throttle gradually
            if s.delay_ms > 100:
                s.delay_ms = max(100, int(s.delay_ms * 0.85))
            s.consecutive_blocks = 0


def next_delay(host: str) -> float:
    """Return seconds the caller should sleep before next request to `host`."""
    with _lock:
        s = _states[host]
        # Add ±15% jitter to look human
        jitter = random.uniform(0.85, 1.15)
        base = (s.delay_ms / 1000.0) * jitter
        # Enforce minimum interval since last request
        since_last = time.time() - s.last_request
        s.last_request = time.time()
        return max(0.0, base - since_last)


def state_for(host: str) -> dict:
    """Diagnostic — used by reporter/dashboard."""
    with _lock:
        s = _states[host]
        return {
            "delay_ms": s.delay_ms,
            "consecutive_blocks": s.consecutive_blocks,
            "recent_statuses": list(s.recent_statuses),
            "current_ua": s.ua[:50] + "...",
        }
