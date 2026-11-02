"""
Session state tracking — Burp/ZAP-style.

Pro DAST tools maintain session state across the whole audit so that:
  - Cookies set by the login flow are kept
  - CSRF tokens are extracted and re-injected
  - Bearer tokens are kept across requests
  - Auth failures trigger re-login automatically

This module is a lightweight version: it preserves cookies + headers
across an entire audit run, and re-extracts CSRF tokens from intercepted
responses.
"""
from __future__ import annotations

import re
from http.cookies import SimpleCookie
from urllib.parse import urlparse


CSRF_PATTERNS = [
    # HTML hidden input
    re.compile(r'name=["\'](_token|csrf|csrf_token|csrfmiddlewaretoken|'
               r'__RequestVerificationToken|authenticity_token|_csrf)["\']\s+'
               r'value=["\']([^"\']+)["\']', re.I),
    re.compile(r'value=["\']([^"\']+)["\']\s+name=["\'](_token|csrf|csrf_token|'
               r'csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token)["\']', re.I),
    # Meta tag
    re.compile(r'<meta[^>]+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']+)["\']\s+name=["\']csrf-token["\']', re.I),
    # JSON body
    re.compile(r'"(csrf|csrf_token|_token|xsrf)"\s*:\s*"([^"]+)"', re.I),
]


class Session:
    """Holds cookies + auth headers + CSRF tokens for an audit run."""

    def __init__(self, base_headers: dict | None = None):
        self.cookies: dict[str, str] = {}   # name → value
        self.headers: dict[str, str] = dict(base_headers or {})
        self.csrf_token: str | None = None
        self.csrf_field_name: str | None = None
        self._origin_host: str | None = None

    # ── Cookie management ────────────────────────────────────────────────
    def update_from_response_headers(self, headers: dict, url: str = ""):
        """Parse Set-Cookie headers, update CSRF tokens from body if needed."""
        if not headers:
            return
        # Set-Cookie may appear multiple times
        for hname, hval in headers.items():
            if hname.lower() == "set-cookie":
                # urllib http.cookies handles one Set-Cookie line
                c = SimpleCookie()
                try:
                    c.load(hval)
                except Exception:
                    continue
                for k in c:
                    self.cookies[k] = c[k].value

    def update_from_response_body(self, body: str):
        """Extract CSRF tokens from HTML / JSON body."""
        if not body:
            return
        for pat in CSRF_PATTERNS:
            m = pat.search(body)
            if not m:
                continue
            groups = m.groups()
            # Pattern may put value/name in different group orders
            if len(groups) == 2:
                if groups[0].lower() in {"_token", "csrf", "csrf_token",
                                          "csrfmiddlewaretoken",
                                          "__requestverificationtoken",
                                          "authenticity_token", "_csrf", "xsrf"}:
                    self.csrf_field_name = groups[0]
                    self.csrf_token = groups[1]
                else:
                    self.csrf_token = groups[0]
                    self.csrf_field_name = groups[1] if len(groups) > 1 else "csrf"
            else:
                self.csrf_token = groups[0]
            return

    def update(self, response):
        """Convenience: update cookies + CSRF from a requests Response object."""
        try:
            for k, v in response.cookies.items():
                self.cookies[k] = v
            self.update_from_response_body(response.text[:50000])
        except Exception:
            pass

    # ── Request injection ────────────────────────────────────────────────
    def apply(self, headers: dict | None, body: str | None = "",
              content_type: str = "") -> tuple[dict, str]:
        """Return (headers, body) with session cookies + CSRF injected."""
        h = dict(headers or {})
        # Cookies
        if self.cookies:
            existing = h.get("Cookie") or h.get("cookie") or ""
            existing_pairs = {}
            for kv in existing.split(";"):
                if "=" in kv:
                    k, _, v = kv.strip().partition("=")
                    existing_pairs[k.strip()] = v.strip()
            # Session cookies override any existing
            for k, v in self.cookies.items():
                existing_pairs[k] = v
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in existing_pairs.items())
        # Custom headers (Authorization, X-API-Key, etc.)
        for k, v in self.headers.items():
            if k.lower() not in ("cookie",):
                h.setdefault(k, v)
        # CSRF token: inject into body if csrf field present
        if self.csrf_token and self.csrf_field_name and body:
            ct = content_type.lower()
            if "application/json" in ct:
                # Don't break JSON parse — only inject if field already exists
                pass
            elif "application/x-www-form-urlencoded" in ct or "=" in body:
                if self.csrf_field_name in body:
                    body = re.sub(
                        rf"({re.escape(self.csrf_field_name)}=)[^&]*",
                        rf"\1{self.csrf_token}", body)
        return h, body
