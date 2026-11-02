"""
Noise Filter — central blocklist for known false-positive sources.

Problem: scanning often finds "vulnerabilities" on third-party assets that
aren't in scope: Chrome extensions, analytics scripts, Facebook embeds,
LinkedIn social buttons, etc. These are not your bugs to report.

This module is called by storage.py before EVERY finding is saved.
If the finding's URL/host matches a noise pattern, it's dropped (or
labeled INFO-only depending on the severity).

How a phase uses it: just save findings normally. The filter happens at
storage layer — no per-phase code changes needed.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse


# Browser extension URL schemes — never real findings
EXTENSION_SCHEMES = re.compile(r"^(chrome|moz|safari|edge|firefox)-extension://", re.I)

# Third-party hosts that almost never represent bugs in YOUR target.
# Findings hitting these get dropped (or downgraded to INFO).
THIRD_PARTY_HOSTS = {
    # Analytics / tracking
    "google-analytics.com",       "googletagmanager.com",
    "google.com/recaptcha",       "recaptcha.net",
    "hotjar.com",                  "hotjar.io",
    "segment.com",                "segment.io",
    "mixpanel.com",
    "amplitude.com",
    "fullstory.com",
    "logrocket.com",
    "newrelic.com",                "nr-data.net",
    "datadog.com",                "datadoghq.com",
    "sentry.io",                  "sentry-cdn.com",
    "bugsnag.com",
    "rollbar.com",
    "intercom.io",                "intercom.com",
    "drift.com",
    "zendesk.com",
    "salesforce.com",
    # Social embeds
    "facebook.com",                "facebook.net",
    "connect.facebook.net",
    "fbcdn.net",
    "twitter.com",                "x.com",                  "twimg.com",
    "linkedin.com",                "licdn.com",
    "instagram.com",
    "pinterest.com",
    "youtube.com",                "ytimg.com",              "youtu.be",
    "tiktok.com",
    # Ad networks
    "doubleclick.net",            "googlesyndication.com",  "adservice.google.com",
    "adnxs.com",                  "criteo.com",
    # Public CDNs (vulns on these are not yours)
    "cloudflare.com",              "cloudfront.net",         "akamaihd.net",
    "fastly.net",                 "jsdelivr.net",            "unpkg.com",
    "cdnjs.cloudflare.com",
    # App stores
    "chromewebstore.google.com",  "addons.mozilla.org",
    "apps.apple.com",              "play.google.com",
    "microsoft.com/store",
    # Auth providers (their bugs are not yours)
    "accounts.google.com",
    "appleid.apple.com",
    "login.microsoftonline.com",
    "github.com/login",            "gitlab.com/users/sign_in",
    # Source control hosts (the platform itself, not target's content)
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "bitbucket.org",
    # Common 3rd-party services people accidentally scan
    "stripe.com",                  "stripe.network",
    "paypal.com",                  "paypalobjects.com",
    "twilio.com",
    "auth0.com",
    "okta.com",
    "onelogin.com",
}

# Patterns within paths that indicate 3rd-party widgets even on YOUR domain
NOISE_PATH_PATTERNS = [
    re.compile(r"/recaptcha/",          re.I),
    re.compile(r"/google-analytics",    re.I),
    re.compile(r"/gtag/",               re.I),
    re.compile(r"/segment/",            re.I),
    re.compile(r"/_next/static/",       re.I),     # Next.js build artifacts
    re.compile(r"/__nextjs_original/",  re.I),
    re.compile(r"\.css\.map$",          re.I),     # source maps
    re.compile(r"\.js\.map$",           re.I),
    # Webpack/Vite build chunks (massive false-positive source)
    re.compile(r"/static/(js|css|media)/[a-z0-9]+\.[a-f0-9]{8}\.",  re.I),
]


def is_noise(url: str, in_scope_hosts: set | None = None) -> tuple[bool, str]:
    """
    Returns (is_noise: bool, reason: str).
    `in_scope_hosts` (optional): user's actual targets. If a URL is on one of
    these, it's never noise even if it matches a third-party pattern.
    """
    if not url:
        return False, ""

    # Extension schemes — always noise
    if EXTENSION_SCHEMES.match(url):
        return True, "browser-extension URL (not a target asset)"

    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False, ""

    if not host:
        return False, ""

    # If we have a known in-scope list and this host IS in scope, never noise
    if in_scope_hosts:
        for h in in_scope_hosts:
            h = h.lower().lstrip("*.")
            if host == h or host.endswith("." + h):
                return False, ""

    # Third-party host blocklist
    for noise_host in THIRD_PARTY_HOSTS:
        if host == noise_host or host.endswith("." + noise_host):
            return True, f"third-party host '{noise_host}' (out of scope by default)"

    # Path-based noise patterns
    for pat in NOISE_PATH_PATTERNS:
        if pat.search(url):
            return True, "path matches known build-artifact / widget pattern"

    return False, ""


def should_drop_finding(finding: dict, in_scope_hosts: set | None = None) -> tuple[bool, str]:
    """
    Decide if a finding should be silently dropped. Severity-aware:
      - CRITICAL/HIGH: only drop on extension URLs (never drop real findings).
      - MEDIUM: drop if host clearly third-party.
      - LOW/INFO: drop on any noise match.
    """
    url = finding.get("url", "") or finding.get("target", "")
    if not url:
        return False, ""
    noise, reason = is_noise(url, in_scope_hosts)
    if not noise:
        return False, ""

    sev = (finding.get("severity") or "INFO").upper()
    # Extension URLs always dropped (no real bugs come from these)
    if "extension URL" in reason:
        return True, reason
    # For high-impact findings, only drop the obvious noise (extensions);
    # keep them flagged for review otherwise.
    if sev in ("CRITICAL", "HIGH"):
        return False, ""
    if sev == "MEDIUM" and "third-party host" in reason:
        return True, reason
    # LOW / INFO — be aggressive
    return True, reason
