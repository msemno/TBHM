"""
core/ineligible_findings.py   (v2.12)

Suppress findings that HackerOne's Core / Platform Standards mark as ineligible,
so they don't clutter the report or waste triage time. Merges two views:

  - CORE_INELIGIBLE      : exact template-id set (from your filters/ snippet)
  - NEVER_REPORT_PATTERNS: regex set for the always-ineligible header/cookie
                           class (from your lib/categorization snippet)

IMPORTANT design choices, because they fix real gaps in the raw snippets:

1. Findings in TBHM are dicts, not objects. `finding.template_id` /
   `finding.severity = "SUPPRESS"` would crash. Everything here takes a dict
   (and also tolerates an object, so your original call style still works).

2. The bundled templates are prefixed `tbhm-` (e.g. tbhm-missing-hsts), and
   official nuclei IDs vary (http-missing-csp, etc.). An exact-set check alone
   misses them. So matching is: exact-id  OR  regex-on-id  OR  title-signature.
   The id is normalised first (lowercased, `tbhm-`/`http-`/`generic-` stripped).

3. NOT over-suppressing. The regex list is deliberately limited to the
   *always*-ineligible header/cookie/security.txt class. Conditional ones
   (open-redirect, clickjacking) are matched ONLY by their explicit "no-impact"
   / "no-sensitive-action" id, never by a broad pattern — a real open redirect
   or clickjack with impact must still report.

4. Nothing is deleted. Suppressed findings are tagged
   (severity="SUPPRESS", suppress_reason=...) and routed to the existing
   dropped-findings archive, so they remain visible in the review file and can
   be resurfaced with --include-ineligible.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

# ── Exact template-id set (your filters/ineligible_findings.py) ───────────────
CORE_INELIGIBLE = {
    # Missing headers — all
    "missing-hsts",
    "missing-x-content-type-options",
    "missing-x-frame-options",
    "missing-csp",
    "missing-permissions-policy",
    "missing-referrer-policy",
    "missing-security-txt",
    "missing-cookie-flags",
    "cookie-without-secure",
    "cookie-without-httponly",

    # Other auto-N/A on HackerOne Core Standards
    "clickjacking-no-sensitive-action",
    "open-redirect-no-impact",
    "self-xss",
    "verbose-error-message",
    "directory-listing-no-sensitive-data",
    "spf-dmarc-issues",
    "spf-record-missing",
    "dmarc-record-missing",
    "tls-config-weakness",
    "tls-version-1-0-1-1",
    "rate-limit-bypass-no-impact",
    "empty-bucket",          # the Scaleway empty-bucket case
    "version-disclosure",
    "software-version-disclosure",
}

# ── Regex set — ALWAYS-ineligible header/cookie class only (your lib snippet) ──
# Kept header-only on purpose. These run against the (normalised) template id and
# catch the tbhm-/http-/community-prefixed variants in one shot.
NEVER_REPORT_PATTERNS = [
    r"missing[-_]hsts",
    r"missing[-_]?strict[-_]transport",
    r"missing[-_]x[-_]content[-_]type",
    r"missing[-_]x[-_]frame",
    r"missing[-_]csp",
    r"missing[-_]content[-_]security[-_]policy",
    r"missing[-_]permissions[-_]policy",
    r"missing[-_]feature[-_]policy",
    r"missing[-_]referrer[-_]policy",
    r"missing[-_]security[-_]txt",
    r"missing[-_]cookie[-_]flags",
    r"cookie[-_]without[-_](secure|httponly)",
    r"x[-_]powered[-_]by[-_]disclosure",
    r"server[-_]version[-_]disclosure",
]
_NEVER_RE = [re.compile(p, re.I) for p in NEVER_REPORT_PATTERNS]

# ── Title signatures — for findings without a clean id (e.g. cloud buckets) ───
# Loose, lowercase substring/regex match against the finding title. Conservative:
# only phrases that are unambiguously the ineligible class.
_TITLE_SIGNATURES = [
    r"missing .*strict-transport-security",
    r"missing .*content-security-policy",
    r"missing .*x-frame-options",
    r"missing .*x-content-type-options",
    r"missing .*referrer-policy",
    r"missing .*permissions-policy",
    r"without secure flag",
    r"without httponly",
    r"missing security\.txt",
    r"(empty|unclaimed).{0,25}bucket",
    r"bucket.{0,25}(empty|unclaimed)",
    r"\bself[- ]xss\b",
    r"spf.{0,10}(missing|record)",
    r"dmarc.{0,10}(missing|record)",
]
_TITLE_RE = [re.compile(p, re.I) for p in _TITLE_SIGNATURES]

_PREFIXES = ("tbhm-", "http-", "https-", "generic-", "nuclei-")


def _normalise(template_id: str) -> str:
    tid = (template_id or "").strip().lower()
    for pre in _PREFIXES:
        if tid.startswith(pre):
            tid = tid[len(pre):]
            break
    return tid


def _user_extra() -> set[str]:
    """Optional: extra ids the user wants suppressed, one per line."""
    f = Path.home() / ".tbhm" / "ineligible_extra.txt"
    if not f.exists():
        return set()
    try:
        return {ln.strip().lower() for ln in f.read_text().splitlines()
                if ln.strip() and not ln.startswith("#")}
    except Exception:
        return set()


# ── Public API ────────────────────────────────────────────────────────────────
def is_never_report(template_id: str) -> bool:
    """Your lib/categorization.py function — regex check on the (normalised) id."""
    tid = _normalise(template_id)
    return any(rx.search(tid) for rx in _NEVER_RE)


def classify(finding) -> tuple[bool, str]:
    """
    Decide whether a finding is HackerOne Core-ineligible.
    Returns (suppress: bool, reason: str). Accepts a dict or an object.
    """
    if isinstance(finding, dict):
        tid = finding.get("template_id") or finding.get("template-id") or ""
        title = finding.get("title", "") or ""
    else:  # object fallback for the original call style
        tid = getattr(finding, "template_id", "") or ""
        title = getattr(finding, "title", "") or ""

    ntid = _normalise(tid)

    if ntid and ntid in (CORE_INELIGIBLE | _user_extra()):
        return True, f"Core Ineligible per HackerOne Platform Standards (id: {ntid})"
    if is_never_report(tid):
        return True, "Core Ineligible per HackerOne Platform Standards (missing security header / cookie flag)"
    if title and any(rx.search(title) for rx in _TITLE_RE):
        return True, "Core Ineligible per HackerOne Platform Standards (matched title signature)"
    return False, ""


def should_suppress(finding) -> bool:
    """Your filters/ineligible_findings.py function — thin bool wrapper."""
    return classify(finding)[0]


def mark_suppressed(finding: dict, reason: str) -> dict:
    """Apply the SUPPRESS tag in place (your lib-snippet mutation, dict-safe)."""
    finding["original_severity"] = finding.get("severity")
    finding["severity"] = "SUPPRESS"
    finding["ineligible"] = True
    finding["suppress_reason"] = reason
    return finding
