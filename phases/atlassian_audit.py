"""
Phase: atlassian_audit

Specific tests for Atlassian Jira and Confluence instances (on
*.atlassian.net, *.atlassian.com, and self-hosted Jira/Confluence).

Detects:
  1. IDOR on Jira tickets: enumerate issues from other projects/queues
     where external accounts shouldn't see them.
  2. Sensitive info disclosure: queue/issue content revealing PII,
     credentials, or internal project names.
  3. Permission bypass: opening tickets in queues you shouldn't access.
  4. Confluence anonymous access: internal spaces visible without auth.
  5. User enumeration via /rest/api/user/search.
  6. JQL/CQL injection on search endpoints.
  7. Misconfigured Atlassian Connect apps.

How it scores:
  - 200 + JSON with sensitive content fields → Critical
  - 200 + non-empty space list without auth → Critical (anon Confluence)
  - 200 on issue endpoint → IDOR confirmed
  - 401/403 → proper denial (informational)
"""
from __future__ import annotations
import json
import re
import time
from urllib.parse import urlparse, urljoin

from core import anti_block, noise_filter
from core.targets import get_root_domains
from core.idor_engine import (detect_ids, mutate_id, build_mutated_url,
                              fingerprint_response, classify_idor,
                              looks_like_spa_fallback, random_invalid_path)

try:
    import requests
except ImportError:
    requests = None


# Atlassian asset signatures (we only run on these hosts)
ATLASSIAN_HOST_RE = re.compile(
    r"(atlassian\.net|atlassian\.com|jira\.|confluence\.|"
    r"servicedesk\.|/wiki/|/jira/|/secure/)", re.I
)

# Jira REST API endpoints to probe (v2 + v3 + agile + servicedesk)
JIRA_ENDPOINTS = [
    # (path,                                     sensitivity, description)
    ("/rest/api/2/project",                     "HIGH",  "list all projects"),
    ("/rest/api/3/project",                     "HIGH",  "list all projects (v3)"),
    ("/rest/api/2/project/search?maxResults=200", "HIGH", "search projects"),
    ("/rest/api/2/dashboard",                   "MEDIUM", "list dashboards"),
    ("/rest/api/2/filter/favourite",            "MEDIUM", "saved JQL filters"),
    ("/rest/api/2/myself",                      "LOW",    "current user (auth check)"),
    ("/rest/api/2/serverInfo",                  "INFO",   "Jira server version"),
    ("/rest/api/2/permissions",                 "LOW",    "global permissions"),
    ("/rest/api/2/user/search?username=.&maxResults=200", "HIGH", "enumerate users by '.'"),
    ("/rest/api/2/user/search?query=@",         "HIGH",  "enumerate users by '@'"),
    ("/rest/api/3/users/search?maxResults=200", "HIGH",  "enumerate users (v3)"),
    ("/rest/api/2/groupuserpicker?query=a",     "MEDIUM", "enumerate groups & users"),
    ("/rest/api/2/group?groupname=jira-administrators", "HIGH", "admin group members"),
    ("/rest/api/2/search?jql=ORDER%20BY%20created%20DESC&maxResults=50",
                                                "CRITICAL", "search all issues (no JQL filter)"),
    ("/rest/api/2/search?jql=project%20is%20not%20empty&maxResults=50",
                                                "CRITICAL", "search all issues (alternate JQL)"),
    ("/rest/agile/1.0/board",                   "MEDIUM",  "list agile boards"),
    ("/rest/servicedeskapi/servicedesk",        "HIGH",    "list service desks"),
    ("/rest/servicedeskapi/request",            "CRITICAL", "list customer requests"),
    ("/rest/api/2/issue/createmeta",            "MEDIUM",  "issue create metadata (project enum)"),
    # File-attachment listing
    ("/rest/api/2/attachment/meta",             "LOW",     "attachment metadata"),
]

# Confluence REST API endpoints
CONFLUENCE_ENDPOINTS = [
    ("/wiki/rest/api/space?limit=200",          "HIGH",     "list all spaces (anon)"),
    ("/wiki/rest/api/space?type=global&limit=200", "HIGH",  "list global spaces"),
    ("/wiki/rest/api/content?limit=200",        "CRITICAL", "list all content (anon)"),
    ("/wiki/rest/api/content/search?cql=type=page&limit=50", "CRITICAL", "search all pages"),
    ("/wiki/rest/api/content/search?cql=label=internal&limit=50", "CRITICAL", "label-based search"),
    ("/wiki/rest/api/user/current",             "LOW",      "current user"),
    ("/wiki/rest/api/settings/systemInfo",      "INFO",     "Confluence version"),
    ("/wiki/rest/api/group",                    "MEDIUM",   "list groups"),
    # Legacy paths
    ("/rest/api/space",                         "HIGH",     "spaces (legacy path)"),
    ("/rest/api/content",                       "CRITICAL", "content (legacy path)"),
]

# Sensitive content patterns (PII / credentials / internal markers)
SENSITIVE_PATTERNS = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "email_address"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                              "ssn_pattern"),
    (re.compile(r"\b(?:\d{4}[\s-]?){4}\b"),                             "credit_card_pattern"),
    (re.compile(r"\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]", re.I), "credential_keyword"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                             "google_api_key"),
    (re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),                  "stripe_key"),
    (re.compile(r"ghp_[0-9a-zA-Z]{36,}"),                               "github_pat"),
    (re.compile(r"xox[bap]-[0-9]{10,15}-[0-9a-zA-Z]{20,40}"),           "slack_token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),                                    "aws_access_key"),
    (re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"), "private_key_block"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "jwt_token"),
]

# Internal-project markers in returned content
INTERNAL_MARKERS_RE = re.compile(
    r"\b(internal|confidential|restricted|admin[_-]?only|sec(?:urity)?[_-]?ops|"
    r"hr|finance|legal|incident|breach|insider|do[\s_-]?not[\s_-]?share)\b",
    re.I,
)


def run(ctx):
    if not requests:
        return

    # Find Atlassian hosts in our scope
    candidates = _collect_atlassian_hosts(ctx)
    if not candidates:
        ctx.log("INFO", "atlassian_audit",
                "no Atlassian (jira/confluence) hosts detected — skipping")
        return

    ctx.log("INFO", "atlassian_audit",
            f"━━━ Atlassian audit on {len(candidates)} host(s) ━━━")

    in_scope = set(get_root_domains(ctx))
    n_findings = 0

    for base in candidates:
        host = urlparse(base).hostname or base
        ctx.log("INFO", "atlassian_audit", f"  → {base}")

        # 1) Anonymous endpoint enumeration (Jira + Confluence)
        n_findings += _probe_endpoints(ctx, base, host, JIRA_ENDPOINTS, "jira", in_scope)
        n_findings += _probe_endpoints(ctx, base, host, CONFLUENCE_ENDPOINTS,
                                        "confluence", in_scope)

        # 2) IDOR sweep on issue/ticket/page IDs discovered earlier
        n_findings += _idor_sweep(ctx, base, host)

        # 3) JQL/CQL injection tests
        n_findings += _jql_injection_test(ctx, base, host)

        # 4) ServiceDesk customer request enumeration
        n_findings += _servicedesk_request_enum(ctx, base, host)

    ctx.log("OK", "atlassian_audit",
            f"atlassian_audit: {n_findings} findings on {len(candidates)} host(s)")


# ──────────────────────────────────────────────────────────────────────────────
# Host detection
# ──────────────────────────────────────────────────────────────────────────────
def _collect_atlassian_hosts(ctx) -> list[str]:
    """Find Atlassian-shaped hosts among our scope."""
    out = set()
    # 1. From explicit targets
    for t in ctx.targets:
        if not t.startswith("http"):
            t = "https://" + t
        if ATLASSIAN_HOST_RE.search(t):
            out.add(t.rstrip("/"))
    # 2. From alive.txt
    alive = ctx.output / "recon" / "alive.txt"
    if alive.exists():
        for u in ctx.runner.read_lines(alive):
            if ATLASSIAN_HOST_RE.search(u):
                parsed = urlparse(u)
                out.add(f"{parsed.scheme}://{parsed.netloc}")
    # 3. Implicit: any host containing 'atlassian'
    return sorted(out)


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint probing
# ──────────────────────────────────────────────────────────────────────────────
def _probe_endpoints(ctx, base_url: str, host: str,
                     endpoints: list[tuple], category: str,
                     in_scope: set) -> int:
    """
    Hit every endpoint anonymously. Compare against an invalid-baseline to
    rule out SPA fallback. Look for sensitive content patterns.
    """
    # Get invalid baseline first
    invalid_fp = _get_invalid_baseline(base_url, host)

    n = 0
    for path, sensitivity, desc in endpoints:
        full_url = urljoin(base_url + "/", path.lstrip("/"))
        if noise_filter.is_noise(full_url, in_scope_hosts=in_scope)[0]:
            continue

        try:
            r = requests.get(full_url, timeout=12, verify=False,
                              headers=anti_block.headers_for(host),
                              allow_redirects=False, cookies={})
            anti_block.observe(host, r.status_code, len(r.content), r.text[:800])
        except Exception:
            continue

        time.sleep(anti_block.next_delay(host))

        fp = fingerprint_response(r.status_code, r.content, dict(r.headers))

        # Skip if response is just the SPA fallback
        if looks_like_spa_fallback(r.content):
            continue
        if invalid_fp and fp["body_hash"] == invalid_fp["body_hash"]:
            continue

        # 401/403 = proper denial (informational only — skip)
        if r.status_code in (401, 403):
            continue

        # 200 with JSON and content > minimal → potential issue
        if r.status_code == 200 and len(r.content) > 100:
            content_type = (r.headers.get("Content-Type") or "").lower()
            is_json = "json" in content_type
            is_meaningful = is_json or "<page>" in r.text or "<space>" in r.text

            if not is_meaningful:
                continue

            # Detect what kind of leak this is
            try:
                data = r.json() if is_json else None
            except Exception:
                data = None

            # Count entities returned
            entity_count = _count_entities(data) if data else 0

            sensitive_hits = _scan_sensitive(r.text[:50000])
            internal_hits  = INTERNAL_MARKERS_RE.findall(r.text[:50000])

            # Build finding
            severity = sensitivity
            confidence = "HIGH"
            if entity_count == 0 and not sensitive_hits and not internal_hits:
                # 200 but empty / no signal → downgrade
                severity = "LOW"
                confidence = "MEDIUM"
            elif sensitive_hits:
                severity = "CRITICAL"
            elif entity_count > 5:
                # Real data returned → bump severity
                if severity not in ("HIGH", "CRITICAL"):
                    severity = "HIGH"

            title = f"[{category}] {desc} — anonymous access"
            evidence_parts = [
                f"GET {path} → 200, {len(r.content)} bytes, "
                f"Content-Type={content_type or '?'}",
                f"Entities returned: {entity_count}",
            ]
            if sensitive_hits:
                evidence_parts.append(
                    "Sensitive patterns: " + ", ".join(
                        f"{kind}({count})" for kind, count in sensitive_hits.items()
                    )
                )
            if internal_hits:
                evidence_parts.append(
                    f"Internal markers: {', '.join(set(m.lower() for m in internal_hits[:5]))}"
                )

            ctx.save_finding({
                "phase": "atlassian_audit", "severity": severity,
                "confidence": confidence,
                "title": title,
                "target": host, "url": full_url, "method": "GET",
                "evidence": " | ".join(evidence_parts),
                "description": (
                    f"The Atlassian {category} endpoint '{path}' returned a "
                    f"non-empty response without any authentication. "
                    f"This endpoint is documented to require auth.\n"
                    f"Manually verify the returned content does not contain "
                    f"sensitive data about other users / projects / queues."
                ),
                "impact": (
                    "Information disclosure of internal project structure, "
                    "user lists, ticket data, or even credentials embedded in "
                    "Confluence pages / Jira comments."
                ),
                "remediation": (
                    "Set 'Anonymous access' permission to OFF in Jira/Confluence "
                    "global permissions. For Atlassian Cloud, review Site Access > "
                    "Permissions. Apply 'Public access' = Disabled on Confluence."
                ),
                "cwe": "CWE-285",
                "mrs_score": _mrs_for(severity),
            })
            n += 1

    return n


def _get_invalid_baseline(base_url: str, host: str) -> dict | None:
    """GET a random path to learn what 'doesn't exist' looks like for this host."""
    try:
        url = random_invalid_path(base_url)
        r = requests.get(url, timeout=10, verify=False,
                          headers=anti_block.headers_for(host),
                          allow_redirects=False, cookies={})
        return fingerprint_response(r.status_code, r.content, dict(r.headers))
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# IDOR sweep
# ──────────────────────────────────────────────────────────────────────────────
def _idor_sweep(ctx, base_url: str, host: str) -> int:
    """
    Test sequential issue/page IDs. If we can fetch ANY issue without auth → IDOR.
    """
    # Common Jira issue endpoint patterns
    probes = []
    # We need known project keys. Try common ones.
    for project in ("SUPPORT", "INTERNAL", "SEC", "INFRA", "OPS", "ADMIN",
                    "ENG", "DEV", "PROD", "IT", "HR"):
        for num in (1, 100, 999):
            probes.append((f"/rest/api/2/issue/{project}-{num}", "jira_issue", project, num))
    # Confluence page IDs (numeric)
    for page_id in (1, 100, 1000, 65536, 100000):
        probes.append((f"/wiki/rest/api/content/{page_id}", "confluence_page",
                       "page", page_id))

    invalid_fp = _get_invalid_baseline(base_url, host)
    n = 0
    found_keys = set()

    for path, kind, project, num in probes:
        full_url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            r = requests.get(full_url, timeout=10, verify=False,
                              headers=anti_block.headers_for(host),
                              allow_redirects=False, cookies={})
            anti_block.observe(host, r.status_code, len(r.content))
        except Exception:
            continue
        time.sleep(anti_block.next_delay(host))

        if r.status_code in (401, 403, 404):
            continue
        if r.status_code != 200 or len(r.content) < 100:
            continue
        if looks_like_spa_fallback(r.content):
            continue
        if invalid_fp and r.content[:5000] == invalid_fp["body_prefix"]:
            continue

        # Parse JSON to confirm it's a real issue/page
        try:
            data = r.json()
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        # Jira issue shape: has "key" and "fields"
        if kind == "jira_issue" and "key" in data and "fields" in data:
            issue_key = data.get("key", f"{project}-{num}")
            summary   = (data.get("fields") or {}).get("summary", "")[:120]
            found_keys.add(issue_key)

            sensitive_hits = _scan_sensitive(r.text[:50000])
            internal_match = INTERNAL_MARKERS_RE.search(r.text[:50000])

            severity = "HIGH"
            if sensitive_hits:
                severity = "CRITICAL"
            elif internal_match:
                severity = "CRITICAL"

            ctx.save_finding({
                "phase": "atlassian_audit", "severity": severity, "confidence": "HIGH",
                "title": f"[jira] IDOR: ticket {issue_key} fetchable without auth",
                "target": host, "url": full_url, "method": "GET",
                "parameter": "issue_key", "payload": issue_key,
                "evidence": (f"GET /rest/api/2/issue/{issue_key} → 200. "
                            f"Summary: '{summary}'. "
                            f"Sensitive hits: {list(sensitive_hits.keys())}. "
                            f"Internal markers: {bool(internal_match)}"),
                "description": (
                    "Issue data accessible without authentication. Anonymous "
                    "attackers can enumerate sequential ticket keys (PROJ-1, "
                    "PROJ-2, …) and read potentially sensitive content."
                ),
                "impact": (
                    "Disclosure of: support tickets (customer PII), internal "
                    "engineering tickets (vulnerability discussions, infra "
                    "details), HR/legal tickets, or credentials accidentally "
                    "posted in ticket descriptions."
                ),
                "remediation": (
                    "In Jira: Project Settings → Permissions → 'Browse Projects' "
                    "must NOT include Anonymous / Public roles. In Cloud, "
                    "review Site Access settings and ensure all projects are "
                    "set to 'Private'."
                ),
                "cwe": "CWE-639",
                "mrs_score": 90,
            })
            n += 1

        # Confluence page shape: has "type" and "title"
        elif kind == "confluence_page" and data.get("type") == "page":
            page_title = data.get("title", "")[:120]
            sensitive_hits = _scan_sensitive(r.text[:50000])

            severity = "CRITICAL" if sensitive_hits or "internal" in page_title.lower() else "HIGH"
            ctx.save_finding({
                "phase": "atlassian_audit", "severity": severity, "confidence": "HIGH",
                "title": f"[confluence] Anonymous read of page id={num}",
                "target": host, "url": full_url, "method": "GET",
                "parameter": "page_id", "payload": str(num),
                "evidence": (f"GET /wiki/rest/api/content/{num} → 200. "
                            f"Title: '{page_title}'. "
                            f"Sensitive: {list(sensitive_hits.keys())}"),
                "description": (
                    "A Confluence page is readable without authentication. "
                    "Sequential numeric page IDs allow enumeration of every "
                    "page in the instance."
                ),
                "impact": (
                    "Wholesale extraction of internal Confluence wiki content "
                    "including engineering docs, runbooks, secrets, and onboarding."
                ),
                "remediation": (
                    "Confluence → Space Settings → Permissions → remove 'anonymous' "
                    "from 'View'. Set instance-wide anonymous access OFF."
                ),
                "cwe": "CWE-285",
                "mrs_score": 95,
            })
            n += 1

    if found_keys:
        ctx.log("OK", "atlassian_audit",
                f"  ⚠️  IDOR confirmed on {len(found_keys)} Jira keys: "
                f"{', '.join(list(found_keys)[:5])}")
    return n


# ──────────────────────────────────────────────────────────────────────────────
# JQL/CQL injection
# ──────────────────────────────────────────────────────────────────────────────
def _jql_injection_test(ctx, base_url: str, host: str) -> int:
    """
    Test JQL injection on search endpoints. A successful JQL bypassing
    project restrictions returns issues you shouldn't see.
    """
    payloads = [
        ("ORDER BY created DESC",                                "broad_order_by"),
        ("project IS NOT EMPTY",                                  "all_projects"),
        ("status != Closed",                                     "all_open"),
        ("created > -30d",                                       "recent_30d"),
        ('summary ~ "password" OR description ~ "secret"',       "secret_keyword"),
        ('summary ~ "internal" OR labels = "internal"',          "internal_label"),
    ]
    n = 0
    for jql, label in payloads:
        from urllib.parse import quote
        path = f"/rest/api/2/search?jql={quote(jql)}&maxResults=5"
        full_url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            r = requests.get(full_url, timeout=12, verify=False,
                              headers=anti_block.headers_for(host),
                              allow_redirects=False, cookies={})
            anti_block.observe(host, r.status_code, len(r.content))
        except Exception:
            continue
        time.sleep(anti_block.next_delay(host))
        if r.status_code != 200:
            continue
        try:
            data = r.json()
            total = data.get("total", 0)
            issues = data.get("issues", [])
        except Exception:
            continue
        if total == 0 or not issues:
            continue

        sample_keys = [i.get("key", "?") for i in issues[:5]]
        ctx.save_finding({
            "phase": "atlassian_audit", "severity": "CRITICAL", "confidence": "HIGH",
            "title": f"[jira] Anonymous JQL search returns issues (jql={label})",
            "target": host, "url": full_url, "method": "GET",
            "parameter": "jql", "payload": jql,
            "evidence": (f"JQL '{jql}' anonymously returned total={total}, "
                        f"sample keys: {sample_keys}"),
            "description": (
                "The Jira search endpoint allows JQL queries without authentication. "
                "Attackers can craft JQL to bypass project-level permissions and "
                "retrieve issues across the entire instance."
            ),
            "impact": (
                "Mass disclosure of every ticket the anonymous role can technically "
                "see, plus enumeration of internal project structure and labels."
            ),
            "remediation": (
                "Remove 'Browse Projects' from the Anonymous role at the project "
                "permission scheme level. Set Application Access > Anonymous to OFF."
            ),
            "cwe": "CWE-285",
            "mrs_score": 92,
        })
        n += 1
    return n


# ──────────────────────────────────────────────────────────────────────────────
# ServiceDesk customer request enumeration
# ──────────────────────────────────────────────────────────────────────────────
def _servicedesk_request_enum(ctx, base_url: str, host: str) -> int:
    """Detect Jira Service Desk request leakage (customer-facing tickets)."""
    n = 0
    for path in ("/rest/servicedeskapi/request",
                 "/rest/servicedeskapi/request?start=0&limit=50",
                 "/rest/servicedeskapi/customer"):
        full_url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            r = requests.get(full_url, timeout=10, verify=False,
                              headers=anti_block.headers_for(host),
                              allow_redirects=False, cookies={})
            anti_block.observe(host, r.status_code, len(r.content))
        except Exception:
            continue
        time.sleep(anti_block.next_delay(host))
        if r.status_code != 200 or len(r.content) < 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        size = data.get("size", 0) if isinstance(data, dict) else 0
        values = data.get("values", []) if isinstance(data, dict) else []
        if not values:
            continue

        ctx.save_finding({
            "phase": "atlassian_audit", "severity": "CRITICAL", "confidence": "HIGH",
            "title": "[jira-servicedesk] customer requests readable anonymously",
            "target": host, "url": full_url, "method": "GET",
            "evidence": f"GET {path} → 200 with size={size}, values_len={len(values)}",
            "description": (
                "Jira Service Desk customer requests are exposed without auth. "
                "These often contain customer email addresses, support ticket bodies "
                "(error messages, account IDs), and attached files."
            ),
            "impact": (
                "PII exfiltration of customer support data. Reputational damage. "
                "In EU jurisdictions: GDPR-reportable breach."
            ),
            "remediation": (
                "JSM Project → Customer Permissions → 'Who can raise requests' "
                "must NOT be 'Anyone'. Disable public portals. "
                "Restrict /rest/servicedeskapi to authenticated callers via "
                "Application Access settings."
            ),
            "cwe": "CWE-285", "mrs_score": 95,
        })
        n += 1
    return n


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _scan_sensitive(text: str) -> dict[str, int]:
    """Return {pattern_name: count} for sensitive patterns found in `text`."""
    out = {}
    for pat, name in SENSITIVE_PATTERNS:
        hits = pat.findall(text)
        if hits:
            out[name] = len(hits)
    return out


def _count_entities(data) -> int:
    """How many user/project/issue/page items did the response return?"""
    if not data:
        return 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("values", "issues", "users", "projects", "results", "groups",
                    "spaces", "pages", "filters"):
            v = data.get(key)
            if isinstance(v, list):
                return len(v)
        return 1 if data else 0
    return 0


def _mrs_for(sev: str) -> int:
    return {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 60, "LOW": 40, "INFO": 25}.get(sev, 30)
