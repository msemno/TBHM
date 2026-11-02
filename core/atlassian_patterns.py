"""
Atlassian recon patterns — shared by atlassian_audit + sensitive_data_scan.

Covers:
  - Jira (Cloud + Server)
  - Jira Service Management / Service Desk (queues, portals, requests)
  - Confluence (Cloud + Server) — spaces, pages, restrictions
  - Bitbucket (workspaces, repos, snippets)
"""
from __future__ import annotations
import re


# ──────────────────────────────────────────────────────────────────────────────
# Fingerprints — detect Atlassian from HTTP response
# ──────────────────────────────────────────────────────────────────────────────
ATLASSIAN_HEADER_INDICATORS = [
    re.compile(r"X-A(USERNAME|REQUESTID|TLASSIAN-TOKEN)", re.I),
    re.compile(r"atl-(traceid|request)", re.I),
    re.compile(r"Atlassian-Service-Tools", re.I),
]
ATLASSIAN_BODY_INDICATORS = [
    re.compile(r"<meta\s+name=\"ajs-(version-number|context-path)\"", re.I),
    re.compile(r"Powered by\s+Atlassian", re.I),
    re.compile(r"Atlassian Confluence", re.I),
    re.compile(r"Atlassian Jira", re.I),
    re.compile(r"servicedesk-internal-portal", re.I),
    re.compile(r"window\.AJS\s*=", re.I),
]
ATLASSIAN_URL_HINTS = re.compile(
    r"\.atlassian\.(net|com)|/(jira|wiki|confluence|servicedesk|bitbucket)\b", re.I
)


# ──────────────────────────────────────────────────────────────────────────────
# Anonymous-enumeration endpoints
# (these often work without auth on misconfigured instances)
# ──────────────────────────────────────────────────────────────────────────────
JIRA_ANON_ENDPOINTS = [
    # API endpoints (Cloud v3 + legacy v2)
    "/rest/api/3/project/search",
    "/rest/api/3/project",
    "/rest/api/2/project",
    "/rest/api/2/user/picker?query=a",
    "/rest/api/2/user/assignable/search?project=TEST",
    "/rest/api/3/user/picker?query=a",
    "/rest/api/latest/dashboard",
    "/rest/api/2/serverInfo",
    "/rest/api/3/myself",
    # JQL search — sometimes anon
    "/rest/api/2/search?jql=order%20by%20created%20DESC&maxResults=10",
    "/rest/api/3/search?jql=order%20by%20created%20DESC&maxResults=10",
    # Old-school Jira pages
    "/secure/Dashboard.jspa",
    "/issues/?jql=order+by+created+DESC",
    "/secure/popups/IssuePicker.jspa",
]

CONFLUENCE_ANON_ENDPOINTS = [
    # Spaces enumeration
    "/wiki/rest/api/space",
    "/wiki/rest/api/space?limit=100",
    "/rest/api/space",
    # Content enumeration
    "/wiki/rest/api/content?limit=50",
    "/rest/api/content",
    # Group / user enumeration
    "/wiki/rest/api/group",
    "/rest/api/group",
    # Search
    "/wiki/rest/api/search?cql=type=space",
    "/wiki/rest/api/search?cql=type=page",
    "/wiki/dosearchsite.action?queryString=*",
    # Server-specific
    "/confluence/rest/api/space",
    "/confluence/rest/api/content",
]

SERVICEDESK_ANON_ENDPOINTS = [
    # Portal enumeration
    "/servicedesk/customer/portals",
    "/servicedesk/customer/portal/1",
    "/servicedesk/customer/portal/2",
    "/servicedesk/customer/portal/3",
    # API endpoints
    "/rest/servicedeskapi/servicedesk",
    "/rest/servicedesk/1/servicedesk-data/1",
    "/rest/servicedesk/1/servicedesk-data/2",
    "/rest/servicedesk/1/customer/groups/1/requests",
    "/rest/servicedesk/1/customer/portal/1/article",
    "/rest/servicedesk/1/customer/request-type-by-group",
    "/rest/servicedesk/1/customer/portal/1/group/-1",
    "/rest/servicedesk/1/customer/portal/1/group/-2",
    "/rest/servicedesk/1/internal/servicedesk-data",
    # KB articles often anon
    "/rest/servicedeskapi/knowledgebase/article",
]

BITBUCKET_ANON_ENDPOINTS = [
    "/api/2.0/repositories",
    "/rest/api/1.0/projects",
    "/projects",
    "/projects.json",
    "/rest/api/1.0/repos",
]


# ──────────────────────────────────────────────────────────────────────────────
# Per-resource fetch templates (fill in placeholder)
# ──────────────────────────────────────────────────────────────────────────────
JIRA_ISSUE_FETCH = "/rest/api/3/issue/{key}"     # key like PROJ-1234
JIRA_ISSUE_FETCH_V2 = "/rest/api/2/issue/{key}"
JIRA_BROWSE = "/browse/{key}"
CONFLUENCE_SPACE_FETCH = "/wiki/rest/api/space/{key}"
CONFLUENCE_PAGE_FETCH = "/wiki/rest/api/content/{id}"
CONFLUENCE_SPACE_OVERVIEW = "/wiki/spaces/{key}/overview"
SERVICEDESK_PORTAL_FETCH = "/servicedesk/customer/portal/{id}"
SERVICEDESK_QUEUE_FETCH = "/rest/servicedesk/1/customer/portal/{portal}/group/{queue}"


# ──────────────────────────────────────────────────────────────────────────────
# Sensitive content detection (used by sensitive_data_scan)
# ──────────────────────────────────────────────────────────────────────────────
# Patterns that indicate a queue/space contains employee PII or secrets
INTERNAL_KEYWORDS = re.compile(
    r"\b(employee[_\s-]?id|salary|payroll|ssn|social security|"
    r"compensation|performance review|hire date|termination|"
    r"badge[_\s-]?number|nda|confidential|internal[_\s-]?only|"
    r"proprietary|trade secret|do not share|do not distribute|"
    r"engineering[_\s-]?roadmap|product[_\s-]?roadmap|"
    r"strategic[_\s-]?plan|board[_\s-]?meeting|customer list|"
    r"vendor[_\s-]?list|password|credential|api[_\s-]?key|"
    r"private[_\s-]?key|access[_\s-]?token|secret[_\s-]?key)\b",
    re.I,
)

# Project / queue / space names that should be private
PRIVATE_NAME_KEYWORDS = re.compile(
    r"\b(internal|private|confidential|restricted|secret|nda|"
    r"hr[\s_-]?only|finance[\s_-]?only|leadership|exec|executive|"
    r"board|legal|compliance|security[\s_-]?team|infosec|incident|"
    r"red[\s_-]?team|on[\s_-]?call|payroll|accounting)\b",
    re.I,
)


def is_atlassian(headers: dict, body: str, url: str) -> bool:
    """Return True if response indicates an Atlassian product."""
    h_str = " ".join(f"{k}:{v}" for k, v in headers.items())
    for r in ATLASSIAN_HEADER_INDICATORS:
        if r.search(h_str):
            return True
    if ATLASSIAN_URL_HINTS.search(url):
        return True
    body_sample = body[:50_000] if body else ""
    for r in ATLASSIAN_BODY_INDICATORS:
        if r.search(body_sample):
            return True
    return False
