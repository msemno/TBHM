"""
core/cwe_cvss.py   (v2.18)

Enriches findings with a CWE id and an approximate CVSS 3.1 vector/score when the
finding doesn't already carry them. The vector is DERIVED from severity + finding
type — it is an estimate for triage, not a substitute for manual CVSS scoring.
"""
from __future__ import annotations

import re

# title keyword -> CWE id
_CWE_MAP = [
    (r"sql\s*inj|sqli",                "CWE-89"),
    (r"\b(?:command inj\w*|os\.system|rce)\b", "CWE-77"),
    (r"\bxss\b|innerhtml|cross.site scripting", "CWE-79"),
    (r"ssrf|server.side request",      "CWE-918"),
    (r"path travers|lfi|file inclusion","CWE-22"),
    (r"idor|insecure direct",          "CWE-639"),
    (r"broken access|authoriz",        "CWE-285"),
    (r"open redirect",                 "CWE-601"),
    (r"deserial",                      "CWE-502"),
    (r"xxe|external entit",            "CWE-611"),
    (r"csrf",                          "CWE-352"),
    # A specific weak-hash description is more informative than its use in a
    # token. Keep the broad crypto hint later so generic random text does not
    # outrank an explicit hardcoded-credential observation.
    (r"\b(?:weak hash|md5|sha1|weak cipher|static iv|weak prng)\b", "CWE-327"),
    (r"secret|api key|token|credential|password", "CWE-798"),
    (r"cors",                          "CWE-942"),
    (r"clickjack|x-frame",             "CWE-1021"),
    (r"hsts|cleartext|tls",            "CWE-319"),
    (r"\b(?:weak hash|md5|sha1|crypto|cipher|iv|prng|random)\b", "CWE-327"),
    (r"takeover",                      "CWE-350"),
    (r"smuggl",                        "CWE-444"),
    (r"vulnerable dependency|known cve","CWE-1104"),
    (r"debuggable|allowbackup|exported","CWE-926"),
    (r"directory listing",             "CWE-548"),
    (r"stack trace|verbose error|disclosure", "CWE-200"),
]

_SEV_BASE = {"CRITICAL": 9.5, "HIGH": 8.1, "MEDIUM": 6.1, "LOW": 3.7, "INFO": 0.0}


def cwe_for(title: str, existing: str = "") -> str:
    if existing:
        return existing
    t = (title or "").lower()
    for pat, cwe in _CWE_MAP:
        if re.search(pat, t):
            return cwe
    return ""


def cvss_for(severity: str, authenticated: bool = False) -> dict:
    sev = (severity or "INFO").upper()
    score = _SEV_BASE.get(sev, 0.0)
    if score == 0.0:
        return {"score": 0.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}
    pr = "L" if authenticated else "N"
    # Coarse impact bucketing by severity band.
    if sev in ("CRITICAL", "HIGH"):
        c = i = "H"; a = "L"
    elif sev == "MEDIUM":
        c = "L"; i = "L"; a = "N"
    else:
        c = "L"; i = "N"; a = "N"
    vector = f"CVSS:3.1/AV:N/AC:L/PR:{pr}/UI:N/S:U/C:{c}/I:{i}/A:{a}"
    return {"score": score, "vector": vector}


# v3.6: representative real-world CVEs per weakness class. These are REFERENCE
# exemplars for the report ("this class of bug looks like …"), not a claim that
# the target is affected by that specific CVE. SCA findings carry their own real
# CVE ids from OSV and are never overwritten by these.
_CWE_REF_CVES = {
    "CWE-89":  ["CVE-2019-6340 (Drupal SQLi RCE)", "CVE-2021-27890 (MyBB SQLi)"],
    "CWE-77":  ["CVE-2021-44228 (Log4Shell)", "CVE-2014-6271 (Shellshock)"],
    "CWE-78":  ["CVE-2021-44228 (Log4Shell chain)", "CVE-2019-14287 (sudo)"],
    "CWE-79":  ["CVE-2020-11022 (jQuery XSS)", "CVE-2019-11358 (jQuery)"],
    "CWE-918": ["CVE-2021-22214 (GitLab SSRF)", "CVE-2019-11043 (SSRF chain)"],
    "CWE-22":  ["CVE-2021-41773 (Apache path traversal)", "CVE-2018-1000861"],
    "CWE-639": ["CVE-2019-5715 (IDOR)", "CVE-2020-2140 (Jenkins IDOR)"],
    "CWE-285": ["CVE-2022-22965 (Spring auth)", "CVE-2021-22986 (F5 auth bypass)"],
    "CWE-601": ["CVE-2020-8203 (open redirect)", "CVE-2019-10744"],
    "CWE-502": ["CVE-2017-9805 (Struts deserialization)", "CVE-2015-7501 (Java)"],
    "CWE-611": ["CVE-2018-1000840 (XXE)", "CVE-2019-9670 (Zimbra XXE)"],
    "CWE-352": ["CVE-2020-11651 (CSRF chain)", "CVE-2019-11510"],
    "CWE-798": ["CVE-2022-1388 (hardcoded creds)", "CVE-2020-10148"],
    "CWE-942": ["CVE-2019-11730 (CORS)", "CVE-2018-6789"],
    "CWE-319": ["CVE-2019-12274 (cleartext)", "CVE-2018-1285"],
    "CWE-327": ["CVE-2020-1968 (weak crypto)", "CVE-2016-2183 (SWEET32)"],
    "CWE-444": ["CVE-2019-18277 (request smuggling)", "CVE-2021-33193 (h2c)"],
    "CWE-1104": [],  # SCA carries its own real CVE ids
    "CWE-95":  ["CVE-2017-11610 (code injection)", "CVE-2021-44228"],
    "CWE-200": ["CVE-2019-11510 (info disclosure)", "CVE-2020-3452"],
}


def reference_cves(cwe: str) -> list:
    return _CWE_REF_CVES.get((cwe or "").upper(), [])


def enrich(finding: dict) -> dict:
    """Add cwe + cvss + reference CVEs to a finding dict in place if absent."""
    finding["cwe"] = cwe_for(finding.get("title", ""), finding.get("cwe", ""))
    if "cvss" not in finding or not finding.get("cvss"):
        finding["cvss"] = cvss_for(finding.get("severity", "INFO"))
    # attach reference CVEs unless the finding already carries real (SCA) CVE ids
    if not finding.get("references_cve") and finding.get("cwe"):
        refs = reference_cves(finding["cwe"])
        if refs:
            finding["references_cve"] = refs
    return finding
