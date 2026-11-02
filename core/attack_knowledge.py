"""
core/attack_knowledge.py   (v3.2)

Static knowledge tables used by the post-processing analysis phases:

  * MITRE ATT&CK technique mapping (phase/finding -> TTP)
  * attack-chain rules (which finding combinations imply an escalation path)
  * compliance mapping (CWE / OWASP Top 10 2021 / OWASP API Top 10 / PCI-DSS)

Everything here is read-only reference data. No network, no third-party deps.
"""
from __future__ import annotations

import re

# ── MITRE ATT&CK: map a finding to (tactic, technique_id, technique_name) ────
# Keyed by a lowercase substring match against the finding title/phase/cwe.
ATTACK_MAP = [
    # (matcher, tactic, technique_id, technique_name)
    ("subdomain takeover", "Initial Access", "T1584.001", "Compromise Infrastructure: Domains"),
    ("cname", "Initial Access", "T1584.001", "Compromise Infrastructure: Domains"),
    ("sql injection", "Initial Access", "T1190", "Exploit Public-Facing Application"),
    ("command injection", "Execution", "T1059", "Command and Scripting Interpreter"),
    ("code injection", "Execution", "T1059", "Command and Scripting Interpreter"),
    ("rce", "Execution", "T1059", "Command and Scripting Interpreter"),
    ("deserialization", "Execution", "T1059", "Command and Scripting Interpreter"),
    ("ssrf", "Discovery", "T1590", "Gather Victim Network Information"),
    ("xxe", "Collection", "T1213", "Data from Information Repositories"),
    ("hardcoded secret", "Credential Access", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    ("secret in", "Credential Access", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    ("api key", "Credential Access", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    (".env", "Credential Access", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    ("jwt", "Credential Access", "T1552", "Unsecured Credentials"),
    ("as-rep", "Credential Access", "T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting"),
    ("kerberoast", "Credential Access", "T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
    ("spn", "Credential Access", "T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
    ("delegation", "Privilege Escalation", "T1134.005", "Access Token Manipulation: SID-History"),
    ("dcsync", "Credential Access", "T1003.006", "OS Credential Dumping: DCSync"),
    ("idor", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    ("broken access", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    ("privilege", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    ("admin", "Privilege Escalation", "T1078", "Valid Accounts"),
    ("auth", "Defense Evasion", "T1078", "Valid Accounts"),
    ("cors", "Collection", "T1119", "Automated Collection"),
    ("open redirect", "Initial Access", "T1566.002", "Phishing: Spearphishing Link"),
    ("upload", "Persistence", "T1505.003", "Server Software Component: Web Shell"),
    ("webshell", "Persistence", "T1505.003", "Server Software Component: Web Shell"),
    ("service binary", "Privilege Escalation", "T1543.003", "Create/Modify System Process: Windows Service"),
    ("unquoted service", "Privilege Escalation", "T1574.009", "Hijack Execution Flow: Unquoted Path"),
    ("dll", "Privilege Escalation", "T1574.001", "Hijack Execution Flow: DLL Search Order"),
    ("actuator", "Discovery", "T1082", "System Information Discovery"),
    ("s3", "Collection", "T1530", "Data from Cloud Storage"),
    ("bucket", "Collection", "T1530", "Data from Cloud Storage"),
    ("metadata", "Credential Access", "T1552.005", "Cloud Instance Metadata API"),
    ("webhook", "Command and Control", "T1102", "Web Service"),
    ("prompt injection", "Execution", "T1059", "Command and Scripting Interpreter"),
    ("smuggling", "Defense Evasion", "T1090", "Proxy"),
    ("dependency", "Initial Access", "T1195.001", "Supply Chain Compromise: Software Dependencies"),
    ("typosquat", "Initial Access", "T1195.001", "Supply Chain Compromise: Software Dependencies"),
    ("ci/cd", "Initial Access", "T1195.002", "Supply Chain Compromise: Software Supply Chain"),
    ("exposed", "Discovery", "T1046", "Network Service Discovery"),
    ("port", "Discovery", "T1046", "Network Service Discovery"),
]


def map_attack(finding: dict) -> tuple[str, str, str] | None:
    hay = " ".join(str(finding.get(k, "")) for k in
                   ("title", "phase", "cwe", "description")).lower()
    for matcher, tactic, tid, tname in ATTACK_MAP:
        if matcher in hay:
            return tactic, tid, tname
    return None


# ── attack-chain rules ───────────────────────────────────────────────────────
# Each rule: name, list of required capability tags, resulting narrative.
# A finding contributes a capability tag if any of its `signals` match.
CAP_SIGNALS = {
    "foothold_web":  ["sql injection", "command injection", "rce", "deserialization",
                      "upload", "webshell", "code injection"],
    "creds_exposed": ["hardcoded secret", "api key", "secret in", ".env", "credential",
                      "console.log", "jwt"],
    "cloud_access":  ["s3", "bucket", "metadata", "iam", "lambda", "actuator"],
    "ad_surface":    ["as-rep", "kerberoast", "spn", "delegation", "dcsync"],
    "priv_esc":      ["idor", "broken access", "privilege", "service binary",
                      "unquoted service", "dll", "admin route", "admin surface"],
    "recon_exposed": ["exposed", "port", "subdomain", "actuator", "swagger", "openapi"],
    "persistence":   ["upload", "webshell", "service binary", "rmm", "scheduled"],
    "c2_egress":     ["webhook", "smuggling", "ssrf", "open redirect"],
}

CHAIN_RULES = [
    ("External foothold to cloud takeover",
     ["foothold_web", "creds_exposed", "cloud_access"],
     "External app compromise ({foothold_web}) exposes credentials ({creds_exposed}) "
     "that grant cloud access ({cloud_access}). An attacker moves from the public app "
     "into the cloud control plane."),
    ("Secret exposure to AD escalation",
     ["creds_exposed", "ad_surface"],
     "Leaked credentials ({creds_exposed}) combined with an exposed AD attack surface "
     "({ad_surface}) enable domain credential access and lateral movement."),
    ("Web foothold to privilege escalation",
     ["foothold_web", "priv_esc"],
     "Initial web access ({foothold_web}) chains with a privilege-escalation primitive "
     "({priv_esc}) to reach higher-privileged functionality."),
    ("Recon exposure to foothold",
     ["recon_exposed", "foothold_web"],
     "Exposed services/endpoints ({recon_exposed}) provide the entry point exploited "
     "for a foothold ({foothold_web})."),
    ("Foothold to persistence and egress",
     ["foothold_web", "persistence", "c2_egress"],
     "A foothold ({foothold_web}) is made durable via persistence ({persistence}) and "
     "an outbound channel ({c2_egress}) suitable for command-and-control."),
    ("Supply-chain to execution",
     ["recon_exposed", "foothold_web"],
     "A dependency/CI weakness provides code execution in the build or runtime path."),
]


def capabilities_of(finding: dict) -> set[str]:
    hay = " ".join(str(finding.get(k, "")) for k in
                   ("title", "phase", "cwe", "description")).lower()
    caps = set()
    for cap, signals in CAP_SIGNALS.items():
        if any(s in hay for s in signals):
            caps.add(cap)
    return caps


# ── compliance mapping ───────────────────────────────────────────────────────
# CWE -> OWASP Top 10 2021 category
CWE_TO_OWASP = {
    "CWE-89": "A03:2021 Injection",
    "CWE-78": "A03:2021 Injection",
    "CWE-79": "A03:2021 Injection",
    "CWE-94": "A03:2021 Injection",
    "CWE-95": "A03:2021 Injection",
    "CWE-611": "A05:2021 Security Misconfiguration",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-1104": "A06:2021 Vulnerable and Outdated Components",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-306": "A07:2021 Identification and Authentication Failures",
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-284": "A01:2021 Broken Access Control",
    "CWE-639": "A01:2021 Broken Access Control",
    "CWE-862": "A01:2021 Broken Access Control",
    "CWE-863": "A01:2021 Broken Access Control",
    "CWE-434": "A04:2021 Insecure Design",
    "CWE-840": "A04:2021 Insecure Design",
    "CWE-918": "A10:2021 Server-Side Request Forgery",
    "CWE-295": "A02:2021 Cryptographic Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-345": "A08:2021 Software and Data Integrity Failures",
    "CWE-506": "A08:2021 Software and Data Integrity Failures",
    "CWE-732": "A05:2021 Security Misconfiguration",
    "CWE-16":  "A05:2021 Security Misconfiguration",
    "CWE-1427": "A04:2021 Insecure Design",
    "CWE-926": "A04:2021 Insecure Design",
}

OWASP_TOP10_2021 = [
    "A01:2021 Broken Access Control",
    "A02:2021 Cryptographic Failures",
    "A03:2021 Injection",
    "A04:2021 Insecure Design",
    "A05:2021 Security Misconfiguration",
    "A06:2021 Vulnerable and Outdated Components",
    "A07:2021 Identification and Authentication Failures",
    "A08:2021 Software and Data Integrity Failures",
    "A09:2021 Security Logging and Monitoring Failures",
    "A10:2021 Server-Side Request Forgery",
]

# OWASP category -> relevant PCI-DSS v4.0 requirement(s)
OWASP_TO_PCI = {
    "A01:2021 Broken Access Control": "PCI 7 (Restrict access), PCI 8 (Identify users)",
    "A02:2021 Cryptographic Failures": "PCI 3 (Protect stored data), PCI 4 (Encrypt transmission)",
    "A03:2021 Injection": "PCI 6.2.4 (Secure coding), PCI 6.4 (Web app protections)",
    "A04:2021 Insecure Design": "PCI 6.2 (Bespoke software)",
    "A05:2021 Security Misconfiguration": "PCI 2 (Secure configurations)",
    "A06:2021 Vulnerable and Outdated Components": "PCI 6.3 (Security vulnerabilities)",
    "A07:2021 Identification and Authentication Failures": "PCI 8 (Authenticate access)",
    "A08:2021 Software and Data Integrity Failures": "PCI 6.4.3, PCI 11.5 (Change detection)",
    "A09:2021 Security Logging and Monitoring Failures": "PCI 10 (Log and monitor)",
    "A10:2021 Server-Side Request Forgery": "PCI 6.2.4 (Secure coding)",
}

# Which OWASP categories each TBHM phase is capable of covering (for gap detection).
PHASE_OWASP_COVERAGE = {
    "injections": ["A03:2021 Injection"],
    "add_sqli": ["A03:2021 Injection"],
    "code_intel": ["A01:2021 Broken Access Control", "A03:2021 Injection",
                   "A04:2021 Insecure Design", "A06:2021 Vulnerable and Outdated Components",
                   "A07:2021 Identification and Authentication Failures",
                   "A08:2021 Software and Data Integrity Failures"],
    "access_control": ["A01:2021 Broken Access Control"],
    "auth_advanced": ["A07:2021 Identification and Authentication Failures"],
    "vuln_scan_extended": ["A06:2021 Vulnerable and Outdated Components"],
    "code_scan": ["A02:2021 Cryptographic Failures",
                  "A06:2021 Vulnerable and Outdated Components"],
    "secrets_misc": ["A05:2021 Security Misconfiguration"],
    "infra_exposure": ["A05:2021 Security Misconfiguration"],
    "waf_evasion_ssrf": ["A10:2021 Server-Side Request Forgery"],
    "business_logic": ["A04:2021 Insecure Design"],
}


def owasp_for(finding: dict) -> str:
    cwe = (finding.get("cwe") or "").upper().strip()
    if cwe in CWE_TO_OWASP:
        return CWE_TO_OWASP[cwe]
    # fall back to keyword inference
    hay = (finding.get("title", "") + " " + finding.get("description", "")).lower()
    if "sql" in hay or "xss" in hay or "injection" in hay:
        return "A03:2021 Injection"
    if "access" in hay or "idor" in hay or "authoriz" in hay:
        return "A01:2021 Broken Access Control"
    if "ssrf" in hay:
        return "A10:2021 Server-Side Request Forgery"
    if "secret" in hay or "credential" in hay or "auth" in hay:
        return "A07:2021 Identification and Authentication Failures"
    if "dependency" in hay or "cve" in hay or "outdated" in hay:
        return "A06:2021 Vulnerable and Outdated Components"
    if "tls" in hay or "crypto" in hay or "cipher" in hay:
        return "A02:2021 Cryptographic Failures"
    if "misconfig" in hay or "exposed" in hay or "header" in hay:
        return "A05:2021 Security Misconfiguration"
    return "Unmapped"
