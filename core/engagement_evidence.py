"""Authorized exercise evidence normalization and instructor simulation helpers.

This module never launches credential attacks, remote execution, persistence,
defense evasion, or exploitation tooling. It accepts evidence produced by a
separately governed exercise, redacts secrets and operational command details,
and converts the material into provenance-preserving TBHM observations.
"""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Iterable

from core.llm_local import redact_text

_ALLOWED_SUFFIXES = {".json", ".jsonl", ".sarif", ".txt", ".log", ".csv", ".md", ".xml"}
_MAX_MEMBER_BYTES = 8 * 1024 * 1024

# Detection is intentionally evidence-oriented. Regex matches are used only to
# categorize imported material; matched secrets/commands are never emitted.
_CATEGORIES = [
    {
        "name": "credential-capture",
        "pattern": re.compile(r"(?i)\b(?:responder|inveigh|net-?ntlmv?2?|credential capture|captured hash)\b"),
        "severity": "HIGH",
        "title": "Credential-capture activity present in authorized exercise evidence",
        "technique": "T1557.001",
        "cwe": "CWE-319",
        "remediation": "Disable unnecessary name-resolution fallbacks, require SMB signing, harden authentication, and monitor for credential-capture infrastructure.",
    },
    {
        "name": "offline-credential-recovery",
        "pattern": re.compile(r"(?i)\b(?:hashcat|john(?: the ripper)?|potfile|password recovered|hash cracked)\b"),
        "severity": "HIGH",
        "title": "Offline credential-recovery result present in authorized exercise evidence",
        "technique": "T1110.002",
        "cwe": "CWE-521",
        "remediation": "Reset affected credentials, increase password strength, use managed service accounts, and review password policy and reuse exposure.",
    },
    {
        "name": "kerberos-ticket-exposure",
        "pattern": re.compile(r"(?i)\b(?:kerberoast|as-?rep roast|krb5tgs|krb5asrep|tgs-?rep|rubeus|getuserspns)\b"),
        "severity": "HIGH",
        "title": "Kerberos ticket-exposure activity present in authorized exercise evidence",
        "technique": "T1558",
        "cwe": "CWE-521",
        "remediation": "Use gMSA or long managed service-account passwords, require pre-authentication, prefer AES, and reduce service-account privilege.",
    },
    {
        "name": "pass-the-hash",
        "pattern": re.compile(r"(?i)\b(?:pass[- ]the[- ]hash|pth|pwn3d|netexec|crackmapexec|nxc)\b"),
        "severity": "CRITICAL",
        "title": "Pass-the-hash activity present in authorized exercise evidence",
        "technique": "T1550.002",
        "cwe": "CWE-522",
        "remediation": "Reduce local-admin reuse, deploy Windows LAPS, restrict NTLM, use credential guard, tier administration, and segment management protocols.",
    },
    {
        "name": "remote-command-execution",
        "pattern": re.compile(r"(?i)\b(?:wmiexec|psexec|smbexec|atexec|evil-winrm|remote command|command execution|interactive session)\b"),
        "severity": "CRITICAL",
        "title": "Remote command-execution evidence present in authorized exercise artifacts",
        "technique": "T1021",
        "cwe": "CWE-284",
        "remediation": "Restrict remote-management protocols, enforce privileged access workstations, remove excessive admin rights, and monitor remote service creation and WMI/WinRM use.",
    },
    {
        "name": "directory-replication-exposure",
        "pattern": re.compile(r"(?i)\b(?:dcsync|secretsdump|ntds\.dit|krbtgt|directory replication)\b"),
        "severity": "CRITICAL",
        "title": "Directory-replication or domain-secret exposure evidence present",
        "technique": "T1003.006",
        "cwe": "CWE-732",
        "remediation": "Remove unauthorized replication rights, rotate exposed credentials in the correct order, protect domain controllers, and monitor replication APIs and privileged group changes.",
    },
    {
        "name": "metasploit-session",
        "pattern": re.compile(r"(?i)\b(?:metasploit|meterpreter|msfconsole|msfvenom|session opened)\b"),
        "severity": "HIGH",
        "title": "Metasploit or post-exploitation session evidence present",
        "technique": "T1059",
        "cwe": "CWE-284",
        "remediation": "Review the initial execution path, contain affected systems, collect EDR telemetry, remove introduced artifacts, and correct the enabling control weakness.",
    },
    {
        "name": "remote-shell",
        "pattern": re.compile(r"(?i)\b(?:reverse shell|bind shell|shell session|command shell)\b"),
        "severity": "CRITICAL",
        "title": "Remote shell evidence present in authorized exercise artifacts",
        "technique": "T1059.003",
        "cwe": "CWE-78",
        "remediation": "Identify and close the execution path, restrict outbound and inbound control channels, improve application control, and validate EDR prevention and response coverage.",
    },
    {
        "name": "persistence",
        "pattern": re.compile(r"(?i)\b(?:persistence|autorun|run key|scheduled task|service install|startup folder|logon script)\b"),
        "severity": "HIGH",
        "title": "Persistence activity present in authorized exercise evidence",
        "technique": "T1547",
        "cwe": "CWE-284",
        "remediation": "Remove exercise artifacts, review persistence-capable locations, restrict modification rights, and alert on unexpected service, task, and autorun changes.",
    },
    {
        "name": "defense-evasion",
        "pattern": re.compile(r"(?i)\b(?:amsi bypass|edr bypass|disable defender|tamper protection|security tool disabled|defense evasion)\b"),
        "severity": "HIGH",
        "title": "Defense-evasion activity present in authorized exercise evidence",
        "technique": "T1562.001",
        "cwe": "CWE-693",
        "remediation": "Enable tamper protection, restrict security-control changes, monitor exclusions and service stops, and validate prevention plus alerting with approved benign simulations.",
    },
]

_OPERATIONAL_LINE = re.compile(
    r"(?i)(?:\b(?:mimikatz|secretsdump|rubeus|hashcat|john(?: the ripper)?|"
    r"netexec|crackmapexec|nxc|wmiexec|psexec|smbexec|atexec|evil-winrm|"
    r"msfconsole|msfvenom|meterpreter|responder|inveigh)\b|"
    r"\b(?:powershell|cmd\.exe|/bin/(?:ba)?sh|curl|wget|nc|ncat)\b[^\n]{0,220})"
)


def sanitize_excerpt(value: object, limit: int = 1600) -> str:
    """Return a redacted, non-operational excerpt suitable for reports."""
    text = redact_text(value, max(limit * 2, 2000))
    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _OPERATIONAL_LINE.search(line):
            lines.append("[OPERATIONAL COMMAND OR TOOL DETAIL REDACTED]")
        else:
            lines.append(line[:500])
        if sum(len(item) for item in lines) >= limit:
            break
    return "\n".join(lines)[:limit]


def _safe_zip_name(name: str) -> bool:
    p = Path(name)
    return not p.is_absolute() and ".." not in p.parts


def _read_file(path: Path, byte_limit: int) -> tuple[bytes, str]:
    data = path.read_bytes()[:byte_limit]
    return data, data.decode("utf-8", errors="replace")


def iter_evidence_blobs(path: str | Path, max_files: int = 200,
                        max_total_bytes: int = 100 * 1024 * 1024) -> Iterable[tuple[str, bytes, str]]:
    """Yield ``(source_name, raw_bytes, decoded_text)`` under strict bounds."""
    root = Path(path).expanduser().resolve()
    candidates: list[Path]
    if root.is_file():
        candidates = [root]
    elif root.is_dir():
        candidates = sorted(p for p in root.rglob("*") if p.is_file())
    else:
        raise FileNotFoundError(f"evidence path does not exist: {root}")

    total = 0
    emitted = 0
    for item in candidates:
        if emitted >= max_files or total >= max_total_bytes:
            break
        if item.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(item) as zf:
                    for member in zf.infolist():
                        if emitted >= max_files or total >= max_total_bytes:
                            break
                        suffix = Path(member.filename).suffix.lower()
                        if member.is_dir() or suffix not in _ALLOWED_SUFFIXES or not _safe_zip_name(member.filename):
                            continue
                        remaining = max_total_bytes - total
                        read_limit = min(_MAX_MEMBER_BYTES, remaining)
                        if read_limit <= 0:
                            break
                        data = zf.read(member)[:read_limit]
                        total += len(data)
                        emitted += 1
                        yield f"{item.name}!{member.filename}", data, data.decode("utf-8", errors="replace")
            except zipfile.BadZipFile:
                continue
            continue

        if item.suffix.lower() not in _ALLOWED_SUFFIXES:
            continue
        remaining = max_total_bytes - total
        if remaining <= 0:
            break
        data, text = _read_file(item, min(_MAX_MEMBER_BYTES, remaining))
        total += len(data)
        emitted += 1
        yield str(item), data, text


def _line_excerpt(text: str, pattern: re.Pattern[str]) -> str:
    for line in text.splitlines():
        if pattern.search(line):
            return sanitize_excerpt(line)
    return "[MATCHED EVIDENCE REDACTED]"


def analyze_path(path: str | Path, forced_type: str = "auto", max_files: int = 200,
                 max_total_mb: int = 100) -> dict:
    observations: dict[str, dict] = {}
    sources: list[dict] = []
    total_bytes = max(1, min(int(max_total_mb), 1024)) * 1024 * 1024
    for source, raw, text in iter_evidence_blobs(path, max(1, min(max_files, 2000)), total_bytes):
        sha256 = hashlib.sha256(raw).hexdigest()
        sources.append({"source": source, "sha256": sha256, "bytes_read": len(raw)})
        for category in _CATEGORIES:
            if forced_type != "auto" and category["name"] != forced_type:
                continue
            matches = list(category["pattern"].finditer(text))
            if not matches:
                continue
            current = observations.setdefault(category["name"], {
                **{k: v for k, v in category.items() if k != "pattern"},
                "match_count": 0,
                "sources": [],
                "excerpts": [],
            })
            current["match_count"] += len(matches)
            if source not in current["sources"]:
                current["sources"].append(source)
            if len(current["excerpts"]) < 3:
                current["excerpts"].append(_line_excerpt(text, category["pattern"]))

    return {
        "mode": "authorized-evidence-import",
        "source_path": str(Path(path).expanduser()),
        "files_processed": len(sources),
        "sources": sources,
        "observations": list(observations.values()),
        "safety": {
            "execution_performed": False,
            "credentials_stored": False,
            "hashes_stored": False,
            "operational_commands_stored": False,
            "provenance_hashes_recorded": True,
        },
    }


def synthetic_scenario(name: str = "ad-domain-compromise") -> dict:
    """Return non-operational training evidence for instructor demonstrations."""
    scenario = name or "ad-domain-compromise"
    stages = [
        ("credential-capture", "Simulated name-resolution credential-capture alert", "T1557.001"),
        ("kerberos-ticket-exposure", "Simulated service-account ticket exposure", "T1558"),
        ("offline-credential-recovery", "Simulated weak credential recovery outcome", "T1110.002"),
        ("pass-the-hash", "Simulated credential-reuse validation across a lab segment", "T1550.002"),
        ("remote-command-execution", "Simulated remote administration proof event", "T1021"),
        ("directory-replication-exposure", "Simulated unauthorized directory replication alert", "T1003.006"),
        ("persistence", "Simulated persistence-control validation event", "T1547"),
        ("defense-evasion", "Simulated security-control tamper alert", "T1562.001"),
    ]
    by_name = {item["name"]: item for item in _CATEGORIES}
    observations = []
    for category_name, description, technique in stages:
        meta = by_name[category_name]
        observations.append({
            "name": category_name,
            "severity": "INFO",
            "title": f"[SIMULATION] {meta['title']}",
            "technique": technique,
            "cwe": meta["cwe"],
            "remediation": meta["remediation"],
            "match_count": 1,
            "sources": ["synthetic-instructor-scenario"],
            "excerpts": [description],
            "simulation": True,
        })
    return {
        "mode": "instructor-simulation",
        "scenario": scenario,
        "files_processed": 0,
        "sources": [],
        "observations": observations,
        "safety": {
            "execution_performed": False,
            "network_activity": False,
            "credentials_used": False,
            "operational_commands_generated": False,
            "synthetic_only": True,
        },
    }
