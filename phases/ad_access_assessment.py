"""Safe Active Directory access and exposure assessment (v3.9).

This phase intentionally stops at read-only inventory and configuration review.
It can inspect supplied DC service exposure, SMB signing, and LDAP attributes,
and it can normalize existing BloodHound/LDAPDomainDump/AD assessment exports.
It never captures or cracks credentials, requests Kerberos service tickets,
performs pass-the-hash, remote command execution, DCSync, secrets dumping,
reverse shells, persistence, poisoning/relay, or defense evasion.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import ssl
import zipfile
from pathlib import Path

from core import redteam_utils as RT
from core.scanner_normalizer import parse_file, parse_json_value, save_items

try:
    import ldap3  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    ldap3 = None  # type: ignore

DC_PORTS = "53,88,135,139,389,445,464,636,3268,3269,5985,5986"
BIT_AND = "1.2.840.113556.1.4.803"

LDAP_QUERIES = [
    {
        "name": "spn_accounts",
        "filter": "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
        "attributes": ["sAMAccountName", "servicePrincipalName", "userAccountControl", "pwdLastSet", "memberOf"],
        "severity": "MEDIUM",
        "title": "Service account with SPN identified",
        "category": "kerberoast-exposure",
        "cwe": "CWE-521",
        "remediation": "Use long managed service-account passwords or gMSA, prefer AES, restrict privileges, and review SPN ownership.",
    },
    {
        "name": "asrep_accounts",
        "filter": f"(&(objectCategory=person)(objectClass=user)(userAccountControl:{BIT_AND}:=4194304))",
        "attributes": ["sAMAccountName", "userAccountControl", "memberOf"],
        "severity": "HIGH",
        "title": "Account does not require Kerberos pre-authentication",
        "category": "asrep-exposure",
        "cwe": "CWE-521",
        "remediation": "Require Kerberos pre-authentication and reset/review the account credentials and privileges.",
    },
    {
        "name": "unconstrained_delegation",
        "filter": f"(|(&(objectClass=user)(userAccountControl:{BIT_AND}:=524288))(&(objectClass=computer)(userAccountControl:{BIT_AND}:=524288)))",
        "attributes": ["sAMAccountName", "dNSHostName", "userAccountControl", "memberOf"],
        "severity": "HIGH",
        "title": "Unconstrained delegation configured",
        "category": "delegation",
        "cwe": "CWE-284",
        "remediation": "Remove unconstrained delegation and use constrained/resource-based delegation only where strictly required.",
    },
    {
        "name": "constrained_delegation",
        "filter": "(msDS-AllowedToDelegateTo=*)",
        "attributes": ["sAMAccountName", "dNSHostName", "msDS-AllowedToDelegateTo", "memberOf"],
        "severity": "MEDIUM",
        "title": "Constrained delegation relationship identified",
        "category": "delegation",
        "cwe": "CWE-284",
        "remediation": "Validate the delegation target and protocol transition settings; remove unused relationships.",
    },
    {
        "name": "rbcd",
        "filter": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        "attributes": ["sAMAccountName", "dNSHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        "severity": "MEDIUM",
        "title": "Resource-based constrained delegation relationship identified",
        "category": "delegation",
        "cwe": "CWE-284",
        "remediation": "Review principals permitted for RBCD and remove unexpected write/control rights over computer objects.",
    },
    {
        "name": "password_not_required",
        "filter": f"(&(objectCategory=person)(objectClass=user)(userAccountControl:{BIT_AND}:=32))",
        "attributes": ["sAMAccountName", "userAccountControl", "memberOf"],
        "severity": "HIGH",
        "title": "Account has PASSWD_NOTREQD set",
        "category": "password-policy",
        "cwe": "CWE-521",
        "remediation": "Clear PASSWD_NOTREQD, set a strong password, and review why the exception existed.",
    },
    {
        "name": "password_never_expires",
        "filter": f"(&(objectCategory=person)(objectClass=user)(userAccountControl:{BIT_AND}:=65536))",
        "attributes": ["sAMAccountName", "userAccountControl", "pwdLastSet", "memberOf"],
        "severity": "MEDIUM",
        "title": "Account password is configured to never expire",
        "category": "password-policy",
        "cwe": "CWE-521",
        "remediation": "Use gMSA or a managed rotation process and remove unnecessary non-expiring password exceptions.",
    },
]

TEXT_PATTERNS = [
    (r"(?i)message_signing\s*:\s*(?:disabled|enabled but not required)|signing.*not required", "MEDIUM", "SMB signing is not required", "CWE-319"),
    (r"(?i)DONT_REQ_PREAUTH|as-?rep.*roast", "HIGH", "AS-REP exposure candidate imported", "CWE-521"),
    (r"(?i)unconstrained delegation", "HIGH", "Unconstrained delegation candidate imported", "CWE-284"),
    (r"(?i)msDS-AllowedToActOnBehalfOfOtherIdentity|resource[- ]based constrained delegation", "MEDIUM", "RBCD relationship candidate imported", "CWE-284"),
    (r"(?i)GenericAll|GenericWrite|WriteDacl|WriteOwner|AddMember", "HIGH", "Dangerous AD ACL relationship candidate imported", "CWE-732"),
    (r"(?i)PASSWD_NOTREQD|password.*never expires", "MEDIUM", "Weak AD account password control candidate imported", "CWE-521"),
]


def _base_dn(domain: str, explicit: str = "") -> str:
    if explicit:
        return explicit
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def _entry_dict(entry, attributes: list[str]) -> dict:
    data = {"dn": str(getattr(entry, "entry_dn", ""))}
    for attr in attributes:
        try:
            value = entry[attr].value
        except Exception:
            value = ""
        if isinstance(value, (bytes, bytearray)):
            value = "[binary attribute present]"
        elif isinstance(value, list):
            value = ["[binary attribute present]" if isinstance(v, (bytes, bytearray)) else str(v) for v in value[:50]]
        elif value is not None:
            value = str(value)
        data[attr] = value
    return data


def _save_lead(ctx, *, title: str, severity: str, target: str, evidence: str,
               cwe: str, remediation: str, category: str) -> None:
    ctx.save_finding({
        "phase": "ad_access_assessment",
        "severity": severity,
        "confidence": "MEDIUM",
        "title": title if "candidate" in title.lower() else f"{title} candidate",
        "target": target,
        "description": (
            "Read-only AD configuration review identified an exposure condition. "
            "No credential attack or privilege escalation was attempted, so this remains a lead."
        ),
        "evidence": evidence[:2400],
        "impact": "If reachable and combined with weak credentials or excessive privileges, this condition may support credential or privilege-escalation paths.",
        "remediation": remediation,
        "cwe": cwe,
        "mrs_score": 75 if severity == "HIGH" else 50,
        "status": "lead",
        "finding_class": "lead",
        "validation_required": "Validate the relationship, affected principal, reachability, and business impact without performing credential theft or remote execution.",
        "playbook_branch": category,
    })


def _ldap_review(ctx, out: Path, dc: str, domain: str, base_dn: str, user: str,
                 password: str, use_ssl: bool, ca_file: str = "") -> tuple[list[dict], list[str]]:
    observations: list[dict] = []
    errors: list[str] = []
    if ldap3 is None:
        return observations, ["ldap3 is not installed; authenticated in-process LDAP review skipped"]
    try:
        tls_config = ldap3.Tls(
            validate=ssl.CERT_REQUIRED,
            ca_certs_file=ca_file or None,
        )
        server = ldap3.Server(
            dc, port=636 if use_ssl else 389, use_ssl=use_ssl, tls=tls_config,
            get_info=ldap3.NONE, connect_timeout=12,
        )
        conn = ldap3.Connection(server, user=user, password=password, auto_bind=True,
                                receive_timeout=30, raise_exceptions=False)
        if not conn.bound:
            return observations, [f"LDAP bind failed: {conn.result.get('description', 'unknown error')}"]

        # Domain policy attributes are read directly from the domain object.
        if conn.search(base_dn, "(objectClass=domainDNS)", search_scope=ldap3.BASE,
                       attributes=["minPwdLength", "lockoutThreshold", "pwdProperties", "maxPwdAge"]):
            for entry in conn.entries:
                observations.append({
                    "name": "domain_password_policy",
                    "severity": "INFO",
                    "title": "Domain password policy inventory",
                    "category": "password-policy",
                    "cwe": "CWE-521",
                    "remediation": "Review password length, lockout, and rotation controls against current organizational policy.",
                    "entry": _entry_dict(entry, ["minPwdLength", "lockoutThreshold", "pwdProperties", "maxPwdAge"]),
                })

        for query in LDAP_QUERIES:
            ok = conn.search(base_dn, query["filter"], search_scope=ldap3.SUBTREE,
                             attributes=query["attributes"], size_limit=500)
            if not ok and conn.result.get("description") not in {"success", "sizeLimitExceeded"}:
                errors.append(f"{query['name']}: {conn.result.get('description', 'query failed')}")
                continue
            for entry in conn.entries[:500]:
                observations.append({**query, "entry": _entry_dict(entry, query["attributes"])})
        conn.unbind()
    except Exception as exc:
        errors.append(f"LDAP review error: {exc}")

    (out / "ad_access_ldap_observations.json").write_text(
        json.dumps(observations, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return observations, errors


_BH_DANGEROUS_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    "ForceChangePassword", "AddMember", "AllExtendedRights",
    "GetChanges", "GetChangesAll", "AllowedToAct",
}


def _is_bloodhound(data) -> bool:
    return (
        isinstance(data, dict)
        and isinstance(data.get("data"), list)
        and isinstance(data.get("meta"), dict)
        and str((data.get("meta") or {}).get("type", "")).lower()
        in {"users", "groups", "computers", "domains", "gpos", "ous", "containers"}
    )


def _import_bloodhound(ctx, data: dict, source: str, limit: int = 5000) -> int:
    """Normalize high-signal SharpHound/BloodHound object properties and ACEs."""
    count = 0
    object_type = str((data.get("meta") or {}).get("type", "object")).rstrip("s") or "object"
    for obj in data.get("data", [])[:50_000]:
        if not isinstance(obj, dict) or count >= limit:
            break
        props = obj.get("Properties") or obj.get("properties") or {}
        if not isinstance(props, dict):
            props = {}
        identifier = str(obj.get("ObjectIdentifier") or obj.get("objectid") or "")
        target = str(props.get("name") or props.get("samaccountname") or identifier or source)

        property_checks = [
            ("dontreqpreauth", "HIGH", "Account does not require Kerberos pre-authentication", "CWE-521", "asrep-exposure"),
            ("unconstraineddelegation", "HIGH", "Unconstrained delegation configured", "CWE-284", "delegation"),
            ("passwordnotreqd", "HIGH", "Account has PASSWD_NOTREQD set", "CWE-521", "password-policy"),
            ("pwdneverexpires", "MEDIUM", "Account password is configured to never expire", "CWE-521", "password-policy"),
            ("hasspn", "MEDIUM", "Service account with SPN identified", "CWE-521", "kerberoast-exposure"),
        ]
        for key, sev, title, cwe, category in property_checks:
            if count >= limit:
                break
            if props.get(key) is True:
                _save_lead(
                    ctx, title=title, severity=sev, target=target,
                    evidence=json.dumps({"source": source, "object_type": object_type, "object": target, key: True}, ensure_ascii=False),
                    cwe=cwe, remediation="Review and harden the affected AD principal or delegation/password setting.",
                    category=category,
                )
                count += 1

        for ace in obj.get("Aces", []) or []:
            if count >= limit or not isinstance(ace, dict):
                break
            right = str(ace.get("RightName") or ace.get("rightname") or "")
            if right not in _BH_DANGEROUS_RIGHTS:
                continue
            principal = str(ace.get("PrincipalSID") or ace.get("principalid") or "unknown principal")
            _save_lead(
                ctx, title=f"BloodHound dangerous ACE: {right} on {target}",
                severity="HIGH", target=target,
                evidence=json.dumps({
                    "source": source, "principal": principal, "right": right,
                    "target": target, "inherited": bool(ace.get("IsInherited", False)),
                }, ensure_ascii=False),
                cwe="CWE-732",
                remediation="Remove unnecessary AD object-control rights, apply tiered administration, and verify the effective ACL after the change.",
                category="dangerous-ad-acl",
            )
            count += 1

        delegated = obj.get("AllowedToDelegate") or obj.get("allowedtodelegate") or []
        if delegated and count < limit:
            _save_lead(
                ctx, title=f"BloodHound constrained delegation relationship on {target}",
                severity="MEDIUM", target=target,
                evidence=json.dumps({"source": source, "object": target, "allowed_to_delegate": delegated}, ensure_ascii=False)[:2400],
                cwe="CWE-284",
                remediation="Validate each delegation target and remove unused or overly broad delegation relationships.",
                category="delegation",
            )
            count += 1

        allowed_to_act = obj.get("AllowedToAct") or obj.get("allowedtoact") or []
        if allowed_to_act and count < limit:
            _save_lead(
                ctx, title=f"BloodHound RBCD relationship on {target}",
                severity="MEDIUM", target=target,
                evidence=json.dumps({"source": source, "object": target, "allowed_to_act": allowed_to_act}, ensure_ascii=False)[:2400],
                cwe="CWE-284",
                remediation="Review principals allowed to act on behalf of the target and remove unexpected RBCD relationships.",
                category="delegation",
            )
            count += 1
    return count


def _import_text_content(ctx, text: str, target: str, max_matches: int = 500) -> int:
    count = 0
    for pattern, severity, title, cwe in TEXT_PATTERNS:
        for match in re.finditer(pattern, text):
            if count >= max_matches:
                return count
            lo, hi = max(0, match.start() - 220), min(len(text), match.end() + 500)
            _save_lead(
                ctx, title=title, severity=severity, target=target,
                evidence=text[lo:hi], cwe=cwe,
                remediation="Review the imported AD relationship or configuration, reduce privilege/exposure, and retest read-only.",
                category="imported-ad-evidence",
            )
            count += 1
    return count


def _import_text(ctx, path: Path) -> int:
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return 0
    return _import_text_content(ctx, text, str(path))


def _import_zip(ctx, path: Path) -> tuple[int, list[str]]:
    """Read bounded AD export members without extracting archive paths."""
    count = 0
    imported: list[str] = []
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:500]:
                if info.is_dir() or info.flag_bits & 0x1:
                    continue
                if info.file_size > 50_000_000:
                    continue
                total_uncompressed += info.file_size
                if total_uncompressed > 250_000_000:
                    break
                suffix = Path(info.filename).suffix.lower()
                if suffix not in {".json", ".jsonl", ".sarif", ".txt", ".log", ".csv", ".ldif", ".xml", ".html"}:
                    continue
                raw = archive.read(info)
                text = raw.decode("utf-8", errors="ignore")
                source = f"{path.name}:{info.filename}"
                if suffix in {".json", ".jsonl", ".sarif"}:
                    values = []
                    if suffix == ".jsonl":
                        for line in text.splitlines()[:100_000]:
                            if not line.strip():
                                continue
                            try:
                                values.append(json.loads(line))
                            except Exception:
                                continue
                    else:
                        try:
                            values.append(json.loads(text))
                        except Exception:
                            values = []
                    for value in values:
                        if _is_bloodhound(value):
                            count += _import_bloodhound(ctx, value, source, limit=max(0, 5000 - count))
                        else:
                            items = parse_json_value(value, Path(info.filename).stem, max_items=5000)
                            count += save_items(ctx, "ad_access_assessment", items, Path(info.filename).stem)
                        if count >= 5000:
                            break
                else:
                    count += _import_text_content(ctx, text, source)
                imported.append(source)
    except (OSError, zipfile.BadZipFile):
        return 0, []
    return count, imported


def run(ctx):
    if not (getattr(ctx.args, "ad_access", False) or getattr(ctx.args, "ad_access_results", None)):
        return

    out = RT.evidence_dir(ctx, "29_ad_access_assessment")
    supplied_dcs = RT.get_dc_ips(ctx)
    dropped_dcs: list[str] = []
    approved_cidrs = []
    for cidr in RT.get_cidrs(ctx):
        try:
            approved_cidrs.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    dcs = []
    for dc in supplied_dcs:
        allowed = bool(getattr(ctx, "scope", None) is None or ctx.scope.allows(dc))
        if approved_cidrs:
            address = ipaddress.ip_address(dc)
            allowed = allowed and any(address in network for network in approved_cidrs)
        if allowed:
            dcs.append(dc)
        else:
            dropped_dcs.append(dc)
    max_dcs = max(1, min(int(getattr(ctx.args, "ad_access_max_dcs", 5) or 5), 20))
    dcs = dcs[:max_dcs]
    domain = getattr(ctx.args, "ad_domain", None) or ""
    base_dn = _base_dn(domain, getattr(ctx.args, "ad_base_dn", None) or "")
    user = getattr(ctx.args, "ad_user", None) or ""
    pass_env = getattr(ctx.args, "ad_password_env", None) or "TBHM_AD_PASSWORD"
    password = os.environ.get(pass_env, "")
    use_ssl = bool(getattr(ctx.args, "ad_ldaps", False))
    ca_file = str(getattr(ctx.args, "ad_ldap_ca_file", None) or "")
    live_actions: list[dict] = []
    errors: list[str] = []
    normalized = 0

    if getattr(ctx.args, "ad_access", False):
        if dcs and ctx.runner.has("nmap"):
            target_file = RT.safe_target_file(ctx, "ad_access_dc_ips.txt", dcs)
            nmap_out = out / "ad_access_dc_services.nmap"
            cmd = [
                "nmap", "-sT", "-Pn", "--version-light", "--max-retries", "2",
                "--host-timeout", "5m", "-p", DC_PORTS,
                "--script", "smb2-security-mode", "-iL", str(target_file),
                "-oN", str(nmap_out),
            ]
            rc, _, err = ctx.runner.run(cmd, timeout=max(600, 360 * len(dcs)), log_name="ad_access_nmap")
            live_actions.append({"action": "nmap DC service/signing review", "returncode": rc, "output": str(nmap_out)})
            if err:
                errors.append(err[:400])
            if nmap_out.exists():
                normalized += _import_text(ctx, nmap_out)
        elif dcs:
            errors.append("nmap not installed; DC service/signing review skipped")
        else:
            errors.append("No DC IP supplied; use --dc-ip or --dc-ips-file")

        if dcs and base_dn and user and password and use_ssl:
            observations, ldap_errors = _ldap_review(
                ctx, out, dcs[0], domain, base_dn, user, password, use_ssl, ca_file
            )
            errors.extend(ldap_errors)
            live_actions.append({"action": "authenticated read-only LDAP inventory", "dc": dcs[0], "records": len(observations)})
            for obs in observations:
                if obs.get("severity") == "INFO":
                    continue
                _save_lead(
                    ctx,
                    title=obs.get("title", "AD exposure"),
                    severity=obs.get("severity", "MEDIUM"),
                    target=str((obs.get("entry") or {}).get("dn") or dcs[0]),
                    evidence=json.dumps(obs.get("entry") or {}, ensure_ascii=False),
                    cwe=obs.get("cwe", "CWE-284"),
                    remediation=obs.get("remediation", "Review and reduce the AD exposure."),
                    category=obs.get("category", "ad-access"),
                )
                normalized += 1
        else:
            missing = []
            if not dcs: missing.append("--dc-ip/--dc-ips-file")
            if not base_dn: missing.append("--ad-domain or --ad-base-dn")
            if not user: missing.append("--ad-user")
            if not password: missing.append(f"environment variable {pass_env}")
            if not use_ssl: missing.append("--ad-ldaps (required to avoid cleartext bind credentials)")
            errors.append("Authenticated LDAP review not run; missing " + ", ".join(missing))

    imported: list[str] = []
    results_path = getattr(ctx.args, "ad_access_results", None)
    if results_path:
        root = Path(results_path)
        files = [root] if root.is_file() else list(root.rglob("*")) if root.is_dir() else []
        for file in files[:2000]:
            if not file.is_file() or file.stat().st_size > 250_000_000:
                continue
            if file.suffix.lower() in {".json", ".jsonl", ".sarif"}:
                count = 0
                if file.suffix.lower() == ".json":
                    try:
                        value = json.loads(file.read_text(errors="ignore"))
                    except Exception:
                        value = None
                    if _is_bloodhound(value):
                        count = _import_bloodhound(ctx, value, str(file))
                    else:
                        items = parse_file(file, file.stem, max_items=5000)
                        count = save_items(ctx, "ad_access_assessment", items, file.stem)
                else:
                    items = parse_file(file, file.stem, max_items=5000)
                    count = save_items(ctx, "ad_access_assessment", items, file.stem)
                imported_names = [str(file)]
            elif file.suffix.lower() in {".txt", ".log", ".csv", ".ldif", ".xml", ".html"}:
                count = _import_text(ctx, file)
                imported_names = [str(file)]
            elif file.suffix.lower() == ".zip":
                count, imported_names = _import_zip(ctx, file)
            else:
                continue
            normalized += count
            imported.extend(imported_names)

    summary = {
        "domain": domain,
        "base_dn": base_dn,
        "domain_controllers": dcs,
        "dropped_out_of_scope_domain_controllers": dropped_dcs,
        "ldaps_ca_file": ca_file or "system trust store",
        "live_actions": live_actions,
        "imported_evidence": imported,
        "normalized_leads": normalized,
        "errors": errors,
        "safety_boundary": {
            "read_only": True,
            "credential_capture": False,
            "password_or_hash_cracking": False,
            "kerberos_ticket_requests": False,
            "poisoning_or_relay": False,
            "pass_the_hash": False,
            "remote_execution": False,
            "dcsync_or_secretsdump": False,
            "shells_or_metasploit": False,
            "defense_evasion": False,
            "safety_gate_override": False,
        },
    }
    (out / "ad_access_assessment.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    RT.write_md(out / "AD_ACCESS_ASSESSMENT_SUMMARY.md", "AD Access Assessment — Safe Read-Only", [
        ("Status", f"{normalized} AD exposure lead(s) normalized."),
        ("Live review", json.dumps(live_actions, ensure_ascii=False) if live_actions else "None"),
        ("Imported evidence", "\n".join(f"- {x}" for x in imported) if imported else "None"),
        ("Errors / skipped coverage", "\n".join(f"- {x}" for x in errors) if errors else "None"),
        ("Supported evidence", "BloodHound/SharpHound ZIP or extracted JSON, LDAPDomainDump, ADRecon, LDAP exports, Nmap, and other JSON/JSONL/SARIF/text assessment outputs through bounded import."),
        ("Scope enforcement", f"Accepted DCs: {', '.join(dcs) if dcs else 'none'}; dropped: {', '.join(dropped_dcs) if dropped_dcs else 'none'}."),
        ("Safety boundary", "No Responder/Inveigh poisoning, Kerberoasting/AS-REP ticket retrieval, credential/hash cracking, pass-the-hash, WMI/WinRM/SMB command execution, DCSync, secretsdump, Golden Tickets, Metasploit, reverse/bind shells, persistence, AMSI/EDR bypass, or safety-gate disabling."),
        ("Evidence", str(out / "ad_access_assessment.json")),
    ])
    ctx.log("OK", "ad_access_assessment", f"{normalized} AD access/exposure lead(s) normalized")
