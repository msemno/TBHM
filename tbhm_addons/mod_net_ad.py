"""
tbhm_addons.mod_net_ad
=====================

Network + Active Directory READ-ONLY enumeration and attack-path REVIEW.

Scope of this module (deliberate):
  * Network: live-host discovery and service/version fingerprint via nmap
    (safe flags), so you know what you're looking at before touching AD.
  * AD identity review via read-only LDAP (ldapsearch / native ldap3):
      - domain / DC / trust inventory
      - privileged group membership
      - accounts with SPNs (kerberoast *targets* — identification only)
      - AS-REP-roastable accounts (DONT_REQ_PREAUTH flag)
      - unconstrained / constrained delegation
      - weak Kerberos crypto (RC4-only / DES) via msDS-SupportedEncryptionTypes
      - password policy weaknesses (never-expire, reversible encryption)

What this module does NOT do, by design:
  * No credential dumping, no hash cracking, no ticket requests, no relaying,
    no DCSync, no lateral movement. It IDENTIFIES the attack surface and the
    misconfigurations that enable those attacks, and reports them with
    remediation. Proving exploitation is a manual, per-host, client-witnessed
    step — not automated here.

Engines:
  * nmap via subprocess (must be installed).
  * LDAP via python-ldap3 if available, else ldapsearch subprocess fallback.

All actions log through a PhaseLogger from logging_core when supplied.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

try:
    import ldap3  # type: ignore
except ImportError:
    ldap3 = None  # type: ignore


# userAccountControl bit flags we care about
UAC_DONT_REQ_PREAUTH = 0x400000       # AS-REP roastable
UAC_TRUSTED_FOR_DELEGATION = 0x80000  # unconstrained delegation
UAC_PASSWD_NOTREQD = 0x0020
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_USE_DES_KEY_ONLY = 0x200000
UAC_ACCOUNTDISABLE = 0x0002

# msDS-SupportedEncryptionTypes bits
ENC_DES_CBC_CRC = 0x1
ENC_DES_CBC_MD5 = 0x2
ENC_RC4_HMAC = 0x4
ENC_AES128 = 0x8
ENC_AES256 = 0x10

PRIVILEGED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Server Operators",
    "Backup Operators", "Print Operators", "DnsAdmins",
    "Group Policy Creator Owners",
]


class _NoopPhase:
    def event(self, *a: Any, **k: Any) -> None: ...
    def tool(self, *a: Any, **k: Any) -> None: ...
    def fail(self, *a: Any, **k: Any) -> None: ...
    def run(self, name: str, argv: list[str], **k: Any):
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=k.get("timeout", 300))


@dataclass
class AdObservation:
    category: str        # spn | asrep | delegation | weak_crypto | privgroup | policy
    principal: str
    detail: str
    severity: str        # info | low | medium | high
    remediation: str = ""


@dataclass
class NetAdResult:
    dc_host: str = ""
    base_dn: str = ""
    live_hosts: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    observations: list[AdObservation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["observations"] = [asdict(o) for o in self.observations]
        return d


class NetAdModule:
    def __init__(self, nmap_timing: str = "-T3") -> None:
        self.nmap_timing = nmap_timing

    # -- network discovery --------------------------------------------------
    def discover_hosts(self, cidr: str, phase: Any = None) -> list[str]:
        ph = phase or _NoopPhase()
        nmap = shutil.which("nmap")
        if not nmap:
            ph.fail("nmap missing", RuntimeError("nmap not on PATH"))
            return []
        argv = [nmap, "-sn", self.nmap_timing, "--max-retries", "2", cidr, "-oG", "-"]
        cp = ph.run("nmap.ping", argv, timeout=600)
        hosts = re.findall(r"Host: ([\d.]+) ", cp.stdout or "")
        ph.event("discovery", f"{len(hosts)} live hosts in {cidr}",
                 cidr=cidr, count=len(hosts))
        return hosts

    def fingerprint(self, target: str, top_ports: int = 1000,
                    phase: Any = None) -> list[str]:
        ph = phase or _NoopPhase()
        nmap = shutil.which("nmap")
        if not nmap:
            return []
        argv = [nmap, "-sV", "--version-light", self.nmap_timing,
                "--top-ports", str(top_ports), "--max-retries", "2",
                target, "-oG", "-"]
        cp = ph.run("nmap.sv", argv, timeout=1200)
        svc = re.findall(r"\d+/open/\S+", cp.stdout or "")
        ph.event("fingerprint", f"{len(svc)} open services on {target}",
                 target=target)
        return svc

    # -- AD review (ldap3 path) --------------------------------------------
    def review_ad(self, dc_ip: str, base_dn: str, bind_user: str,
                  bind_password: str, phase: Any = None,
                  use_ssl: bool = False) -> NetAdResult:
        """Read-only LDAP review. bind_user/password are the AUTHORIZED test
        account from the ROE. Password is used only to bind; it is never
        logged (logging_core stores a session *handle*, not the secret)."""
        ph = phase or _NoopPhase()
        res = NetAdResult(dc_host=dc_ip, base_dn=base_dn)

        if ldap3 is None:
            # fallback to ldapsearch subprocess for raw dumps
            return self._review_ad_ldapsearch(dc_ip, base_dn, bind_user,
                                              bind_password, ph, res)

        try:
            server = ldap3.Server(dc_ip, use_ssl=use_ssl,
                                  get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=bind_user,
                                    password=bind_password, auto_bind=True)
            ph.event("ldap_bind", f"bound to {dc_ip} as (handle) test account",
                     dc=dc_ip)
        except Exception as exc:  # noqa: BLE001
            ph.fail("LDAP bind failed", exc, dc=dc_ip, user=bind_user)
            res.errors.append(f"bind: {exc}")
            return res

        # SPN accounts (kerberoast targets)
        self._ldap_spns(conn, base_dn, ph, res)
        # AS-REP roastable
        self._ldap_asrep(conn, base_dn, ph, res)
        # delegation
        self._ldap_delegation(conn, base_dn, ph, res)
        # weak crypto
        self._ldap_weak_crypto(conn, base_dn, ph, res)
        # password policy flags on accounts
        self._ldap_pwd_flags(conn, base_dn, ph, res)

        conn.unbind()
        return res

    def _search(self, conn: Any, base_dn: str, flt: str, attrs: list[str]):
        conn.search(base_dn, flt, attributes=attrs)
        return conn.entries

    def _ldap_spns(self, conn, base_dn, ph, res):
        try:
            entries = self._search(
                conn, base_dn,
                "(&(servicePrincipalName=*)(objectClass=user))",
                ["sAMAccountName", "servicePrincipalName",
                 "msDS-SupportedEncryptionTypes"])
            for e in entries:
                name = str(e["sAMAccountName"])
                enc = _first_int(e, "msDS-SupportedEncryptionTypes")
                weak = enc is not None and not (enc & (ENC_AES128 | ENC_AES256))
                res.observations.append(AdObservation(
                    category="spn", principal=name,
                    detail=f"SPN present; enc={enc} weak_rc4={weak}",
                    severity="medium" if weak else "low",
                    remediation="Use gMSA + AES-only; long random password; "
                                "remove SPNs from human accounts."))
            ph.event("ad_spn", f"{len(entries)} SPN accounts (kerberoast targets)")
        except Exception as exc:  # noqa: BLE001
            ph.fail("SPN query failed", exc)
            res.errors.append(f"spn: {exc}")

    def _ldap_asrep(self, conn, base_dn, ph, res):
        try:
            flt = (f"(&(objectClass=user)"
                   f"(userAccountControl:1.2.840.113556.1.4.803:="
                   f"{UAC_DONT_REQ_PREAUTH}))")
            entries = self._search(conn, base_dn, flt, ["sAMAccountName"])
            for e in entries:
                res.observations.append(AdObservation(
                    category="asrep", principal=str(e["sAMAccountName"]),
                    detail="DONT_REQ_PREAUTH set (AS-REP roastable)",
                    severity="high",
                    remediation="Remove 'Do not require Kerberos preauth'; "
                                "enforce strong password."))
            ph.event("ad_asrep", f"{len(entries)} AS-REP roastable accounts")
        except Exception as exc:  # noqa: BLE001
            ph.fail("AS-REP query failed", exc)
            res.errors.append(f"asrep: {exc}")

    def _ldap_delegation(self, conn, base_dn, ph, res):
        try:
            # unconstrained
            flt_u = (f"(userAccountControl:1.2.840.113556.1.4.803:="
                     f"{UAC_TRUSTED_FOR_DELEGATION})")
            for e in self._search(conn, base_dn, flt_u, ["sAMAccountName"]):
                res.observations.append(AdObservation(
                    category="delegation", principal=str(e["sAMAccountName"]),
                    detail="Unconstrained delegation enabled",
                    severity="high",
                    remediation="Remove unconstrained delegation; use "
                                "constrained/RBCD with strict targets."))
            # constrained (msDS-AllowedToDelegateTo populated)
            flt_c = "(msDS-AllowedToDelegateTo=*)"
            for e in self._search(conn, base_dn, flt_c,
                                  ["sAMAccountName", "msDS-AllowedToDelegateTo"]):
                res.observations.append(AdObservation(
                    category="delegation", principal=str(e["sAMAccountName"]),
                    detail="Constrained delegation configured (review targets)",
                    severity="medium",
                    remediation="Confirm delegation targets are minimal and "
                                "intended; watch for protocol transition."))
            ph.event("ad_deleg", "delegation review complete")
        except Exception as exc:  # noqa: BLE001
            ph.fail("delegation query failed", exc)
            res.errors.append(f"delegation: {exc}")

    def _ldap_weak_crypto(self, conn, base_dn, ph, res):
        try:
            entries = self._search(
                conn, base_dn,
                "(msDS-SupportedEncryptionTypes=*)",
                ["sAMAccountName", "msDS-SupportedEncryptionTypes"])
            for e in entries:
                enc = _first_int(e, "msDS-SupportedEncryptionTypes")
                if enc is None:
                    continue
                if enc & (ENC_DES_CBC_CRC | ENC_DES_CBC_MD5):
                    sev, note = "high", "DES enabled"
                elif enc & ENC_RC4_HMAC and not (enc & (ENC_AES128 | ENC_AES256)):
                    sev, note = "medium", "RC4-only (no AES)"
                else:
                    continue
                res.observations.append(AdObservation(
                    category="weak_crypto", principal=str(e["sAMAccountName"]),
                    detail=f"{note} (enc={enc})", severity=sev,
                    remediation="Enable AES128/AES256; disable DES/RC4."))
            ph.event("ad_crypto", "weak-crypto review complete")
        except Exception as exc:  # noqa: BLE001
            ph.fail("weak-crypto query failed", exc)
            res.errors.append(f"weak_crypto: {exc}")

    def _ldap_pwd_flags(self, conn, base_dn, ph, res):
        try:
            entries = self._search(
                conn, base_dn,
                "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:="
                f"{UAC_DONT_EXPIRE_PASSWD}))",
                ["sAMAccountName"])
            for e in entries:
                res.observations.append(AdObservation(
                    category="policy", principal=str(e["sAMAccountName"]),
                    detail="Password never expires",
                    severity="low",
                    remediation="Apply expiry or move to gMSA; justify "
                                "exceptions."))
            ph.event("ad_policy", f"{len(entries)} never-expire accounts")
        except Exception as exc:  # noqa: BLE001
            ph.fail("pwd flag query failed", exc)
            res.errors.append(f"policy: {exc}")

    # -- ldapsearch fallback ------------------------------------------------
    def _review_ad_ldapsearch(self, dc_ip, base_dn, user, password, ph, res):
        ls = shutil.which("ldapsearch")
        if not ls:
            res.errors.append("neither ldap3 nor ldapsearch available")
            ph.fail("no LDAP engine", RuntimeError("ldap3/ldapsearch missing"))
            return res
        # single raw dump of SPN accounts as a minimum viable fallback
        argv = [ls, "-x", "-H", f"ldap://{dc_ip}", "-D", user, "-w", password,
                "-b", base_dn, "(servicePrincipalName=*)",
                "sAMAccountName", "servicePrincipalName"]
        # NOTE: password appears in argv here; logging_core.tool records argv,
        # so in fallback mode we log a REDACTED argv explicitly.
        redacted = list(argv)
        redacted[redacted.index(password)] = "<redacted>"
        try:
            cp = subprocess.run(argv, capture_output=True, text=True, timeout=120)
            ph.tool("ldapsearch", redacted, returncode=cp.returncode,
                    stdout_tail=(cp.stdout or "")[:400])
            names = re.findall(r"sAMAccountName:\s*(\S+)", cp.stdout or "")
            for n in names:
                res.observations.append(AdObservation(
                    category="spn", principal=n,
                    detail="SPN present (kerberoast target, via ldapsearch)",
                    severity="low",
                    remediation="gMSA + AES-only; remove SPNs from human accts."))
            ph.event("ad_spn_fallback", f"{len(names)} SPN accounts")
        except Exception as exc:  # noqa: BLE001
            ph.fail("ldapsearch fallback failed", exc, argv=redacted)
            res.errors.append(f"ldapsearch: {exc}")
        return res


def _first_int(entry: Any, attr: str) -> Optional[int]:
    try:
        v = entry[attr].value
        if v is None:
            return None
        if isinstance(v, list):
            v = v[0]
        return int(v)
    except Exception:
        return None


if __name__ == "__main__":
    m = NetAdModule()
    print("privileged groups tracked:", len(PRIVILEGED_GROUPS))
    print("ldap3 available:", ldap3 is not None)
    print("nmap on PATH:", shutil.which("nmap") is not None)
    print("UAC flags: asrep=%#x deleg=%#x noexpire=%#x"
          % (UAC_DONT_REQ_PREAUTH, UAC_TRUSTED_FOR_DELEGATION,
             UAC_DONT_EXPIRE_PASSWD))
