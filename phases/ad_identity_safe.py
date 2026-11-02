"""Active Directory / identity read-only checks."""
from __future__ import annotations
import os
import tempfile
from pathlib import Path
from core import redteam_utils as RT

DC_PORTS = "53,88,135,139,389,445,464,593,636,3268,3269,5985,5986"


def run(ctx):
    out = RT.evidence_dir(ctx, "05_active_directory_identity")
    dcs = RT.get_dc_ips(ctx)
    domain = getattr(ctx.args, "ad_domain", None) or ""
    ad_user = getattr(ctx.args, "ad_user", None) or ""
    pass_env = getattr(ctx.args, "ad_password_env", None) or "TBHM_AD_PASSWORD"
    use_ldaps = bool(getattr(ctx.args, "ad_ldaps", False))
    ldap_ca_file = str(getattr(ctx.args, "ad_ldap_ca_file", None) or "")

    if not dcs and not domain:
        RT.write_md(out / "AD_NOT_RUN.md", "AD / Identity Not Run", [
            ("Reason", "No --dc-ip / --dc-ips-file / --ad-domain was supplied. This branch is marked Not Tested, not Safe."),
            ("Minimum inputs", "--ad-domain corp.local --dc-ip 10.10.10.10. Optional read-only LDAP bind: --ad-user user@corp.local with password in env var TBHM_AD_PASSWORD."),
        ])
        RT.add_control_finding(ctx, "ad_identity_safe", "AD identity branch not tested", "INFO",
                               "No AD/DC input supplied; do not claim AD coverage.", str(out / "AD_NOT_RUN.md"),
                               remediation="Provide approved domain controller IP/domain and rerun.")
        return

    # DNS SRV discovery if a domain is supplied.
    if domain:
        if ctx.runner.has("dig"):
            for rec in [f"_ldap._tcp.dc._msdcs.{domain}", f"_kerberos._tcp.{domain}"]:
                ctx.runner.run(["dig", "+short", "SRV", rec], timeout=60, log_name=f"rt_ad_dig_{rec.replace('.', '_')}", capture_mode="tail")
        elif ctx.runner.has("nslookup"):
            ctx.runner.run(["nslookup", "-type=SRV", f"_ldap._tcp.dc._msdcs.{domain}"], timeout=60, log_name="rt_ad_nslookup_ldap", capture_mode="tail")

    # DC service exposure scan.
    if dcs and ctx.runner.has("nmap"):
        tf = RT.safe_target_file(ctx, "dc_ips.txt", dcs)
        ctx.runner.run(["nmap", "-sV", "--version-light", "-Pn", "-p", DC_PORTS, "-iL", str(tf),
                        "-oN", str(out / "dc_services.nmap")], timeout=1800, log_name="rt_ad_dc_services", capture_mode="tail")

    # Anonymous LDAP namingContexts check only. No password attacks.
    if dcs and ctx.runner.has("ldapsearch"):
        for dc in dcs[:3]:
            ctx.runner.run(["ldapsearch", "-x", "-H", f"ldap://{dc}", "-s", "base", "namingContexts"],
                           timeout=60, log_name=f"rt_ad_anon_ldap_{dc}", capture_mode="tail")

    # Authenticated read-only LDAP summary if credentials are explicitly provided by env.
    ran_auth = False
    if dcs and domain and ad_user and os.environ.get(pass_env) and use_ldaps and ctx.runner.has("ldapsearch"):
        # Derive Base DN from domain labels.
        base = ",".join(f"DC={p}" for p in domain.split(".") if p)
        dc = dcs[0]
        pw = os.environ.get(pass_env, "")
        ran_auth = True
        queries = {
            "domain_policy_rootdse": ["-s", "base", "*"],
            "users_sample": ["-b", base, "(&(objectCategory=person)(objectClass=user))", "sAMAccountName", "userAccountControl", "servicePrincipalName"],
            "groups_sample": ["-b", base, "(objectClass=group)", "cn", "member"],
            "computers_sample": ["-b", base, "(objectClass=computer)", "dNSHostName", "operatingSystem", "userAccountControl"],
        }
        password_file = None
        try:
            # ldapsearch -y reads the bind password from a protected file, avoiding
            # command-line/process-list and TBHM command-log exposure.
            with tempfile.NamedTemporaryFile("w", prefix="tbhm-ldap-", delete=False) as tmp:
                tmp.write(pw)
                password_file = tmp.name
            os.chmod(password_file, 0o600)
            for name, q in queries.items():
                cmd = ["ldapsearch", "-LLL", "-H", f"ldaps://{dc}:636", "-D", ad_user, "-y", password_file] + q
                ldap_env = {"LDAPTLS_CACERT": ldap_ca_file} if ldap_ca_file else None
                rc, out_text, err = ctx.runner.run(
                    cmd, timeout=180, log_name=f"rt_ad_ldap_{name}", env=ldap_env
                )
                (out / f"{name}.ldif").write_text(out_text[:500000], encoding="utf-8", errors="ignore")
        finally:
            if password_file:
                try:
                    os.unlink(password_file)
                except OSError:
                    pass
    elif dcs and domain and ad_user and os.environ.get(pass_env) and not use_ldaps:
        ctx.log("WARN", "ad_identity", "authenticated LDAP inventory skipped: add --ad-ldaps to protect bind credentials")

    cards = [
        {"check": "Domain controller service exposure", "status": "tested" if dcs else "not tested", "evidence": "dc_services.nmap"},
        {"check": "Anonymous LDAP rootDSE/namingContexts", "status": "tested" if dcs and ctx.runner.has("ldapsearch") else "not tested", "evidence": "logs/rt_ad_anon_ldap_*"},
        {"check": "Authenticated read-only LDAPS inventory", "status": "tested" if ran_auth else "not tested", "evidence": "users_sample.ldif/groups_sample.ldif/computers_sample.ldif"},
        {"check": "Kerberoast/AS-REP/AD CS/delegation/DCSync", "status": "not executed by this tool", "evidence": "Requires separate high-risk authorization or lab emulation; report as residual risk if not tested."},
    ]
    RT.write_csv(out / "ad_identity_status.csv", cards)
    RT.write_md(out / "AD_IDENTITY_SUMMARY.md", "AD / Identity Safe Summary", [
        ("Inputs", f"domain={domain or 'not set'}; dcs={', '.join(dcs) if dcs else 'not set'}; auth_readonly={'yes' if ran_auth else 'no'}"),
        ("What this phase tests", "DC services, DNS/LDAP discovery, anonymous LDAP exposure, and optional read-only LDAPS inventory."),
        ("What it does not do", "No hash capture/cracking, credential dumping, NTLM relay, Kerberoasting execution, DCSync, lateral movement, or persistence."),
        ("Report wording", "If high-risk AD attack paths were not separately approved, mark them Needs High-Risk Approval / Not Tested instead of Safe."),
    ])
    RT.add_control_finding(ctx, "ad_identity_safe", "AD / identity safe review completed", "INFO",
                           "Generated AD/DC safe review status and evidence files.", str(out / "ad_identity_status.csv"),
                           remediation="Use the AD status CSV to decide which identity attack paths need separate approval.")
    ctx.log("OK", "ad_identity", f"AD safe review written to {out}")
