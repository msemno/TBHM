"""TBHM v3 phase: deeper network + AD read-only review add-on."""
from __future__ import annotations

import os

from tbhm_addons.mod_net_ad import NetAdModule, NetAdResult
from core import redteam_utils as RT
from .addons_common import evidence_dir, save_json, write_md, make_logger, domain_to_base_dn, severity


CATEGORY_TITLE = {
    "spn": "Kerberoast target exposure",
    "asrep": "AS-REP roastable account",
    "delegation": "Delegation configuration requires review",
    "weak_crypto": "Weak Kerberos encryption configuration",
    "privgroup": "Privileged group exposure",
    "policy": "Password policy exception",
}


def run(ctx):
    phase_name = "add_net_ad"
    out = evidence_dir(ctx, "02_add_net_ad")
    cidrs = RT.get_cidrs(ctx)
    dcs = RT.get_dc_ips(ctx)
    domain = getattr(ctx.args, "ad_domain", None) or ""
    base_dn = getattr(ctx.args, "ad_base_dn", None) or (domain_to_base_dn(domain) if domain else "")
    ad_user = getattr(ctx.args, "ad_user", None) or ""
    pass_env = getattr(ctx.args, "ad_password_env", None) or "TBHM_AD_PASSWORD"
    ad_password = os.environ.get(pass_env, "")
    use_ldaps = bool(getattr(ctx.args, "ad_ldaps", False))

    logger_target = dcs[0] if dcs else (cidrs[0] if cidrs else (domain or "AD"))
    logger = make_logger(ctx, "ADD-NETAD", target=logger_target)
    mod = NetAdModule(nmap_timing=getattr(ctx.args, "addon_nmap_timing", "-T3") or "-T3")

    result = NetAdResult(dc_host=dcs[0] if dcs else "", base_dn=base_dn)

    with logger.phase("ADD-NETAD", "Network + AD read-only attack-surface review", silent=getattr(ctx.args, "silent", False)) as ph:
        for cidr in cidrs:
            hosts = mod.discover_hosts(cidr, phase=ph)
            result.live_hosts.extend(hosts)
        # Fingerprint supplied DCs only by default to avoid scanning whole networks twice.
        for dc in dcs[:5]:
            services = mod.fingerprint(dc, phase=ph)
            result.services.extend([f"{dc} {s}" for s in services])
        if dcs and base_dn and ad_user and ad_password:
            ad_result = mod.review_ad(dcs[0], base_dn, ad_user, ad_password, phase=ph, use_ssl=use_ldaps)
            result.observations.extend(ad_result.observations)
            result.errors.extend(ad_result.errors)
        else:
            missing = []
            if not dcs: missing.append("--dc-ip/--dc-ips-file")
            if not base_dn: missing.append("--ad-base-dn or --ad-domain")
            if not ad_user: missing.append("--ad-user")
            if not ad_password: missing.append(f"env:{pass_env}")
            result.errors.append("Authenticated AD review not run; missing " + ", ".join(missing))
            ph.event("ad_not_run", result.errors[-1])

    data = result.to_dict()
    save_json(out / "add_net_ad_results.json", data)

    saved = 0
    for obs in data.get("observations", []):
        cat = obs.get("category", "ad")
        sev = severity(obs.get("severity", "info"))
        title = CATEGORY_TITLE.get(cat, f"AD observation: {cat}")
        ctx.save_finding({
            "phase": phase_name,
            "severity": sev,
            "confidence": "MEDIUM" if sev in ("LOW", "INFO") else "HIGH",
            "title": f"{title}: {obs.get('principal', '')}",
            "target": data.get("dc_host") or (ctx.targets[0] if ctx.targets else "AD"),
            "description": f"Read-only LDAP review identified: {obs.get('detail', '')}",
            "evidence": f"Principal: {obs.get('principal', '')}\nCategory: {cat}\nDetail: {obs.get('detail', '')}",
            "impact": "This identity configuration can expand credential attack surface or privilege-escalation paths if combined with weak passwords, excessive delegation, or poor segmentation.",
            "remediation": obs.get("remediation", "Review the AD object, remove unnecessary exposure, enforce least privilege, and document approved exceptions."),
            "cwe": "CWE-269",
            "mrs_score": 80 if sev in ("HIGH", "MEDIUM") else 45,
            "extra_json": obs,
        })
        saved += 1

    if not saved:
        ctx.save_finding({
            "phase": phase_name, "severity": "INFO", "confidence": "MEDIUM",
            "title": "ADD-NETAD review completed or partially completed",
            "target": data.get("dc_host") or (ctx.targets[0] if ctx.targets else "AD"),
            "description": "The v3 AD add-on ran read-only checks where inputs were available. No AD misconfiguration observations were saved as findings, or authenticated inputs were missing.",
            "evidence": str(out / "add_net_ad_results.json"),
            "impact": "AD coverage may be incomplete if no DC/base DN/read-only bind account was supplied.",
            "remediation": "Provide --dc-ip, --ad-domain or --ad-base-dn, --ad-user, and the password via --ad-password-env for full read-only AD review.",
        })

    write_md(out / "ADD_NET_AD_SUMMARY.md", "ADD-NETAD Read-Only AD Summary", [
        ("Inputs", f"cidrs={cidrs or 'not set'}; dcs={dcs or 'not set'}; domain={domain or 'not set'}; base_dn={base_dn or 'not set'}; readonly_bind={'yes' if ad_user and ad_password else 'no'}"),
        ("Live hosts", str(len(data.get("live_hosts", [])))),
        ("DC services", str(len(data.get("services", [])))),
        ("AD observations", str(saved)),
        ("Errors / skipped coverage", "\n".join(f"- {e}" for e in data.get("errors", [])) or "None"),
        ("Safety boundary", "Read-only network/LDAP review. No ticket requests, cracking, relaying, DCSync, credential dumping, lateral movement, persistence, or destructive changes."),
        ("Evidence", str(out / "add_net_ad_results.json")),
    ])
    ctx.log("OK", phase_name, f"ADD-NETAD complete: {saved} observation finding(s)")
