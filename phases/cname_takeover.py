"""
Phase: cname_takeover   (v2.19)

CNAME inventory + dangling-takeover heuristic (playbook §4.1). subzy (in
vuln_scan) fingerprints known services; this adds the raw CNAME map and a second
opinion: any subdomain whose CNAME points to a known-takeover-able provider is
flagged for MANUAL confirmation (never auto-claimed).

Uses `dnsx -cname` if installed, else Python socket resolution. Detection only.
"""
from __future__ import annotations

import socket
from pathlib import Path

# provider substring -> service (fingerprint of takeover-prone CNAME targets)
TAKEOVER_TARGETS = {
    "s3.amazonaws.com": "AWS S3", "s3-website": "AWS S3 website",
    "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "github.io": "GitHub Pages", "githubusercontent": "GitHub",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure",
    "azureedge.net": "Azure CDN", "trafficmanager.net": "Azure Traffic Manager",
    "cloudfront.net": "CloudFront", "fastly.net": "Fastly",
    "netlify.app": "Netlify", "netlify.com": "Netlify",
    "ghost.io": "Ghost", "wordpress.com": "WordPress",
    "pantheonsite.io": "Pantheon", "wpengine.com": "WP Engine",
    "surge.sh": "Surge", "bitbucket.io": "Bitbucket",
    "readthedocs.io": "ReadTheDocs", "readme.io": "Readme",
    "helpscoutdocs.com": "HelpScout", "zendesk.com": "Zendesk",
    "statuspage.io": "Statuspage", "uservoice.com": "UserVoice",
    "desk.com": "Desk", "cargocollective.com": "Cargo",
    "unbouncepages.com": "Unbounce", "canny.io": "Canny",
    "fly.dev": "Fly.io", "render.com": "Render", "vercel.app": "Vercel",
    "shopify.com": "Shopify", "myshopify.com": "Shopify",
    "webflow.io": "Webflow", "hubspot.net": "HubSpot",
}


def _cnames_via_dnsx(ctx, subs_file, out_file):
    if not ctx.runner.has("dnsx"):
        return None
    try:
        ctx.runner.run(["dnsx", "-l", str(subs_file), "-cname", "-resp", "-silent",
                        "-o", str(out_file)], timeout=600, log_name="dnsx_cname", capture_mode="tail")
        if out_file.exists():
            return out_file.read_text(errors="ignore").splitlines()
    except Exception:
        pass
    return None


def _cname_python(host):
    try:
        # socket doesn't expose CNAME directly; use getaddrinfo canonname.
        res = socket.getaddrinfo(host, None, flags=socket.AI_CANONNAME)
        if res and res[0][3] and res[0][3].lower() != host.lower():
            return res[0][3]
    except Exception:
        pass
    return None


def run(ctx):
    subs_file = ctx.output / "recon" / "subdomains.txt"
    hosts = []
    if subs_file.exists():
        hosts = ctx.runner.read_lines(subs_file)
    if not hosts:
        hosts = [t.replace("*.", "") for t in ctx.targets]
    hosts = list(dict.fromkeys(h.strip() for h in hosts if h.strip()))[:2000]
    if not hosts:
        return

    out_dir = ctx.output / "recon"
    cname_out = out_dir / "cnames.txt"

    # Gather host -> cname
    mapping = {}
    dnsx_lines = _cnames_via_dnsx(ctx, subs_file, out_dir / "dnsx_cname.txt") if subs_file.exists() else None
    if dnsx_lines:
        for line in dnsx_lines:
            # dnsx -cname -resp format: "host [CNAME target]" variants
            parts = line.replace("[", " ").replace("]", " ").split()
            if len(parts) >= 2:
                mapping[parts[0]] = parts[-1]
    else:
        for h in hosts[:300]:   # python fallback is slower; cap
            cn = _cname_python(h)
            if cn:
                mapping[h] = cn

    if mapping:
        cname_out.write_text("\n".join(f"{h} -> {c}" for h, c in mapping.items()))

    n = 0
    for host, cname in mapping.items():
        cl = cname.lower()
        for sig, service in TAKEOVER_TARGETS.items():
            if sig in cl:
                n += 1
                ctx.save_finding({
                    "phase": "cname_takeover", "severity": "MEDIUM", "confidence": "LOW",
                    "title": f"Potential subdomain takeover: {host} → {service}",
                    "target": host, "url": f"https://{host}", "method": "GET",
                    "evidence": f"{host} CNAME {cname} ({service})",
                    "description": f"{host} has a dangling-capable CNAME to {service}. UNCONFIRMED — "
                                   f"manually verify the target resource is unclaimed (NXDOMAIN / "
                                   f"'no such bucket' / default service page) before claiming takeover.",
                    "impact": "Full control of the subdomain if the target resource is unclaimed.",
                    "remediation": "Remove the dangling DNS record or reclaim the target resource.",
                    "cwe": "CWE-350", "mrs_score": 55,
                })
                break
    ctx.log("OK", "cname_takeover",
            f"cname_takeover: {len(mapping)} CNAMEs mapped, {n} takeover candidate(s) (manual confirm)")
