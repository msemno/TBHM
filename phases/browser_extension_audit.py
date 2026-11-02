"""
Phase: browser_extension_audit   (v3.3)   [--browser-extension-audit FILE]

Cross-references a provided browser-extension inventory (exported from Chrome
Enterprise / Edge management / Intune) against risk heuristics:

  * dangerous permissions ("<all_urls>", "Read and change all your data",
    webRequest+blocking, nativeMessaging, cookies+all hosts),
  * known-risky/abandoned extension IDs (seed list; extend with --ext-blocklist),
  * extensions not on an allow-list (--ext-allowlist).

Input FILE is JSON: a list of {id,name,permissions:[...],version} or the Chrome
policy 'ExtensionInstallForcelist' style. No browsers are touched; this is an
offline inventory review.
"""
from __future__ import annotations

import json
from pathlib import Path

_DANGER_PERMS = {
    "<all_urls>": "can read/modify data on all sites",
    "*://*/*": "can read/modify data on all sites",
    "read and change all your data": "full page access",
    "nativemessaging": "can talk to native host binaries",
    "debugger": "can attach to the debugger protocol",
    "proxy": "can redirect all traffic",
    "webrequestblocking": "can intercept/modify requests",
    "cookies": "can read cookies (session theft if broad host access)",
    "management": "can control other extensions",
}
# tiny seed list of historically-abused/abandoned IDs (illustrative; extend via file)
_SEED_BLOCK = {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "placeholder-known-bad",
}


def _load_list(path):
    if not path or not Path(path).is_file():
        return []
    try:
        data = json.loads(Path(path).read_text())
    except Exception:
        return []
    if isinstance(data, dict):
        # chrome policy style {id: "url;update_url"} or {"extensions":[...]}
        if "extensions" in data:
            return data["extensions"]
        return [{"id": k, "name": k} for k in data.keys()]
    return data if isinstance(data, list) else []


def run(ctx):
    inv_path = getattr(ctx.args, "browser_extension_audit", None)
    if not inv_path:
        return
    exts = _load_list(inv_path)
    if not exts:
        ctx.log("WARN", "browser_extension_audit",
                f"no parseable extensions in {inv_path} — skipping")
        return

    out_dir = ctx.output / "browser_extensions"
    out_dir.mkdir(exist_ok=True)

    allow = set(_ids(_load_list(getattr(ctx.args, "ext_allowlist", None))))
    block = dict(_SEED_BLOCK)
    for e in _load_list(getattr(ctx.args, "ext_blocklist", None)):
        block[str(e.get("id", e)).lower()] = e.get("reason", "user blocklist")

    flagged, findings = [], 0
    for e in exts:
        eid = str(e.get("id", "")).lower()
        name = e.get("name", eid)
        perms = [str(p).lower() for p in (e.get("permissions") or [])]
        reasons = []
        for p in perms:
            for danger, why in _DANGER_PERMS.items():
                if danger in p:
                    reasons.append(f"permission '{p}' — {why}")
        if eid in block:
            reasons.append(f"on blocklist: {block[eid]}")
        if allow and eid and eid not in allow:
            reasons.append("not on corporate allow-list")
        if reasons:
            flagged.append({"id": eid, "name": name, "reasons": reasons})
            sev = "HIGH" if (eid in block) else ("MEDIUM" if any("all sites" in r
                   or "all your data" in r for r in reasons) else "LOW")
            ctx.save_finding({
                "phase": "browser_extension_audit", "severity": sev, "confidence": "MEDIUM",
                "title": f"Risky browser extension: {name}",
                "target": eid or name, "url": "",
                "description": "Fleet extension review flagged: " + "; ".join(reasons),
                "evidence": f"id={eid} perms={perms}",
                "impact": "Over-privileged/abandoned extensions can exfiltrate data or hijack sessions.",
                "remediation": "Remove or restrict via ExtensionInstallBlocklist / allow-list policy; "
                               "review broad-host and nativeMessaging grants.",
                "cwe": "CWE-829", "mrs_score": {"HIGH": 70, "MEDIUM": 45, "LOW": 25}[sev],
            })
            findings += 1

    (out_dir / "browser_extension_audit.json").write_text(json.dumps(
        {"total": len(exts), "flagged": flagged}, indent=2))
    ctx.log("OK", "browser_extension_audit",
            f"{len(exts)} extension(s) reviewed | {len(flagged)} flagged | {findings} finding(s)")


def _ids(lst):
    return [str(e.get("id", e)).lower() for e in lst]
