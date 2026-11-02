"""
Phase: playbook_integration   (v3.3)   [--playbook-mode]

Bridges TBHM output into a BR-branch objective playbook structure:

  * coverage_tracker.csv   - one row per objective: branch, phase(s), status,
                             finding count, evidence path.
  * playbook/BRxx-xxx.md   - auto-generated objective card stubs with timestamps,
                             ROE ticket link, mapped phase, and evidence paths.
  * master_coverage.html   - single view merging TBHM phases + objective cards.
  * residual_risk_register.json - open items aligned to BR branches.

Phase -> BR-branch mapping is defined below and can be extended. Read-only:
it only reads this run's findings/phase status and writes report artefacts.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime

# TBHM phase -> BR branch (branch codes follow the operator's BRxx taxonomy)
PHASE_TO_BR = {
    "recon": "BR01-RECON", "discovery": "BR01-RECON", "content_discovery": "BR01-RECON",
    "ports": "BR02-NETWORK", "internal_network_safe": "BR02-NETWORK",
    "ad_identity_safe": "BR03-AD", "add_net_ad": "BR03-AD",
    "lateral_movement_paths": "BR03-AD",
    "vuln_scan": "BR04-WEBVULN", "injections": "BR04-WEBVULN", "add_sqli": "BR04-WEBVULN",
    "access_control": "BR05-ACCESS", "auth_advanced": "BR06-AUTH",
    "auth_modern_review": "BR06-AUTH", "mfa_bypass_safe": "BR06-AUTH",
    "api_specific": "BR07-API", "api_fuzz": "BR07-API", "graphql_audit": "BR07-API",
    "interface_probe": "BR07-API", "modern_protocols_discovery": "BR07-API",
    "code_scan": "BR08-SOURCE", "code_intel": "BR08-SOURCE",
    "supply_chain_review": "BR08-SOURCE",
    "cloud_recon": "BR09-CLOUD", "cloud_recon_extended": "BR09-CLOUD",
    "k8s_recon_safe": "BR09-CLOUD", "cloud_inventory_safe": "BR09-CLOUD",
    "iac_drift": "BR09-CLOUD",
    "mobile_scan": "BR10-MOBILE",
    "ai_redteam_safe": "BR11-AI", "llm_agent_tool_call_abuse": "BR11-AI",
    "iot_cctv_safe": "BR12-IOT", "ot_ics_safe": "BR12-IOT",
    "wireless_physical_soc": "BR13-WIRELESS_PHYS",
    "business_logic": "BR14-BIZLOGIC", "upload_race": "BR14-BIZLOGIC",
    "egress_canary": "BR15-EXFIL", "attack_path": "BR16-CHAINS",
    "backup_restore_simulation": "BR17-RESILIENCE",
    "browser_extension_audit": "BR18-ENDPOINT",
    "secrets_misc": "BR19-EXPOSURE", "infra_exposure": "BR19-EXPOSURE",
}


def run(ctx):
    if not getattr(ctx.args, "playbook_mode", False):
        return

    out_dir = ctx.output / "playbook"
    out_dir.mkdir(exist_ok=True)
    roe = (getattr(ctx.args, "roe_ticket", None) or "N/A")
    ts = datetime.utcnow().isoformat() + "Z"

    try:
        findings = ctx.storage.all_findings()
    except Exception:
        findings = []

    # findings per branch
    by_branch = {}
    for f in findings:
        br = PHASE_TO_BR.get(f.get("phase", ""), "BR99-OTHER")
        by_branch.setdefault(br, []).append(f)

    # which phases ran
    ran = {}
    for ph, br in PHASE_TO_BR.items():
        try:
            if ctx.storage.is_phase_done(ph):
                ran.setdefault(br, []).append(ph)
        except Exception:
            pass

    branches = sorted(set(list(by_branch.keys()) + list(ran.keys())
                          + list(set(PHASE_TO_BR.values()))))

    # coverage_tracker.csv
    with open(out_dir / "coverage_tracker.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["branch", "phases_run", "status", "findings",
                    "critical_high", "evidence_path", "roe_ticket"])
        for br in branches:
            phs = ran.get(br, [])
            fs = by_branch.get(br, [])
            ch = sum(1 for x in fs if x.get("severity") in ("CRITICAL", "HIGH"))
            status = ("findings" if fs else ("covered" if phs else "not-run"))
            w.writerow([br, "|".join(phs), status, len(fs), ch,
                        f"playbook/{br}.md", roe])

    # objective card stubs
    for br in branches:
        phs = ran.get(br, [])
        fs = by_branch.get(br, [])
        card = [f"# {br}", "", f"- **Generated:** {ts}", f"- **ROE ticket:** {roe}",
                f"- **Mapped phases:** {', '.join(phs) or '(none run)'}",
                f"- **Status:** {'findings' if fs else ('covered' if phs else 'not-run')}",
                f"- **Findings:** {len(fs)}", "",
                "## Evidence", ""]
        for x in fs[:25]:
            card.append(f"- `[{x.get('severity')}]` {x.get('title','')[:90]} "
                        f"({x.get('phase')}) → {x.get('evidence','')[:80]}")
        card += ["", "## Operator notes", "", "_(fill in)_", ""]
        (out_dir / f"{br}.md").write_text("\n".join(card))

    # residual risk register (open CRITICAL/HIGH/MEDIUM by branch)
    residual = []
    for br in branches:
        for x in by_branch.get(br, []):
            if x.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
                residual.append({"branch": br, "severity": x.get("severity"),
                                 "title": x.get("title", ""), "phase": x.get("phase"),
                                 "remediation": x.get("remediation", "")})
    (out_dir / "residual_risk_register.json").write_text(json.dumps(residual, indent=2))

    # master_coverage.html
    rows = "".join(
        f"<tr><td>{br}</td><td>{'|'.join(ran.get(br, [])) or '-'}</td>"
        f"<td>{len(by_branch.get(br, []))}</td>"
        f"<td>{sum(1 for x in by_branch.get(br, []) if x.get('severity') in ('CRITICAL','HIGH'))}</td>"
        f"<td>{'findings' if by_branch.get(br) else ('covered' if ran.get(br) else 'not-run')}</td></tr>"
        for br in branches)
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>TBHM master coverage</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:2rem}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:.45rem .6rem;font-size:13px}}
th{{background:#f0f0f0}}</style></head><body>
<h1>Master coverage (TBHM &rarr; BR branches)</h1>
<p>Generated {ts} | ROE {roe} | {len(findings)} findings across {len(branches)} branches.</p>
<table><tr><th>BR branch</th><th>Phases run</th><th>Findings</th><th>Crit/High</th><th>Status</th></tr>
{rows}</table></body></html>"""
    (out_dir / "master_coverage.html").write_text(html)

    ctx.log("OK", "playbook_integration",
            f"{len(branches)} BR branches | coverage_tracker.csv + {len(branches)} objective cards "
            f"+ master_coverage.html + residual_risk_register.json")
