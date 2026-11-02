"""Red-team governance, coverage matrix, approvals, and residual-risk register.

v2.23: The branch matrix is now aligned 1:1 with the field playbook
(authorized_red_team_master_playbook_2026 ... ADDITIVE.md). The playbook defines
34 branches (BR01-BR34); this module tracks all of them so the report matrix and the
playbook never disagree. Titles are copied from the playbook branch headers.

Nothing here performs intrusive actions. It emits a coverage matrix, a high-risk
approval register, and residual-risk reporting rules used by the reporter so that
untested or unauthorized branches are never marked "safe".
"""
from __future__ import annotations
from core import redteam_utils as RT

# ── Playbook-aligned branch list (BR01..BR34) ────────────────────────────────
# IDs + titles mirror the playbook's "## 5. Full Branch Checklist" (BR01-BR26)
# and the additive "## 5B. Extended Branch Checklist" (BR27-BR34) exactly.
BRANCHES = [
    ("BR01", "Pre-Engagement, ROE, Legal, and Safety Control"),
    ("BR02", "Program Management, Planning, and Coverage Matrix"),
    ("BR03", "Physical Security and On-Site Operations"),
    ("BR04", "Network Architecture and Segmentation"),
    ("BR05", "Asset Inventory and Service Discovery"),
    ("BR06", "Active Directory and Identity Security"),
    ("BR07", "Endpoint and User Machine Security"),
    ("BR08", "Windows and Linux Server Infrastructure"),
    ("BR09", "Web Applications"),
    ("BR10", "APIs and Microservices"),
    ("BR11", "Mobile Applications"),
    ("BR12", "Wireless, Bluetooth, and RF Surface"),
    ("BR13", "IoT Devices and Sensors"),
    ("BR14", "CCTV, Cameras, DVR/NVR, Access Control"),
    ("BR15", "Printers, MFPs, and Peripheral Devices"),
    ("BR16", "Cloud, SaaS, Email, and Collaboration Platforms"),
    ("BR17", "Containers, Kubernetes, DevOps, and CI/CD"),
    ("BR18", "Source Code, Secrets, and Software Supply Chain"),
    ("BR19", "Reverse Engineering, Firmware, and Binaries"),
    ("BR20", "AI, LLM, Automation, and Data Science Systems"),
    ("BR21", "Email, Awareness, and Social Engineering Readiness"),
    ("BR22", "Data Security, Databases, and File Shares"),
    ("BR23", "Backup, Disaster Recovery, and Ransomware Resilience"),
    ("BR24", "Logging, SIEM, SOC, and Detection Validation"),
    ("BR25", "External Attack Surface and Third-Party Exposure"),
    ("BR26", "Reporting, Remediation, Retesting, and Executive Closure"),
    # ── Additive extended branches (playbook Section 5B) ──────────────────────
    ("BR27", "Operational Technology, ICS, SCADA, and Safety Systems"),
    ("BR28", "Kubernetes Runtime, Service Mesh, and Workload Identity"),
    ("BR29", "PKI, Certificate, Secret, and Key Lifecycle"),
    ("BR30", "Identity Federation, SSO, OAuth, and Conditional Access"),
    ("BR31", "Container Image Supply Chain and Build Provenance"),
    ("BR32", "Data Pipeline, Warehouse, and ML-Ops Security"),
    ("BR33", "Insider Threat, DLP, and Egress Simulation"),
    ("BR34", "Purple Team, Detection Engineering, and Response Validation"),
    # ── Additive appendix branch groups (playbook remaining-objective cards) ──
    # These come from the playbook's additive appendix (BR39-BR46). They carry
    # their own sub-topic cards and were previously tracked only in the objective
    # coverage map; adding them here keeps the canonical branch matrix aligned
    # with the full playbook scope. IDs are non-contiguous by design (they mirror
    # the playbook's own numbering).
    ("BR39", "Zero Trust, SASE, and Non-Human Identity"),
    ("BR40", "Physical Security, Hardware Implants, PACS, and BMS"),
    ("BR41", "UCaaS, Collaboration Platforms, Meetings, and Webhooks"),
    ("BR42", "Internal DevSecOps, CI/CD, and Package Registries"),
    ("BR43", "Advanced EDR Control Validation, OOB Management, and MDM/UEM"),
    ("BR44", "AI-Enhanced Social Engineering and Human-Process Resilience"),
    ("BR45", "Advanced Data Exfiltration, DLP Egress, and Shadow IT"),
    ("BR46", "M&A Orphaned Infrastructure and Inherited Shadow Estate"),
]

# 200 objectives per branch in the playbook; used only to show planned scope size.
OBJECTIVES_PER_BRANCH = 200

# Which branches TBHM automation can partially exercise vs. which are checklist-only.
# This drives an honest "automation coverage" hint in the matrix. A branch marked
# checklist_only=True means the tool does NOT probe it automatically; the human
# must work the playbook objectives and record status manually.
AUTOMATION_HINTS = {
    "BR02": "partial",   "BR03": "checklist",  "BR04": "partial",
    "BR05": "partial",   "BR06": "partial",    "BR07": "checklist",
    "BR08": "partial",   "BR09": "partial",    "BR10": "partial",
    "BR11": "partial",   "BR12": "checklist",  "BR13": "partial",
    "BR14": "partial",   "BR15": "partial",    "BR16": "partial",
    "BR17": "partial",   "BR18": "partial",    "BR19": "partial",
    "BR20": "partial",   "BR21": "checklist",  "BR22": "partial",
    "BR23": "checklist", "BR24": "checklist",  "BR25": "partial",
    "BR26": "partial",   "BR01": "checklist",
    "BR27": "checklist", "BR28": "partial",    "BR29": "partial",
    "BR30": "partial",   "BR31": "partial",    "BR32": "checklist",
    "BR33": "checklist", "BR34": "checklist",
    "BR39": "partial",   "BR40": "checklist", "BR41": "partial",
    "BR42": "partial",   "BR43": "checklist", "BR44": "checklist",
    "BR45": "checklist", "BR46": "partial",
}

HIGH_RISK = [
    ("Credential attacks", "password spraying, phishing collection, hash capture/cracking, token theft", "Simulation / lab only unless separately authorized"),
    ("Exploit execution", "RCE, payload execution, exploit modules, command execution", "Use non-destructive version/config validation first"),
    ("Persistence", "services, WMI, startup items, C2 beacons, backdoors", "Detection exercise only; no persistence on production"),
    ("EDR bypass", "AMSI/ETW patching, direct syscalls, driver abuse, obfuscation", "Tabletop or lab detection validation"),
    ("Data exfiltration", "real data transfer, bulk export, cloud sync abuse", "Synthetic canaries only"),
    ("Physical entry", "tailgating, locks, badges, drop boxes", "Requires physical test authorization and safety plan"),
    ("Wireless disruption", "deauth, jamming, evil twin, handshake forcing", "Passive only unless RF authorization exists"),
    ("Destructive impact", "ransomware, delete, wipe, power-off, DoS", "Never run on production; tabletop or isolated lab"),
    ("OT/ICS interaction", "PLC/RTU writes, protocol fuzzing, SIS-network access", "Never in Phase 1; process/safety owner sign-off + operator present"),
    ("Live key/secret extraction", "exporting private keys, dumping secret stores", "Record location/gap only; never exfiltrate the material"),
]

STATUS_VOCAB = [
    "Tested", "Simulated", "Lab Only", "Not Authorized",
    "Not Applicable", "Blocked", "Needs High-Risk Approval",
]


def _is_redteam(ctx) -> bool:
    if getattr(ctx.args, "redteam", False):
        return True
    name = ctx.profile.get("name") if isinstance(ctx.profile, dict) else getattr(ctx.profile, "name", "")
    return name == "authorized_redteam"


def run(ctx):
    out = RT.evidence_dir(ctx, "00_governance")
    redteam = _is_redteam(ctx)
    rows = []
    for bid, branch in BRANCHES:
        hint = AUTOMATION_HINTS.get(bid, "checklist")
        rows.append({
            "branch_id": bid,
            "branch": branch,
            "playbook_objectives": OBJECTIVES_PER_BRANCH,
            "automation": hint,  # partial = tool probes some; checklist = manual only
            "status": "planned" if redteam else "available",
            "evidence_folder": f"redteam/{bid.lower()}",
            "report_rule": "Never mark Safe. Use: " + " / ".join(STATUS_VOCAB) + ".",
        })
    RT.write_csv(out / "redteam_coverage_matrix.csv", rows)

    high = [{"area": a, "examples": e, "allowed_status": s} for a, e, s in HIGH_RISK]
    RT.write_csv(out / "high_risk_approval_register.csv", high)

    total_obj = len(BRANCHES) * OBJECTIVES_PER_BRANCH
    partial = sum(1 for b, _ in BRANCHES if AUTOMATION_HINTS.get(b) == "partial")
    checklist = len(BRANCHES) - partial

    sections = [
        ("Purpose", "This additive layer turns TBHM from mostly web/API pentest automation into an enterprise red-team coverage orchestrator. It records realistic attacker paths without silently deleting high-risk areas, and it keeps the branch matrix aligned 1:1 with the field playbook."),
        ("Playbook alignment", f"The field playbook defines {len(BRANCHES)} branches (BR01-BR34 + additive BR39-BR46) with {OBJECTIVES_PER_BRANCH} objectives each ({total_obj:,} total). This module tracks all {len(BRANCHES)} branches so the report and the playbook never disagree. {partial} branches are partially automated by TBHM; {checklist} are checklist-only and must be worked and recorded manually."),
        ("Reporting rule", "Never report `everything is safe` or `no missing gaps`. For every branch and objective use one of: " + ", ".join(STATUS_VOCAB) + "."),
        ("Safety boundary", "The tool performs inventory, read-only validation, non-destructive probes, synthetic canary checks, configuration review, and report generation. It does not perform credential theft, malware, persistence, EDR bypass, destructive exploitation, OT/ICS writes, live key extraction, or denial-of-service."),
        ("Inputs detected", f"corp_cidr={getattr(ctx.args, 'corp_cidr', '') or 'not set'}; dc_ip={getattr(ctx.args, 'dc_ip', '') or 'not set'}; ad_domain={getattr(ctx.args, 'ad_domain', '') or 'not set'}; firmware={getattr(ctx.args, 'firmware', '') or 'not set'}; ai_endpoints_file={getattr(ctx.args, 'ai_endpoints_file', '') or 'not set'}"),
    ]
    RT.write_md(out / "REDTEAM_GOVERNANCE.md", "TBHM Red-Team Governance Addendum", sections)

    # Persist the branch list as JSON so the reporter can render the same matrix.
    RT.save_json(out / "branch_matrix.json", {
        "branches": [{"id": b, "title": t,
                      "automation": AUTOMATION_HINTS.get(b, "checklist"),
                      "objectives": OBJECTIVES_PER_BRANCH} for b, t in BRANCHES],
        "objectives_per_branch": OBJECTIVES_PER_BRANCH,
        "total_objectives": total_obj,
        "status_vocab": STATUS_VOCAB,
        "redteam_mode": redteam,
    })

    RT.add_control_finding(
        ctx, "redteam_governance", f"Enterprise red-team coverage matrix generated ({len(BRANCHES)} branches)", "INFO",
        f"Generated a playbook-aligned branch coverage matrix ({len(BRANCHES)} branches, {total_obj:,} objectives), high-risk approval register, and residual-risk reporting rules.",
        f"{out/'redteam_coverage_matrix.csv'}; {out/'high_risk_approval_register.csv'}; {out/'branch_matrix.json'}",
        remediation="Use this matrix in the final report so untested/high-risk areas are not falsely marked safe.",
    )
    ctx.log("OK", "redteam_governance",
            f"coverage matrix ({len(BRANCHES)} branches) + high-risk register written to {out}")
