"""Wireless/RF, physical/social, and SOC detection planning layer."""
from __future__ import annotations
from core import redteam_utils as RT

WIRELESS_CHECKS = [
    ("WIFI-001", "SSID inventory", "Passive list of visible SSIDs/BSSIDs/channels/security."),
    ("WIFI-002", "WPA-Enterprise certificate validation", "Confirm clients validate RADIUS server cert and reject evil-twin certs."),
    ("WIFI-003", "Guest isolation", "Guest Wi-Fi cannot reach internal networks or admin services."),
    ("WIFI-004", "Rogue AP detection", "Blue team detects unauthorized AP/BSSID in a controlled simulation."),
    ("WIFI-005", "RF high-risk actions", "Deauth/jamming/evil twin/handshake cracking require separate written approval."),
]
PHYSICAL_CHECKS = [
    ("PHY-001", "Visitor process", "Badge, escort, sign-in/out and restricted-area enforcement."),
    ("PHY-002", "Network port exposure", "Conference/lobby/unused ports require NAC/802.1X or disabled switchports."),
    ("PHY-003", "CCTV blind spots", "Map blind spots with facility team; no camera tampering."),
    ("PHY-004", "Drop device simulation", "Only approved inert/synthetic drop device; no backdoor."),
    ("PHY-005", "Physical high-risk actions", "Tailgating, badge cloning, lock bypass require physical test authorization."),
]
SOC_CHECKS = [
    ("SOC-001", "Failed login alert", "Controlled failed-login event visible in SIEM."),
    ("SOC-002", "Port scan alert", "Low-rate authorized scan generates expected detection or documented gap."),
    ("SOC-003", "Admin login/change alert", "Admin role/security setting changes generate audit logs."),
    ("SOC-004", "Synthetic DLP canary", "Approved fake canary file movement is detected, not real data exfiltration."),
    ("SOC-005", "EDR telemetry", "Execution/block events are validated using benign test artifacts only."),
]


def _maybe_wireless(ctx, out):
    iface = getattr(ctx.args, "wireless_interface", None) or ""
    if not iface:
        return "No --wireless-interface supplied; checklist generated only."
    if ctx.runner.has("iw"):
        ctx.runner.run(["iw", "dev", iface, "scan"], timeout=90, log_name="rt_wireless_iw_scan", capture_mode="tail")
    elif ctx.runner.has("nmcli"):
        ctx.runner.run(["nmcli", "dev", "wifi", "list", "ifname", iface], timeout=90, log_name="rt_wireless_nmcli_list", capture_mode="tail")
    return f"Passive wireless inventory attempted on interface {iface}."


def run(ctx):
    out = RT.evidence_dir(ctx, "08_20_19_wireless_physical_soc")
    RT.write_csv(out / "wireless_checks.csv", [{"id": i, "check": c, "method": m, "status": "planned/simulated"} for i, c, m in WIRELESS_CHECKS])
    RT.write_csv(out / "physical_social_checks.csv", [{"id": i, "check": c, "method": m, "status": "requires explicit authorization"} for i, c, m in PHYSICAL_CHECKS])
    RT.write_csv(out / "soc_detection_checks.csv", [{"id": i, "check": c, "method": m, "status": "coordinate with SOC"} for i, c, m in SOC_CHECKS])
    wi = _maybe_wireless(ctx, out)
    RT.write_md(out / "WIRELESS_PHYSICAL_SOC_SUMMARY.md", "Wireless / Physical / SOC Red-Team Coverage", [
        ("Wireless", wi + " High-risk RF actions are not automated."),
        ("Physical/social", "This tool creates authorization and evidence checklists only. It does not perform impersonation, badge cloning, lock bypass, or device drops."),
        ("SOC", "Use the SOC CSV to coordinate detection validation and record alert IDs, timestamps, owner, and result."),
    ])
    RT.add_control_finding(ctx, "wireless_physical_soc", "Wireless/physical/SOC coverage checklists generated", "INFO",
                           "Generated wireless, physical/social, and SOC detection coverage files.", str(out),
                           remediation="Coordinate each test with facilities, SOC, legal, and business owners before execution.")
    ctx.log("OK", "wireless_physical_soc", f"coverage files written to {out}")
