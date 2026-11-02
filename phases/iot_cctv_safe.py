"""IoT, CCTV, sensors, printers, VoIP, BMS/OT-like safe inventory."""
from __future__ import annotations
from core import redteam_utils as RT

IOT_PORTS = {
    80: ("HTTP management UI", "INFO"), 443: ("HTTPS management UI", "INFO"),
    23: ("Telnet", "HIGH"), 22: ("SSH", "INFO"), 21: ("FTP", "MEDIUM"),
    554: ("RTSP camera stream", "MEDIUM"), 8554: ("RTSP alternate", "MEDIUM"),
    161: ("SNMP", "MEDIUM"), 162: ("SNMP trap", "INFO"), 515: ("LPD printer", "LOW"),
    631: ("IPP printer", "LOW"), 9100: ("JetDirect printer raw", "MEDIUM"),
    5060: ("SIP", "MEDIUM"), 5061: ("SIP TLS", "LOW"),
    1883: ("MQTT", "HIGH"), 8883: ("MQTT TLS", "MEDIUM"), 5683: ("CoAP", "HIGH"),
    502: ("Modbus/TCP", "HIGH"), 102: ("Siemens S7", "HIGH"), 44818: ("EtherNet/IP", "HIGH"),
    47808: ("BACnet", "HIGH"), 1911: ("Tridium Niagara Fox", "HIGH"),
}


def run(ctx):
    cidrs = RT.get_cidrs(ctx)
    out = RT.evidence_dir(ctx, "07_iot_cctv_sensors")
    if not cidrs:
        RT.write_md(out / "IOT_NOT_RUN.md", "IoT/CCTV/Sensors Not Run", [
            ("Reason", "No --corp-cidr / --corp-cidrs-file was provided. This branch is Not Tested, not Safe."),
            ("Scope needed", "Approved IoT/CCTV/sensor/printer/VoIP/BMS VLANs and test windows."),
        ])
        return
    if not ctx.runner.has("nmap"):
        ctx.log("WARN", "iot_cctv", "nmap missing — cannot run IoT inventory")
        return
    ports = ",".join(str(p) for p in sorted(IOT_PORTS))
    rows = []
    for cidr in cidrs:
        normal = out / f"iot_services_{cidr.replace('/', '_')}.nmap"
        gn = out / f"iot_services_{cidr.replace('/', '_')}.gnmap"
        cmd = ["nmap", "-sV", "--version-light", "-Pn", "--max-retries", "1", "--host-timeout", "60s",
               "-p", ports, cidr, "-oN", str(normal), "-oG", str(gn)]
        ctx.runner.run(cmd, timeout=7200, log_name=f"rt_iot_services_{cidr.replace('/', '_')}", capture_mode="tail")
        rows += RT.parse_nmap_normal_services(normal.read_text(errors="ignore") if normal.exists() else "")
    enriched = []
    for r in rows:
        p = int(r.get("port", 0))
        label, sev = IOT_PORTS.get(p, (r.get("service", "unknown"), "INFO"))
        enriched.append({**r, "device_surface": label, "severity": sev})
        if sev in ("HIGH", "MEDIUM"):
            RT.add_control_finding(ctx, "iot_cctv_safe", f"IoT/CCTV/OT-like service reachable: {label} on {r['host']}:{p}", sev,
                                   f"Read-only discovery found {label}. Validate segmentation, authentication, firmware lifecycle, default credential policy, and logging.",
                                   f"{r['host']}:{p}/{r.get('proto')} {r.get('service')} {r.get('version')}", target=r['host'],
                                   remediation="Place device on segmented VLAN, restrict management ports, disable insecure protocols, update firmware, and monitor access.")
    RT.write_csv(out / "iot_cctv_sensor_inventory.csv", enriched)
    RT.write_md(out / "IOT_CCTV_SENSOR_SUMMARY.md", "IoT/CCTV/Sensor Safe Inventory", [
        ("What was tested", "Read-only service inventory for camera, printer, VoIP, MQTT/CoAP, BMS and OT-like protocol exposure."),
        ("What was not done", "No default-credential brute force, stream viewing, device takeover, firmware flashing, jamming, or unsafe protocol writes."),
        ("Output", f"{len(enriched)} service observations written to iot_cctv_sensor_inventory.csv."),
    ])
    ctx.log("OK", "iot_cctv", f"{len(enriched)} IoT/CCTV/sensor service observations")
