"""TBHM v3 phase: Windows service execution-primitive review add-on."""
from __future__ import annotations

import platform

from tbhm_addons.mod_service_primitive import ServicePrimitiveModule
from .addons_common import evidence_dir, save_json, write_md, make_logger, severity


def run(ctx):
    phase_name = "add_service_primitive"
    out = evidence_dir(ctx, "03_add_service_primitive")
    prove_requested = bool(getattr(ctx.args, "svc_prove_writable", False))
    prove = prove_requested and bool(getattr(ctx.args, "allow_writes", False))

    if prove_requested and not prove:
        ctx.log("WARN", phase_name, "--svc-prove-writable ignored because --allow-writes was not supplied")

    logger = make_logger(ctx, "ADD-SVCPRIM", target=platform.node())
    mod = ServicePrimitiveModule(prove_writable=prove)

    with logger.phase("ADD-SVCPRIM", "Windows service execution-primitive detection", silent=getattr(ctx.args, "silent", False)) as ph:
        res = mod.check_host(phase=ph)
    data = res.to_dict()
    save_json(out / "add_service_primitive_results.json", data)

    if not data.get("platform_supported", False):
        write_md(out / "ADD_SERVICE_PRIMITIVE_NOT_RUN.md", "ADD-SVCPRIM Not Run", [
            ("Reason", "This phase requires local execution on an authorized Windows host. The current platform is not Windows."),
            ("How to run", "Run this phase from the Windows machine being assessed: python tbhm.py -d example.local --profile authorized_redteam -y --redteam --phases add_service_primitive"),
            ("Safety", "By default it only checks ACL/path conditions. Inert marker proof requires both --svc-prove-writable and --allow-writes."),
        ])
        ctx.save_finding({
            "phase": phase_name, "severity": "INFO", "confidence": "MEDIUM",
            "title": "Windows service primitive add-on not tested on this platform",
            "target": ctx.targets[0] if ctx.targets else platform.node(),
            "description": "The v3 ADD-SVCPRIM phase requires local Windows execution and was skipped on this platform.",
            "evidence": str(out / "ADD_SERVICE_PRIMITIVE_NOT_RUN.md"),
            "impact": "Windows service ACL/path execution-primitive coverage is incomplete for this run.",
            "remediation": "Run the phase from an authorized Windows endpoint/server or provide equivalent manual review evidence.",
        })
        ctx.log("INFO", phase_name, "ADD-SVCPRIM skipped: non-Windows platform")
        return

    saved = 0
    for f in data.get("findings", []):
        sev = severity(f.get("severity", "medium"), default="MEDIUM")
        ctx.save_finding({
            "phase": phase_name,
            "severity": sev,
            "confidence": "HIGH",
            "title": f"Windows service execution primitive: {f.get('issue', 'weak_service_condition')}",
            "target": data.get("host") or (ctx.targets[0] if ctx.targets else platform.node()),
            "url": f.get("binary_path", ""),
            "description": f"Service '{f.get('service', '')}' has a condition that may allow code to execute as the service account: {f.get('issue', '')}.",
            "evidence": f"Service: {f.get('service', '')}\nBinary/path: {f.get('binary_path', '')}\nPrincipal: {f.get('principal', '')}\nProof: {f.get('proof', '')}",
            "impact": "A non-privileged user may be able to modify a service binary/path/DLL-search location or service configuration so code executes with the service account's privileges after service restart or host reboot.",
            "remediation": f.get("remediation", "Remove write permissions for untrusted principals, quote service paths, harden service ACLs, and monitor service binary/configuration changes."),
            "cwe": "CWE-732",
            "mrs_score": 85 if sev in ("HIGH", "CRITICAL") else 70,
            "extra_json": f,
        })
        saved += 1

    write_md(out / "ADD_SERVICE_PRIMITIVE_SUMMARY.md", "ADD-SVCPRIM Windows Service Primitive Summary", [
        ("Host", data.get("host", "unknown")),
        ("Findings", str(saved)),
        ("Inert write proof", "enabled" if prove else "disabled"),
        ("Errors", "\n".join(f"- {e}" for e in data.get("errors", [])) or "None"),
        ("Safety boundary", "No executable payloads are dropped and no service is started/restarted by this phase. Optional proof writes only a temporary inert .txt marker when --allow-writes is explicitly enabled."),
        ("Evidence", str(out / "add_service_primitive_results.json")),
    ])
    ctx.log("OK", phase_name, f"ADD-SVCPRIM complete: {saved} finding(s)")
