"""Corporate OSINT/red-team OPSEC preflight (v3.9.5).

This phase verifies declared controls; it does not claim to anonymize traffic or
randomize fingerprints.  Missing controls are visible and can be made fatal with
--require-opsec.
"""
from __future__ import annotations
import json, os, stat
from pathlib import Path
from core import redteam_utils as RT
try:
    import yaml
except Exception:
    yaml = None


def _load(path):
    if not path: return {}
    p=Path(path)
    if not p.is_file(): return {}
    text=p.read_text(errors="ignore")
    try:
        return json.loads(text) if p.suffix.lower()==".json" else (yaml.safe_load(text) if yaml else {})
    except Exception: return {}


def run(ctx):
    _profile_name=str((getattr(ctx, "profile", {}) or {}).get("name", ""))
    _corporate_profile=_profile_name in {"authorized_redteam", "authorized_assumed_breach"}
    if not (_corporate_profile or getattr(ctx.args,"corporate_osint",False) or getattr(ctx.args,"redteam",False)
            or getattr(ctx.args,"require_opsec",False)):
        return
    out=RT.evidence_dir(ctx,"02_opsec_preflight")
    manifest=_load(getattr(ctx.args,"opsec_manifest",None))
    checks=[]
    def add(control, ok, detail, required=True):
        checks.append({"control":control,"status":"PASS" if ok else "FAIL" if required else "WARN","detail":detail,"required":required})
    profile=(ctx.profile or {})
    active=bool(profile.get("active_probes",False))
    add("written_authorization", profile.get("name")=="passive_only" or bool(getattr(ctx.args,"yes_i_am_authorized",False)), "Explicit authorization flag present for active work.")
    add("scope_controls", bool(getattr(ctx,"scope_includes",[])) or len(getattr(ctx,"targets",[]) or [])==1, "Explicit allowlist preferred for corporate engagements.", required=active)
    add("dedicated_research_identity", bool(manifest.get("dedicated_identity")), "Manifest must confirm no personal accounts are used.", required=bool(getattr(ctx.args,"corporate_osint",False)))
    add("egress_verified", bool(manifest.get("egress_verified")), "Operator-confirmed dedicated/approved egress; TBHM does not fabricate anonymity.", required=active)
    add("evidence_encrypted", bool(manifest.get("evidence_encrypted")), "Output storage encryption/volume control declared.", required=active)
    add("pii_minimization", bool(manifest.get("pii_minimization",True)), "PII collection is bounded to corporate purpose.", required=True)
    add("browser_isolation", bool(manifest.get("browser_isolation")), "Dedicated browser/container for interactive OSINT.", required=False)
    add("fingerprint_control", bool(manifest.get("fingerprint_control")), "JA3/JA4/browser fingerprint control is operator infrastructure, not silently provided by TBHM.", required=False)
    add("tls_fingerprint_profile", bool(manifest.get("tls_fingerprint_profile")), "Named approved TLS/client fingerprint profile is declared; TBHM does not rotate or spoof fingerprints.", required=False)
    add("egress_rotation_policy", bool(manifest.get("egress_rotation_policy")), "Approved proxy/egress rotation and attribution policy is documented; TBHM does not provision or rotate infrastructure.", required=False)
    add("persona_inventory", bool(manifest.get("persona_inventory")), "Approved research personas/accounts are inventoried and separated from personal identities.", required=bool(getattr(ctx.args,"corporate_osint",False)))
    add("source_request_budget", bool(manifest.get("source_request_budget")), "Per-source request budget and timing/jitter policy are declared.", required=False)
    add("collection_window", bool(manifest.get("collection_window")), "Approved collection time window/business-hours policy is declared.", required=False)
    add("honeypot_policy", bool(manifest.get("honeypot_policy")), "Honeypot/canary handling and stop conditions are declared.", required=False)
    add("kill_switch", bool(manifest.get("kill_switch")), "Named stop/kill procedure exists.", required=active)
    add("retention_policy", bool(manifest.get("retention_days") or manifest.get("retention_policy")), "Evidence retention period declared.", required=True)
    try:
        mode=stat.S_IMODE(ctx.output.stat().st_mode)
        add("output_permissions", (mode & 0o077)==0, f"Output directory mode is {oct(mode)}; recommended 0700.", required=False)
    except Exception:
        pass
    proxies={k:os.environ.get(k,"") for k in ("HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY") if os.environ.get(k)}
    report={"manifest":manifest,"checks":checks,"proxy_environment_present":bool(proxies),"proxy_variables":list(proxies),
            "statement":"This is a declared-control verification, not proof of anonymity or anti-attribution."}
    (out/"opsec_preflight.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    RT.write_csv(out/"opsec_controls.csv",checks)
    failed=[x for x in checks if x["status"]=="FAIL"]
    RT.write_md(out/"OPSEC_PREFLIGHT.md","Corporate OPSEC Preflight",[("Result",f"{len(checks)-len(failed)}/{len(checks)} required/declarative checks passed."),("Important limitation",report["statement"]),("Failed controls","\n".join(f"- {x['control']}: {x['detail']}" for x in failed) or "None")])
    if failed and getattr(ctx.args,"require_opsec",False):
        raise RuntimeError("OPSEC preflight failed: "+", ".join(x["control"] for x in failed))
    ctx.log("WARN" if failed else "OK","opsec_preflight",f"{len(failed)} required OPSEC control(s) failed")
