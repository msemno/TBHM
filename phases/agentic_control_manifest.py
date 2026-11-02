"""Generate non-executing MCP/agentic and capability manifests."""
from __future__ import annotations

import json
from core import redteam_utils as RT, tool_catalog, capability_registry
from core.mcp_registry import build


def run(ctx):
    if not (getattr(ctx.args,"agentic_manifest",False) or getattr(ctx.args,"ai_supervise",False) or str((ctx.profile or {}).get("name","")) in {"authorized_redteam","authorized_assumed_breach"}): return
    out=RT.evidence_dir(ctx,"03_agentic_control_manifest")
    catalog=tool_catalog.load(getattr(ctx.args,"tool_catalog",None))
    capabilities=capability_registry.summary(capability_registry.load(getattr(ctx.args,"capability_registry",None)))
    try:
        import tbhm; phases=list(tbhm.PHASE_ORDER)
    except Exception: phases=[]
    manifest=build(phases=phases,tool_rows=catalog.get("tools",[]))
    manifest["capability_registry"]={"version":capabilities.get("registry_version"),"registered":capabilities.get("registered"),"available_now":capabilities.get("available_now"),"implementation_states":capabilities.get("counts_by_implementation_state")}
    manifest["supervision"]={"run_artifacts":"sanitized T3 untrusted knowledge","code_evolution":"proposal only; human approval and regression tests required","tool_calls":"deny by default; only the explicit structured read-only safe-plan allowlist may execute","planned_or_unavailable":"never represented as operational"}
    (out/"mcp_capability_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    (out/"capability_status.json").write_text(json.dumps(capabilities,indent=2),encoding="utf-8")
    RT.write_md(out/"AGENTIC_CONTROL_MANIFEST.md","Agentic and Capability Control Manifest",[("Architecture","A local declarative manifest is generated. No MCP network server is started and catalog registration does not make a tool AI-callable."),("Capability honesty",json.dumps(manifest["capability_registry"],indent=2)),("Trust","All outputs are untrusted evidence. The AI plane cannot change scope, confirmation, severity, code, or execution state.")])
    ctx.phase_state["agentic_manifest"]={"tools":len(manifest["tool_resources"]),"phases":len(manifest["phase_resources"]),"capabilities":capabilities.get("registered",0)}
    ctx.log("OK","agentic_control_manifest",f"manifested {len(manifest['tool_resources'])} tools, {len(manifest['phase_resources'])} phases, {capabilities.get('registered',0)} capabilities")
