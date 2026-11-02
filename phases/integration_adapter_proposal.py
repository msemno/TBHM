"""Generate a disabled, proposal-only integration adapter design."""
from __future__ import annotations

import json
from pathlib import Path
from core import redteam_utils as RT
from core.adapter_proposals import generate


def run(ctx):
    path=getattr(ctx.args,"adapter_definition",None)
    if not path:
        return
    out=RT.evidence_dir(ctx,"109_integration_adapter_proposal")
    try:
        definition=json.loads(Path(path).read_text(encoding="utf-8"))
        proposal=generate(definition)
    except Exception as exc:
        proposal={"status":"REJECTED","error":f"{type(exc).__name__}: {exc}","activation":{"approved":False,"automatic_install":False,"automatic_execution":False}}
    (out/"adapter_proposal.json").write_text(json.dumps(proposal,indent=2,ensure_ascii=False),encoding="utf-8")
    RT.write_md(out/"ADAPTER_PROPOSAL.md","Proposal-Only Integration Adapter",[("Status",str(proposal.get("status"))), ("Activation",json.dumps(proposal.get("activation",{}),indent=2)), ("Boundary","The generated material is unapproved design output. It cannot install, activate, trust, register as operational, or execute the proposed adapter.")])
    ctx.phase_state["integration_adapter_proposal"]={"status":proposal.get("status")}
    ctx.log("OK" if proposal.get("status")=="UNAPPROVED_PROPOSAL" else "WARN","integration_adapter_proposal",str(proposal.get("status")))
