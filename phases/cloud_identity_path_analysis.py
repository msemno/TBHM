"""Read-only AWS/Azure/GCP IAM graph and privilege-path analysis."""
from __future__ import annotations

import json
from core import redteam_utils as RT
from core.cloud_iam_graph import analyze, _walk as _core_walk


def _walk(value):
    """v3.9.6 compatibility wrapper for recursive IAM value iteration."""
    yield from _core_walk(value)


def run(ctx):
    path=getattr(ctx.args,"cloud_iam_input",None)
    if not (getattr(ctx.args,"cloud_identity_paths",False) or path):
        return
    out=RT.evidence_dir(ctx,"79_cloud_identity_path_analysis")
    if not path:
        result={"schema_version":"1","nodes":[],"edges":[],"paths":[],"malformed":[],"summary":{"files":0,"nodes":0,"edges":0,"path_indicators":0,"malformed":0},"boundary":"No input supplied; no cloud IAM conclusion can be made."}
    else:
        result=analyze(path,max_files=max(1,min(int(getattr(ctx.args,"cloud_iam_max_files",2000) or 2000),10000)))
    (out/"cloud_identity_graph.json").write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    # v3.9.6 output compatibility.
    (out/"cloud_identity_paths.json").write_text(json.dumps(result.get("paths",[]),indent=2,ensure_ascii=False),encoding="utf-8")
    for row in result.get("paths",[])[:5000]:
        ctx.save_finding({"phase":"cloud_identity_path_analysis","source_capability":"cloud.iam_graph","severity":"HIGH","confidence":"MEDIUM","title":f"Potential {str(row.get('provider')).upper()} IAM privilege path — {row.get('permission_or_role')}"[:180],"target":row.get("principal") or row.get("source"),"description":"Read-only graph analysis identified an evidence-backed permission/role edge commonly involved in privilege escalation or durable-access paths. Effective exploitability is not asserted.","evidence":json.dumps(row,ensure_ascii=False)[:5000],"evidence_paths":[str(out/"cloud_identity_graph.json")],"impact":"A principal may obtain additional permissions or durable access only if the listed prerequisites, resource scope, trust relationships, and conditions are satisfied.","prerequisites":row.get("prerequisites",[]),"confirmed_behavior":"Permission or role text was present in the supplied IAM evidence.","unconfirmed_assumptions":"Effective permissions, applicable resources, trust policy, deny controls, organization policy, and compensating controls.","remediation":"Review effective permissions and trust, restrict key creation/role assignment/policy modification, apply least privilege and conditions, and monitor sensitive IAM changes.","cwe":"CWE-269","finding_class":"lead","status":"lead","verified":False,"provenance":{"edge_id":row.get("edge_id"),"source":row.get("source")}})
    RT.write_md(out/"CLOUD_IDENTITY_PATHS.md","Read-Only Cloud IAM Privilege Paths",[("Result",json.dumps(result.get("summary",{}),indent=2)),("Method","Normalized AWS, Azure/Entra, GCP, and partially recognized IAM JSON into nodes and edges. Includes AWS iam:CreateAccessKey, Azure Application Administrator and Privileged Role Administrator, and GCP roles/editor indicators; mixed-provider files are analyzed for every applicable provider."),("Limit",result.get("boundary","Permission names and graph edges do not prove exploitability."))])
    ctx.phase_state["cloud_identity_paths"]=result.get("summary",{})
    ctx.log("OK","cloud_identity_path_analysis",f"{result.get('summary',{}).get('path_indicators',0)} potential path indicator(s)")
