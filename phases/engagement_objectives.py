"""First-class engagement lifecycle, objective and kill-chain state model."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT
try:
    import yaml
except Exception:
    yaml=None

DEFAULT_STAGES=["governance","threat_model","intelligence","enumeration","vulnerability_analysis","evidence_validation","controlled_access","detection_validation","cleanup","reporting_retest"]


def _load(path):
    if not path: return {}
    p=Path(path)
    if not p.is_file(): return {}
    text=p.read_text(errors="ignore")
    try: return json.loads(text) if p.suffix.lower()==".json" else (yaml.safe_load(text) if yaml else {})
    except Exception: return {}


def run(ctx):
    _profile_name=str((getattr(ctx, "profile", {}) or {}).get("name", ""))
    _corporate_profile=_profile_name in {"authorized_redteam", "authorized_assumed_breach"}
    if not (_corporate_profile or getattr(ctx.args,"engagement_plan",None) or getattr(ctx.args,"redteam",False)):
        return
    plan=_load(getattr(ctx.args,"engagement_plan",None))
    out=RT.evidence_dir(ctx,"03_engagement_objectives")
    stages=[]
    supplied={str(x.get("stage")):x for x in plan.get("stages",[]) if isinstance(x,dict)} if isinstance(plan,dict) else {}
    for name in DEFAULT_STAGES:
        row=supplied.get(name,{})
        stages.append({"stage":name,"status":row.get("status","planned"),"objectives":row.get("objectives",[]),"success_criteria":row.get("success_criteria",[]),"owner":row.get("owner","")})
    payload={"engagement_id":plan.get("engagement_id","") if isinstance(plan,dict) else "","crown_jewels":plan.get("crown_jewels",[]) if isinstance(plan,dict) else [],"adversary_profiles":plan.get("adversary_profiles",[]) if isinstance(plan,dict) else [],"detection_objectives":plan.get("detection_objectives",[]) if isinstance(plan,dict) else [],"stages":stages,"limitations":plan.get("limitations",[]) if isinstance(plan,dict) else [],"stop_conditions":plan.get("stop_conditions",[]) if isinstance(plan,dict) else []}
    (out/"engagement_objectives.json").write_text(json.dumps(payload,indent=2),encoding="utf-8")
    RT.write_csv(out/"lifecycle_status.csv",stages)
    RT.write_md(out/"ENGAGEMENT_OBJECTIVES.md","Engagement Objectives and Lifecycle",[("Engagement",payload["engagement_id"] or "Not supplied"),("Crown jewels","\n".join(f"- {x}" for x in payload["crown_jewels"]) or "Not supplied"),("Lifecycle","\n".join(f"- {x['stage']}: {x['status']}" for x in stages)),("Safety","Objectives and success criteria do not authorize actions; intrusive validation still requires the approval manifest.")])
    ctx.phase_state["engagement_objectives"]=payload
    ctx.log("OK","engagement_objectives",f"{len(stages)} lifecycle stages registered")
