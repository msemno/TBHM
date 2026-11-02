"""Purple-team detection-validation plan/result normalizer (v3.9.5)."""
from __future__ import annotations
import csv,json,re
from pathlib import Path
from core import redteam_utils as RT
try:
    import yaml
except Exception:yaml=None

def _load(p):
    if not p:return {}
    q=Path(p)
    try:return json.loads(q.read_text()) if q.suffix.lower()=='.json' else yaml.safe_load(q.read_text())
    except Exception:return {}

def run(ctx):
    if not (getattr(ctx.args,'purple_team',False) or getattr(ctx.args,'purple_results',None) or getattr(ctx.args,'purple_plan',None)):
        return
    out=RT.evidence_dir(ctx,'101_purple_team_validation'); plan=_load(getattr(ctx.args,'purple_plan',None)); rows=[]
    for item in (plan.get('tests',[]) if isinstance(plan,dict) else []):
        if not isinstance(item,dict):continue
        rows.append({'test_id':item.get('id',''),'attack_technique':item.get('attack_technique',''),'objective':item.get('objective',''),'expected_telemetry':item.get('expected_telemetry',''),'d3fend':item.get('d3fend',''),'execution_status':'PLANNED','alert_result':'NOT_TESTED','investigation_result':'NOT_TESTED','cleanup':'REQUIRED'})
    rp=getattr(ctx.args,'purple_results',None)
    if rp:
        q=Path(rp); files=[q] if q.is_file() else [p for p in q.rglob('*') if p.is_file()] if q.is_dir() else []
        for p in files[:1000]:
            try:
                if p.suffix.lower() in ('.json','.jsonl'):
                    data=json.loads(p.read_text(errors='ignore')); vals=data if isinstance(data,list) else data.get('results',[data]) if isinstance(data,dict) else []
                    for x in vals:
                        if isinstance(x,dict):rows.append({'test_id':x.get('test_id') or x.get('id',''),'attack_technique':x.get('attack_technique') or x.get('technique',''),'objective':x.get('objective',''),'expected_telemetry':x.get('expected_telemetry',''),'d3fend':x.get('d3fend',''),'execution_status':x.get('execution_status') or x.get('status','OBSERVED'),'alert_result':x.get('alert_result','UNKNOWN'),'investigation_result':x.get('investigation_result','UNKNOWN'),'cleanup':x.get('cleanup','UNKNOWN'),'source':p.name})
            except Exception:continue
    RT.write_csv(out/'detection_validation_matrix.csv',rows)
    payload={'tests':len(rows),'detected':sum(1 for r in rows if str(r.get('alert_result')).upper() in ('DETECTED','PASS','TRUE')),'not_detected':sum(1 for r in rows if str(r.get('alert_result')).upper() in ('NOT_DETECTED','FAIL','FALSE')),'supported_integrations':['Atomic Red Team result import','MITRE CALDERA result import','Stratus Red Team result import','PurpleSharp/Invoke-Atomic result import','Sigma/YARA rule references'],'execution_boundary':'TBHM does not execute adversary-emulation tests in this phase. Execution requires the controlled validation plane and operator approval.'}
    (out/'purple_team_summary.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    RT.write_md(out/'PURPLE_TEAM_VALIDATION.md','Purple-Team Detection Validation',[("Result",json.dumps(payload,indent=2)),("Required record",'Every test connects ATT&CK technique, expected telemetry, actual telemetry, alert, investigation, response and cleanup evidence.'),("D3FEND",'Defensive countermeasure IDs may be supplied in the plan or imported from a maintained D3FEND dataset.')])
    ctx.log('OK','purple_team_validation',f'{len(rows)} detection-validation record(s)')
