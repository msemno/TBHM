"""Approval-gated operator validation register and evidence importer (v3.9.5).

This phase deliberately does not launch exploit frameworks, C2, phishing,
credential attacks, coercion, wireless disruption, OT writes or malware.  It
validates the authorization envelope, registers planned actions, imports signed
results, and enforces cleanup/evidence requirements.
"""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from core import redteam_utils as RT
from core.approval_gate import load_manifest,approved,summary as approval_summary
try:
    import yaml
except Exception:yaml=None

def _load(path):
    if not path:return {}
    p=Path(path)
    try:return json.loads(p.read_text()) if p.suffix.lower()=='.json' else yaml.safe_load(p.read_text())
    except Exception:return {}

def _hash_file(path):
    try:return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:return ''

def run(ctx):
    if getattr(ctx.args, 'brokered_http_plan', None):
        from core.brokered_http import run as replay_reads
        replay_reads(ctx)
    if getattr(ctx.args, 'strict_replay_plan', None):
        from core.strict_replay import run as strict_replay
        strict_replay(ctx)
    if not (getattr(ctx.args,'validation_plan',None) or getattr(ctx.args,'validation_results',None) or getattr(ctx.args,'controlled_validation',False)):
        return
    out=RT.evidence_dir(ctx,'103_controlled_validation_plane')
    try:manifest=load_manifest(getattr(ctx.args,'approval_manifest',None))
    except Exception as e:manifest={}; ctx.log('WARN','controlled_validation_plane',str(e))
    plan=_load(getattr(ctx.args,'validation_plan',None)); actions=[]
    for item in (plan.get('actions',[]) if isinstance(plan,dict) else []):
        if not isinstance(item,dict):continue
        action=str(item.get('action') or item.get('type') or '').strip(); target=str(item.get('target') or '').strip()
        ok,detail=approved(manifest,action,target)
        actions.append({'id':item.get('id',''),'action':action,'target':target,'attack_technique':item.get('attack_technique',''),'expected_impact':item.get('expected_impact',''),'max_duration':item.get('max_duration',''),'request_limit':item.get('request_limit',''),'evidence_required':item.get('evidence_required',[]),'cleanup':item.get('cleanup',[]),'approved':ok,'approval_detail':detail,'execution_status':'AUTHORIZED_NOT_EXECUTED' if ok else 'BLOCKED'})
    results=[]; rp=getattr(ctx.args,'validation_results',None)
    if rp:
        q=Path(rp); files=[q] if q.is_file() else [p for p in q.rglob('*.json') if p.is_file()] if q.is_dir() else []
        for p in files[:1000]:
            try:
                data=json.loads(p.read_text(errors='ignore')); vals=data if isinstance(data,list) else data.get('results',[data]) if isinstance(data,dict) else []
                for x in vals:
                    if not isinstance(x,dict):continue
                    action=str(x.get('action') or x.get('type') or 'approved_external_validation_import')
                    target=str(x.get('target') or '')
                    result_ok,result_detail=approved(manifest,action,target)
                    row={**x,'source_file':p.name,'source_sha256':_hash_file(p),
                         'approval_verified':result_ok,'approval_detail':result_detail}; results.append(row)
                    if result_ok and str(x.get('outcome','')).lower() in ('success','validated') and x.get('evidence'):
                        ctx.save_finding({'phase':'controlled_validation_plane','severity':str(x.get('severity') or 'HIGH').upper(),'confidence':'HIGH','title':str(x.get('title') or f"Approved validation evidence — {action}")[:180],'target':target,'description':'Imported evidence from a separately approved validation action. TBHM preserves the authorization and cleanup record but does not execute the action itself.','evidence':str(x.get('evidence'))[:2400],'impact':str(x.get('impact') or x.get('expected_impact') or 'Approved proof-of-impact was recorded.'),'remediation':str(x.get('remediation') or 'Remediate the validated control failure, remove test artifacts, and retest.'),'cwe':str(x.get('cwe') or 'CWE-693'),'finding_class':'supported','status':'supported','verified':False,'verification_method':'approved-external-validation-evidence','approval_manifest':approval_summary(manifest),'cleanup_status':x.get('cleanup_status','UNKNOWN')})
            except Exception:continue
    RT.write_csv(out/'validation_action_register.csv',actions)
    (out/'validation_results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    blocked=sum(1 for a in actions if not a['approved']); cleanup_open=sum(1 for r in results if str(r.get('cleanup_status','')).upper() not in ('COMPLETE','COMPLETED','VERIFIED'))
    payload={'approval':approval_summary(manifest),'actions':len(actions),'approved_actions':len(actions)-blocked,'blocked_actions':blocked,'imported_results':len(results),'cleanup_open_or_unknown':cleanup_open,'execution':'No high-impact action is launched by TBHM. Approved operator tooling is external and evidence is imported.'}
    (out/'controlled_validation_summary.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    RT.write_md(out/'CONTROLLED_VALIDATION_PLANE.md','Approval-Gated Validation Plane',[("Summary",json.dumps(payload,indent=2)),("Required controls",'Engagement ID, exact target/action, ATT&CK technique, expected impact, maximum duration, request limits, evidence requirements, kill/stop conditions, cleanup and human approval.'),("Operator-layer catalog",'Metasploit, Sliver, Mythic, Havoc, Cobalt Strike, GoPhish, Atomic Red Team, CALDERA, Stratus, credential/coercion/relay tools and disruptive wireless/OT tooling are registered but never auto-executed.')])
    ctx.log('WARN' if blocked else 'OK','controlled_validation_plane',f'{len(actions)-blocked}/{len(actions)} planned actions authorized; {len(results)} result(s) imported')
