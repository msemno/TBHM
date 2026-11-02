"""AI supervision of phase/tool coverage and run learning (v3.9.5).

The local co-pilot reviews deterministic readiness and run state, writes an
advisory, and can create a proposal record only when the operator explicitly
sets --ai-propose-improvements. It never applies code or runs tools.
"""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT
from core import tool_catalog
from core.ai_plane.sanitizer import scrub,controlled_state
from core.ai_plane.findings import confirmation_status

def run(ctx):
    _profile_name=str((getattr(ctx, "profile", {}) or {}).get("name", ""))
    _corporate_profile=_profile_name in {"authorized_redteam", "authorized_assumed_breach"}
    if not (_corporate_profile or getattr(ctx.args,'ai_supervise',False) or getattr(ctx.args,'ai_observe',False)):
        return
    out=RT.evidence_dir(ctx,'106_ai_supervision')
    catalog=tool_catalog.load(getattr(ctx.args,'tool_catalog',None)); ready=tool_catalog.readiness(catalog)
    missing=[r for r in ready['rows'] if r.get('executable') and not r.get('installed')]
    deterministic={'tool_catalog_registered':ready['registered'],'executable_integrations':ready['executable_entries'],'installed':ready['installed_executables'],'missing_by_category':{},'phase_failures':[],'recommendations':[]}
    for row in missing: deterministic['missing_by_category'].setdefault(row['category'],[]).append(row['name'])
    try:
        for r in ctx.storage.conn.execute("SELECT phase,status FROM phase_state WHERE status NOT IN ('done','succeeded')"):
            deterministic['phase_failures'].append({'phase':r['phase'],'status':r['status']})
    except Exception:pass
    priorities=['vulnerability-intelligence','identity-security','cloud-posture','corporate-osint','osint-depth','ci-cd-security','api-testing','mobile-reverse','data-analysis','purple-team','agentic-control']
    for cat in priorities:
        names=deterministic['missing_by_category'].get(cat,[])
        if names: deterministic['recommendations'].append({'category':cat,'missing':names[:20],'action':'install vetted tools or configure import/API evidence; keep approval-only tooling external'})
    advisory={'deterministic':deterministic,'model_used':False,'model':{},'non_authoritative':True}
    plane=None
    try:
        from core.ai_plane import build_plane
        plane=build_plane(ctx.args,create=True,need_runtime=True)
        if plane.runtime and plane.runtime.client.available()[0]:
            findings=[]
            for f in ctx.storage.all_findings():
                st=confirmation_status(f)
                if st in ('CONFIRMED','SUPPORTED'):
                    findings.append({'title':scrub(f.get('title',''),160),'status':st,'severity':f.get('severity'),'phase':f.get('phase'),'where':scrub(f.get('url') or f.get('target') or '',160)})
            observed=json.dumps({'readiness':deterministic,'data_analysis':ctx.phase_state.get('data_analysis_summary',{}),'engagement_objectives':ctx.phase_state.get('engagement_objectives',{}),'osint_depth':ctx.phase_state.get('osint_depth',{}),'execution_orchestration':ctx.phase_state.get('execution_orchestration',{}),'compliance_extended':ctx.phase_state.get('compliance_extended',{}),'agentic_manifest':ctx.phase_state.get('agentic_manifest',{})},default=str)
            model=plane.advisor.analyze_run(controlled_state(ctx),findings[:50],observed=observed)
            advisory['model_used']=True; advisory['model']=model
            if getattr(ctx.args,'ai_propose_improvements',False):
                gaps=list(model.get('coverage_gaps') or [])+[
                    f"Missing {x['category']} integrations: {', '.join(x['missing'][:8])}" for x in deterministic['recommendations'][:20]
                ]
                if gaps:
                    rec=plane.gate.create(problem='TBHM run/tool coverage gaps require operator review',evidence=[{'run_output':str(ctx.output),'gaps':gaps[:30]}],affected_files=[],patch_text='',expected_benefit='Improve coverage without weakening authorization, scope, evidence or propose-and-approve controls.',risks=['Adding tools without adapter tests can create false confidence.','High-risk operator tooling must remain approval-gated.'])
                    advisory['proposal_id']=rec['proposal_id']
    except Exception as e:
        advisory['model_error']=str(e)
    finally:
        if plane:
            try:plane.close()
            except Exception:pass
    (out/'ai_supervision.json').write_text(json.dumps(advisory,indent=2),encoding='utf-8')
    lines=['# AI Supervision and Continuous Learning','', '> Advisory only. The co-pilot never executes tools, changes scope/status/severity, or applies code.', '', '## Deterministic readiness','', '```json',json.dumps(deterministic,indent=2),'```','']
    if advisory['model_used']:
        lines+=['## Local-model advisory','',str(advisory['model'].get('overall_summary','')),'','### Coverage gaps','']+[f"- {x}" for x in advisory['model'].get('coverage_gaps',[])]
    if advisory.get('proposal_id'):lines+=['',f"Proposal created for human review: **{advisory['proposal_id']}**. It contains no auto-applied patch."]
    (out/'AI_SUPERVISION.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    ctx.log('OK','ai_supervision',f"supervision complete; model_used={advisory['model_used']}")
