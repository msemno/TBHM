"""Multi-cloud/Kubernetes posture adapter phase (v3.9.5)."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT
from core.scanner_normalizer import iter_result_files, parse_file, save_items
from core.approval_gate import load_manifest, approved, summary as approval_summary


def _run(ctx,out,manifest):
    if not getattr(ctx.args,'cloud_posture_live',False): return [], 'not requested'
    ok, reason = approved(manifest, 'cloud_readonly', '')
    if not ok: return [], reason
    tools={x.strip().lower() for x in str(getattr(ctx.args,'cloud_posture_tools','prowler,scoutsuite,kube-bench,kubescape,kubeaudit,kube-linter')).split(',') if x.strip()}
    providers=[x.strip().lower() for x in str(getattr(ctx.args,'cloud_profiles','') or '').split(',') if x.strip()]
    made=[]
    for provider in providers:
        if 'prowler' in tools and ctx.runner.has('prowler'):
            p=out/f'prowler_{provider}'; p.mkdir(exist_ok=True)
            ctx.runner.run(['prowler',provider,'--output-directory',str(p)],timeout=3600,log_name=f'cloud_prowler_{provider}', capture_mode="tail"); made.append(p)
        if 'scoutsuite' in tools and (ctx.runner.has('scout') or ctx.runner.has('ScoutSuite')):
            exe='scout' if ctx.runner.has('scout') else 'ScoutSuite'; p=out/f'scoutsuite_{provider}'; p.mkdir(exist_ok=True)
            ctx.runner.run([exe,provider,'--report-dir',str(p),'--no-browser'],timeout=3600,log_name=f'cloud_scoutsuite_{provider}', capture_mode="tail"); made.append(p)
    if 'kube-bench' in tools and ctx.runner.has('kube-bench'):
        p=out/'kube_bench.json'; rc,stdout,stderr=ctx.runner.run(['kube-bench','run','--json'],timeout=1200,log_name='cloud_kube_bench'); p.write_text(stdout,encoding='utf-8'); made.append(p)
    if 'kubescape' in tools and ctx.runner.has('kubescape'):
        p=out/'kubescape.json'; ctx.runner.run(['kubescape','scan','framework','nsa','--format','json','--output',str(p)],timeout=1800,log_name='cloud_kubescape', capture_mode="tail"); made.append(p)
    if 'kubeaudit' in tools and ctx.runner.has('kubeaudit'):
        p=out/'kubeaudit.json'; rc,stdout,stderr=ctx.runner.run(['kubeaudit','all','-o','json'],timeout=1200,log_name='cloud_kubeaudit'); p.write_text(stdout,encoding='utf-8'); made.append(p)
    kdir=getattr(ctx.args,'k8s_manifests',None)
    if kdir and 'kube-linter' in tools and ctx.runner.has('kube-linter'):
        p=out/'kube_linter.json'; rc,stdout,stderr=ctx.runner.run(['kube-linter','lint',str(kdir),'--format','json'],timeout=1200,log_name='cloud_kube_linter'); p.write_text(stdout,encoding='utf-8'); made.append(p)
    return made, 'approved read-only posture tools attempted'

def run(ctx):
    if not (getattr(ctx.args,'cloud_posture',False) or getattr(ctx.args,'cloud_posture_results',None)):
        return
    out=RT.evidence_dir(ctx,'77_cloud_posture_tooling')
    try: manifest=load_manifest(getattr(ctx.args,'approval_manifest',None))
    except Exception as exc: manifest={}; ctx.log('WARN','cloud_posture_tooling',str(exc))
    generated, live_detail=_run(ctx,out,manifest)
    paths=[]; rp=getattr(ctx.args,'cloud_posture_results',None)
    if rp:
        q=Path(rp); paths=[q] if q.is_file() else list(q.rglob('*')) if q.is_dir() else []
    paths += list(out.rglob('*'))
    count=0
    for p in paths:
        if p.is_file() and p.suffix.lower() in {'.json','.jsonl','.sarif'}:
            count += save_items(ctx,'cloud_posture_tooling',parse_file(p,source=p.stem),p.stem,{'cloud_posture':True})
    payload={'normalized_observations':count,'tools':['Prowler','ScoutSuite','Steampipe/CloudQuery/Cartography imports','Cloudsplaining','kube-bench','Kubescape','kubeaudit','kube-linter','Polaris imports','OPA/Conftest/Kyverno policy results'],'live_execution':'read-only posture commands only when --cloud-posture-live is set and cloud_readonly is approved','live_detail':live_detail,'approval':approval_summary(manifest)}
    (out/'cloud_posture_summary.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    RT.write_md(out/'CLOUD_POSTURE_SUMMARY.md','Cloud, Kubernetes and Policy Posture',[("Result",json.dumps(payload,indent=2)),("Boundary",'No cloud resource creation, modification, role assumption, persistence or exploitation is performed.')])
    ctx.log('OK','cloud_posture_tooling',f'{count} cloud posture observation(s) normalized')
