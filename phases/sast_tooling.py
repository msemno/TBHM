"""Opt-in SAST/SCA orchestration and normalized import (v3.7).

Preserves native code_scan/code_intel. This phase adds adapters, never replaces them.
Live execution is limited to local source supplied with --code-dir.
"""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT


def _sev(v):
    s=str(v or 'INFO').upper()
    return {'ERROR':'HIGH','WARNING':'MEDIUM','NOTE':'LOW','CRITICAL':'CRITICAL','HIGH':'HIGH','MEDIUM':'MEDIUM','LOW':'LOW','INFO':'INFO'}.get(s,'INFO')

def _emit(ctx, title, sev, path='', line='', evidence='', rule=''):
    ctx.save_finding({'phase':'sast_tooling','severity':_sev(sev),'confidence':'MEDIUM','title':title[:180],
      'target':path,'url':'','description':f'Static-analysis result from {rule or "external SAST"}. Review data flow and reachability before treating as exploitable.',
      'evidence':f'{path}:{line} {evidence}'[:1800],'impact':'Potential source-code weakness; actual impact depends on reachability and controls.',
      'remediation':'Validate the finding, fix the unsafe data flow or dependency, add a regression test, and rerun SAST.',
      'cwe':'CWE-20','mrs_score':{'CRITICAL':90,'HIGH':75,'MEDIUM':50,'LOW':25,'INFO':10}.get(_sev(sev),10)})

def _import(ctx, p:Path):
    try: data=json.loads(p.read_text(errors='ignore'))
    except Exception: return 0
    n=0
    # SARIF
    for run in data.get('runs',[]) if isinstance(data,dict) else []:
      rules={r.get('id'):r for r in run.get('tool',{}).get('driver',{}).get('rules',[])}
      for r in run.get('results',[]):
        loc=((r.get('locations') or [{}])[0].get('physicalLocation') or {})
        art=(loc.get('artifactLocation') or {}).get('uri',''); reg=loc.get('region') or {}
        rid=r.get('ruleId',''); msg=(r.get('message') or {}).get('text','')
        _emit(ctx, f'SAST: {rid or msg[:80]}', r.get('level'), art, reg.get('startLine',''), msg, rid); n+=1
    # Semgrep JSON
    if isinstance(data,dict):
      for r in data.get('results',[]):
        extra=r.get('extra') or {}; meta=extra.get('metadata') or {}
        sev=extra.get('severity') or meta.get('severity')
        _emit(ctx, f"Semgrep: {r.get('check_id','finding')}",sev,r.get('path',''),(r.get('start') or {}).get('line',''),extra.get('message',''),r.get('check_id','')); n+=1
    return n

def run(ctx):
    if not (getattr(ctx.args,'sast_tooling',False) or getattr(ctx.args,'sast_results',None)): return
    out=RT.evidence_dir(ctx,'19_sast_tooling'); total=0
    src=getattr(ctx.args,'code_dir',None)
    if getattr(ctx.args,'sast_tooling',False) and src and Path(src).is_dir():
      if ctx.runner.has('semgrep'):
        dest=out/'semgrep.json'
        ctx.runner.run(['semgrep','scan','--config',str(Path(__file__).resolve().parents[1]/'tooling'/'semgrep-native.yaml'),'--json','--output',str(dest),str(Path(src).resolve())],timeout=3600,log_name='sast_semgrep', capture_mode="tail")
        if dest.exists(): total+=_import(ctx,dest)
      else: ctx.log('WARN','sast_tooling','semgrep not installed — native code_scan/code_intel remain active')
    rp=getattr(ctx.args,'sast_results',None)
    if rp:
      q=Path(rp)
      for f in ([q] if q.is_file() else list(q.rglob('*')) if q.is_dir() else []):
        if f.is_file() and f.suffix.lower() in ('.json','.sarif'): total+=_import(ctx,f)
    RT.write_md(out/'SAST_TOOLING_SUMMARY.md','SAST Tooling Summary', [('Status',f'{total} normalized result(s).'),('Coverage','Semgrep execution plus SARIF/JSON import supports evidence produced by Snyk Code, commercial SAST platforms, and CI scanners without coupling TBHM to proprietary APIs.'),('Validation','Imported findings remain MEDIUM confidence until source reachability and exploitability are confirmed.')])
    ctx.log('OK','sast_tooling',f'{total} SAST result(s) normalized')
