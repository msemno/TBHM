"""Mobile security tooling adapter (v3.7). Native mobile_scan remains authoritative."""
from __future__ import annotations
import json, os
from pathlib import Path
from core import redteam_utils as RT

def run(ctx):
  if not (getattr(ctx.args,'mobile_tooling',False) or getattr(ctx.args,'mobile_results',None)): return
  out=RT.evidence_dir(ctx,'21_mobile_tooling'); n=0
  # MobSF API is optional and requires explicit server + env key; upload is a user-authorized write to their scanner only.
  server=getattr(ctx.args,'mobsf_url',None); key=os.environ.get('TBHM_MOBSF_API_KEY','')
  app=getattr(ctx.args,'apk',None) or getattr(ctx.args,'ipa',None)
  if getattr(ctx.args,'mobile_tooling',False) and server and key and app and Path(app).is_file() and ctx.runner.has('curl') and getattr(ctx.args,'allow_writes',False):
    ctx.runner.run(['curl','-fsS','-H',f'Authorization: {key}','-F',f'file=@{Path(app).resolve()}',server.rstrip('/')+'/api/v1/upload'],timeout=600,log_name='mobsf_upload', capture_mode="tail")
  elif getattr(ctx.args,'mobile_tooling',False) and server and app and not getattr(ctx.args,'allow_writes',False):
    ctx.log('WARN','mobile_tooling','MobSF upload skipped: requires --allow-writes because it sends the app to the configured scanner')
  rp=getattr(ctx.args,'mobile_results',None)
  if rp and Path(rp).is_file():
    try: d=json.loads(Path(rp).read_text(errors='ignore'))
    except Exception: d={}
    candidates=[]
    if isinstance(d,dict):
      for k in ('findings','issues','results','code_analysis','manifest_analysis'):
        v=d.get(k,[])
        if isinstance(v,list): candidates+=v
        elif isinstance(v,dict): candidates += [{'title':kk,'description':vv} for kk,vv in v.items()]
    for x in candidates:
      if not isinstance(x,dict): continue
      title=x.get('title') or x.get('name') or x.get('rule') or 'Mobile scanner finding'
      sev=str(x.get('severity') or x.get('level') or 'INFO').upper()
      ctx.save_finding({'phase':'mobile_tooling','severity':sev if sev in ('CRITICAL','HIGH','MEDIUM','LOW','INFO') else 'INFO','confidence':'MEDIUM','title':f'Mobile: {title}'[:180],
       'target':str(app or ''),'url':'','description':str(x.get('description') or x.get('info') or '')[:1200], 'evidence':json.dumps(x,ensure_ascii=False)[:1800],
       'impact':'Mobile application or privacy risk; validate on an approved test device.', 'remediation':'Apply platform hardening and verify with static and dynamic retesting.','cwe':'CWE-693','mrs_score':45}); n+=1
  RT.write_md(out/'MOBILE_TOOLING_SUMMARY.md','Mobile Tooling Summary',[('Status',f'{n} external result(s) normalized.'),('Coverage','Complements native APK/IPA/source checks with MobSF-compatible result import and an explicitly gated API upload path.'),('Safety','No drozer or device-side actions are automated; dynamic tests remain operator-controlled on approved test devices.')])
  ctx.log('OK','mobile_tooling',f'{n} mobile result(s) normalized')
