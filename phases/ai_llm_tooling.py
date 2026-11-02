"""Opt-in AI/LLM assessment adapter and result normalizer (v3.7)."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT

def _iter(path):
  for f in ([path] if path.is_file() else path.rglob('*') if path.is_dir() else []):
    if not f.is_file() or f.suffix.lower() not in ('.json','.jsonl'): continue
    for line in ([f.read_text(errors='ignore')] if f.suffix.lower()=='.json' else f.read_text(errors='ignore').splitlines()):
      try:
        d=json.loads(line)
        for x in (d if isinstance(d,list) else [d]): yield f,x
      except Exception: continue

def run(ctx):
  if getattr(ctx.args,'llm_security_input',None):
    from core.llm_security_import import run as import_security_evidence
    import_security_evidence(ctx)
  if getattr(ctx.args,'learning_corpus_input',None):
    from core.learning_corpus_audit import run as audit_learning_data
    audit_learning_data(ctx)
  if not (getattr(ctx.args,'ai_tooling',False) or getattr(ctx.args,'ai_results',None)): return
  out=RT.evidence_dir(ctx,'20_ai_llm_tooling'); n=0
  if getattr(ctx.args,'ai_tooling',False):
    gen=getattr(ctx.args,'ai_generator',None); model=getattr(ctx.args,'ai_model',None)
    if gen and model and ctx.runner.has('garak'):
      probes=','.join(x.strip() for x in getattr(ctx.args,'ai_probes','promptinject,leakreplay').split(',') if x.strip())
      ctx.runner.run(['garak','--model_type',gen,'--model_name',model,'--probes',probes,'--report_prefix',str(out/'garak')],timeout=7200,log_name='ai_garak', capture_mode="tail")
    elif gen or model: ctx.log('WARN','ai_llm_tooling','garak unavailable or generator/model incomplete — importing/checklist only')
  rp=getattr(ctx.args,'ai_results',None)
  if rp:
    for f,d in _iter(Path(rp)):
      failed=d.get('passed') is False or d.get('status') in ('failed','vulnerable') or float(d.get('score',0) or 0)>0.5
      if not failed: continue
      title=d.get('probe') or d.get('name') or d.get('category') or 'AI/LLM adverse behavior'
      ctx.save_finding({'phase':'ai_llm_tooling','severity':str(d.get('severity','MEDIUM')).upper(),'confidence':'MEDIUM','title':f'AI/LLM: {title}'[:180],
       'target':d.get('model',''),'url':d.get('endpoint',''),'description':'Normalized AI red-team result. Reproduce with an approved synthetic prompt and review application-layer controls.',
       'evidence':json.dumps(d,ensure_ascii=False)[:1800],'impact':'Possible prompt injection, data leakage, unsafe tool use, or policy-control failure depending on the test.',
       'remediation':'Add layered input/output controls, authorization at every tool/data boundary, monitoring, and regression evaluations.', 'cwe':'CWE-1426','mrs_score':55}); n+=1
  RT.write_md(out/'AI_LLM_TOOLING_SUMMARY.md','AI / LLM Tooling Summary',[('Status',f'{n} adverse result(s) normalized.'),('Execution safety','Live execution is explicit opt-in and uses user-selected conservative probe families. No credentials, hidden prompts, or real private data are requested by TBHM.'),('Supported model','Garak-compatible execution and generic JSON/JSONL import for PyRIT and other evaluation frameworks.')])
  ctx.log('OK','ai_llm_tooling',f'{n} AI/LLM result(s) normalized')
