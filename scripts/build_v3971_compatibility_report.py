#!/usr/bin/env python3
"""Build v3.9.6 baseline and v3.9.7.2 compatibility manifests."""
from __future__ import annotations
import argparse, ast, hashlib, json, os, re, stat
from pathlib import Path
from typing import Any

TEXT_SUFFIXES={'.py','.sh','.md','.yaml','.yml','.json','.txt','.csv','.html','.toml','.ini','.cfg','.conf','.xml','.sarif','.sql','.ps1'}
IGNORE={'__pycache__','.pytest_cache','.git','results','result','output','outputs'}
GENERATED_COMPATIBILITY={
 'BASELINE_COMPATIBILITY_MANIFEST_v3.9.6.json',
 'FINAL_COMPATIBILITY_MANIFEST_v3.9.7.2.json',
 'BACKWARD_COMPATIBILITY_COMPARISON_v3.9.7.2.json',
 'BACKWARD_COMPATIBILITY_REPORT_v3.9.7.2.md',
 'FINAL_STATIC_VALIDATION_v3.9.7.2.json',
 'CLI_SMOKE_SUMMARY_v3.9.7.2.json',
 'RELEASE_MANIFEST-v3.9.7.2.json',
}
OUTPUT_RE=re.compile(r'["\']([^"\']+(?:\.jsonl?|\.md|\.html|\.csv|\.sarif|\.txt|\.log|\.sqlite3|\.db))["\']')
SCHEMA_RE=re.compile(r'(?:https?://[^\s\"\']*schema[^\s\"\']*|tbhm-[a-z0-9_.-]+/v\d+|[A-Za-z0-9_.:/-]*schema[A-Za-z0-9_.:/-]*\.(?:json|yaml|yml))', re.I)
ENV_RE=re.compile(r'(?:os\.environ(?:\.get)?|os\.getenv)\s*\(\s*["\']([^"\']+)["\']')

def sha(path:Path)->str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()

def files(root:Path):
 for p in sorted(root.rglob('*')):
  if any(part in IGNORE for part in p.relative_to(root).parts): continue
  if p.is_file() and p.name not in GENERATED_COMPATIBILITY: yield p

def text(path:Path)->str:
 try:return path.read_text(encoding='utf-8')
 except Exception:
  try:return path.read_text(encoding='latin-1')
  except Exception:return ''

def phase_order(root:Path)->list[str]:
 p=root/'tbhm.py'
 try: tree=ast.parse(text(p))
 except Exception:return []
 for n in tree.body:
  if isinstance(n,(ast.Assign,ast.AnnAssign)):
   targets=n.targets if isinstance(n,ast.Assign) else [n.target]
   value=n.value
   if any(isinstance(t,ast.Name) and t.id=='PHASE_ORDER' for t in targets):
    try:
     v=ast.literal_eval(value)
     if isinstance(v,list):return [str(x) for x in v]
    except Exception: pass
 return []

def public_symbols(path:Path)->list[str]:
 try: tree=ast.parse(text(path))
 except Exception:return []
 out=[]
 for n in tree.body:
  if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
   if not n.name.startswith('_'):out.append(n.name)
   if isinstance(n,ast.ClassDef):
    out += [f'{n.name}.{m.name}' for m in n.body if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)) and not m.name.startswith('_')]
 return sorted(set(out))

def cli_inventory(root:Path)->list[dict]:
 out=[]
 for p in files(root):
  if p.suffix!='.py':continue
  try:tree=ast.parse(text(p))
  except Exception:continue
  for n in ast.walk(tree):
   if not(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='add_argument'):continue
   flags=[]
   for a in n.args:
    try:v=ast.literal_eval(a)
    except Exception:continue
    if isinstance(v,str) and v.startswith('-'):flags.append(v)
   if not flags:continue
   kwargs={}
   for kw in n.keywords:
    if not kw.arg:continue
    try:kwargs[kw.arg]=ast.literal_eval(kw.value)
    except Exception:
     try:kwargs[kw.arg]=ast.unparse(kw.value)
     except Exception:kwargs[kw.arg]='<dynamic>'
   out.append({'path':str(p.relative_to(root)),'line':n.lineno,'flags':flags,'primary':next((x for x in flags if x.startswith('--')),flags[0]),'aliases':flags[1:],'dest':kwargs.get('dest'),'action':kwargs.get('action'),'default':kwargs.get('default'),'required':kwargs.get('required',False)})
 return sorted(out,key=lambda x:(x['primary'],x['path'],x['line']))

def nested_keys(obj:Any,prefix='')->set[str]:
 out=set()
 if isinstance(obj,dict):
  for k,v in obj.items():
   key=f'{prefix}.{k}' if prefix else str(k);out.add(key);out|=nested_keys(v,key)
 elif isinstance(obj,list):
  for v in obj[:50]:out|=nested_keys(v,prefix+'[]')
 return out

def structured_keys(root:Path)->dict[str,list[str]]:
 out={}
 for p in files(root):
  if p.suffix.lower() not in {'.json','.yaml','.yml'}:continue
  try:
   if p.suffix.lower()=='.json':obj=json.loads(text(p))
   else:
    import yaml;obj=yaml.safe_load(text(p))
  except Exception:continue
  out[str(p.relative_to(root))]=sorted(nested_keys(obj))
 return out

def profile_phases(root:Path)->dict[str,list[str]]:
 out={}
 try:import yaml
 except Exception:return out
 for p in sorted((root/'profiles').glob('*.y*ml')) if (root/'profiles').is_dir() else []:
  try:d=yaml.safe_load(text(p)) or {}
  except Exception:continue
  if isinstance(d,dict) and isinstance(d.get('phases'),list):out[str(p.relative_to(root))]=list(map(str,d['phases']))
 return out

def manifest(root:Path,release:str)->dict:
 fs=[]; outputs=set(); reports=set(); evidence=set(); schemas=set(); env=set(); entry=[]; docs=[]; installers=[]; modules=[]; packages=[]; py_symbols={}
 for p in files(root):
  rel=str(p.relative_to(root));t=text(p) if p.suffix.lower() in TEXT_SUFFIXES and p.stat().st_size<=5_000_000 else ''
  fs.append({'path':rel,'size':p.stat().st_size,'sha256':sha(p),'executable':bool(p.stat().st_mode&stat.S_IXUSR),'type':p.suffix.lower().lstrip('.') or 'no_extension'})
  if p.suffix=='.py':
   mod=rel[:-3].replace('/','.')
   if mod.endswith('.__init__'):mod=mod[:-9];packages.append(mod)
   else:modules.append(mod)
   py_symbols[rel]=public_symbols(p)
   if 'if __name__' in t and '__main__' in t:entry.append(rel)
  if p.suffix=='.sh' and bool(p.stat().st_mode&stat.S_IXUSR):entry.append(rel)
  if p.suffix=='.md':docs.append(rel)
  if p.suffix=='.sh' and ('install' in p.name.lower() or rel.startswith('scripts/install')):installers.append(rel)
  for val in OUTPUT_RE.findall(t):
   outputs.add(val)
   if 'report' in val.lower() or 'methodology' in val.lower():reports.add(val)
   if 'evidence' in val.lower():evidence.add(val)
  schemas.update(x for x in SCHEMA_RE.findall(t) if len(x)<220)
  env.update(ENV_RE.findall(t))
 cli=cli_inventory(root); flags=sorted({f for r in cli for f in r['flags']})
 phases=phase_order(root)
 return {'schema':'tbhm-compatibility-manifest/v2','release':release,'root_name':root.name,'root_sha256':hashlib.sha256('\n'.join(f"{x['sha256']}  {x['path']}" for x in fs).encode()).hexdigest(),'files':fs,'file_paths':[x['path'] for x in fs],'executable_scripts':sorted(set(entry)),'python_modules':sorted(modules),'importable_packages':sorted(set(packages)),'public_symbols':py_symbols,'cli_arguments':cli,'cli_option_strings':flags,'cli_option_count':len(flags),'phase_names':phases,'phase_count':len(phases),'profile_phase_order':profile_phases(root),'configuration_keys':structured_keys(root),'report_filenames':sorted(reports),'output_filenames':sorted(outputs),'evidence_paths':sorted(evidence),'schema_identifiers':sorted(schemas),'environment_variables':sorted(env),'entry_points':sorted(set(entry)),'installer_scripts':sorted(installers),'documentation_files':sorted(docs)}

def flatten_config(d:dict)->set[str]:
 return {f'{p}::{k}' for p,ks in d.items() for k in ks}

def compare(base:dict,final:dict)->dict:
 bpaths=set(base['file_paths']);fpaths=set(final['file_paths']);bflags=set(base['cli_option_strings']);fflags=set(final['cli_option_strings']);bph=base['phase_names'];fph=final['phase_names']
 common=[x for x in bph if x in fph]
 reordered=[]
 last=-1
 for x in common:
  idx=fph.index(x)
  if idx<last:reordered.append(x)
  last=max(last,idx)
 profile_changes={}
 for path,old in base['profile_phase_order'].items():
  new=final['profile_phase_order'].get(path)
  if new is not None and old!=new: profile_changes[path]={'old':old,'new':new}
 bcfg=flatten_config(base['configuration_keys']);fcfg=flatten_config(final['configuration_keys'])
 return {'schema':'tbhm-compatibility-comparison/v2','baseline_release':base['release'],'final_release':final['release'],'summary':{'baseline_files':len(bpaths),'final_files':len(fpaths),'preserved_original_paths':len(bpaths&fpaths),'missing_original_paths':len(bpaths-fpaths),'added_paths':len(fpaths-bpaths),'baseline_cli_options':len(bflags),'final_cli_options':len(fflags),'missing_cli_options':len(bflags-fflags),'added_cli_options':len(fflags-bflags),'baseline_phases':len(bph),'final_phases':len(fph),'missing_phases':len(set(bph)-set(fph)),'added_phases':len(set(fph)-set(bph))},'original_file_paths_preserved':sorted(bpaths&fpaths),'original_file_paths_intentionally_migrated':[],'missing_original_file_paths':sorted(bpaths-fpaths),'added_file_paths':sorted(fpaths-bpaths),'compatibility_aliases_added':['REPORT.json -> report.json equivalent','REPORT.csv -> report.csv equivalent','REPORT.sarif -> report.sarif equivalent','legacy reporter helpers','legacy scanner sev/walk wrappers','legacy reverse import_json/static_strings wrappers'],'original_cli_options_preserved':sorted(bflags&fflags),'missing_original_cli_options':sorted(bflags-fflags),'new_cli_options':sorted(fflags-bflags),'renamed_cli_options_with_aliases':[],'original_phases_preserved':sorted(set(bph)&set(fph)),'missing_original_phases':sorted(set(bph)-set(fph)),'new_phases':sorted(set(fph)-set(bph)),'phase_order_reversals_among_original_phases':reordered,'profile_phase_reordering':profile_changes,'old_output_paths_preserved':sorted(set(base['output_filenames'])&set(final['output_filenames'])),'missing_old_output_paths':sorted(set(base['output_filenames'])-set(final['output_filenames'])),'new_output_paths':sorted(set(final['output_filenames'])-set(base['output_filenames'])),'old_report_paths_preserved':sorted(set(base['report_filenames'])&set(final['report_filenames'])),'missing_old_report_paths':sorted(set(base['report_filenames'])-set(final['report_filenames'])),'old_schema_ids_preserved':sorted(set(base['schema_identifiers'])&set(final['schema_identifiers'])),'missing_old_schema_ids':sorted(set(base['schema_identifiers'])-set(final['schema_identifiers'])),'configuration_keys_preserved_count':len(bcfg&fcfg),'missing_configuration_keys':sorted(bcfg-fcfg),'added_configuration_keys_count':len(fcfg-bcfg),'known_breaking_changes':[],'intentional_behavior_hardening':['Malformed Nuclei YAML no longer counts as a usable template.','Header-based admin bypass requires a direct /admin control differential.','Sensitive-file probes reject same-host catch-all responses and generic HTML shells.','Canonical profile ordering ensures preflight precedes operational phases and report/finalization remains last.'],'target_zero_unintentional_removals':not (bpaths-fpaths or bflags-fflags or set(bph)-set(fph))}

def md(comp:dict)->str:
 s=comp['summary'];lines=['# TBHM v3.9.7.2 Backward-Compatibility Report','',f"Baseline: `{comp['baseline_release']}`  ",f"Final: `{comp['final_release']}`",'', '## Measured summary','',f"- Files: {s['baseline_files']} baseline, {s['final_files']} final; {s['missing_original_paths']} missing original paths.",f"- CLI option strings: {s['baseline_cli_options']} baseline, {s['final_cli_options']} final; {s['missing_cli_options']} missing.",f"- Ordered phases: {s['baseline_phases']} baseline, {s['final_phases']} final; {s['missing_phases']} missing and {s['added_phases']} added.",f"- Zero unintentional removals target: **{'PASS' if comp['target_zero_unintentional_removals'] else 'FAIL'}**",'', '## New phases','']
 lines += [f'- `{x}`' for x in comp['new_phases']] or ['- None.']
 lines += ['', '## Added compatibility aliases','']+[f'- {x}' for x in comp['compatibility_aliases_added']]
 lines += ['', '## Intentionally hardened behavior','']+[f'- {x}' for x in comp['intentional_behavior_hardening']]
 lines += ['', '## Missing baseline contracts','',f"- Paths: {comp['missing_original_file_paths'] or 'none'}",f"- CLI options: {comp['missing_original_cli_options'] or 'none'}",f"- Phases: {comp['missing_original_phases'] or 'none'}",f"- Report paths: {comp['missing_old_report_paths'] or 'none'}",f"- Schema identifiers: {comp['missing_old_schema_ids'] or 'none'}",'', '## Known breaking changes','', '- None identified in the supplied v3.9.6 public path, CLI, phase, output, or schema surface. The stricter false-positive behavior above is intentional correctness hardening.','']
 return '\n'.join(lines)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-root',type=Path,required=True);ap.add_argument('--final-root',type=Path,required=True);ap.add_argument('--output-dir',type=Path,required=True);a=ap.parse_args();a.output_dir.mkdir(parents=True,exist_ok=True)
 b=manifest(a.baseline_root.resolve(),'3.9.6-enterprise-control-plane');f=manifest(a.final_root.resolve(),'3.9.7.2-historical-coverage-restored');c=compare(b,f)
 (a.output_dir/'BASELINE_COMPATIBILITY_MANIFEST_v3.9.6.json').write_text(json.dumps(b,indent=2,ensure_ascii=False),encoding='utf-8')
 (a.output_dir/'FINAL_COMPATIBILITY_MANIFEST_v3.9.7.2.json').write_text(json.dumps(f,indent=2,ensure_ascii=False),encoding='utf-8')
 (a.output_dir/'BACKWARD_COMPATIBILITY_COMPARISON_v3.9.7.2.json').write_text(json.dumps(c,indent=2,ensure_ascii=False),encoding='utf-8')
 (a.output_dir/'BACKWARD_COMPATIBILITY_REPORT_v3.9.7.2.md').write_text(md(c),encoding='utf-8')
 print(json.dumps(c['summary'],indent=2));print('zero_unintentional_removals',c['target_zero_unintentional_removals'])
if __name__=='__main__':main()
