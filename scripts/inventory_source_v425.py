#!/usr/bin/env python3
"""Whole-tree structural inventory; deliberately not a universal semantic audit."""
import argparse,ast,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
WRITE={'write_text','write_bytes','writerow','writerows','dump','dumps','to_csv','save','savefig','execute','executemany','executescript','open'}
NET={'get','post','put','delete','request','send','connect','urlopen','Popen','run','run_lines','new_context','goto','getaddrinfo'}
def inventory():
 rows=[]
 for p in sorted(ROOT.rglob('*.py')):
  rel=p.relative_to(ROOT)
  if any(part in {'.venv','.git','__pycache__'} for part in rel.parts):continue
  tree=ast.parse(p.read_text());writes=[];network=[]
  for n in ast.walk(tree):
   if not isinstance(n,ast.Call):continue
   name=ast.unparse(n.func)
   if name.rsplit('.',1)[-1] in WRITE:writes.append({'line':n.lineno,'call':name})
   if name.rsplit('.',1)[-1] in NET:network.append({'line':n.lineno,'call':name})
  rows.append({'path':rel.as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
    'functions':sum(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) for n in ast.walk(tree)),
    'writer_candidates':writes,'network_or_execution_candidates':network})
 return {'schema':'tbhm.source-inventory/1','python_files':len(rows),'files':rows,
  'scope':'Every packaged Python source parsed. Call-name candidates include false positives; dynamic/native writers and callbacks require semantic review. Inventory is not proof of privacy/containment closure.',
  'all_sensitive_writers_reviewed':False}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();r=inventory();a.output.write_text(json.dumps(r,indent=2)+'\n');print('Inventoried',r['python_files'],'Python files')
