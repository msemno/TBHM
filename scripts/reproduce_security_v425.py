#!/usr/bin/env python3
"""Harmless probes: imported retrieval trust, proposal traversal, missing manifests."""
import argparse,json,subprocess,sys
from pathlib import Path
PROBE=r'''
import json,tempfile
from pathlib import Path
from types import SimpleNamespace
from core.ai_plane.advisor import Advisor
from core.ai_plane.proposals import ProposalGate
from core.package_verifier import verify_tree
class Index:
 def search(self,*a,**kw):return [{'text':'PRIVATE_OTHER_PROJECT_CASE', 'trust_level':'T3','kind':'run_artifact','source_path':'runs/other/private.json'}]
a=Advisor(None,(None,None,Index()))
context=a._context_block('query')
class Client:
 def chat_json(self,system,user):self.user=user;return {}
client=Client();Advisor(client).plan_next_steps({},[],{'approved_lessons':['PRIVATE_OTHER_PROJECT_HISTORY']})
with tempfile.TemporaryDirectory() as td:
 root=Path(td);pending=root/'pending';pending.mkdir();outside=root/'outside';outside.mkdir()
 home=SimpleNamespace(proposals_pending=pending,proposals_accepted=root/'accepted',proposals_rejected=root/'rejected')
 gate=ProposalGate(SimpleNamespace(set_proposal_status=lambda *a:None),home,SimpleNamespace(record=lambda *a:None))
 try:r=gate.decide('../outside',True);traversal=r.get('ok',False)
 except (ValueError,OSError):traversal=False
 empty=root/'empty';empty.mkdir()
 result={'unscoped_run_data_in_context':'PRIVATE_OTHER_PROJECT_CASE' in context,
 'unscoped_history_in_context':'PRIVATE_OTHER_PROJECT_HISTORY' in client.user,
 'untrusted_labeled_trusted':'PRIVATE_OTHER_PROJECT_CASE' in context and '(trusted' in context,
 'proposal_parent_traversal_accepted':traversal,
 'missing_manifest_accepted':verify_tree(empty,compile_python=False,**({'require_manifest':True} if 'require_manifest=True' in Path('install.sh').read_text() else {}))['passed']}
 print(json.dumps(result))
'''
def execute(root):
 p=subprocess.run([sys.executable,'-c',PROBE],cwd=root,capture_output=True,text=True,timeout=20)
 if p.returncode:raise RuntimeError(p.stderr)
 return json.loads(p.stdout)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 result=execute(a.source.resolve());a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
