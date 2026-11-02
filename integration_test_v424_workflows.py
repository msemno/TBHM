import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from fixtures_v424 import Fixture
from core.evidence_manifest import verify_manifest
from core.storage import Storage

class Workflows(unittest.TestCase):
    def fixture(self,td):f=Fixture(td);self.addCleanup(f.close);return f
    def invoke(self,f,*extra):
        out=f.root/'cli';policy=f.root/'policy.json';policy.write_text(json.dumps(f.ctx.program_policy));env=dict(os.environ,**f.env())
        p=subprocess.run([sys.executable,str(ROOT/'tbhm.py'),'-u',f.url,'--strict-replay-plan',str(f.path),
            '--program-policy',str(policy),'-o',str(out),'-y','--silent','--no-ai-observe','--no-bootstrap',*extra],cwd=ROOT,env=env,capture_output=True,text=True,timeout=40)
        return p,out
    def test_live_pinned_proofs_persist_restore_report_graph_and_seal(self):
        with tempfile.TemporaryDirectory() as td:
            f=self.fixture(td);f.plan['cases']=[f.case('path_traversal'),f.case('bfla')];f.path.write_text(json.dumps(f.plan))
            p,out=self.invoke(f,'--approve-strict-replay');self.assertEqual(p.returncode,0,p.stdout[-2500:]+p.stderr[-1500:])
            report=json.loads((out/'evidence/strict_replay/results.json').read_text());self.assertEqual([r['result'] for r in report['cases']],['pass','pass'])
            db=Storage(out/'tbhm.db')
            try:rows=db.all_findings();self.assertEqual(sum(r['finding_class']=='confirmed' for r in rows),2)
            finally:db.close()
            self.assertTrue(verify_manifest(out)['passed']);self.assertTrue((out/'REPORT_confirmed.md').is_file())
            graph=json.loads((out/'evidence_graph.json').read_text());self.assertEqual(sum(n.get('proof_verified',False) for n in graph['nodes']),2)
            self.assertTrue(any(n['kind']=='evidence' for n in graph['relationship_nodes']))
    def test_missing_approval_and_offline_make_no_target_contact(self):
        for extra in ((),('--approve-strict-replay','--offline')):
            with tempfile.TemporaryDirectory() as td:
                f=self.fixture(td);f.plan['cases']=[f.case('path_traversal')];f.path.write_text(json.dumps(f.plan))
                p,out=self.invoke(f,*extra);self.assertEqual(p.returncode,2,p.stdout[-1000:]+p.stderr[-1000:]);self.assertEqual(f.hits,[])

if __name__=='__main__':unittest.main(verbosity=2)
