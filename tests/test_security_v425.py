import json,sys,tempfile,unittest,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.package_verifier import verify_tree,verify_zip
from core.ai_plane.advisor import Advisor
from core.research_input import load
class Security(unittest.TestCase):
 def test_installable_release_requires_manifest_but_generic_zip_remains_supported(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);self.assertFalse(verify_tree(root,compile_python=False,require_manifest=True)['passed'])
   (root/'RELEASE_MANIFEST-v4.2.5.json').write_text('{}');self.assertFalse(verify_tree(root,compile_python=False)['passed'])
   z=root/'generic.zip'
   with zipfile.ZipFile(z,'w') as f:f.writestr('clean.txt','clean generic import')
   self.assertTrue(verify_zip(z)['passed'])
 def test_legacy_retrieval_omits_private_run_and_imported_text(self):
  class Index:
   def search(self,*a,**kw):return [{'trust_level':'T3','text':'PRIVATE_MARKER','source_path':'runs/private','kind':'run_artifact'},
     {'trust_level':'T1','text':'source guidance','source_path':'core/example.py','kind':'function'}]
  block=Advisor(None,(None,None,Index()))._context_block('query')
  self.assertNotIn('PRIVATE_MARKER',block);self.assertIn('UNTRUSTED DATA',block);self.assertIn('source guidance',block)
 def test_bounded_learning_input_rejects_symlinks_corrupt_and_oversize(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);p=root/'a.json';p.write_text('{"a":1,"a":2}')
   with self.assertRaises(ValueError):load(p)
   p.write_text('{}');q=root/'link.json';q.symlink_to(p)
   with self.assertRaises(ValueError):load(q)
   p.write_text('x'*100)
   with self.assertRaises(ValueError):load(p,10)
if __name__=='__main__':unittest.main(verbosity=2)
