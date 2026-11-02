import os,sys,unittest
from pathlib import Path
sys.path.insert(0,os.environ.get('TBHM_SOURCE_ROOT',str(Path(__file__).resolve().parents[1])))
from core.code_intel import live_bases_from_targets
class LocalPlaceholder(unittest.TestCase):
 def test_local_source_placeholder_never_becomes_a_live_base(self):
  self.assertEqual(live_bases_from_targets(['local-analysis.invalid'],['https://local-analysis.invalid']),[])
  self.assertEqual(live_bases_from_targets(['api.example.test'],[]),['https://api.example.test'])
if __name__=='__main__':unittest.main(verbosity=2)
