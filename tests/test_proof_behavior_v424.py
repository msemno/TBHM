import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

class LegacyProofBehavior(unittest.TestCase):
    def test_all_three_original_contracts_match_executed_baseline_vectors(self):
        expected=json.loads((ROOT/'knowledge/proof_behavior_v423.json').read_text())
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'current.json';p=subprocess.run([sys.executable,str(ROOT/'scripts/proof_vectors_v424.py'),'--source',str(ROOT),'--output',str(path)],capture_output=True,text=True,timeout=20)
            self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(path.read_text()),expected)
    def test_proof_files_are_not_in_old_hash_freeze(self):
        contract=json.loads((ROOT/'knowledge/flow_contract_v422.json').read_text())
        for path in ('core/proof_contracts.py','core/assertion_engine.py','core/finding_class.py'):self.assertNotIn(path,contract['protected_files'])

if __name__=='__main__':unittest.main(verbosity=2)
