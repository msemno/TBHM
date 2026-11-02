import hashlib
import importlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))

class Compatibility(unittest.TestCase):
    def test_original_phase_prefix_ordinals_and_every_dispatch_resolves(self):
        import tbhm
        contract=json.loads((ROOT/'knowledge/phase_cli_contract_v423.json').read_text())
        self.assertEqual(tbhm.FULL_PHASE_ORDER[:len(contract['phases'])],contract['phases'])
        for phase in tbhm.FULL_PHASE_ORDER:
            if phase=='preflight':continue
            self.assertTrue(callable(importlib.import_module('phases.'+phase).run),phase)
    def test_old_cli_signatures_and_sqlite_semantics_are_retained(self):
        from scripts.compare_release_contracts import probe
        from core.storage import SCHEMA
        old=json.loads((ROOT/'knowledge/phase_cli_contract_v423.json').read_text());new=probe(ROOT)
        for name,value in old['actions'].items():self.assertEqual(new['actions'][name],value,name)
        self.assertEqual(hashlib.sha256(SCHEMA.encode()).hexdigest(),old['sqlite_schema_sha256'])
    def test_real_v423_database_rows_and_evidence_ids_survive_open(self):
        from core.storage import Storage
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'tbhm.db';shutil.copyfile(ROOT/'tests/data/v423-run.sqlite3',path)
            store=Storage(path)
            try:
                rows=store.all_findings();self.assertEqual(len(rows),1);self.assertEqual(rows[0]['id'],1)
                self.assertEqual(rows[0]['url'],'https://fixture.example.test/legacy');self.assertEqual(rows[0]['evidence'],'legacy-evidence-reference-423')
                self.assertEqual(store.conn.execute('SELECT profile FROM runs WHERE id=1').fetchone()[0],'legacy-4.2.3')
            finally:store.close()
    def test_new_plan_routing_remains_opt_in_and_manual_override_wins(self):
        from unittest.mock import patch
        import tbhm
        with patch.object(sys,'argv',['tbhm','--strict-replay-plan','plan.json']):
            args=tbhm.parse_args();self.assertIsNone(args.domain);self.assertFalse(args.approve_strict_replay)
            self.assertEqual(args.phases.split(','),['preflight','controlled_validation_plane','report','evidence_finalize'])
        with patch.object(sys,'argv',['tbhm','--phases','report','--strict-replay-plan','plan.json']):self.assertEqual(tbhm.parse_args().phases,'report')
    def test_disabled_new_options_preserve_legacy_resume_identity(self):
        from types import SimpleNamespace
        from core.execution_ledger import input_fingerprint
        old=SimpleNamespace(domain='example.test',resume=True)
        current=SimpleNamespace(domain='example.test',resume=True,strict_replay_plan=None,approve_strict_replay=False)
        profile={'name':'test'};targets=['https://example.test']
        self.assertEqual(input_fingerprint(old,profile,targets),input_fingerprint(current,profile,targets))
        current.strict_replay_plan='reviewed-plan.json';current.approve_strict_replay=True
        self.assertNotEqual(input_fingerprint(old,profile,targets),input_fingerprint(current,profile,targets))

if __name__=='__main__':unittest.main(verbosity=2)
