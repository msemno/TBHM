import ast
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


class FlowContractTests(unittest.TestCase):
    def test_dispatcher_context_runner_scope_proof_and_storage_are_preserved(self):
        contract=json.loads((ROOT/'knowledge/flow_contract_v422.json').read_text())
        # Operational modules evolve under executable behavior regressions.
        # The historical contract is retained unchanged for all other modules.
        evolving = {'core/runner.py', 'core/storage.py', 'core/http_policy.py'}
        for name,digest in contract['protected_files'].items():
            if name not in evolving:
                self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),digest,name)
        import tbhm
        phases=json.loads((ROOT/'knowledge/phase_cli_contract_v423.json').read_text())['phases']
        self.assertEqual(tbhm.FULL_PHASE_ORDER[:len(phases)], phases)
        tree=ast.parse((ROOT/'tbhm.py').read_text())
        nodes={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for name,digest in contract['controller_functions'].items():
            if name == 'main':
                continue  # Tested through CLI fixtures, SIGINT, reports and resume identity.
            self.assertEqual(hashlib.sha256(ast.dump(nodes[name],include_attributes=False).encode()).hexdigest(),digest,name)

    def test_original_phase_behavior_is_retained_after_opt_in_hook(self):
        contract=json.loads((ROOT/'knowledge/flow_contract_v422.json').read_text())
        count={'phases/controlled_validation_plane.py':2,'phases/ai_llm_tooling.py':2,'phases/engagement_evidence_review.py':1}
        for name,digest in contract['phase_run_functions'].items():
            tree=ast.parse((ROOT/name).read_text())
            node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run')
            for hook in node.body[:count[name]]:self.assertIsInstance(hook,ast.If)
            node.body=node.body[count[name]:]
            self.assertEqual(hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest(),digest,name)

    def parse(self,argv):
        import tbhm
        with patch.object(sys,'argv',['tbhm',*argv]):return tbhm.parse_args()

    def test_new_inputs_choose_only_existing_phases_and_manual_override_wins(self):
        args=self.parse(['--llm-security-input','a.json','--learning-corpus-input','b.json'])
        self.assertEqual(args.domain,'local-analysis.invalid')
        self.assertEqual(args.phases.split(','),['preflight','ai_llm_tooling','report','evidence_finalize'])
        for argv in (['--phases','report','--llm-security-input','a.json'],
                     ['--llm-security-input','a.json','--phases','report','--learning-corpus-input','b.json']):
            self.assertEqual(self.parse(argv).phases,'report')
        args=self.parse(['--llm-security-input','a.json','--brokered-http-plan','b.json'])
        self.assertIsNone(args.domain)
        self.assertIn('controlled_validation_plane',args.phases)
        args=self.parse([])
        self.assertIsNone(args.llm_security_input);self.assertFalse(args.approve_brokered_http)
        self.assertIsNone(args.phases)

    def test_new_capabilities_are_typed_and_off_by_default(self):
        from core.capability_registry import load,by_id,validate_registry
        registry=load();self.assertEqual(validate_registry(registry),[])
        rows=by_id(registry)
        for name in ('transport.brokered_read_replay','llm.security_evidence_import','llm.learning_corpus_hygiene','evidence.delivery_privacy_audit'):
            self.assertFalse(rows[name]['enabled_by_default'])
        self.assertEqual(rows['llm.security_evidence_import']['implementation_state'],'import_only')
        self.assertTrue(rows['transport.brokered_read_replay']['approval_required'])


if __name__ == '__main__':unittest.main(verbosity=2)
