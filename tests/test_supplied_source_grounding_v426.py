"""Source attachment and model-advice gates; no real model quality claim."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

CODE_HOME = Path(os.environ.get('TBHM_TEST_CODE_HOME', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(CODE_HOME))
from core import llm_review as review
from core.ai_plane.home import AIHome
from core.ai_plane.observer import RunObserver
from core.ai_plane.proposals import Audit
from core.ai_plane.store import Store
from core.storage import Storage

DEMO = 'import os\nfrom flask import request\n\ndef demo():\n    value = request.args["value"]\n    os.system("echo " + value)\n'
DEMO_SHA = '9341d01a859d156eba5f5a065dd11528f970109bb309f2d4bb248cd981264162'


class SourceGroundingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.root = self.work/'src'
        self.root.mkdir()
        self.path = self.root/'demo.py'
        self.path.write_text(DEMO)
        self.finding = {'id': 2, 'phase': 'code_intel', 'target': 'src/demo.py',
                        'line': None, 'evidence': 'src/demo.py:6  os.system("echo " + value) | request.args'}

    def references(self, finding=None):
        return review.context_for(finding or self.finding, self.root, budget=2600)

    def response(self, **changes):
        value = {'finding_id': 2, 'verdict': 'counterevidence_observed',
                 'evidence_ids': ['E1'], 'rationale': 'The code at line 6 is commented out.',
                 'missing_evidence': 'Runtime environment is not supplied.'}
        return {**value, **changes}

    def test_actual_legacy_target_attaches_exact_file_hash_and_line(self):
        refs = self.references()
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), DEMO_SHA)
        self.assertEqual([r['id'] for r in refs], ['E1','S1'])
        source = refs[1]
        self.assertEqual(source['sha256'], DEMO_SHA)
        self.assertEqual(source['file'], 'demo.py')
        self.assertEqual(source['line'], 6)
        self.assertEqual(source['reported_line_kind'], 'python_code')
        self.assertEqual(source['runtime_reachability'], 'unverified')
        self.assertIn('6:     os.system("echo " + value)', source['text'])

    def test_evidence_location_only_and_absolute_in_root_are_supported(self):
        for finding in ({'evidence': self.finding['evidence']},
                        {'target': str(self.path), 'line': 6},
                        {'file': 'demo.py', 'line': 6},
                        {'source_file': 'demo.py', 'line': 6}):
            with self.subTest(finding=finding):
                self.assertEqual(len(self.references(finding)), 2)

    def test_ambiguous_legacy_prefix_is_not_guessed(self):
        (self.root/'src').mkdir()
        (self.root/'src/demo.py').write_text('# different file\n')
        self.assertEqual(len(self.references()), 1)
        explicit = self.references({'file':'src/demo.py','line':1})
        self.assertEqual(explicit[1]['file'], 'src/demo.py')

    def test_traversal_and_outside_absolute_paths_are_not_read(self):
        outside = self.work/'outside.py'
        outside.write_text('PRIVATE_OUTSIDE_DATA')
        for target in ('../outside.py', str(outside), 'https://example.invalid/demo.py'):
            refs = self.references({'phase':'code_intel','target':target})
            self.assertEqual(len(refs), 1)
            self.assertNotIn('PRIVATE_OUTSIDE_DATA', json.dumps(refs))

    def test_source_links_and_linked_directories_are_not_followed(self):
        (self.root/'link.py').symlink_to(self.path)
        outside = self.work/'outside';outside.mkdir();(outside/'demo.py').write_text('PRIVATE')
        (self.root/'linked').symlink_to(outside,target_is_directory=True)
        for target in ('link.py','linked/demo.py'):
            self.assertEqual(len(self.references({'file':target})),1)

    def test_descriptor_walk_rejects_directory_swap_after_resolution(self):
        folder=self.root/'nested';folder.mkdir();(folder/'demo.py').write_text(DEMO)
        chosen=review._resolve_source(self.root,'nested/demo.py')
        folder.rename(self.root/'retained')
        outside=self.work/'outside';outside.mkdir();(outside/'demo.py').write_text('PRIVATE')
        folder.symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):
            review._read_source_bytes(self.root,chosen)

    def test_descriptor_read_rejects_fifo_without_blocking(self):
        self.path.unlink();os.mkfifo(self.path)
        with self.assertRaises(OSError):
            review._read_source_bytes(self.root,self.path)

    def test_line_facts_distinguish_comment_code_literal_and_syntax_error(self):
        cases = [(DEMO,6,'python_code'),
                 (DEMO.replace('    os.system','    # os.system'),6,'comment_only'),
                 ('x = """first\n# not a Python comment\nlast"""\n',2,'string_literal'),
                 ('def broken(\n',1,'unparsed')]
        for text,line,kind in cases:
            self.assertEqual(review._python_line_kind(text,line),kind)

    def test_missing_source_schema_forbids_counterevidence_for_source_case(self):
        refs=review.context_for(self.finding,None)
        schema=review.response_schema(2,refs)
        self.assertNotIn('counterevidence_observed',schema['properties']['verdict']['enum'])
        self.assertIn('source_quotes',schema['required'])

    def test_exact_old_bad_response_becomes_unresolved_and_retains_model_text(self):
        result=review.validate_response(self.response(),2,self.references())
        self.assertEqual(result['verdict'],'unresolved')
        self.assertEqual(result['model_verdict'],'counterevidence_observed')
        self.assertIn('commented out',result['model_rationale'])
        self.assertIn('source_counterevidence_requires_exact_source_quote',result['review_warnings'])
        self.assertFalse(result['reasoning_independently_validated'])
        self.assertTrue(result['finding_unchanged'])

    def test_quote_does_not_rescue_comment_claim_contradicting_python_tokens(self):
        quote='6:     os.system("echo " + value)'
        response=self.response(evidence_ids=['S1'],source_quotes=[{'evidence_id':'S1','quote':quote}])
        result=review.validate_response(response,2,self.references())
        self.assertEqual(result['verdict'],'unresolved')
        self.assertIn('comment_claim_conflicts_with_python_source_tokens',result['review_warnings'])

    def test_genuine_comment_quote_remains_non_authoritative_counterevidence(self):
        self.path.write_text(DEMO.replace('    os.system','    # os.system'))
        response=self.response(evidence_ids=['S1'],source_quotes=[
            {'evidence_id':'S1','quote':'6:     # os.system("echo " + value)'}])
        result=review.validate_response(response,2,self.references())
        self.assertEqual(result['verdict'],'counterevidence_observed')
        self.assertFalse(result['reasoning_independently_validated'])
        self.assertTrue(result['non_authoritative'])

    def test_negated_comment_claim_is_not_reversed_by_narrow_guard(self):
        response=self.response(evidence_ids=['S1'],rationale='The call is not commented out; review another control.',
                              source_quotes=[{'evidence_id':'S1','quote':'os.system("echo " + value)'}])
        result=review.validate_response(response,2,self.references())
        self.assertNotIn('comment_claim_conflicts_with_python_source_tokens',result['review_warnings'])

    def test_invented_source_quote_is_not_accepted(self):
        response=self.response(evidence_ids=['S1'],source_quotes=[{'evidence_id':'S1','quote':'# this is imaginary'}])
        result=review.validate_response(response,2,self.references())
        self.assertEqual(result['verdict'],'unresolved')
        self.assertIn('source_quote_not_in_supplied_source',result['review_warnings'])

    def test_non_source_legacy_client_contract_is_preserved(self):
        refs=[{'id':'E1','kind':'scanner_evidence','text':'captured HTTP control'}]
        result=review.validate_response(self.response(rationale='Review captured HTTP control.'),2,refs)
        self.assertEqual(result['verdict'],'counterevidence_observed')
        self.assertEqual(result['review_warnings'],[])

    def test_refutation_replay_does_not_mutate_stored_finding_proof_or_severity(self):
        storage=Storage(self.work/'run.sqlite3');self.addCleanup(storage.close)
        finding={**self.finding,'severity':'LOW','confidence':'HIGH',
                 'title':'Static command injection observation','finding_class':'supported',
                 'discovered_at':'fixture','cwe':'CWE-78'}
        fid=storage.save_finding(finding)
        before=storage.all_findings()[0]
        ctx=SimpleNamespace(args=SimpleNamespace(code_dir=str(self.root),llm_refute_max_findings=3),storage=storage)
        calls=[]
        def chat(system,payload,schema):
            request=json.loads(payload);calls.append(request)
            return self.response(finding_id=fid)
        result=review.run_refutation(ctx,SimpleNamespace(chat_json_schema=chat),
                                    storage.all_findings(),self.work,'fixture-model',2048)
        after=storage.all_findings()[0]
        for key in ('id','severity','confidence','finding_class','cwe','evidence','target'):
            self.assertEqual(before[key],after[key])
        self.assertEqual([r['id'] for r in calls[0]['references']],['E1','S1'])
        self.assertEqual(result['errors'],[])
        self.assertEqual(result['results'][0]['verdict'],'unresolved')
        self.assertTrue(ctx._llm_review_quality_warnings)

    def test_grounding_warnings_persist_only_as_unreviewed_candidates(self):
        home=AIHome(self.work/'ai').ensure();store=Store(home.db_path);self.addCleanup(store.close)
        audit=Audit(store,home)
        observer=RunObserver(store=store,embedder=None,vector_index=None,advisor=None,
                             proposal_gate=None,audit=audit,runtime=None)
        observer.run_id=store.start_run(run_uid=observer.run_uid,tbhm_version='4.2.5',
                                        profile='passive_only',intensity='standard',target_count=0)
        ctx=SimpleNamespace(storage=SimpleNamespace(all_findings=lambda:[]),
                            _llm_review_quality_warnings=[
                                {'finding_id':1,'codes':['source_counterevidence_requires_exact_source_quote']},
                                {'finding_id':2,'codes':['source_counterevidence_requires_exact_source_quote','untrusted arbitrary text']}])
        observer._record_run_mistakes(ctx)
        rows=store.query('SELECT kind,pattern FROM mistake_ledger')
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['kind'],'model_grounding')
        candidates=store.query('SELECT status,evidence_count,confidence FROM lesson_candidates')
        self.assertEqual(len(candidates),1)
        self.assertEqual(candidates[0]['status'],'candidate')
        self.assertEqual(candidates[0]['evidence_count'],2)
        self.assertIsNone(candidates[0]['confidence'])
        self.assertEqual(store.counts()['approved_lessons'],0)
        self.assertTrue(audit.verify_chain()[0])

    def test_independent_local_shell_marker_and_argument_vector_control(self):
        self.assertEqual(hashlib.sha256(DEMO.encode()).hexdigest(),DEMO_SHA)
        function=next(n for n in ast.parse(DEMO).body if isinstance(n,ast.FunctionDef))
        captured=[]
        value='TBHM_BASE; printf TBHM_MARKER'
        namespace={'os':SimpleNamespace(system=lambda command:captured.append(command) or 0),
                   'request':SimpleNamespace(args={'value':value})}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'owned-demo.py','exec'),namespace)
        namespace['demo']()
        self.assertEqual(captured,['echo '+value])
        positive=subprocess.run(['/bin/sh','-c',captured[0]],capture_output=True,text=True,
                                timeout=3,check=True,env={'PATH':'/usr/bin:/bin'})
        negative=subprocess.run(['/usr/bin/printf','%s\n',value],capture_output=True,text=True,
                                timeout=3,check=True,env={'PATH':'/usr/bin:/bin'})
        self.assertEqual(positive.stdout.splitlines(),['TBHM_BASE','TBHM_MARKER'])
        self.assertEqual(negative.stdout.splitlines(),[value])


if __name__ == '__main__':
    unittest.main(verbosity=2)
