import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from core.evidence_manifest import build_manifest,verify_manifest


class Workflows(unittest.TestCase):
    def command(self,*args,env=None):
        return subprocess.run([sys.executable,str(ROOT/'tbhm.py'),*map(str,args),'--silent','--no-ai-observe','--no-bootstrap'],
            cwd=ROOT,env=env,capture_output=True,text=True,timeout=35)

    def test_combined_llm_import_and_reviewed_cards_reach_sealed_delivery(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/'llm.json';corpus=root/'corpus.json';out=root/'run'
            source.write_text(json.dumps({'schema':'tbhm.llm-security-evidence/1','records':[
                {'id':'sample','producer':'reviewed export','category':'prompt-injection','evaluator_outcome':'fail'}]}))
            text='A reviewed synthetic negative-control example.'
            corpus.write_text(json.dumps({'schema':'tbhm.learning-corpus/1','records':[
                {'id':'sample','project_id':'fixture','root_cause_id':'fixture-root','split':'train','source_url':'https://example.test/fixture',
                 'source_license':'CC0-1.0 fixture','reuse_approved':True,'human_reviewed':True,'contains_sensitive_data':False,
                 'technical_validity':'refuted','program_outcome':'not-applicable','text':text,
                 'reviewed_text_sha256':hashlib.sha256(text.encode()).hexdigest()}]}))
            result=self.command('--offline','--profile','passive_only','--llm-security-input',source,'--llm-security-format','tbhm',
                '--learning-corpus-input',corpus,'--export-retrieval-cards','-o',out)
            self.assertEqual(result.returncode,0,result.stdout[-2500:]+result.stderr[-1000:])
            review=json.loads((out/'evidence/llm_security_review/review.json').read_text())
            self.assertFalse(review['records'][0]['confirmed'])
            self.assertTrue((out/'evidence/learning_corpus_audit/retrieval_cards/sample.md').is_file())
            queue=json.loads((out/'operator_queue.json').read_text())
            self.assertFalse(any(row['proof_verified'] for row in queue['queue']))
            self.assertTrue(verify_manifest(out)['passed'])

    def test_prior_delivery_audit_cli_fails_for_opaque_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);prior=root/'prior';prior.mkdir();out=root/'audit'
            (prior/'pixels.png').write_bytes(b'\x89PNG\r\n\x1a\nopaque pixels')
            build_manifest(prior)
            env=os.environ.copy();env['TBHM_PRIVACY_CANARY']='synthetic-audit-canary-467865'
            result=self.command('--offline','--profile','passive_only','--delivery-audit-input',prior,
                '--privacy-canary-env','TBHM_PRIVACY_CANARY','--require-private-delivery','-o',out,env=env)
            self.assertEqual(result.returncode,2,result.stdout[-2000:]+result.stderr[-1000:])
            report=json.loads((out/'evidence/delivery_privacy_audit/audit.json').read_text())
            self.assertEqual(report['status'],'incomplete')
            self.assertTrue((out/'REPORT_final.html').is_file())
            self.assertTrue(verify_manifest(out)['passed'])

    def test_broker_plan_runs_native_and_real_isolated_worker_via_cli(self):
        spec=importlib.util.spec_from_file_location('broker_fixture',ROOT/'tests/test_brokered_http_v423.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        fixture=module.BrokerTests();fixture.setUp()
        try:
            plan=fixture.root/'plan.json';policy=fixture.root/'policy.json';out=fixture.root/'cli'
            plan.write_text(json.dumps({'schema':'tbhm.brokered-http/1','request_limit':3,'body_limit':128,'max_response_body_bytes':8,
                'requests':[fixture.job('native'),{**fixture.job('child'),'driver':'pipe-v1'}]}))
            policy.write_text(json.dumps(fixture.ctx.program_policy))
            result=self.command('-u',fixture.url,'--brokered-http-plan',plan,'--approve-brokered-http','--program-policy',policy,'-y','-o',out)
            self.assertEqual(result.returncode,0,result.stdout[-2500:]+result.stderr[-1500:])
            report=json.loads((out/'evidence/brokered_http/results.json').read_text())
            self.assertEqual(report['quota']['request_slots_used'],2)
            self.assertEqual(report['worker']['isolation_check'],'network_socket_denied')
            self.assertEqual(fixture.server.hits,['/ok','/ok'])
            self.assertTrue(verify_manifest(out)['passed'])
        finally:fixture.tearDown();fixture.doCleanups()


if __name__ == '__main__':unittest.main(verbosity=2)
