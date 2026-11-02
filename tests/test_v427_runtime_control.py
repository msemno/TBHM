"""Scheduler policy and real CLI dispatch against a protocol fixture, not a quality benchmark."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace as NS
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.ai_plane.runtime_control import RuntimeController, ready_window, validate_choice
from core import request_guard
import requests


def decision(phase='supply_chain_review'):
    return {'next_phase':phase,'reason':'Review dependency provenance before the next independent check.',
            'evidence_ids':['E0'],'review_notes':['Runtime reachability has not been established.']}


class RuntimeControlTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.calls=[]
        self.ctx=NS(args=NS(ai_control='adaptive',ai_control_max_decisions=3),output=self.root,
            phase_state={},storage=NS(all_findings=lambda:[]),log=lambda *a:None)
        self.client=NS(chat_json_bounded=lambda *a,**k:self.reply(*a,**k),config=NS(model='fixture'))
        self.plane=NS(advisor=NS(client=self.client,_context_block=lambda *a,**k:'',_public_block=lambda *a,**k:''))
        self.answer=decision()

    def reply(self,*a,**kw):
        self.calls.append((a,kw))
        return self.answer

    def test_ready_windows_respect_producer_unknown_and_proof_barriers(self):
        self.assertEqual(ready_window(['code_scan','supply_chain_review']),[])
        self.assertEqual(ready_window(['spec_scan','api_fuzz','strict_finding_validation']),['spec_scan','api_fuzz'])
        self.assertEqual(ready_window(['api_fuzz','surface_correlation','spec_scan']),[])
        self.assertEqual(ready_window(['report','spec_scan']),[])

    def test_decision_writer_rejects_linked_directory(self):
        outside=self.root/'outside';outside.mkdir()
        (self.root/'llm_analysis').symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):RuntimeController(self.ctx,self.plane)
        self.assertFalse(list(outside.iterdir()))

    def test_decision_receipt_is_private_and_atomic(self):
        controller=RuntimeController(self.ctx,self.plane)
        self.assertEqual(controller.path.stat().st_mode & 0o777,0o600)
        self.assertFalse(list(controller.path.parent.glob('*.tmp')))

    def test_valid_choice_changes_priority_without_adding_or_skipping(self):
        pending=['code_security_tooling','supply_chain_review','report']
        controller=RuntimeController(self.ctx,self.plane)
        self.assertEqual(controller.choose(pending),'supply_chain_review')
        self.assertEqual(pending,['code_security_tooling','supply_chain_review','report'])
        receipt=json.loads(controller.path.read_text())
        self.assertTrue(receipt['decisions'][0]['changed_order'])
        self.assertFalse(receipt['confirmation_authority'])
        self.assertIn('UNTRUSTED',self.calls[0][0][1])

    def test_unknown_phase_scope_change_and_bad_citations_fall_back(self):
        for response in (decision('shell'),{**decision(),'scope':'*.outside.invalid'},
                         {**decision(),'evidence_ids':['INVENTED']},
                         {**decision(),'review_notes':{'command':'run'}},
                         {**decision(),'reason':''}):
            self.answer=response
            controller=RuntimeController(self.ctx,self.plane)
            self.assertEqual(controller.choose(['code_security_tooling','supply_chain_review']),'code_security_tooling')
            self.assertEqual(controller.decisions[0]['status'],'fallback')

    def test_observe_default_does_not_contact_model(self):
        self.ctx.args.ai_control='observe'
        self.assertEqual(RuntimeController(self.ctx,self.plane).choose(['code_security_tooling','supply_chain_review']),'code_security_tooling')
        self.assertFalse(self.calls)

    def test_required_model_failure_is_retained_as_run_failure(self):
        self.ctx.args.local_llm_required=True
        self.answer={}
        controller=RuntimeController(self.ctx,self.plane)
        self.assertEqual(controller.choose(['code_security_tooling','supply_chain_review']),'code_security_tooling')
        self.assertTrue(self.ctx.phase_state['local_llm_required_failed'])

    def test_decision_budget_and_failure_budget_are_finite(self):
        self.ctx.args.ai_control_max_decisions=1
        controller=RuntimeController(self.ctx,self.plane)
        for _ in range(5):controller.choose(['code_security_tooling','supply_chain_review'])
        self.assertEqual(len(self.calls),1)
        self.ctx.args.ai_control_max_decisions=8;self.answer={}
        controller=RuntimeController(self.ctx,self.plane)
        for _ in range(5):controller.choose(['code_security_tooling','supply_chain_review'])
        self.assertEqual(len(controller.decisions),2)

    def test_no_reuse_permission_does_not_retrieve_private_scenarios(self):
        p=self.root/'permission.json';p.write_text(json.dumps({'schema':'tbhm.run-learning-permission/1',
            'project_id':'fixture','reuse_approved':False}))
        self.ctx.args.ai_scenario_context=str(p)
        with patch('core.ai_plane.scenarios.ScenarioMemory.context',side_effect=AssertionError('private retrieval')):
            controller=RuntimeController(self.ctx,self.plane)
            self.assertEqual(controller.choose(['code_security_tooling','supply_chain_review']),'supply_chain_review')
        self.assertFalse(controller.decisions[0]['retrieval']['reviewed_scenarios'])

    def test_guard_honors_explicit_model_timeout_and_keeps_target_cap(self):
        ctx=NS(args=NS(local_llm=True,local_llm_url='http://127.0.0.1:11435',local_llm_timeout=120,proxy=None),
               profile={'runtime':{'service_timeout_seconds':15}})
        timeouts=[]
        def transport(session,prepared,**kw):
            timeouts.append(kw['timeout']);response=requests.Response();response.status_code=200
            response._content=b'{}';response._content_consumed=True;return response
        with patch.object(request_guard,'_SEND',side_effect=transport):
            for url in ('http://127.0.0.1:11435/api/chat','https://owned.invalid/'):
                prepared=requests.Request('GET',url).prepare()
                request_guard._bounded_send(ctx,requests.Session(),prepared,{'timeout':120})
        self.assertEqual(timeouts,[120,30])

    def test_service_circuit_separates_generation_embeddings_and_targets(self):
        hits=[];events=[]
        ctx=NS(args=NS(local_llm_url='http://127.0.0.1:11435',local_llm=True,no_ai_observe=False,
            offline=False,proxy=None,local_llm_timeout=120),profile={'name':'authorized_safe'},
            execution_ledger=NS(current_phase='local_llm_triage',record=lambda **kw:events.append(kw)))
        def dead(session,prepared,**kw):
            hits.append(prepared.url)
            if prepared.url.endswith('/api/chat'):raise requests.ReadTimeout('fixture inference timeout')
            response=requests.Response();response.status_code=200;response._content=b'{}';response._content_consumed=True;return response
        try:
            with patch.object(request_guard,'_SEND',side_effect=dead):
                request_guard.activate(ctx)
                for _ in range(6):
                    with self.assertRaises(Exception):requests.post('http://127.0.0.1:11435/api/chat',timeout=1)
                requests.post('http://127.0.0.1:11435/api/embeddings',timeout=1)
                requests.get('http://127.0.0.1:11435/api/tags',timeout=1)
            self.assertEqual(sum(u.endswith('/api/chat') for u in hits),3)
            self.assertTrue(any('circuit open' in e.get('reason','') for e in events))
            self.assertTrue(any(u.endswith('/api/embeddings') for u in hits))
        finally:request_guard.deactivate()

    def test_real_cli_dispatch_is_changed_and_sealed(self):
        calls=[]
        class Handler(BaseHTTPRequestHandler):
            def send(self,value):
                body=json.dumps(value).encode();self.send_response(200)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
                self.end_headers();self.wfile.write(body)
            def do_GET(self):self.send({'models':[{'name':'fixture-model'}]})
            def do_POST(self):
                payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if self.path in ('/api/embeddings','/api/embed'):
                    self.send({'embedding':[1.0,0.0,0.0]});return
                schema=payload.get('format',{})
                properties=schema.get('properties',{}) if isinstance(schema,dict) else {}
                if 'next_phase' in properties:
                    choice=properties['next_phase']['enum'][-1];answer=decision(choice)
                    calls.append(choice)
                elif 'situation' in properties:
                    answer={'situation':'Protocol fixture only','prioritized_targets':[],'recommended_next_phases':[],
                            'skip_phases':[],'avoid_repeating':[],'operator_decision_required':''}
                else:
                    answer={'overall_summary':'Protocol fixture only','risk_narrative':'Unverified',
                            'correlations':[],'verify_next':[],'coverage_gaps':[]}
                self.send({'message':{'content':json.dumps(answer)},'done':True})
            def log_message(self,*a):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            src=self.root/'src';src.mkdir();(src/'package.json').write_text('{"name":"fixture","version":"1.0.0"}')
            results=self.root/'results.json';results.write_text('{}')
            out=self.root/'run';ai=self.root/'ai'
            phases='preflight,code_security_tooling,supply_chain_review,ci_cd_supply_chain_security,report,evidence_finalize'
            cmd=[sys.executable,str(ROOT/'tbhm.py'),'--code-dir',str(src),'--profile','passive_only','--no-bootstrap',
                 '--phases',phases,'--ai-control','adaptive','--ai-control-max-decisions','2',
                 '--local-llm-url',f'http://127.0.0.1:{server.server_port}','--local-llm-model','fixture-model',
                 '--ai-home',str(ai),'--code-security-results',str(results),'-o',str(out)]
            process=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=45,
                env={**os.environ,'TBHM_AI_HOME':str(ai),'PYTHONDONTWRITEBYTECODE':'1'})
            self.assertEqual(process.returncode,0,process.stdout[-5000:]+process.stderr[-1500:])
            receipt=json.loads((out/'llm_analysis/runtime_decisions.json').read_text())
            self.assertEqual(receipt['executed_order'][:3],['ci_cd_supply_chain_security','supply_chain_review','code_security_tooling'])
            self.assertEqual(len(calls),2)
            from core.evidence_manifest import verify_manifest
            self.assertTrue(verify_manifest(out)['passed'])
            ledger=json.loads((out/'execution_ledger.json').read_text())
            executed=[e['phase'] for e in ledger['events'] if e.get('kind')=='phase' and e.get('status')=='executed']
            self.assertEqual(executed[:3],receipt['executed_order'][:3])
            self.assertEqual(set(executed),set(phases.split(','))-{'preflight','evidence_finalize'})
            if os.environ.get('TBHM_VALIDATION_OUTPUT'):
                import shutil
                dest=Path(os.environ['TBHM_VALIDATION_OUTPUT'])/'runtime-control-cli';dest.mkdir(parents=True,exist_ok=True)
                for name in ('execution_ledger.json','evidence_manifest.json','REPORT.json','llm_analysis/runtime_decisions.json'):
                    target=dest/Path(name).name;shutil.copy2(out/name,target)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=='__main__':unittest.main()
