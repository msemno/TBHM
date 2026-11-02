"""Owned loopback CLI workflows, cancellation and durable evidence contracts."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))


class WorkflowTests(unittest.TestCase):
    def retain(self, name, output):
        destination=os.environ.get('TBHM_VALIDATION_OUTPUT')
        if not destination:
            return
        import shutil
        root=Path(destination)/name;root.mkdir(parents=True,exist_ok=True)
        for filename in ('REPORT.json','execution_ledger.json','phase_timings.json','evidence_manifest.json'):
            source=output/filename
            if source.exists():shutil.copy2(source,root/filename)
    def command(self, url, output, phases, *extra):
        return [sys.executable,str(ROOT/'tbhm.py'),'-d',url,'-y','--no-bootstrap',
                '--no-ai-observe','--output',str(output),'--phases',phases,*extra]

    def test_cli_vulnerable_patched_and_public_bola(self):
        from fixtures_v425 import BolaFixture
        from core.evidence_manifest import verify_manifest
        for mode, confirmed in [('vulnerable',1),('secure',0),('public',0)]:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as td:
                f=BolaFixture(td,mode)
                try:
                    f.plan['cases']=[f.case()];f.path.write_text(json.dumps(f.plan))
                    policy=Path(td)/'policy.json';policy.write_text(json.dumps(f.ctx.program_policy))
                    out=Path(td)/'cli-run'
                    env=dict(os.environ,**f.env(),PYTHONDONTWRITEBYTECODE='1')
                    p=subprocess.run(self.command(f.url,out,
                        'preflight,controlled_validation_plane,strict_finding_validation,test_coverage_ledger,report,evidence_finalize',
                        '--strict-replay-plan',str(f.path),'--approve-strict-replay','--program-policy',str(policy)),
                        cwd=ROOT,env=env,capture_output=True,text=True,timeout=45)
                    self.assertEqual(p.returncode,0,p.stdout[-3500:]+p.stderr[-1000:])
                    report=json.loads((out/'REPORT.json').read_text())
                    self.assertEqual(report['summary']['confirmed'],confirmed)
                    self.assertEqual(report['version'],'4.2.7')
                    self.assertTrue(report['source_build_sha256'])
                    self.assertGreater(report['evidence_lifecycle']['validation_attempts'],0)
                    self.assertEqual(len(f.hits),7)
                    ledger=json.loads((out/'execution_ledger.json').read_text())
                    self.assertEqual(ledger['events'][-1]['status'],'completed')
                    self.assertTrue(verify_manifest(out)['passed'])
                    self.retain('cli-bola-'+mode,out)
                finally:f.close()

    def test_sigint_stops_ffuf_without_post_cancel_model_requests(self):
        from core.evidence_manifest import verify_manifest
        class Handler(BaseHTTPRequestHandler):
            hits=0
            def do_GET(self):
                type(self).hits+=1;self.send_response(200);self.end_headers();self.wfile.write(b'{"models":[]}')
            def log_message(self,*unused):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                root=Path(td);bin_dir=root/'bin';bin_dir.mkdir();marker=root/'started'
                ffuf=bin_dir/'ffuf'
                ffuf.write_text('#!'+sys.executable+'\nimport time\nfrom pathlib import Path\n'
                    'Path('+repr(str(marker))+').write_text("started")\ntime.sleep(60)\n');ffuf.chmod(0o700)
                out=root/'run';(out/'recon').mkdir(parents=True)
                (out/'recon/alive.txt').write_text('https://example.test\n')
                env=dict(os.environ,PATH=str(bin_dir)+os.pathsep+os.environ['PATH'],PYTHONDONTWRITEBYTECODE='1')
                cmd=self.command('example.test',out,'preflight,content_discovery,report,evidence_finalize',
                    '--local-llm','--local-llm-url',f'http://127.0.0.1:{server.server_port}')
                proc=subprocess.Popen(cmd,cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    deadline=time.monotonic()+15
                    while not marker.exists() and proc.poll() is None and time.monotonic()<deadline:
                        time.sleep(.02)
                    self.assertTrue(marker.exists(),'ffuf fixture did not start')
                    started=time.monotonic();proc.send_signal(signal.SIGINT)
                    stdout,stderr=proc.communicate(timeout=15)
                    self.assertLess(time.monotonic()-started,8)
                    self.assertEqual(proc.returncode,2,stdout[-2000:]+stderr[-1000:])
                    ledger=json.loads((out/'execution_ledger.json').read_text())
                    jobs=[e for e in ledger['events'] if e['kind']=='tool' and Path(e['argv'][0]).name=='ffuf']
                    self.assertEqual(len(jobs),1)
                    self.assertEqual(jobs[0]['returncode'],130)
                    timing=json.loads((out/'phase_timings.json').read_text())
                    self.assertEqual(timing['per_phase_details']['content_discovery']['state'],'CANCELLED')
                    self.assertTrue((out/'REPORT.json').exists());self.assertTrue(verify_manifest(out)['passed'])
                    self.assertEqual(Handler.hits,0)
                    self.retain('cli-sigint',out)
                finally:
                    if proc.poll() is None:proc.kill();proc.communicate()
        finally:server.shutdown();server.server_close();thread.join(2)

    def test_phase_deadline_cannot_be_swallowed_as_a_probe_error(self):
        from core.runner import Runner
        from core.lifecycle import PhaseStopped
        with tempfile.TemporaryDirectory() as td:
            runner=Runner({},None,NS(wait_if_pressured=lambda **kw:None),Path(td))
            runner._phase_lifecycle_active=True;runner._phase_deadline=time.monotonic()-1
            with self.assertRaises(PhaseStopped) as result:
                runner.run([sys.executable,'-c','raise SystemExit("should not execute")'])
            self.assertEqual(result.exception.state,'TIMED_OUT')

    def test_owned_term_ignoring_child_is_killed_and_unrelated_child_survives(self):
        import psutil
        from core.runner import Runner
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);pid_file=root/'child.pid'
            unrelated=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True)
            child='import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)'
            parent='import subprocess,sys,time;from pathlib import Path;p=subprocess.Popen([sys.executable,"-c",'+repr(child)+']);Path('+repr(str(pid_file))+').write_text(str(p.pid));time.sleep(60)'
            runner=Runner({},None,NS(wait_if_pressured=lambda **kw:None),root)
            timer=threading.Timer(.3,runner.cancel);timer.start()
            try:
                started=time.monotonic();rc,_,_=runner.run([sys.executable,'-c',parent],timeout=10)
                self.assertEqual(rc,130);self.assertLess(time.monotonic()-started,3)
                self.assertIsNone(unrelated.poll())
                if pid_file.exists():
                    pid=int(pid_file.read_text())
                    self.assertTrue(not psutil.pid_exists(pid) or psutil.Process(pid).status()==psutil.STATUS_ZOMBIE)
            finally:timer.cancel();unrelated.terminate();unrelated.wait(3)

    def test_native_inference_records_success_after_target_budget_is_spent(self):
        import requests
        from core.execution_ledger import ExecutionLedger
        from core.request_guard import activate,deactivate
        from core.http_policy import RequestBlocked
        from core.scope import Scope
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Length','13');self.end_headers();self.wfile.write(b'{"models":[]}')
            def log_message(self,*unused):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                ctx=NS(args=NS(local_llm=True,no_ai_observe=False,offline=False,proxy=None,
                    local_llm_url=f'http://127.0.0.1:{server.server_port}'),
                    targets=['example.test'],scope=Scope(['=example.test'],[]),scope_excludes=[],
                    runner=NS(_cancel_event=threading.Event()),execution_ledger=ExecutionLedger(td),
                    profile={'name':'authorized_safe','rate_limit':{'global_rps':20,'per_target_rps':20},
                             'http_policy':{'request_budget':0,'service_request_budget':1}})
                activate(ctx)
                try:
                    s=requests.Session();s.trust_env=False
                    self.assertEqual(s.get(ctx.args.local_llm_url+'/api/tags',timeout=1).status_code,200)
                    with self.assertRaises(RequestBlocked):s.get('https://example.test/',timeout=1)
                    with self.assertRaises(RequestBlocked):s.get(ctx.args.local_llm_url+'/api/tags',timeout=1)
                    self.assertEqual(ctx._http_policy_state['used'],0)
                    self.assertEqual(ctx._service_http_policy_state['used'],1)
                    self.assertTrue(any(e['kind']=='service_http' and e['status']=='executed' for e in ctx.execution_ledger.rows))
                finally:deactivate()
        finally:server.shutdown();server.server_close();thread.join(2)

    def test_gcp_project_is_positional_and_explicit_on_every_command(self):
        from phases.cloud_inventory_safe import run
        with tempfile.TemporaryDirectory() as td:
            ctx=NS(output=Path(td),args=NS(cloud_profiles='gcp',live_inventory=None,gcp_project='owned-project-123'),log=Mock())
            ctx.runner=NS(run=Mock(return_value=(0,'[]','')))
            with patch('phases.cloud_inventory_safe.shutil.which',return_value='/fixture/gcloud'):run(ctx)
            jobs=[call.args[0] for call in ctx.runner.run.call_args_list]
            self.assertEqual(len(jobs),3)
            self.assertTrue(all(job[job.index('--project')+1]=='owned-project-123' for job in jobs))
            self.assertIn(['gcloud','projects','get-iam-policy','owned-project-123','--format=json','--project','owned-project-123','--quiet'],jobs)

    def test_real_httpx_fixture_process_uses_json_and_preserves_partial_metadata(self):
        from core.runner import Runner
        from core.execution_ledger import ExecutionLedger
        from core.scope import Scope
        from phases.recon import _alive_check
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);binary=root/'httpx'
            binary.write_text('#!'+sys.executable+'\nimport sys,json\n'
                'if "-jsonl" in sys.argv:sys.exit(2)\n'
                'if "-json" in sys.argv:\n print(json.dumps({"url":"https://example.test","status_code":200}));print("{broken")\n'
                'else:print("https://example.test")\nprint("fixture banner",file=sys.stderr)\n')
            binary.chmod(0o700)
            ctx=NS(output=root,profile={'rate_limit':{'global_rps':10,'per_target_rps':10}},targets=['example.test'],
                scope=Scope(['=example.test'],[]),scope_excludes=[],threads=2,log=Mock())
            ctx.runner=Runner(ctx.profile,None,NS(wait_if_pressured=lambda **kw:None),root)
            ctx.execution_ledger=ExecutionLedger(root);ctx.runner.execution_ledger=ctx.execution_ledger
            subs=root/'subs.txt';subs.write_text('example.test\n')
            with patch.dict(os.environ,{'PATH':td+os.pathsep+os.environ['PATH']}):
                alive=_alive_check(ctx,subs,root/'alive.txt',root/'tech.json',[])
            self.assertEqual(alive,['https://example.test'])
            self.assertEqual(len(json.loads((root/'tech.json').read_text())),1)
            jobs=[e for e in ctx.execution_ledger.rows if e['kind']=='tool']
            self.assertTrue(any('-json' in e['argv'] for e in jobs))
            self.assertTrue(all(e['executable']['sha256'] for e in jobs))
            self.assertTrue(any(e['status']=='parser-error' for e in ctx.execution_ledger.rows))

    def test_nuclei_timeout_retains_valid_capture_and_records_malformed_output(self):
        from core.runner import Runner
        from core.execution_ledger import ExecutionLedger
        from core.scope import Scope
        from phases.vuln_scan import _nuclei
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);binary=root/'nuclei'
            result={'template-id':'owned-fixture','host':'https://example.test',
                'matched-at':'https://example.test/admin','info':{'name':'fixture match','severity':'high'},
                'request':'GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n',
                'response':'HTTP/1.1 200 OK\r\n\r\nowned fixture'}
            binary.write_text('#!'+sys.executable+'\nimport sys,json\nfrom pathlib import Path\n'
                'p=Path(sys.argv[sys.argv.index("-o")+1]);p.write_text('+repr(json.dumps(result)+'\n{broken\n')+')\nsys.exit(124)\n')
            binary.chmod(0o700);(root/'scans').mkdir();alive=root/'alive.txt';alive.write_text('https://example.test\n')
            ctx=NS(output=root,profile={'active_probes':True,'rate_limit':{'global_rps':2}},
                args=NS(),targets=['example.test'],scope=Scope(['=example.test'],[]),scope_excludes=[],log=Mock(),save_finding=Mock())
            ctx.runner=Runner(ctx.profile,None,NS(wait_if_pressured=lambda **kw:None),root)
            ctx.execution_ledger=ExecutionLedger(root);ctx.runner.execution_ledger=ctx.execution_ledger
            with patch.dict(os.environ,{'PATH':td+os.pathsep+os.environ['PATH']}),patch('phases.vuln_scan.bootstrap.nuclei_templates_root',return_value=root):
                _nuclei(ctx,alive)
            self.assertEqual(ctx.save_finding.call_count,1)
            saved=ctx.save_finding.call_args.args[0]
            self.assertEqual(saved['finding_class'],'supported');self.assertIn('owned fixture',saved['response_raw'])
            self.assertTrue(any(e.get('returncode')==124 for e in ctx.execution_ledger.rows))
            self.assertTrue(any(e['status']=='parser-error' for e in ctx.execution_ledger.rows))

    def test_mandatory_external_containment_fails_before_process_launch(self):
        from core.runner import Runner
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);marker=root/'should-not-exist'
            runner=Runner({'runtime':{'require_external_containment':True}},None,NS(wait_if_pressured=lambda **kw:None),root)
            rc,_,_=runner.run([sys.executable,'-c','from pathlib import Path;Path('+repr(str(marker))+').touch()'])
            self.assertEqual(rc,77);self.assertFalse(marker.exists())


if __name__=='__main__':unittest.main(verbosity=2)
