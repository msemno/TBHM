"""Behavior regressions: run unchanged against baseline and corrected source.

TBHM_SOURCE_ROOT selects an external source tree for the red/green comparison.
All HTTP and scanner inputs are owned local fixtures or in-memory transports.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

ROOT = Path(os.environ.get('TBHM_SOURCE_ROOT', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT))


def context(root):
    from core.scope import Scope
    return NS(output=Path(root), targets=['example.test'], scope=Scope(['=example.test'], []),
              scope_excludes=[], args=NS(local_llm=True, local_llm_url='http://127.0.0.1:11435',
                  no_ai_observe=False, offline=False, allow_external_enrichment=False),
              profile={'name':'authorized_safe', 'active_probes':True,
                  'http_policy':{'request_budget':1, 'service_request_budget':4},
                  'rate_limit':{'global_rps':50, 'per_target_rps':20}},
              log=Mock(), save_finding=Mock(), storage=Mock())


class IncidentRegressions(unittest.TestCase):
    def test_service_budget_survives_target_exhaustion(self):
        from core.http_policy import BudgetedSession
        with tempfile.TemporaryDirectory() as td:
            ctx=context(td)
            transport=NS(_tbhm_service=True, headers={}, request=Mock(return_value=NS(status_code=200)))
            session=BudgetedSession(ctx,transport,budget=8,max_rps=50)
            ctx._http_policy_state['used']=ctx._http_policy_state['budget']
            self.assertEqual(session.request('GET','http://127.0.0.1:11435/api/tags').status_code,200)
            self.assertEqual(ctx._http_policy_state['used'],1)

    def test_service_budget_does_not_consume_target_budget(self):
        from core.http_policy import BudgetedSession
        with tempfile.TemporaryDirectory() as td:
            ctx=context(td)
            transport=NS(_tbhm_service=True, headers={}, request=Mock(return_value=NS(status_code=200)))
            BudgetedSession(ctx,transport,budget=8,max_rps=50).request('GET','http://127.0.0.1:11435/api/tags')
            self.assertEqual(ctx._http_policy_state['used'],0)

    def test_cancel_content_stops_after_first_tool_and_keeps_partial_parse(self):
        from phases import content_discovery
        with tempfile.TemporaryDirectory() as td:
            ctx=context(td);ctx.profile['katana_depth']=2
            ctx.runner=NS(has=lambda _:True,read_lines=lambda _:['https://example.test'],
                          _cancel_event=threading.Event())
            def run(cmd,**kwargs):
                Path(cmd[cmd.index('-o')+1]).write_text(json.dumps({'results':[]}))
                ctx.runner._cancel_event.set()
                return 130,'','cancelled'
            ctx.runner.run=Mock(side_effect=run)
            wordlist=Path(td)/'words';wordlist.write_text('admin\n')
            with patch('phases.content_discovery.seclists.get',return_value=wordlist):
                content_discovery.run(ctx)
            self.assertEqual(ctx.runner.run.call_count,1)
            self.assertFalse(any(a.args[0]=='OK' for a in ctx.log.call_args_list))

    def test_diagnostic_wrapper_is_never_executed(self):
        from phases import diagnostics
        with tempfile.TemporaryDirectory() as td:
            wrapper=Path(td)/'amass';marker=Path(td)/'SIDE_EFFECT'
            wrapper.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\necho fixture\n');wrapper.chmod(0o700)
            with patch.dict(os.environ,{'PATH':td+os.pathsep+os.environ['PATH']}):
                diagnostics._get_version('amass')
            self.assertFalse(marker.exists())

    def test_exact_host_archive_intake_never_queries_shared_parent(self):
        from phases import discovery
        with tempfile.TemporaryDirectory() as td:
            ctx=context(td);ctx.targets=['app.herokuapp.com'];ctx.scope=None
            recon=Path(td)/'recon';recon.mkdir();(recon/'alive.txt').write_text('https://app.herokuapp.com\n')
            calls=[]
            class R:
                def has(self,name):return name=='waybackurls'
                def read_lines(self,p):return Path(p).read_text().splitlines() if Path(p).exists() else []
                def run_lines(self,cmd,**kwargs):calls.append(cmd);return []
                def write_lines(self,p,lines):Path(p).write_text('\n'.join(sorted(lines)))
            ctx.runner=R();ctx.storage.top_endpoints.return_value=[]
            discovery.run(ctx)
            self.assertEqual(calls,[['waybackurls','app.herokuapp.com']])

    def test_browser_regex_exec_is_not_a_shell_sink(self):
        from core.taint_engine import analyze_js
        flows=analyze_js('const data = location.hash;\nconst match = /x/.exec(data);','https://example.test/jquery.min.js')
        self.assertFalse([f for f in flows if f.sink_cwe=='CWE-78'])

    def test_node_regex_exec_is_not_a_shell_sink(self):
        from core.taint_engine import analyze_js
        flows=analyze_js('const data = req.query.q;\nconst match = regex.exec(data);','/server/app.js')
        self.assertFalse([f for f in flows if f.sink_cwe=='CWE-78'])
        shell=analyze_js('const data = req.query.q;\nchild_process.exec(data);','/server/app.js')
        self.assertTrue([f for f in shell if f.sink_cwe=='CWE-78'])

    def test_nmap_leaf_address_preserves_host(self):
        from phases.network_firewall_tooling import import_results
        with tempfile.TemporaryDirectory() as td:
            ctx=context(td);p=Path(td)/'nmap.xml'
            p.write_text('<nmaprun><host><address addr="192.0.2.18" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>')
            self.assertEqual(import_results(ctx,p),1)
            self.assertEqual(ctx.save_finding.call_args.args[0]['target'],'192.0.2.18')

    def test_generated_curl_is_not_an_original_request(self):
        from core.storage import Storage
        with tempfile.TemporaryDirectory() as td:
            st=Storage(Path(td)/'tbhm.db')
            try:
                st.save_finding({'phase':'code_scan','title':'source lead','severity':'LOW','confidence':'LOW','target':'src/app.py',
                                 'url':'','evidence':'static source','finding_class':'lead','discovered_at':'2026-10-26T00:00:00Z'})
                f=st.all_findings()[0]
                self.assertFalse(f.get('request_raw'))
            finally:st.close()

    def test_mfa_url_match_is_a_lead_at_its_actual_host(self):
        from phases import mfa_bypass_safe
        from core.finding_class import classify
        with tempfile.TemporaryDirectory() as td:
            ctx=context(td);ctx.targets=['first.test','second.test']
            (Path(td)/'recon').mkdir();(Path(td)/'recon/urls.txt').write_text('https://second.test/autodiscover/\n')
            ctx.runner=NS(read_lines=lambda p:Path(p).read_text().splitlines())
            mfa_bypass_safe.run(ctx)
            f=ctx.save_finding.call_args_list[0].args[0]
            self.assertEqual(f['target'],'second.test');self.assertEqual(classify(f),'lead')

    def test_ledger_snapshots_are_amortized_and_journal_recovers(self):
        from core.execution_ledger import ExecutionLedger
        with tempfile.TemporaryDirectory() as td:
            ledger=ExecutionLedger(td)
            with patch.object(ledger,'flush',wraps=ledger.flush) as flush:
                for i in range(1000):ledger.record(kind='http',status='blocked',url='https://example.test/'+str(i),reason='budget')
                self.assertLess(flush.call_count,30)
            recovered=ExecutionLedger(td,recover=True)
            self.assertEqual(len(recovered.rows),1000)

    def test_runtime_learning_commits_progress_before_later_row_fails(self):
        import numpy as np
        from core.ai_plane.embeddings import VectorIndex, EmbeddingDeferred
        class Store:
            def query(self,sql,args=()):
                rows=[{'id':1,'text':'good'},{'id':2,'text':'fails'}]
                if 'text' not in sql:return [{'id':1},{'id':2}]
                return [r for r in rows if r['id'] in args]
        class Embed:
            model='fixture'
            def embed_runtime_batch(self,texts,**kwargs):
                if 'fails' in texts:raise EmbeddingDeferred('model unavailable')
                return np.array([[1.,0.]]),'ollama'
        with tempfile.TemporaryDirectory() as td:
            index=VectorIndex(Path(td)/'v.npz',Path(td)/'v.json')
            result=index.update_pending(Store(),Embed(),limit=2)
            self.assertEqual(result['updated_rows'],1)
            self.assertEqual(result['pending_rows'],1)
            self.assertTrue(index.load());self.assertEqual(index.chunk_ids,[1])

    def test_httpx_fixture_parses_and_reports_invalid_records(self):
        from core.httpx_adapter import parse_records
        records,errors=parse_records('{"url":"https://example.test","status_code":200}\n{broken\n')
        self.assertEqual(len(records),1);self.assertEqual(len(errors),1)

    def test_strict_missing_proof_has_explicit_coverage(self):
        from phases.strict_finding_validation import run
        with tempfile.TemporaryDirectory() as td:
            ctx=context(td);(Path(td)/'evidence').mkdir()
            ctx.storage.all_findings.return_value=[{'id':1,'phase':'curl_verify','finding_class':'supported','url':'https://example.test'}]
            run(ctx)
            d=json.loads((Path(td)/'evidence/strict_finding_validation.json').read_text())
            self.assertEqual(d['missing_proof'],1)
            self.assertEqual(d['coverage_status'],'NO_PROOF_EXECUTED')


if __name__=='__main__':unittest.main(verbosity=2)
