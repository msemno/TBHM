"""Runtime memory must survive failures without blocking the phase loop."""
import hashlib
import json
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.ai_plane.embeddings import Embedder, EmbeddingDeferred, VectorIndex
from core.ai_plane.observer import RunObserver
from core.ai_plane.run_learning import ingest_phase_artifacts
from core.ai_plane.store import Store


class RuntimeLearningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root/'memory.sqlite3')
        self.index = VectorIndex(self.root/'vectors.npz', self.root/'manifest.json')
        self.embedder = Embedder(max_workers=1)
        self.calls = []
        def remote(text, session, **options):
            self.calls.append((text, options))
            return np.asarray([1.0, 0.0], dtype=np.float32)
        self.embedder._request_remote = remote

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def chunks(self, number, name='fixture.py'):
        doc = self.store.upsert_source_document(
            sha256=hashlib.sha256(name.encode()).hexdigest(), source_type='source_code',
            source_path=name, trust_level='T1')
        return self.store.replace_chunks(doc, [
            {'text': 'fixture '+str(i), 'symbol': str(i), 'kind':'text',
             'sha256':hashlib.sha256((name+str(i)).encode()).hexdigest()} for i in range(number)])

    def test_missing_cache_does_not_rebuild_all_chunks(self):
        ids = self.chunks(256)
        self.index.rebuild = lambda *_: self.fail('runtime rebuilt the whole cache')
        result = self.index.update_pending(self.store, self.embedder, changed_ids=[ids[-1]])
        self.assertEqual(len(self.calls), 8)
        self.assertEqual(result['pending_rows'], 248)
        self.assertEqual(result['status'], 'pending')
        self.assertIn(ids[-1], self.index.chunk_ids)
        self.assertEqual(self.store.counts()['document_chunks'], 256)

    def test_backlog_survives_process_restart_and_drains_without_new_artifacts(self):
        self.chunks(19)
        first = self.index.update_pending(self.store, self.embedder)
        self.assertEqual(first['pending_rows'], 11)
        fresh = VectorIndex(self.index.index_path, self.index.manifest_path)
        self.assertEqual(fresh.update_pending(self.store, self.embedder)['pending_rows'], 3)
        self.assertEqual(fresh.update_pending(self.store, self.embedder)['pending_rows'], 0)
        self.assertTrue(fresh.coverage(self.store)['complete'])

    def test_cancel_before_dispatch_makes_zero_requests(self):
        self.chunks(256)
        result = self.index.update_pending(self.store, self.embedder, cancelled=lambda: True)
        self.assertEqual(result['status'], 'deferred')
        self.assertEqual(self.calls, [])
        self.assertEqual(self.store.counts()['document_chunks'], 256)

    def test_cancel_during_batch_retains_previous_cache(self):
        self.chunks(1)
        self.index.update_pending(self.store, self.embedder)
        self.chunks(10)
        original = self.index.index_path.read_bytes()
        event = threading.Event()
        def remote(*args, **kw):
            event.set()
            return np.asarray([1., 0.], dtype=np.float32)
        self.embedder._request_remote = remote
        result = self.index.update_pending(self.store, self.embedder, cancelled=event.is_set)
        self.assertEqual(result['status'], 'deferred')
        self.assertEqual(self.index.index_path.read_bytes(), original)

    def test_mid_batch_failure_stops_immediately_and_never_mixes_spaces(self):
        self.chunks(1)
        self.index.update_pending(self.store, self.embedder)
        self.chunks(15)
        original = self.index.index_path.read_bytes()
        answers = iter([np.asarray([1., 0.], dtype=np.float32), None])
        calls = []
        def remote(*args, **kw):
            calls.append(1)
            return next(answers)
        self.embedder._request_remote = remote
        result = self.index.update_pending(self.store, self.embedder)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result['status'], 'deferred')
        self.assertNotEqual(self.index.index_path.read_bytes(), original)
        self.assertEqual(result['updated_rows'], 1)
        self.assertEqual(len(self.index.chunk_ids), 2)
        self.assertEqual(self.index.meta['embedding_mode'], 'ollama')

    def test_deadline_is_checked_before_next_request(self):
        now = [0.]
        def remote(*args, **kw):
            now[0] += 7
            return np.asarray([1., 0.], dtype=np.float32)
        self.embedder._request_remote = remote
        with patch('core.ai_plane.embeddings.time.monotonic', side_effect=lambda: now[0]):
            with self.assertRaises(EmbeddingDeferred):
                self.embedder.embed_runtime_batch(['a','b','c'], deadline=6)
        self.assertEqual(now[0], 7)

    def test_request_timeout_is_capped_by_remaining_budget(self):
        self.embedder.embed_runtime_batch(['a'], deadline=time.monotonic()+1.25)
        self.assertLessEqual(self.calls[0][1]['request_timeout'], 1.25)

    def test_changed_dimensions_do_not_replace_cache(self):
        self.chunks(1)
        self.index.update_pending(self.store, self.embedder)
        original = self.index.index_path.read_bytes()
        self.chunks(3)
        self.embedder._request_remote = lambda *a, **kw: np.asarray([1., 0., 0.], dtype=np.float32)
        result = self.index.update_pending(self.store, self.embedder)
        self.assertEqual(result['status'], 'deferred')
        self.assertEqual(original, self.index.index_path.read_bytes())

    def test_model_change_requires_explicit_maintenance(self):
        self.chunks(1)
        self.index.update_pending(self.store, self.embedder)
        self.chunks(3)
        self.calls.clear()
        self.embedder.model = 'different-model'
        result = self.index.update_pending(self.store, self.embedder)
        self.assertEqual(result['status'], 'deferred')
        self.assertEqual(self.calls, [])

    def test_deletions_are_removed_without_model_work(self):
        self.chunks(3)
        self.index.update_pending(self.store, self.embedder)
        self.store.tombstone_source('fixture.py')
        self.calls.clear()
        result = self.index.update_pending(self.store, self.embedder)
        self.assertEqual(result['pending_rows'], 0)
        self.assertEqual(self.index.chunk_ids, [])
        self.assertEqual(self.calls, [])

    def test_runtime_search_never_rebuilds_on_model_failure(self):
        self.chunks(1)
        self.index.update_pending(self.store, self.embedder)
        self.index.runtime_cancelled = lambda: False
        self.embedder._request_remote = lambda *args, **kwargs: None
        with patch.object(self.index, 'rebuild', side_effect=AssertionError('full rebuild')):
            self.assertEqual(self.index.search(self.store, self.embedder, 'query'), [])

    def test_sanitized_phase_notes_are_durable_when_cancelled(self):
        run = self.root/'run'
        run.mkdir()
        (run/'notes.txt').write_text('Observation password=PRIVATE_CANARY')
        result = ingest_phase_artifacts(store=self.store, vector_index=self.index,
            embedder=self.embedder, run_uid='run-test', phase='discovery',
            output_root=run, before={}, cancelled=lambda: True)
        self.assertEqual(result['indexed_files'], 1)
        self.assertEqual(result['vector']['status'], 'deferred')
        self.assertEqual(self.calls, [])
        saved = '\n'.join(row['text'] for row in self.store.all_chunks())
        self.assertNotIn('PRIVATE_CANARY', saved)
        self.assertIn('UNTRUSTED', saved)

    def test_observer_reports_deferred_work_and_skips_cancelled_model_advisories(self):
        run = self.root/'run'
        run.mkdir()
        (run/'notes.txt').write_text('A reproducible local observation')
        logs = []
        event = threading.Event()
        ctx = SimpleNamespace(args=SimpleNamespace(intensity='standard', ai_scenario_context=None),
            profile={'name':'passive_only'}, targets=[], output=run,
            runner=SimpleNamespace(_cancel_event=event),
            storage=SimpleNamespace(all_findings=lambda: []))
        observer = RunObserver(store=self.store, embedder=self.embedder,
            vector_index=self.index, advisor=SimpleNamespace(), proposal_gate=None,
            audit=SimpleNamespace(record=lambda *a, **kw:None), runtime=None,
            log=lambda *args: logs.append(args))
        observer.on_run_start(ctx)
        observer.before_phase(ctx, 'discovery')
        (run/'notes.txt').write_text('Another reproducible local observation')
        event.set()
        observer.after_phase(ctx, 'discovery', True, .1)
        observer._final_analysis(ctx)
        observer._direction_plan(ctx)
        events = {r['event'] for r in self.store.query('SELECT event FROM phase_events')}
        self.assertIn('artifacts_started', events)
        self.assertIn('artifacts_stored', events)
        self.assertIn('vector_deferred', events)
        self.assertIn('analysis_deferred', events)
        self.assertIn('direction_deferred', events)
        self.assertNotIn('artifacts_indexed', events)
        self.assertTrue(any('pending=' in str(line) for line in logs))

    def test_partial_cache_is_not_reported_complete(self):
        self.chunks(9)
        self.index.update_pending(self.store, self.embedder)
        coverage = self.index.coverage(self.store)
        self.assertEqual(coverage['pending_rows'], 1)
        self.assertFalse(coverage['complete'])

    def test_actual_loopback_model_timeout_does_not_repeat_for_remaining_chunks(self):
        hits = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                hits.append(self.path)
                time.sleep(.35)
                try:
                    body = b'{"embedding":[1,0]}'
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            emb = Embedder(endpoint=f'http://127.0.0.1:{server.server_port}')
            started = time.monotonic()
            with self.assertRaises(EmbeddingDeferred):
                emb.embed_runtime_batch(['first','second','third'], force_mode='ollama',
                                         deadline=started+.12)
            self.assertLess(time.monotonic()-started, .8)
            self.assertEqual(hits, [])  # Insufficient budget is deferred before dispatch.
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_cancelled_guard_blocks_other_model_callers_before_transport(self):
        import requests
        from core import request_guard
        event = threading.Event()
        event.set()
        ctx = SimpleNamespace(args=SimpleNamespace(local_llm_url='http://127.0.0.1:11435',
            local_llm=True, no_ai_observe=False, offline=False, proxy=None),
            profile={'name':'authorized_safe'}, runner=SimpleNamespace(_cancel_event=event),
            execution_ledger=SimpleNamespace(current_phase='report', record=lambda **kw:None))
        try:
            with patch.object(request_guard, '_SEND', side_effect=AssertionError('transport used')):
                request_guard.activate(ctx)
                with self.assertRaises(request_guard.RequestBlocked):
                    requests.post('http://127.0.0.1:11435/api/generate', json={'prompt':'fixture'}, timeout=1)
        finally:
            request_guard.deactivate()

    def test_archive_queries_respect_exact_hosts_and_explicit_apex_permission(self):
        from phases import discovery
        from core.scope import Scope
        ctx = SimpleNamespace(targets=['https://app.herokuapp.com/'], scope_excludes=[],
                              scope=Scope(['=app.herokuapp.com'], []))
        with patch.object(discovery, 'get_root_domains', return_value=['herokuapp.com']):
            self.assertEqual(discovery._archive_domains(ctx), ['app.herokuapp.com'])
            ctx.scope = Scope(['herokuapp.com'], [])
            self.assertEqual(discovery._archive_domains(ctx), ['herokuapp.com'])
            ctx.scope = Scope([], [])
            self.assertEqual(discovery._archive_domains(ctx), ['app.herokuapp.com'])

    def test_provider_urls_are_filtered_by_host_boundary_before_persistence(self):
        from phases import discovery
        from core.scope import Scope
        run = self.root/'discovery'
        (run/'recon').mkdir(parents=True)
        (run/'recon/alive.txt').write_text('https://app.example.invalid/\n')
        calls = []
        def harvest(cmd, **kw):
            calls.append(cmd)
            return ['https://app.example.invalid/allowed',
                    'https://app.example.invalid.evil.invalid/denied',
                    'https://sibling.example.invalid/denied']
        runner = SimpleNamespace(has=lambda name: name in {'waybackurls','gau'},
            read_lines=lambda path: Path(path).read_text().splitlines(), run_lines=harvest,
            write_lines=lambda path, values: Path(path).write_text('\n'.join(values)))
        ctx = SimpleNamespace(targets=['https://app.example.invalid/'], scope=Scope([], []),
            scope_excludes=[], output=run, runner=runner, profile={'active_probes':False},
            threads=1, log=lambda *a:None,
            storage=SimpleNamespace(save_endpoint_score=lambda *a:None, top_endpoints=lambda *_:[]))
        discovery.run(ctx)
        self.assertTrue(all(cmd[-1] == 'app.example.invalid' for cmd in calls))
        self.assertEqual((run/'recon/urls.txt').read_text(), 'https://app.example.invalid/allowed')

    def test_redaction_fast_paths_preserve_original_secret_substitutions(self):
        from core import evidence_redaction as er
        from core.code_patterns import _SECRETS
        def reference(text):
            for secret in sorted(tuple(er._KNOWN_SECRETS), key=len, reverse=True):
                text = text.replace(secret, '[REDACTED]')
            text = er._URL.sub(er._redact_url, text)
            text = er._URL_USERINFO.sub(r'\1[REDACTED]@', text)
            text = er._QUERY_SECRET.sub(r'\1[REDACTED]', text)
            text = er._JSON_SECRET.sub(r'\1"[REDACTED]"', text)
            text = er._URI_CREDS.sub(r'\1[REDACTED_USER]:[REDACTED_PASSWORD]@', text)
            for rule in er._PATTERNS:
                text = rule[0].sub(rule[1], text)
            for name, pattern, _ in _SECRETS:
                if name not in {'Firebase Database URL','Twilio Account SID','Private Key Block','Generic Secret Assignment'}:
                    text = pattern.sub('[REDACTED_PROVIDER_CREDENTIAL]', text)
            return text
        samples = ['Authorization: Bearer fixture-value', 'Cookie: session=fixture',
            'password=synthetic-secret', 'AKIA'+'A'*16, 'ghp_'+'a'*40,
            'github_pat_'+'a'*70, 'glpat-'+'a'*30, 'SG.'+'a'*22+'.'+'b'*43,
            'sk_live_'+'a'*32, 'rk_test_'+'a'*32, 'pk_test_'+'a'*16,
            'sk-'+'a'*30, 'xoxb-'+'a'*20, 'AIza'+'a'*35,
            'eyJ'+'a'*12+'.eyJ'+'b'*12+'.'+'c'*20,
            '-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----',
            'https://user:password@example.invalid/p?token=private#fragment',
            '{"api_key":"fixture-private-key"}', 'postgres://user:password@example.invalid/db',
            'aws_secret_access_key="'+'a'*40+'"', 'ya29.'+'a'*30,
            'https://hooks.slack.com/services/A/B/C', 'SK'+'a'*32,
            'key-'+'a'*32, 'AAAA'+'a'*7+':'+'b'*140,
            'heroku_key="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"', 'npm_'+'a'*36,
            'sq0atp-'+'a'*22, 'access_token$production$'+'a'*16+'$'+'b'*32,
            'x'*8192, 'regular source guidance']
        for sample in samples:
            for value in (sample, 'prefix '+sample+' suffix', sample.upper()):
                with self.subTest(value=value[:50]):
                    self.assertEqual(er.redact_text(value), reference(value))

    def test_stopped_stream_never_writes_to_closed_log(self):
        import io
        from core.runner import Runner, _TailBuffer
        event = threading.Event()
        event.set()
        log = io.BytesIO()
        log.close()
        Runner._stream_pipe(None, io.BytesIO(b'fixture'), log, _TailBuffer(1024),
                            b'output', threading.Lock(), stop_event=event)


if __name__ == '__main__':
    unittest.main(verbosity=2)
