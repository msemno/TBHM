"""Regressions for exact-reference loss and malformed local refutation output.

All model responses in this module are fixtures, never a real inference claim.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(os.environ.get('TBHM_TEST_CODE_HOME', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT))
from core.ai_plane.public_knowledge import Catalog, retrieve_context
from core.llm_local import OllamaClient, LocalLLMConfig
from core.llm_review import run_refutation, validate_response, VERDICTS
from core.storage import Storage
from phases import local_llm_triage


class InterruptLexical:
    def __init__(self, connection):
        self.connection = connection
        self.lexical_attempts = 0

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def execute(self, sql, parameters=()):
        if 'entry_fts MATCH' in sql:
            self.lexical_attempts += 1
            raise sqlite3.OperationalError('interrupted')
        return self.connection.execute(sql, parameters)


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.path = Path(self.work.name) / 'catalog.sqlite3'
        writer = Catalog(self.path, create=True)
        for cid, state, kind in [('CWE-78', 'ACTIVE', 'cwe'),
                                 ('CWE-999', 'DEPRECATED', 'cwe'),
                                 ('CVE-2020-12345', 'REJECTED', 'cve')]:
            writer.put(entry_id=cid, kind=kind, status=state,
                       title='OS command injection', body='fixture command injection validation',
                       raw_sha='fixture', meta={'source_url':'https://example.invalid/reference'},
                       dataset='fixture', run='fixture')
        writer.checkpoint('fixture', {'status':'complete'})
        writer.close()

    def open(self):
        catalog = Catalog(self.path)
        self.addCleanup(catalog.close)
        return catalog

    def test_exact_reference_survives_interrupted_broad_search(self):
        catalog = self.open()
        wrapped = InterruptLexical(catalog.db)
        catalog.db = wrapped
        hits = catalog.search('CWE-78 OS command injection source report unsafe', 2)
        self.assertEqual([hit['id'] for hit in hits], ['CWE-78'])
        self.assertEqual(wrapped.lexical_attempts, 0)

    def test_context_uses_the_same_exact_reference(self):
        block, refs = retrieve_context(self.path, 'CWE-78 command injection', budget=1000)
        self.assertEqual(refs[0]['id'], 'CWE-78')
        self.assertIn('background only', block)

    def test_rejected_and_deprecated_records_remain_excluded(self):
        catalog = self.open()
        self.assertEqual(catalog.search('CWE-999'), [])
        self.assertEqual(catalog.search('CVE-2020-12345'), [])

    def test_lexical_search_and_literal_fts_quoting_still_work(self):
        catalog = self.open()
        self.assertEqual(catalog.search('command injection " OR * NEAR(')[0]['id'], 'CWE-78')

    def test_deadline_without_a_reference_stays_visible(self):
        catalog = self.open()
        catalog.db = InterruptLexical(catalog.db)
        with self.assertRaisesRegex(sqlite3.OperationalError, 'interrupted'):
            catalog.search('command injection')

    def test_search_does_not_write_to_catalog(self):
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        catalog = self.open()
        catalog.search('CWE-78 command injection')
        self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).hexdigest())
        with self.assertRaises(sqlite3.OperationalError):
            catalog.db.execute("DELETE FROM entries")


class Response:
    def __init__(self, data, status=200):
        self.data, self.status_code = data, status
        self.text = json.dumps(data)

    def json(self):
        return self.data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise ValueError('fixture HTTP error')


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.client = OllamaClient(LocalLLMConfig())
        self.addCleanup(self.client.session.close)
        self.calls = []
        self.schema = {'type':'object', 'properties':{'verdict':{'enum':['unresolved']}},
                       'required':['verdict']}

    def fixture(self, fallback=False):
        def post(url, **kwargs):
            self.calls.append((url, kwargs))
            if fallback and url.endswith('/api/chat'):
                return Response({'error':'fixture has no chat template'}, 400)
            if url.endswith('/api/generate'):
                return Response({'response':'{"verdict":"unresolved"}'})
            return Response({'message':{'content':'{"verdict":"unresolved"}'}})
        self.client.session.post = post

    def test_schema_is_transmitted_to_chat(self):
        self.fixture()
        self.assertEqual(self.client.chat_json_schema('system', 'user', self.schema)['verdict'], 'unresolved')
        self.assertEqual(self.calls[0][1]['json']['format'], self.schema)
        self.assertFalse(self.calls[0][1]['allow_redirects'])
        self.assertFalse(self.client.session.trust_env)

    def test_generate_fallback_keeps_identical_schema(self):
        self.fixture(fallback=True)
        self.client.chat_json_schema('system', 'user', self.schema)
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(all(call[1]['json']['format'] == self.schema for call in self.calls))

    def test_existing_json_only_call_is_compatible(self):
        self.fixture()
        self.client.chat_json('system', 'user')
        self.assertEqual(self.calls[0][1]['json']['format'], 'json')

    def test_non_object_schema_is_rejected_before_request(self):
        self.fixture()
        with self.assertRaises(ValueError):
            self.client.chat_json_schema('system', 'user', {'type':'array'})
        self.assertEqual(self.calls, [])


class RefutationTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.writes = []
        self.ctx = SimpleNamespace(args=SimpleNamespace(llm_refute_max_findings=2, code_dir=None),
            storage=SimpleNamespace(enrich_finding=lambda fid, value:self.writes.append((fid,value)) or True))
        self.findings = [{'id':7, 'title':'Fixture static lead', 'evidence':'Fixture source only'}]
        self.reply = {'finding_id':7,'verdict':'needs_validation','evidence_ids':['E1'],
                      'rationale':'Only static evidence is supplied.',
                      'missing_evidence':'Independent runtime evidence.'}

    def run_case(self, reply=None, structured=True):
        reply = self.reply if reply is None else reply
        self.schemas = []
        if structured:
            def chat(system, user, schema):
                self.assertEqual(json.loads(user)['finding_id'], 7)
                self.assertEqual(json.loads(user)['response_schema'], schema)
                self.schemas.append(schema)
                return reply
            client = SimpleNamespace(chat_json_schema=chat)
        else:
            client = SimpleNamespace(chat_json=lambda system,user:reply)
        return run_refutation(self.ctx, client, self.findings, Path(self.work.name), 'fixture-model', 4096)

    def test_enum_and_finding_identity_are_constrained(self):
        result = self.run_case()
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(set(self.schemas[0]['properties']['verdict']['enum']), VERDICTS)
        self.assertEqual(self.schemas[0]['properties']['finding_id']['const'], 7)
        self.assertTrue(result['results'][0]['finding_unchanged'])

    def test_legacy_two_argument_client_is_compatible(self):
        self.assertEqual(self.run_case(structured=False)['status'], 'complete')

    def test_pipe_joined_verdict_stays_unresolved(self):
        result = self.run_case({**self.reply, 'verdict':'counterevidence_observed|unresolved|needs_validation'})
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['errors'][0]['status'], 'unresolved')
        self.assertEqual(self.writes, [])

    def test_invented_reference_and_wrong_finding_are_rejected(self):
        for change in ({'evidence_ids':['E999']}, {'finding_id':8},
                       {'verdict':'counterevidence_observed','evidence_ids':[]}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    validate_response({**self.reply, **change}, 7, [{'id':'E1'}])


class EnrichmentIdentityTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.store = Storage(self.root/'run.sqlite3')
        self.addCleanup(self.store.close)
        self.ids = [self.store.save_finding({
            'phase': 'code_intel', 'title': 'Owned fixture '+str(index),
            'severity': 'LOW', 'confidence': 'LOW', 'finding_class': 'lead',
            'discovered_at': 'fixture', 'evidence': 'Static fixture only',
        }) for index in range(2)]
        self.before = self.store.all_findings()
        self.calls = []

    def run_case(self, transform=None, *, structured=True):
        def schema_chat(system, user, schema):
            self.calls.append((user, schema))
            self.assertIn('Required response schema:', system)
            fid = schema['properties']['items']['items']['properties']['finding_id']['const']
            response = {'items': [{'finding_id': fid, 'assessment': 'needs-review',
                'rationale': 'Static evidence only.', 'evidence_gaps': 'Runtime proof.',
                'cwe': 'CWE-78', 'cvss_score': '0.0'}]}
            return transform(response) if transform else response
        def legacy_chat(system, user):
            self.calls.append((user, None))
            return {'items': [{'finding_id': fid} for fid in self.ids]}
        client = SimpleNamespace(available=lambda: (True, 'fixture'))
        if structured:
            client.chat_json_schema = schema_chat
            client.chat_json = lambda *args: self.fail('Unexpected unconstrained retry')
        else:
            client.chat_json = legacy_chat
        runtime = SimpleNamespace(client=client, hardware={}, model='fixture',
            endpoint='http://127.0.0.1:11435', context=4096, timeout=30)
        self.ctx = SimpleNamespace(output=self.root, storage=self.store,
            phase_state={}, local_llm_runtime=runtime, log=lambda *args: None,
            args=SimpleNamespace(local_llm=True, local_llm_required=True,
                llm_refute=False, no_ai_knowledge=True))
        with patch.object(local_llm_triage, 'detect_hardware', return_value={}):
            local_llm_triage.run(self.ctx)
        return json.loads((self.root/'redteam/31_local_llm_triage/local_llm_enrichment.json').read_text())

    def test_structured_requests_cover_both_findings_individually(self):
        result = self.run_case()
        self.assertEqual(result['findings_enriched'], 2)
        self.assertEqual(result['errors'], [])
        self.assertEqual(len(self.calls), 2)
        for (user, schema), fid in zip(self.calls, self.ids):
            array = schema['properties']['items']
            self.assertEqual((array['minItems'], array['maxItems']), (1, 1))
            self.assertEqual(array['items']['properties']['finding_id']['const'], fid)
            self.assertEqual(array['items']['properties']['finding_id']['enum'], [fid])
            self.assertEqual(len(json.loads(user.split('\n', 1)[1])), 1)

    def test_advisory_does_not_change_existing_proof_class_severity_or_cwe(self):
        self.run_case()
        for before, after in zip(self.before, self.store.all_findings()):
            for key in ('id', 'severity', 'confidence', 'finding_class', 'cwe', 'evidence'):
                self.assertEqual(before.get(key), after.get(key), key)
            self.assertTrue(after['enrichment']['local_llm']['non_authoritative'])

    def test_missing_item_is_not_replaced_with_a_synthetic_success(self):
        result = self.run_case(lambda value: {'items': []})
        self.assertEqual(result['findings_enriched'], 0)
        self.assertEqual(len(result['errors']), 2)
        self.assertTrue(all(row['error']=='response omitted finding IDs' for row in result['errors']))
        self.assertIn('local_llm_required_failed', self.ctx.phase_state)

    def test_wrong_identity_is_rejected_instead_of_relabelled(self):
        result = self.run_case(lambda value: {'items': [{**value['items'][0], 'finding_id': 999}]})
        self.assertEqual(result['findings_enriched'], 0)
        self.assertTrue(any('out-of-batch' in row['error'] for row in result['errors']))
        self.assertTrue(all(not row.get('enrichment') for row in self.store.all_findings()))

    def test_boolean_identity_is_not_accepted_as_integer_one(self):
        result = self.run_case(lambda value: {'items': [{**value['items'][0], 'finding_id': True}]})
        self.assertEqual(result['findings_enriched'], 0)
        self.assertTrue(any(row['error']=='invalid finding ID' for row in result['errors']))

    def test_duplicate_output_stays_incomplete(self):
        result = self.run_case(lambda value: {'items': value['items']*2})
        self.assertEqual(result['findings_enriched'], 2)
        self.assertEqual(len(result['errors']), 2)
        self.assertIn('local_llm_required_failed', self.ctx.phase_state)

    def test_non_list_response_stays_incomplete(self):
        result = self.run_case(lambda value: {'items': {}})
        self.assertEqual(result['findings_enriched'], 0)
        self.assertTrue(all(row['error']=='response items is not a list' for row in result['errors']))

    def test_schema_transport_failure_does_not_retry_without_constraints(self):
        def fail(value):
            raise ValueError('fixture schema request refused')
        result = self.run_case(fail)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(result['findings_enriched'], 0)
        self.assertEqual(len(result['errors']), 2)

    def test_legacy_client_keeps_its_two_argument_batch_contract(self):
        result = self.run_case(structured=False)
        self.assertEqual(result['findings_enriched'], 2)
        self.assertEqual(result['errors'], [])
        self.assertEqual(len(self.calls), 1)

    def test_invented_authority_fields_are_not_applied(self):
        result = self.run_case(lambda value: {'items': [{**value['items'][0],
            'assessment': 'confirmed', 'finding_class': 'confirmed',
            'severity': 'CRITICAL', 'proof_verified': True}]})
        self.assertEqual(result['findings_enriched'], 2)
        for after in self.store.all_findings():
            self.assertEqual(after['finding_class'], 'lead')
            self.assertEqual(after['severity'], 'LOW')
            self.assertEqual(after['enrichment']['local_llm']['assessment'], 'needs-review')
            self.assertNotIn('proof_verified', after['enrichment']['local_llm'])


if __name__ == '__main__':
    unittest.main()
