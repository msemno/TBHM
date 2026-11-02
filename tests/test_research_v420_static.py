"""Behavioral controls for research-driven static analysis and contract intake."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import taint_engine as TE, api_contracts as API, soft404
from core.android_manifest import manifest_inventory
from phases import web3


class StaticTests(unittest.TestCase):
    def test_shadowed_numeric_function_is_not_a_control(self):
        flows = self.flows(' def int(value):\n  return value\n x=request.args["x"]\n os.system(int(x))\n')
        self.assertEqual(len(flows), 1); self.assertFalse(flows[0].sanitized)

    def test_finally_can_observe_taint_before_a_failed_assignment(self):
        flows = self.flows(' x=request.args["x"]\n try:\n  may_raise()\n  x="fixed"\n finally:\n  os.system(x)\n')
        self.assertEqual(len(flows), 1); self.assertFalse(flows[0].sanitized)

    def test_labeled_static_regression_corpus(self):
        cases = json.loads((Path(__file__).resolve().parents[1]/'examples/research-v420/taint_cases.json').read_text())
        for case in cases:
            with self.subTest(case=case['id']):
                detected = any(f.sink_cwe == case['category'] and not f.sanitized for f in TE.analyze_python(case['source']))
                self.assertEqual(detected, case['vulnerable'])

    def flows(self, body):
        return TE.analyze_python('import os, subprocess, html\nfrom flask import request\ndef route():\n'+body, 'app.py')

    def test_overwrite_kills_taint_but_conditional_overwrite_does_not(self):
        self.assertEqual(self.flows(' x=request.args["x"]\n x="fixed"\n os.system(x)\n'), [])
        self.assertEqual(len(self.flows(' x=request.args["x"]\n if flag:\n  x="fixed"\n os.system(x)\n')), 1)

    def test_html_escaping_does_not_sanitize_sql_or_shell(self):
        for sink in ('cursor.execute', 'os.system'):
            flows = self.flows(f' x=request.args["x"]\n {sink}(html.escape(x))\n')
            self.assertEqual(len(flows), 1)
            self.assertFalse(flows[0].sanitized)

    def test_unrelated_sanitizer_does_not_hide_source(self):
        flow = self.flows(' x=request.args["x"]\n cursor.execute(x+html.escape("constant"))\n')[0]
        self.assertFalse(flow.sanitized)

    def test_numeric_control_is_tracked_only_on_complete_value(self):
        for code in (' x=int(request.args["x"])\n cursor.execute(x)\n',
                     ' x=request.args["x"]\n cursor.execute(int(x))\n'):
            self.assertTrue(self.flows(code)[0].sanitized)
        self.assertFalse(self.flows(' x=request.args["x"]\n cursor.execute(x+str(int("3")))\n')[0].sanitized)

    def test_parameterized_sql_values_are_not_query_taint(self):
        self.assertEqual(self.flows(' x=request.args["x"]\n cursor.execute("select * from t where id=%s", (x,))\n'), [])

    def test_subprocess_shell_semantics_and_inline_flow(self):
        self.assertEqual(self.flows(' x=request.args["x"]\n subprocess.run(["echo", x])\n'), [])
        flows = self.flows(' subprocess.run("echo "+request.args["x"], shell=True)\n')
        self.assertEqual(len(flows), 1); self.assertFalse(flows[0].confirmed)

    def test_lexical_js_does_not_pretend_url_encoding_is_html_sanitization(self):
        flows = TE.analyze_js('const x = req.query.x;\nnode.innerHTML = encodeURIComponent(x);', 'app.js')
        self.assertTrue(flows); self.assertFalse(flows[0].sanitized)

    def test_soft404_different_bodies_with_same_status_do_not_suppress(self):
        responses = [SimpleNamespace(status_code=200, text='random A'), SimpleNamespace(status_code=200, text='random B')]
        soft404._CACHE.clear()
        with patch.object(soft404.requests, 'get', side_effect=responses):
            self.assertFalse(soft404.is_catch_all('https://x.test/admin', 200, 'real administration'))
        soft404._CACHE.clear()

    def test_wallet_prose_hashes_and_redaction(self):
        ordinary = 'this is ordinary prose containing twelve simple words inside a javascript document'
        self.assertEqual(web3.indicators(ordinary+' 0x'+'a'*64), [])
        hits = web3.indicators('const privateKey = "0x'+'b'*64+'";')
        self.assertEqual(len(hits), 1)
        self.assertNotIn('b'*64, json.dumps(hits))
        self.assertEqual(web3.indicators('const mnemonic = "one two three"'), [])

    def test_slither_import_errors_dedup_and_no_confirmation(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td); source = out/'slither.json'; saved = []
            ctx = SimpleNamespace(args=SimpleNamespace(), output=out, phase_state={},
                                  save_finding=lambda f: saved.append(f) or len(saved), log=lambda *a: None)
            detector = {'check': 'reentrancy-eth', 'impact': 'High', 'confidence': 'Medium', 'description': 'fixture contract state transition'}
            source.write_text(json.dumps({'success': True, 'results': {'detectors': [detector, detector, {}]}}))
            web3._import_slither(ctx, source, out)
            self.assertEqual(len(saved), 1); self.assertEqual(saved[0]['finding_class'], 'lead')
            self.assertEqual(ctx.phase_state['web3_import'], 'partial')
            source.write_text('{"success":false,"results":{"detectors":[]}}')
            web3._import_slither(ctx, source, out)
            self.assertEqual(ctx.phase_state['web3_import'], 'error')

    def manifest(self, contents, app=''):
        return manifest_inventory('<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk android:targetSdkVersion="31"/><permission android:name="com.test.PRIVATE" android:protectionLevel="signature"/><application '+app+'>'+contents+'</application></manifest>')

    def test_manifest_exported_permissions_inheritance_and_enabled(self):
        inv = self.manifest('<service android:name=".S" android:exported="true"/><activity android:name=".A" android:exported="true" android:enabled="false"/>', 'android:permission="com.test.PRIVATE"')
        self.assertEqual(inv['status'], 'complete')
        self.assertEqual(inv['components'][0]['permissions']['general'], 'com.test.PRIVATE')
        self.assertEqual(inv['components'][0]['permission_protection']['com.test.PRIVATE'], 'signature')
        self.assertNotIn('without_declared', inv['components'][0]['review'])
        self.assertEqual(inv['components'][1]['exposure'], 'disabled_by_declaration')
        self.assertFalse(any(c['vulnerability_confirmed'] for c in inv['components']))

    def test_manifest_unknown_exported_default_and_deep_link_not_verified(self):
        inv = self.manifest('<activity android:name=".A"><intent-filter android:autoVerify="true"><data android:scheme="https" android:host="example.test"/></intent-filter></activity>')
        self.assertEqual(inv['components'][0]['exposure'], 'unknown_default_or_resource')
        self.assertIn('requires explicit', inv['components'][0]['issue'])
        self.assertFalse(inv['deep_links'][0]['association_verified'])
        self.assertEqual(manifest_inventory('<!DOCTYPE x><manifest/>')['status'], 'unknown')


class ContractTests(unittest.TestCase):
    def test_repeated_large_reference_shapes_do_not_expand_without_bounds(self):
        doc = self.contract()
        doc['components']['requestBodies'] = {'large': {'description': 'x'*20000, 'content': {'application/json': {'schema': {'type': 'object'}}}}}
        doc['paths'] = {f'/objects/{i}': {'post': {'requestBody': {'$ref': '#/components/requestBodies/large'}, 'responses': {}}} for i in range(200)}
        result = API.inventory(doc)
        self.assertTrue(result['operations'][0]['request_body']['shape_summarized'])
        self.assertLess(len(json.dumps(result)), 250000)

    def test_source_analyzer_failure_is_not_a_clean_result(self):
        from core import code_intel as CI
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'app.py').write_text('value=1\n'); cmap = {'routes': []}
            with patch.object(TE, 'analyze', side_effect=RuntimeError('fixture analysis failure')):
                CI.trace_vulns(root, cmap)
            self.assertEqual(cmap['_taint_coverage'][0]['mode'], 'analysis_error')

    def test_server_base_path_and_shared_schema_changes_are_visible(self):
        doc = self.contract(); doc['servers'][0]['url'] += '/v1'
        before = API.inventory(doc)
        har = {'log': {'entries': [{'request': {'url': 'https://api.example.test/v1/users/3', 'method': 'GET'}}]}}
        traffic = API.traffic_inventory(har, before)
        self.assertEqual(next(o for o in traffic['operations'] if o['operation'].startswith('GET'))['observations'], 1)
        doc['components']['schemas'] = {'User': {'type': 'object', 'properties': {'id': {'type': 'string'}}}}
        self.assertTrue(API.compare(before, API.inventory(doc))['shared_schemas_changed'])

    def test_python_parse_failure_is_explicit_analysis_coverage(self):
        from core import code_intel as CI
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'app.py').write_text('def invalid(:\n os.system(request.args["x"])\n')
            cmap = {'routes': []}
            CI.trace_vulns(root, cmap)
            self.assertEqual(cmap['_taint_coverage'][0]['mode'], 'parse_error')
            self.assertFalse(cmap['_taint_coverage'][0]['runtime_verified'])

    def contract(self):
        return {'openapi': '3.1.0', 'components': {'securitySchemes': {'bearer': {'type': 'http', 'scheme': 'bearer'}},
                 'parameters': {'id': {'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}}},
                'security': [{'bearer': []}], 'servers': [{'url': 'https://api.example.test'}],
                'paths': {'/users/{id}': {'parameters': [{'$ref': '#/components/parameters/id'}],
                'get': {'responses': {}}, 'post': {'security': [], 'responses': {}},
                'delete': {'security': [{}, {'bearer': []}], 'responses': {}}}}}

    def test_inherited_security_empty_override_and_or_anonymous(self):
        operations = {o['method']: o for o in API.inventory(self.contract())['operations']}
        self.assertEqual(operations['GET']['authorization'], 'required_by_contract')
        for method in ('POST', 'DELETE'):
            self.assertEqual(operations[method]['authorization'], 'anonymous_allowed_by_contract')
        self.assertEqual(operations['GET']['parameters'][0]['name'], 'id')
        self.assertEqual(operations['GET']['test_status'], 'not_tested')

    def test_reference_cycles_remote_refs_and_malformed_security_are_partial(self):
        doc = self.contract(); doc['components']['parameters']['id'] = {'$ref': '#/components/parameters/id'}
        doc['paths']['/users/{id}']['get']['security'] = 'bearer'
        doc['paths']['/remote'] = {'$ref': 'https://outside.test/contract.json'}
        inv = API.inventory(doc)
        self.assertTrue(inv['issues'])
        self.assertEqual(next(o for o in inv['operations'] if o['method'] == 'GET')['authorization'], 'unknown')
        self.assertTrue(inv['operations'][0]['issues'])

    def test_diff_reports_security_change_and_removed_operation(self):
        before = self.contract(); after = copy.deepcopy(before)
        after['paths']['/users/{id}']['get']['security'] = []
        del after['paths']['/users/{id}']['post']
        diff = API.compare(API.inventory(before), API.inventory(after))
        self.assertEqual(diff['removed'], ['POST /users/{id}'])
        self.assertIn('security', diff['changed'][0]['fields'])

    def test_har_observation_is_scoped_to_declared_host_and_not_security_coverage(self):
        har = {'log': {'entries': [{'request': {'url': 'https://api.example.test/users/7?token=do-not-copy', 'method': 'GET'}},
                                  {'request': {'url': 'https://outside.test/users/9', 'method': 'GET'}}]}}
        result = API.traffic_inventory(har, API.inventory(self.contract()))
        self.assertEqual(next(o for o in result['operations'] if o['operation'].startswith('GET'))['observations'], 1)
        self.assertFalse(any(o['security_tested'] for o in result['operations']))
        self.assertNotIn('do-not-copy', json.dumps(result))
        self.assertEqual(len(result['undocumented_observations']), 1)

    def test_yaml_alias_cycle_oversize_and_unsupported_version(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'input.yaml'; path.write_text('value: &a [*a]')
            with self.assertRaises(ValueError): API.load_document(path)
            path.write_bytes(b' '* (API.MAX_BYTES+1))
            with self.assertRaises(ValueError): API.load_document(path)
        with self.assertRaises(ValueError): API.inventory({'openapi': '3.2.0', 'paths': {}})


if __name__ == '__main__': unittest.main(verbosity=2)
