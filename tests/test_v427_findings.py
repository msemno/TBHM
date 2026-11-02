"""Regressions derived from run failures plus independent controls; no live targets."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.scanner_normalizer import parse_json_value, scanner_diagnostics
from core import api_baseline as AB, code_patterns as CP
from phases import protected_routes as PR, supply_chain_review as SC, mobile_scan, ports


class FindingRegressions(unittest.TestCase):
    def test_ci_without_source_or_attestation_input_never_scans_cwd(self):
        from phases import ci_cd_supply_chain_security as cicd
        with tempfile.TemporaryDirectory() as td:
            ctx=NS(output=Path(td),args=NS(cicd_security=True),phase_state={},
                   runner=NS(has=lambda _:False),log=lambda *a:None)
            with patch.object(cicd,'analyze_tree',side_effect=AssertionError('Unrequested source tree scanned')):
                cicd.run(ctx)
            saved=json.loads(next(Path(td).rglob('ci_cd_supply_chain_summary.json')).read_text())
            self.assertEqual(saved['attestation_inventory'],[])
            self.assertEqual(saved['scanned_pipeline_files'],0)

    def test_recon_live_is_not_a_cryptographic_iv(self):
        from core.cwe_cvss import cwe_for
        self.assertNotEqual(cwe_for('Recon: 1 subdomains, 2 live'), 'CWE-327')
        self.assertEqual(cwe_for('Weak hash md5 in token generation'), 'CWE-327')
        self.assertEqual(cwe_for('Hardcoded token with random characters'), 'CWE-798')
        self.assertNotEqual(cwe_for('Source inventory and force refresh'), 'CWE-77')
        self.assertEqual(cwe_for('OS command injection candidate'), 'CWE-77')

    def test_checkov_only_failed_with_real_location_is_a_candidate(self):
        base = {'check_id':'CKV_GHA_9', 'check_name':'Untrusted workflow input',
                'file_path':'.github/workflows/release.yml', 'file_line_range':[8,9]}
        passed = {**base, 'check_result':{'result':'PASSED'}}
        failed = {**base, 'check_result':{'result':'FAILED'}}
        data = {'check_type':'github_actions','results':{'passed_checks':[passed]*327,
                'skipped_checks':[failed], 'failed_checks':[failed, passed]}}
        items = parse_json_value(data, 'results_json')
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['line'], 8)
        self.assertEqual(items[0]['target'], base['file_path'])
        self.assertEqual(len(parse_json_value([data], 'imported')),1)

    def test_checkov_passed_or_missing_file_never_produces_vulnerability(self):
        for result in ({'check_id':'A','check_result':{'result':'PASSED'},'file_path':'real.yml'},
                       {'check_id':'A','check_result':{'result':'FAILED'}}):
            self.assertFalse(parse_json_value({'results':{'failed_checks':[result]}},'checkov'))

    def test_njsscan_parser_error_not_a_finding_and_locations_are_retained(self):
        error = {'message':'Syntax error','code':3,'level':'warn','path':'server.js'}
        rule = {'files':[{'file_path':'src/app.js','match_lines':[7,8],'match_string':'sink(value)'}],
                'metadata':{'severity':'WARNING','cwe':'CWE-78','description':'Candidate injection'}}
        data = {'njsscan_version':'fixture','errors':[error], 'nodejs':{'exec':rule,
                'redacted':'[REDACTED]', 'no_match':{'metadata':{'severity':'HIGH','description':'fake'}}}}
        rows = parse_json_value(data, 'njsscan')
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['target'],'src/app.js')
        self.assertEqual(rows[0]['cwe'],'CWE-78')
        self.assertEqual(len(rows[0]['occurrences']),1)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'scan.json';p.write_text(json.dumps(data))
            self.assertEqual(scanner_diagnostics(p,'njsscan')[0]['kind'],'parser-error')

    def test_declarations_are_not_runtime_sinks_but_executable_code_remains(self):
        code = 'child_process.execSync(value); exec(value)'
        for name in ('index.d.ts','INDEX.D.MTS','api.d.cts'):
            self.assertFalse(CP.find_sinks(code,name))
        self.assertTrue(CP.find_sinks(code,'src/server.js'))
        self.assertTrue(CP.find_sinks('os.system(value)','test/command.py'))
        self.assertTrue(CP.find_sinks('os.system(value)','app.py'))

    def test_api_denials_and_server_errors_are_inventory_not_vulnerability(self):
        base = AB.make_signature(404,'missing')
        for status in (200,301,400,401,403,405,422,500,503):
            with self.subTest(status=status):
                changed, description, severity = AB.classify(AB.make_signature(status,'different response body'),base)
                self.assertTrue(changed)
                self.assertEqual(severity,'INFO')
                self.assertNotIn('injection',description)
        self.assertFalse(AB.classify(AB.make_signature(200,'missing'),base)[0])

    def test_path_boundaries_and_static_assets_do_not_imply_authentication(self):
        for path in ('/favicon.ico','/dashboard/main.css','/metrics/gtm.js','/profiler_v4.js',
                     '/industries/healthcare','/product/account-verification-services'):
            self.assertIsNone(PR.route_class('https://owned.invalid'+path))
        for path in ('/api/admin/users','/dashboard','/internal/config'):
            self.assertIsNotNone(PR.route_class('https://owned.invalid'+path))

    def test_public_spa_and_sensitive_field_control(self):
        self.assertEqual(PR.response_assessment(200,'<html><div id="app"></div></html>')['outcome'],'public_or_spa_response')
        self.assertEqual(PR.response_assessment(200,'{"users":["public-profile"]}')['outcome'],'structured_response_inventory')
        self.assertEqual(PR.response_assessment(403,'{"access_token":"fake-control"}')['outcome'],'access_denied')
        self.assertEqual(PR.response_assessment(200,'{"users":[{"password_hash":"fixture-value-1234"}]}')['sensitive_fields'],['password_hash'])

    def test_handler_keywords_are_inventory_without_losing_locations(self):
        from phases.code_intel import _emit_handler_branch
        with tempfile.TemporaryDirectory() as td:
            observations=[];ctx=NS(storage=NS(save_observation=lambda **kw:observations.append(kw)),
                                  save_finding=lambda _:self.fail('feature became vulnerability'))
            result, count = _emit_handler_branch(ctx, {'handlers':{'upload':[{'file':'upload.py','line':4,'match':'upload('}]}},
                Path(td),'upload','code_uploads','MEDIUM','Upload handler','CWE-434','Unverified')
            self.assertEqual(count,0);self.assertEqual(result['count'],1)
            self.assertEqual(observations[0]['evidence']['line'],4)

    def test_local_link_must_resolve_inside_root_and_match_package_name(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'packages').mkdir();(root/'packages/lib').mkdir()
            (root/'package.json').write_text('{"name":"app","workspaces":["packages/*"]}')
            (root/'packages/lib/package.json').write_text('{"name":"core-private"}')
            for spec in ('file:packages/lib','workspace:*','link:packages/lib'):
                self.assertIsNotNone(SC._local_dependency('npm','core-private',spec,str(root/'package.json'),[root]))
            for spec in ('file:../outside','file:missing','https://example.invalid/pkg'):
                self.assertIsNone(SC._local_dependency('npm','core-private',spec,str(root/'package.json'),[root]))
            self.assertIsNone(SC._local_dependency('npm','wrong-name','file:packages/lib',str(root/'package.json'),[root]))

    def test_missing_mobile_artifact_is_explicit_failure_not_success(self):
        with tempfile.TemporaryDirectory() as td:
            ctx=NS(args=NS(apk=str(Path(td)/'missing.apk'),ipa=None,mobile_src=None),output=Path(td),log=lambda *a:None)
            with self.assertRaisesRegex(ValueError,'mobile input missing'):
                mobile_scan.run(ctx)
            receipt=json.loads((Path(td)/'mobile/capability_receipt.json').read_text())
            self.assertEqual(receipt['inputs']['apk']['status'],'missing')
            self.assertFalse(receipt['inputs']['apk']['static_analysis_attempted'])

    def test_no_mobile_artifact_records_not_requested(self):
        with tempfile.TemporaryDirectory() as td:
            mobile_scan.run(NS(args=NS(),output=Path(td),log=lambda *a:None))
            receipt=json.loads((Path(td)/'mobile/capability_receipt.json').read_text())
            self.assertFalse(receipt['dynamic_device_testing_executed'])
            self.assertTrue(all(v['status']=='not_requested' for v in receipt['inputs'].values()))

    def test_port_scope_never_inferred_from_dns_and_policy_excludes_win(self):
        with tempfile.TemporaryDirectory() as td:
            ctx=NS(args=NS(network_scope=None),program_policy=None)
            self.assertFalse(ports._authorized_addresses(ctx,['owned.invalid'])[0])
            p=Path(td)/'network.txt';p.write_text('192.0.2.0/24\n');ctx.args.network_scope=str(p)
            addresses=[(2,1,6,'',('192.0.2.10',0)),(2,1,6,'',('198.51.100.1',0))]
            with patch.object(ports.socket,'getaddrinfo',return_value=addresses):
                approved,denied=ports._authorized_addresses(ctx,['owned.invalid'])
                self.assertEqual(approved,['192.0.2.10']);self.assertEqual(len(denied),1)
                ctx.program_policy={'included_assets':['192.0.2.10'],'excluded_assets':['192.0.2.10']}
                self.assertFalse(ports._authorized_addresses(ctx,['owned.invalid'])[0])


if __name__=='__main__':unittest.main()
