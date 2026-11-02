"""Offline regression coverage for incident-derived compatibility corrections."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock
from core.taint_engine import analyze_js, js_runtime_context
from core.nuclei_runtime import installed_templates, interpret_execution, evidence_fields
from core.origin_firewall_analysis import review_origin_candidates, review_firewall_pairs
from phases.nuclei_extended import _to_finding
from phases.network_firewall_tooling import import_results

class OperationalRepairs(unittest.TestCase):
    def test_diagnostic_version_probe_does_not_execute_wrapper(self):
        from unittest.mock import patch
        from phases import diagnostics
        with patch('phases.diagnostics.shutil.which', return_value='/fake/bin/nuclei'):
            with patch('phases.diagnostics.subprocess.run', side_effect=AssertionError('unvetted wrapper executed')):
                self.assertEqual(diagnostics._get_version('nuclei'), 'detected / not probed')

    def test_third_party_path_does_not_suppress_findings(self):
        from core.source_provenance import classify_source
        hit = classify_source('web/node_modules/pkg/a.js', 'const a=1')
        self.assertEqual(hit['status'], 'third-party-likely')
        self.assertFalse(hit['suppress_automatically'])
        self.assertEqual(classify_source('src/app.js','const a=1')['status'],'unknown-or-first-party')

    def test_browser_query_cannot_be_sql_injection(self):
        script='const data = location.search;\ndb.query(data);\n'
        self.assertFalse([f for f in analyze_js(script,'/public/app.js') if f.sink_cwe=='CWE-89'])
        self.assertTrue([f for f in analyze_js('const x = location.search;\nelement.innerHTML = x;', '/public/app.js') if f.sink_cwe=='CWE-79'])

    def test_node_sql_flow_retained(self):
        flows=analyze_js('const value = req.query.id;\ndb.query(value);','/server/api.js')
        self.assertEqual([f.sink_cwe for f in flows],['CWE-89'])

    def test_nuclei_classifies_invalid_executions(self):
        self.assertEqual(interpret_execution(2,'unknown flag: -jsonl'), 'tool-incompatible')
        self.assertEqual(interpret_execution(124,''), 'timeout')
        self.assertEqual(interpret_execution(1,'',output_present=False), 'tool-error')
        self.assertEqual(interpret_execution(0,'',output_present=False), 'no-matches')

    def test_nuclei_templates_have_no_install_side_effect(self):
        api=Mock()
        api.nuclei_templates_root.return_value=Path('/tmp/templates')
        api.nuclei_template_count.return_value=14_035
        self.assertTrue(installed_templates(api)['ready'])
        api.ensure_nuclei_templates.assert_not_called()

    def test_imported_scanner_match_without_capture_remains_lead(self):
        obj={'template-id':'tbhm-test','matched-at':'https://example.test/a','info':{'severity':'high','name':'test'}}
        f=_to_finding(obj,'cves',70)
        self.assertEqual(f['finding_class'],'lead')
        self.assertEqual(f['evidence_capture_status'],'missing-http-exchange')
        self.assertEqual(evidence_fields({'request':'GET / HTTP/1.1','response':'HTTP/1.1 200 OK'})['finding_class'],'supported')

    def test_nmap_xml_host_address_survives_boolean_false_element(self):
        xml='<nmaprun><host><address addr="192.0.2.18" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>'
        with TemporaryDirectory() as tmp:
            p=Path(tmp)/'result.xml';p.write_text(xml)
            ctx=Mock();ctx.save_finding=Mock()
            self.assertEqual(import_results(ctx,p),1)
            self.assertEqual(ctx.save_finding.call_args[0][0]['target'],'192.0.2.18')

    def test_origin_is_candidate_not_permission(self):
        rows=[{'hostname':'app.example.test','ip':'192.0.2.42','source':'historical-dns'},
              {'hostname':'app.example.test','ip':'192.0.2.42','source':'user-inventory'}]
        o=review_origin_candidates(rows,[])
        self.assertEqual(len(o),1)
        self.assertEqual(o[0]['authorization'],'not-approved')
        self.assertEqual(o[0]['state'],'candidate-only')
        self.assertEqual(review_origin_candidates(rows,['192.0.2.42'])[0]['authorization'],'approved-ip')

    def test_firewall_status_differential_is_not_vuln(self):
        result=review_firewall_pairs([{'test_id':'lab-1','baseline':{'status':200},'variant':{'status':403}}])[0]
        self.assertEqual(result['observation'],'possible-filter-differential')
        self.assertEqual(result['security_conclusion'],'unverified')

if __name__=='__main__': unittest.main()
