import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.compliance_catalog import test_id_coverage


class CoverageTests(unittest.TestCase):
    def test_phase_only_or_untrusted_assertion_is_not_a_test(self):
        report = test_id_coverage([{'id': 1, 'phase': 'access_control', 'status': 'passed'},
                                   {'id': 2, 'phase': 'strict_finding_validation', 'status': 'passed',
                                    'assertion_json': '{"vulnerability_class":"access_control"}'}])
        self.assertEqual(report['counts']['executed'], 0)
        self.assertTrue(report['catalog_is_partial'])

    def test_class_binds_to_explicit_ids(self):
        report = test_id_coverage([{'id': 7, 'phase': 'strict_finding_validation',
                                    'status': 'failed-security-control',
                                    'assertion_json': '{"schema":"tbhm.proof/2","vulnerability_class":"access_control"}'}])
        executed = {r['id'] for r in report['records'] if r['status'] == 'executed'}
        self.assertEqual(executed, {'WSTG-ATHZ-04','API1:2023','V8.2.2'})
        self.assertNotIn('WSTG-INPV-05', executed)
        self.assertTrue(all(r['completed_test_count'] == 1 for r in report['records'] if r['status'] == 'executed'))

    def test_inconclusive_is_not_executed(self):
        report = test_id_coverage([{'id': 10, 'phase': 'strict_finding_validation',
                                    'status': 'inconclusive',
                                    'assertion': {'schema':'tbhm.proof/2','vulnerability_class':'access_control'}}])
        self.assertEqual(report['counts']['executed'], 0)
        self.assertEqual(report['counts']['inconclusive'], 3)


if __name__ == '__main__': unittest.main()
