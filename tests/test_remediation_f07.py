"""F07: confirmed severity and incomplete execution are independent CI gates."""
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tbhm
from phases import evidence_finalize, report


class CiGateTests(unittest.TestCase):
    def test_confirmed_gate_keeps_leads(self):
        lead = dict(severity='HIGH', title='candidate', phase='test', finding_class='lead')
        confirmed = dict(severity='HIGH', title='verified', phase='test', finding_class='confirmed',
            verified=True, verification_method='fixture', verification_state='confirmed',
            assertion_passed=True, negative_control_passed=True, repeatability_passed=True)
        from test_support import verified_fields
        with tempfile.TemporaryDirectory() as capture_root:
            confirmed.update(verified_fields(capture_root))
        for rows, fail in [([lead], False), ([lead, confirmed], True)]:
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as td:
                store = SimpleNamespace(all_findings=lambda: list(rows),
                    severity_counts=lambda: dict(Counter(f['severity'] for f in rows)))
                ctx = SimpleNamespace(args=SimpleNamespace(ci=True), storage=store, output=Path(td),
                    phase_state={}, profile={}, targets=[], log=lambda *a: None)
                evidence_finalize.run(ctx)
                self.assertEqual(ctx.phase_state['ci_gate_fail'], fail)
                self.assertEqual(store.all_findings(), rows)

    def test_main_detects_crashes_missing_modules_and_missing_reports(self):
        for kind in ['crash', 'missing_module', 'missing_report', 'clean']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as td:
                def fail(ctx): raise RuntimeError('synthetic failure')
                def importer(name):
                    if name == 'diagnostics':
                        if kind == 'missing_module': return None
                        return SimpleNamespace(run=fail if kind == 'crash' else lambda c: None)
                    if name == 'report':
                        return SimpleNamespace(run=lambda c: None) if kind == 'missing_report' else report
                    return evidence_finalize
                argv = ['tbhm', '-d', 'allowed.invalid', '-y', '--ci', '--silent',
                    '--phases', 'diagnostics,report', '--no-bootstrap', '--no-ai-observe',
                    '--no-exploitability-assessment', '-o', td]
                with patch.object(sys, 'argv', argv), patch.object(tbhm, 'import_phase', side_effect=importer):
                    code = tbhm.main()
                self.assertEqual(code, 0 if kind == 'clean' else 2)
                incomplete = json.loads((Path(td)/'ci_incomplete_summary.json').read_text())
                self.assertEqual(incomplete['gate_fail'], kind != 'clean')
                self.assertTrue((Path(td)/'junit_incomplete.xml').is_file())


if __name__ == '__main__': unittest.main(verbosity=2)
