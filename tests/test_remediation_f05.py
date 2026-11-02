"""F05: mandatory OPSEC runs before bootstrap/phases and cannot be resumed away."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tbhm
from phases import opsec_preflight


class RequiredGateTests(unittest.TestCase):
    def test_required_gate_halts_before_any_later_work(self):
        for phases in ['opsec_preflight,diagnostics,report', 'diagnostics,report']:
            with self.subTest(phases=phases), tempfile.TemporaryDirectory() as td:
                ran = []
                def importer(name):
                    if name == 'opsec_preflight': return opsec_preflight
                    return SimpleNamespace(run=lambda ctx: ran.append(name))
                argv = ['tbhm', '-d', 'allowed.invalid', '-y', '--phases', phases,
                        '--require-opsec', '--no-ai-observe', '--silent', '-o', td]
                with patch.object(sys, 'argv', argv), patch.object(tbhm, 'import_phase', side_effect=importer), \
                     patch('core.bootstrap.ensure_nuclei_templates') as bootstrap, \
                     patch('core.bootstrap.ensure_seclists'), patch('core.bootstrap.ensure_custom_templates'):
                    self.assertEqual(tbhm.main(), 2)
                self.assertEqual(ran, [])
                bootstrap.assert_not_called()
                self.assertTrue((Path(td)/'REPORT_final.md').is_file())
                partial = json.loads((Path(td)/'PARTIAL_RUN.json').read_text())
                self.assertEqual(partial['failed_gate'], 'opsec_preflight')

    def test_missing_mandatory_module_is_fatal(self):
        with tempfile.TemporaryDirectory() as td:
            argv = ['tbhm', '-d', 'allowed.invalid', '-y', '--phases', 'report',
                    '--require-opsec', '--no-bootstrap', '--no-ai-observe', '--silent', '-o', td]
            with patch.object(sys, 'argv', argv), patch.object(tbhm, 'import_phase', return_value=None):
                self.assertEqual(tbhm.main(), 2)


if __name__ == '__main__': unittest.main(verbosity=2)
