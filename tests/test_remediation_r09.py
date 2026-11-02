"""Risk 2.1/R09: unresolved --recheck-only never falls back to a full scan."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tbhm


class EmptyRecheckTests(unittest.TestCase):
    def test_missing_and_empty_prior_are_blocked(self):
        for missing in [False, True]:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as td:
                root = Path(td); prior = root/'prior.json'
                if not missing: prior.write_text(json.dumps([]))
                ran = []
                argv = ['tbhm', '-d', 'allowed.invalid', '-y', '--silent',
                    '--phases', 'diagnostics,report', '--no-bootstrap', '--no-ai-observe',
                    '--recheck-only', str(prior), '-o', str(root/'run')]
                with patch.object(sys, 'argv', argv), patch.object(tbhm, 'import_phase',
                        side_effect=lambda name: SimpleNamespace(run=lambda c: ran.append(name))):
                    self.assertEqual(tbhm.main(), 2)
                self.assertEqual(ran, [])


if __name__ == '__main__': unittest.main(verbosity=2)
