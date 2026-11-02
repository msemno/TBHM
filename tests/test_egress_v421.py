"""Regression: explicit egress diagnostic flag must not bypass --offline."""
import tempfile
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phases import egress_canary

class TestEgress(unittest.TestCase):
    def test_offline_makes_no_external_attempt(self):
        with tempfile.TemporaryDirectory() as td:
            logs=[]
            ctx=SimpleNamespace(args=SimpleNamespace(test_egress_canary=True,offline=True),
                                output=Path(td),log=lambda *row: logs.append(row))
            with (patch.object(egress_canary, '_tcp_probe', side_effect=AssertionError('unexpected TCP')),
                  patch.object(egress_canary, '_dns_probe', side_effect=AssertionError('unexpected DNS')),
                  patch.object(egress_canary, '_http_probe', side_effect=AssertionError('unexpected HTTP'))):
                egress_canary.run(ctx)
            self.assertTrue(logs)
            self.assertFalse((Path(td)/'egress'/'egress_matrix.json').exists())

if __name__ == '__main__': unittest.main()
