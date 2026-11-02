import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.evidence_redaction import register_secrets
from core.evidence_manifest import build_manifest, verify_manifest
from core.evaluation import evaluate


class DeliveryTests(unittest.TestCase):
    def test_export_redacts_supported_text_and_sqlite_without_touching_live(self):
        secret = 'opaque-delivery-canary-498001'
        register_secrets([secret])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for suffix in ('sarif', 'har', 'json', 'txt', 'svg'):
                (root/('fixture.'+suffix)).write_text(json.dumps({'message': secret, 'nested': {'token': 'another-private-value'}}))
            with sqlite3.connect(root/'tbhm.db') as db:
                db.execute('CREATE TABLE audit (id INTEGER PRIMARY KEY, message TEXT)')
                db.execute('INSERT INTO audit(message) VALUES (?)', (secret,))
            manifest = build_manifest(root)
            snapshot = root/manifest['snapshot_dir']
            for path in snapshot.rglob('*'):
                if path.is_file(): self.assertNotIn(secret.encode(), path.read_bytes())
            self.assertIn(secret, (root/'fixture.sarif').read_text())
            with sqlite3.connect(snapshot/'tbhm.db') as db:
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                self.assertEqual(db.execute('SELECT message FROM audit').fetchone()[0], '[REDACTED]')
            self.assertTrue(verify_manifest(root)['passed'])
            for path in snapshot.rglob('*'):
                if not path.is_file(): continue
                original = path.read_bytes(); path.chmod(0o644); path.write_bytes(original+b'!')
                self.assertFalse(verify_manifest(root)['passed'], path.name)
                path.write_bytes(original)
            self.assertTrue(verify_manifest(root)['passed'])

    def test_missing_predictions_keep_empty_classes_visible(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); labels, predictions = root/'labels.json', root/'predictions.json'
            labels.write_text(json.dumps([{'id': 'a', 'category': 'api', 'vulnerable': True},
                                         {'id': 'b', 'category': 'mobile', 'vulnerable': True},
                                         {'id': 'c', 'category': 'api', 'vulnerable': True}]))
            predictions.write_text('[{"id":"a","detected":true}]')
            report = evaluate(labels, predictions)
            self.assertEqual(report['by_category']['mobile']['unresolved'], 1)
            self.assertEqual(report['by_category']['mobile']['recall_lower_bound'], 0)
            self.assertEqual(report['by_category']['api']['recall_lower_bound'], .5)
            self.assertAlmostEqual(report['prediction_coverage'], 1/3)
            self.assertEqual(report['status'], 'partial')


if __name__ == '__main__': unittest.main(verbosity=2)
