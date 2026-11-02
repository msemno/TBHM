"""Outer extraction deadline must cover a worker stuck before reporting."""
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from core import safe_archive as sa


class ArchiveDeadlineTests(unittest.TestCase):
    def test_stalled_extractor_is_killed_by_its_own_deadline(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); archive = root/'input.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('clean.txt', 'clean fixture')
            with patch.object(sa, '_EXTRACTION_TIMEOUT_SECONDS', 0.2, create=True), \
                 patch.object(sa, '_EXTRACT_WORKER_CODE', 'import time; time.sleep(60)', create=True):
                start = time.monotonic()
                report = sa.safe_extract_zip(archive, root/'out')
            self.assertLess(time.monotonic() - start, 2)
            self.assertFalse(report.safe)
            self.assertEqual(report.extracted, 0)
            self.assertTrue(report.truncated)
            self.assertTrue(any('timeout' in r for r in report.rejected))

    def test_clean_archive_still_extracts_with_the_same_report(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); archive = root/'input.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('clean.txt', 'clean fixture')
            report = sa.safe_extract_zip(archive, root/'out')
            self.assertTrue(report.safe)
            self.assertEqual(report.extracted, 1)
            self.assertEqual((root/'out/clean.txt').read_text(), 'clean fixture')


if __name__ == '__main__':
    unittest.main(verbosity=2)
