"""F10: rejected ZIP members never enter CRC/decompression preflight."""
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from core.safe_archive import safe_extract_zip


class ArchivePreflightTests(unittest.TestCase):
    def test_budget_rejects_before_any_decompression(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); z = root/'input.zip'
            with zipfile.ZipFile(z, 'w', zipfile.ZIP_DEFLATED) as f:
                f.writestr('large', 'x'*4096)
            with patch.object(zipfile.ZipFile, 'testzip', side_effect=AssertionError('eager CRC')), \
                 patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('decompression')):
                report = safe_extract_zip(z, root/'out', max_file_bytes=1)
            self.assertEqual(report.extracted, 0)
            self.assertTrue(report.skipped)

    def test_streaming_crc_detects_corruption(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); z = root/'input.zip'
            with zipfile.ZipFile(z, 'w', zipfile.ZIP_STORED) as f:
                f.writestr('bad', b'UNIQUE_CRC_FIXTURE')
            z.write_bytes(z.read_bytes().replace(b'UNIQUE_CRC_FIXTURE', b'BROKEN_CRC_FIXTURE'))
            report = safe_extract_zip(z, root/'out')
            self.assertEqual(report.extracted, 0)
            self.assertTrue(report.rejected)
            self.assertFalse((root/'out/bad').exists())


if __name__ == '__main__': unittest.main(verbosity=2)
