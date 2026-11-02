"""Package verification must also put policy and an outer deadline before CRC."""
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from core import package_verifier as pv


class PackageDeadlineTests(unittest.TestCase):
    def archive(self, root):
        archive=root/'fixture.zip'
        with zipfile.ZipFile(archive,'w') as z: z.writestr('clean','clean fixture')
        return archive

    def test_budget_rejection_never_enters_crc(self):
        with tempfile.TemporaryDirectory() as td:
            archive=self.archive(Path(td))
            algorithm=getattr(pv,'_verify_zip',pv.verify_zip)
            with patch.object(zipfile.ZipFile,'testzip',side_effect=AssertionError('CRC before budget')):
                result=algorithm(archive,max_uncompressed_bytes=1)
            self.assertFalse(result['passed'])
            self.assertTrue(any('exceeds policy' in issue for issue in result['issues']))

    def test_stalled_worker_is_stopped_without_external_watchdog(self):
        with tempfile.TemporaryDirectory() as td:
            archive=self.archive(Path(td))
            with patch.object(pv,'_VERIFY_TIMEOUT_SECONDS',0.2,create=True), \
                 patch.object(pv,'_VERIFY_WORKER_CODE','import time;time.sleep(60)',create=True):
                start=time.monotonic();result=pv.verify_zip(archive)
            self.assertLess(time.monotonic()-start,2)
            self.assertFalse(result['passed'])
            self.assertIn('verification-timeout',result['issues'])

    def test_clean_package_is_still_verified(self):
        with tempfile.TemporaryDirectory() as td:
            result=pv.verify_zip(self.archive(Path(td)))
            self.assertTrue(result['passed'],result)
            self.assertEqual(len(result['sha256']),64)


if __name__=='__main__': unittest.main(verbosity=2)
