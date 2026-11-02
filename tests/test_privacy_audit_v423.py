import base64
import gzip
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.delivery_privacy_audit import audit
from core.evidence_manifest import build_manifest


class PrivacyAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.canary='opaque-'+uuid.uuid4().hex
    def tearDown(self):self.temp.cleanup()
    def inspect(self,**kwargs):
        with patch.dict(os.environ,{'TBHM_AUDIT_CANARY':self.canary}):
            report=audit(self.root,['TBHM_AUDIT_CANARY'],**kwargs)
        self.assertNotIn(self.canary,json.dumps(report))
        self.assertNotIn(base64.b64encode(self.canary.encode()).decode(),json.dumps(report))
        return report

    def test_zip_utf16_and_gzip_tar_contents_are_scanned_without_extracting(self):
        with zipfile.ZipFile(self.root/'nested.zip','w',zipfile.ZIP_DEFLATED) as z:
            z.writestr('private.bin',self.canary.encode('utf-16le'))
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w') as tar:
            data=self.canary.encode();info=tarfile.TarInfo('inside.txt');info.size=len(data);tar.addfile(info,io.BytesIO(data))
        (self.root/'bundle.tar.gz').write_bytes(gzip.compress(buf.getvalue()))
        build_manifest(self.root)
        report=self.inspect()
        self.assertEqual(report['status'],'fail')
        self.assertGreaterEqual(report['containers_scanned'],3)
        self.assertTrue(any(r['encoding']=='utf16le' for r in report['hits']))
        self.assertFalse((self.root/'inside.txt').exists())

    def test_opaque_formats_never_receive_a_clean_result(self):
        (self.root/'screenshot.png').write_bytes(b'\x89PNG\r\n\x1a\n'+b'opaque pixels')
        build_manifest(self.root)
        report=self.inspect()
        self.assertEqual(report['status'],'incomplete')
        self.assertTrue(report['incomplete'])

    def test_clean_supported_delivery_and_later_mutation(self):
        (self.root/'notes.txt').write_text('Reviewed harmless text.')
        manifest=build_manifest(self.root)
        report=self.inspect();self.assertEqual(report['status'],'pass')
        target=self.root/manifest['snapshot_dir']/'notes.txt'
        target.chmod(0o644);target.write_text('Changed after seal.')
        self.assertEqual(self.inspect()['status'],'fail')

    def test_decompression_budgets_remain_incomplete(self):
        (self.root/'bomb.gz').write_bytes(gzip.compress(b'x'*100000))
        build_manifest(self.root)
        report=self.inspect(maximum_bytes=6000)
        self.assertEqual(report['status'],'incomplete')
        self.assertTrue(any('budget' in item['reason'] for item in report['incomplete']))

    def test_unsafe_zip_member_never_extracts(self):
        with zipfile.ZipFile(self.root/'unsafe.zip','w') as z:z.writestr('../../escape.txt',self.canary)
        build_manifest(self.root)
        report=self.inspect()
        # The stored canary is also visible in the raw ZIP bytes, so the
        # strongest result is fail, alongside the unsupported-member record.
        self.assertEqual(report['status'],'fail')
        self.assertTrue(any('unsafe' in r['reason'] for r in report['incomplete']))

    def test_missing_canary_fails_before_any_privacy_claim(self):
        build_manifest(self.root)
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(ValueError):audit(self.root,['TBHM_AUDIT_CANARY'])


if __name__ == '__main__':unittest.main(verbosity=2)
