"""Paired local XML/aapt fixtures for explicit application boolean settings."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from phases import mobile_scan

ATTRS={'debuggable':'Debuggable application','allowBackup':'Backup allowed',
       'usesCleartextTraffic':'Cleartext traffic allowed'}


class ManifestTests(unittest.TestCase):
    def scan(self,text,dump=False):
        findings=[]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'AndroidManifest.xml').write_text(text)
            ctx=SimpleNamespace(log=lambda *a:None,save_finding=findings.append)
            with patch('shutil.which',side_effect=lambda x:'aapt' if dump and x=='aapt' else None), \
                 patch.object(mobile_scan.subprocess,'run',return_value=SimpleNamespace(stdout=text,returncode=0)):
                mobile_scan._analyze_manifest(ctx,root/'fixture.apk',root)
        return {f['title'] for f in findings}

    def test_paired_xml_and_aapt_fixtures(self):
        # Six vulnerable and six clean cases, counted by the tested attribute.
        tp=fp=fn=tn=0
        for dump in (False,True):
            for attr,title in ATTRS.items():
                for enabled in (False,True):
                    with self.subTest(dump=dump,attribute=attr,enabled=enabled):
                        if dump:
                            values='\n'.join(f'    A: android:{key}(0x01010000)=(type 0x12)'+
                                ('0xffffffff' if enabled and key==attr else '0x0') for key in ATTRS)
                            text='E: manifest (line=1)\n  E: application (line=2)\n'+values+\
                                 '\n    E: meta-data (line=3)\n      A: android:value(0x01010000)="true"'
                        else:
                            values=' '.join(f'android:{key}="'+str(enabled and key==attr).lower()+'"' for key in ATTRS)
                            text='<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application '+values+\
                                 '><meta-data android:value="true"/></application></manifest>'
                        detected='Android manifest: '+title in self.scan(text,dump)
                        tp+=int(enabled and detected);fn+=int(enabled and not detected)
                        fp+=int(not enabled and detected);tn+=int(not enabled and not detected)
                        self.assertEqual(detected,enabled)
        print(f'paired_application_booleans: TP={tp} FP={fp} FN={fn} TN={tn} cases=12')

    def test_unstructured_wrong_namespace_and_non_application_are_not_proof(self):
        for text in ('usesCleartextTraffic true',
                     '<manifest><application usesCleartextTraffic="true"/></manifest>',
                     '<manifest xmlns:a="http://schemas.android.com/apk/res/android"><activity a:usesCleartextTraffic="true"/></manifest>',
                     '<!DOCTYPE manifest [<!ENTITY x "true">]><manifest><application/></manifest>'):
            with self.subTest(text=text):
                self.assertNotIn('Android manifest: Cleartext traffic allowed',self.scan(text))


if __name__=='__main__':unittest.main(verbosity=2)
