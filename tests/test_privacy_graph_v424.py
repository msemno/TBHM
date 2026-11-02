import base64
import bz2
import json
import lzma
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.delivery_privacy_audit import audit
from core.evidence_manifest import build_manifest
from core.evidence_graph import build
from core.proof_contracts import ConfirmationReceipt

class PrivacyGraph(unittest.TestCase):
    def audit_file(self,name,data,limit=64*1024*1024):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/name).write_bytes(data);build_manifest(root)
            with patch.dict(os.environ,{'TBHM_PRIVACY_MARKER':'fixture-marker-<26>'}):return audit(root,['TBHM_PRIVACY_MARKER'],maximum_bytes=limit)
    def test_extra_encodings_and_nested_bzip_xz(self):
        value='fixture-marker-<26>'
        encodings=[value.encode('utf-32le'),value.encode('utf-32be'),value.encode().hex().encode(),''.join('%%%02X'%b for b in value.encode()).encode(),''.join('&#%d;'%ord(c) for c in value).encode(),base64.urlsafe_b64encode(value.encode()).rstrip(b'=')]
        for raw in encodings:
            self.assertEqual(self.audit_file('encoded.bin',raw)['status'],'fail')
        for name,raw in [('evidence.bz2',bz2.compress(value.encode())),('nested.xz',lzma.compress(bz2.compress(value.encode())))]:
            result=self.audit_file(name,raw);self.assertEqual(result['status'],'fail');self.assertNotIn(value,json.dumps(result))
    def test_xz_memory_and_concatenated_surfaces_remain_incomplete(self):
        combined=lzma.compress(b'harmless')+lzma.compress(b'other')
        self.assertEqual(self.audit_file('concat.xz',combined)['status'],'incomplete')
        huge=lzma.compress(b'harmless',filters=[{'id':lzma.FILTER_LZMA2,'dict_size':128*1024*1024}])
        self.assertEqual(self.audit_file('dictionary.xz',huge)['status'],'incomplete')
    def test_unknown_image_and_expansion_budget_are_not_clean(self):
        self.assertEqual(self.audit_file('image.png',b'\x89PNGopaque')['status'],'incomplete')
        self.assertEqual(self.audit_file('bomb.bz2',bz2.compress(b'A'*100000),5000)['status'],'incomplete')
    def test_integrity_checked_empty_lock_has_no_unreviewed_content(self):
        self.assertEqual(self.audit_file('ledger.dispatch.lock',b'')['status'],'pass')
    def test_graph_rejects_imported_confirmation_flags(self):
        f={'id':1,'url':'https://example.test/a','verified':True,'finding_class':'confirmed','parameter':'q'}
        graph=build([f]);node=next(n for n in graph['nodes'] if n['kind']=='finding');self.assertFalse(node['proof_verified'])
        self.assertNotEqual(node['evidence_state'],'confirmed')
        self.assertTrue(graph['relationship_nodes']);self.assertTrue(all(not e['confirms_exploit_edge'] for e in graph['relationship_edges']))
    def test_graph_retains_receipt_authority_without_confirming_chain(self):
        f={'id':1,'url':'https://example.test/a','verified':True,'finding_class':'confirmed',
           '_confirmation_receipt':ConfirmationReceipt(verifier_version='tbhm-proof-v2',test_id='fixture'),
           'assertion':{'limited_actor':'member'},'proof':{'captures':{'mutation':{'path':'evidence/captures/example.json','sha256':'a'*64}}}}
        graph=build([f]);self.assertTrue(next(n for n in graph['nodes'] if n['kind']=='finding')['proof_verified'])
        self.assertEqual({n['kind'] for n in graph['relationship_nodes']},{'route','identity','evidence'})
        self.assertFalse(any(e['confirms_exploit_edge'] for e in graph['relationship_edges']))
    def test_operator_queue_uses_the_same_receipt_authority(self):
        from core.operator_view import write
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as td:
            f={'id':1,'url':'https://example.test/a','severity':'HIGH','verified':True,'finding_class':'confirmed'}
            ctx=SimpleNamespace(output=Path(td),storage=SimpleNamespace(all_findings=lambda:[f]))
            result=write(ctx);self.assertFalse(result['queue'][0]['proof_verified']);self.assertNotEqual(result['queue'][0]['evidence_state'],'confirmed')

if __name__=='__main__':unittest.main(verbosity=2)
