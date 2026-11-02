import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]));sys.path.insert(0,str(Path(__file__).resolve().parent))
from fixtures_v424 import Fixture
from core.assertion_engine import evaluate
from core.finding_class import classify

class StrictClasses(unittest.TestCase):
    def fixture(self,mode='vulnerable'):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);f=Fixture(t.name,mode);self.addCleanup(f.close);return f
    def bundles(self,f):
        report=f.run();rows=f.store.conn.execute('SELECT assertion_json,proof_json FROM validation_attempts ORDER BY id').fetchall()
        return report,[(json.loads(r[0]),json.loads(r[1])) for r in rows]
    def test_live_vulnerable_filesystem_and_owned_role_function_confirm(self):
        f=self.fixture();report,_=self.bundles(f);self.assertEqual([c['result'] for c in report['cases']],['pass','pass'])
        self.assertEqual(len(f.hits),11)
        findings=f.store.all_findings();self.assertEqual(len(findings),2)
        self.assertTrue(all(classify(r)=='confirmed' for r in findings))
        self.assertTrue(all('privileged-fixture' not in p.read_text() for p in (f.runroot/'evidence/captures').glob('*.json')))
    def test_patched_controls_hold_without_confirmation(self):
        f=self.fixture('secure');report,_=self.bundles(f);self.assertEqual([c['result'] for c in report['cases']],['fail','fail']);self.assertEqual(f.store.all_findings(),[])
    def test_missing_controls_and_repeats_remain_inconclusive(self):
        f=self.fixture();_,bundles=self.bundles(f)
        for a,p in bundles:
            for key in ('negative_control','repeats'):
                q=copy.deepcopy(p);q['captures'].pop(key);self.assertEqual(evaluate(a,q,evidence_root=f.runroot)['result'],'inconclusive')
            if a['vulnerability_class']=='bfla':
                q=copy.deepcopy(p);q['captures'].pop('privacy_control');self.assertEqual(evaluate(a,q,evidence_root=f.runroot)['result'],'inconclusive')
    def test_tampered_signature_replayed_capture_wrong_class_and_cross_binding_refused(self):
        f=self.fixture();_,bundles=self.bundles(f)
        for a,p in bundles:
            for attack in ('signature','repeat','class','request','marker'):
                x,y=copy.deepcopy(a),copy.deepcopy(p)
                if attack=='signature':y['captures']['mutation']['signature']='0'*64
                elif attack=='repeat':y['captures']['repeats'][1]=y['captures']['repeats'][0]
                elif attack=='class':x['vulnerability_class']='ssti'
                elif attack=='request':
                    if x['vulnerability_class']=='bfla':x['function_id']='other'
                    else:x['traversal_value']='../tbhm-proof-'+'1'*32+'.txt'
                else:x['canary']='TBHM_'+'0'*32
                self.assertNotEqual(evaluate(x,y,evidence_root=f.runroot)['result'],'pass',attack)
    def test_public_function_and_expired_privileged_identity_are_inconclusive(self):
        for mode in ('public','expired'):
            f=self.fixture(mode);report=f.run(('bfla',));self.assertEqual(report['cases'][0]['result'],'inconclusive')
    def test_metamorphic_order_noise_and_missing_generic_assertion(self):
        f=self.fixture();_,bundles=self.bundles(f)
        for a,p in bundles:
            q=copy.deepcopy(p);q['captures']['repeats'].reverse()
            x=dict(reversed(list(a.items())));x['untrusted_scanner_confidence']=1.0
            self.assertEqual(evaluate(x,q,evidence_root=f.runroot)['result'],'pass')
            x['failure_conditions']=[];self.assertEqual(evaluate(x,q,evidence_root=f.runroot)['result'],'inconclusive')
    def test_complete_plan_is_validated_before_any_contact(self):
        from core.strict_replay import run
        from unittest.mock import patch
        f=self.fixture();f.plan['cases']=[f.case('path_traversal'),f.case('bfla')];f.plan['cases'][1]['negative_control_url']='http://127.0.0.2:1/no'
        f.path.write_text(json.dumps(f.plan))
        with patch.dict('os.environ',f.env()):
            with self.assertRaises(PermissionError):run(f.ctx)
        self.assertEqual(f.hits,[])
    def test_signed_unstable_repeat_and_physical_tamper_are_refused(self):
        from core.proof_contracts import capture_snapshot
        f=self.fixture();_,bundles=self.bundles(f)
        for a,p in bundles:
            row=json.loads((f.runroot/p['captures']['repeats'][0]['path']).read_text())
            req=row['request'];req['headers']['Authorization']=f.env()['TBHM_FIXTURE_MEMBER']
            ref=capture_snapshot(f.runroot,test_id=a['test_id'],vulnerability_class=a['vulnerability_class'],role='repeat',actor_id=row['actor_id'],request=req,response={'status':403,'headers':{},'body':'denied'})
            q=copy.deepcopy(p);q['captures']['repeats'][0]=ref
            self.assertEqual(evaluate(a,q,evidence_root=f.runroot)['result'],'inconclusive')
            for kind in ('access_control','sensitive_data_exposure','open_redirect','ssti','path_traversal','bfla'):
                if kind==a['vulnerability_class']:continue
                x=dict(a,vulnerability_class=kind);self.assertNotEqual(evaluate(x,p,evidence_root=f.runroot)['result'],'pass')
            path=f.runroot/p['captures']['mutation']['path'];path.chmod(0o600);path.write_bytes(path.read_bytes()+b' ')
            self.assertEqual(evaluate(a,p,evidence_root=f.runroot)['result'],'inconclusive')

if __name__=='__main__':unittest.main(verbosity=2)
