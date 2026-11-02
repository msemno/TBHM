"""Additive compatibility and explicit model selection; no inference service required."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.compare_release_contracts import additive_columns
from core.ai_plane import build_plane
from core.ai_plane.home import get


class UpgradeContracts(unittest.TestCase):
    def test_nullable_and_defaulted_additions_are_compatible(self):
        old={'cases':[[0,'id','INTEGER',0,None,1],[1,'label','TEXT',0,None,0]]}
        for added in ([2,'note','TEXT',0,None,0],[2,'state','TEXT',1,"'pending'",0]):
            self.assertTrue(additive_columns(old,{'cases':old['cases']+[added],'new_table':[]}))
        self.assertFalse(additive_columns(old,{'cases':old['cases']+[[2,'required','TEXT',1,None,0]]}))
        self.assertFalse(additive_columns(old,{'cases':old['cases'][:1]}))
        self.assertFalse(additive_columns(old,{}))

    def test_model_lock_default_and_explicit_override_do_not_mutate_the_lock(self):
        with tempfile.TemporaryDirectory() as td:
            home=get(td,create=True)
            raw=json.dumps({'advisor_model':'locked-advisor','embedding_model':'locked-embedding'})
            home.model_lock.write_text(raw)
            captured=[]
            def runtime(args):
                captured.append(args.local_llm_model)
                return NS(client=NS(available=lambda:(False,'fixture')))
            args=NS(ai_home=td,local_llm_url='http://127.0.0.1:11435',local_llm_model='requested-advisor',
                    ai_embedding_model='requested-embedding',ai_advisor_model=None)
            with patch('core.llm_local.runtime_from_args',side_effect=runtime):
                plane=build_plane(args,create=True)
                self.assertEqual(captured[-1],'locked-advisor');self.assertEqual(plane.embedder.model,'locked-embedding');plane.close()
                args._local_llm_model_explicit=True;args._ai_embedding_model_explicit=True
                plane=build_plane(args,create=True)
                self.assertEqual(captured[-1],'requested-advisor');self.assertEqual(plane.embedder.model,'requested-embedding');plane.close()
            self.assertEqual(home.model_lock.read_text(),raw)


if __name__=='__main__':unittest.main()
