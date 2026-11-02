"""Scope/rate/passive checks must precede DNS and recon child dispatch."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from core.scope import Scope
from phases import recon


class ReconPreflightTests(unittest.TestCase):
    def context(self, root, **profile):
        calls=[]
        runner=SimpleNamespace(has=lambda n: True,
            read_lines=lambda p: Path(p).read_text().splitlines() if Path(p).exists() else [],
            write_lines=lambda p,v: Path(p).write_text('\n'.join(sorted(v))),
            run=lambda cmd,**kw: (calls.append(cmd) or (0,'api.example.invalid\n','')))
        ctx=SimpleNamespace(targets=['api.example.invalid'],scope=Scope([],[]),scope_excludes=[],
            output=root,runner=runner,profile={'active_probes':True,'rate_limit':{'global_rps':1,'per_target_rps':1},**profile},
            phase_state={},log=lambda *a:None,save_finding=lambda *a:None)
        return ctx,calls

    def test_passive_and_policy_zero_never_call_any_source(self):
        for policy_zero in (False,True):
            with self.subTest(policy_zero=policy_zero),tempfile.TemporaryDirectory() as td:
                root=Path(td);(root/'recon').mkdir();ctx,calls=self.context(root)
                if policy_zero:
                    ctx.program_policy={'max_requests_per_second':0}
                else:
                    ctx.profile['active_probes']=False
                with patch.object(recon,'_crtsh',side_effect=AssertionError('provider contacted')):
                    recon.run(ctx)
                self.assertEqual(calls,[])
                self.assertEqual(ctx.phase_state['alive_hosts'],[])
                self.assertEqual((root/'recon/alive.txt').read_text(),'')

    def test_denied_apex_is_not_sent_to_dns_basics(self):
        with tempfile.TemporaryDirectory() as td:
            ctx,calls=self.context(Path(td))
            recon._dns_basics(ctx,'example.invalid',Path(td))
            self.assertEqual(calls,[])

    def test_bruteforce_filters_candidates_before_dnsx_and_uses_ceiling(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ctx,calls=self.context(root);wordlist=root/'words';wordlist.write_text('api\nadmin\n')
            with patch.object(recon.seclists,'get',return_value=wordlist):
                recon._dns_bruteforce(ctx,'example.invalid',root)
            self.assertEqual(len(calls),1)
            cmd=calls[0]
            self.assertEqual(Path(cmd[cmd.index('-l')+1]).read_text().splitlines(),['api.example.invalid'])
            self.assertEqual(cmd[cmd.index('-rl')+1],'1')

    def test_fractional_child_rate_fails_closed_instead_of_rounding_up(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ctx,calls=self.context(root,rate_limit={'global_rps':0.25,'per_target_rps':0.25})
            wordlist=root/'words';wordlist.write_text('api\n')
            with patch.object(recon.seclists,'get',return_value=wordlist):
                recon._dns_bruteforce(ctx,'example.invalid',root)
            self.assertEqual(calls,[])


if __name__=='__main__': unittest.main(verbosity=2)
