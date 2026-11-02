"""Migrated discovery GETs share attempt budgets and exact fractional pacing."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

from core.http_policy import BudgetedSession, RequestBlocked
from core.scope import Scope
from core.scoped_http import effective_rps, safe_get
import core.http_policy as hp


class Transport:
    def __init__(self): self.calls=[];self.headers={'User-Agent':'TBHM identifying'}
    def request(self, method, url, **kwargs):
        self.calls.append((method,url,kwargs))
        return SimpleNamespace(status_code=200,headers={})
    def get(self, url, **kwargs): return self.request('GET',url,**kwargs)


def context():
    return SimpleNamespace(targets=['allowed.invalid'],scope=Scope([],[]),scope_excludes=[],
        args=SimpleNamespace(proxy='http://127.0.0.1:8080'),
        profile={'active_probes':True,'rate_limit':{'global_rps':0.05,'per_target_rps':0.05},
                 'http_policy':{'request_budget':3,'ca_bundle':'/approved/ca.pem'}})


class HttpBrokerTests(unittest.TestCase):
    def test_new_adapters_cannot_reset_the_context_budget(self):
        ctx=context();raw=Transport();now=[0.0]
        api=BudgetedSession(ctx,raw,budget=20,max_rps=50)
        def attempt(i):
            try:
                if i%2: safe_get(ctx,raw,'https://allowed.invalid/discovery')
                else: api.request('GET','https://allowed.invalid/api')
            except RequestBlocked: pass
        with patch.object(hp.time,'monotonic',side_effect=lambda:now[0]), \
             patch.object(hp.time,'sleep',side_effect=lambda t:now.__setitem__(0,now[0]+t)):
            with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(attempt,range(12)))
        self.assertEqual(len(raw.calls),3)
        self.assertEqual(now[0],40.0)
        self.assertEqual(api.remaining,0)

    def test_discovery_uses_scope_action_tls_proxy_and_neutral_user_agent(self):
        ctx=context();raw=Transport()
        ctx.program_policy={'included_assets':['allowed.invalid'],'allowed_http_methods':['GET'],
                            'allowed_actions':['discovery'],'max_requests_per_second':1}
        safe_get(ctx,raw,'https://allowed.invalid/',headers={'User-Agent':'TBHM identifying'},verify=False)
        self.assertEqual(len(raw.calls),1)
        kwargs=raw.calls[0][2]
        self.assertEqual(kwargs['verify'],'/approved/ca.pem')
        self.assertEqual(kwargs['proxies'],{'http':ctx.args.proxy,'https':ctx.args.proxy})
        self.assertEqual(kwargs['headers']['User-Agent'],'Mozilla/5.0')
        self.assertFalse(kwargs['allow_redirects'])

    def test_zero_budget_passive_denied_and_invalid_rates_do_not_dispatch(self):
        for case in ('zero','passive','policy','nan','hard-zero'):
            with self.subTest(case=case):
                ctx=context();raw=Transport()
                if case=='zero':ctx.profile['http_policy']['request_budget']=0
                if case=='passive':ctx.profile['active_probes']=False
                if case=='policy':ctx.program_policy={'included_assets':['allowed.invalid'],
                    'allowed_actions':['api_fuzz'],'allowed_http_methods':['GET'],'max_requests_per_second':1}
                if case=='nan':ctx.profile['rate_limit']['global_rps']=float('nan')
                if case=='hard-zero':ctx.profile['rate_limit']['hard_cap']=0
                with self.assertRaises(RequestBlocked):safe_get(ctx,raw,'https://allowed.invalid/')
                self.assertEqual(raw.calls,[])
        self.assertEqual(effective_rps(context()),0.05)


if __name__=='__main__':unittest.main(verbosity=2)
