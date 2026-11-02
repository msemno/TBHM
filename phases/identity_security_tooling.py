"""AD/Entra/ADCS posture and attack-path evidence integration (v3.9.5).

Read-only live collectors require an approval manifest. Credential attacks,
coercion, relay, ticket abuse and credential extraction are never auto-run.
Their results may be imported from a separately governed exercise.
"""
from __future__ import annotations
import json, os, re
from pathlib import Path
from core import redteam_utils as RT
from core.approval_gate import load_manifest, approved, summary as approval_summary
from core.scanner_normalizer import iter_result_files, parse_file, save_items

TEXT_EXT={'.txt','.log','.csv','.xml','.html'}

def _import_text(ctx,p):
    n=0; text=p.read_text(errors='ignore')[:10_000_000]
    patterns=[
      (r'\bESC(?:1[0-6]|[1-9])\b','AD CS escalation-path observation','HIGH','CWE-284'),
      (r'(?i)unconstrained delegation|resource[- ]based constrained delegation','Delegation-risk observation','HIGH','CWE-732'),
      (r'(?i)global administrator|privileged role|tenant[- ]wide consent','Privileged cloud-identity observation','HIGH','CWE-269'),
      (r'(?i)password never expires|legacy authentication|mfa.*disabled','Identity hygiene observation','MEDIUM','CWE-521'),
    ]
    for pat,title,sev,cwe in patterns:
        for m in re.finditer(pat,text):
            fid=ctx.save_finding({'phase':'identity_security_tooling','severity':sev,'confidence':'MEDIUM','title':f'{title} — {m.group(0)}'[:180],'target':p.name,'description':'Normalized read-only identity/AD posture evidence. It requires analyst review and an approved reproduction plan before any access claim.','evidence':text[max(0,m.start()-300):m.end()+500][:1600],'impact':'May expose a path to privilege escalation, domain compromise, tenant compromise, or durable unauthorized access.','remediation':'Review the referenced identity control, remove excessive privilege, harden certificate/role/delegation configuration, enable modern authentication and monitoring, then retest.','cwe':cwe,'finding_class':'lead','status':'lead','verified':False})
            if fid is not None:n+=1
    return n

def _live_readonly(ctx,out,manifest):
    n=0; ok,reason=approved(manifest,'identity_readonly',getattr(ctx.args,'ad_domain','') or '')
    if not getattr(ctx.args,'identity_live',False):return n, 'not requested'
    if not ok:return n, reason
    user=getattr(ctx.args,'ad_user',None); domain=getattr(ctx.args,'ad_domain',None); dcs=RT.get_dc_ips(ctx)
    ccache=os.environ.get('KRB5CCNAME','').strip()
    if not (user and domain and dcs and ccache):
        return n,'missing --ad-user/--ad-domain/--dc-ip or pre-existing KRB5CCNAME credential cache'
    dc=dcs[0]
    if ctx.runner.has('certipy'):
        prefix=out/'certipy_find'
        # Never place passwords or hashes on the process command line.  The
        # approved read-only collector consumes a separately obtained, scoped
        # Kerberos credential cache.
        cmd=['certipy','find','-u',f'{user}@{domain}','-k','-no-pass','-dc-ip',dc,'-json','-output',str(prefix)]
        rc,stdout,stderr=ctx.runner.run(cmd,timeout=600,log_name='identity_certipy_find')
        (out/'certipy_stdout.txt').write_text(stdout,encoding='utf-8'); (out/'certipy_stderr.txt').write_text(stderr,encoding='utf-8')
        n+=1 if rc==0 else 0
    # Password-based ldapdomaindump execution remains import-only because its
    # common CLI interface exposes the secret in the process list.
    return n,'approved read-only collectors attempted using a pre-existing Kerberos cache; password CLI collectors skipped'

def run(ctx):
    if not (getattr(ctx.args,'identity_security',False) or getattr(ctx.args,'identity_results',None)):
        return
    out=RT.evidence_dir(ctx,'18_identity_security_tooling')
    try:manifest=load_manifest(getattr(ctx.args,'approval_manifest',None))
    except Exception as e:manifest={}; ctx.log('WARN','identity_security_tooling',str(e))
    live_n,live_detail=_live_readonly(ctx,out,manifest)
    paths=[]; rp=getattr(ctx.args,'identity_results',None)
    if rp:
        q=Path(rp); paths=[q] if q.is_file() else [p for p in q.rglob('*') if p.is_file()] if q.is_dir() else []
    paths += [p for p in out.rglob('*') if p.is_file()]
    normalized=0
    for p in paths[:2000]:
        if p.suffix.lower() in {'.json','.jsonl','.sarif'}:
            normalized += save_items(ctx,'identity_security_tooling',parse_file(p,source=p.stem),p.stem,{'identity_evidence':True})
        elif p.suffix.lower() in TEXT_EXT:
            normalized += _import_text(ctx,p)
    payload={'live_collectors_succeeded':live_n,'live_detail':live_detail,'normalized_observations':normalized,'approval':approval_summary(manifest),'supported_tools':['Certipy find via pre-existing Kerberos cache (read-only, approved)','ldapdomaindump result import','PingCastle/Purple Knight/Locksmith imports','ROADtools/AzureHound/GraphRunner/Maester/ScubaGear/Monkey365 imports','Kerbrute/coercion/relay/ticket/credential operations: approval-plane imports only']}
    (out/'identity_security_summary.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    RT.write_md(out/'IDENTITY_SECURITY_SUMMARY.md','AD, AD CS and Entra Identity Security',[("Result",json.dumps(payload,indent=2)),("Safety boundary",'No password spray, coercion, relay, ticket abuse, credential dumping or privilege action is executed by this phase. Those require a separate approved operator workflow and imported evidence.')])
    ctx.log('OK','identity_security_tooling',f'{normalized} identity observation(s) normalized; {live_n} approved collector(s) completed')
