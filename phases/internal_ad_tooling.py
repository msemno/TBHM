"""Internal network and advanced AD evidence normalization (v3.8-safe).
No password spraying, credential dumping, NTLM poisoning/relay, ticket forgery,
remote execution, DCShadow, persistence, or lateral movement is performed.
"""
from __future__ import annotations
import json,re,csv
from pathlib import Path
from core import redteam_utils as RT

PATTERNS=[
 (r'(?i)kerberoast(?:able)?|serviceprincipalname','MEDIUM','Kerberoast exposure candidate','CWE-521'),
 (r'(?i)as-?rep.*(?:roast|preauth.*false)|DONT_REQ_PREAUTH','HIGH','AS-REP roastable account candidate','CWE-521'),
 (r'(?i)unconstrained delegation','HIGH','Unconstrained delegation configured','CWE-284'),
 (r'(?i)resource[- ]based constrained delegation|msds-allowedtoact','MEDIUM','RBCD relationship identified','CWE-284'),
 (r'(?i)admincount\s*[=:]\s*1|domain admins|enterprise admins','INFO','Privileged AD principal observation','CWE-269'),
 (r'(?i)password.*(?:never expires|not required)|PASSWD_NOTREQD','HIGH','Weak AD account password control','CWE-521'),
 (r'(?i)ldap signing.*(?:disabled|not required)|channel binding.*(?:disabled|not required)','HIGH','LDAP signing/channel binding weakness','CWE-319'),
 (r'(?i)llmnr|nbt-?ns|netbios name service','MEDIUM','Legacy name-resolution poisoning exposure','CWE-350'),
 (r'(?i)zerologon|CVE-2020-1472|printnightmare|CVE-2021-34527','HIGH','Legacy critical AD vulnerability indicator','CWE-1104'),
 (r'(?i)genericall|genericwrite|writedacl|writeowner|addmember','HIGH','Dangerous AD ACL relationship','CWE-732')]

def emit(ctx,title,sev,target,ev,cwe):
 ctx.save_finding({'phase':'internal_ad_tooling','severity':sev,'confidence':'MEDIUM','title':title,'target':target,'url':'',
 'description':'Read-only internal/Active Directory assessment observation imported from authorized evidence.',
 'evidence':ev[:2200],'impact':'May enable credential attacks, privilege escalation, lateral movement, or domain compromise if the relationship is reachable and controls are weak.',
 'remediation':'Confirm the relationship, remove unnecessary privilege/delegation, enforce modern authentication controls, patch domain controllers and endpoints, and retest.','cwe':cwe,'mrs_score':70 if sev=='HIGH' else 45})

def parse_text(ctx,p):
 text=p.read_text(errors='ignore'); n=0
 for pat,sev,title,cwe in PATTERNS:
  for m in re.finditer(pat,text):
   lo=max(0,m.start()-200); hi=min(len(text),m.end()+450); emit(ctx,title,sev,str(p),text[lo:hi],cwe); n+=1
 return n

def run(ctx):
 rp=getattr(ctx.args,'ad_results',None)
 if not rp:return
 out=RT.evidence_dir(ctx,'27_internal_ad_tooling'); q=Path(rp); n=0
 for f in ([q] if q.is_file() else q.rglob('*') if q.is_dir() else []):
  if f.is_file() and f.suffix.lower() in ('.json','.jsonl','.csv','.txt','.log','.ldif','.xml','.html') and f.stat().st_size<250_000_000:n+=parse_text(ctx,f)
 RT.write_md(out/'INTERNAL_AD_TOOLING_SUMMARY.md','Internal and Active Directory Tooling Summary',[
 ('Status',f'{n} AD/internal candidate condition(s) normalized.'),('Supported evidence','BloodHound/SharpHound, ADRecon, ldapsearch/PowerView/ADFind, NetExec/CrackMapExec and Impacket assessment logs, Rubeus/Responder/Inveigh/ntlmrelayx observations, and vendor AD assessment exports.'),
 ('Safety boundary','No password spraying, password/hash/ticket extraction, LSASS access, NTLM poisoning or relay, remote service execution, pass-the-hash, ticket forgery, ZeroLogon/PrintNightmare exploitation, Skeleton Key, DCShadow, C2, or tunneling is automated.'),
 ('Existing coverage','Complements ad_identity_safe, add_net_ad, lateral_movement_paths and internal_network_safe.')])
 ctx.log('OK','internal_ad_tooling',f'{n} internal/AD candidate(s) normalized')
