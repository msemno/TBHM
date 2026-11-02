"""Privilege-escalation audit evidence normalization (v3.8).
Accepts outputs from LinPEAS/WinPEAS/LinEnum/PSpy/PowerUp/Seatbelt/SharpUp and exploit suggesters.
It does not execute exploits or alter local privilege state.
"""
from __future__ import annotations
import json,re
from pathlib import Path
from core import redteam_utils as RT

RULES=[
 (r'(?i)writable.*(?:service|binary|path|cron|systemd|sudoers)','HIGH','Privileged component appears writable','CWE-732'),
 (r'(?i)unquoted service path','HIGH','Unquoted Windows service path','CWE-428'),
 (r'(?i)(?:alwaysinstallelevated|SeImpersonatePrivilege|SeDebugPrivilege).*enabled','HIGH','High-risk Windows privilege condition','CWE-269'),
 (r'(?i)(?:suid|setuid).*(?:writable|gtfobin|shell)','HIGH','Potentially abusable SUID binary','CWE-250'),
 (r'(?i)(?:password|credential|token|private key).*(?:found|readable|exposed)','HIGH','Credential material exposed to low-privilege user','CWE-522'),
 (r'(?i)(?:kernel|cve-\d{4}-\d+).*(?:vulnerable|exploit suggested)','MEDIUM','Kernel exploit candidate reported','CWE-1104'),
 (r'(?i)(?:cron|scheduled task).*(?:writable|unquoted|weak permission)','HIGH','Weak privileged scheduled execution','CWE-732')]

def emit(ctx,title,sev,target,ev,cwe):
 ctx.save_finding({'phase':'privesc_audit_tooling','severity':sev,'confidence':'MEDIUM','title':title,'target':target,'url':'',
 'description':'Privilege-escalation audit observation imported from an authorized endpoint assessment. No exploitation was attempted.',
 'evidence':ev[:2200],'impact':'A low-privilege user may be able to gain elevated local privileges if the condition is reachable and exploitable.',
 'remediation':'Validate manually, correct permissions or configuration, patch affected software, rotate exposed credentials, and retest as a standard user.','cwe':cwe,'mrs_score':68 if sev=='HIGH' else 46})

def scan_text(ctx,p):
 text=p.read_text(errors='ignore'); n=0
 for pat,sev,title,cwe in RULES:
  for m in re.finditer(pat,text):
   lo=max(0,m.start()-180); hi=min(len(text),m.end()+360); emit(ctx,title,sev,str(p),text[lo:hi],cwe); n+=1
 return n

def scan_json(ctx,p):
 try:d=json.loads(p.read_text(errors='ignore'))
 except Exception:return 0
 return scan_text(ctx,p) if isinstance(d,(dict,list)) else 0

def run(ctx):
 rp=getattr(ctx.args,'privesc_results',None)
 if not rp:return
 out=RT.evidence_dir(ctx,'26_privesc_audit_tooling'); q=Path(rp); n=0
 for f in ([q] if q.is_file() else q.rglob('*') if q.is_dir() else []):
  if f.is_file() and f.suffix.lower() in ('.txt','.log','.json','.xml','.csv','.html') and f.stat().st_size<100_000_000:n+=scan_text(ctx,f)
 RT.write_md(out/'PRIVESC_AUDIT_SUMMARY.md','Privilege Escalation Audit Summary',[
 ('Status',f'{n} candidate condition(s) normalized.'),('Supported evidence','LinPEAS, WinPEAS, LinEnum, PSpy, PowerUp, Seatbelt, SharpUp, Linux/Windows exploit suggester and equivalent authorized audit output.'),
 ('Safety boundary','This phase never launches kernel exploits, invokes GTFOBins techniques, changes services/tasks/permissions, dumps credentials, or attempts elevation.'),
 ('Confidence','Candidates remain MEDIUM confidence until an analyst confirms permissions, execution context, patch state and a non-destructive proof.')])
 ctx.log('OK','privesc_audit_tooling',f'{n} privilege-escalation candidate(s) normalized')
