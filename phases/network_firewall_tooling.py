"""Read-only network/firewall evidence adapters and static configuration checks (v3.7)."""
from __future__ import annotations
import json,re,xml.etree.ElementTree as ET
from pathlib import Path
from core import redteam_utils as RT

def finding(ctx,title,sev,target,ev,rem):
 ctx.save_finding({'phase':'network_firewall_tooling','severity':sev,'confidence':'MEDIUM','title':title,'target':target,'url':'','description':title,'evidence':ev[:1800],
 'impact':'May expose management services, weaken segmentation, or permit unintended traffic.','remediation':rem,'cwe':'CWE-284','mrs_score':55})
def audit_cfg(ctx,p):
 n=0; text=p.read_text(errors='ignore')
 checks=[(r'(?im)^\s*(?:permit|allow)\s+(?:ip\s+)?any\s+any','HIGH','Broad any-to-any firewall rule','Replace with least-privilege source, destination, service and logging.'),
 (r'(?im)^\s*(?:telnet|service telnet|set service telnet)','HIGH','Telnet management enabled','Disable Telnet and use SSH with restricted management ACLs.'),
 (r'(?im)^\s*(?:snmp-server community|community)\s+(public|private)\b','HIGH','Default SNMP community present','Use SNMPv3 and rotate/remove default communities.'),
 (r'(?im)^\s*(?:http server enable|ip http server)\b','MEDIUM','Plain HTTP management enabled','Disable HTTP management or restrict and redirect to TLS.'),
 (r'(?im)\b(log|logging)\s+(?:disable|off)\b','MEDIUM','Firewall logging disabled','Enable rule, deny, admin and configuration-change logging.')]
 for pat,sev,title,rem in checks:
  for m in re.finditer(pat,text): finding(ctx,title,sev,str(p),m.group(0),rem); n+=1
 return n
def import_results(ctx,p):
 n=0
 if p.suffix.lower()=='.xml':
  try:root=ET.parse(p).getroot()
  except Exception:return 0
  for h in root.findall('.//host'):
   addr=next((a.get('addr','') for a in h.findall('address') if a.get('addrtype')=='ipv4'), '') or next((a.get('addr','') for a in h.findall('address')), '')
   for port in h.findall('.//port'):
    st=port.find('state'); svc=port.find('service')
    if st is not None and st.get('state')=='open':
     finding(ctx,f"Open network service: {port.get('portid')}/{port.get('protocol')}",'INFO',addr,ET.tostring(port,encoding='unicode'),'Confirm necessity, restrict exposure, patch and monitor.'); n+=1
 elif p.suffix.lower()=='.json':
  try:d=json.loads(p.read_text(errors='ignore'))
  except Exception:return 0
  for x in d.get('findings',[]) if isinstance(d,dict) else []:
   finding(ctx,str(x.get('title','Network scanner finding')),str(x.get('severity','INFO')).upper(),str(x.get('host','')),json.dumps(x),'Validate and remediate according to the affected service.'); n+=1
 return n
def run(ctx):
 if not (getattr(ctx.args,'network_results',None) or getattr(ctx.args,'firewall_config',None) or getattr(ctx.args,'firewall_tooling',False)): return
 out=RT.evidence_dir(ctx,'23_network_firewall_tooling'); n=0
 rp=getattr(ctx.args,'network_results',None)
 if rp:
  q=Path(rp)
  for f in ([q] if q.is_file() else q.rglob('*') if q.is_dir() else []):
   if f.is_file() and f.suffix.lower() in ('.xml','.json'): n+=import_results(ctx,f)
 cfg=getattr(ctx.args,'firewall_config',None)
 if cfg:
  q=Path(cfg)
  for f in ([q] if q.is_file() else q.rglob('*') if q.is_dir() else []):
   if f.is_file() and f.stat().st_size<20_000_000: n+=audit_cfg(ctx,f)
 RT.write_md(out/'NETWORK_FIREWALL_TOOLING_SUMMARY.md','Network and Firewall Tooling Summary',[('Status',f'{n} observation(s) normalized.'),('Coverage','Nmap-style XML, generic JSON, and static firewall/router/switch configuration checks. This complements existing ports, internal_network_safe, AD, IoT, OT and segmentation phases.'),('Commercial tools','Nessus, Qualys, Core Impact and vendor firewall products can be integrated through exported evidence; no proprietary API dependency is required.')])
 ctx.log('OK','network_firewall_tooling',f'{n} network/firewall observation(s) normalized')
