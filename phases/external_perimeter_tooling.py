"""External perimeter assessment adapters (v3.8, additive and safe).

Imports reconnaissance/scanner/exploitation-framework evidence and optionally runs
read-only local reconnaissance tools against targets already approved by TBHM scope.
No phishing, credential capture, C2, tunneling, persistence, or exploit execution.
"""
from __future__ import annotations
import json, re, xml.etree.ElementTree as ET
from pathlib import Path
from core import redteam_utils as RT

SEV={"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","moderate":"MEDIUM","low":"LOW","info":"INFO","informational":"INFO"}

def emit(ctx,title,sev,target,evidence,source="external perimeter tool",confidence="MEDIUM"):
    s=SEV.get(str(sev).lower(),str(sev).upper() if str(sev).upper() in SEV.values() else "INFO")
    ctx.save_finding({"phase":"external_perimeter_tooling","severity":s,"confidence":confidence,"title":title[:180],
      "target":target,"url":target if str(target).startswith("http") else "","description":f"Normalized observation from {source}. It must remain within the authorized scope and be independently verified before exploitation.",
      "evidence":str(evidence)[:2200],"impact":"May identify an externally reachable asset, vulnerable service, exposed application, or exploitable perimeter weakness.",
      "remediation":"Validate ownership and reachability, reproduce safely, patch or harden the affected component, restrict exposure, and retest.","cwe":"CWE-200","mrs_score":{"CRITICAL":90,"HIGH":72,"MEDIUM":48,"LOW":24,"INFO":8}[s]})

def walk_json(ctx,obj,source,path=""):
    n=0
    if isinstance(obj,dict):
        title=obj.get("title") or obj.get("name") or obj.get("template-id") or obj.get("plugin_name") or obj.get("vulnerability")
        sev=obj.get("severity") or obj.get("risk") or obj.get("level") or obj.get("cvss_severity")
        target=obj.get("host") or obj.get("url") or obj.get("matched-at") or obj.get("ip") or obj.get("domain") or obj.get("hostname") or path
        evidence=obj.get("description") or obj.get("info") or obj.get("evidence") or obj.get("output") or obj.get("matched")
        if title and (sev or any(k in obj for k in ("host","url","ip","matched-at","port"))):
            emit(ctx,str(title),sev or "INFO",str(target or ""),json.dumps(obj,ensure_ascii=False),source); n+=1
        for k,v in obj.items(): n+=walk_json(ctx,v,source,f"{path}/{k}")
    elif isinstance(obj,list):
        for i,v in enumerate(obj): n+=walk_json(ctx,v,source,f"{path}/{i}")
    return n

def import_file(ctx,p:Path):
    n=0; ext=p.suffix.lower(); source=p.stem
    if ext in (".json",".jsonl"):
        try:
            if ext==".jsonl":
                for line in p.read_text(errors="ignore").splitlines():
                    try:n+=walk_json(ctx,json.loads(line),source)
                    except Exception:pass
            else:n+=walk_json(ctx,json.loads(p.read_text(errors="ignore")),source)
        except Exception:return 0
    elif ext==".xml":
        try:root=ET.parse(p).getroot()
        except Exception:return 0
        for item in root.findall('.//*'):
            tag=item.tag.lower().split('}')[-1]
            attrs=item.attrib
            title=attrs.get('name') or attrs.get('pluginName') or attrs.get('type')
            if tag in ('result','reportitem','alertitem','vulnerability','issue') or title:
                text=' '.join(x.strip() for x in item.itertext() if x and x.strip())
                target=attrs.get('host') or attrs.get('uri') or attrs.get('ip') or ''
                sev=attrs.get('severity') or attrs.get('risk') or 'INFO'
                emit(ctx,title or f'{source} finding',sev,target,text or ET.tostring(item,encoding='unicode'),source); n+=1
    elif ext in (".txt",".csv",".log"):
        text=p.read_text(errors="ignore")
        for line in text.splitlines():
            if re.search(r'(?i)\b(critical|high|medium|vulnerab|cve-\d{4}-\d+|open port|subdomain)\b',line):
                emit(ctx,f'{source}: imported observation','INFO','',line,source,'LOW'); n+=1
    return n

def run(ctx):
    if not (getattr(ctx.args,'external_tooling',False) or getattr(ctx.args,'external_results',None)): return
    out=RT.evidence_dir(ctx,'24_external_perimeter_tooling'); n=0
    rp=getattr(ctx.args,'external_results',None)
    if rp:
        q=Path(rp)
        files=[q] if q.is_file() else list(q.rglob('*')) if q.is_dir() else []
        for f in files:
            if f.is_file() and f.suffix.lower() in ('.json','.jsonl','.xml','.txt','.csv','.log'): n+=import_file(ctx,f)
    RT.write_md(out/'EXTERNAL_PERIMETER_TOOLING_SUMMARY.md','External Perimeter Tooling Summary',[
      ('Status',f'{n} imported perimeter observation(s).'),
      ('Supported evidence','Amass/Sublist3r/theHarvester/Shodan exports; ZAP/Burp/Nuclei/Nessus/OpenVAS scanner exports; SearchSploit/Metasploit assessment logs; generic JSON, JSONL, XML, CSV and text.'),
      ('Safety boundary','TBHM does not automate phishing credential capture, Evilginx, SET payload delivery, C2 deployment, covert tunnels, persistence, or exploit execution. Those require separate human-approved procedures and controls.'),
      ('Validation','Imported items are normalized into the existing verification, false-positive review, evidence and reporting pipeline.')])
    ctx.log('OK','external_perimeter_tooling',f'{n} perimeter observation(s) normalized')
