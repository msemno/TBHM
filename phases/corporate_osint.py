"""Corporate/company intelligence phase, deliberately separate from recon/enum.

Collects organization, subsidiary, domain, code, document, identity-pattern and
third-party evidence into a provenance-aware entity graph.  Newly discovered
assets remain scope candidates; they are never fed into active scanning unless
the existing TBHM scope explicitly permits them.
"""
from __future__ import annotations
import csv, hashlib, ipaddress, json, re
from pathlib import Path

try:
    import yaml
except Exception:
    yaml = None
from urllib.parse import urlparse
from core import redteam_utils as RT
from core.entity_graph import EntityGraph
from core.targets import target_scope_allows
from core.approval_gate import load_manifest, approved, summary as approval_summary

DOMAIN_RE=re.compile(r"(?<![@A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
EMAIL_RE=re.compile(r"\b[\w.+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
URL_RE=re.compile(r"https?://[^\s\"'<>]+",re.I)
IP_RE=re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

def _lines(path): return RT.read_lines(path)

def _flatten_values(value):
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _flatten_values(v)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _flatten_values(item)
    elif value is not None:
        yield str(value)

def _seed_values(path):
    if not path:
        return []
    p=Path(path)
    if not p.is_file() or p.stat().st_size > 10_000_000:
        return []
    suffix=p.suffix.lower()
    try:
        text=p.read_text(encoding='utf-8',errors='ignore')
        if suffix=='.json':
            return list(_flatten_values(json.loads(text)))
        if suffix in {'.yaml','.yml'} and yaml is not None:
            return list(_flatten_values(yaml.safe_load(text)))
        if suffix=='.csv':
            values=[]
            for row in csv.reader(text.splitlines()): values.extend(row)
            return values
        return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    except Exception:
        return []

def _hash(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
    return h.hexdigest()

def _scope(ctx,value):
    host=urlparse(value).hostname if value.startswith(('http://','https://')) else value
    try: return 'in-scope' if target_scope_allows(ctx,'https://'+host) else 'candidate-outside-current-scope'
    except Exception: return 'unknown'

def _seed_domains(ctx):
    vals=[]
    for t in getattr(ctx,'targets',[]) or []:
        h=urlparse(t).hostname if str(t).startswith(('http://','https://')) else str(t).split('/')[0].split(':')[0]
        if h and '.' in h: vals.append(h.lower())
    for raw in _seed_values(getattr(ctx.args,'osint_seeds',None)):
        vals.extend(x.lower() for x in DOMAIN_RE.findall(str(raw)))
    vals += [x.lower() for x in _lines(getattr(ctx.args,'organization_domains_file',None))]
    cap=max(1,min(int(getattr(ctx.args,'osint_max_domains',200) or 200),5000))
    return sorted(set(vals))[:cap]

def _ingest_text(graph, org_id, text, source, ctx, sensitivity='corporate', allow_people=False):
    counts={'domains':0,'emails':0,'ips':0,'urls':0}
    for domain in sorted(set(DOMAIN_RE.findall(text)))[:5000]:
        eid=graph.entity('domain',domain,confidence=.45,scope_status=_scope(ctx,domain),source=source,sensitivity=sensitivity)
        if org_id: graph.relationship(org_id,'associated_with',eid,confidence=.45,source=source)
        counts['domains']+=1
    for email in sorted(set(EMAIL_RE.findall(text)))[:5000]:
        normalized=email.lower().strip()
        if allow_people:
            kind='email'; value=normalized; relation='public_contact_or_identity_pattern'
        else:
            # Default corporate collection preserves correlation value without
            # retaining the address. Raw identities require both the explicit
            # person-collection flag and a supplied PII policy.
            kind='email_hash'; value=hashlib.sha256(normalized.encode('utf-8')).hexdigest(); relation='hashed_identity_pattern'
        eid=graph.entity(kind,value,confidence=.4,scope_status='identity-evidence',source=source,sensitivity='pii-limited')
        if org_id: graph.relationship(org_id,relation,eid,confidence=.4,source=source)
        counts['emails']+=1
    for ip in sorted(set(IP_RE.findall(text)))[:5000]:
        try: ipaddress.ip_address(ip)
        except Exception: continue
        eid=graph.entity('ip',ip,confidence=.4,scope_status=_scope(ctx,ip),source=source)
        if org_id: graph.relationship(org_id,'infrastructure_candidate',eid,confidence=.35,source=source)
        counts['ips']+=1
    for url in sorted(set(URL_RE.findall(text)))[:5000]:
        eid=graph.entity('url',url[:2000],confidence=.45,scope_status=_scope(ctx,url),source=source)
        if org_id: graph.relationship(org_id,'published_or_observed_url',eid,confidence=.4,source=source)
        counts['urls']+=1
    return counts

def _run_tools(ctx,out,domains,usernames,allow_people,manifest):
    results=[]
    if not getattr(ctx.args,'osint_live',False): return results, 'not requested'
    selected={x.strip().lower() for x in str(getattr(ctx.args,'osint_tools','') or '').split(',') if x.strip()}
    ok, reason = approved(manifest, 'corporate_osint', str(getattr(ctx.args,'organization_name','') or ''))
    if not ok: return results, reason
    max_domains=max(1,min(int(getattr(ctx.args,'osint_max_domains',10) or 10),100))
    for domain in domains[:max_domains]:
        if 'asnmap' in selected and ctx.runner.has('asnmap'):
            rc,stdout,stderr=ctx.runner.run(['asnmap','-d',domain,'-json'],timeout=120,log_name=f'osint_asnmap_{domain.replace(".","_")}')
            p=out/f'asnmap_{domain}.jsonl'; p.write_text(stdout,encoding='utf-8'); results.append(p)
        if ('theharvester' in selected or 'theHarvester' in selected) and ctx.runner.has('theHarvester'):
            base=out/f'theharvester_{domain}'
            cmd=['theHarvester','-d',domain,'-b',str(getattr(ctx.args,'osint_sources','crtsh,rapiddns,otx,urlscan')).replace(' ','') ,'-f',str(base)]
            ctx.runner.run(cmd,timeout=300,log_name=f'osint_theharvester_{domain.replace(".","_")}', capture_mode="tail")
            results += list(out.glob(base.name+'*'))
    if allow_people:
        for username in usernames[:50]:
            safe=re.sub(r'[^A-Za-z0-9_.-]+','_',username)[:80]
            if 'sherlock' in selected and ctx.runner.has('sherlock'):
                p=out/f'sherlock_{safe}.txt'; rc,stdout,stderr=ctx.runner.run(['sherlock',username,'--print-found'],timeout=240,log_name=f'osint_sherlock_{safe}'); p.write_text(stdout,encoding='utf-8'); results.append(p)
            if 'maigret' in selected and ctx.runner.has('maigret'):
                p=out/f'maigret_{safe}.json'; ctx.runner.run(['maigret',username,'--json',str(p)],timeout=300,log_name=f'osint_maigret_{safe}', capture_mode="tail"); results.append(p)
    docs=Path(getattr(ctx.args,'osint_docs', '') or '')
    if docs.exists() and ('exiftool' in selected or 'metadata' in selected) and ctx.runner.has('exiftool'):
        files=[docs] if docs.is_file() else [p for p in docs.rglob('*') if p.is_file()][:500]
        if files:
            p=out/'document_metadata.json'
            rc,stdout,stderr=ctx.runner.run(['exiftool','-json']+[str(x) for x in files],timeout=600,log_name='osint_exiftool')
            p.write_text(stdout,encoding='utf-8'); results.append(p)
    return results, 'approved passive/read-only collectors attempted: ' + ','.join(sorted(selected))

def run(ctx):
    if not (getattr(ctx.args,'corporate_osint',False) or getattr(ctx.args,'osint_results',None)):
        return
    out=RT.evidence_dir(ctx,'10_corporate_osint')
    graph=EntityGraph(out/'corporate_intelligence.db')
    org=str(getattr(ctx.args,'organization_name','') or '').strip()
    aliases=[x.strip() for x in str(getattr(ctx.args,'organization_aliases','') or '').split(',') if x.strip()]
    org_id=graph.entity('organization',org,display_name=org,confidence=.9,scope_status='engagement-seed',source='operator') if org else ''
    for alias in aliases:
        aid=graph.entity('organization_alias',alias,confidence=.8,scope_status='engagement-seed',source='operator')
        if org_id: graph.relationship(org_id,'has_alias',aid,confidence=.9,source='operator')
    domains=_seed_domains(ctx)
    for d in domains:
        did=graph.entity('domain',d,confidence=.9,scope_status=_scope(ctx,d),source='operator-or-target')
        if org_id: graph.relationship(org_id,'owns_or_authorized_seed',did,confidence=.9,source='operator-or-target')
    allow_people=bool(getattr(ctx.args,'osint_person_collection',False) and getattr(ctx.args,'osint_pii_policy',None))
    usernames=_lines(getattr(ctx.args,'osint_usernames',None)) if allow_people else []
    emails=_lines(getattr(ctx.args,'osint_emails',None)) if allow_people else []
    for e in emails:
        eid=graph.entity('email',e,confidence=.75,scope_status='authorized-corporate-identity',source='operator',sensitivity='pii-limited')
        if org_id: graph.relationship(org_id,'authorized_identity_seed',eid,confidence=.8,source='operator')
    try: manifest=load_manifest(getattr(ctx.args,'approval_manifest',None))
    except Exception as exc: manifest={}; ctx.log('WARN','corporate_osint',str(exc))
    result_files, live_detail=_run_tools(ctx,out,domains,usernames,allow_people,manifest)
    rp=getattr(ctx.args,'osint_results',None)
    if rp:
        q=Path(rp); result_files += [q] if q.is_file() else [p for p in q.rglob('*') if p.is_file()] if q.is_dir() else []
    totals={'domains':0,'emails':0,'ips':0,'urls':0,'files':0}
    seen=set()
    for p in result_files[:2000]:
        try:
            if not p.is_file() or p.stat().st_size>50_000_000: continue
            key=str(p.resolve())
            if key in seen: continue
            seen.add(key); totals['files']+=1
            text=p.read_text(errors='ignore')
            c=_ingest_text(graph,org_id,text,p.name,ctx,allow_people=allow_people)
            for k in ('domains','emails','ips','urls'): totals[k]+=c[k]
            graph.timeline(org_id or graph.entity('case','corporate-osint'), 'collection', f'Ingested {p.name}', source=p.name, evidence_hash=_hash(p))
        except Exception: continue
    stats=graph.export(out/'exports'); stats.update(totals)
    graph.close()
    payload={'organization':org,'aliases':aliases,'seed_domains':domains,'people_collection_enabled':allow_people,'stats':stats,'safety':{'corporate_purpose_only':True,'pii_minimized':True,'new_assets_not_auto_scanned':True,'credential_use_disabled':True,'personal_background_services_catalog_only':True},'live_detail':live_detail,'approval':approval_summary(manifest)}
    (out/'corporate_osint_summary.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    RT.write_md(out/'CORPORATE_OSINT_SUMMARY.md','Corporate OSINT and Company Intelligence',[("Organization",org or 'Not supplied'),("Seeds",'\n'.join(f'- {d}' for d in domains) or 'None'),("Collection",json.dumps(stats,indent=2)),("Scope rule",'Discovered subsidiaries, domains, IPs and identities remain candidates. TBHM does not automatically add them to active scope.'),("PII boundary",'Person/username/email collection requires both --osint-person-collection and --osint-pii-policy. Personal background, tracking and facial-recognition services are catalogued but not automated.')])
    ctx.phase_state['corporate_osint_db']=str(out/'corporate_intelligence.db')
    ctx.log('OK','corporate_osint',f"corporate graph: {stats.get('entities',0)} entities / {stats.get('relationships',0)} relationships")
