"""Explicit opt-in import from the existing run SQLite, preserving provenance.

No automatic permission inference or trusted label import. Every case starts
pending review even if a legacy field says CONFIRMED.
"""
import hashlib
import sqlite3
from pathlib import Path
from core.research_input import read_bytes
from core.ai_plane.scenarios import text,identity

def ingest_run(memory,project,plan):
    path=Path(plan['run_database']).absolute()
    # Refuse live WAL input rather than silently importing an inconsistent view.
    raw=read_bytes(path,32*1024*1024)
    if Path(str(path)+'-wal').exists():raise ValueError('close/checkpoint the run database or supply a SQLite backup first')
    if not raw.startswith(b'SQLite format 3\x00'):raise ValueError('SQLite run database required')
    source_hash=hashlib.sha256(raw).hexdigest()
    db=sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)
    db.row_factory=sqlite3.Row
    # A hostile database may contain views; never evaluate arbitrary schemas.
    db.set_authorizer(lambda action,*_:sqlite3.SQLITE_DENY if action in {sqlite3.SQLITE_ATTACH,sqlite3.SQLITE_DETACH,sqlite3.SQLITE_FUNCTION} else sqlite3.SQLITE_OK)
    db.set_progress_handler(lambda:1 if __import__('time').monotonic()>deadline else 0,1000)
    import time
    deadline=time.monotonic()+3
    try:
        obj=db.execute("SELECT type FROM sqlite_master WHERE name='findings'").fetchone()
        if not obj or obj[0]!='table':raise ValueError('findings must be a real run table')
        rows=db.execute('SELECT id,title,evidence,cwe,phase FROM findings ORDER BY id LIMIT 101').fetchall()
        if len(rows)>100:raise ValueError('run import budget exceeded; supply a bounded reviewed export')
        results=[]
        for row in rows:
            sid=identity(plan['run_id']+'-finding-'+str(row['id']))
            evidence=text(str(row['evidence'] or ''),4000)
            record={'scenario_id':sid,'run_id':plan['run_id'],'project_id':project,
             'scope_reference':plan['scope_reference'],'vulnerability_class':plan['vulnerability_class'],
             'observation_summary':text(row['title'],1000),'test_objective':plan['test_objective'],
             'evidence':[{'id':'E1','sha256':hashlib.sha256(evidence.encode()).hexdigest(),'summary':evidence,'kind':'sanitized_run_finding'}],
             'root_cause_id':sid,'source_license':plan['source_license'],'permission_reference':plan['permission_reference'],
             'reuse_approved':plan['reuse_approved'],'split':plan['split'],'cwe':[str(row['cwe'] or '')],
             'limitations':'Imported field labels are untrusted; technical validity awaits independent review.',
             'safe_reproduction_reference':'run-database-sha256:'+source_hash}
            results.append(memory.ingest(record))
        return {'imported':results,'source_sha256':source_hash,'trusted_labels_imported':False}
    finally:db.close()

def capture_findings(memory,ctx,run_id,settings):
    """Current-run hook. Opt-in processing metadata, never imported review labels."""
    import json
    if not isinstance(settings,dict) or settings.get('schema')!='tbhm.run-learning-permission/1':raise ValueError('run learning permission schema required')
    project=identity(settings['project_id']);identity(run_id)
    findings=ctx.storage.all_findings()
    if len(findings)>100:raise ValueError('automatic scenario capture limited to 100 findings; use a bounded export')
    results=[]
    for f in findings:
        sid=identity(run_id+'-finding-'+str(f['id']))
        raw=f.get('evidence','');raw=raw if isinstance(raw,str) else json.dumps(raw,default=str)
        summary=text(raw[:3000],4000)
        record={'scenario_id':sid,'project_id':project,'run_id':run_id,'scope_reference':settings['scope_reference'],
         'vulnerability_class':settings.get('vulnerability_class','unclassified'),'observation_summary':text(str(f.get('title',''))[:1000]),
         'test_objective':settings.get('test_objective','Review observed scanner evidence with independent controls'),
         'evidence':[{'id':'E1','sha256':hashlib.sha256(summary.encode()).hexdigest(),'summary':summary,'kind':'sanitized_run_finding'}],
         'root_cause_id':sid,'source_license':settings['source_license'],'permission_reference':settings['permission_reference'],
         'reuse_approved':settings['reuse_approved'],'split':'train','training_allowed':False,
         'proof_status':'untrusted-imported-observation','limitations':'Requires hash-bound independent review before retrieval.'}
        results.append(memory.ingest(record))
    return {'captured_pending':len(results),'scenarios':results,'trusted_labels_imported':False}
