#!/usr/bin/env python3
"""Export selected legacy AI observations as pending, permission-bound plans.

This never imports review labels, merges databases or approves a scenario.
Each selected legacy run needs its own truthful processing/reuse permission.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.research_input import load, read_bytes
from core.ai_plane.scenarios import normalize, identity, text


def connect(path):
    path = Path(path).expanduser().absolute()
    raw = read_bytes(path, 256*1024*1024)
    if not raw.startswith(b'SQLite format 3\x00') or Path(str(path)+'-wal').exists():
        raise ValueError('closed SQLite snapshot required; use the staged backup')
    sha = hashlib.sha256(raw).hexdigest()
    db = sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1', uri=True)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
    deadline = time.monotonic()+5
    db.set_progress_handler(lambda: int(time.monotonic()>deadline), 1000)
    for name in ('runs', 'findings'):
        row = db.execute('SELECT type FROM sqlite_master WHERE name=?', (name,)).fetchone()
        if not row or row[0] != 'table':
            db.close(); raise ValueError('expected legacy AI memory tables')
    return db, sha


def export(db, sha, run_uid, permission, output, *, offset=0, limit=50):
    if permission.get('schema') != 'tbhm.run-learning-permission/1':
        raise ValueError('explicit per-run permission context required')
    project = identity(permission['project_id'])
    run = db.execute('SELECT id,run_uid FROM runs WHERE run_uid=?', (run_uid,)).fetchone()
    if run is None:
        raise ValueError('legacy run identity not found')
    rows = db.execute('SELECT id,title,where_ref,phase FROM findings WHERE run_id=? ORDER BY id LIMIT ? OFFSET ?',
        (run['id'], max(1,min(int(limit),100)), max(0,int(offset)))).fetchall()
    out = Path(output).absolute()
    if out.exists() or out.is_symlink() or any(p.is_symlink() for p in out.parents):
        raise ValueError('new unlinked output directory required')
    plans = []
    for row in rows:
        sid = f"legacy-{sha[:12]}-r{run['id']}-f{row['id']}"
        summary = text(str(row['title'] or '')[:800]+'\nLegacy location: '+str(row['where_ref'] or '')[:800], 3000)
        record = {'scenario_id': sid, 'project_id': project, 'run_id': identity('legacy-'+str(run['run_uid'])),
            'scope_reference': permission['scope_reference'], 'source_license': permission['source_license'],
            'permission_reference': permission['permission_reference'], 'reuse_approved': permission['reuse_approved'],
            'training_allowed': False, 'split': 'train', 'vulnerability_class': 'unclassified',
            'root_cause_id': sid, 'observation_summary': text(str(row['title'] or '')[:800], 1000),
            'test_objective': 'Independently revalidate a legacy observation before learning from it',
            'evidence': [{'id':'E1', 'kind':'legacy_observation_only',
                'summary': summary, 'sha256': hashlib.sha256(summary.encode()).hexdigest()}],
            'safe_reproduction_reference': 'legacy-ai-snapshot-sha256:'+sha,
            'proof_status': 'untrusted-imported-observation',
            'limitations': 'Legacy titles/location summaries are not request/response proof. Prior severity, confirmation and review labels were discarded. Recollect evidence and independently review this content hash.'}
        normalize(record)  # validate every plan before writing any file
        plans.append({'schema':'tbhm.learning-operation/1','project_id':project,'operation':'ingest','record':record})
    out.mkdir(parents=True,mode=0o700)
    for plan in plans:
        path = out/(plan['record']['scenario_id']+'.json')
        with path.open('x',encoding='utf-8') as f:
            json.dump(plan,f,indent=2,ensure_ascii=False)
        path.chmod(0o600)
    return {'exported_plans':len(plans),'output':str(out),'source_sha256':sha,
        'labels_imported':False,'plans_applied':False,'training_allowed':False,
        'next':'Review each plan, then explicitly ingest selected plans with --approve-ai-learning. Ingested cases remain pending/quarantined.'}


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--db',required=True,type=Path)
    sub=p.add_subparsers(dest='operation',required=True); sub.add_parser('list')
    s=sub.add_parser('export'); s.add_argument('--run-uid',required=True)
    s.add_argument('--permission',required=True,type=Path); s.add_argument('--output',required=True,type=Path)
    s.add_argument('--offset',type=int,default=0); s.add_argument('--limit',type=int,default=50)
    args=p.parse_args(); db=None
    try:
        db,sha=connect(args.db)
        if args.operation=='list':
            result={'source_sha256':sha,'runs':[dict(r) for r in db.execute('''SELECT r.run_uid,r.profile,r.target_count,r.status,
                COUNT(f.id) AS finding_count FROM runs r LEFT JOIN findings f ON f.run_id=r.id
                GROUP BY r.id ORDER BY r.id LIMIT 500''')], 'locations_omitted':True}
        else:
            result=export(db,sha,args.run_uid,load(args.permission,64000),args.output,offset=args.offset,limit=args.limit)
        print(json.dumps(result,indent=2)); return 0
    except (ValueError,KeyError,OSError,sqlite3.Error) as exc:
        print(json.dumps({'status':'failed','error':str(exc)[:400]})); return 2
    finally:
        if db is not None: db.close()


if __name__=='__main__': raise SystemExit(main())
