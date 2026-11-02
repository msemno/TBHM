#!/usr/bin/env python3
"""Inspect/stage a legacy TBHM tar without executing or merging its contents.

Extraction requires a NEW destination, rejects links/special/path escapes, and
stores all files privately. Nested archives remain unopened. No active AI home
or source tree is selected automatically.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import tarfile
import tempfile
import time


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def db_summary(path):
    db = sqlite3.connect(Path(path).absolute().as_uri()+'?mode=ro&immutable=1', uri=True)
    db.row_factory = sqlite3.Row
    deadline = time.monotonic()+8
    db.set_progress_handler(lambda: int(time.monotonic()>deadline), 1000)
    db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
    try:
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        counts = {}
        for name in ('documents', 'document_chunks', 'runs', 'phase_events', 'findings', 'lesson_candidates', 'approved_lessons', 'change_proposals', 'scenarios'):
            if name in tables:
                counts[name] = db.execute('SELECT COUNT(*) FROM '+name).fetchone()[0]
        result = {'quick_check': db.execute('PRAGMA quick_check').fetchone()[0], 'counts': counts}
        if 'schema_migrations' in tables:
            result['schema_versions'] = [r[0] for r in db.execute('SELECT version FROM schema_migrations ORDER BY version LIMIT 100')]
        if 'audit_log' in tables:
            prev = ''; intact = True; n = 0
            for r in db.execute('SELECT action,subject,detail_json,prev_hash,this_hash,created_at FROM audit_log ORDER BY id LIMIT 100001'):
                n += 1
                if n>100000:
                    intact = False; break
                payload = {'action': r['action'], 'subject': r['subject'], 'detail': json.loads(r['detail_json'] or '{}'), 'at': r['created_at']}
                expected = hashlib.sha256(prev.encode()+json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
                if r['prev_hash'] != prev or r['this_hash'] != expected:
                    intact = False; break
                prev = r['this_hash']
            result['audit'] = {'intact': intact, 'entries_checked': n, 'meaning': 'hash consistency, not independent validation of finding labels'}
        return result
    finally:
        db.close()


def inspect(archive, destination=None):
    archive = Path(archive).expanduser().absolute()
    if archive.is_symlink() or not archive.is_file():
        raise ValueError('regular archive file required')
    if archive.stat().st_size > 1024**3:
        raise ValueError('compressed archive budget exceeded')
    result = {'schema': 'tbhm.legacy-backup-inspection/1', 'archive': archive.name,
              'sha256': digest(archive), 'execution_performed': False, 'merged_into_active_memory': False}
    with tarfile.open(archive, 'r:*') as tf:
        members = []; names = set(); total = 0
        # Iterate with a limit instead of allocating unbounded getmembers().
        for m in tf:
            p = PurePosixPath(m.name)
            if (len(members)>=20000 or p.is_absolute() or '..' in p.parts or '\\' in m.name
                    or any(ord(c)<32 for c in m.name) or not p.parts
                    or not (m.isfile() or m.isdir()) or m.size < 0):
                raise ValueError('unsafe archive member or member budget exceeded')
            canonical = p.as_posix()
            if canonical in names:
                raise ValueError('duplicate normalized archive path')
            names.add(canonical); members.append(m); total += m.size
            if total>1024**3 or (m.isfile() and m.size>256*1024*1024):
                raise ValueError('expanded archive budget exceeded')
        # Detect files used as parents before writing anything.
        file_names = {PurePosixPath(m.name).as_posix() for m in members if m.isfile()}
        for m in members:
            if any(p.as_posix() in file_names for p in PurePosixPath(m.name).parents if p.as_posix() != '.'):
                raise ValueError('file/directory collision')
        result.update({'members': len(members), 'files': sum(m.isfile() for m in members),
                       'expanded_bytes': total, 'roots': sorted({PurePosixPath(m.name).parts[0] for m in members})})
        result['databases'] = []
        for m in members:
            if m.isfile() and (m.name.endswith('/database/memory.sqlite3') or m.name.endswith('/tbhm.db')):
                with tempfile.TemporaryDirectory(prefix='tbhm-legacy-inspect-') as td:
                    p = Path(td)/'snapshot.sqlite3'
                    with p.open('xb') as out, tf.extractfile(m) as src:
                        shutil.copyfileobj(src, out, 1024*1024)
                    p.chmod(0o600)
                    result['databases'].append({'role': 'AI memory' if '/database/' in m.name else 'scanner run', **db_summary(p)})
        if destination:
            dest = Path(destination).expanduser().absolute()
            if dest.exists() or dest.is_symlink() or any(p.is_symlink() for p in dest.parents):
                raise ValueError('a new, unlinked destination is required; never overwrite an active home')
            dest.mkdir(parents=True, mode=0o700)
            for m in members:
                target = dest.joinpath(*PurePosixPath(m.name).parts)
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    with target.open('xb') as out, tf.extractfile(m) as src:
                        shutil.copyfileobj(src, out, 1024*1024)
                    target.chmod(0o600)
            result['staged_at'] = str(dest)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive', type=Path); p.add_argument('--destination', type=Path)
    p.add_argument('--report', type=Path)
    args = p.parse_args()
    try:
        result = inspect(args.archive, args.destination)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            with args.report.open('x', encoding='utf-8') as f:
                json.dump(result, f, indent=2)
            args.report.chmod(0o600)
        print(json.dumps(result, indent=2)); return 0
    except (ValueError, OSError, tarfile.TarError, sqlite3.Error) as exc:
        print(json.dumps({'status': 'failed', 'error': str(exc)[:500], 'merged_into_active_memory': False})); return 2


if __name__ == '__main__':
    raise SystemExit(main())
