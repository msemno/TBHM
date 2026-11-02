"""Bounded lexical RAG over public reference data, separate from reviewed cases.

No downloads, model training, command execution or proof authority. Large CVE
collections stay in SQLite/FTS5 on disk, outside the source/vector index.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import urlsplit

from core.ai_plane.sanitizer import scrub, wrap_untrusted

SCHEMA = '''
CREATE TABLE IF NOT EXISTS entries(
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL,
 title TEXT NOT NULL, body TEXT NOT NULL, sha256 TEXT NOT NULL,
 metadata TEXT NOT NULL, dataset TEXT NOT NULL, seen_in TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS entry_fts USING fts5(id UNINDEXED,title,body);
CREATE TABLE IF NOT EXISTS imports(dataset TEXT PRIMARY KEY, report TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notices(dataset TEXT PRIMARY KEY, text TEXT NOT NULL, sha256 TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_public_kind_status ON entries(kind,status);
CREATE TRIGGER IF NOT EXISTS entry_insert AFTER INSERT ON entries BEGIN
 INSERT INTO entry_fts(rowid,id,title,body) VALUES(new.rowid,new.id,new.title,new.body); END;
CREATE TRIGGER IF NOT EXISTS entry_delete AFTER DELETE ON entries BEGIN
 DELETE FROM entry_fts WHERE rowid=old.rowid; END;
CREATE TRIGGER IF NOT EXISTS entry_update AFTER UPDATE OF title,body ON entries BEGIN
 DELETE FROM entry_fts WHERE rowid=old.rowid;
 INSERT INTO entry_fts(rowid,id,title,body) VALUES(new.rowid,new.id,new.title,new.body); END;
'''


def default_path(args=None, home=None):
    if args is not None and getattr(args, 'ai_knowledge_db', None):
        return Path(args.ai_knowledge_db).expanduser().resolve()
    if home is None:
        from core.ai_plane.home import resolve_home
        home = resolve_home(getattr(args, 'ai_home', None) if args else None)
    return Path(home) / 'knowledge' / 'public-catalog.sqlite3'


def safe_url(value):
    if not isinstance(value, str) or len(value) > 2000:
        return ''
    try:
        u = urlsplit(value)
        return value if u.scheme in {'http', 'https'} and u.hostname and not u.username and not u.password else ''
    except ValueError:
        return ''


class Catalog:
    def __init__(self, path, *, create=False):
        self.path = Path(path).expanduser().absolute()
        if self.path.is_symlink() or any(p.is_symlink() for p in self.path.parents):
            raise ValueError('linked catalog path refused')
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(self.path, timeout=2)
            self.path.chmod(0o600)
            self.db.executescript(SCHEMA)
            self.db.execute('PRAGMA cache_size=-8192')
        else:
            self.db = sqlite3.connect(self.path.as_uri()+'?mode=ro', uri=True, timeout=.4)
            self.db.execute('PRAGMA query_only=ON')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA trusted_schema=OFF')
        # FTS5 triggers are not marked innocuous on every supported SQLite.
        if create:
            self.db.execute('PRAGMA trusted_schema=ON')

    def close(self):
        self.db.close()

    def put(self, *, entry_id, kind, status, title, body, raw_sha, meta, dataset, run):
        if kind not in {'cve', 'cwe', 'methodology'} or not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,220}', entry_id):
            raise ValueError('invalid public reference identity')
        title, body = scrub(str(title), 700), scrub(str(body), 32000)
        metadata = json.dumps(meta, ensure_ascii=False, sort_keys=True)
        old = self.db.execute('SELECT sha256,title,body,metadata FROM entries WHERE id=?', (entry_id,)).fetchone()
        if old and tuple(old) == (raw_sha, title, body, metadata):
            self.db.execute('UPDATE entries SET seen_in=?,status=? WHERE id=?', (run, status, entry_id))
            return 'unchanged'
        self.db.execute('''INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
          kind=excluded.kind,status=excluded.status,title=excluded.title,body=excluded.body,
          sha256=excluded.sha256,metadata=excluded.metadata,dataset=excluded.dataset,seen_in=excluded.seen_in''',
          (entry_id, kind, status, title, body, raw_sha, metadata, dataset, run))
        return 'updated' if old else 'added'

    def checkpoint(self, dataset, report):
        self.db.execute('INSERT OR REPLACE INTO imports VALUES(?,?)', (dataset, json.dumps(report, sort_keys=True)))
        self.db.commit()

    def finish(self, dataset, run, report):
        if report['status'] == 'complete':
            # Deleted/filtered records from a complete new snapshot cannot remain
            # searchable. Preserve the row for provenance and possible re-entry.
            self.db.execute("UPDATE entries SET status='WITHDRAWN' WHERE dataset=? AND seen_in<>?", (dataset, run))
        self.checkpoint(dataset, report)

    def status(self):
        return {'schema': 'tbhm.public-knowledge-status/1',
                'counts': [dict(r) for r in self.db.execute('SELECT kind,status,COUNT(*) AS count FROM entries GROUP BY kind,status')],
                'imports': [json.loads(r[0]) for r in self.db.execute('SELECT report FROM imports ORDER BY dataset')],
                'retrieval': 'SQLite FTS5; no bulk embeddings or weight training',
                'non_authoritative': True}

    def search(self, query, k=4):
        # Literal token quoting prevents FTS syntax/operators from untrusted
        # finding text. Cap work even for a damaged or overlarge catalog.
        query = str(query)[:4000]
        # A cold, disk-backed CVE snapshot can take longer than 800 ms on a VM.
        # Keep a hard deadline without discarding indexed identity matches while
        # attempting an unrelated, much broader lexical search.
        deadline = time.monotonic()+3.0
        self.db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        try:
            exact = list(dict.fromkeys(x.upper() for x in re.findall(r'(?i)\b(?:CVE-\d{4}-\d{4,}|CWE-\d{1,5})\b', query)))[:6]
            hits = []
            if exact:
                hits = self.db.execute('SELECT * FROM entries WHERE id IN ('+','.join('?' for _ in exact)+") AND status IN ('PUBLISHED','ACTIVE')", exact).fetchall()
            remainder = re.sub(r'(?i)\b(?:CVE-\d{4}-\d{4,}|CWE-\d{1,5})\b', ' ', query)
            tokens = list(dict.fromkeys(t for t in re.findall(r'[A-Za-z0-9_]{3,50}', remainder.lower())
                if t not in {'the', 'and', 'for', 'with', 'this', 'that', 'from', 'finding', 'title', 'evidence', 'cve', 'cwe'}))[:20]
            if tokens and not hits:
                expression = ' OR '.join('"'+t+'"' for t in tokens)
                hits += self.db.execute('''SELECT e.* FROM entry_fts JOIN entries e ON e.rowid=entry_fts.rowid
                    WHERE entry_fts MATCH ? AND rank MATCH 'bm25(0,5,1)'
                    AND e.status IN ('PUBLISHED','ACTIVE')
                    ORDER BY rank LIMIT ?''', (expression, max(1, min(int(k), 6))+len(exact))).fetchall()
            out, seen = [], set()
            for row in hits:
                if row['id'] in seen:
                    continue
                seen.add(row['id'])
                meta = json.loads(row['metadata'])
                imported = self.db.execute('SELECT report FROM imports WHERE dataset=?', (row['dataset'],)).fetchone()
                import_report = json.loads(imported[0]) if imported else {}
                out.append({'id': row['id'], 'kind': row['kind'], 'title': row['title'],
                    'text': row['body'][:2000], 'sha256': row['sha256'],
                    'source_url': safe_url(meta.get('source_url', '')), 'metadata': meta,
                    'import_status': import_report.get('status', 'unknown'),
                    'snapshot_revision': meta.get('source_revision', 'unverified'), 'reference_only': True})
                if len(out) >= max(1, min(int(k), 6)):
                    break
            return out
        finally:
            self.db.set_progress_handler(None, 0)


def retrieve_context(path, query, *, budget=1400, k=2):
    """Read at most a few excerpts; callers keep reference failures observable."""
    path = Path(path)
    if not path.is_file():
        return '', []
    catalog = Catalog(path)
    try:
        hits = catalog.search(query, k=k)
    finally:
        catalog.close()
    parts, refs = [], []
    remaining = max(0, min(int(budget), 4000))
    for hit in hits:
        header = f"{hit['id']} | {hit['title'][:160]} | {hit['source_url']} | SHA256 {hit['sha256']} | import={hit['import_status']}\n"
        if remaining < len(header)+100:
            break
        excerpt = hit['text'][:min(remaining-len(header), max(180, budget//max(1, len(hits))-len(header)))]
        block = scrub(header+excerpt, remaining)
        remaining -= len(block)
        parts.append(block)
        refs.append({key: hit[key] for key in ('id', 'kind', 'sha256', 'source_url', 'import_status', 'snapshot_revision')})
    if not parts:
        return '', []
    return ('PUBLIC REFERENCE EXCERPTS: background only; relevance/version applicability and current-target proof remain unverified.\n'
            +wrap_untrusted('\n\n'.join(parts), 'T3')), refs
