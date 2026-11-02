"""Atomic delivery snapshots, consistent SQLite backups and integrity checks."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from core import code_patterns as CP
from core.evidence_redaction import redact_text, redact_value

_TEXTY = {'.txt', '.log', '.json', '.md', '.html', '.csv', '.xml', '.yaml', '.yml', '.jsonl',
          '.sarif', '.har', '.js', '.map', '.toml', '.ini', '.cfg', '.svg', ''}
_PRIVATE = {'.proof-capture.key', '.secret_vault.key', 'evidence_manifest.json'}


def _sanitize_text(value):
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        return redact_text(value)
    clean = redact_value(parsed)
    return value if clean == parsed else json.dumps(clean, ensure_ascii=False, sort_keys=True)


def _sanitize_snapshot(root):
    """Sanitize the copy, never signed originals or the live database.

    This covers supported text exports and SQLite TEXT cells. Images, binaries
    and application-specific opaque containers still require writer review.
    """
    for path in root.rglob('*'):
        if not path.is_file() or path.suffix.lower() not in _TEXTY:
            continue
        if path.stat().st_size > 16*1024*1024:
            raise ValueError('text delivery artifact exceeds sanitization budget: '+str(path.relative_to(root)))
        try:
            original = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            raise ValueError('text delivery artifact is not UTF-8: '+str(path.relative_to(root)))
        clean = _sanitize_text(original)
        if clean != original:
            if 'captures' in path.relative_to(root).parts or 'oast' in path.relative_to(root).parts:
                raise ValueError('signed evidence contains unredacted data; re-capture before delivery')
            path.write_text(clean, encoding='utf-8')
    db = root/'tbhm.db'
    if db.is_file():
        with sqlite3.connect(db) as connection:
            connection.execute('PRAGMA secure_delete=ON')
            tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
            def quote(name):
                return '"'+name.replace('"', '""')+'"'
            for (table,) in tables:
                name = quote(table)
                columns = connection.execute('PRAGMA table_info('+name+')').fetchall()
                for column in columns:
                    col = quote(column[1])
                    # Use SQLite's actual type; JSON and ordinary log cells go
                    # through the same persistence sanitizer as text artifacts.
                    values = connection.execute('SELECT DISTINCT '+col+' FROM '+name+" WHERE typeof("+col+")='text'").fetchall()
                    for (value,) in values:
                        clean = _sanitize_text(value)
                        if clean != value:
                            connection.execute('UPDATE '+name+' SET '+col+'=? WHERE '+col+'=?', (clean, value))
            connection.commit()
            connection.execute('VACUUM')
            if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('sanitized SQLite backup integrity check failed')


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def redaction_scan(output_dir: Path) -> dict:
    output_dir = Path(output_dir)
    hits = []
    for f in sorted(output_dir.rglob('*')):
        if not f.is_file() or f.is_symlink() or f.name in _PRIVATE or f.name == 'redaction_report.json':
            continue
        if f.suffix.lower() not in _TEXTY or f.stat().st_size > 5_000_000:
            continue
        for s in CP.find_secrets(f.read_text(errors='replace'), str(f.relative_to(output_dir))):
            if s['severity'] != 'LOW':
                hits.append({'file': str(f.relative_to(output_dir)), 'type': s['type'],
                             'line': s['line'], 'preview': '[VALUE WITHHELD]'})
    report = {'generated_at': datetime.now(timezone.utc).isoformat(),
              'secret_hits_in_deliverable': len(hits), 'hits': hits}
    (output_dir / 'redaction_report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def build_manifest(output_dir: Path, roe_ticket: str = '') -> dict:
    """Freeze a new delivery; later live-output writes cannot invalidate it.

    Every call creates a separate snapshot. Earlier deliveries are never rewritten.
    Read-only file modes prevent accidents, not deliberate local tampering.
    """
    output_dir = Path(output_dir).resolve(strict=True)
    delivery = output_dir / 'delivery'
    if delivery.is_symlink():
        raise ValueError('delivery path is a symlink')
    delivery.mkdir(exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.building-', dir=delivery))
    final = delivery / ('run-' + uuid.uuid4().hex)
    try:
        for source in sorted(output_dir.rglob('*')):
            rel = source.relative_to(output_dir)
            if rel.parts[0] == 'delivery' or '_repos' in rel.parts or source.name in _PRIVATE or source.name.endswith(('-wal', '-shm')):
                continue
            if source.is_symlink():
                raise ValueError(f'symlink cannot be included in delivery: {rel}')
            if not source.is_file() or source.name == 'tbhm.db':
                continue
            target = temporary / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            before = source.stat()
            shutil.copyfile(source, target)
            after = source.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise RuntimeError(f'evidence producer still writing: {rel}')
        db = output_dir / 'tbhm.db'
        if db.is_file():
            with sqlite3.connect(db.as_uri() + '?mode=ro', uri=True) as source_db:
                with sqlite3.connect(temporary / 'tbhm.db') as backup:
                    source_db.backup(backup)
                    if backup.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                        raise RuntimeError('SQLite backup integrity check failed')
        _sanitize_snapshot(temporary)
        redaction_scan(temporary)
        files = [{'path': p.relative_to(temporary).as_posix(), 'bytes': p.stat().st_size, 'sha256': _sha256(p)}
                 for p in sorted(temporary.rglob('*')) if p.is_file()]
        manifest = {'schema': 'tbhm.evidence_snapshot/2',
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'roe_ticket': redact_text(roe_ticket), 'file_count': len(files), 'files': files}
        (temporary / 'evidence_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        os.replace(temporary, final)
        for p in final.rglob('*'):
            if p.is_file():
                p.chmod(0o444)
        files.append({'path': 'evidence_manifest.json', 'bytes': (final / 'evidence_manifest.json').stat().st_size,
                      'sha256': _sha256(final / 'evidence_manifest.json')})
        manifest['file_count'] = len(files)
        manifest['snapshot_dir'] = final.relative_to(output_dir).as_posix()
        manifest['files'] = [{**row, 'path': manifest['snapshot_dir'] + '/' + row['path']} for row in files]
        pointer = output_dir / '.evidence_manifest.tmp'
        pointer.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        os.replace(pointer, output_dir / 'evidence_manifest.json')
        return manifest
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def verify_manifest(output_dir: Path) -> dict:
    root = Path(output_dir).resolve(strict=True)
    manifest = json.loads((root / 'evidence_manifest.json').read_text())
    issues = []
    listed = [row['path'] for row in manifest['files']]
    if len(set(listed)) != len(listed):
        issues.append('duplicate manifest paths')
    snapshot = root / manifest.get('snapshot_dir', '.')
    if not snapshot.resolve().is_relative_to(root) or snapshot.is_symlink():
        return {'passed': False, 'files_checked': 0, 'issues': ['unsafe snapshot path']}
    actual = {p.relative_to(root).as_posix() for p in snapshot.rglob('*') if p.is_file()
              and (p.name != 'evidence_manifest.json' or p.relative_to(root).as_posix() in listed)}
    if actual != set(listed):
        issues.append('snapshot inventory mismatch')
    for row in manifest['files']:
        path = root / row['path']
        if (not path.resolve().is_relative_to(root) or path.is_symlink() or not path.is_file()
                or path.stat().st_size != row['bytes'] or _sha256(path) != row['sha256']):
            issues.append(row['path'])
    return {'passed': not issues, 'files_checked': len(manifest['files']), 'issues': issues}
