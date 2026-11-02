#!/usr/bin/env python3
"""Import operator-downloaded public CVE/CWE/methodology data; never execute it.

Run --help. All commands use bounded files and a disk-backed SQLite/FTS5 index.
No model calls, API keys or training packages. Uses existing TBHM dependencies.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import date, datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.ai_plane.public_knowledge import Catalog, default_path, safe_url


def stamp():
    return datetime.now(timezone.utc).isoformat()


def bounded(path, maximum):
    path = Path(path).absolute()
    if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.is_file():
        raise ValueError('regular unlinked input required')
    with path.open('rb') as f:
        raw = f.read(maximum+1)
    if len(raw) > maximum:
        raise ValueError('input byte budget exceeded')
    return raw


def paths(root, suffixes):
    root = Path(root).absolute()
    if root.is_symlink() or any(p.is_symlink() for p in root.parents) or not root.is_dir():
        raise ValueError('regular unlinked source directory required')
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {'.git', '.venv', '__pycache__', 'node_modules', 'results', 'dist', 'build'} and not (Path(base)/d).is_symlink())
        for name in sorted(files):
            p = Path(base)/name
            if p.suffix.lower() in suffixes:
                yield p


def descriptions(rows):
    if not isinstance(rows, list):
        return []
    english = [r.get('value', '') for r in rows if isinstance(r, dict) and str(r.get('lang', '')).startswith('en')]
    return english or [r.get('value', '') for r in rows if isinstance(r, dict)]


def parse_cve(raw, *, start, end, selection='union'):
    obj = json.loads(raw)
    if obj.get('dataType') != 'CVE_RECORD' or not str(obj.get('dataVersion', '')).startswith('5.'):
        raise ValueError('CVE JSON 5.x record required')
    m = obj['cveMetadata']; cid = m['cveId']
    if not isinstance(cid, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cid):
        raise ValueError('invalid CVE identity')
    state = m['state']
    if state not in {'PUBLISHED', 'REJECTED', 'RESERVED'}:
        raise ValueError('unknown CVE state')
    if state == 'RESERVED':
        return None
    published = str(m.get('datePublished', ''))
    pub_date = date.fromisoformat(published[:10]) if published else None
    if state == 'PUBLISHED' and not pub_date:
        raise ValueError('published record missing publication date')
    if pub_date and pub_date > end:
        return None
    in_years = start.year <= int(cid.split('-')[1]) <= end.year
    in_dates = bool(pub_date and start <= pub_date <= end)
    if not (in_dates if selection == 'published' else in_years if selection == 'id-year' else in_dates or in_years):
        return None
    containers = obj.get('containers', {})
    cna = containers.get('cna') or {}
    all_containers = [cna]+[c for c in containers.get('adp', []) if isinstance(c, dict)]
    body, refs, cwes = [], [], set()
    for container in all_containers:
        provider = container.get('providerMetadata') or {}
        body.append('CONTAINER '+str(provider.get('shortName', 'CNA/ADP')))
        body.extend(descriptions(container.get('descriptions', [])))
        body.extend(descriptions(container.get('rejectedReasons', [])))
        for problem in container.get('problemTypes', []):
            for d in problem.get('descriptions', []):
                cwes.update(re.findall(r'CWE-\d+', str(d.get('cweId', ''))+' '+str(d.get('description', ''))))
        # Preserve exact ranges/changes/defaultStatus as data. Never interpret
        # arbitrary/custom version ranges as proof that an installed product is affected.
        for key in ('affected', 'metrics', 'solutions', 'workarounds'):
            if container.get(key):
                body.append(key+': '+json.dumps(container[key], ensure_ascii=False))
        for ref in container.get('references', []):
            url = safe_url(ref.get('url', ''))
            if url and url not in refs:
                refs.append(url)
    body.insert(0, ' '.join(sorted(cwes)))
    full = '\n'.join(str(x) for x in body)
    return {'entry_id': cid, 'kind': 'cve', 'status': state,
        'title': cna.get('title') or cid, 'body': full,
        'raw_sha': hashlib.sha256(raw).hexdigest(),
        'meta': {'source_url': 'https://www.cve.org/CVERecord?id='+cid,
                 'published': published, 'modified': m.get('dateUpdated', ''),
                 'data_version': obj['dataVersion'], 'cwe': sorted(cwes),
                 'references': refs[:20], 'reference_count': len(refs),
                 'excerpt_truncated': len(full)>32000,
                 'terms': 'https://www.cve.org/Legal/TermsOfUse',
                 'target_applicability': 'unverified; check vendor advisory and exact affected versions'}}


def report_base(dataset, args):
    return {'schema': 'tbhm.public-knowledge-import/1', 'dataset': dataset,
        'status': 'in_progress', 'started_at': stamp(), 'finished_at': None,
        'revision': args.revision or 'operator-local-snapshot-unverified',
        'source_root': str(args.source.absolute()), 'counts': {}, 'errors': [],
        'completeness_scope': 'files present in this local source snapshot only; upstream completeness not independently established',
        'proof_authority': False, 'training_executed': False}


def run_import(catalog, args):
    dataset = {'cve': 'cvelistV5', 'cwe': 'mitre-cwe'}.get(args.command, args.name if args.command == 'methods' else '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', dataset):
        raise ValueError('bounded dataset identity required')
    run = uuid.uuid4().hex
    report = report_base(dataset, args); counts = Counter()
    if args.terms_file:
        notice = bounded(args.terms_file, 2*1024*1024)
        catalog.db.execute('INSERT OR REPLACE INTO notices VALUES(?,?,?)',
            (dataset, notice.decode('utf-8'), hashlib.sha256(notice).hexdigest()))
        report['terms_notice_sha256'] = hashlib.sha256(notice).hexdigest()
    catalog.checkpoint(dataset, report)
    def error(path, exc):
        counts['errors'] += 1
        if len(report['errors']) < 20:
            report['errors'].append({'file': str(path), 'error': str(exc)[:200]})
    def put(row):
        row['meta'].update({'source_revision': report['revision'], 'imported_by': 'tbhm.knowledge-catalog/1'})
        counts[catalog.put(**row, dataset=dataset, run=run)] += 1
        counts['selected'] += 1
        counts['state_'+row['status']] += 1
    try:
        if args.command == 'cve':
            start = date.fromisoformat(args.start); end = date.fromisoformat(args.through)
            if end < start or end > datetime.now(timezone.utc).date():
                raise ValueError('ordered dates through today (UTC) required')
            report.update({'start': str(start), 'through': str(end), 'selection': args.selection})
            counts_by_year = Counter()
            for p in paths(args.source, {'.json'}):
                if not re.fullmatch(r'CVE-\d{4}-\d{4,}\.json', p.name):
                    continue
                counts['examined'] += 1
                try:
                    row = parse_cve(bounded(p, 4*1024*1024), start=start, end=end, selection=args.selection)
                    if row is None:
                        counts['excluded'] += 1
                    else:
                        if row['entry_id']+'.json' != p.name:
                            raise ValueError('record identity does not match filename')
                        row['meta']['source_relative_path'] = p.relative_to(args.source.absolute()).as_posix()
                        put(row); counts_by_year[row['entry_id'].split('-')[1]] += 1
                except (ValueError, KeyError, TypeError, OSError) as exc:
                    error(p.relative_to(args.source.absolute()), exc)
                if counts['examined'] % 1000 == 0:
                    report['counts'] = dict(counts); catalog.checkpoint(dataset, report)
                    print(f"[catalog] examined={counts['examined']} selected={counts['selected']} errors={counts['errors']}", file=sys.stderr, flush=True)
            report['selected_by_identifier_year'] = dict(sorted(counts_by_year.items()))
        elif args.command == 'cwe':
            raw = bounded(args.source, 128*1024*1024)
            xml = raw
            if zipfile.is_zipfile(io.BytesIO(raw)):
                with zipfile.ZipFile(io.BytesIO(raw)) as z:
                    members = [m for m in z.infolist() if m.filename.endswith('.xml') and not m.is_dir()]
                    if len(members) != 1 or members[0].file_size > 128*1024*1024:
                        raise ValueError('one bounded CWE XML member required')
                    with z.open(members[0]) as f:
                        xml = f.read(128*1024*1024+1)
            if len(xml)>128*1024*1024 or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():
                raise ValueError('oversized XML or DTD/entity declaration refused')
            report['download_sha256'] = hashlib.sha256(raw).hexdigest()
            for event, elem in ET.iterparse(io.BytesIO(xml), events=('start', 'end')):
                tag = elem.tag.rsplit('}', 1)[-1]
                if event == 'start' and tag == 'Weakness_Catalog':
                    report['catalog_version'] = elem.get('Version'); report['catalog_date'] = elem.get('Date')
                if event != 'end' or tag not in {'Weakness', 'Category', 'View'}:
                    continue
                cid = 'CWE-'+elem.attrib['ID']; counts['examined'] += 1
                content = '\n'.join(' '.join(t.split()) for t in elem.itertext() if t.strip())
                relations = [dict(c.attrib) for c in elem.iter() if c.tag.rsplit('}',1)[-1] == 'Related_Weakness']
                content += '\nRelations: '+json.dumps(relations)
                put({'entry_id': cid, 'kind': 'cwe', 'status': 'DEPRECATED' if elem.get('Status', '').lower() == 'deprecated' else 'ACTIVE',
                    'title': elem.get('Name', cid), 'body': content,
                    'raw_sha': hashlib.sha256(ET.tostring(elem)).hexdigest(),
                    'meta': {'source_url': 'https://cwe.mitre.org/data/definitions/'+elem.attrib['ID']+'.html',
                        'catalog_version': report.get('catalog_version'), 'catalog_date': report.get('catalog_date'),
                        'entry_type': tag, 'status': elem.get('Status'), 'excerpt_truncated': len(content)>32000,
                        'terms': 'https://cwe.mitre.org/about/termsofuse.html'}})
                elem.clear()
        elif args.command == 'methods':
            if not safe_url(args.source_url) or not args.license.strip():
                raise ValueError('source attribution URL and license identifier required')
            for p in paths(args.source, {'.md', '.txt'}):
                counts['examined'] += 1
                try:
                    raw = bounded(p, 2*1024*1024)
                    text = raw.decode('utf-8')
                    rel = p.relative_to(args.source.absolute()).as_posix()
                    for part, offset in enumerate(range(0, len(text), 16000)):
                        put({'entry_id': 'METHOD-'+dataset+'-'+hashlib.sha256(rel.encode()).hexdigest()[:16]+'-'+str(part),
                            'kind': 'methodology', 'status': 'ACTIVE', 'title': rel+' part '+str(part+1),
                            'body': text[offset:offset+16000], 'raw_sha': hashlib.sha256(raw).hexdigest(),
                            'meta': {'source_url': args.source_url, 'relative_path': rel, 'part': part,
                                     'license': args.license, 'reference_only': True}})
                except (ValueError, OSError, UnicodeError) as exc:
                    error(p.relative_to(args.source.absolute()), exc)
        report['status'] = 'complete' if counts['examined'] and not counts['errors'] and counts['selected'] else 'partial'
    except BaseException as exc:
        report['status'] = 'interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed'
        error('source', exc)
    finally:
        report['counts'] = dict(counts); report['finished_at'] = stamp()
        catalog.finish(dataset, run, report)
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db', type=Path, help='Default: AI home/knowledge/public-catalog.sqlite3')
    sub = p.add_subparsers(dest='command', required=True)
    for kind in ('cve', 'cwe', 'methods'):
        s = sub.add_parser(kind); s.add_argument('--source', required=True, type=Path)
        s.add_argument('--revision', default=''); s.add_argument('--report', type=Path)
        s.add_argument('--terms-file', type=Path, help='Preserve the source license/terms once inside the portable catalog')
        if kind == 'cve':
            s.add_argument('--start', default='2016-01-01')
            s.add_argument('--through', default=str(datetime.now(timezone.utc).date()))
            s.add_argument('--selection', choices=('union', 'published', 'id-year'), default='union',
                help='union includes ID years plus older IDs published in the date window')
        elif kind == 'methods':
            s.add_argument('--name', required=True); s.add_argument('--source-url', required=True)
            s.add_argument('--license', required=True)
    sub.add_parser('status')
    s = sub.add_parser('search'); s.add_argument('query'); s.add_argument('--limit', type=int, default=4)
    args = p.parse_args(argv)
    path = args.db or default_path()
    catalog = None
    try:
        catalog = Catalog(path, create=args.command in {'cve', 'cwe', 'methods'})
        if args.command == 'status':
            result = catalog.status(); rc = 0
        elif args.command == 'search':
            result = {'hits': catalog.search(args.query, args.limit), 'non_authoritative': True}; rc = 0
        else:
            result = run_import(catalog, args)
            rc = 0 if result['status'] == 'complete' else 130 if result['status'] == 'interrupted' else 2
        if getattr(args, 'report', None):
            args.report.parent.mkdir(parents=True, exist_ok=True)
            with args.report.open('x', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            args.report.chmod(0o600)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return rc
    except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
        print(json.dumps({'status': 'failed', 'error': str(exc)[:500]})); return 2
    finally:
        if catalog is not None:
            catalog.close()


if __name__ == '__main__':
    raise SystemExit(main())
