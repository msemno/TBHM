"""Opt-in audit of a *prior sealed delivery*, including supported containers.

Matches operator-provided canaries without disclosing their values. An opaque
format or exhausted budget is incomplete, never a privacy guarantee. Nothing
in the source run or its sealed delivery is rewritten by this capability.
"""
from __future__ import annotations
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile
import zlib
import bz2
import lzma
from urllib.parse import quote
import html
from core.evidence_manifest import verify_manifest
from core.evidence_redaction import register_secrets, redact_value
from core.research_input import load, read_bytes

TEXT = {'.txt', '.log', '.json', '.jsonl', '.md', '.html', '.csv', '.xml', '.yaml', '.yml', '.sarif', '.har', '.js', '.map', '.toml', '.ini', '.cfg', '.svg', '.py', '.patch'}


def audit(root, environment_names, *, maximum_bytes=64*1024*1024, maximum_files=2000):
    root = Path(root).absolute()
    if root.is_symlink() or any(p.is_symlink() for p in root.parents): raise ValueError('linked audit root rejected')
    maximum_bytes = min(256*1024*1024, max(1, int(maximum_bytes)))
    maximum_files = min(10000, max(1, int(maximum_files)))
    if not isinstance(environment_names, list) or not 1 <= len(environment_names) <= 32:
        raise ValueError('1–32 canary environment-variable names required')
    needles = []
    for name in environment_names:
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,120}', name):
            raise ValueError('invalid canary environment-variable name')
        value = os.environ.get(name, '')
        if not 8 <= len(value) <= 128: raise ValueError('canary value missing or outside 8–128 characters')
        encoded = [('utf8',value.encode()), ('utf16le',value.encode('utf-16le')), ('utf16be',value.encode('utf-16be')),
                   ('utf32le',value.encode('utf-32le')), ('utf32be',value.encode('utf-32be')),
                   ('base64',base64.b64encode(value.encode())), ('base64url',base64.urlsafe_b64encode(value.encode()).rstrip(b'=')),
                   ('url',quote(value,safe='').encode()), ('url-all', ''.join('%%%02X'%b for b in value.encode()).encode()),
                   ('hex',value.encode().hex().encode()), ('hex-upper',value.encode().hex().upper().encode()),
                   ('html',html.escape(value,quote=True).encode()), ('html-decimal',''.join('&#%d;'%ord(c) for c in value).encode()),
                   ('json',json.dumps(value,ensure_ascii=True)[1:-1].encode())]
        register_secrets([value]+[data.decode('ascii') for _,data in encoded if data.isascii()])
        raw = value.encode()
        for encoding, data in encoded:
            needles.append((name, encoding, data))
    manifest_path = root/'evidence_manifest.json'
    manifest_raw = read_bytes(manifest_path)
    manifest_hash = hashlib.sha256(manifest_raw).hexdigest()
    manifest = load(manifest_path)
    files = manifest.get('files') if isinstance(manifest, dict) else None
    if not isinstance(files, list): raise ValueError('snapshot manifest files array required')
    if (len(files) > maximum_files or any(not isinstance(item, dict) or type(item.get('bytes')) is not int or item['bytes'] < 0 for item in files)
            or sum(item['bytes'] for item in files) > maximum_bytes):
        raise ValueError('snapshot inventory exceeds audit preflight budget')
    integrity = verify_manifest(root)
    report = {'schema': 'tbhm.delivery-privacy-audit/1', 'manifest_sha256': manifest_hash,
              'integrity': integrity, 'hits': [], 'incomplete': [], 'files_scanned': 0,
              'bytes_scanned': 0, 'containers_scanned': 0, 'canary_environment_names': environment_names}
    budget = [maximum_bytes]
    def scan(name, raw, depth=0):
        if report['files_scanned'] >= maximum_files or len(raw) > budget[0] or depth > 3:
            report['incomplete'].append({'path': name, 'reason': 'audit file/expanded-byte/depth budget'}); return
        report['files_scanned'] += 1; report['bytes_scanned'] += len(raw); budget[0] -= len(raw)
        for env, encoding, marker in needles:
            if marker in raw: report['hits'].append({'path': name, 'canary_environment_name': env, 'encoding': encoding})
            if marker in name.encode(): report['hits'].append({'path':name,'canary_environment_name':env,'encoding':'filename-'+encoding})
        if not raw: return  # Integrity-checked empty files have no opaque content; names were checked above.
        if raw.startswith(b'PK\x03\x04'):
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    entries = archive.infolist()
                    if len(entries) > 500: raise ValueError('ZIP member limit')
                    report['containers_scanned'] += 1
                    for item in entries:
                        if item.is_dir(): continue
                        rel = PurePosixPath(item.filename.replace('\\', '/'))
                        if (rel.is_absolute() or '..' in rel.parts or item.flag_bits & 1
                                or stat.S_ISLNK(item.external_attr >> 16)):
                            raise ValueError('unsafe/encrypted ZIP member')
                        if item.file_size > budget[0]: raise ValueError('ZIP expanded-byte budget')
                        with archive.open(item) as handle: data = handle.read(min(budget[0], 16*1024*1024)+1)
                        if len(data) > min(budget[0], 16*1024*1024): raise ValueError('ZIP member byte budget')
                        scan(name+'!'+str(rel), data, depth+1)
            except (ValueError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                report['incomplete'].append({'path': name, 'reason': str(exc)})
        elif raw.startswith(b'\x1f\x8b'):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle: data = handle.read(min(budget[0], 16*1024*1024)+1)
                if len(data) > min(budget[0], 16*1024*1024): raise ValueError('gzip expanded-byte budget')
                report['containers_scanned'] += 1
                scan(name+'!payload', data, depth+1)
            except (OSError, ValueError, EOFError, zlib.error) as exc:
                report['incomplete'].append({'path': name, 'reason': str(exc)})
        elif len(raw) > 262 and raw[257:262] == b'ustar':
            try:
                with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
                    report['containers_scanned'] += 1
                    for index, item in enumerate(archive):
                        if index >= 500: raise ValueError('tar member limit')
                        rel = PurePosixPath(item.name)
                        if rel.is_absolute() or '..' in rel.parts or not (item.isfile() or item.isdir()):
                            raise ValueError('unsafe tar member')
                        if item.isdir(): continue
                        if item.size > budget[0]: raise ValueError('tar expanded-byte budget')
                        with archive.extractfile(item) as handle: data = handle.read(min(budget[0], 16*1024*1024)+1)
                        if len(data) > min(budget[0], 16*1024*1024): raise ValueError('tar member byte budget')
                        scan(name+'!'+str(rel), data, depth+1)
            except (ValueError, OSError, tarfile.TarError) as exc:
                report['incomplete'].append({'path': name, 'reason': str(exc)})
        elif raw.startswith((b'BZh',b'\xfd7zXZ\x00')):
            try:
                if raw.startswith(b'BZh'):
                    with bz2.BZ2File(io.BytesIO(raw)) as handle:data=handle.read(min(budget[0],16*1024*1024)+1)
                else:
                    decoder=lzma.LZMADecompressor(memlimit=32*1024*1024)
                    data=decoder.decompress(raw,max_length=min(budget[0],16*1024*1024)+1)
                    if not decoder.eof or decoder.unused_data:raise ValueError('XZ truncated/oversized/concatenated payload requires review')
                if len(data)>min(budget[0],16*1024*1024):raise ValueError('compressed expanded-byte budget')
                report['containers_scanned']+=1;scan(name+'!payload',data,depth+1)
            except (OSError, ValueError, EOFError, lzma.LZMAError) as exc:
                report['incomplete'].append({'path':name,'reason':str(exc)})
        elif raw.startswith(b'SQLite format 3\0'):
            pass  # Scan physical bytes, including free-page remnants, in common encodings.
        else:
            try:
                raw.decode('utf-8')
                # gzip's anonymous payload may be ordinary UTF-8 text.
                if Path(name).suffix.lower() not in TEXT and not name.endswith('!payload'):
                    raise UnicodeError('unregistered text/opaque format')
            except UnicodeError:
                report['incomplete'].append({'path': name, 'reason': 'opaque format: raw canary scan only; semantic/manual review required'})
    for item in files:
        name = item.get('path') if isinstance(item, dict) else None
        if not isinstance(name, str): raise ValueError('invalid snapshot member')
        path = root/name
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            report['incomplete'].append({'path': name, 'reason': 'unsafe snapshot path'}); continue
        try:
            scan(name, read_bytes(path, min(maximum_bytes, 16*1024*1024)))
        except (ValueError, OSError) as exc:
            report['incomplete'].append({'path': name, 'reason': str(exc)})
    final_integrity = verify_manifest(root)
    report['integrity_unchanged'] = final_integrity['passed'] and hashlib.sha256(read_bytes(manifest_path)).hexdigest() == manifest_hash
    report['status'] = 'fail' if report['hits'] or not integrity['passed'] or not report['integrity_unchanged'] else 'incomplete' if report['incomplete'] else 'pass'
    report['meaning'] = 'Only supplied canary encodings and supported bounded containers were checked. A pass does not prove absence of unknown secrets, PII, image pixels, encrypted payloads or all writer defects.'
    return redact_value(report)


def run(ctx):
    root = getattr(ctx.args, 'delivery_audit_input', None)
    if not root: return None
    names = (getattr(ctx.args, 'privacy_canary_env', '') or '').split(',')
    report = audit(root, [name.strip() for name in names if name.strip()])
    out = ctx.output/'evidence'/'delivery_privacy_audit'; out.mkdir(parents=True, exist_ok=True)
    (out/'audit.json').write_text(json.dumps(report, indent=2)+'\n')
    ctx.storage.save_observation(phase='engagement_evidence_review', observation_type='delivery_privacy_audit',
        target='prior-delivery', summary=report['status'], evidence={'manifest_sha256': report['manifest_sha256'],
            'hits': len(report['hits']), 'incomplete': len(report['incomplete'])})
    ctx.log('WARN' if report['status'] != 'pass' else 'OK', 'engagement_evidence_review',
            'Prior delivery privacy audit: '+report['status'])
    if getattr(ctx.args, 'require_private_delivery', False) and report['status'] != 'pass':
        raise ValueError('required prior-delivery privacy audit failed or is incomplete')
    return report
