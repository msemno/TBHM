#!/usr/bin/env python3
"""Build a reproducible ZIP from a verified current-release manifest.

--write-manifest explicitly writes only the current VERSION's new manifest;
historical release manifests are preserved. Output must be outside the source.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import stat
import sys
import time
from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.version import VERSION
from core.package_verifier import verify_tree,verify_zip

IGNORED={'.git','.venv','__pycache__','.pytest_cache'}


def files():
    return sorted(p for p in ROOT.rglob('*') if p.is_file()
        and not any(x in IGNORED for x in p.relative_to(ROOT).parts))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--write-manifest',action='store_true')
    args=parser.parse_args();output=args.output.resolve()
    if output.is_relative_to(ROOT):parser.error('output must be outside the source tree')
    manifest=ROOT/f'RELEASE_MANIFEST-v{VERSION}.json'
    if args.write_manifest:
        rows=[]
        for path in files():
            if path==manifest:continue
            if path.is_symlink():raise ValueError('source symlinks are not allowed')
            raw=path.read_bytes()
            rows.append({'path':path.relative_to(ROOT).as_posix(),'size':len(raw),
                'sha256':hashlib.sha256(raw).hexdigest(),'executable':bool(path.stat().st_mode&0o111),
                'type':path.suffix.lstrip('.')})
        data={'schema':'tbhm.release_manifest/1','release':VERSION,'semantic_version':VERSION,
            'root_name':'TBHM-'+VERSION,'generated_at':int(time.time()),
            'manifest_policy':'Every packaged file except this current manifest and runtime caches; historical manifests retained.',
            'summary':{'file_count':len(rows),'total_bytes':sum(r['size'] for r in rows)},'files':rows}
        manifest.write_text(json.dumps(data,indent=2)+'\n')
    result=verify_tree(ROOT,compile_python=False,require_manifest=True)
    if not result['passed']:raise RuntimeError(json.dumps(result))
    meta=json.loads(manifest.read_text());stamp=datetime.fromtimestamp(meta['generated_at'],timezone.utc)
    date_tuple=stamp.timetuple()[:6]
    output.parent.mkdir(parents=True,exist_ok=True)
    paths=[ROOT/r['path'] for r in meta['files']]+[manifest]
    with ZipFile(output,'w',compression=ZIP_DEFLATED,compresslevel=9) as archive:
        for path in sorted(paths):
            info=ZipInfo('TBHM-'+VERSION+'/'+path.relative_to(ROOT).as_posix(),date_time=date_tuple)
            info.create_system=3;info.compress_type=ZIP_DEFLATED
            info.external_attr=(stat.S_IFREG|(0o755 if path.stat().st_mode&0o111 else 0o644))<<16
            archive.writestr(info,path.read_bytes(),compress_type=ZIP_DEFLATED,compresslevel=9)
    verified=verify_zip(output)
    print(json.dumps(verified,indent=2))
    return 0 if verified['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
