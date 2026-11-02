#!/usr/bin/env python3
"""Build or verify the manifest for the central current release identity."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.version import VERSION


def build(root):
    name = 'RELEASE_MANIFEST-v'+VERSION+'.json'
    files = []
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if any(part in {'.git', '.venv', '__pycache__', '.pytest_cache'} for part in rel.parts): continue
        if path.is_symlink(): raise ValueError('release contains symlink: '+str(rel))
        if not path.is_file() or rel.as_posix() == name: continue
        files.append({'path': rel.as_posix(), 'size': path.stat().st_size,
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                      'executable': bool(path.stat().st_mode & 0o111),
                      'type': path.suffix.lstrip('.') or 'none'})
    return {'schema': 'tbhm.release_manifest/1', 'release': VERSION, 'semantic_version': VERSION,
            'root_name': 'TBHM-'+VERSION, 'generated_at': int(time.time()),
            'manifest_policy': 'Every packaged file except this manifest and ignored runtime/cache directories.',
            'summary': {'file_count': len(files), 'total_bytes': sum(row['size'] for row in files)}, 'files': files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(); root = args.root.resolve()
    current = build(root); path = root/('RELEASE_MANIFEST-v'+VERSION+'.json')
    if args.check:
        previous = json.loads(path.read_text())
        passed = previous['release'] == VERSION and previous['files'] == current['files']
        print('Manifest matches source tree.' if passed else 'Manifest drift.')
        return 0 if passed else 1
    path.write_text(json.dumps(current, indent=2)+'\n')
    print('Wrote '+path.name+': '+str(len(current['files']))+' files')
    return 0


if __name__ == '__main__': raise SystemExit(main())
