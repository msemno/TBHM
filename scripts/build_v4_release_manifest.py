#!/usr/bin/env python3
"""Regenerate RELEASE_MANIFEST-v4.2.0.json for the TBHM v4 tree.

Lists every packaged file except the manifest itself and __pycache__, recording
sha256/size/executable so the package_verification phase can verify the tree or
ZIP. Run from the package root:

    python3 scripts/build_v4_release_manifest.py [--root .] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT_DEFAULT = Path(__file__).resolve().parent.parent
MANIFEST_NAME = "RELEASE_MANIFEST-v4.2.0.json"

sys.path.insert(0, str(ROOT_DEFAULT))
try:
    from core.version import VERSION, SEMANTIC_VERSION  # noqa: E402
except Exception:
    VERSION, SEMANTIC_VERSION = "4.2.0", "4.2.0"

ARCHIVE_ROOT = "TBHM-4.2.0"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for blk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(blk)
    return h.hexdigest()


def build(root: Path) -> dict:
    files, counts = [], {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink() or any(part in {"__pycache__", ".git", ".venv", ".pytest_cache"} for part in p.relative_to(root).parts):
            continue
        rel = p.relative_to(root).as_posix()
        if rel == MANIFEST_NAME:
            continue
        ext = p.suffix.lstrip(".").lower() or "none"
        counts[ext] = counts.get(ext, 0) + 1
        files.append({"path": rel, "size": p.stat().st_size, "sha256": sha256_file(p),
                      "executable": bool(p.stat().st_mode & 0o111), "type": ext})
    return {
        "schema": "tbhm.release_manifest/1", "release": VERSION,
        "semantic_version": SEMANTIC_VERSION, "generated_at": int(time.time()),
        "root_name": ARCHIVE_ROOT,
        "manifest_policy": "Lists every packaged file except this manifest and __pycache__.",
        "summary": {"file_count": len(files), "total_bytes": sum(f["size"] for f in files)},
        "counts_by_extension": dict(sorted(counts.items())), "files": files,
        "notes": "TBHM 4.2.0: complete tool distribution with pinned offline core dependencies.",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=ROOT_DEFAULT)
    ap.add_argument("--check", action="store_true",
                    help="Verify the on-disk manifest matches the tree; do not rewrite.")
    args = ap.parse_args()
    root = args.root.resolve()
    manifest = build(root)
    target = root / MANIFEST_NAME
    if args.check:
        if not target.is_file():
            print("FAIL: manifest missing"); return 1
        current = json.loads(target.read_text())
        cur = {f["path"]: (f["sha256"], f["size"]) for f in current.get("files", [])}
        new = {f["path"]: (f["sha256"], f["size"]) for f in manifest["files"]}
        if cur == new:
            print(f"OK: manifest matches tree ({len(new)} files)"); return 0
        only_disk = sorted(set(cur) - set(new))
        only_tree = sorted(set(new) - set(cur))
        changed = sorted(k for k in set(cur) & set(new) if cur[k] != new[k])
        print(f"DRIFT: +tree={len(only_tree)} -disk={len(only_disk)} changed={len(changed)}")
        for k in (only_tree + only_disk + changed)[:20]:
            print("  ", k)
        return 2
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {MANIFEST_NAME}: {manifest['summary']['file_count']} files, "
          f"{manifest['summary']['total_bytes']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
