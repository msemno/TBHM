"""Release/package integrity verification for TBHM source trees and ZIP archives."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import py_compile
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

_VERIFY_TIMEOUT_SECONDS=30.0
_VERIFY_WORKER_CODE=('import sys;sys.path.insert(0,sys.argv[1]);'
                     'from core.package_verifier import _verify_worker;_verify_worker()')


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _manifest_entries(raw: dict) -> list[dict]:
    entries = raw.get("files") or raw.get("entries") or []
    if isinstance(entries, dict):
        return [{"path": key, **(value if isinstance(value, dict) else {"sha256": value})}
                for key, value in entries.items()]
    return [row for row in entries if isinstance(row, dict)]


def _safe_rel(value: str) -> PurePosixPath | None:
    path = PurePosixPath(str(value).replace("\\", "/"))
    return None if path.is_absolute() or ".." in path.parts or not path.parts else path


def verify_zip(path: str | Path, *, max_uncompressed_bytes: int = 20 * 1024 * 1024 * 1024,
               max_ratio: float = 1000.0) -> dict:
    """Bound central-directory parsing, CRC, manifest reads and hashing together."""
    path=Path(path).resolve(strict=True)
    job={'path':str(path),'max_uncompressed_bytes':max_uncompressed_bytes,'max_ratio':max_ratio}
    worker=subprocess.Popen([sys.executable,'-c',_VERIFY_WORKER_CODE,str(Path(__file__).resolve().parents[1])],
                            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
    try:
        stdout,_=worker.communicate(json.dumps(job).encode(),timeout=_VERIFY_TIMEOUT_SECONDS)
        if worker.returncode==0: return json.loads(stdout)
        issue='verification-worker-failed'
    except subprocess.TimeoutExpired:
        worker.kill();worker.communicate();issue='verification-timeout'
    finally:
        if worker.poll() is None: worker.kill();worker.wait()
    return {'path':str(path),'sha256':'','members':0,'uncompressed_bytes':0,'manifest':'',
            'manifest_release':'','manifest_entries_checked':0,'issues':[issue],'passed':False}


def _verify_worker():
    job=json.load(sys.stdin)
    print(json.dumps(_verify_zip(**job)))


def _verify_zip(path, *, max_uncompressed_bytes=20*1024*1024*1024, max_ratio=1000.0):
    path = Path(path).resolve(strict=True)
    issues, names, manifest_checked = [], [], 0
    manifest_name, manifest_release = "", ""
    total_uncompressed = 0
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        by_name = {info.filename: info for info in infos}
        for info in infos:
            name = info.filename
            names.append(name)
            pure = _safe_rel(name)
            if pure is None:
                issues.append(f"unsafe member path: {name}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                issues.append(f"symlink member not allowed: {name}")
            if not info.is_dir():
                total_uncompressed += info.file_size
                if info.file_size > 10 * 1024 * 1024:
                    ratio = info.file_size / max(1, info.compress_size)
                    if ratio > max_ratio:
                        issues.append(f"suspicious compression ratio {ratio:.1f}: {name}")
        if total_uncompressed > max_uncompressed_bytes:
            issues.append(f"uncompressed size exceeds policy: {total_uncompressed}")
        counts = Counter(names)
        issues.extend(f"duplicate member: {name}" for name, count in counts.items() if count > 1)
        if issues:
            return {'path':str(path),'sha256':sha256_file(path),'members':len(names),
                    'uncompressed_bytes':total_uncompressed,'manifest':'','manifest_release':'',
                    'manifest_entries_checked':0,'issues':issues,'passed':False}
        bad = zf.testzip()
        if bad:
            issues.append(f"CRC failure: {bad}")

        manifests = sorted((name for name in names if PurePosixPath(name).name.startswith("RELEASE_MANIFEST-v")
                            and PurePosixPath(name).suffix == ".json"), reverse=True)
        if manifests:
            manifest_name = manifests[0]
            try:
                raw = json.loads(zf.read(manifest_name).decode("utf-8", "replace"))
                manifest_release = str(raw.get("release") or "")
                prefix = str(PurePosixPath(manifest_name).parent)
                prefix = "" if prefix == "." else prefix.rstrip("/") + "/"
                listed_paths = set()
                for row in _manifest_entries(raw):
                    rel = _safe_rel(str(row.get("path") or row.get("name") or ""))
                    expected = str(row.get("sha256") or "").lower()
                    if rel is None or not re.fullmatch(r"[a-f0-9]{64}", expected):
                        continue
                    listed_paths.add(rel.as_posix())
                    member = prefix + rel.as_posix()
                    info = by_name.get(member)
                    if info is None or info.is_dir():
                        issues.append(f"manifest member missing: {rel.as_posix()}")
                        continue
                    data = zf.read(info)
                    manifest_checked += 1
                    actual = hashlib.sha256(data).hexdigest()
                    if actual != expected:
                        issues.append(f"manifest hash mismatch: {rel.as_posix()}")
                    if row.get("size") is not None and int(row.get("size")) != len(data):
                        issues.append(f"manifest size mismatch: {rel.as_posix()}")
                    if "executable" in row:
                        mode = (info.external_attr >> 16) & 0xFFFF
                        actual_exec = bool(mode & 0o111)
                        if actual_exec != bool(row.get("executable")):
                            issues.append(f"manifest executable-mode mismatch: {rel.as_posix()}")
                actual_paths = {name[len(prefix):] for name, info in by_name.items()
                                if name.startswith(prefix) and not info.is_dir() and name != manifest_name}
                unlisted = sorted(actual_paths - listed_paths)
                stale = sorted(listed_paths - actual_paths)
                issues.extend(f"unlisted archive member: {name}" for name in unlisted)
                issues.extend(f"manifest path absent from archive inventory: {name}" for name in stale)
            except Exception as exc:
                issues.append(f"embedded manifest parse/verification failure: {exc}")
    return {
        "path": str(path), "sha256": sha256_file(path), "members": len(names),
        "uncompressed_bytes": total_uncompressed, "manifest": manifest_name,
        "manifest_release": manifest_release, "manifest_entries_checked": manifest_checked,
        "issues": issues, "passed": not issues,
    }


def verify_tree(root: str | Path, manifest: str | Path | None = None, compile_python: bool = True, *, require_manifest: bool = False) -> dict:
    root = Path(root).resolve(strict=True)
    issues, compiled = [], 0
    paths = [p for p in root.rglob("*") if not any(part in {".git", ".venv", ".pytest_cache", "__pycache__"} for part in p.relative_to(root).parts)]
    files = [p for p in paths if p.is_file() and not p.is_symlink() and "__pycache__" not in p.parts]
    if any(p.is_symlink() for p in paths):
        issues.append("source tree contains symlinks")
    manifest_path = Path(manifest).resolve() if manifest else next(iter(sorted(root.glob("RELEASE_MANIFEST-v*.json"), reverse=True)), None)
    checked = 0
    if require_manifest and (not manifest_path or not manifest_path.is_file()):
        issues.append('release manifest missing')
    if manifest_path and manifest_path.is_file():
        try:
            raw = json.loads(manifest_path.read_text(errors="ignore"))
            if not isinstance(raw, dict) or not _manifest_entries(raw):
                raise ValueError('nonempty release manifest required')
            listed_paths = set()
            for row in _manifest_entries(raw):
                rel_value = str(row.get("path") or row.get("name") or "")
                rel = _safe_rel(rel_value)
                expected = str(row.get("sha256") or "").lower()
                if rel is None or not re.fullmatch(r"[a-f0-9]{64}", expected):
                    continue
                listed_paths.add(rel.as_posix())
                target = (root / Path(*rel.parts)).resolve()
                try:
                    target.relative_to(root)
                except ValueError:
                    issues.append(f"manifest path escapes root: {rel_value}"); continue
                if not target.is_file() or target.is_symlink():
                    issues.append(f"manifest file missing or unsafe: {rel_value}"); continue
                actual = sha256_file(target)
                checked += 1
                if actual != expected:
                    issues.append(f"hash mismatch: {rel_value}")
                if row.get("size") is not None and target.stat().st_size != int(row.get("size")):
                    issues.append(f"size mismatch: {rel_value}")
                if "executable" in row:
                    actual_exec = bool(target.stat().st_mode & 0o111)
                    if actual_exec != bool(row.get("executable")):
                        issues.append(f"executable-mode mismatch: {rel_value}")
            actual_paths = {path.relative_to(root).as_posix() for path in files if path.resolve() != manifest_path}
            unlisted = sorted(actual_paths - listed_paths)
            stale = sorted(listed_paths - actual_paths)
            issues.extend(f"unlisted source-tree file: {name}" for name in unlisted)
            issues.extend(f"manifest path absent from source-tree inventory: {name}" for name in stale)
        except Exception as exc:
            issues.append(f"manifest parse failure: {exc}")
    if compile_python:
        for path in files:
            if path.suffix == ".py":
                try:
                    py_compile.compile(str(path), doraise=True)
                    compiled += 1
                except Exception as exc:
                    issues.append(f"python compile failure {path.relative_to(root)}: {exc}")
    return {
        "root": str(root), "files": len(files), "manifest": str(manifest_path or ""),
        "manifest_entries_checked": checked, "python_files_compiled": compiled,
        "issues": issues, "passed": not issues,
    }
