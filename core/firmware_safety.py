"""Safe filesystem helpers for untrusted extracted firmware trees.

The functions in this module never treat firmware symlinks as host paths.  They
resolve links lexically inside the extracted root and reject escapes.  Directory
walks never follow links.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import Iterable


def canonical_root(root: str | Path) -> Path:
    path = Path(root).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"not a directory: {path}")
    return path


def _normalise_parts(parts: Iterable[str]) -> tuple[str, ...] | None:
    out: list[str] = []
    for raw in parts:
        part = str(raw)
        if part in ("", "."):
            continue
        if part == "..":
            if not out:
                return None
            out.pop()
            continue
        out.append(part)
    return tuple(out)


def safe_resolve(root: str | Path, relative: str | Path, *, max_symlinks: int = 24) -> Path | None:
    """Resolve a firmware path while keeping all links inside ``root``.

    Absolute links are interpreted as firmware-root absolute paths, not host
    absolute paths.  Escaping ``..`` links and loops are rejected.
    """
    try:
        base = canonical_root(root)
    except Exception:
        return None
    rel_text = str(relative).replace("\\", "/")
    rel = PurePosixPath(rel_text.lstrip("/"))
    parts = _normalise_parts(rel.parts)
    if parts is None:
        return None
    hops = 0
    while True:
        current = base
        changed = False
        for index, part in enumerate(parts):
            candidate = current / part
            try:
                is_link = candidate.is_symlink()
            except OSError:
                return None
            if is_link:
                hops += 1
                if hops > max_symlinks:
                    return None
                try:
                    target = os.readlink(candidate)
                except OSError:
                    return None
                remaining = parts[index + 1:]
                if target.startswith("/"):
                    target_parts = PurePosixPath(target.lstrip("/")).parts
                else:
                    parent_rel = candidate.parent.relative_to(base).parts
                    target_parts = (*parent_rel, *PurePosixPath(target).parts)
                normal = _normalise_parts((*target_parts, *remaining))
                if normal is None:
                    return None
                parts = normal
                changed = True
                break
            current = candidate
        if changed:
            continue
        try:
            resolved_parent = current.parent.resolve(strict=False)
            if resolved_parent != base and base not in resolved_parent.parents:
                return None
        except OSError:
            return None
        return current


def safe_read_text(root: str | Path, relative: str | Path, *, max_bytes: int = 4_000_000) -> str | None:
    path = safe_resolve(root, relative)
    if path is None:
        return None
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
        if size < 0 or size > max_bytes:
            return None
        with path.open("rb") as handle:
            return handle.read(max_bytes + 1)[:max_bytes].decode("utf-8", "ignore")
    except OSError:
        return None


def iter_regular_files(root: str | Path, *, max_files: int = 100_000):
    """Yield ``(absolute_path, relative_path)`` without following symlinks."""
    base = canonical_root(root)
    count = 0
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dpath = Path(dirpath)
        kept_dirs = []
        for name in dirnames:
            child = dpath / name
            if not child.is_symlink():
                kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in filenames:
            child = dpath / name
            try:
                if child.is_symlink() or not child.is_file():
                    continue
                rel = child.relative_to(base)
            except (OSError, ValueError):
                continue
            yield child, rel
            count += 1
            if count >= max_files:
                return


def validate_rootfs(root: str | Path, *, min_files: int = 5) -> tuple[bool, dict]:
    try:
        base = canonical_root(root)
    except Exception as exc:
        return False, {"reason": str(exc), "file_count": 0, "markers": []}
    markers = []
    for rel in ("etc", "bin", "sbin", "usr", "lib", "etc/passwd", "etc/inittab"):
        path = safe_resolve(base, rel)
        if path is not None and path.exists():
            markers.append(rel)
    file_count = 0
    for _path, _rel in iter_regular_files(base, max_files=max(min_files, 1000)):
        file_count += 1
        if file_count >= min_files:
            break
    ok = file_count >= min_files and bool(markers)
    return ok, {"root": str(base), "file_count_at_least": file_count, "markers": markers,
                "reason": "validated" if ok else "insufficient filesystem structure"}


def strip_shell_comments(text: str) -> str:
    """Remove whole-line and unquoted shell comments conservatively."""
    output = []
    for raw in str(text or "").splitlines():
        line = raw.lstrip()
        if not line or line.startswith("#"):
            continue
        quote = None
        escaped = False
        kept = []
        for ch in raw:
            if escaped:
                kept.append(ch); escaped = False; continue
            if ch == "\\":
                kept.append(ch); escaped = True; continue
            if ch in ("'", '"'):
                if quote == ch:
                    quote = None
                elif quote is None:
                    quote = ch
                kept.append(ch); continue
            if ch == "#" and quote is None:
                break
            kept.append(ch)
        cleaned = "".join(kept).strip()
        if cleaned:
            output.append(cleaned)
    return "\n".join(output)
