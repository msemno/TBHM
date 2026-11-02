"""
core/sourcemaps.py   (v2.18)

Reconstruct original source from JavaScript source maps. When a site ships
.map files (or the JS references //# sourceMappingURL=), the map's
`sourcesContent` array usually holds the ORIGINAL TypeScript/JSX before
bundling — including comments, endpoints, and sometimes secrets stripped from
the minified output.

reconstruct_dir(root, out) -> writes recovered sources under out/, returns count.
extract_from_map(map_json)  -> {path: content}
"""
from __future__ import annotations
from core.evidence_redaction import redact_text

import json
import os
import re
from pathlib import Path, PurePosixPath


def extract_from_map(text: str) -> dict:
    """Parse a source map's JSON and pull out original sources."""
    try:
        data = json.loads(text)
    except Exception:
        return {}
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    out = {}
    for i, src in enumerate(sources):
        if i < len(contents) and contents[i]:
            # Normalise webpack/vite prefixes into a safe relative path.
            name = str(src)
            name = name.replace("\\", "/")
            for pre in ("webpack://", "webpack-internal://"):
                if name.startswith(pre):
                    name = name[len(pre):]
                    break
            path = PurePosixPath(name)
            if (not name or "\x00" in name or path.is_absolute()
                    or ".." in path.parts or re.match(r"^[A-Za-z]:", name)
                    or not path.parts or not isinstance(contents[i], str)):
                continue
            out[str(path)] = contents[i]
    return out


def reconstruct_dir(root: Path, out_dir: Path, *, redact: bool = True) -> int:
    """Find every *.map under root, recover sources into out_dir. Returns file count."""
    out_dir.mkdir(parents=True, exist_ok=True)
    recovered = 0
    for mapf in root.rglob("*.map"):
        try:
            files = extract_from_map(mapf.read_text(errors="ignore"))
        except Exception:
            continue
        for name, content in files.items():
            # Skip node_modules / vendor noise in recovered trees.
            if "node_modules" in name or "/vendor/" in name:
                continue
            dest = out_dir / name
            try:
                resolved_root = out_dir.resolve()
                if resolved_root not in dest.resolve().parents:
                    continue
                _write_recovered(out_dir, PurePosixPath(name).parts, content, redact=redact)
                recovered += 1
            except Exception:
                continue
    return recovered


def _write_recovered(root, parts, content, *, redact=True):
    """Anchor each open to a directory descriptor; refuse links and collisions.

    Fail closed on platforms without openat/O_NOFOLLOW. O_EXCL also prevents
    truncating a pre-existing hard link. The output tree must be operator-owned.
    """
    if (os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd
            or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")):
        raise OSError("safe source recovery requires descriptor-relative opens")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(root, flags)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, "w", encoding="utf-8", errors="ignore") as handle:
            handle.write(redact_text(content) if redact else content)
    finally:
        os.close(directory)
