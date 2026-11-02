"""Delta-aware TBHM source indexer.

The source path is the identity and its content hash is the version.  A changed
file replaces its prior document/chunks, stores a redacted snapshot for a real
unified diff, and updates only changed vector rows.  Deleted files are removed
from both SQLite and the vector cache.  This prevents stale old code from being
retrieved after a ZIP replacement.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import os
import subprocess
import time
from pathlib import Path

from core.ai_plane.sanitizer import scrub

INDEX_EXTS = {".py", ".yaml", ".yml", ".md", ".sh", ".txt", ".example", ".java"}
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".venv", "venv", "node_modules", "results", "dist", "build",
}
_MAX_CHUNK_CHARS = 4000
_MAX_SNAPSHOT_CHARS = 2_000_000
_MAX_DIFF_CHARS = 16_000


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_commit(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=8, check=False,
        )
        return result.stdout.strip() or None if result.returncode == 0 else None
    except Exception:
        return None


def _tbhm_version(root: Path) -> str:
    changelogs = sorted(root.glob("CHANGELOG-v*.md"))
    return changelogs[-1].stem.replace("CHANGELOG-", "") if changelogs else "unknown"


def iter_source_files(root: Path):
    """Yield every packaged text/code/config resource relevant to the tool.

    Previous releases indexed only core/phases/profiles/docs and omitted tests,
    add-ons, reverse scripts, bundled templates, payloads and wordlists.
    """
    root = Path(root)
    # Arbitrarily named run folders and copied AI homes are not tool source.
    # Prune before descent; never follow a source-tree link into private data.
    for base, dirs, files in os.walk(root, followlinks=False):
        base = Path(base)
        if base != root and any((base/name).exists() for name in
                ('tbhm.db', 'execution_ledger.json', '.tbhm-ai-home')):
            dirs[:] = []
            continue
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not (base/d).is_symlink())
        for name in sorted(files):
            path = base/name
            if path.is_file() and not path.is_symlink() and path.suffix.lower() in INDEX_EXTS:
                yield path


def _mk(text: str, symbol=None, kind="text") -> dict:
    redacted = scrub(text, limit=_MAX_CHUNK_CHARS + 500)
    return {
        "text": redacted,
        "symbol": symbol,
        "kind": kind,
        "token_estimate": max(1, len(redacted) // 4),
        "sha256": _sha256(redacted.encode("utf-8")),
    }


def _split_big(chunk: dict) -> list[dict]:
    text = chunk["text"]
    if len(text) <= _MAX_CHUNK_CHARS:
        return [chunk]
    return [
        _mk(text[i:i + _MAX_CHUNK_CHARS], symbol=chunk.get("symbol"), kind=chunk.get("kind"))
        for i in range(0, len(text), _MAX_CHUNK_CHARS)
    ]


def _chunk_python(text: str, rel: str) -> list[dict]:
    chunks: list[dict] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _chunk_text(text, rel, kind="module")
    lines = text.splitlines()

    doc = ast.get_docstring(tree)
    if doc:
        chunks.append(_mk(f"module docstring of {rel}\n\n{doc}", symbol=rel, kind="module"))

    def segment(node) -> str:
        start = max(0, getattr(node, "lineno", 1) - 1)
        end = getattr(node, "end_lineno", start + 1)
        return "\n".join(lines[start:end])

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            chunks.append(_mk(
                f"# {rel} :: function {node.name}\n{segment(node)}",
                symbol=f"{rel}::{node.name}", kind="function",
            ))
        elif isinstance(node, ast.ClassDef):
            class_doc = ast.get_docstring(node)
            if class_doc:
                chunks.append(_mk(
                    f"# {rel} :: class {node.name}\n{class_doc}",
                    symbol=f"{rel}::{node.name}", kind="class",
                ))
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    chunks.append(_mk(
                        f"# {rel} :: {node.name}.{sub.name}\n{segment(sub)}",
                        symbol=f"{rel}::{node.name}.{sub.name}", kind="method",
                    ))
    if not chunks:
        return _chunk_text(text, rel, kind="module")
    return [part for chunk in chunks for part in _split_big(chunk)]


def _chunk_text(text: str, rel: str, kind: str = "text") -> list[dict]:
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.startswith("#") and current:
            blocks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    output: list[dict] = []
    for block in blocks:
        if block.strip():
            output.extend(_split_big(_mk(f"# {rel}\n{block}", symbol=rel, kind=kind)))
    return output or [_mk(f"# {rel}\n{text[:_MAX_CHUNK_CHARS]}", symbol=rel, kind=kind)]


def chunk_file(path: Path, rel: str) -> list[dict]:
    text = path.read_text(errors="ignore")
    if path.suffix.lower() == ".py":
        return _chunk_python(text, rel)
    kind = "yaml" if path.suffix.lower() in {".yaml", ".yml"} else "text"
    return _chunk_text(text, rel, kind=kind)


def compute_delta(root: Path, store) -> dict:
    prev = store.manifest_map()
    seen: dict[str, str] = {}
    for path in iter_source_files(root):
        rel = path.relative_to(root).as_posix()
        seen[rel] = _sha256(path.read_bytes())
    return {
        "added": sorted(rel for rel in seen if rel not in prev),
        "modified": sorted(rel for rel in seen if rel in prev and prev[rel] != seen[rel]),
        "deleted": sorted(rel for rel in prev if rel not in seen),
        "seen": seen,
    }


def _source_type(rel: str) -> str:
    if rel.startswith("CHANGELOG"):
        return "changelog"
    if rel.startswith("profiles/"):
        return "profile"
    if rel.startswith(("docs/", "checklists/", "templates/")) or rel.endswith(".md"):
        return "doc"
    if rel.startswith(("nuclei-templates/", "payloads/", "wordlists/")):
        return "tool_resource"
    if rel.startswith("integration_test"):
        return "test"
    return "source_code"


def _safe_snapshot(text: str) -> str:
    limit = min(max(len(text) + 256, 6000), _MAX_SNAPSHOT_CHARS)
    return scrub(text, limit=limit)


def _unified_diff(rel: str, old: str, new: str) -> str:
    lines = difflib.unified_diff(
        old.splitlines(), new.splitlines(),
        fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="",
    )
    output = "\n".join(lines)
    if len(output) > _MAX_DIFF_CHARS:
        output = output[:_MAX_DIFF_CHARS] + "\n...[diff truncated]"
    return output


def reindex(root: Path, store, embedder, vector_index, *, full: bool = False,
            log=lambda *args: None) -> dict:
    root = Path(root)
    version = _tbhm_version(root)
    commit = _git_commit(root)
    delta = compute_delta(root, store)
    changed = sorted(delta["seen"]) if full else sorted(set(delta["added"] + delta["modified"]))

    changed_chunk_ids: list[int] = []
    removed_chunk_ids: list[int] = []
    source_diffs: list[dict] = []
    reindexed = 0

    for rel in changed:
        path = root / rel
        if not path.is_file():
            continue
        data = path.read_bytes()
        sha = _sha256(data)
        raw_text = path.read_text(errors="ignore")
        snapshot = _safe_snapshot(raw_text)
        previous = store.source_snapshot(rel)
        old_text = previous["text"] if previous else ""
        diff_text = _unified_diff(rel, old_text, snapshot)
        if diff_text and not full:
            source_diffs.append({
                "file": rel,
                "change": "added" if previous is None else "modified",
                "diff": diff_text,
            })

        doc_id = store.upsert_source_document(
            sha256=f"{sha}:{rel}", source_type=_source_type(rel), source_path=rel,
            trust_level="T1", title=rel,
            meta={"tbhm_version": version, "git_commit": commit},
        )
        chunk_delta = store.replace_chunks_delta(doc_id, chunk_file(path, rel))
        changed_chunk_ids.extend(chunk_delta["added"])
        removed_chunk_ids.extend(chunk_delta["removed"])
        store.set_source_snapshot(file_path=rel, sha256=sha, text=snapshot)
        store.record_manifest(
            tbhm_version=version, git_commit=commit, file_path=rel,
            sha256=sha, size=len(data), mtime=path.stat().st_mtime,
        )
        reindexed += 1

    for rel in delta["deleted"]:
        rows = store.query(
            "SELECT c.id FROM document_chunks c JOIN documents d ON d.id=c.document_id "
            "WHERE d.source_path=?", (rel,),
        )
        removed_chunk_ids.extend(int(row["id"]) for row in rows)
        previous = store.source_snapshot(rel)
        if previous and not full:
            source_diffs.append({
                "file": rel, "change": "deleted",
                "diff": _unified_diff(rel, previous["text"], ""),
            })
        store.tombstone_source(rel)

    if full:
        vector_info = vector_index.rebuild(store, embedder)
    elif changed_chunk_ids or removed_chunk_ids:
        vector_info = vector_index.update(
            store, embedder,
            changed_ids=changed_chunk_ids,
            removed_ids=removed_chunk_ids,
        )
    elif vector_index.load():
        vector_info = {
            "rows": len(vector_index.chunk_ids),
            "embedding_mode": vector_index.meta.get("embedding_mode", "unknown"),
            "model": vector_index.meta.get("model"),
            "dim": vector_index.meta.get("dim", 0),
            "updated_rows": 0,
            "removed_rows": 0,
            "rebuild": False,
        }
    else:
        vector_info = vector_index.rebuild(store, embedder)

    summary = {
        "tbhm_version": version,
        "git_commit": commit,
        "added": delta["added"],
        "modified": delta["modified"],
        "deleted": delta["deleted"],
        "files_tracked": len(delta["seen"]),
        "files_reindexed": reindexed,
        "chunk_rows_added": len(set(changed_chunk_ids)),
        "chunk_rows_removed": len(set(removed_chunk_ids)),
        "source_diffs": source_diffs,
        "vector_index": vector_info,
        "indexed_at": time.time(),
    }
    log(
        "OK", "ai-index",
        f"reindexed={reindexed} deleted={len(delta['deleted'])} "
        f"vectors={vector_info.get('rows')} updated={vector_info.get('updated_rows')} "
        f"mode={vector_info.get('embedding_mode')}",
    )
    return summary
