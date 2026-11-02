"""Bounded run-artifact learning for the portable AI control plane.

Only sanitized textual artifacts produced by a phase are indexed.  This module
never executes content, follows links, changes findings, or modifies TBHM code.
Run artifacts are T3 untrusted evidence and are fenced/redacted before storage.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from core.ai_plane.sanitizer import scrub, wrap_untrusted

_ALLOWED = {".json", ".jsonl", ".csv", ".md", ".txt", ".xml", ".yaml", ".yml", ".log", ".sarif"}
_EXCLUDED_NAMES = {"tbhm.log", "tbhm.jsonl", "execution_ledger.json",
                   "execution_ledger.events.jsonl", "evidence_manifest.json", "phase_timings.json"}
_MAX_FILES = 20
_MAX_FILE_BYTES = 1_000_000
_MAX_TEXT = 120_000
_CHUNK = 4000


def _local_file(root, path):
    """Do not ingest links or files outside the run as AI evidence."""
    root = Path(root).resolve()
    path = Path(path)
    try:
        if not path.resolve().is_relative_to(root) or path.is_symlink():
            return False
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in {'delivery', 'llm_analysis'}:
            return False
        return not any((root/Path(*relative.parts[:i])).is_symlink()
                       for i in range(1, len(relative.parts)))
    except (ValueError, OSError):
        return False


def snapshot(root: str | Path) -> dict[str, tuple[int, int]]:
    root = Path(root).resolve()
    out: dict[str, tuple[int, int]] = {}
    if not root.exists():
        return out
    for p in root.rglob("*"):
        try:
            if (not _local_file(root, p) or not p.is_file() or p.suffix.lower() not in _ALLOWED or
                    p.name in _EXCLUDED_NAMES or p.stat().st_size > _MAX_FILE_BYTES):
                continue
            rel = p.relative_to(root).as_posix()
            st = p.stat()
            out[rel] = (int(st.st_mtime_ns), int(st.st_size))
        except Exception:
            continue
    return out


def changed_files(root: str | Path, before: dict[str, tuple[int, int]], *, limit: int = _MAX_FILES) -> list[Path]:
    root = Path(root).resolve()
    rows: list[tuple[int, Path]] = []
    for rel, state in snapshot(root).items():
        if before.get(rel) == state:
            continue
        p = root / rel
        if not _local_file(root, p):
            continue
        rows.append((state[0], p))
    rows.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in rows[: max(1, min(limit, _MAX_FILES))]]


def _chunks(text: str, *, phase: str, rel: str) -> list[dict]:
    redacted = scrub(text, limit=_MAX_TEXT)
    fenced = wrap_untrusted(redacted, "T3")
    pieces = []
    for ordinal, start in enumerate(range(0, len(fenced), _CHUNK)):
        value = fenced[start:start + _CHUNK]
        if not value.strip():
            continue
        pieces.append({
            "text": value,
            "symbol": f"run::{phase}::{rel}::{ordinal}",
            "kind": "run_artifact",
            "token_estimate": max(1, len(value) // 4),
            "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        })
    return pieces


def ingest_run_log(*, store, vector_index, embedder, run_uid: str,
                   output_root: str | Path, log_names=("tbhm.log", "tbhm.jsonl"),
                   max_tail_bytes: int = 400_000, cancelled=lambda: False,
                   progress=lambda *_: None) -> dict:
    """Ingest the run's own log stream as sanitized T3 knowledge.

    Per-phase artifact ingestion deliberately skips the raw log files; this pulls
    them in explicitly (bounded to the tail, redacted, fenced) so the co-pilot can
    learn what happened during the run and, across runs, stop repeating the same
    mistakes. It never executes log content or changes findings/scope/code.
    """
    root = Path(output_root).resolve()
    indexed: list[dict] = []
    added: list[int] = []
    removed: list[int] = []
    for name in log_names:
        p = root / name
        try:
            if not _local_file(root, p) or not p.is_file() or p.stat().st_size == 0:
                continue
            size = p.stat().st_size
            with p.open("r", encoding="utf-8", errors="ignore") as fh:
                if size > max_tail_bytes:
                    fh.seek(size - max_tail_bytes)
                    fh.readline()  # drop partial line
                raw = fh.read()
            chunks = _chunks(raw, phase="run_log", rel=name)
            if not chunks:
                continue
            digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
            doc_id = store.upsert_source_document(
                sha256=digest, source_type="run_log", source_path=f"runs/{run_uid}/logs/{name}",
                trust_level="T3", title=f"run log: {name}", sensitivity="sanitized-run-log",
                meta={"run_uid": run_uid, "log_name": name, "tail_bytes": min(size, max_tail_bytes),
                      "untrusted": True})
            delta = store.replace_chunks_delta(doc_id, chunks)
            added.extend(delta["added"])
            removed.extend(delta["removed"])
            indexed.append({"log": name, "chunks": len(chunks), "sha256": digest})
        except Exception:
            continue
    vector_result = vector_index.update_pending(
        store, embedder, changed_ids=added, cancelled=cancelled, progress=progress)
    return {"indexed_logs": len(indexed), "logs": indexed,
            "added_chunks": len(added), "removed_chunks": len(removed), "vector": vector_result}


def ingest_phase_artifacts(*, store, vector_index, embedder, run_uid: str,
                           phase: str, output_root: str | Path,
                           before: dict[str, tuple[int, int]],
                           cancelled=lambda: False, progress=lambda *_: None) -> dict:
    root = Path(output_root).resolve()
    changed = changed_files(root, before)
    added: list[int] = []
    removed: list[int] = []
    indexed: list[dict] = []
    for p in changed:
        try:
            if not _local_file(root, p):
                continue
            rel = p.relative_to(root).as_posix()
            raw = p.read_text(encoding="utf-8", errors="ignore")
            chunks = _chunks(raw, phase=phase, rel=rel)
            if not chunks:
                continue
            digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
            source_path = f"runs/{run_uid}/{phase}/{rel}"
            doc_id = store.upsert_source_document(
                sha256=digest, source_type="run_artifact", source_path=source_path,
                trust_level="T3", title=f"{phase}: {rel}", sensitivity="sanitized-run-evidence",
                meta={"phase": phase, "run_uid": run_uid, "relative_path": rel,
                      "original_size": p.stat().st_size, "untrusted": True},
            )
            delta = store.replace_chunks_delta(doc_id, chunks)
            added.extend(delta["added"])
            removed.extend(delta["removed"])
            indexed.append({"path": rel, "chunks": len(chunks), "sha256": digest})
        except Exception:
            continue
    vector_result = vector_index.update_pending(
        store, embedder, changed_ids=added, cancelled=cancelled, progress=progress)
    return {
        "changed_files": len(changed),
        "indexed_files": len(indexed),
        "files": indexed,
        "added_chunks": len(added),
        "removed_chunks": len(removed),
        "vector": vector_result,
    }
