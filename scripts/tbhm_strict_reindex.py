#!/usr/bin/env python3
"""Build a resumable, strictly Ollama-backed TBHM vector cache.

This is an operator maintenance command, not a source patch or a model trainer.
It uses the existing model lock, the existing chunk text and the legacy endpoint
used by TBHM. The live cache is installed only after every row has succeeded.
Oversized inputs are recursively split without discarding text. Their vectors
are combined with character-count weights and normalized, with provenance in
the checkpoint, vector manifest and audit. This is a retrieval approximation,
not an embedding of the entire long input or a model-quality evaluation.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time
from urllib.parse import quote

import numpy as np
import requests

MAINTENANCE_VERSION = "2026-10-23.context-split-1"
CONTEXT_POLICY = "split-full-text-character-weighted-mean/1"


class ContextLimitError(RuntimeError):
    """A model-declared context limit, eligible for bounded text subdivision."""


def emit(**fields):
    print(json.dumps(fields, sort_keys=True), flush=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise RuntimeError("Linked maintenance paths are not supported")
    if not path.is_file():
        raise RuntimeError("Required file missing: " + str(path))
    return path


def private_dir(path):
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise RuntimeError("Linked maintenance paths are not supported")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def atomic_bytes(path, data):
    descriptor, name = tempfile.mkstemp(prefix=".strict-", dir=path.parent)
    pending = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def read_chunks(path):
    uri = "file:" + quote(str(regular(path))) + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        connection.execute("PRAGMA query_only=ON")
        return connection.execute(
            "SELECT c.id,c.text FROM document_chunks c JOIN documents d "
            "ON d.id=c.document_id ORDER BY c.id").fetchall()
    finally:
        connection.close()


def snapshot(rows):
    digest = hashlib.sha256()
    for chunk_id, text in rows:
        if not isinstance(text, str):
            raise RuntimeError("Non-text source chunk encountered")
        encoded = text.encode("utf-8")
        digest.update(f"{chunk_id}:{len(encoded)}:".encode("ascii"))
        digest.update(encoded)
    return digest.hexdigest()


def file_state(path):
    return sha(regular(path).read_bytes()) if path.exists() else None


def ensure_idle(root):
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
        except (OSError, PermissionError):
            continue
        for value in argv:
            candidate = Path(os.fsdecode(value))
            if candidate.name not in {"tbhm.py", "tbhm"}:
                continue
            if not candidate.is_absolute():
                try:
                    candidate = (entry / "cwd").resolve() / candidate
                except OSError:
                    continue
            if candidate.absolute() in {root / "tbhm.py", root / "tbhm"}:
                raise RuntimeError("Another TBHM process is active; finish it before maintenance")


def model_digest(session, base, model):
    response = session.get(base + "/api/tags", timeout=(5, 20), allow_redirects=False)
    if response.status_code != 200:
        raise RuntimeError("Model inventory unavailable; HTTP " + str(response.status_code))
    candidates = response.json().get("models", [])
    match = next((row for row in candidates
                  if model in {row.get("name"), row.get("model")}), None)
    if not match or not isinstance(match.get("digest"), str) or not match["digest"]:
        raise RuntimeError("Locked model or its digest is unavailable")
    return match["digest"]


def _embedding_request(session, base, model, text, chunk_id, dimension, deadline):
    for attempt in range(1, 4):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Maintenance time budget exhausted; rerun to resume")
        transient = False
        status = None
        reason = "invalid_embedding"
        try:
            response = session.post(
                base + "/api/embeddings", json={"model": model, "prompt": text},
                timeout=(min(5, remaining), min(30, remaining)), allow_redirects=False)
            status = response.status_code
            try:
                data = response.json()
            except ValueError:
                data = {}
            error = str(data.get("error", "")).lower() if isinstance(data, dict) else ""
            if "context" in error or "input length" in error:
                raise ContextLimitError("Embedding model rejected the input context length")
            elif status != 200:
                reason = "http_error"
                transient = status in {408, 429, 500, 502, 503, 504}
            else:
                values = data.get("embedding") if isinstance(data, dict) else None
                if (isinstance(values, list) and len(values) == dimension
                        and all(isinstance(v, (int, float)) and not isinstance(v, bool)
                                and math.isfinite(v) for v in values)):
                    vector = np.asarray(values, dtype=np.float32)
                    norm = float(np.linalg.norm(vector))
                    if np.isfinite(vector).all() and math.isfinite(norm) and norm > 0:
                        return vector / norm
        except (requests.Timeout, requests.ConnectionError) as error:
            reason = type(error).__name__
            transient = True
        emit(status="embedding_error", chunk_id=chunk_id, characters=len(text),
             http=status, reason=reason, attempt=attempt, retry=transient and attempt < 3)
        if not transient or attempt == 3:
            raise RuntimeError("Embedding failed at chunk_id=" + str(chunk_id))
        time.sleep(min(attempt, max(0, deadline - time.monotonic())))
    raise RuntimeError("Embedding retry limit reached")


def embedding(session, base, model, text, chunk_id, dimension, deadline):
    """Return a full-input vector plus explicit metadata for any split input.

    Successful direct embeddings retain their original numerical path. Only a
    model-declared context error triggers subdivision, bounded to 64 leaves and
    eight levels. Every character occurs in exactly one successful leaf input.
    No tokenizer estimate, text truncation, context enlargement or hash fallback
    is used. Averaging preserves the one-row-per-chunk TBHM cache contract.
    """
    leaves = []

    def visit(start, end, depth):
        if len(leaves) >= 64:
            raise RuntimeError("Context split leaf budget exhausted at chunk_id=" + str(chunk_id))
        value = text[start:end]
        try:
            vector = _embedding_request(
                session, base, model, value, chunk_id, dimension, deadline)
        except ContextLimitError:
            if len(value) <= 32 or depth >= 8:
                raise RuntimeError("Context limit persists after bounded splitting at chunk_id="
                                   + str(chunk_id)) from None
            middle = start + len(value) // 2
            emit(status="splitting_context", chunk_id=chunk_id,
                 characters=len(value), depth=depth, text_discarded=False)
            visit(start, middle, depth + 1)
            visit(middle, end, depth + 1)
        else:
            leaves.append((start, end, vector))

    visit(0, len(text), 0)
    if len(leaves) == 1:
        return leaves[0][2], None
    if (leaves[0][0] != 0 or leaves[-1][1] != len(text)
            or any(left[1] != right[0] for left, right in zip(leaves, leaves[1:]))):
        raise RuntimeError("Internal full-text segment coverage check failed")
    combined = np.average(np.vstack([part[2] for part in leaves]), axis=0,
                          weights=[end - start for start, end, _ in leaves])
    norm = float(np.linalg.norm(combined))
    if not np.isfinite(combined).all() or not math.isfinite(norm) or norm <= 0:
        raise RuntimeError("Invalid pooled embedding at chunk_id=" + str(chunk_id))
    info = {"policy": CONTEXT_POLICY, "source_sha256": sha(text.encode("utf-8")),
            "source_characters": len(text), "parts": len(leaves),
            "segments": [{"start": start, "end": end,
                          "sha256": sha(text[start:end].encode("utf-8"))}
                         for start, end, _ in leaves],
            "text_discarded": False, "retrieval_quality_evaluated": False}
    emit(status="context_handled", chunk_id=chunk_id, parts=len(leaves),
         characters=len(text), text_discarded=False, policy=CONTEXT_POLICY)
    return (combined / norm).astype(np.float32), info


def validate_pooling(metadata, rows, completed):
    if not isinstance(metadata, dict):
        raise RuntimeError("Invalid checkpoint pooling metadata")
    available = {str(chunk_id): text for chunk_id, text in rows[:completed]}
    for chunk_id, info in metadata.items():
        if chunk_id not in available or not isinstance(info, dict):
            raise RuntimeError("Unexpected checkpoint pooled chunk identity")
        value = available[chunk_id]
        parts = info.get("segments")
        if (info.get("policy") != CONTEXT_POLICY or
                info.get("source_sha256") != sha(value.encode("utf-8")) or
                info.get("source_characters") != len(value) or
                not isinstance(parts, list) or not 2 <= len(parts) <= 64 or
                info.get("parts") != len(parts) or info.get("text_discarded") is not False):
            raise RuntimeError("Invalid checkpoint pooled chunk provenance")
        previous = 0
        for part in parts:
            start, end = part.get("start"), part.get("end")
            if (not isinstance(start, int) or not isinstance(end, int) or
                    isinstance(start, bool) or isinstance(end, bool) or
                    start != previous or not start < end <= len(value) or
                    part.get("sha256") != sha(value[start:end].encode("utf-8"))):
                raise RuntimeError("Invalid checkpoint text segment coverage")
            previous = end
        if previous != len(value):
            raise RuntimeError("Incomplete checkpoint text segment coverage")
    return metadata


def run(args):
    root = Path(args.tool_home).expanduser().absolute()
    home = Path(args.ai_home).expanduser().absolute()
    regular(root / "tbhm.py")
    regular(home / "database/memory.sqlite3")
    lock_path = regular(home / "models/model-lock.json")
    lock_bytes = lock_path.read_bytes()
    model = json.loads(lock_bytes).get("embedding_model")
    if not isinstance(model, str) or not model:
        raise RuntimeError("An explicit embedding_model is required in the existing model lock")
    ensure_idle(root)
    sys.path.insert(0, str(root))
    from core.ai_plane.embeddings import Embedder, VectorIndex
    from core.ai_plane.home import AIHome
    from core.ai_plane.proposals import Audit
    from core.ai_plane.store import Store

    embedder = Embedder(endpoint=args.url, model=model, max_workers=1)
    session = embedder.session
    base = embedder.base
    indexes = private_dir(home / "indexes")
    maint = private_dir(indexes / "strict-maintenance")
    lock_file = maint / "maintenance.lock"
    if lock_file.is_symlink():
        raise RuntimeError("Linked maintenance lock refused")
    with lock_file.open("a+") as exclusive:
        lock_file.chmod(0o600)
        try:
            fcntl.flock(exclusive, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another strict rebuild is already running") from None
        try:
            rebuild(args, root, home, lock_path, lock_bytes, model, base, session,
                    maint, VectorIndex, AIHome, Audit, Store)
        finally:
            session.close()


def rebuild(args, root, home, lock_path, lock_bytes, model, base, session,
            maint, VectorIndex, AIHome, Audit, Store):
    rows = read_chunks(home / "database/memory.sqlite3")
    if not rows:
        raise RuntimeError("No stored chunks; run source indexing before strict maintenance")
    data_sha = snapshot(rows)
    remote_digest = model_digest(session, base, model)
    signature = {"schema": "tbhm.strict-rebuild/1", "snapshot": data_sha,
                 "model": model, "model_digest": remote_digest, "url": base,
                 "dimension": args.dimension, "rows": len(rows),
                 "normalization": "float32-l2", "endpoint": "/api/embeddings"}
    work = private_dir(maint / sha(json.dumps(signature, sort_keys=True).encode()))
    checkpoint = work / "checkpoint.json"
    matrix_path = work / "matrix.npy"
    if checkpoint.exists():
        state = json.loads(regular(checkpoint).read_text())
        if state.get("signature") != signature:
            raise RuntimeError("Checkpoint identity mismatch")
        done = state.get("completed")
        if not isinstance(done, int) or isinstance(done, bool) or not 0 <= done <= len(rows):
            raise RuntimeError("Invalid checkpoint completion count")
        if state.get("context_policy") not in (None, CONTEXT_POLICY):
            raise RuntimeError("Unsupported checkpoint context policy")
        pooled_chunks = validate_pooling(state.get("pooled_chunks", {}), rows, done)
        matrix = np.load(regular(matrix_path), mmap_mode="r+", allow_pickle=False)
        if matrix.shape != (len(rows), args.dimension) or matrix.dtype != np.float32:
            raise RuntimeError("Invalid checkpoint matrix")
        prefix = matrix[:done]
        if (not np.isfinite(prefix).all() or
                (done and not np.allclose(np.linalg.norm(prefix, axis=1), 1, atol=1e-4))):
            raise RuntimeError("Invalid checkpoint vector values")
    else:
        if matrix_path.is_symlink():
            raise RuntimeError("Linked checkpoint matrix refused")
        matrix = np.lib.format.open_memmap(
            matrix_path, mode="w+", dtype=np.float32, shape=(len(rows), args.dimension))
        matrix_path.chmod(0o600)
        done = 0
        pooled_chunks = {}
    current = home / "indexes/vectors.npz"
    manifest = home / "indexes/vector-manifest.json"
    initial = {path: file_state(path) for path in (current, manifest)}
    start = time.monotonic()
    deadline = start + args.max_seconds
    emit(status="building", total=len(rows), resumed_rows=done, model=model,
         dimension=args.dimension, checkpoint=str(work), training_executed=False,
         maintenance_version=MAINTENANCE_VERSION, context_policy=CONTEXT_POLICY)

    def save_checkpoint():
        matrix.flush()
        with matrix_path.open("rb") as stream:
            os.fsync(stream.fileno())
        completed_ids = {str(chunk_id) for chunk_id, _ in rows[:done]}
        saved_pooling = {key: value for key, value in pooled_chunks.items()
                         if key in completed_ids}
        atomic_bytes(checkpoint, json.dumps(
            {"signature": signature, "completed": done,
             "context_policy": CONTEXT_POLICY, "pooled_chunks": saved_pooling},
            sort_keys=True).encode())

    last_message = start
    try:
        for index in range(done, len(rows)):
            chunk_id, text = rows[index]
            vector, info = embedding(session, base, model, text, chunk_id,
                                     args.dimension, deadline)
            matrix[index] = vector
            if info is not None:
                pooled_chunks[str(chunk_id)] = info
            done = index + 1
            now = time.monotonic()
            if done % 32 == 0:
                save_checkpoint()
            if done % 50 == 0 or now - last_message >= 5 or done == len(rows):
                emit(status="progress", completed=done, total=len(rows),
                     elapsed_seconds=round(now - start, 1))
                last_message = now
    finally:
        save_checkpoint()
    ensure_idle(root)
    if snapshot(read_chunks(home / "database/memory.sqlite3")) != data_sha:
        raise RuntimeError("Stored chunk text changed; live cache was not replaced")
    if lock_path.read_bytes() != lock_bytes:
        raise RuntimeError("Model lock changed; live cache was not replaced")
    if model_digest(session, base, model) != remote_digest:
        raise RuntimeError("Model digest changed; live cache was not replaced")
    staged = VectorIndex(work / "vectors.npz", work / "vector-manifest.json")
    staged.matrix = np.asarray(matrix)
    staged.chunk_ids = [int(row[0]) for row in rows]
    staged._save(mode="ollama", model=model)
    metadata = json.loads(staged.manifest_path.read_text())
    metadata.update(context_policy=CONTEXT_POLICY, pooled_chunks=pooled_chunks,
                    source_text_modified=False, retrieval_quality_evaluated=False)
    atomic_bytes(staged.manifest_path, json.dumps(metadata, indent=2).encode())
    staged.index_path.chmod(0o600)
    staged.manifest_path.chmod(0o600)
    if not staged.load() or staged.meta.get("embedding_mode") != "ollama":
        raise RuntimeError("Staged cache did not pass the TBHM cache reader")
    store = Store(home / "database/memory.sqlite3")
    try:
        audit = Audit(store, AIHome(home))
        intact, _ = audit.verify_chain()
        if not intact:
            raise RuntimeError("Existing audit chain is not intact; no cache installed")
        if any(file_state(path) != initial[path] for path in initial):
            raise RuntimeError("Another writer changed the live cache; no cache installed")
        backup = private_dir(work / ("backup-" + str(time.time_ns())))
        destination = sqlite3.connect(str(backup / "memory.sqlite3"))
        try:
            store.conn.backup(destination)
        finally:
            destination.close()
        (backup / "memory.sqlite3").chmod(0o600)
        for path in initial:
            if path.exists():
                shutil.copy2(path, backup / path.name)
                (backup / path.name).chmod(0o600)
        if snapshot(read_chunks(home / "database/memory.sqlite3")) != data_sha:
            raise RuntimeError("Stored chunk text changed during backup; no cache installed")
        ensure_idle(root)
        installed = []
        try:
            for target, source in ((current, staged.index_path), (manifest, staged.manifest_path)):
                atomic_bytes(target, source.read_bytes())
                installed.append(target)
            loaded = VectorIndex(current, manifest)
            if not loaded.load() or loaded.chunk_ids != staged.chunk_ids:
                raise RuntimeError("Installed cache validation failed")
            audit.record("ai.strict-vector-rebuild", model,
                         {"rows": len(rows), "dimension": args.dimension,
                          "model_digest": remote_digest, "snapshot_sha256": data_sha,
                          "backup": str(backup), "training_executed": False,
                          "context_policy": CONTEXT_POLICY,
                          "pooled_chunks": pooled_chunks,
                          "retrieval_quality_evaluated": False})
            intact, detail = audit.verify_chain()
            if not intact:
                raise RuntimeError("Final audit verification failed; restoring cache")
        except BaseException:
            for target in reversed(installed):
                previous = backup / target.name
                if initial[target] is None:
                    target.unlink(missing_ok=True)
                else:
                    atomic_bytes(target, previous.read_bytes())
            raise
        emit(status="complete", embedding_mode="ollama", model=model,
             dim=args.dimension, rows=len(rows), vector_cache_complete=True,
             audit_intact=intact, audit_detail=detail, backup=str(backup),
             training_executed=False, tool_source_modified=False,
             pooled_chunk_count=len(pooled_chunks), context_policy=CONTEXT_POLICY,
             source_text_modified=False, retrieval_quality_evaluated=False)
    finally:
        store.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=MAINTENANCE_VERSION)
    parser.add_argument("--tool-home", required=True)
    parser.add_argument("--ai-home", default=str(Path.home() / ".local/share/tbhm-ai"))
    parser.add_argument("--url", default="http://127.0.0.1:11435")
    parser.add_argument("--dimension", type=int, default=768)
    parser.add_argument("--max-seconds", type=int, default=1800)
    args = parser.parse_args()
    if not 1 <= args.dimension <= 16384 or not 1 <= args.max_seconds <= 86400:
        parser.error("Invalid dimension or maintenance time budget")
    os.umask(0o077)
    try:
        run(args)
        return 0
    except KeyboardInterrupt:
        emit(status="interrupted", detail="Rerun the same command to resume")
        return 130
    except Exception as error:
        emit(status="failed", error_type=type(error).__name__, detail=str(error)[:300],
             note="See the last progress/error record. Completed checkpoint rows are retained.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
