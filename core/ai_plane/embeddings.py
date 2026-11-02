"""Portable embeddings and an incrementally maintained vector cache.

SQLite remains authoritative.  The NPZ cache contains one *homogeneous*
embedding space only: every row is either produced by one Ollama model and one
dimension, or by the deterministic fallback.  Mixed/padded vector spaces are
rejected and rebuilt instead of silently degrading retrieval.
"""
from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from threading import local
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import requests

from core.llm_local import is_loopback_url

_FALLBACK_DIM = 256
_FALLBACK_MODEL = "tbhm-hash-v1"


class EmbeddingDeferred(RuntimeError):
    """Runtime work remains durable in SQLite and can be indexed later."""


def _hash_embed(text: str, dim: int = _FALLBACK_DIM) -> np.ndarray:
    vec = np.zeros(dim, dtype=np.float32)
    for tok in text.lower().split():
        h = int(hashlib.blake2b(tok.encode("utf-8"), digest_size=8).hexdigest(), 16)
        vec[h % dim] += 1.0
    norm = np.linalg.norm(vec)
    return vec / norm if norm else vec


class Embedder:
    def __init__(self, endpoint: str = "http://127.0.0.1:11434",
                 model: str = "nomic-embed-text", timeout: int = 60,
                 max_workers: int = 2):
        self.base = endpoint.rstrip("/")
        parsed = urlparse(self.base)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise ValueError("embedding endpoint must be an unauthenticated loopback URL")
        if not is_loopback_url(self.base):
            raise ValueError("embedding endpoint must resolve to loopback")
        self.model = model
        self.timeout = max(1, int(timeout))
        self.max_workers = max(1, min(int(max_workers), 8))
        self.session = requests.Session()
        self.session.trust_env = False
        self._thread_local = local()
        self._mode = "unknown"

    @staticmethod
    def _new_session() -> requests.Session:
        session = requests.Session()
        session.trust_env = False
        return session

    def _worker_session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = self._new_session()
            self._thread_local.session = session
        return session

    def _request_remote(self, text: str, session: requests.Session,
                        *, request_timeout=None) -> np.ndarray | None:
        try:
            response = session.post(
                f"{self.base}/api/embeddings",
                json={"model": self.model, "prompt": text},
                timeout=self.timeout if request_timeout is None else request_timeout,
                allow_redirects=False,
            )
            if 300 <= response.status_code < 400:
                return None
            response.raise_for_status()
            raw = response.json().get("embedding")
            if not isinstance(raw, list) or not raw:
                return None
            vector = np.asarray(raw, dtype=np.float32)
            if vector.ndim != 1 or not np.isfinite(vector).all():
                return None
            norm = np.linalg.norm(vector)
            return vector / norm if norm else vector
        except Exception:
            return None

    def _remote(self, text: str) -> np.ndarray | None:
        """Compatibility path used for the availability probe and single texts."""
        return self._request_remote(text, self.session)

    def _remote_worker(self, text: str) -> np.ndarray | None:
        return self._request_remote(text, self._worker_session())

    def embed_many(self, texts: list[str], *, force_mode: str | None = None) -> tuple[np.ndarray, str]:
        """Embed a batch in one coherent space.

        If even one remote embedding fails or dimensions disagree, the *whole*
        batch is regenerated with the deterministic fallback.  We never pad and
        mix remote/fallback vectors.
        """
        if not texts:
            mode = force_mode or "fallback"
            dim = _FALLBACK_DIM
            return np.zeros((0, dim), dtype=np.float32), mode

        if force_mode != "fallback":
            # Probe once before submitting a batch. This preserves the cheap,
            # deterministic fallback when Ollama is unavailable and prevents a
            # failed local endpoint from receiving one request per source chunk.
            first = self._remote(texts[0])
            remote: list[np.ndarray] = [first] if first is not None else []
            if first is not None and len(texts) > 1:
                if self.max_workers == 1:
                    rest = [self._remote(text) for text in texts[1:]]
                else:
                    with ThreadPoolExecutor(max_workers=min(self.max_workers, len(texts) - 1),
                                            thread_name_prefix="tbhm-embed") as pool:
                        rest = list(pool.map(self._remote_worker, texts[1:]))
                if all(vector is not None for vector in rest):
                    remote.extend(rest)
                else:
                    remote = []
            if remote and len(remote) == len(texts) and len({int(v.shape[0]) for v in remote}) == 1:
                self._mode = "ollama"
                return np.vstack(remote).astype(np.float32), "ollama"
            if force_mode == "ollama":
                raise RuntimeError("locked Ollama embedding space is unavailable")

        self._mode = "fallback"
        return np.vstack([_hash_embed(text) for text in texts]), "fallback"

    def embed(self, text: str, *, force_mode: str | None = None) -> tuple[np.ndarray, str]:
        matrix, mode = self.embed_many([text], force_mode=force_mode)
        return matrix[0], mode

    def space_id(self, mode: str, dim: int) -> str:
        model = self.model if mode == "ollama" else _FALLBACK_MODEL
        return f"{mode}:{model}:{dim}"

    def embed_runtime_batch(self, texts, *, force_mode=None, deadline,
                            cancelled=lambda: False, progress=lambda *_: None):
        """Small sequential batches; never start a new request after cancellation.

        Explicit source indexing retains embed_many's existing worker contract.
        Runtime indexing uses no detached workers and never replaces a valid
        remote space with fallback vectors after a model/transport failure.
        """
        def check(*, before_request=False):
            if cancelled():
                raise EmbeddingDeferred("scan cancellation requested")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or (before_request and remaining < 1.0):
                raise EmbeddingDeferred("runtime embedding time budget exhausted")
            return remaining

        mode = force_mode
        vectors = []
        for number, value in enumerate(texts, 1):
            remaining = check(before_request=True)
            if mode == "fallback":
                vector = _hash_embed(value)
            else:
                vector = self._request_remote(
                    value, self.session,
                    request_timeout=min(float(self.timeout), 5.0, remaining))
                check()
                if vector is None:
                    if mode is None and not vectors:
                        mode = "fallback"
                        vector = _hash_embed(value)
                    else:
                        raise EmbeddingDeferred("runtime embedding model unavailable")
                else:
                    mode = "ollama"
            if vectors and vector.shape != vectors[0].shape:
                raise EmbeddingDeferred("runtime embedding dimensions changed")
            vectors.append(vector)
            progress(number, len(texts))
        check()
        self._mode = mode or "fallback"
        dim = _FALLBACK_DIM if not vectors else len(vectors[0])
        return (np.vstack(vectors).astype(np.float32) if vectors else
                np.zeros((0, dim), dtype=np.float32)), self._mode


class VectorIndex:
    """Row-aligned matrix + chunk-ID manifest, persisted as a rebuildable NPZ."""

    def __init__(self, index_path: str | Path, manifest_path: str | Path):
        self.index_path = Path(index_path)
        self.manifest_path = Path(manifest_path)
        self.matrix = np.zeros((0, _FALLBACK_DIM), dtype=np.float32)
        self.chunk_ids: list[int] = []
        self.meta: dict = {}
        self.runtime_cancelled = None

    def load(self) -> bool:
        if not self.index_path.exists() or not self.manifest_path.exists():
            return False
        try:
            data = np.load(self.index_path, allow_pickle=False)
            matrix = np.asarray(data["matrix"], dtype=np.float32)
            chunk_ids = [int(v) for v in data["chunk_ids"].tolist()]
            meta = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            if matrix.ndim != 2 or matrix.shape[0] != len(chunk_ids):
                return False
            if len(set(chunk_ids)) != len(chunk_ids) or not np.isfinite(matrix).all():
                return False
            if int(meta.get("rows", -1)) != matrix.shape[0]:
                return False
            if matrix.size and int(meta.get("dim", -1)) != matrix.shape[1]:
                return False
            expected = f"{meta.get('embedding_mode')}:{meta.get('model')}:{meta.get('dim')}"
            if meta.get("vector_space_id") != expected:
                return False
            self.matrix, self.chunk_ids, self.meta = matrix, chunk_ids, meta
            return True
        except Exception:
            return False

    def _save(self, *, mode: str, model: str) -> None:
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.index_path.with_suffix(self.index_path.suffix + ".tmp.npz")
        np.savez_compressed(
            temp,
            matrix=self.matrix,
            chunk_ids=np.asarray(self.chunk_ids, dtype=np.int64),
        )
        temp.replace(self.index_path)
        dim = int(self.matrix.shape[1]) if self.matrix.ndim == 2 else 0
        self.meta = {
            "built_at": time.time(),
            "rows": int(self.matrix.shape[0]),
            "dim": dim,
            "embedding_mode": mode,
            "model": model,
            "vector_space_id": f"{mode}:{model}:{dim}",
            "note": "Rebuildable homogeneous cache; SQLite document_chunks is authoritative.",
        }
        manifest_temp = self.manifest_path.with_suffix(self.manifest_path.suffix+'.tmp')
        manifest_temp.write_text(json.dumps(self.meta, indent=2), encoding="utf-8")
        manifest_temp.replace(self.manifest_path)

    @staticmethod
    def _model_for(embedder: Embedder, mode: str) -> str:
        return embedder.model if mode == "ollama" else _FALLBACK_MODEL

    def rebuild(self, store, embedder: Embedder) -> dict:
        rows = store.all_chunks()
        texts = [r["text"] for r in rows]
        ids = [int(r["id"]) for r in rows]
        matrix, mode = embedder.embed_many(texts)
        self.matrix = matrix
        self.chunk_ids = ids
        model = self._model_for(embedder, mode)
        self._save(mode=mode, model=model)
        return {
            "rows": len(ids),
            "embedding_mode": mode,
            "model": model,
            "dim": int(matrix.shape[1]) if matrix.ndim == 2 else 0,
            "updated_rows": len(ids),
            "rebuild": True,
        }

    def update(self, store, embedder: Embedder, *, changed_ids: list[int],
               removed_ids: list[int]) -> dict:
        """Incrementally update rows; rebuild on embedding-space incompatibility."""
        changed = sorted({int(v) for v in changed_ids})
        removed = {int(v) for v in removed_ids}
        if not self.load():
            return self.rebuild(store, embedder)

        # Remove deleted/replaced rows and any changed IDs before re-adding them.
        drop = removed | set(changed)
        keep_positions = [i for i, cid in enumerate(self.chunk_ids) if cid not in drop]
        kept_matrix = self.matrix[keep_positions] if keep_positions else np.zeros(
            (0, self.matrix.shape[1]), dtype=np.float32)
        kept_ids = [self.chunk_ids[i] for i in keep_positions]

        new_matrix = np.zeros((0, self.matrix.shape[1]), dtype=np.float32)
        mode = str(self.meta.get("embedding_mode"))
        model = str(self.meta.get("model"))
        if changed:
            marks = ",".join("?" for _ in changed)
            rows = store.query(
                f"SELECT id, text FROM document_chunks WHERE id IN ({marks}) ORDER BY id", changed)
            actual_ids = [int(r["id"]) for r in rows]
            texts = [r["text"] for r in rows]
            candidate, candidate_mode = embedder.embed_many(texts)
            candidate_model = self._model_for(embedder, candidate_mode)
            if (candidate_mode != mode or candidate_model != model or
                    (candidate.size and candidate.shape[1] != self.matrix.shape[1])):
                # Availability/model changed: rebuild every row in one coherent space.
                return self.rebuild(store, embedder)
            new_matrix = candidate
            changed = actual_ids

        if new_matrix.shape[0]:
            self.matrix = np.vstack([kept_matrix, new_matrix])
        else:
            self.matrix = kept_matrix
        self.chunk_ids = kept_ids + changed
        self._save(mode=mode, model=model)
        return {
            "rows": len(self.chunk_ids),
            "embedding_mode": mode,
            "model": model,
            "dim": int(self.matrix.shape[1]) if self.matrix.ndim == 2 else 0,
            "updated_rows": len(changed),
            "removed_rows": len(removed),
            "rebuild": False,
        }

    def _query_vector(self, store, embedder: Embedder, query: str) -> np.ndarray | None:
        mode = str(self.meta.get("embedding_mode"))
        model = str(self.meta.get("model"))
        dim = int(self.meta.get("dim") or 0)
        if mode == "fallback":
            return _hash_embed(query, dim=dim or _FALLBACK_DIM)
        if mode != "ollama" or model != embedder.model:
            return None
        try:
            if self.runtime_cancelled is not None:
                matrix, actual_mode = embedder.embed_runtime_batch(
                    [query], force_mode="ollama", deadline=time.monotonic()+5,
                    cancelled=self.runtime_cancelled)
                vector = matrix[0]
            else:
                vector, actual_mode = embedder.embed(query, force_mode="ollama")
        except Exception:
            return None
        if actual_mode != "ollama" or vector.shape[0] != dim:
            return None
        return vector

    def search(self, store, embedder: Embedder, query: str, k: int = 6) -> list[dict]:
        if not self.load() or not self.chunk_ids:
            return []
        vector = self._query_vector(store, embedder, query)
        if vector is None:
            if self.runtime_cancelled is not None:
                # A retrieval request must not rebuild thousands of vectors in
                # the middle of a scan. Explicit index maintenance still can.
                return []
            # Current model/runtime is incompatible with the cache.  Rebuild once
            # rather than padding incompatible vectors.
            self.rebuild(store, embedder)
            vector = self._query_vector(store, embedder, query)
            if vector is None or not self.chunk_ids:
                return []

        similarities = self.matrix @ vector
        top = np.argsort(-similarities)[:max(1, k)]
        selected_ids = [self.chunk_ids[int(i)] for i in top]
        marks = ",".join("?" for _ in selected_ids)
        found = {int(r["id"]): r for r in store.query(
            f"SELECT c.id, c.text, c.symbol, c.kind, d.source_path, d.trust_level "
            f"FROM document_chunks c JOIN documents d ON d.id=c.document_id "
            f"WHERE c.id IN ({marks})", selected_ids)}
        output = []
        for i in top:
            pos = int(i)
            cid = self.chunk_ids[pos]
            row = found.get(cid)
            if not row:
                continue
            output.append({
                "score": float(similarities[pos]),
                "chunk_id": cid,
                "symbol": row["symbol"],
                "kind": row["kind"],
                "source_path": row["source_path"],
                "trust_level": row["trust_level"],
                "text": row["text"],
            })
        return output

    def update_pending(self, store, embedder, *, changed_ids=(), limit=8,
                       seconds=12.0, cancelled=lambda: False,
                       progress=lambda *_: None):
        """Reconcile a bounded batch with authoritative SQLite chunk IDs.

        Missing IDs are a durable backlog, even after a process restart or a
        lost vector cache. No extra schema, in-memory-only queue, full rebuild,
        or background writer is needed to preserve/retry captured knowledge.
        """
        started = time.monotonic()
        valid = self.load()
        current = {int(row["id"]) for row in store.query("SELECT id FROM document_chunks")}
        cached = set(self.chunk_ids) if valid else set()
        pending = current - cached
        priority = list(dict.fromkeys(int(cid) for cid in changed_ids if int(cid) in pending))
        priority_set = set(priority)
        chosen = (priority + sorted(pending-priority_set))[:max(1, min(int(limit), 32))]
        mode = str(self.meta.get("embedding_mode")) if valid else None
        model = str(self.meta.get("model")) if valid else None
        summary = {"status": "complete", "updated_rows": 0,
                   "pending_rows": len(pending), "rebuild": False}
        if cancelled():
            return {**summary, "status": "deferred", "reason": "scan cancellation requested"}
        if mode == "ollama" and model != embedder.model:
            return {**summary, "status": "deferred",
                    "reason": "embedding model changed; explicit index rebuild required"}
        if not chosen:
            # Deleted chunks are excluded from retrieval by the SQLite join.
            # Persist their removal without making any model requests.
            if valid and cached-current:
                keep = [i for i, cid in enumerate(self.chunk_ids) if cid in current]
                self.matrix = self.matrix[keep]
                self.chunk_ids = [self.chunk_ids[i] for i in keep]
                self._save(mode=mode, model=model)
            return summary
        marks = ",".join("?" for _ in chosen)
        rows = store.query(f"SELECT id, text FROM document_chunks WHERE id IN ({marks}) ORDER BY id", chosen)
        deadline = started+max(.01, min(float(seconds), 30.0))
        updated = 0
        reason = None
        for row in rows:
            try:
                if cancelled() or time.monotonic() >= deadline:
                    raise EmbeddingDeferred('cancelled or runtime embedding deadline reached')
                candidate, actual_mode = embedder.embed_runtime_batch(
                    [row['text']], force_mode=mode, deadline=deadline,
                    cancelled=cancelled)
                if (candidate.ndim != 2 or candidate.shape[0] != 1
                        or not candidate.shape[1] or not np.isfinite(candidate).all()):
                    raise EmbeddingDeferred('invalid embedding shape or nonfinite vector')
                if valid and (actual_mode != mode or candidate.shape[1] != self.matrix.shape[1]):
                    raise EmbeddingDeferred('runtime embedding space changed; cache retained')
            except (EmbeddingDeferred, OSError, ValueError, RuntimeError) as exc:
                reason = str(exc)
                break
            keep = [i for i, cid in enumerate(self.chunk_ids) if cid in current] if valid else []
            kept = self.matrix[keep] if keep else np.zeros((0, candidate.shape[1]), dtype=np.float32)
            self.matrix = np.vstack([kept, candidate])
            self.chunk_ids = ([self.chunk_ids[i] for i in keep] if valid else []) + [int(row['id'])]
            mode = actual_mode
            # A failed later row never discards this successful checkpoint.
            self._save(mode=mode, model=self._model_for(embedder, mode))
            valid = True
            updated += 1
            progress(updated, len(rows))
        remaining = len(current-set(self.chunk_ids))
        return {**summary, 'status': 'deferred' if reason else ('complete' if remaining == 0 else 'pending'),
                'reason': reason, 'updated_rows': updated, 'pending_rows': remaining,
                'rows': len(self.chunk_ids), 'embedding_mode': mode}

    def coverage(self, store):
        """Report actual cache coverage; a loadable partial cache is not complete."""
        valid = self.load()
        current = {int(row["id"]) for row in store.query("SELECT id FROM document_chunks")}
        cached = set(self.chunk_ids) if valid else set()
        return {"database_rows": len(current), "cached_rows": len(cached),
                "pending_rows": len(current-cached), "stale_rows": len(cached-current),
                "complete": valid and current == cached}
