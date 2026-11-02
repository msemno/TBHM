"""TBHM AI Control Plane.

A separate, portable, non-authoritative co-pilot layer. It observes TBHM through
structured events, retrieves TBHM's own source for grounding, and proposes (never
applies) improvements. All state lives in $TBHM_AI_HOME, outside the tool tree, so
it survives ZIP replacement and laptop moves.

Public entry points:
    build_plane(args)   -> Plane   (assembles store/embedder/index/advisor/gate)
    core.ai_plane.cli   -> --ai-*  command dispatch
    RunObserver         -> orchestrator hooks
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import copy
import json

from core.version import VERSION

__version__ = VERSION


@dataclass
class Plane:
    home: object
    store: object
    embedder: object
    vector_index: object
    advisor: object
    gate: object
    audit: object
    runtime: object

    def close(self):
        try:
            self.store.close()
        except Exception:
            pass


def build_plane(args, *, create: bool = False, need_runtime: bool = True,
                honor_model_lock: bool = True) -> Plane:
    """Assemble the plane using the portable model lock as source of truth.

    Normal commands honor ``models/model-lock.json`` so a later CLI default or
    environment change cannot silently mix advisor/embedding models.  First-run
    bootstrap explicitly disables this until it writes the chosen lock.
    """
    from core.ai_plane import home as home_mod
    from core.ai_plane.store import Store
    from core.ai_plane.embeddings import Embedder, VectorIndex
    from core.ai_plane.advisor import Advisor
    from core.ai_plane.proposals import Audit, ProposalGate

    home = home_mod.get(getattr(args, "ai_home", None), create=create)
    store = Store(home.db_path)

    runtime_args = copy.copy(args)
    locked = {}
    if honor_model_lock and home.model_lock.is_file():
        try:
            locked = json.loads(home.model_lock.read_text(encoding="utf-8"))
        except Exception:
            locked = {}
    if (getattr(args, 'ai_advisor_model', None) and
            (getattr(args, '_ai_advisor_model_explicit', False) or not locked.get('advisor_model'))):
        runtime_args.local_llm_model = str(args.ai_advisor_model)
    elif locked.get("advisor_model") and not getattr(args, '_local_llm_model_explicit', False):
        runtime_args.local_llm_model = str(locked["advisor_model"])
        runtime_args.ai_advisor_model = str(locked["advisor_model"])
    if locked.get("embedding_model") and not getattr(args, '_ai_embedding_model_explicit', False):
        runtime_args.ai_embedding_model = str(locked["embedding_model"])

    endpoint = getattr(runtime_args, "local_llm_url", None) or "http://127.0.0.1:11434"
    emb_model = getattr(runtime_args, "ai_embedding_model", None) or "nomic-embed-text"
    emb_workers = getattr(runtime_args, "ai_embedding_workers", None) or 2
    try:
        embedder = Embedder(endpoint=endpoint, model=emb_model, max_workers=emb_workers)
    except Exception:
        embedder = Embedder()  # defaults; still loopback-guarded

    vector_index = VectorIndex(home.index_path, home.index_manifest)

    runtime = None
    client = None
    if need_runtime:
        try:
            from core.llm_local import runtime_from_args
            runtime = runtime_from_args(runtime_args)
            client = runtime.client
        except Exception:
            runtime = None
            client = None

    retrieval = (store, embedder, vector_index)
    from core.ai_plane.public_knowledge import default_path
    public_catalog = None if getattr(args, 'no_ai_knowledge', False) else default_path(args, home.root)
    advisor = Advisor(client or _NullClient(), retrieval=retrieval, public_catalog=public_catalog)
    audit = Audit(store, home)
    gate = ProposalGate(store, home, audit)

    return Plane(home=home, store=store, embedder=embedder, vector_index=vector_index,
                 advisor=advisor, gate=gate, audit=audit, runtime=runtime)


class _NullClient:
    """Stands in when no local model is configured, so retrieval/CLI still work.
    Any attempt to actually chat raises a clear, safe error."""
    def available(self):
        return False, "no local model configured"

    def chat_json(self, system, user):
        raise RuntimeError("local model not available; advisor analysis skipped")
