"""First-run bootstrap for the AI plane.

Run once, standalone, during (or after) TBHM installation, before any scan:

    export TBHM_AI_HOME="$HOME/.local/share/tbhm-ai"
    ./tbhm.py --ai-init --ai-model qwen3-cybersec:4b --ai-embedding-model nomic-embed-text

Steps:
  1. create the portable home + directory layout
  2. initialize SQLite + apply schema migrations
  3. record the selected model roles (advisor/embedding)
  4. optionally pull/create models via the existing safe Ollama setup path
  5. full-index the current TBHM source + docs and build the vector index
  6. write model-lock.json and an initial baseline
This does NOT redistribute weights; models are pulled by the operator's Ollama.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path


def run_init(args, root: Path, log=print) -> dict:
    from core.ai_plane import build_plane
    from core.ai_plane import indexer
    from core.hardware_profile import detect as detect_hw

    plane = build_plane(args, create=True, need_runtime=True, honor_model_lock=False)
    home = plane.home
    result: dict = {"home": str(home.root), "steps": []}

    def step(name, ok, detail=""):
        result["steps"].append({"step": name, "ok": bool(ok), "detail": detail})
        log(f"[ai-init] {'OK ' if ok else 'FAIL'} {name} {('- ' + detail) if detail else ''}")

    step("home_created", home.exists(), str(home.root))
    step("db_migrated", True, f"schema at {home.db_path}")

    advisor_model = getattr(args, "ai_advisor_model", None) or getattr(args, "local_llm_model", None) \
        or "qwen3-cybersec:4b"
    emb_model = getattr(args, "ai_embedding_model", None) or "nomic-embed-text"
    plane.store.record_model(role="advisor", name=advisor_model)
    plane.store.record_model(role="embedding", name=emb_model)
    step("models_registered", True, f"advisor={advisor_model} embedding={emb_model}")

    # Optional model pull (skipped with --ai-no-pull). Reuses the vetted setup path.
    if not getattr(args, "ai_no_pull", False) and shutil.which("ollama"):
        from core.llm_local import setup_local_model
        class _A:  # shim mapping ai-init flags onto setup_local_model's expectations
            pass
        a = _A()
        a.local_llm_model = advisor_model
        a.local_llm_modelfile = getattr(args, "local_llm_modelfile", None)
        a.local_llm_setup_timeout = getattr(args, "local_llm_setup_timeout", 3600)
        pull = setup_local_model(a)
        step("advisor_model_pull", pull.get("ok"), pull.get("detail", "")[:200])
        # embedding model pull
        a.local_llm_model = emb_model
        a.local_llm_modelfile = None
        pull_e = setup_local_model(a)
        step("embedding_model_pull", pull_e.get("ok"), pull_e.get("detail", "")[:200])
    else:
        step("model_pull", True, "skipped (no ollama binary or --ai-no-pull)")

    # Full index of the tool.
    try:
        summary = indexer.reindex(root, plane.store, plane.embedder, plane.vector_index,
                                  full=True, log=lambda *a: None)
        step("source_indexed", True,
             f"files={summary['files_reindexed']} vectors={summary['vector_index'].get('rows')} "
             f"mode={summary['vector_index'].get('embedding_mode')}")
    except Exception as e:
        summary = {}
        step("source_indexed", False, str(e))

    # model-lock + hardware profile.
    hw = detect_hw()
    home.model_lock.write_text(json.dumps({
        "advisor_model": advisor_model,
        "embedding_model": emb_model,
        "hardware": hw,
        "created_at": time.time(),
        "note": "Reinstall Ollama and re-pull these exact models when migrating.",
    }, indent=2), encoding="utf-8")
    step("model_lock_written", True, str(home.model_lock))

    plane.audit.record("ai.init", None, {"advisor": advisor_model, "embedding": emb_model,
                                         "indexed": summary.get("files_reindexed", 0)})
    result["counts"] = plane.store.counts()
    result["hardware"] = hw
    plane.close()
    return result
