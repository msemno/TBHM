#!/usr/bin/env python3
"""Integration test for the v3.9.4 AI Control Plane.

Runs fully offline: no Ollama, no network. The embedder degrades to its
deterministic hashing fallback, so indexing/retrieval/rebuild all exercise
without a model. Covers the pieces most likely to regress:

  * portable home layout + SQLite schema/migration
  * full index of the real TBHM source, then delta detection on a change
  * vector index rebuild from the authoritative chunk table + retrieval
  * confirmation-status resolver against the REAL nested-enrichment shape
    (finding["enrichment"]["exploitability"]["confirmation_status"]) and the
    computed fallback via exploitability.assess()
  * strict-JSON schema validation (advisor.validate)
  * propose-and-approve gate + tamper-evident audit hash-chain
  * backup (VACUUM INTO + tarball) -> restore round-trip

Exit code 0 = all pass.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

FAILS = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        FAILS.append(name)


def _args(home: Path, endpoint: str):
    return argparse.Namespace(
        ai_home=str(home), local_llm_url=endpoint,
        ai_embedding_model="nomic-embed-text", local_llm_model="qwen3-cybersec:4b",
        local_llm_context=0, local_llm_timeout=180,
    )


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="tbhm-ai-test-"))
    home_dir = tmp / "aihome"
    from scripts.regression_support import unavailable_model_endpoint
    reservation = unavailable_model_endpoint()
    endpoint = reservation.__enter__()
    try:
        from core.ai_plane import build_plane
        from core.ai_plane import indexer
        from core.ai_plane.advisor import validate, RUN_ANALYSIS_SCHEMA
        from core.ai_plane.findings import confirmation_status, is_confirmed

        # -- home + schema ----------------------------------------------------
        plane = build_plane(_args(home_dir, endpoint), create=True, need_runtime=False)
        check("home layout created", plane.home.exists(), str(plane.home.root))
        check("db schema present", plane.store.counts().get("documents") == 0)

        # -- full index of real source ---------------------------------------
        summary = indexer.reindex(ROOT, plane.store, plane.embedder,
                                  plane.vector_index, full=True, log=lambda *a: None)
        chunks = plane.store.counts().get("document_chunks", 0)
        check("source indexed", summary["files_reindexed"] > 50,
              f"{summary['files_reindexed']} files, {chunks} chunks")
        check("vector index built (fallback ok)",
              summary["vector_index"]["rows"] == chunks,
              f"rows={summary['vector_index']['rows']} mode={summary['vector_index']['embedding_mode']}")

        # -- retrieval --------------------------------------------------------
        hits = plane.vector_index.search(plane.store, plane.embedder,
                                         "resume skips phases marked done", k=5)
        check("retrieval returns hits", len(hits) > 0, f"{len(hits)} hits")

        # -- delta detection --------------------------------------------------
        target = ROOT / "profiles" / "quick_recon.yaml"
        original = target.read_text()
        try:
            target.write_text(original + "\n# ai-plane-test-marker\n")
            delta = indexer.compute_delta(ROOT, plane.store)
            check("delta detects modification",
                  "profiles/quick_recon.yaml" in delta["modified"],
                  f"modified={len(delta['modified'])}")
        finally:
            target.write_text(original)

        # -- confirmation-status resolver (the recheck fix) -------------------
        f_confirmed = {"id": 1, "title": "t", "severity": "HIGH", "phase": "audit",
                       "enrichment": {"exploitability": {"confirmation_status": "CONFIRMED"}}}
        f_supported = {"id": 2, "title": "t", "severity": "MEDIUM", "phase": "audit",
                       "enrichment": {"exploitability": {"confirmation_status": "SUPPORTED"}}}
        f_bare = {"id": 3, "title": "possible thing", "severity": "LOW", "phase": "business_logic"}
        check("forged nested CONFIRMED rejected", confirmation_status(f_confirmed) != "CONFIRMED")
        from test_support import verified_fields
        with tempfile.TemporaryDirectory() as capture_root:
            f_confirmed.update(verified_fields(capture_root))
        f_supported['finding_class'] = 'supported'
        check("authenticated confirmation resolved", confirmation_status(f_confirmed) == "CONFIRMED")
        check("nested SUPPORTED resolved", confirmation_status(f_supported) == "SUPPORTED")
        check("bare finding computed via assess()",
              confirmation_status(f_bare) in ("UNCONFIRMED", "SUPPORTED", "CONFIRMED"))
        check("is_confirmed only true for CONFIRMED",
              is_confirmed(f_confirmed) and not is_confirmed(f_supported))

        # -- strict-JSON schema validation ------------------------------------
        bad = {"overall_summary": "ok", "correlations": "none",  # wrong type
               "verify_next": [{"target": "x"}], "coverage_gaps": ["g"]}
        v = validate(bad, RUN_ANALYSIS_SCHEMA)
        check("schema coerces bad correlations to list", isinstance(v["correlations"], list)
              and v["correlations"] == [])
        check("schema keeps valid verify_next rows",
              isinstance(v["verify_next"], list) and v["verify_next"][0]["target"] == "x")

        # -- propose-and-approve + audit chain --------------------------------
        prop = plane.gate.create(problem="resume marks failed phase done",
                                 evidence=["run-1"], affected_files=["tbhm.py"],
                                 patch_text="--- a\n+++ b\n", expected_benefit="correct resume",
                                 risks=["none"])
        check("proposal created (pending, not applied)",
              (plane.home.proposals_pending / prop["proposal_id"]).exists())
        dec = plane.gate.decide(prop["proposal_id"], accept=True)
        check("approval archives, does not auto-apply",
              dec["status"] == "accepted" and dec["applied"] is False)
        ok_chain, chain_detail = plane.audit.verify_chain()
        check("audit hash-chain intact", ok_chain, chain_detail)

        plane.close()

        # -- backup -> restore round-trip -------------------------------------
        from core.ai_plane import cli as ai_cli
        plane2 = build_plane(_args(home_dir, endpoint), create=True, need_runtime=False)
        rc = ai_cli._backup(plane2)
        plane2.close()
        check("backup produced archive", rc == 0)
        archives = list(home_dir.glob("tbhm-ai-backup-*.tar*"))
        check("backup archive on disk", len(archives) == 1,
              archives[0].name if archives else "none")

        # restore into a fresh home
        home2 = tmp / "aihome-restored"
        rargs = _args(home2, endpoint)
        rargs.ai_restore = str(archives[0])
        rc = ai_cli._restore(rargs, ROOT)
        check("restore succeeded", rc == 0)
        plane3 = build_plane(_args(home2, endpoint), create=True, need_runtime=False)
        check("restored db has the indexed chunks",
              plane3.store.counts().get("document_chunks", 0) == chunks,
              f"{plane3.store.counts().get('document_chunks', 0)} chunks")
        plane3.close()

        print()
        if FAILS:
            print(f"RESULT: {len(FAILS)} FAILED — {FAILS}")
            return 1
        print("RESULT: ALL PASS")
        return 0
    finally:
        reservation.__exit__(None, None, None)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
