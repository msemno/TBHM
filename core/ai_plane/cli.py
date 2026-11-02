"""Dispatch for the --ai-* command family.

These are standalone maintenance/knowledge commands that do NOT need a scan target.
They cover the operator's whole portability lifecycle:

  first time:        ./tbhm.py --ai-init
  after code change: ./tbhm.py --ai-sync-tool          (delta re-index only)
  new ZIP / laptop:  ./tbhm.py --ai-migrate            (migrate schema + resync source)
  health:            ./tbhm.py --ai-doctor
  teach it:          ./tbhm.py --ai-ingest-resource FILE
                     ./tbhm.py --ai-ingest-note FILE
  portability:       ./tbhm.py --ai-backup   /  --ai-restore ARCHIVE
  governance:        ./tbhm.py --ai-proposals / --ai-approve UID / --ai-reject UID
                     ./tbhm.py --ai-verify-audit
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

_AI_FLAGS = (
    'ai_learning',
    "ai_init", "ai_doctor", "ai_status", "ai_index_tool", "ai_sync_tool",
    "ai_baseline", "ai_migrate", "ai_regression_check", "ai_backup", "ai_restore",
    "ai_ingest_resource", "ai_ingest_note", "ai_ingest_folder", "ai_proposals",
    "ai_approve", "ai_reject", "ai_verify_audit", "ai_review_delta",
    "ai_mistakes", "ai_lesson_approve",
    "ai_propose_delta",
)


def requested(args) -> bool:
    return any(getattr(args, f, None) for f in _AI_FLAGS)


def handle(args, root: Path) -> int:
    root = Path(root)
    if getattr(args, 'ai_learning', None):
        from core.ai_plane.learning_cli import handle as learning_handle
        return learning_handle(args)
    if getattr(args, "ai_init", False):
        from core.ai_plane import bootstrap
        out = bootstrap.run_init(args, root)
        print(json.dumps(out, indent=2, default=str))
        return 0

    if getattr(args, "ai_restore", None):
        return _restore(args, root)

    # everything below needs the plane assembled
    from core.ai_plane import build_plane
    plane = build_plane(args, create=True, need_runtime=True)
    try:
        if getattr(args, "ai_doctor", False) or getattr(args, "ai_status", False):
            return _doctor(plane, root)
        if getattr(args, "ai_index_tool", False) or getattr(args, "ai_sync_tool", False):
            return _sync(plane, root, full=getattr(args, "ai_index_tool", False))
        if getattr(args, "ai_baseline", False):
            return _baseline(plane, root)
        if getattr(args, "ai_migrate", False):
            return _migrate(plane, root)
        if getattr(args, "ai_regression_check", False):
            return _regression(plane, root)
        if getattr(args, "ai_backup", False):
            return _backup(plane)
        if getattr(args, "ai_ingest_resource", None):
            return _ingest(plane, root, Path(args.ai_ingest_resource), source_type="imported_resource")
        if getattr(args, "ai_ingest_note", None):
            return _ingest(plane, root, Path(args.ai_ingest_note), source_type="operator_note")
        if getattr(args, "ai_ingest_folder", None):
            return _ingest_folder(plane, root, Path(args.ai_ingest_folder))
        if getattr(args, "ai_proposals", False):
            return _list_proposals(plane)
        if getattr(args, "ai_mistakes", False):
            rows = plane.store.known_mistakes(limit=500)
            print(json.dumps({"known_mistakes": rows, "count": len(rows)}, indent=2))
            return 0
        if getattr(args, "ai_lesson_approve", None):
            try:
                cand_id = int(args.ai_lesson_approve)
                row = plane.store.one("SELECT candidate FROM lesson_candidates WHERE id=?", (cand_id,))
                if not row:
                    print(json.dumps({"ok": False, "detail": f"no lesson candidate {cand_id}"})); return 1
                lid = plane.store.add_approved_lesson(lesson=row["candidate"], source_candidate=cand_id)
                plane.store.conn.execute("UPDATE lesson_candidates SET status='approved' WHERE id=?", (cand_id,))
                plane.store.conn.commit()
                plane.audit.record("lesson.approve", str(cand_id), {"approved_lesson_id": lid})
                print(json.dumps({"ok": True, "approved_lesson_id": lid}, indent=2)); return 0
            except Exception as exc:
                print(json.dumps({"ok": False, "detail": str(exc)})); return 2
        if getattr(args, "ai_approve", None):
            print(json.dumps(plane.gate.decide(args.ai_approve, True), indent=2)); return 0
        if getattr(args, "ai_reject", None):
            print(json.dumps(plane.gate.decide(args.ai_reject, False), indent=2)); return 0
        if getattr(args, "ai_verify_audit", False):
            ok, detail = plane.audit.verify_chain()
            print(json.dumps({"audit_intact": ok, "detail": detail}, indent=2))
            return 0 if ok else 2
        if getattr(args, "ai_review_delta", False):
            return _review_delta(plane, root)
        if getattr(args, "ai_propose_delta", False):
            return _propose_delta(plane, root)
        print("no AI command matched"); return 1
    finally:
        plane.close()


# --- command bodies ----------------------------------------------------------

def _doctor(plane, root: Path) -> int:
    from core.ai_plane import indexer
    from core.hardware_profile import detect as detect_hw
    delta = indexer.compute_delta(root, plane.store)
    vindex_ok = plane.vector_index.load()
    model_ready, model_detail = (plane.runtime.client.available()
                                 if plane.runtime else (False, "no runtime"))
    ok_audit, audit_detail = plane.audit.verify_chain()
    report = {
        "home": str(plane.home.root),
        "db": str(plane.home.db_path),
        "db_counts": plane.store.counts(),
        "vector_index_loaded": vindex_ok,
        "vector_index_manifest": plane.vector_index.meta,
        "vector_index_coverage": plane.vector_index.coverage(plane.store),
        "source_delta_vs_index": {
            "added": len(delta["added"]), "modified": len(delta["modified"]),
            "deleted": len(delta["deleted"]),
            "stale": bool(delta["added"] or delta["modified"] or delta["deleted"]),
        },
        "advisor_model_ready": model_ready,
        "advisor_model_detail": model_detail,
        "embedding_mode": plane.vector_index.meta.get("embedding_mode", "unknown"),
        "audit_chain": {"intact": ok_audit, "detail": audit_detail},
        "hardware": detect_hw(),
        "pending_proposals": len(plane.gate.list_pending()),
    }
    from core.ai_plane.public_knowledge import Catalog, default_path
    public_path = default_path(home=plane.home.root)
    report['public_knowledge'] = {'present': public_path.is_file(), 'path': str(public_path),
                                  'proof_authority': False}
    if public_path.is_file():
        try:
            catalog = Catalog(public_path)
            try:
                report['public_knowledge'].update(catalog.status())
            finally:
                catalog.close()
        except Exception as exc:
            report['public_knowledge']['error'] = str(exc)[:300]
    print(json.dumps(report, indent=2, default=str))
    if report["source_delta_vs_index"]["stale"]:
        print("\nHINT: source has changed since last index. Run: ./tbhm.py --ai-sync-tool")
    return 0


def _sync(plane, root: Path, full: bool) -> int:
    from core.ai_plane import indexer
    summary = indexer.reindex(root, plane.store, plane.embedder, plane.vector_index,
                              full=full, log=lambda *a: print("[ai]", *a[1:]))
    plane.audit.record("ai.sync", None,
                       {"reindexed": summary["files_reindexed"], "full": full})
    print(json.dumps(summary, indent=2, default=str))
    return 0


def _review_delta(plane, root: Path) -> int:
    """Delta index + ask the advisor to review the change (advisory, optional)."""
    from core.ai_plane import indexer
    summary = indexer.reindex(root, plane.store, plane.embedder, plane.vector_index,
                              full=False, log=lambda *a: None)
    review = {"note": "advisor unavailable"}
    if plane.runtime and plane.runtime.client.available()[0]:
        try:
            review = plane.advisor.review_tool_delta(summary)
        except Exception as e:
            review = {"note": f"advisor review failed: {e}"}
    print(json.dumps({"delta": summary, "review": review}, indent=2, default=str))
    return 0


def _propose_delta(plane, root: Path) -> int:
    """Create a pending, non-applying proposal from the real redacted delta."""
    from core.ai_plane import indexer
    summary = indexer.reindex(
        root, plane.store, plane.embedder, plane.vector_index,
        full=False, log=lambda *a: None,
    )
    affected = [d.get("file") for d in summary.get("source_diffs", []) if d.get("file")]
    if not affected:
        print(json.dumps({"ok": False, "detail": "no source delta to propose"}, indent=2))
        return 1
    review = {"summary": "Advisor unavailable", "issues": [],
              "missing_capabilities": [], "questions_for_operator": []}
    if plane.runtime and plane.runtime.client.available()[0]:
        try:
            review = plane.advisor.review_tool_delta(summary)
        except Exception as exc:
            review["summary"] = f"Advisor review failed: {exc}"
    patch = "\n\n".join(
        d.get("diff", "") for d in summary.get("source_diffs", []) if d.get("diff")
    )
    risks = [
        f"{item.get('severity', 'review')}: {item.get('problem', '')}"
        for item in review.get("issues", []) if isinstance(item, dict)
    ]
    record = plane.gate.create(
        problem=review.get("summary") or "Review the current TBHM source delta",
        evidence=[{"delta": {k: summary.get(k) for k in ("added", "modified", "deleted")},
                   "advisor_review": review}],
        affected_files=affected,
        patch_text=patch,
        expected_benefit="Operator-reviewed integration of the indexed source delta.",
        risks=risks or ["Proposal is advisory and must be reviewed/tested before any manual application."],
    )
    print(json.dumps({"ok": True, "proposal": record, "review": review}, indent=2, default=str))
    return 0


def _baseline(plane, root: Path) -> int:
    from core.ai_plane import indexer
    delta = indexer.compute_delta(root, plane.store)
    baseline = {
        "created_at": time.time(),
        "tbhm_files_tracked": len(delta["seen"]),
        "db_counts": plane.store.counts(),
        "index_rows": plane.vector_index.meta.get("rows", 0),
    }
    (plane.home.root / "backups" / "baseline.json").write_text(
        json.dumps(baseline, indent=2), encoding="utf-8")
    plane.audit.record("ai.baseline", None, baseline)
    print(json.dumps(baseline, indent=2, default=str))
    return 0


def _migrate(plane, root: Path) -> int:
    """After replacing the ZIP or moving laptop: schema is already migrated by
    Store(); here we resync the source delta so the index matches the new tree."""
    print("[ai-migrate] schema migrated on open; resyncing source delta...")
    rc = _sync(plane, root, full=False)
    plane.audit.record("ai.migrate", None, {"root": str(root)})
    return rc


def _regression(plane, root: Path) -> int:
    from core.ai_plane import indexer
    delta = indexer.compute_delta(root, plane.store)
    checks = {
        "home_present": plane.home.exists(),
        "db_readable": plane.store.counts().get("document_chunks", 0) >= 0,
        "index_loads": plane.vector_index.load(),
        "vector_cache_complete": plane.vector_index.coverage(plane.store)["complete"],
        "source_in_sync": not (delta["added"] or delta["modified"] or delta["deleted"]),
        "audit_intact": plane.audit.verify_chain()[0],
    }
    ok = all(checks.values())
    print(json.dumps({"regression_ok": ok, "checks": checks}, indent=2))
    if not checks["source_in_sync"]:
        print("HINT: run ./tbhm.py --ai-sync-tool to realign the index with the tool.")
    return 0 if ok else 2


def _backup(plane) -> int:
    """Create a safe portable backup of durable, sanitized AI state.

    Proposal JSON/patches are included. Rebuildable vectors and model weights are
    excluded. Legacy raw resource files are never copied into the archive.
    """
    home = plane.home
    home.backups_dir.mkdir(parents=True, exist_ok=True)
    snap = home.backups_dir / "memory-backup.sqlite3"
    if snap.exists():
        snap.unlink()
    plane.store.conn.execute("VACUUM INTO ?", (str(snap),))
    plane.store.conn.commit()

    # Keep the separate disk-backed reference catalog portable too. SQLite's
    # backup API captures a consistent snapshot without copying a live DB/WAL.
    from core.ai_plane.public_knowledge import default_path
    import sqlite3
    catalog_path = default_path(home=home.root)
    catalog_snap = home.backups_dir / 'public-catalog-backup.sqlite3'
    if catalog_snap.exists():
        catalog_snap.unlink()
    if catalog_path.is_file() and not catalog_path.is_symlink():
        with sqlite3.connect(catalog_path.as_uri()+'?mode=ro', uri=True) as source:
            with sqlite3.connect(catalog_snap) as target:
                source.backup(target)
        catalog_snap.chmod(0o600)

    ts = time.strftime("%Y%m%d-%H%M%S")
    archive = home.root / f"tbhm-ai-backup-{ts}.tar.gz"
    included: list[str] = []

    def add_path(tf: tarfile.TarFile, path: Path, arcname: str) -> None:
        if not path.exists():
            return
        tf.add(path, arcname=arcname, recursive=True)
        included.append(arcname)

    with tarfile.open(archive, "w:gz") as tf:
        for rel in ("config", "models/model-lock.json", "audit", "proposals",
                    "knowledge/approved-lessons", "indexes/vector-manifest.json",
                    "backups/memory-backup.sqlite3", "backups/public-catalog-backup.sqlite3"):
            add_path(tf, home.root / rel, rel)
        # Only new sanitized imports and their provenance metadata are portable.
        if home.resources_dir.exists():
            for resource in sorted(home.resources_dir.iterdir()):
                if resource.is_file() and (resource.name.endswith(".sanitized.txt") or
                                           resource.name.endswith(".meta.json")):
                    rel = f"knowledge/imported-resources/{resource.name}"
                    add_path(tf, resource, rel)

    plane.audit.record("ai.backup", None, {"archive": str(archive), "includes": included})
    print(json.dumps({
        "archive": str(archive), "compression": "gzip", "includes": included,
        "excludes": [
            "model weights (re-pull via model-lock.json)",
            "rebuildable vector matrix",
            "legacy/raw imported resources",
        ],
        "restore": f"./tbhm.py --ai-restore {archive}",
    }, indent=2))
    return 0


def _restore(args, root: Path) -> int:
    from core.ai_plane import home as home_mod
    archive = Path(args.ai_restore).expanduser().resolve()
    if not archive.is_file():
        print(json.dumps({"ok": False, "detail": f"archive not found: {archive}"}))
        return 2
    home = home_mod.get(getattr(args, "ai_home", None), create=True)

    try:
        with tarfile.open(archive, "r:*") as tf:
            base = home.root.resolve()
            for member in tf.getmembers():
                target = (base / member.name).resolve()
                if target != base and base not in target.parents:
                    raise ValueError(f"unsafe archive path: {member.name}")
                if member.issym() or member.islnk():
                    raise ValueError(f"links are not allowed in AI backups: {member.name}")
                if not (member.isfile() or member.isdir()):
                    raise ValueError(
                        f"special archive members are not allowed in AI backups: {member.name}"
                    )
            tf.extractall(base)
    except Exception as exc:
        print(json.dumps({"ok": False, "detail": f"safe extract failed: {exc}"}))
        return 2

    snap = home.backups_dir / "memory-backup.sqlite3"
    if snap.exists():
        home.db_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(snap, home.db_path)

    catalog_snap = home.backups_dir / 'public-catalog-backup.sqlite3'
    if catalog_snap.is_file():
        from core.ai_plane.public_knowledge import default_path
        catalog_path = default_path(home=home.root)
        catalog_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(catalog_snap, catalog_path)

    from core.ai_plane import build_plane
    plane = build_plane(args, create=True, need_runtime=True)
    try:
        info = plane.vector_index.rebuild(plane.store, plane.embedder)
        plane.audit.record("ai.restore", None, {"archive": str(archive), "rows": info["rows"]})
        from core.ai_plane import indexer
        delta = indexer.compute_delta(root, plane.store)
        stale = bool(delta["added"] or delta["modified"] or delta["deleted"])
        print(json.dumps({
            "ok": True, "home": str(home.root), "db": str(home.db_path),
            "index_rebuilt_rows": info["rows"], "embedding_mode": info["embedding_mode"],
            "tool_source_stale_vs_restored_index": stale,
            "next": "run ./tbhm.py --ai-sync-tool" if stale else "ready",
        }, indent=2))
        return 0
    finally:
        plane.close()


def _ingest(plane, root: Path, path: Path, source_type: str) -> int:
    """Extract and redact before any persistent write. No raw quarantine copy."""
    from core.ai_plane import indexer
    from core.ai_plane.sanitizer import scrub
    if not path.is_file():
        print(json.dumps({"ok": False, "detail": f"not a file: {path}"}))
        return 2

    raw = path.read_bytes()
    raw_sha = hashlib.sha256(raw).hexdigest()
    extracted = _extract_text(path)
    if not extracted.strip():
        print(json.dumps({"ok": False, "detail": "no extractable text (binary or empty)"}))
        return 2
    redacted = scrub(extracted, limit=200_000)
    sanitized_sha = hashlib.sha256(redacted.encode("utf-8")).hexdigest()

    safe_name = Path(path.name).name.replace("/", "_")
    dest = plane.home.resources_dir / f"{raw_sha[:12]}-{safe_name}.sanitized.txt"
    meta_path = plane.home.resources_dir / f"{raw_sha[:12]}-{safe_name}.meta.json"
    dest.write_text(redacted, encoding="utf-8")
    meta_path.write_text(json.dumps({
        "original_name": safe_name,
        "origin": str(path),
        "raw_sha256": raw_sha,
        "sanitized_sha256": sanitized_sha,
        "source_type": source_type,
        "stored_raw": False,
        "ingested_at": time.time(),
    }, indent=2), encoding="utf-8")
    # Remove a legacy raw copy with the old naming convention, if present.
    legacy = plane.home.resources_dir / f"{raw_sha[:12]}-{safe_name}"
    if legacy.exists() and legacy != dest:
        try:
            legacy.unlink()
        except Exception:
            pass

    doc_id = plane.store.upsert_document(
        sha256=sanitized_sha + ":resource", source_type=source_type,
        source_path=str(dest), trust_level="T2", title=safe_name,
        sensitivity="redacted", meta={"origin": str(path), "raw_sha256": raw_sha,
                                        "stored_raw": False},
    )
    chunk_delta = plane.store.replace_chunks_delta(
        doc_id, indexer._chunk_text(redacted, safe_name, kind="text"))
    info = plane.vector_index.update(
        plane.store, plane.embedder, changed_ids=chunk_delta["added"],
        removed_ids=chunk_delta["removed"],
    )
    plane.audit.record("ai.ingest", safe_name, {
        "type": source_type, "chunks": len(chunk_delta["kept"] + chunk_delta["added"]),
        "raw_stored": False,
    })

    advisory = {"note": "stored as sanitized knowledge; advisor mapping skipped"}
    try:
        hits = plane.vector_index.search(plane.store, plane.embedder, redacted[:1500], k=5)
        related = sorted({h.get("source_path") for h in hits if h.get("trust_level") == "T1"})
        advisory = {
            "related_tbhm_components": [r for r in related if r][:8],
            "note": "Knowledge added. Any source change must go through review/proposal governance.",
        }
    except Exception as exc:
        advisory = {"note": f"advisor mapping failed: {exc}"}

    print(json.dumps({
        "ok": True, "source_type": source_type, "sanitized_copy": str(dest),
        "metadata": str(meta_path), "raw_stored": False,
        "chunks_added": len(chunk_delta["added"]), "chunks_reused": len(chunk_delta["kept"]),
        "raw_sha256": raw_sha, "sanitized_sha256": sanitized_sha,
        "vector_index": info, "advisory": advisory,
    }, indent=2, default=str))
    return 0


def _ingest_folder(plane, root: Path, folder: Path) -> int:
    if not folder.is_dir():
        print(json.dumps({"ok": False, "detail": f"not a folder: {folder}"})); return 2
    results = []
    for p in sorted(folder.rglob("*")):
        if p.is_file() and p.suffix.lower() in (".md", ".txt", ".json", ".yaml", ".yml", ".pdf"):
            rc = _ingest(plane, root, p, source_type="imported_resource")
            results.append({"file": str(p), "rc": rc})
    print(json.dumps({"ingested": len(results)}, indent=2))
    return 0


def _list_proposals(plane) -> int:
    pending = plane.gate.list_pending()
    print(json.dumps({"pending": [
        {"id": p["proposal_id"], "problem": p["problem"][:200],
         "affected_files": p["affected_files"], "risks": p.get("risks", [])}
        for p in pending]}, indent=2, default=str))
    if pending:
        print("\napprove: ./tbhm.py --ai-approve <ID>   reject: ./tbhm.py --ai-reject <ID>")
    return 0


# --- helpers -----------------------------------------------------------------

def _extract_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        for cmd in (["pdftotext", str(path), "-"],):
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
                if p.returncode == 0 and p.stdout.strip():
                    return p.stdout
            except Exception:
                pass
        return ""
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""
