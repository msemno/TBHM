"""SQLite store: the single source of truth for the AI plane.

Design rule (from the architecture doc): SQLite is authoritative; the vector
index is a rebuildable cache. If the index is lost or becomes incompatible after
an upgrade, it is regenerated from `document_chunks` here. Large raw payloads are
NOT stored inline — only a sha256 + metadata; the compressed object lives under
knowledge/objects/<sha256>.zst. That keeps the DB small and portable.

VACUUM INTO is used for consistent snapshots (see cli.backup).
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 6

_DDL = [
    # ---- migrations bookkeeping --------------------------------------------
    """CREATE TABLE IF NOT EXISTS schema_migrations(
         version INTEGER PRIMARY KEY,
         applied_at REAL NOT NULL,
         note TEXT
       )""",
    # ---- model + source provenance -----------------------------------------
    """CREATE TABLE IF NOT EXISTS model_registry(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         role TEXT NOT NULL,               -- advisor | embedding | summarizer | reviewer
         name TEXT NOT NULL,
         digest TEXT,
         params_json TEXT,
         recorded_at REAL NOT NULL
       )""",
    """CREATE TABLE IF NOT EXISTS source_manifests(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         tbhm_version TEXT,
         git_commit TEXT,
         file_path TEXT NOT NULL,
         sha256 TEXT NOT NULL,
         size INTEGER,
         mtime REAL,
         tombstoned INTEGER NOT NULL DEFAULT 0,
         created_at REAL NOT NULL
       )""",
    "CREATE INDEX IF NOT EXISTS ix_manifest_path ON source_manifests(file_path)",
    """CREATE TABLE IF NOT EXISTS source_snapshots(
         file_path TEXT PRIMARY KEY,
         sha256 TEXT NOT NULL,
         text TEXT NOT NULL,
         updated_at REAL NOT NULL
       )""",
    # ---- knowledge (chunks are what get embedded) --------------------------
    """CREATE TABLE IF NOT EXISTS documents(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         sha256 TEXT UNIQUE NOT NULL,
         source_type TEXT NOT NULL,        -- source_code | doc | changelog | profile |
                                           -- imported_resource | operator_note | lesson
         source_path TEXT,
         trust_level TEXT NOT NULL,        -- T0..T4
         sensitivity TEXT,
         title TEXT,
         meta_json TEXT,
         created_at REAL NOT NULL
       )""",
    """CREATE TABLE IF NOT EXISTS document_chunks(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         document_id INTEGER NOT NULL,
         ordinal INTEGER NOT NULL,
         symbol TEXT,                      -- module/class/function name when known
         kind TEXT,                        -- module|class|function|method|yaml|md|text
         text TEXT NOT NULL,
         token_estimate INTEGER,
         sha256 TEXT NOT NULL,
         created_at REAL NOT NULL,
         FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE
       )""",
    "CREATE INDEX IF NOT EXISTS ix_chunk_doc ON document_chunks(document_id)",
    "CREATE INDEX IF NOT EXISTS ix_chunk_sha ON document_chunks(sha256)",
    """CREATE TABLE IF NOT EXISTS code_relationships(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         src TEXT NOT NULL,                -- e.g. phase name / symbol
         rel TEXT NOT NULL,                -- imports | consumes_cli | produces_artifact |
                                           -- next_phase | calls | verified_by
         dst TEXT NOT NULL,
         meta_json TEXT,
         created_at REAL NOT NULL
       )""",
    # ---- operational memory -------------------------------------------------
    """CREATE TABLE IF NOT EXISTS runs(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         run_uid TEXT UNIQUE NOT NULL,
         tbhm_version TEXT,
         profile TEXT,
         intensity TEXT,
         target_count INTEGER,
         started_at REAL NOT NULL,
         ended_at REAL,
         status TEXT                        -- running | completed | interrupted | error
       )""",
    """CREATE TABLE IF NOT EXISTS phase_events(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         run_id INTEGER NOT NULL,
         phase TEXT NOT NULL,
         event TEXT NOT NULL,               -- start | success | failed | zero_output | pressure
         detail TEXT,
         duration_s REAL,
         created_at REAL NOT NULL,
         FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
       )""",
    "CREATE INDEX IF NOT EXISTS ix_event_run ON phase_events(run_id)",
    """CREATE TABLE IF NOT EXISTS tool_executions(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         run_id INTEGER,
         tool TEXT,
         command_fingerprint TEXT,
         return_code INTEGER,
         duration_s REAL,
         stdout_summary TEXT,
         stderr_summary TEXT,
         phase TEXT,
         created_at REAL NOT NULL
       )""",
    """CREATE TABLE IF NOT EXISTS findings(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         run_id INTEGER,
         finding_uid TEXT,
         classification TEXT,
         confirmation_status TEXT,
         severity TEXT,
         phase TEXT,
         title TEXT,
         where_ref TEXT,
         confidence TEXT,
         meta_json TEXT,
         created_at REAL NOT NULL
       )""",
    # ---- experience-validation loop ----------------------------------------
    """CREATE TABLE IF NOT EXISTS operator_feedback(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         run_id INTEGER,
         subject TEXT,                      -- proposal id | lesson id | finding uid
         decision TEXT,                     -- accepted | rejected | deferred
         note TEXT,
         created_at REAL NOT NULL
       )""",
    """CREATE TABLE IF NOT EXISTS lesson_candidates(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         candidate TEXT NOT NULL,
         based_on_runs TEXT,
         evidence_count INTEGER,
         confidence REAL,
         status TEXT NOT NULL DEFAULT 'candidate',  -- candidate|approved|rejected|deprecated|superseded
         superseded_by INTEGER,
         created_at REAL NOT NULL
       )""",
    """CREATE TABLE IF NOT EXISTS approved_lessons(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         lesson TEXT NOT NULL,
         source_candidate INTEGER,
         approved_at REAL NOT NULL
       )""",
    # ---- propose-and-approve ------------------------------------------------
    """CREATE TABLE IF NOT EXISTS change_proposals(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         proposal_uid TEXT UNIQUE NOT NULL,
         problem TEXT,
         evidence_json TEXT,
         affected_files TEXT,
         patch_path TEXT,
         expected_benefit TEXT,
         risks TEXT,
         status TEXT NOT NULL DEFAULT 'pending',  -- pending|accepted|rejected
         created_at REAL NOT NULL,
         decided_at REAL
       )""",
    """CREATE TABLE IF NOT EXISTS proposal_validations(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         proposal_id INTEGER NOT NULL,
         kind TEXT,                         -- unit|integration|safety|performance
         status TEXT,
         detail TEXT,
         created_at REAL NOT NULL,
         FOREIGN KEY(proposal_id) REFERENCES change_proposals(id) ON DELETE CASCADE
       )""",
    # ---- mistakes / false-positive ledger (advisory; never auto-suppresses) -
    """CREATE TABLE IF NOT EXISTS mistake_ledger(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         kind TEXT NOT NULL,                -- false_positive | phase_error | zero_output | bad_direction
         pattern TEXT NOT NULL,             -- normalized signature e.g. phase:cwe or phase name
         detail TEXT,
         first_run_uid TEXT,
         last_run_uid TEXT,
         times_seen INTEGER NOT NULL DEFAULT 1,
         status TEXT NOT NULL DEFAULT 'open',   -- open | acknowledged | resolved
         created_at REAL NOT NULL,
         updated_at REAL
       )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_mistake_kind_pattern ON mistake_ledger(kind, pattern)",
    # ---- audit --------------------------------------------------------------
    """CREATE TABLE IF NOT EXISTS audit_log(
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         action TEXT NOT NULL,
         subject TEXT,
         detail_json TEXT,
         prev_hash TEXT,
         this_hash TEXT,
         created_at REAL NOT NULL
       )""",
]


class Store:
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ValueError('AI memory database cannot be a symlink')
        self.conn = sqlite3.connect(str(self.path))
        # Set before enabling WAL so SQLite derives private sidecar modes.
        self.path.chmod(0o600)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._created_at_cache: dict[str, bool] = {}
        self.migrate()

    def _table_has_created_at(self, table: str) -> bool:
        if table not in self._created_at_cache:
            cols = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})").fetchall()}
            self._created_at_cache[table] = "created_at" in cols
        return self._created_at_cache[table]

    # -- schema ---------------------------------------------------------------
    def migrate(self) -> int:
        cur = self.conn.cursor()
        for stmt in _DDL:
            cur.execute(stmt)
        # Version 6 adds reviewed learning tables only. Legacy tables, columns,
        # row IDs and readers remain valid; weights/training are not required.
        from core.ai_plane.scenarios import DDL as learning_ddl
        for stmt in learning_ddl:
            cur.execute(stmt)
        row = cur.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        current = row["v"] if row and row["v"] is not None else 0
        if current < SCHEMA_VERSION:
            cur.execute(
                "INSERT OR REPLACE INTO schema_migrations(version, applied_at, note) VALUES(?,?,?)",
                (SCHEMA_VERSION, time.time(), f"additive schema v{SCHEMA_VERSION}"),
            )
        self.conn.commit()
        return SCHEMA_VERSION

    def close(self) -> None:
        try:
            self.conn.commit()
            self.conn.close()
        except Exception:
            pass

    # -- generic helpers ------------------------------------------------------
    def _insert(self, table: str, **cols) -> int:
        # Tables like model_registry/runs/approved_lessons use their own
        # timestamp column (recorded_at/started_at/approved_at) and have no
        # created_at; only inject it where the column actually exists.
        if "created_at" not in cols and self._table_has_created_at(table):
            cols["created_at"] = time.time()
        keys = ",".join(cols)
        ph = ",".join("?" for _ in cols)
        cur = self.conn.execute(
            f"INSERT INTO {table}({keys}) VALUES({ph})", tuple(cols.values())
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, tuple(params)).fetchall())

    def one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, tuple(params)).fetchone()

    # -- documents / chunks ---------------------------------------------------
    def upsert_document(self, *, sha256: str, source_type: str, source_path: str | None,
                        trust_level: str, title: str | None = None,
                        sensitivity: str | None = None, meta: dict | None = None) -> int:
        existing = self.one("SELECT id FROM documents WHERE sha256=?", (sha256,))
        if existing:
            return int(existing["id"])
        return self._insert(
            "documents", sha256=sha256, source_type=source_type,
            source_path=source_path, trust_level=trust_level, sensitivity=sensitivity,
            title=title, meta_json=json.dumps(meta or {}),
        )

    def upsert_source_document(self, *, sha256: str, source_type: str, source_path: str,
                               trust_level: str, title: str | None = None,
                               sensitivity: str | None = None, meta: dict | None = None) -> int:
        """Keep exactly one current document row for a tool source path.

        Older releases keyed documents by content hash, so modifying one file
        created a second row and left stale chunks retrievable beside the new
        code.  Source paths are identities; content hashes are versions.
        """
        rows = self.query(
            "SELECT id FROM documents WHERE source_path=? AND source_type=? ORDER BY id",
            (source_path, source_type),
        )
        if rows:
            keep = int(rows[0]["id"])
            for row in rows[1:]:
                self.conn.execute("DELETE FROM documents WHERE id=?", (int(row["id"]),))
            self.conn.execute(
                "UPDATE documents SET sha256=?, trust_level=?, sensitivity=?, title=?, "
                "meta_json=? WHERE id=?",
                (sha256, trust_level, sensitivity, title, json.dumps(meta or {}), keep),
            )
            self.conn.commit()
            return keep
        return self._insert(
            "documents", sha256=sha256, source_type=source_type,
            source_path=source_path, trust_level=trust_level, sensitivity=sensitivity,
            title=title, meta_json=json.dumps(meta or {}),
        )

    def replace_chunks_delta(self, document_id: int, chunks: list[dict]) -> dict[str, list[int]]:
        """Replace a document's chunks while preserving IDs for unchanged chunks.

        Stable chunk IDs let the vector cache update only genuinely changed
        symbols instead of re-embedding the entire tool after a one-line edit.
        """
        existing = self.query(
            "SELECT id, sha256, symbol, kind FROM document_chunks "
            "WHERE document_id=? ORDER BY ordinal, id", (document_id,),
        )
        by_key: dict[tuple, list[int]] = {}
        for row in existing:
            key = (row["sha256"], row["symbol"] or "", row["kind"] or "")
            by_key.setdefault(key, []).append(int(row["id"]))

        kept: list[int] = []
        added: list[int] = []
        for ordinal, ch in enumerate(chunks):
            key = (ch["sha256"], ch.get("symbol") or "", ch.get("kind") or "")
            candidates = by_key.get(key) or []
            if candidates:
                cid = candidates.pop(0)
                self.conn.execute(
                    "UPDATE document_chunks SET ordinal=?, text=?, token_estimate=? WHERE id=?",
                    (ordinal, ch["text"], ch.get("token_estimate"), cid),
                )
                kept.append(cid)
            else:
                cur = self.conn.execute(
                    "INSERT INTO document_chunks(document_id,ordinal,symbol,kind,text,"
                    "token_estimate,sha256,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (document_id, ordinal, ch.get("symbol"), ch.get("kind"), ch["text"],
                     ch.get("token_estimate"), ch["sha256"], time.time()),
                )
                added.append(int(cur.lastrowid))

        removed = [cid for ids in by_key.values() for cid in ids]
        if removed:
            marks = ",".join("?" for _ in removed)
            self.conn.execute(f"DELETE FROM document_chunks WHERE id IN ({marks})", removed)
        self.conn.commit()
        return {"kept": kept, "added": added, "removed": removed}

    def replace_chunks(self, document_id: int, chunks: list[dict]) -> list[int]:
        delta = self.replace_chunks_delta(document_id, chunks)
        return delta["kept"] + delta["added"]

    def all_chunks(self) -> list[sqlite3.Row]:
        return self.query(
            "SELECT c.id, c.text, c.symbol, c.kind, d.source_path, d.source_type, d.trust_level "
            "FROM document_chunks c JOIN documents d ON d.id=c.document_id"
        )

    def tombstone_source(self, file_path: str) -> None:
        self.conn.execute(
            "UPDATE source_manifests SET tombstoned=1 WHERE file_path=?", (file_path,))
        rows = self.query("SELECT id FROM documents WHERE source_path=?", (file_path,))
        for row in rows:
            self.conn.execute("DELETE FROM documents WHERE id=?", (row["id"],))
        self.conn.execute("DELETE FROM source_snapshots WHERE file_path=?", (file_path,))
        self.conn.commit()

    # -- source snapshots (redacted; used for bounded real diffs) -------------
    def source_snapshot(self, file_path: str) -> dict | None:
        row = self.one(
            "SELECT file_path, sha256, text, updated_at FROM source_snapshots WHERE file_path=?",
            (file_path,),
        )
        return dict(row) if row else None

    def set_source_snapshot(self, *, file_path: str, sha256: str, text: str) -> None:
        self.conn.execute(
            "INSERT INTO source_snapshots(file_path,sha256,text,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(file_path) DO UPDATE SET sha256=excluded.sha256, "
            "text=excluded.text, updated_at=excluded.updated_at",
            (file_path, sha256, text, time.time()),
        )
        self.conn.commit()

    # -- manifests ------------------------------------------------------------
    def manifest_map(self) -> dict[str, str]:
        rows = self.query(
            "SELECT file_path, sha256 FROM source_manifests WHERE tombstoned=0")
        return {r["file_path"]: r["sha256"] for r in rows}

    def record_manifest(self, *, tbhm_version, git_commit, file_path, sha256, size, mtime):
        self.conn.execute("DELETE FROM source_manifests WHERE file_path=?", (file_path,))
        return self._insert(
            "source_manifests", tbhm_version=tbhm_version, git_commit=git_commit,
            file_path=file_path, sha256=sha256, size=size, mtime=mtime, tombstoned=0)

    # -- runs / events --------------------------------------------------------
    def start_run(self, *, run_uid, tbhm_version, profile, intensity, target_count) -> int:
        return self._insert(
            "runs", run_uid=run_uid, tbhm_version=tbhm_version, profile=profile,
            intensity=intensity, target_count=target_count, started_at=time.time(),
            status="running")

    def end_run(self, run_id: int, status: str) -> None:
        self.conn.execute(
            "UPDATE runs SET ended_at=?, status=? WHERE id=?", (time.time(), status, run_id))
        self.conn.commit()

    def add_event(self, *, run_id, phase, event, detail=None, duration_s=None) -> int:
        return self._insert(
            "phase_events", run_id=run_id, phase=phase, event=event,
            detail=(detail or "")[:4000], duration_s=duration_s)

    def add_tool_execution(self, **cols) -> int:
        return self._insert("tool_executions", **cols)

    def mirror_finding(self, **cols) -> int:
        return self._insert("findings", **cols)

    # -- lessons / feedback / proposals --------------------------------------
    def add_lesson_candidate(self, *, candidate, based_on_runs, evidence_count, confidence) -> int:
        return self._insert(
            "lesson_candidates", candidate=candidate,
            based_on_runs=json.dumps(based_on_runs), evidence_count=evidence_count,
            confidence=confidence, status="candidate")

    def add_feedback(self, *, run_id, subject, decision, note=None) -> int:
        return self._insert(
            "operator_feedback", run_id=run_id, subject=subject, decision=decision, note=note)

    def add_proposal(self, **cols) -> int:
        return self._insert("change_proposals", **cols)

    def set_proposal_status(self, proposal_uid: str, status: str) -> None:
        self.conn.execute(
            "UPDATE change_proposals SET status=?, decided_at=? WHERE proposal_uid=?",
            (status, time.time(), proposal_uid))
        self.conn.commit()

    def record_model(self, *, role, name, digest=None, params=None) -> int:
        return self._insert(
            "model_registry", role=role, name=name, digest=digest,
            params_json=json.dumps(params or {}), recorded_at=time.time())

    # -- audit (hash-chained) -------------------------------------------------
    def audit(self, action: str, subject: str | None, detail: dict | None,
              prev_hash: str, this_hash: str, created_at: float | None = None) -> int:
        # created_at MUST equal the timestamp hashed by the caller, or chain
        # verification (which recomputes from created_at) will fail.
        return self._insert(
            "audit_log", action=action, subject=subject,
            detail_json=json.dumps(detail or {}), prev_hash=prev_hash,
            this_hash=this_hash, created_at=created_at if created_at is not None else time.time())

    def last_audit_hash(self) -> str:
        row = self.one("SELECT this_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        return row["this_hash"] if row else ""

    def counts(self) -> dict[str, int]:
        out = {}
        for t in ("documents", "document_chunks", "runs", "phase_events",
                  "findings", "lesson_candidates", "approved_lessons", "change_proposals"):
            r = self.one(f"SELECT COUNT(*) AS n FROM {t}")
            out[t] = int(r["n"]) if r else 0
        return out

    # -- mistakes / false-positive ledger (advisory) --------------------------
    def record_mistake(self, *, kind: str, pattern: str, detail: str = "",
                       run_uid: str = "") -> int:
        """Insert or bump a mistake pattern. Advisory memory only; it never
        silently suppresses a finding — turning a pattern into an active
        suppression is a separate, operator-approved lesson."""
        now = time.time()
        existing = self.one(
            "SELECT id, times_seen FROM mistake_ledger WHERE kind=? AND pattern=?",
            (kind, pattern))
        if existing:
            self.conn.execute(
                "UPDATE mistake_ledger SET times_seen=times_seen+1, last_run_uid=?, "
                "detail=COALESCE(NULLIF(?, ''), detail), updated_at=? WHERE id=?",
                (run_uid, detail[:2000], now, int(existing["id"])))
            self.conn.commit()
            return int(existing["id"])
        cur = self.conn.execute(
            "INSERT INTO mistake_ledger(kind,pattern,detail,first_run_uid,last_run_uid,"
            "times_seen,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (kind, pattern, detail[:2000], run_uid, run_uid, 1, "open", now, now))
        self.conn.commit()
        return int(cur.lastrowid)

    def known_mistakes(self, *, limit: int = 200, min_seen: int = 1) -> list[dict]:
        rows = self.query(
            "SELECT kind, pattern, detail, times_seen, status, last_run_uid "
            "FROM mistake_ledger WHERE times_seen>=? AND status!='resolved' "
            "ORDER BY times_seen DESC, updated_at DESC LIMIT ?", (min_seen, limit))
        return [dict(r) for r in rows]

    def set_mistake_status(self, *, kind: str, pattern: str, status: str) -> None:
        self.conn.execute(
            "UPDATE mistake_ledger SET status=?, updated_at=? WHERE kind=? AND pattern=?",
            (status, time.time(), kind, pattern))
        self.conn.commit()

    # -- cross-run history (past + present context for the advisor) ----------
    def recent_runs_digest(self, *, limit: int = 10) -> list[dict]:
        rows = self.query(
            "SELECT run_uid, tbhm_version, profile, intensity, target_count, "
            "started_at, ended_at, status FROM runs ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def recurring_failures(self, *, limit: int = 20) -> list[dict]:
        rows = self.query(
            "SELECT phase, COUNT(*) AS failures, COUNT(DISTINCT run_id) AS runs "
            "FROM phase_events WHERE event='failed' GROUP BY phase "
            "HAVING runs >= 1 ORDER BY failures DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def cross_run_finding_themes(self, *, limit: int = 25) -> list[dict]:
        rows = self.query(
            "SELECT phase, severity, COUNT(*) AS n, COUNT(DISTINCT run_id) AS runs "
            "FROM findings WHERE confirmation_status IN ('CONFIRMED','SUPPORTED') "
            "GROUP BY phase, severity ORDER BY n DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def approved_lessons_list(self, *, limit: int = 100) -> list[str]:
        rows = self.query(
            "SELECT lesson FROM approved_lessons ORDER BY id DESC LIMIT ?", (limit,))
        return [r["lesson"] for r in rows]

    def add_approved_lesson(self, *, lesson: str, source_candidate: int | None = None) -> int:
        return self._insert("approved_lessons", lesson=lesson,
                            source_candidate=source_candidate, approved_at=time.time())
