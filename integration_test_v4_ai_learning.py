#!/usr/bin/env python3
"""v4 AI co-pilot learning-loop integration test.

Proves the four v4 capabilities end to end, all non-authoritative and gated:
  1. learns from the (sanitized) run log — and redacts secrets before storage
  2. records a cross-run mistake / false-positive ledger
  3. loads past mistakes at the start of the next run
  4. produces a prioritized next-step plan filed as a PENDING proposal that is
     NOT auto-applied; approval + explicit opt-in are required to use it.
Also proves a pre-v4 AI home migrates without data loss.
"""
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


class _FakeClient:
    def available(self):
        return True, "fake"

    def chat_json(self, system, user):
        if "recommended_next_phases" in user or "next DIRECTION" in user:
            return {"situation": "s",
                    "prioritized_targets": [{"target": "app.example.com", "why": "w", "value": "high"}],
                    "recommended_next_phases": [{"phase": "verify", "why": "confirm"},
                                                {"phase": "api_key_pivot", "why": "validate"}],
                    "skip_phases": [{"phase": "wireless_physical_soc", "why": "oos"}],
                    "avoid_repeating": ["example-token FP"],
                    "operator_decision_required": "approve"}
        return {"overall_summary": "ok", "risk_narrative": "n",
                "correlations": [], "verify_next": [], "coverage_gaps": []}


class _FakeRuntime:
    client = _FakeClient()


class _Storage:
    def __init__(self, f):
        self._f = f

    def all_findings(self):
        return self._f


class _Ctx:
    pass


def _plane(ai_home):
    from core.ai_plane import home as home_mod
    from core.ai_plane.store import Store
    from core.ai_plane.embeddings import Embedder, VectorIndex
    from core.ai_plane.advisor import Advisor
    from core.ai_plane.proposals import Audit, ProposalGate
    home = home_mod.get(ai_home, create=True)
    store = Store(home.db_path)
    emb = Embedder()
    vidx = VectorIndex(home.index_path, home.index_manifest)
    audit = Audit(store, home)
    gate = ProposalGate(store, home, audit)
    advisor = Advisor(_FakeClient(), retrieval=(store, emb, vidx))
    return home, store, emb, vidx, advisor, gate, audit


def _ctx(findings, secret="SUPER_SECRET_PW_98765"):
    c = _Ctx()
    c.output = Path(tempfile.mkdtemp(prefix="run-"))
    (c.output / "tbhm.log").write_text(
        f"[INFO] discovery ok\n[ERR] phase 'mobile_scan' crashed: boom\npassword={secret}\n")
    c.storage = _Storage(findings)
    c.args = type("A", (), {"intensity": "normal"})()
    c.profile = {"name": "authorized_safe"}
    c.targets = ["app.example.com"]
    c.log = lambda *a: None
    return c


class V4AILearningTests(unittest.TestCase):
    def setUp(self):
        self.ai_home = tempfile.mkdtemp(prefix="aihome-")
        os.environ["TBHM_AI_HOME"] = self.ai_home

    def test_learning_loop(self):
        from core.ai_plane.observer import RunObserver
        home, store, emb, vidx, advisor, gate, audit = _plane(self.ai_home)
        obs = RunObserver(store=store, embedder=emb, vector_index=vidx, advisor=advisor,
                          proposal_gate=gate, audit=audit, runtime=_FakeRuntime(), log=lambda *a: None)
        ctx1 = _ctx([
            {"id": "1", "title": "Confirmed IDOR", "finding_class": "confirmed",
             "severity": "HIGH", "phase": "access_control",
             "confirmation_status": "CONFIRMED", "verified": True},
            {"id": "2", "title": "gitleaks example token", "finding_class": "false_positive",
             "severity": "LOW", "phase": "code_scan", "cwe": "CWE-798"},
        ])
        obs.on_run_start(ctx1)
        obs.before_phase(ctx1, "mobile_scan")
        obs.after_phase(ctx1, "mobile_scan", False, 1.0)
        obs.on_run_end(ctx1, "completed")

        # 1. run log ingested and secret redacted
        logdocs = store.query("SELECT id FROM documents WHERE source_type='run_log'")
        self.assertTrue(logdocs, "run log should be ingested")
        chunks = store.query(
            "SELECT text FROM document_chunks c JOIN documents d ON d.id=c.document_id "
            "WHERE d.source_type='run_log'")
        self.assertFalse(any("SUPER_SECRET_PW_98765" in r["text"] for r in chunks),
                         "raw secret must be redacted before storage")

        # 2. mistake ledger populated (a phase error and a false positive)
        kinds = {m["kind"] for m in store.known_mistakes()}
        self.assertIn("phase_error", kinds)
        self.assertIn("false_positive", kinds)

        # 3. next run loads known mistakes
        obs2 = RunObserver(store=store, embedder=emb, vector_index=vidx, advisor=advisor,
                           proposal_gate=gate, audit=audit, runtime=_FakeRuntime(), log=lambda *a: None)
        ctx2 = _ctx([{"id": "9", "title": "x", "finding_class": "lead", "phase": "discovery"}])
        obs2.on_run_start(ctx2)
        self.assertGreaterEqual(len(getattr(ctx2, "_ai_known_mistakes", [])), 2)

        # 4. direction plan written + filed as pending proposal, NOT auto-applied
        self.assertTrue((ctx1.output / "llm_analysis" / "NEXT_STEPS.md").exists())
        pend = list(home.proposals_pending.glob("AI-PROP-*/proposal.json"))
        self.assertTrue(pend, "a pending direction proposal should exist")
        newest = max(pend, key=lambda p: p.stat().st_mtime)
        uid = newest.parent.name
        decision = gate.decide(uid, True, "approved")
        self.assertEqual(decision["status"], "accepted")
        self.assertFalse(decision["applied"], "approval must NOT auto-apply anything")

        import tbhm
        rec = tbhm._load_approved_plan_phases(type("A", (), {"ai_home": self.ai_home})())
        self.assertIn("verify", rec)
        self.assertIn("api_key_pivot", rec)

        ok, _msg = audit.verify_chain()
        self.assertTrue(ok, "audit hash-chain must stay intact")

    def test_pre_v4_home_migrates_without_loss(self):
        from core.ai_plane.store import Store, SCHEMA_VERSION
        db = tempfile.mktemp(suffix=".sqlite3")
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at REAL, note TEXT)")
        c.execute("INSERT INTO schema_migrations VALUES(4,?,?)", (time.time(), "old"))
        c.execute("CREATE TABLE approved_lessons(id INTEGER PRIMARY KEY AUTOINCREMENT, lesson TEXT NOT NULL, "
                  "source_candidate INTEGER, approved_at REAL NOT NULL)")
        c.execute("INSERT INTO approved_lessons(lesson,approved_at) VALUES(?,?)", ("kept lesson", time.time()))
        c.commit()
        c.close()
        store = Store(db)
        row = store.one("SELECT MAX(version) v FROM schema_migrations")
        self.assertEqual(row["v"], SCHEMA_VERSION)
        self.assertEqual(store.approved_lessons_list(), ["kept lesson"])
        store.record_mistake(kind="phase_error", pattern="x", run_uid="r")
        self.assertEqual(len(store.known_mistakes()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
