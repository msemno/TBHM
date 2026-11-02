#!/usr/bin/env python3
"""Offline regression suite for v3.9.4.1 correctness/safety fixes.

No live network, model, or external security tool is required.  The suite uses
small temporary artifacts and mocked HTTP responses to verify the exact failure
modes found in the v3.9.4 audit.
"""
from __future__ import annotations

import io
import json
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

ROOT = Path(__file__).resolve().parent


class FakeResponse:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.content = text.encode("utf-8")


class FakeRequests:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        value = self.routes.get(url)
        if isinstance(value, Exception):
            raise value
        return value or FakeResponse(404, "not found", {"Content-Type": "text/html"})


class FakeRunner:
    @staticmethod
    def read_lines(path):
        p = Path(path)
        return p.read_text(errors="ignore").splitlines() if p.exists() else []

    @staticmethod
    def has(_name):
        return False


class FakeStorage:
    def __init__(self, findings=None):
        self.scores = []
        self.findings = findings or []
        self.enriched = []

    def save_endpoint_score(self, url, score, components):
        self.scores.append((url, score, components))

    def all_findings(self):
        return self.findings

    def enrich_finding(self, finding_id, data):
        self.enriched.append((finding_id, data))


class FakeCtx:
    def __init__(self, output, *, targets=None, profile=None, scope=None, args=None,
                 findings=None):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.targets = targets or ["example.com"]
        self.profile = profile or {
            "name": "authorized_safe", "active_probes": True,
            "rate_limit": {"global_rps": 10, "per_target_rps": 10},
        }
        self.scope = scope
        self.scope_excludes = []
        self.runner = FakeRunner()
        self.storage = FakeStorage(findings=findings)
        self.args = args or types.SimpleNamespace()
        self.saved = []
        self.logs = []
        self.phase_state = {}

    def save_finding(self, finding):
        self.saved.append(finding)
        return len(self.saved)

    def log(self, level, phase, message):
        self.logs.append((level, phase, message))


class DummyRateLimiter:
    def __init__(self, _rps):
        pass

    def wait(self):
        pass


class V3941RegressionTests(unittest.TestCase):
    def test_public_suffix_and_ip_scope(self):
        from core.targets import _registrable_domain, target_scope_allows
        self.assertEqual(_registrable_domain("app.example.co.uk"), "example.co.uk")
        self.assertEqual(_registrable_domain("api.example.co.id"), "example.co.id")
        self.assertEqual(_registrable_domain("api.example.com.my"), "example.com.my")
        self.assertEqual(_registrable_domain("192.0.2.10"), "192.0.2.10")
        self.assertEqual(_registrable_domain("2001:db8::1"), "2001:db8::1")
        ctx = FakeCtx(tempfile.mkdtemp(), targets=["app.example.co.uk"])
        self.assertFalse(target_scope_allows(ctx, "https://api.example.co.uk/v1"))
        self.assertTrue(target_scope_allows(ctx, "https://app.example.co.uk/v1"))
        self.assertFalse(target_scope_allows(ctx, "https://unrelated.co.uk/"))

    def test_scope_safe_redirect_stops_before_external_request(self):
        from core.scoped_http import safe_get
        ctx = FakeCtx(tempfile.mkdtemp(), targets=["example.com"])
        req = FakeRequests({
            "https://example.com/start": FakeResponse(302, headers={"Location": "https://evil.invalid/x"})
        })
        with self.assertRaises(ValueError):
            safe_get(ctx, req, "https://example.com/start")
        self.assertEqual([c[0] for c in req.calls], ["https://example.com/start"])

    def test_js_analysis_blocks_out_of_scope_before_request(self):
        from phases import js_analysis
        with tempfile.TemporaryDirectory() as td:
            ctx = FakeCtx(td, targets=["example.com"])
            recon = Path(td) / "recon"; recon.mkdir()
            (recon / "javascript.txt").write_text("https://evil.invalid/app.js\n")
            req = FakeRequests()
            with mock.patch.object(js_analysis, "requests", req), \
                 mock.patch("core.api_baseline.RateLimiter", DummyRateLimiter):
                js_analysis.run(ctx)
            self.assertEqual(req.calls, [])

    def test_deep_crawl_passive_and_404_handling(self):
        from phases import deep_crawl
        with tempfile.TemporaryDirectory() as td:
            recon = Path(td) / "recon"; recon.mkdir()
            (recon / "alive.txt").write_text("https://example.com\n")
            passive = FakeCtx(td, targets=["example.com"], profile={
                "name": "passive_only", "active_probes": False,
                "rate_limit": {"global_rps": 0, "per_target_rps": 0},
            })
            req = FakeRequests({"https://example.com": FakeResponse(200, "ok")})
            with mock.patch.object(deep_crawl, "requests", req), \
                 mock.patch("core.api_baseline.RateLimiter", DummyRateLimiter):
                deep_crawl.run(passive)
            self.assertEqual(req.calls, [])

        with tempfile.TemporaryDirectory() as td:
            recon = Path(td) / "recon"; recon.mkdir()
            (recon / "alive.txt").write_text("https://example.com\n")
            ctx = FakeCtx(td, targets=["example.com"])
            req = FakeRequests({
                "https://example.com": FakeResponse(404, "not found", {"Content-Type": "text/html"})
            })
            with mock.patch.object(deep_crawl, "requests", req), \
                 mock.patch("core.api_baseline.RateLimiter", DummyRateLimiter):
                deep_crawl.run(ctx)
            self.assertEqual(ctx.storage.scores, [])
            self.assertEqual((Path(td) / "crawl" / "discovered_urls.txt").read_text(), "")

    def test_deep_crawl_uses_final_redirect_base_for_relative_links(self):
        from phases import deep_crawl
        with tempfile.TemporaryDirectory() as td:
            recon = Path(td) / "recon"; recon.mkdir()
            (recon / "urls.txt").write_text("https://example.com/old\n")
            ctx = FakeCtx(td, targets=["example.com"])
            req = FakeRequests({
                "https://example.com/old": FakeResponse(302, headers={"Location": "/new/base/"}),
                "https://example.com/new/base/": FakeResponse(
                    200, '<a href="child">child</a>', {"Content-Type": "text/html"}),
                "https://example.com/new/base/child": FakeResponse(
                    200, "done", {"Content-Type": "text/html"}),
            })
            with mock.patch.object(deep_crawl, "requests", req), \
                 mock.patch("core.api_baseline.RateLimiter", DummyRateLimiter):
                deep_crawl.run(ctx)
            called = [c[0] for c in req.calls]
            self.assertIn("https://example.com/new/base/child", called)
            self.assertNotIn("https://example.com/child", called)

    def test_surface_correlation_consumes_source_hosts_urls_and_excludes(self):
        from core.scope import Scope
        from phases import surface_correlation
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            for d in (out / "recon", out / "code", out / "crawl"):
                d.mkdir(parents=True, exist_ok=True)
            (out / "recon" / "alive.txt").write_text("https://api.example.com\n")
            (out / "code" / "hosts.txt").write_text("admin.example.com\nblocked.example.com\n")
            (out / "code" / "urls.txt").write_text(
                "https://admin.example.com/internal\nhttps://blocked.example.com/private\n")
            (out / "code" / "endpoints.txt").write_text("/v1/users\n")
            ctx = FakeCtx(td, targets=["example.com"],
                          scope=Scope(["example.com"], ["blocked.example.com"]))
            surface_correlation.run(ctx)
            urls = {row[0] for row in ctx.storage.scores}
            self.assertIn("https://admin.example.com/internal", urls)
            self.assertIn("https://admin.example.com/v1/users", urls)
            self.assertIn("https://api.example.com/v1/users", urls)
            self.assertFalse(any("blocked.example.com" in u for u in urls))

    def test_static_taint_is_supported_not_mitigated_or_confirmed(self):
        from core import code_intel as CI
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "app.py"
            p.write_text(
                "from flask import Flask, request\nimport os\napp=Flask(__name__)\n"
                "@app.route('/run')\ndef run():\n"
                "    cmd = request.args.get('cmd')\n    return os.system(cmd)\n")
            cmap = CI.build_map(Path(td))
            traces = CI.trace_vulns(Path(td), cmap)
            hits = [t for t in traces if t.get("cwe") == "CWE-78"]
            self.assertTrue(hits)
            self.assertEqual(hits[0]["taint_class"], "unsanitized_static_lead")
            self.assertEqual(hits[0]["confidence"], "HIGH")
            self.assertFalse(hits[0]["dataflow_confirmed"])
            for route in cmap.get("routes", []):
                route["live_status"] = 200
            reachable = [t for t in CI.trace_vulns(Path(td), cmap) if t.get("cwe") == "CWE-78"]
            self.assertEqual(reachable[0]["taint_class"], "supported_static_reachable")
            self.assertFalse(reachable[0]["dataflow_confirmed"])

    def test_supported_static_survives_false_positive_gate(self):
        from core.fp_filters import assess
        from core.finding_class import apply
        finding = {
            "phase": "code_intel",
            "severity": "HIGH",
            "confidence": "HIGH",
            "title": "[code_injection] OS command injection supported static lead: app.py:7",
            "target": "src/app.py",
            "evidence": "src/app.py:7 os.system(cmd) | request.args.get('cmd')",
            "finding_class": "supported",
            "verified": False,
            "verification_method": "static-taint-dataflow",
        }
        action, _, _ = assess(finding)
        self.assertEqual(action, "keep")
        apply(finding)
        self.assertEqual(finding["finding_class"], "supported")
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertEqual(finding["severity"], "HIGH")

    def test_ai_restore_rejects_special_tar_members(self):
        import io
        import tarfile
        from core.ai_plane import cli
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "tool"
            root.mkdir()
            archive = Path(td) / "bad.tar"
            with tarfile.open(archive, "w") as tf:
                info = tarfile.TarInfo("bad-fifo")
                info.type = tarfile.FIFOTYPE
                tf.addfile(info, io.BytesIO(b""))
            args = types.SimpleNamespace(ai_restore=str(archive), ai_home=str(Path(td) / "home"))
            self.assertEqual(cli._restore(args, root), 2)

    def test_structured_http_differential_only(self):
        from core.fp_filters import _has_runtime_proof
        self.assertFalse(_has_runtime_proof({"evidence": "baseline -> 403; proof -> 200"}))
        self.assertFalse(_has_runtime_proof({"evidence": "GET /x -> 403"}))
        self.assertTrue(_has_runtime_proof({
            "evidence": "authorization differential recorded separately",
            "differential": {
                "baseline_status": 403, "proof_status": 200,
                "negative_control_passed": True,
                "expected_delta": "protected object became readable under the modified identity",
            },
        }))

    def test_reverse_correlation_groups_by_artifact_id(self):
        from phases import reverse_correlation
        artifact = "sha256:" + "a" * 64
        findings = [
            {"id": 1, "phase": "reverse_static_analysis", "target": "/evidence/ghidra.json",
             "artifact_id": artifact, "severity": "MEDIUM", "verified": False},
            {"id": 2, "phase": "reverse_dynamic_evidence", "target": "/evidence/gdb.log",
             "artifact_id": artifact, "severity": "HIGH", "verified": True},
        ]
        args = types.SimpleNamespace(binary_path="sample.bin", reverse_results=None,
                                     reverse_dynamic_results="gdb.log",
                                     reverse_symbolic_results=None, reverse_tooling=False,
                                     reverse_static=False, reverse_symbolic=False)
        with tempfile.TemporaryDirectory() as td:
            ctx = FakeCtx(td, args=args, findings=findings)
            reverse_correlation.run(ctx)
            payload = ctx.phase_state["reverse_correlation"]
            self.assertEqual(len(payload["artifacts"]), 1)
            item = payload["artifacts"][0]
            self.assertEqual(item["artifact_id"], artifact)
            self.assertEqual(item["assessment"], "corroborated-static-and-dynamic")
            self.assertEqual(len(item["evidence_targets"]), 2)

    def test_storage_redacts_secrets_but_preserves_artifact_hash(self):
        from core.storage import Storage
        with tempfile.TemporaryDirectory() as td:
            st = Storage(Path(td) / "test.db")
            st.save_run({"started_at": "now", "profile": "test", "targets": ["local"],
                         "excludes": [], "args": {}, "bug_bounty_program": ""})
            digest = "b" * 64
            fid = st.save_finding({
                "phase": "test", "severity": "MEDIUM", "confidence": "HIGH",
                "title": "secret", "target": "/tmp/a", "evidence": "api_key=sk_live_ABCDEFGHIJKLMNO",
                "artifact_id": "sha256:" + digest, "discovered_at": "now",
            })
            found = next(f for f in st.all_findings() if f["id"] == fid)
            self.assertNotIn("sk_live_ABCDEFGHIJKLMNO", found["evidence"])
            self.assertIn("REDACTED", found["evidence"])
            self.assertEqual(found["artifact_id"], "sha256:" + digest)

    def test_ai_delta_replaces_stale_document_and_updates_incrementally(self):
        from core.ai_plane.store import Store
        from core.ai_plane.embeddings import Embedder, VectorIndex
        from core.ai_plane import indexer
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "tool"; root.mkdir()
            (root / "a.py").write_text("def value():\n    return 'OLD_MARKER'\n")
            (root / "payloads").mkdir(); (root / "payloads" / "x.txt").write_text("payload-resource")
            store = Store(base / "memory.sqlite3")
            embedder = Embedder(); embedder._remote = lambda _text: None
            vindex = VectorIndex(base / "vectors.npz", base / "manifest.json")
            first = indexer.reindex(root, store, embedder, vindex, full=True)
            total = first["vector_index"]["rows"]
            (root / "a.py").write_text("def value():\n    return 'NEW_MARKER'\n")
            second = indexer.reindex(root, store, embedder, vindex, full=False)
            docs = store.query("SELECT id FROM documents WHERE source_path='a.py'")
            self.assertEqual(len(docs), 1)
            text = "\n".join(r["text"] for r in store.query(
                "SELECT c.text FROM document_chunks c JOIN documents d ON d.id=c.document_id WHERE d.source_path='a.py'"))
            self.assertIn("NEW_MARKER", text)
            self.assertNotIn("OLD_MARKER", text)
            self.assertFalse(second["vector_index"]["rebuild"])
            self.assertLess(second["vector_index"]["updated_rows"], total)
            self.assertTrue(any("-    return 'OLD_MARKER'" in d["diff"] and
                                "+    return 'NEW_MARKER'" in d["diff"]
                                for d in second["source_diffs"]))
            manifest_paths = set(store.manifest_map())
            self.assertIn("payloads/x.txt", manifest_paths)
            store.close()

    def test_ai_embedding_batch_never_mixes_spaces(self):
        from core.ai_plane.embeddings import Embedder
        emb = Embedder()
        calls = iter([np.array([1.0, 0.0], dtype=np.float32), None])
        emb._remote = lambda _text: next(calls)
        matrix, mode = emb.embed_many(["one", "two"])
        self.assertEqual(mode, "fallback")
        self.assertEqual(matrix.shape, (2, 256))

    def test_ai_model_lock_is_authoritative(self):
        from core.ai_plane import home as home_mod
        from core.ai_plane import build_plane
        with tempfile.TemporaryDirectory() as td:
            home = home_mod.get(td, create=True)
            home.model_lock.write_text(json.dumps({
                "advisor_model": "locked-advisor", "embedding_model": "locked-embed"
            }))
            captured = {}
            class Client:
                def available(self): return False, "test"
            def fake_runtime(args):
                captured["model"] = getattr(args, "local_llm_model", None)
                return types.SimpleNamespace(client=Client())
            args = types.SimpleNamespace(ai_home=td, local_llm_url="http://127.0.0.1:11434",
                                         local_llm_model="wrong", ai_advisor_model="wrong",
                                         ai_embedding_model="wrong")
            with mock.patch("core.llm_local.runtime_from_args", fake_runtime):
                plane = build_plane(args, create=True, need_runtime=True)
            try:
                self.assertEqual(plane.embedder.model, "locked-embed")
                self.assertEqual(captured["model"], "locked-advisor")
            finally:
                plane.close()

    def test_ai_ingestion_and_backup_never_store_raw_secret_and_include_proposals(self):
        from core.ai_plane import build_plane
        from core.ai_plane import cli as ai_cli
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            home_dir = base / "ai-home"
            secret_file = base / "note.txt"
            secret = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            secret_file.write_text(f"operator note api_key={secret}\n")
            args = types.SimpleNamespace(ai_home=str(home_dir), local_llm_url="http://127.0.0.1:11434",
                                         local_llm_model=None, ai_embedding_model=None)
            plane = build_plane(args, create=True, need_runtime=False)
            plane.embedder._remote = lambda _text: None
            try:
                self.assertEqual(ai_cli._ingest(plane, ROOT, secret_file, "operator_note"), 0)
                files = list(plane.home.resources_dir.iterdir())
                self.assertTrue(any(p.name.endswith(".sanitized.txt") for p in files))
                self.assertFalse(any(p.name.endswith("note.txt") and not p.name.endswith(".sanitized.txt") for p in files))
                self.assertNotIn(secret, "\n".join(p.read_text(errors="ignore") for p in files))
                proposal = plane.gate.create(problem="test", evidence=[], affected_files=["a.py"],
                                              patch_text="--- a/a.py\n+++ b/a.py\n", risks=[])
                self.assertEqual(ai_cli._backup(plane), 0)
                archive = sorted(plane.home.root.glob("tbhm-ai-backup-*.tar.gz"))[-1]
                with tarfile.open(archive, "r:gz") as tf:
                    names = tf.getnames()
                    self.assertTrue(any(proposal["proposal_id"] in n for n in names))
                    self.assertTrue(any(n.endswith(".sanitized.txt") for n in names))
                    self.assertFalse(any("vectors.npz" in n for n in names))
            finally:
                plane.close()

    def test_observer_lesson_candidates_are_current_run_only(self):
        from core.ai_plane.store import Store
        from core.ai_plane.observer import RunObserver
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "m.sqlite3")
            r1 = store.start_run(run_uid="old", tbhm_version="x", profile="p",
                                 intensity="s", target_count=1)
            store.add_event(run_id=r1, phase="old_phase", event="failed")
            r2 = store.start_run(run_uid="new", tbhm_version="x", profile="p",
                                 intensity="s", target_count=1)
            store.add_event(run_id=r2, phase="new_phase", event="failed")
            obs = RunObserver(store=store, embedder=None, vector_index=None, advisor=None,
                              proposal_gate=None, audit=None, runtime=None)
            obs.run_id = r2; obs.run_uid = "new"
            obs._learning_review(types.SimpleNamespace())
            candidates = [r["candidate"] for r in store.query("SELECT candidate FROM lesson_candidates")]
            self.assertEqual(len(candidates), 1)
            self.assertIn("new_phase", candidates[0])
            self.assertNotIn("old_phase", candidates[0])
            store.close()

    def test_profile_phase_order_rate_and_local_only_gate(self):
        import tbhm
        import yaml
        data = yaml.safe_load((ROOT / "profiles" / "authorized_redteam.yaml").read_text())
        for phase in ("js_analysis", "deep_crawl", "surface_correlation", "llm_run_analysis"):
            self.assertIn(phase, data["phases"])
        self.assertGreater(tbhm.PHASE_ORDER.index("llm_run_analysis"),
                           tbhm.PHASE_ORDER.index("playbook_integration"))
        self.assertLess(tbhm.PHASE_ORDER.index("llm_run_analysis"),
                        tbhm.PHASE_ORDER.index("report"))
        args = types.SimpleNamespace(rate_limit_override=70, silent=True)
        profile = {"name": "authorized_full", "active_probes": True,
                   "rate_limit": {"global_rps": 10, "per_target_rps": 5},
                   "hard_limits": {"max_global_rps": 50, "max_per_target_rps": 20}}
        tbhm._apply_rate_limit_override(args, profile)
        self.assertEqual(profile["rate_limit"]["global_rps"], 50)
        self.assertEqual(profile["rate_limit"]["hard_cap"], 50)
        passive = {"name": "passive_only", "active_probes": False,
                   "rate_limit": {"global_rps": 0, "per_target_rps": 0},
                   "hard_limits": {"max_global_rps": 50, "max_per_target_rps": 20}}
        tbhm._apply_rate_limit_override(args, passive)
        self.assertEqual(passive["rate_limit"]["global_rps"], 0)
        local_args = types.SimpleNamespace(phases="reverse_engineering_tooling,report",
                                           binary_path="sample.bin")
        self.assertEqual(tbhm._local_only_target(local_args), "local-analysis.invalid")
        bad_args = types.SimpleNamespace(phases="recon,report", binary_path="sample.bin")
        self.assertIsNone(tbhm._local_only_target(bad_args))

    def test_boundary_aware_short_api_and_capa_parser(self):
        from core.reverse_utils import raw_short_imports
        from phases.reverse_engineering_tooling import _capa_items
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "sample.bin"
            p.write_bytes(b"ecosystem configuration\x00system\x00")
            names = {x["name"] for x in raw_short_imports(p)}
            self.assertIn("system", names)
            p.write_bytes(b"ecosystem configuration only")
            names = {x["name"] for x in raw_short_imports(p)}
            self.assertNotIn("system", names)
            capa = Path(td) / "capa.json"
            capa.write_text(json.dumps({"rules": {
                "network/http/client": {"meta": {"name": "HTTP client", "description": "uses HTTP"},
                                          "matches": {"0x401000": []}},
                "empty": {"meta": {"name": "Empty"}, "matches": {}},
            }}))
            items = _capa_items(capa, p)
            self.assertEqual(len(items), 1)
            self.assertIn("HTTP client", items[0]["title"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
