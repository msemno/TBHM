#!/usr/bin/env python3
"""Offline regression and backward-compatibility suite for TBHM v3.9.6.1.

The suite is deliberately network-free. It checks that the 3.9.6 enterprise
control plane remains present, earlier CLI/phase/module surfaces were not
accidentally deleted, profile phases use the authoritative dependency order,
and the restored report/reproducer outputs are generated safely.
"""
from __future__ import annotations

import argparse
import ast
import json
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASELINE = ROOT / "knowledge" / "compatibility_baseline_v3961.json"
IGNORE_PARTS = {"__pycache__", ".git", ".pytest_cache", "results", "result", "output", "outputs"}


def _tree(path: Path):
    return ast.parse(path.read_text(encoding="utf-8", errors="ignore"))


def _cli_flags(root: Path) -> set[str]:
    flags = set()
    for path in root.rglob("*.py"):
        if any(part in IGNORE_PARTS for part in path.parts):
            continue
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("-"):
                        flags.add(arg.value)
    return flags


def _public_symbols(path: Path) -> set[str]:
    names = set()
    for node in _tree(path).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            if isinstance(node, ast.ClassDef):
                names.update(
                    child.name for child in node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                )
    return names


def _args(**updates):
    defaults = {
        "confidence_threshold": 0.0,
        "dep_filter": None,
        "no_html": False,
        "allow_writes": False,
        "bug_bounty_program": None,
        "roe_ticket": None,
    }
    defaults.update(updates)
    return types.SimpleNamespace(**defaults)


class Storage:
    def __init__(self, findings=None):
        self.findings = list(findings or [])
    def all_findings(self):
        return list(self.findings)


class Context:
    def __init__(self, output: Path, findings=None):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.args = _args()
        self.targets = ["example.com"]
        self.profile = {
            "name": "authorized_redteam",
            "active_probes": True,
            "rate_limit": {"global_rps": 3, "per_target_rps": 2},
            "hard_limits": {"max_global_rps": 50},
        }
        self.start_ts = "2026-07-19T00:00:00+00:00"
        self.storage = Storage(findings)


class V3961RegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    def test_release_versions_are_synchronized(self):
        import tbhm
        from core import reporter
        from core import ai_plane
        self.assertIn("v4.2.7", tbhm.__doc__ or "")
        self.assertEqual(reporter.VERSION, "4.2.7")
        self.assertEqual(ai_plane.__version__, "4.2.7")

    def test_all_historical_cli_flags_are_retained(self):
        missing = set(self.baseline["cli_flags"]) - _cli_flags(ROOT)
        self.assertEqual(missing, set(), f"Deleted CLI flags: {sorted(missing)}")

    def test_all_historical_phases_are_retained(self):
        import tbhm
        missing = set(self.baseline["phase_names"]) - set(tbhm.PHASE_ORDER)
        self.assertEqual(missing, set(), f"Deleted phases: {sorted(missing)}")
        self.assertEqual(len(tbhm.PHASE_ORDER), len(set(tbhm.PHASE_ORDER)), "PHASE_ORDER contains duplicates")
        self.assertLess(tbhm.PHASE_ORDER.index("preflight"), tbhm.PHASE_ORDER.index("osint_depth_collectors"))
        self.assertLess(tbhm.PHASE_ORDER.index("web3"), tbhm.PHASE_ORDER.index("verify"))
        self.assertLess(tbhm.PHASE_ORDER.index("report"), tbhm.PHASE_ORDER.index("evidence_finalize"))

    def test_historical_source_and_config_paths_are_retained(self):
        missing = [rel for rel in self.baseline["meaningful_paths"] if not str(rel).startswith("__compat_") and not (ROOT / rel).is_file()]
        self.assertEqual(missing, [], f"Deleted source/config files: {missing}")

    def test_historical_public_symbols_are_retained(self):
        missing = {}
        for rel, expected in self.baseline["public_symbols"].items():
            if str(rel).startswith("__compat_"):
                continue
            path = ROOT / rel
            if not path.is_file():
                missing[rel] = expected
                continue
            current = _public_symbols(path)
            lost = set(expected) - current
            if lost:
                missing[rel] = sorted(lost)
        self.assertEqual(missing, {}, f"Deleted public functions/classes/methods: {missing}")

    def test_historical_structured_catalog_identifiers_are_retained(self):
        from scripts.build_compatibility_baseline import collect_identifiers, load_structured
        missing = {}
        for rel, expected in self.baseline["structured_identifiers"].items():
            path = ROOT / rel
            current = collect_identifiers(load_structured(path)) if path.is_file() else set()
            lost = set(expected) - current
            if lost:
                missing[rel] = sorted(lost)
        self.assertEqual(missing, {}, f"Deleted catalog/profile/template identifiers: {missing}")

    def test_historical_payload_and_wordlist_entries_are_retained(self):
        missing = {}
        for rel, expected in self.baseline["payload_wordlist_entries"].items():
            path = ROOT / rel
            current = {
                line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            } if path.is_file() else set()
            lost = set(expected) - current
            if lost:
                missing[rel] = sorted(lost)
        self.assertEqual(missing, {}, f"Deleted payload/wordlist entries: {missing}")

    def test_profiles_are_canonicalized_and_finalization_is_last(self):
        import tbhm
        import yaml
        for name in ("authorized_assumed_breach.yaml", "authorized_redteam.yaml", "quick_recon.yaml"):
            data = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
            phases = data.get("phases") or []
            canonical, unknown, duplicates = tbhm.canonicalize_profile_phases(phases)
            self.assertEqual(unknown, [], name)
            self.assertEqual(duplicates, [], name)
            self.assertEqual(phases, canonical, f"{name} is not in canonical phase order")
            if "preflight" in phases:
                self.assertEqual(phases[0], "preflight", name)
            if "report" in phases and "evidence_finalize" in phases:
                self.assertLess(phases.index("report"), phases.index("evidence_finalize"), name)
                self.assertEqual(phases[-1], "evidence_finalize", name)
            if "web3" in phases and "verify" in phases:
                self.assertLess(phases.index("web3"), phases.index("verify"), name)

    def test_restored_http_reproducer_kit_is_complete(self):
        from core.reporter import Reporter
        assessment = {
            "confirmation_status": "CONFIRMED",
            "exploitability_status": "EXPLOITABLE",
            "evidence_strength": "conclusive",
            "access_level": "authenticated user data",
            "summary": "Authorization check can be bypassed.",
            "proof_of_concept": "curl -i -sk https://example.com/api/items/2",
            "confirmed_steps": ["Authenticate as test user A.", "Request user B's test object."],
            "confirmation_reasons": ["Positive proof succeeded.", "Negative control was denied."],
            "attack_prerequisites": ["Authorized test accounts A and B."],
            "attack_scenario": "A low-privilege account reads another account's test object.",
            "security_impact": "Cross-account data exposure.",
            "remediation": "Enforce object ownership server-side.",
            "retest_criteria": "Cross-account request returns 403 while owner request succeeds.",
        }
        finding = {
            "id": None,
            "phase": "access_control",
            "severity": "HIGH",
            "confidence": "CONFIRMED",
            "title": "Cross-account object access",
            "url": "https://example.com/api/items/2?view=full",
            "target": "example.com",
            "method": "GET",
            "headers": {"Accept": "application/json"},
            "evidence": "HTTP 200 returned user B's synthetic test object.",
            "enrichment": {"exploitability": assessment},
        }
        with tempfile.TemporaryDirectory() as td:
            ctx = Context(Path(td), [finding])
            Reporter(ctx)._write_per_finding_kits([finding])
            directories = list((Path(td) / "PER-FINDING").iterdir())
            self.assertEqual(len(directories), 1)
            kit = directories[0]
            expected = {
                "curl.sh", "reproducer.py", "request.http", "burp_request.txt",
                "postman_collection.json", "WORKBOOK.md", "finding.json",
            }
            self.assertTrue(expected.issubset({path.name for path in kit.iterdir()}))
            self.assertIn("GET /api/items/2?view=full HTTP/1.1", (kit / "request.http").read_text())
            postman = json.loads((kit / "postman_collection.json").read_text())
            self.assertEqual(postman["info"]["schema"], "https://schema.getpostman.com/json/collection/v2.1.0/collection.json")
            compile((kit / "reproducer.py").read_text(), str(kit / "reproducer.py"), "exec")

    def test_reverse_kit_never_executes_the_artifact(self):
        from core.reporter import Reporter
        finding = {
            "id": "RE-1", "phase": "reverse_static_analysis", "severity": "MEDIUM",
            "title": "Dangerous import lead", "target": "/tmp/sample.bin", "url": "",
            "enrichment": {"exploitability": {
                "confirmation_status": "SUPPORTED", "exploitability_status": "UNKNOWN",
                "proof_of_concept": "Static import observation only.", "confirmed_steps": [],
            }},
        }
        with tempfile.TemporaryDirectory() as td:
            kit = Path(td) / "kit"; kit.mkdir()
            Reporter(Context(Path(td)))._write_kit(finding, kit, stable_id="RE-1")
            helper = (kit / "artifact_provenance.sh").read_text()
            self.assertIn("sha256sum", helper)
            self.assertIn("file --", helper)
            self.assertNotIn("exec ", helper)
            self.assertNotIn("./sample.bin", helper)

    def test_detailed_branch_table_is_restored(self):
        from core.reporter import Reporter
        finding = {"id": 1, "phase": "access_control", "severity": "HIGH", "title": "IDOR lead"}
        with tempfile.TemporaryDirectory() as td:
            ctx = Context(Path(td), [finding])
            governance = Path(td) / "redteam" / "00_governance"
            governance.mkdir(parents=True)
            (governance / "branch_matrix.json").write_text(json.dumps({
                "branches": [
                    {"id": "BR09", "title": "Web application testing", "automation": "partial"},
                    {"id": "BR21", "title": "Social engineering", "automation": "checklist"},
                ]
            }), encoding="utf-8")
            Reporter(ctx)._write_methodology_audit([finding])
            text = (Path(td) / "METHODOLOGY_AUDIT.md").read_text()
            self.assertIn("Detailed Playbook Branch Status", text)
            self.assertIn("Tested (partial, automated)", text)
            self.assertIn("Not Tested — manual/checklist only", text)
            self.assertNotIn("| Safe |", text)

    def test_all_python_and_data_files_parse(self):
        import yaml
        failures = []
        for path in ROOT.rglob("*.py"):
            if "__pycache__" not in path.parts:
                try:
                    _tree(path)
                except Exception as exc:
                    failures.append(f"{path.relative_to(ROOT)}: {exc}")
        for path in ROOT.rglob("*.json"):
            try:
                json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            except Exception as exc:
                failures.append(f"{path.relative_to(ROOT)}: {exc}")
        for suffix in ("*.yaml", "*.yml"):
            for path in ROOT.rglob(suffix):
                try:
                    yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
                except Exception as exc:
                    failures.append(f"{path.relative_to(ROOT)}: {exc}")
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main(verbosity=2)
