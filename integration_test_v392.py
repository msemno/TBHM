#!/usr/bin/env python3
"""Structural and report-quality checks for TBHM v3.9.2."""
from __future__ import annotations

import ast
import json
import sys
import tempfile
from argparse import Namespace
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.exploitability import assess
from core.reporter import Reporter
from core.storage import Storage
from phases import reverse_dynamic_evidence, reverse_triage


def check(value, message):
    if not value:
        raise AssertionError(message)


def phase_order():
    tree = ast.parse((ROOT / "tbhm.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "PHASE_ORDER":
                    return ast.literal_eval(node.value)
    raise AssertionError("PHASE_ORDER not found")


def test_registry_and_cli():
    phases = phase_order()
    chain = [
        "firmware_reverse_safe", "reverse_triage", "reverse_static_analysis",
        "reverse_dynamic_evidence", "reverse_symbolic_analysis", "reverse_correlation",
        "reverse_engineering_tooling",
    ]
    for left, right in zip(chain, chain[1:]):
        check(phases.index(left) < phases.index(right), f"phase order: {left} before {right}")
    check(phases.index("local_llm_triage") < phases.index("exploitability_assessment"), "LLM should precede final assessment")
    check(phases.index("exploitability_assessment") < phases.index("report"), "assessment should precede report")

    import tbhm
    old = sys.argv[:]
    try:
        sys.argv = [
            "tbhm", "-d", "training.local", "-y", "--binary-path", "/tmp/sample",
            "--reverse-static", "--reverse-backends", "ghidra,r2",
            "--reverse-dynamic-results", "/tmp/evidence", "--reverse-symbolic",
        ]
        args = tbhm.parse_args()
    finally:
        sys.argv = old
    check(args.reverse_static and args.reverse_symbolic, "reverse flags not parsed")
    check(args.reverse_backends == "ghidra,r2", "reverse backend list not parsed")
    check(hasattr(args, "no_exploitability_assessment"), "assessment disable flag missing")


def test_exploitability_rules():
    confirmed = {
        "phase": "verify", "severity": "HIGH", "confidence": "HIGH",
        "title": "Authorization bypass reproduced", "target": "https://example/api/user/2",
        "method": "GET", "evidence": "verification succeeded: other user's data returned",
        "verified": True, "verification_method": "two-account differential test",
        "finding_class": "confirmed", "impact": "Unauthorized access to another user's record.",
        "remediation": "Enforce object ownership checks.",
    }
    from test_support import verified_fields
    with tempfile.TemporaryDirectory() as td:
        confirmed.update(verified_fields(td))
    result = assess(confirmed)
    check(result["confirmation_status"] == "CONFIRMED", "verified proof was not confirmed")
    check(result["access_possible"] is True, "access impact not recognized")
    check(result["proof_of_concept"], "PoC missing")
    check(len(result["confirmed_steps"]) >= 4, "confirmed steps missing")

    scanner = dict(confirmed)
    scanner.update({"phase": "code_security_tooling", "verified": False, "finding_class": "lead", "evidence": "scanner says confirmed"})
    result = assess(scanner)
    check(result["confirmation_status"] == "UNCONFIRMED", "scanner prose promoted finding")


def test_reverse_triage_and_dynamic_import(tmp: Path):
    sample = tmp / "sample.bin"
    sample.write_bytes(b"\x7fELF\x00" + b"A" * 32 + b"\x00system\x00https://example.test/c2\x00password=NotARealSecret123\x00")

    class Runner:
        @staticmethod
        def has(_tool): return False
        @staticmethod
        def run(*_a, **_k): return 127, "", "missing"

    class Ctx:
        output = tmp / "out"
        args = Namespace(binary_path=str(sample), reverse_tooling=True, reverse_static=False,
                         reverse_max_files=10, reverse_max_file_mb=10, reverse_strings_min=8,
                         reverse_dynamic_results=None, reverse_verification_manifest=None,
                         reverse_evidence_max_mb=10)
        runner = Runner()
        saved = []
        @classmethod
        def save_finding(cls, finding): cls.saved.append(finding); return len(cls.saved)
        @staticmethod
        def log(*_a, **_k): pass

    Ctx.output.mkdir()
    reverse_triage.run(Ctx())
    check((Ctx.output / "redteam/25a_reverse_triage/reverse_triage_index.json").is_file(), "triage index missing")
    check(any("Suspicious imported capability" in f["title"] for f in Ctx.saved), "sensitive import not surfaced")

    dyn = tmp / "gdb.log"
    dyn.write_text("Program received SIGSEGV\nRIP=0x4141414141414141 controlled cyclic pattern\n")
    manifest = tmp / "verification.json"
    import hashlib
    digest = hashlib.sha256(dyn.read_bytes()).hexdigest()
    manifest.write_text(json.dumps({"evidence": [{
        "sha256": digest, "controlled": True, "reproduced": True, "approved": True,
        "verification_method": "clean-snapshot controlled cyclic-pattern reproduction",
        "reviewer": "integration-test", "scope_reference": "ROE-TEST"
    }]}))
    Ctx.args.reverse_dynamic_results = str(dyn)
    Ctx.args.reverse_verification_manifest = str(manifest)
    reverse_dynamic_evidence.run(Ctx())
    dynamic = [f for f in Ctx.saved if f.get("phase") == "reverse_dynamic_evidence"]
    check(dynamic and dynamic[-1].get("verified") is True, "controlled crash proof not marked verified")


def test_final_report(tmp: Path):
    store = Storage(tmp / "tbhm.db")
    store.save_run({"started_at": "2026-07-17T00:00:00", "profile": "authorized_safe", "targets": ["example.test"], "args": {}})
    store.save_finding({
        "phase": "verify", "severity": "HIGH", "confidence": "HIGH",
        "title": "Authorization bypass reproduced", "target": "example.test",
        "url": "https://example.test/api/users/2", "method": "GET", "parameter": "id",
        "payload": "2", "description": "A user can read another user's profile.",
        "evidence": "verification succeeded: other user's data returned", "impact": "Unauthorized PII disclosure.",
        "remediation": "Validate object ownership on every request.", "cwe": "CWE-639", "cvss": "8.1",
        "discovered_at": "2026-07-17T00:00:00", "finding_class": "confirmed", "verified": True,
        "verification_method": "two-account differential test",
    })
    store.save_finding({
        "phase": "reverse_static_analysis", "severity": "MEDIUM", "confidence": "LOW",
        "title": "[LEAD] Unsafe strcpy import", "target": "sample.bin", "description": "Static import only.",
        "evidence": "strcpy", "impact": "Potential memory corruption.", "remediation": "Review callers.",
        "cwe": "CWE-120", "cvss": "", "discovered_at": "2026-07-17T00:00:01", "finding_class": "lead",
    })
    from test_support import captured_access_proof
    from core.assertion_engine import evaluate, confirmation_fields
    assertion, proof = captured_access_proof(tmp)
    fid = next(f['id'] for f in store.all_findings() if f['phase'] == 'verify')
    result = evaluate(assertion, proof, evidence_root=tmp)
    aid = store.record_validation_attempt(verifier='fixture-v2', result=result, assertion=assertion, proof=proof, finding_id=fid)
    store.update_finding_verification(fid, confirmation_fields(result, method='fixture-v2', validation_attempt_id=aid))
    for row in store.all_findings():
        store.enrich_finding(row["id"], {"exploitability": assess(row)})

    class Ctx:
        output = tmp / "report"
        storage = store
        targets = ["example.test"]
        profile = {"name": "authorized_safe"}
        start_ts = "2026-07-17T00:00:00"
        args = Namespace(no_html=False, bug_bounty_program=None, roe_ticket="ROE-TEST")
    Ctx.output.mkdir()
    Reporter(Ctx()).write_all()
    final = (Ctx.output / "REPORT_final.md").read_text()
    for heading in ("Table of Contents", "Executive Summary", "Proof of Concept", "Confirmed Steps to Reproduce", "Security Impact", "Remediation"):
        check(heading in final, f"final report missing {heading}")
    confirmed = (Ctx.output / "REPORT_confirmed.md").read_text()
    check("Authorization bypass" in confirmed and "Unsafe strcpy" not in confirmed, "confirmed/lead separation failed")
    check((Ctx.output / "REPORT_final.html").is_file(), "final HTML report missing")
    binary_kits = list((Ctx.output / "PER-FINDING").glob("*Unsafe_strcpy*"))
    check(binary_kits, "binary lead evidence kit missing")
    check(not (binary_kits[0] / "curl.sh").exists(), "binary finding received invalid curl helper")
    check(not (binary_kits[0] / "reproducer.py").exists(), "binary finding received invalid HTTP reproducer")
    check((binary_kits[0] / "artifact_provenance.sh").is_file(), "binary provenance helper missing")


def main():
    with tempfile.TemporaryDirectory(prefix="tbhm-v392-") as td:
        tmp = Path(td)
        test_registry_and_cli()
        test_exploitability_rules()
        test_reverse_triage_and_dynamic_import(tmp)
        test_final_report(tmp)
    print("v3.9.2 reverse/report/confirmation tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
