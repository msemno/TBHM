#!/usr/bin/env python3
"""Structural tests for v3.9.1 integrated LLM and evidence-safe additions."""
from __future__ import annotations

import ast
import json
import sys
import tempfile
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.engagement_evidence import analyze_path, sanitize_excerpt, synthetic_scenario
from core.finding_class import apply as classify_apply
from core.llm_local import local_llm_status


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def phase_order() -> list[str]:
    tree = ast.parse((ROOT / "tbhm.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "PHASE_ORDER":
                    return ast.literal_eval(node.value)
    raise AssertionError("PHASE_ORDER not found")


def test_registry_and_cli() -> None:
    phases = phase_order()
    check(phases.index("engagement_evidence_review") > phases.index("ad_access_assessment"), "evidence phase order")
    check(phases.index("engagement_evidence_review") < phases.index("local_llm_triage"), "evidence must precede LLM enrichment")
    prohibited = {
        "ad_poison_listen", "ad_harvest_tickets", "ad_crack_hashes", "ad_pth_movement",
        "ad_dcsync_exfil", "offensive_engagement", "meterpreter", "reverse_shell",
    }
    check(not prohibited.intersection(phases), "operational offensive phase registered")

    import tbhm
    old = sys.argv[:]
    try:
        sys.argv = [
            "tbhm", "-d", "training.local", "-y", "--exercise-simulation",
            "--engagement-evidence-type", "auto", "--local-llm", "--local-llm-required",
        ]
        args = tbhm.parse_args()
    finally:
        sys.argv = old
    check(args.exercise_simulation, "simulation flag missing")
    check(args.local_llm and args.local_llm_required, "integrated LLM flags missing")
    check(hasattr(args, "local_llm_status") and hasattr(args, "local_llm_setup"), "LLM management flags missing")


def test_evidence_sanitization(tmp: Path) -> None:
    evidence = tmp / "exercise.log"
    evidence.write_text(
        "Responder captured NTLMv2 00112233445566778899aabbccddeeff\n"
        "nxc smb 10.0.0.10 -u admin -H 00112233445566778899aabbccddeeff -x whoami\n"
        "DCSync result referenced krbtgt and directory replication\n"
        "Meterpreter session opened\n",
        encoding="utf-8",
    )
    report = analyze_path(evidence)
    names = {item["name"] for item in report["observations"]}
    check("credential-capture" in names, "credential evidence not categorized")
    check("pass-the-hash" in names, "PtH evidence not categorized")
    check("directory-replication-exposure" in names, "directory replication evidence not categorized")
    check("metasploit-session" in names, "session evidence not categorized")
    payload = json.dumps(report)
    check("00112233445566778899aabbccddeeff" not in payload, "hash leaked into normalized output")
    check("-x whoami" not in payload, "operational command leaked into normalized output")
    check(report["sources"][0]["sha256"], "source hash missing")
    check(report["safety"]["execution_performed"] is False, "execution boundary incorrect")

    excerpt = sanitize_excerpt("powershell -EncodedCommand AAAA\nbenign telemetry")
    check("EncodedCommand" not in excerpt, "operational line was not redacted")
    check("benign telemetry" in excerpt, "benign context was lost")


def test_synthetic_scenario_and_classification() -> None:
    report = synthetic_scenario("ad-domain-compromise")
    check(report["safety"]["synthetic_only"] is True, "simulation not marked synthetic")
    check(len(report["observations"]) >= 8, "simulation stages missing")
    check(all(item.get("simulation") for item in report["observations"]), "simulation marker missing")

    finding = {
        "phase": "engagement_evidence_review",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "title": "Imported exercise evidence",
        "evidence": "sanitized evidence",
    }
    classify_apply(finding)
    check(finding["finding_class"] == "lead", "imported exercise evidence promoted")
    check(finding["title"].startswith("[LEAD]"), "lead prefix missing")


def test_llm_status_contract() -> None:
    args = Namespace(
        local_llm_url="http://127.0.0.1:11434",
        local_llm_model="qwen3-cybersec:4b",
        local_llm_context=4096,
        local_llm_timeout=30,
    )
    with patch("core.llm_local.OllamaClient.available", return_value=(True, "model available")):
        status = local_llm_status(args)
    check(status["ready"] is True, "mock model readiness failed")
    check(status["endpoint"].startswith("http://127.0.0.1"), "non-loopback status endpoint")
    check(status["hardware"]["recommended_model_size"] == "4B", "hardware sizing changed")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="tbhm-v391-") as td:
        tmp = Path(td)
        test_registry_and_cli()
        test_evidence_sanitization(tmp)
        test_synthetic_scenario_and_classification()
        test_llm_status_contract()
    print("v3.9.1 integrated LLM/evidence-safe tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
