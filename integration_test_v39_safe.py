#!/usr/bin/env python3
"""Local structural/integration checks for the additive v3.9-safe update."""
from __future__ import annotations

import ast
import json
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.finding_class import apply as classify_apply
from core.hardware_profile import detect as detect_hardware
from core.llm_local import LocalLLMConfig, OllamaClient, is_loopback_url, redact_text
from core.scope import Scope
from phases.local_llm_triage import _defensive_text
from core.scanner_normalizer import parse_file
from core.storage import Storage


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


def test_phase_registry_and_cli() -> None:
    phases = phase_order()
    check(len(phases) == len(set(phases)), "duplicate phase names")
    check(phases.index("ad_access_assessment") > phases.index("internal_ad_tooling"), "AD phase order")
    check(phases.index("source_orchestration_tooling") > phases.index("code_security_tooling"), "source orchestrator order")
    check(phases.index("local_llm_triage") > phases.index("verify"), "LLM triage must follow verification")

    prohibited = {
        "ad_poison_listen", "ad_harvest_tickets", "ad_crack_hashes",
        "ad_pth_movement", "ad_dcsync_exfil", "offensive_engagement",
    }
    check(not prohibited.intersection(phases), "prohibited offensive phase registered")

    import tbhm
    old = sys.argv[:]
    try:
        sys.argv = [
            "tbhm", "-d", "example.local", "-y", "--ad-access",
            "--source-orchestration", "--local-llm",
        ]
        args = tbhm.parse_args()
    finally:
        sys.argv = old
    check(args.ad_access and args.source_orchestration and args.local_llm, "new CLI flags not parsed")
    check(args.local_llm_url.startswith("http://127.0.0.1"), "local LLM default is not loopback")
    check(not hasattr(args, "offensive_engagement"), "unsafe override flag exposed")


def test_redaction_and_loopback() -> None:
    raw = (
        "Authorization: Bearer super-secret-token\n"
        "password=hunter2 API_KEY=sk-abcdefghijklmnopqrstuv "
        "eyJabcdefgh.abcdefgh.abcdefgh"
    )
    redacted = redact_text(raw)
    check("hunter2" not in redacted, "password was not redacted")
    check("super-secret-token" not in redacted, "authorization token was not redacted")
    check("sk-abcdefghijklmnopqrstuv" not in redacted, "API key was not redacted")
    check(is_loopback_url("http://127.0.0.1:11434"), "IPv4 loopback rejected")
    check(is_loopback_url("http://[::1]:11434"), "IPv6 loopback rejected")
    check(not is_loopback_url("http://192.168.1.50:11434"), "remote endpoint accepted as loopback")
    blocked = _defensive_text("Run mimikatz then secretsdump", 500)
    check(blocked.startswith("[WITHHELD:"), "operational model guidance was not filtered")


def test_local_llm_client_contract() -> None:
    class Response:
        def __init__(self, payload, status_code=200):
            self.payload = payload
            self.status_code = status_code
        def raise_for_status(self):
            return None
        def json(self):
            return self.payload

    client = OllamaClient(LocalLLMConfig(model="qwen3-cybersec:4b"))
    with patch.object(client.session, "get", return_value=Response({"models": [{"name": "qwen3-cybersec:4b"}]})):
        ready, _ = client.available()
        check(ready, "mock local model was not detected")
    check(client.session.trust_env is False, "proxy environment inheritance was not disabled")
    try:
        OllamaClient(LocalLLMConfig(endpoint="http://192.168.1.50:11434"))
    except ValueError:
        pass
    else:
        raise AssertionError("remote local-LLM endpoint was accepted")

    captured = {}
    def fake_post(url, json=None, timeout=None, allow_redirects=None):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        captured["allow_redirects"] = allow_redirects
        return Response({"message": {"content": '{"items": []}'}})

    with patch.object(client.session, "post", side_effect=fake_post):
        result = client.chat_json("defensive analyst", "[]")
    check(result == {"items": []}, "local LLM JSON response parsing failed")
    check("tools" not in captured["json"], "tool calling was exposed to the local model")
    check(captured["json"].get("format") == "json", "strict JSON mode missing")
    check(captured["url"].endswith("/api/chat"), "unexpected local LLM API path")
    check(captured["allow_redirects"] is False, "local LLM redirects were not disabled")


def test_scanner_normalizer_and_lead_classification(tmp: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "sample", "rules": [{
                "id": "PY001",
                "shortDescription": {"text": "Unsafe call"},
                "properties": {"tags": ["CWE-78"]},
            }]}},
            "results": [{
                "ruleId": "PY001",
                "level": "error",
                "message": {"text": "Potential command execution sink"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 10},
                }}],
            }],
        }],
    }
    path = tmp / "sample.sarif"
    path.write_text(json.dumps(sarif))
    items = parse_file(path, "sample")
    check(items and items[0]["cwe"] == "CWE-78", "SARIF CWE extraction failed")
    finding = {
        "phase": "code_security_tooling", "severity": "HIGH",
        "confidence": "HIGH", "title": "Unsafe call", "evidence": "scanner output",
    }
    classify_apply(finding)
    check(finding["finding_class"] == "lead", "imported scanner observation promoted")
    check(finding["title"].startswith("[LEAD]"), "lead label missing")
    scanner_claim = {
        "phase": "code_security_tooling", "severity": "HIGH", "confidence": "HIGH",
        "title": "Scanner result", "evidence": "scanner says confirmed vulnerability",
    }
    classify_apply(scanner_claim)
    check(scanner_claim["finding_class"] == "lead", "scanner prose promoted an imported observation")


def test_storage_enrichment(tmp: Path) -> None:
    store = Storage(tmp / "test.db")
    fid = store.save_finding({
        "phase": "code_security_tooling", "severity": "MEDIUM", "confidence": "LOW",
        "title": "[LEAD] Example", "target": "app.py", "description": "candidate",
        "evidence": "line 10", "impact": "unknown", "remediation": "review",
        "cwe": "", "cvss": "", "discovered_at": "2026-07-16T00:00:00",
        "finding_class": "lead", "scanner_source": "sample",
    })
    check(fid > 0, "finding save failed")
    check(store.enrich_finding(fid, {"local_llm": {"assessment": "needs-review"}}, cwe="CWE-78", cvss="7.2"), "enrichment failed")
    row = store.all_findings()[0]
    check(row["finding_class"] == "lead", "enrichment changed classification")
    check(row["cwe"] == "CWE-78" and row["cvss"] == "7.2", "empty metadata was not filled")
    check(row.get("scanner_source") == "sample", "scanner metadata not preserved")
    check((row.get("enrichment") or {}).get("local_llm", {}).get("assessment") == "needs-review", "enrichment payload missing")


def test_ad_password_handling_and_hardware() -> None:
    source = (ROOT / "phases" / "ad_identity_safe.py").read_text()
    check('"-w", pw' not in source, "LDAP password still passed on command line")
    check('"-y", password_file' in source, "protected ldapsearch password file not used")
    hardware = detect_hardware()
    for key in ("ram_gb", "nvidia_gpus", "recommended_model_size", "recommended_quantization", "recommended_context"):
        check(key in hardware, f"hardware profile missing {key}")
    check(hardware["recommended_model_size"] == "4B", "unexpected default local model size")



def test_ad_scope_filter(tmp: Path) -> None:
    from argparse import Namespace
    from phases import ad_access_assessment

    class Runner:
        @staticmethod
        def has(_name):
            return False

    class Ctx:
        output = tmp / "ad-scope"
        args = Namespace(
            ad_access=True, ad_access_results=None, ad_access_max_dcs=5,
            dc_ip="10.10.10.10,192.168.50.10", dc_ips_file=None,
            corp_cidr="10.0.0.0/8", corp_cidrs_file=None,
            ad_domain="corp.local", ad_base_dn=None, ad_user=None,
            ad_password_env="TBHM_AD_PASSWORD", ad_ldaps=False,
            ad_ldap_ca_file=None,
        )
        targets = []
        scope = Scope([], [])
        runner = Runner()

        @staticmethod
        def log(*_args, **_kwargs):
            return None

        @staticmethod
        def save_finding(_finding):
            return 1

    Ctx.output.mkdir(parents=True, exist_ok=True)
    ad_access_assessment.run(Ctx())
    summary = json.loads((Ctx.output / "redteam/29_ad_access_assessment/ad_access_assessment.json").read_text())
    check(summary["domain_controllers"] == ["10.10.10.10"], "approved DC was not retained")
    check(summary["dropped_out_of_scope_domain_controllers"] == ["192.168.50.10"], "out-of-CIDR DC was not dropped")


def test_bloodhound_zip_path(tmp: Path) -> None:
    from argparse import Namespace
    from phases import lateral_movement_paths

    bh = tmp / "bh"
    bh.mkdir()
    (bh / "groups.json").write_text(json.dumps({
        "data": [{
            "ObjectIdentifier": "S-1-5-21-DA",
            "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "highvalue": True},
            "Aces": [{"PrincipalSID": "S-1-5-21-U1", "RightName": "GenericAll", "IsInherited": False}],
            "Members": [],
        }],
        "meta": {"type": "groups", "count": 1, "version": 5},
    }))
    (bh / "users.json").write_text(json.dumps({
        "data": [{
            "ObjectIdentifier": "S-1-5-21-U1",
            "Properties": {"name": "JSMITH@CORP.LOCAL", "highvalue": False},
            "Aces": [],
        }],
        "meta": {"type": "users", "count": 1, "version": 5},
    }))
    archive = tmp / "bloodhound.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(bh / "groups.json", "groups.json")
        zf.write(bh / "users.json", "users.json")

    class Ctx:
        output = tmp / "bh-out"
        args = Namespace(ad_graph=None, ad_access_results=str(archive))
        findings = []

        @classmethod
        def save_finding(cls, finding):
            cls.findings.append(finding)
            return len(cls.findings)

        @staticmethod
        def log(*_args, **_kwargs):
            return None

    Ctx.output.mkdir(parents=True, exist_ok=True)
    lateral_movement_paths.run(Ctx())
    paths = json.loads((Ctx.output / "lateral_movement/attack_paths.json").read_text())
    check(paths and paths[0]["from"] == "JSMITH@CORP.LOCAL", "BloodHound path source not resolved")
    check(paths[0]["to"] == "DOMAIN ADMINS@CORP.LOCAL", "BloodHound high-value target not resolved")
    check(Ctx.findings and Ctx.findings[0]["finding_class"] == "lead", "BloodHound path was not saved as a lead")

def main() -> int:
    with tempfile.TemporaryDirectory(prefix="tbhm-v39-test-") as td:
        tmp = Path(td)
        test_phase_registry_and_cli()
        test_redaction_and_loopback()
        test_local_llm_client_contract()
        test_scanner_normalizer_and_lead_classification(tmp)
        test_storage_enrichment(tmp)
        test_ad_password_handling_and_hardware()
        test_ad_scope_filter(tmp)
        test_bloodhound_zip_path(tmp)
    print("v3.9-safe integration tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
