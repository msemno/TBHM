"""Policy-driven compliance catalog loader for TBHM v3.9.6."""
from __future__ import annotations

import json
from pathlib import Path
try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "knowledge" / "compliance_frameworks_v396.json"


def load(path: str | Path | None = None) -> dict:
    p = Path(path) if path else DEFAULT
    text = p.read_text(encoding="utf-8", errors="ignore")
    if p.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        if yaml is None:
            raise ValueError("PyYAML is required for YAML compliance catalogs")
        data = yaml.safe_load(text)
    if not isinstance(data, dict) or not isinstance(data.get("frameworks"), list):
        raise ValueError("compliance catalog must contain a frameworks list")
    return data


def finding_tags(finding: dict) -> set[str]:
    values = [
        str(finding.get("phase") or ""), str(finding.get("cwe") or ""),
        str(finding.get("title") or ""), str(finding.get("description") or ""),
    ]
    text = " ".join(values).lower()
    tags = {str(finding.get("phase") or "").lower(), str(finding.get("cwe") or "").lower()}
    keyword_map = {
        "access-control": ("idor", "authorization", "access control", "privilege"),
        "authentication": ("authentication", "password", "mfa", "session", "oauth", "saml"),
        "logging-monitoring": ("logging", "monitoring", "telemetry", "audit log"),
        "vulnerability-management": ("cve-", "vulnerable component", "dependency"),
        "data-protection": ("pii", "secret", "credential", "encryption", "privacy"),
        "network-security": ("firewall", "network", "port", "tls", "dns"),
        "secure-development": ("source", "sast", "ci/cd", "supply chain", "code"),
        "incident-response": ("incident", "detection", "response", "purple team"),
        "cloud-security": ("cloud", "aws", "azure", "gcp", "kubernetes"),
    }
    for tag, words in keyword_map.items():
        if any(word in text for word in words):
            tags.add(tag)
    return {x for x in tags if x}


def map_findings(catalog: dict, findings: list[dict], phase_done) -> dict:
    output = {"frameworks": []}
    for framework in catalog.get("frameworks", []):
        controls = []
        for control in framework.get("controls", []):
            wanted = {str(x).lower() for x in control.get("tags", [])}
            matched = []
            for finding in findings:
                if wanted & finding_tags(finding):
                    matched.append(finding.get("id") or finding.get("title"))
            phases = [str(x) for x in control.get("phases", [])]
            tested = any(phase_done(x) for x in phases) if phases else False
            status = "findings" if matched else ("phase-completed-not-validated" if tested else ("manual" if control.get("manual") else "not-tested"))
            controls.append({
                "id": control.get("id"), "title": control.get("title"),
                "status": status, "finding_refs": matched[:100],
                "phases": phases, "evidence_required": control.get("evidence_required", []),
                "notes": control.get("notes", ""),
            })
        output["frameworks"].append({
            "id": framework.get("id"), "name": framework.get("name"),
            "version": framework.get("version"), "scope_note": framework.get("scope_note"),
            "controls": controls,
        })
    return output


# v4.2.1 incremental test-ID accounting; legacy load/tags/mapping retained.
# Deliberately narrow, source-checked mappings to requirements/test identifiers.
# ASVS 5.0 re-numbered authorization from V4 to V8.
CATALOG = (
    {'id': 'WSTG-ATHZ-04', 'framework': 'OWASP WSTG stable', 'name': 'Insecure Direct Object References', 'class': 'access_control',
     'source': 'https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References'},
    {'id': 'API1:2023', 'framework': 'OWASP API Security Top 10 2023', 'name': 'Broken Object Level Authorization', 'class': 'access_control',
     'source': 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'},
    {'id': 'V8.2.2', 'framework': 'OWASP ASVS 5.0', 'name': 'Data-specific authorization', 'class': 'access_control',
     'source': 'https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md'},
    {'id': 'WSTG-INPV-01', 'framework': 'OWASP WSTG stable', 'name': 'Reflected Cross-Site Scripting', 'class': 'reflected_xss',
     'source': 'https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting'},
    {'id': 'WSTG-INPV-05', 'framework': 'OWASP WSTG stable', 'name': 'SQL Injection', 'class': 'sqli',
     'source': 'https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection'},
)

COMPLETE = {'passed', 'failed-security-control'}
INCOMPLETE = {'inconclusive', 'blocked', 'not-authorized', 'not-applicable', 'tool-error', 'manual-review-required'}


def _class_from_test(row):
    if row.get('phase') != 'strict_finding_validation':
        return None
    assertion = row.get('assertion_json') or row.get('assertion') or {}
    if isinstance(assertion, str):
        try: assertion = json.loads(assertion)
        except (ValueError, TypeError): return None
    if not isinstance(assertion, dict) or assertion.get('schema') != 'tbhm.proof/2':
        return None
    return assertion.get('vulnerability_class')


def test_id_coverage(tests):
    """A test without trustworthy class and terminal state is never coverage."""
    records = []
    for item in CATALOG:
        matched = [t for t in tests if _class_from_test(t) == item['class']]
        completed = [t for t in matched if t.get('status') in COMPLETE]
        partial = [t for t in matched if t.get('status') in INCOMPLETE]
        state = 'executed' if completed else ('inconclusive' if partial else 'not_tested')
        records.append({**item, 'status': state,
                        'completed_test_count': len(completed),
                        'inconclusive_test_count': len(partial),
                        'test_execution_ids': [t.get('id') for t in completed],
                        'not_a_claim_of_full_requirement_verification': True})
    return {'schema': 'tbhm.standards-execution/1',
            'catalog_is_partial': True,
            'records': records,
            'counts': {k: sum(r['status'] == k for r in records)
                       for k in ('executed', 'inconclusive', 'not_tested')},
            'meaning': ('Counts indicate that matching strict test class was executed, not that every '
                        'sub-requirement was exercised or any framework was certified. '
                        'Missing tests mean not tested, not clean. No MASVS/MASTG coverage asserted.')}
