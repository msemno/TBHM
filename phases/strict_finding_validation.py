"""Apply structured assertions to candidate findings.

No payload is generated here.  A phase/operator supplies an assertion and proof
bundle; this phase evaluates it, records the validation attempt and promotes a
finding only when the assertion, negative control and repeatability all pass.
"""
from __future__ import annotations

import json
from core.assertion_engine import evaluate, confirmation_fields


def run(ctx):
    findings = ctx.storage.all_findings()
    evaluated = confirmed = inconclusive = failed = 0
    missing = []
    for finding in findings:
        assertion = finding.get("assertion")
        proof = finding.get("proof")
        if not isinstance(assertion, dict) or not isinstance(proof, dict):
            missing.append({'finding_id': finding['id'], 'status': 'MANUAL_REVIEW',
                            'reason': 'missing versioned assertion or captured proof bundle'})
            continue
        evaluated += 1
        test_id = str(assertion.get("test_id") or f"finding-{finding['id']}")
        tx = ctx.storage.start_test_execution(
            test_id=test_id, test_version=str(assertion.get("test_version") or "1"),
            phase="strict_finding_validation", target=str(finding.get("url") or finding.get("target") or ""),
            operation="structured finding verification", assertion=assertion,
            scope_decision=str(finding.get("scope_decision") or ""), policy_id=str(finding.get("policy_id") or ""),
        )
        result = evaluate(assertion, proof, evidence_root=ctx.output)
        attempt_id = ctx.storage.record_validation_attempt(
            verifier="strict_finding_validation:tbhm-assertion-v1", result=result,
            assertion=assertion, proof=proof, finding_id=finding["id"],
            candidate_id=finding.get("candidate_id"), test_execution_id=tx,
            artifact_refs=proof.get("artifact_refs") if isinstance(proof.get("artifact_refs"), list) else [],
        )
        fields = confirmation_fields(result, method="structured assertion + negative control + repeatability",
                                     validation_attempt_id=attempt_id)
        if result["result"] in {"pass", "fail"}:
            ctx.storage.update_finding_verification(finding["id"], fields)
        else:
            ctx.storage.update_finding_verification(finding["id"], {
                "last_validation_result": "inconclusive",
                "last_validation_attempt_id": attempt_id,
                "last_validation_reasons": result.get("reasons", []),
            })
        status = "failed-security-control" if result["result"] == "pass" else (
            "passed" if result["result"] == "fail" else "inconclusive")
        ctx.storage.complete_test_execution(tx, status=status,
                                            result_summary="; ".join(result.get("reasons", []))[:4000])
        if result["result"] == "pass": confirmed += 1
        elif result["result"] == "fail": failed += 1
        else: inconclusive += 1
    payload = {"evaluated": evaluated, "confirmed": confirmed, "control_held": failed,
               "inconclusive": inconclusive,
               "missing_proof": len(missing), "missing_proof_records": missing,
               "coverage_status": "PROOF_EXECUTED" if evaluated else "NO_PROOF_EXECUTED",
               "rule": "No assertion/negative-control/repeatability proof means no confirmation."}
    path = ctx.output / "evidence" / "strict_finding_validation.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))
    ctx.log("OK", "strict_finding_validation", json.dumps(payload))
