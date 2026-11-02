"""Finding verification coordinator.

The legacy implementation replayed URLs and logged status/length changes.  That
proved only reachability.  This phase now records a verification test for every
high-value record and delegates actual confirmation to
``strict_finding_validation`` when a structured assertion/proof bundle exists.
"""
from __future__ import annotations


def run(ctx):
    findings = ctx.storage.all_findings()
    if not findings:
        return
    queued = structured = manual = 0
    for finding in findings[:5000]:
        if str(finding.get("severity") or "").upper() not in {"CRITICAL", "HIGH", "MEDIUM"}:
            continue
        queued += 1
        assertion = finding.get("assertion")
        proof = finding.get("proof")
        tx = ctx.storage.start_test_execution(
            test_id=f"verify-{finding.get('id')}", phase="verify",
            target=str(finding.get("url") or finding.get("target") or ""),
            operation="verification triage",
            assertion=assertion if isinstance(assertion, dict) else {},
            extra={"finding_id": finding.get("id"), "finding_class": finding.get("finding_class")},
        )
        if isinstance(assertion, dict) and isinstance(proof, dict):
            structured += 1
            ctx.storage.complete_test_execution(
                tx, status="manual-review-required",
                result_summary="Structured proof queued for strict_finding_validation.")
        else:
            manual += 1
            ctx.storage.complete_test_execution(
                tx, status="manual-review-required",
                result_summary="No versioned assertion/proof bundle. URL liveness or response status is not vulnerability proof.")

    # Hunter memory remains advisory only and never changes classification.
    predictions = 0
    for finding in findings:
        pattern = f"{finding.get('phase','')}:{finding.get('cwe','')}"
        prediction = ctx.storage.predict_decision(pattern)
        if prediction:
            predictions += 1
            decision, confidence = prediction
            ctx.log("INFO", "verify",
                    f"finding #{finding['id']} advisory prediction: {decision} ({confidence*100:.0f}%)")

    # Opt-in legacy compatibility: the pre-v4 generic shadow-replay reachability
    # check. Off by default; enabling it never confirms a finding on its own —
    # results are recorded as advisory persistence evidence only, so the strict
    # v4 lifecycle stays authoritative.
    replayed = 0
    if bool(getattr(ctx.args, "legacy_shadow_replay", False)):
        try:
            from core.verifier import shadow_replay
        except Exception:
            shadow_replay = None
        if shadow_replay is not None:
            for finding in findings[:500]:
                if str(finding.get("severity") or "").upper() not in {"CRITICAL", "HIGH"}:
                    continue
                url = str(finding.get("url") or finding.get("target") or "").strip()
                if not url.startswith("http"):
                    continue
                try:
                    result = shadow_replay(url, method=str(finding.get("method") or "GET"),
                                           payload=str(finding.get("payload") or ""),
                                           parameter=str(finding.get("parameter") or ""))
                except Exception as exc:  # noqa: BLE001
                    result = {"persistent": None, "error": str(exc)[:200]}
                replayed += 1
                tx = ctx.storage.start_test_execution(
                    test_id=f"shadow-replay-{finding.get('id')}", phase="verify",
                    target=url, operation="legacy shadow replay (advisory)",
                    assertion={}, extra={"finding_id": finding.get("id"), "legacy": True})
                ctx.storage.complete_test_execution(
                    tx, status="manual-review-required",
                    result_summary=f"Legacy shadow-replay persistence={result.get('persistent')}; advisory only, not confirmation.")
            ctx.log("INFO", "verify", f"legacy shadow-replay executed on {replayed} finding(s) (advisory)")

    ctx.log("OK", "verify",
            f"queued={queued} structured={structured} manual={manual} predictions={predictions}")
