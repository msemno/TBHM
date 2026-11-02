"""Authorized exercise evidence review and instructor simulation phase.

The phase imports and sanitizes evidence produced outside TBHM or generates a
fully synthetic teaching scenario. It never launches credential capture, hash
cracking, Kerberos extraction, pass-the-hash, remote execution, DCSync,
Metasploit, shells, persistence, or defense-evasion actions.
"""
from __future__ import annotations

import json
from pathlib import Path

from core import redteam_utils as RT
from core.engagement_evidence import analyze_path, synthetic_scenario


def _save_observation(ctx, observation: dict, mode: str) -> None:
    simulation = bool(observation.get("simulation"))
    excerpts = observation.get("excerpts") or []
    sources = observation.get("sources") or []
    evidence = {
        "mode": mode,
        "category": observation.get("name"),
        "mitre_attack": observation.get("technique"),
        "match_count": observation.get("match_count", 0),
        "sources": sources[:20],
        "sanitized_excerpts": excerpts[:3],
        "operational_details_redacted": True,
    }
    ctx.save_finding({
        "phase": "engagement_evidence_review",
        "severity": "INFO" if simulation else observation.get("severity", "MEDIUM"),
        "confidence": "LOW" if simulation else "MEDIUM",
        "title": observation.get("title", "Authorized exercise evidence observation"),
        "target": "synthetic instructor scenario" if simulation else "imported authorized exercise evidence",
        "description": (
            "Synthetic instructor-only exercise card; no live action occurred."
            if simulation else
            "TBHM imported sanitized evidence produced by a separately governed authorized exercise. "
            "TBHM did not execute the activity and therefore records it as an unconfirmed lead."
        ),
        "evidence": json.dumps(evidence, ensure_ascii=False, indent=2),
        "impact": (
            "Training-only illustration of the control objective."
            if simulation else
            "The imported evidence may demonstrate a material compromise path and should be validated against source telemetry, scope, timing, and affected assets."
        ),
        "remediation": observation.get("remediation", "Review the enabling control weakness and validate corrective actions."),
        "cwe": observation.get("cwe", ""),
        "mrs_score": 10 if simulation else (90 if observation.get("severity") == "CRITICAL" else 70),
        "finding_class": "lead",
        "status": "lead",
        "validation_required": (
            "No validation is required for synthetic exercise cards."
            if simulation else
            "Confirm evidence provenance, rules-of-engagement coverage, timestamps, identity/asset attribution, and independent endpoint or directory telemetry."
        ),
        "mitre_attack": observation.get("technique", ""),
        "evidence_import_only": True,
        "simulation": simulation,
    })


def run(ctx):
    if getattr(ctx.args, 'delivery_audit_input', None):
        from core.delivery_privacy_audit import run as audit_delivery
        audit_delivery(ctx)
    evidence_path = getattr(ctx.args, "engagement_evidence", None)
    simulate = bool(getattr(ctx.args, "exercise_simulation", False))
    if not evidence_path and not simulate:
        return

    out = RT.evidence_dir(ctx, "30_engagement_evidence_review")
    reports = []
    if evidence_path:
        try:
            reports.append(analyze_path(
                evidence_path,
                forced_type=getattr(ctx.args, "engagement_evidence_type", "auto") or "auto",
                max_files=int(getattr(ctx.args, "engagement_evidence_max_files", 200) or 200),
                max_total_mb=int(getattr(ctx.args, "engagement_evidence_max_mb", 100) or 100),
            ))
        except Exception as exc:
            ctx.log("ERR", "engagement_evidence_review", f"evidence import failed: {exc}")
            reports.append({
                "mode": "authorized-evidence-import",
                "source_path": str(evidence_path),
                "files_processed": 0,
                "observations": [],
                "error": str(exc),
            })

    if simulate:
        reports.append(synthetic_scenario(getattr(ctx.args, "exercise_scenario", "ad-domain-compromise")))

    observation_count = 0
    for report in reports:
        for observation in report.get("observations", []):
            _save_observation(ctx, observation, report.get("mode", "unknown"))
            observation_count += 1

    payload = {
        "reports": reports,
        "observations_recorded": observation_count,
        "boundary": (
            "Evidence normalization and synthetic instruction only. TBHM did not execute credential capture, "
            "credential recovery, ticket extraction, pass-the-hash, remote command execution, directory-secret "
            "extraction, Metasploit sessions, shells, persistence, or defense evasion."
        ),
    }
    (out / "engagement_evidence_review.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    RT.write_md(out / "ENGAGEMENT_EVIDENCE_REVIEW.md", "Authorized Exercise Evidence Review", [
        ("Modes", ", ".join(r.get("mode", "unknown") for r in reports)),
        ("Observations recorded", str(observation_count)),
        ("Evidence handling", "Secrets, hashes, and operational command lines are redacted; file SHA-256 provenance is retained."),
        ("Execution boundary", payload["boundary"]),
        ("JSON evidence", str(out / "engagement_evidence_review.json")),
    ])
    ctx.log("OK", "engagement_evidence_review", f"{observation_count} sanitized evidence observation(s) recorded")
