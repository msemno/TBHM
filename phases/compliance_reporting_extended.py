"""Evidence-predicate compliance reporting with v3.9.6 output aliases."""
from __future__ import annotations

import csv
import json
from core import redteam_utils as RT
from core.compliance_catalog import load
from core.compliance_predicates import evaluate_catalog


def run(ctx):
    out = RT.evidence_dir(ctx, "104_compliance_reporting_extended")
    try:
        findings = ctx.storage.all_findings()
    except Exception:
        findings = []
    catalog = load(getattr(ctx.args, "compliance_catalog", None))

    def done(name):
        try:
            return ctx.storage.is_phase_done(name)
        except Exception:
            return False

    report = evaluate_catalog(catalog, findings, done)
    report["profile"] = (ctx.profile or {}).get("name")
    report["framework_filter"] = str(getattr(ctx.args, "compliance_frameworks", "") or "")
    wanted = {item.strip().lower() for item in report["framework_filter"].split(",") if item.strip()}
    if wanted:
        report["frameworks"] = [framework for framework in report["frameworks"] if str(framework.get("id")).lower() in wanted]

    (out / "compliance_framework_matrix.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    rows = [{"framework": framework["id"], "version": framework.get("version"), **control} for framework in report["frameworks"] for control in framework["controls"]]
    fields = [
        "framework", "version",
        # Historical columns retained first for existing spreadsheets/scripts.
        "id", "title", "legacy_status", "finding_refs", "phases", "evidence_required", "notes",
        # Authoritative v3.9.7+ predicate fields.
        "control_identifier", "predicate", "status", "confidence", "reason", "evidence_references",
        "remediation", "evaluator_version", "timestamp",
    ]
    with (out / "compliance_framework_matrix.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            copy = dict(row)
            for key in ("finding_refs", "evidence_references", "phases", "evidence_required"):
                copy[key] = ";".join(map(str, copy.get(key, [])))
            writer.writerow(copy)

    summary = {}
    legacy_summary = {}
    for framework in report["frameworks"]:
        counts = {}
        legacy_counts = {}
        for control in framework["controls"]:
            counts[control["status"]] = counts.get(control["status"], 0) + 1
            legacy = control["legacy_status"]
            legacy_counts[legacy] = legacy_counts.get(legacy, 0) + 1
        summary[framework["id"]] = counts
        legacy_summary[framework["id"]] = legacy_counts
    # Preserve the v3.9.7.1 authoritative summary path/shape and emit the
    # historical labels separately so neither consumer contract is ambiguous.
    (out / "compliance_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out / "compliance_legacy_summary.json").write_text(json.dumps(legacy_summary, indent=2), encoding="utf-8")
    RT.write_md(out / "COMPLIANCE_REPORTING_EXTENDED.md", "Control-Level Compliance Predicates", [
        ("Authoritative summary", json.dumps(summary, indent=2)),
        ("Legacy compatibility summary", json.dumps(legacy_summary, indent=2)),
        ("Important limitation", str(report.get("statement") or "Evidence mapping is not a certification opinion.")),
        ("Correctness rule", "A scanner or phase running is never enough to mark a control passed. Historical aliases remain for parsers, but the modern status is authoritative."),
    ])
    ctx.phase_state["compliance_extended"] = summary
    ctx.log("OK", "compliance_reporting_extended", f"evaluated {len(rows)} control record(s)")
