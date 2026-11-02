"""
Phase: evidence_finalize   (v3.2)

End-of-run finalizer that produces engagement/delivery artefacts:

  --evidence-manifest : SHA256 manifest of every output file + redaction scan
                        (greps the deliverable for secrets that shouldn't ship).
  --roe-ticket ID     : writes an ROE stamp and records the ticket in run
                        metadata + the manifest header for legal defensibility.
  --ci                : emits ci_summary.json and junit.xml (severity-graded
                        test cases) so the run can gate a pipeline.

Runs after report so it can hash the finished deliverable. All read-only.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from core import evidence_manifest as EM


def _junit(output_dir: Path, counts: dict, findings: list):
    fails = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    total = sum(counts.values())
    cases = []
    for f in findings:
        sev = f.get("severity", "INFO")
        name = f.get("title", "finding").replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
        cls = f.get("phase", "tbhm")
        if sev in ("CRITICAL", "HIGH"):
            cases.append(f'    <testcase classname="{cls}" name="{name}">\n'
                         f'      <failure type="{sev}">{sev}: {name}</failure>\n'
                         f'    </testcase>')
        else:
            cases.append(f'    <testcase classname="{cls}" name="{name}"/>')
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           f'<testsuites tests="{total}" failures="{fails}">\n'
           f'  <testsuite name="TBHM" tests="{total}" failures="{fails}">\n'
           + "\n".join(cases) + "\n  </testsuite>\n</testsuites>\n")
    (output_dir / "junit.xml").write_text(xml)


def run(ctx):
    # Destroy the run-scoped secret key so any sealed secret-candidate vault
    # becomes unrecoverable once the run is finalized.
    try:
        from core import secret_vault
        secret_vault.shred(ctx)
    except Exception:
        pass
    want_manifest = bool(getattr(ctx.args, "evidence_manifest", False))
    roe = (getattr(ctx.args, "roe_ticket", None) or "").strip()
    want_ci = bool(getattr(ctx.args, "ci", False))
    if not (want_manifest or roe or want_ci):
        return

    out = ctx.output

    if roe:
        (out / "ROE_STAMP.txt").write_text(
            f"ROE / authorization ticket: {roe}\n"
            f"Run profile: {ctx.profile.get('name')}\n"
            f"Targets: {', '.join(ctx.targets)}\n"
            f"Stamped: {datetime.utcnow().isoformat()}Z\n")
        ctx.log("OK", "evidence_finalize", f"ROE ticket {roe} stamped")

    # The orchestrator seals the snapshot after this phase, the observer,
    # execution accounting and completion metadata have all finished writing.
    if want_ci:
        from core.finding_class import classify
        findings = [f for f in ctx.storage.all_findings() if classify(f) == "confirmed"]
        counts = dict(Counter(str(f.get("severity", "INFO")).upper() for f in findings))
        summary = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "profile": ctx.profile.get("name"),
            "targets": ctx.targets,
            "severity_counts": counts,
            "gate_fail": (counts.get("CRITICAL", 0) + counts.get("HIGH", 0)) > 0,
            "roe_ticket": roe,
        }
        (out / "ci_summary.json").write_text(json.dumps(summary, indent=2))
        _junit(out, counts, findings)
        # signal to main() for exit-code gating
        ctx.phase_state["ci_gate_fail"] = summary["gate_fail"]
        ctx.log("OK", "evidence_finalize",
                f"CI output: ci_summary.json + junit.xml (gate_fail={summary['gate_fail']})")


def _incomplete_gate(ctx, failed_phases):
    """NEW independent CI artifacts; existing severity-summary keys are retained.

    Detects orchestrator-visible failures and missing mandatory report outputs.
    Silent tool skips and per-case completeness still require S04 contracts.
    """
    from xml.etree import ElementTree as ET
    missing = [name for name in ("REPORT_final.md", "report.json")
               if not (ctx.output / name).is_file()]
    failures = sorted(set(failed_phases))
    failed = bool(failures or missing)
    (ctx.output / "ci_incomplete_summary.json").write_text(json.dumps({
        "gate_fail": failed, "failed_phases": failures, "missing_outputs": missing,
    }, indent=2))
    suite = ET.Element("testsuite", name="TBHM execution completeness", tests="1",
                       failures="1" if failed else "0")
    case = ET.SubElement(suite, "testcase", classname="execution", name="scan completed")
    if failed:
        ET.SubElement(case, "failure", type="INCOMPLETE").text = (
            f"failed phases: {failures}; missing outputs: {missing}")
    ET.ElementTree(suite).write(ctx.output / "junit_incomplete.xml", encoding="utf-8",
                               xml_declaration=True)
    ctx.phase_state["ci_incomplete_fail"] = failed
    return failed
