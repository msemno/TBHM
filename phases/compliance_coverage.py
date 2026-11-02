"""
Phase: compliance_coverage   (v3.2)

Read-only post-processing. Maps this run's findings and the phases that actually
ran onto compliance frameworks, and flags coverage gaps:

  * OWASP Top 10 (2021) category counts
  * CWE histogram
  * PCI-DSS v4.0 requirement touch-points
  * gap detection: OWASP categories with no covering phase executed

Outputs compliance_coverage.json and compliance_coverage.html.
"""
from __future__ import annotations

import json
from collections import Counter

from core import attack_knowledge as AK


def run(ctx):
    try:
        findings = ctx.storage.all_findings()
    except Exception as e:
        ctx.log("WARN", "compliance_coverage", f"could not load findings: {e}")
        findings = []

    out_dir = ctx.output / "compliance"
    out_dir.mkdir(exist_ok=True)

    owasp_counts = Counter()
    cwe_counts = Counter()
    for f in findings:
        cat = AK.owasp_for(f)
        owasp_counts[cat] += 1
        cwe = (f.get("cwe") or "").upper().strip()
        if cwe:
            cwe_counts[cwe] += 1

    # which phases ran this session
    ran = set()
    for ph in AK.PHASE_OWASP_COVERAGE:
        try:
            if ctx.storage.is_phase_done(ph):
                ran.add(ph)
        except Exception:
            pass

    covered_cats = set()
    for ph in ran:
        covered_cats.update(AK.PHASE_OWASP_COVERAGE.get(ph, []))

    matrix = []
    for cat in AK.OWASP_TOP10_2021:
        found = owasp_counts.get(cat, 0)
        capable = any(cat in cats for cats in AK.PHASE_OWASP_COVERAGE.values())
        tested = cat in covered_cats
        status = ("findings" if found else
                  ("phase-ran-without-test-evidence" if tested else
                   ("no-coverage" if capable else "manual-only")))
        matrix.append({
            "owasp": cat, "findings": found, "tested": False, "phase_completed": tested,
            "pci": AK.OWASP_TO_PCI.get(cat, ""), "status": status,
        })

    gaps = [m["owasp"] for m in matrix if m["status"] == "no-coverage"]

    # Machine-readable standards mapping relies on actual test executions.
    # Completed phase markers must never be promoted to tested coverage.
    from core.compliance_catalog import test_id_coverage
    try:
        executions = ctx.storage.all_test_executions()
    except Exception:
        executions = []
    standards_report = test_id_coverage(executions)
    (out_dir / 'test_id_coverage.json').write_text(json.dumps(standards_report, indent=2))
    for item in matrix:
        if item['status'] == 'tested-clean':
            item['status'] = 'phase-ran-without-test-evidence'
            item['tested'] = False

    report = {
        'standards_execution': standards_report['counts'],
        'coverage_warning': 'Phase completed is not evidence of executing a relevant test; category status is not certification.',
        "owasp_matrix": matrix,
        "cwe_histogram": dict(cwe_counts.most_common()),
        "gaps": gaps,
        "totals": {"findings": len(findings),
                   "mapped": sum(owasp_counts.values()) - owasp_counts.get("Unmapped", 0),
                   "unmapped": owasp_counts.get("Unmapped", 0)},
    }
    (out_dir / "compliance_coverage.json").write_text(json.dumps(report, indent=2))

    # HTML
    def _row(m):
        color = {"findings": "#ffdddd", "phase-ran-without-test-evidence": "#fff3cd",
                 "no-coverage": "#fff3cd", "manual-only": "#eeeeee"}.get(m["status"], "#fff")
        return (f"<tr style='background:{color}'><td>{m['owasp']}</td>"
                f"<td>{m['findings']}</td><td>{'yes' if m['tested'] else 'no'}</td>"
                f"<td>{m['status']}</td><td>{m['pci']}</td></tr>")
    cwe_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>"
                       for k, v in cwe_counts.most_common())
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>TBHM — Compliance Coverage</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:2rem}}
table{{border-collapse:collapse;width:100%;margin:.5rem 0 2rem}}
th,td{{border:1px solid #ddd;padding:.45rem .6rem;text-align:left;font-size:13px}}
th{{background:#f0f0f0}}</style></head><body>
<h1>Compliance coverage</h1>
<p>{len(findings)} findings | {len(gaps)} OWASP gap(s) with capable-but-unrun coverage.</p>
<h2>OWASP Top 10 (2021) &rarr; PCI-DSS</h2>
<table><tr><th>OWASP category</th><th>Findings</th><th>Phase ran</th><th>Status</th><th>PCI-DSS</th></tr>
{''.join(_row(m) for m in matrix)}</table>
<h2>CWE histogram</h2>
<table><tr><th>CWE</th><th>Count</th></tr>{cwe_rows or '<tr><td colspan=2>none</td></tr>'}</table>
</body></html>"""
    (out_dir / "compliance_coverage.html").write_text(html)

    if gaps:
        ctx.save_finding({
            "phase": "compliance_coverage", "severity": "INFO", "confidence": "HIGH",
            "title": f"Coverage gap: {len(gaps)} OWASP category(ies) not exercised",
            "target": ctx.targets[0] if ctx.targets else "",
            "description": "These OWASP Top 10 categories have capable TBHM phases that did "
                           "not run this session: " + ", ".join(gaps),
            "evidence": "; ".join(gaps),
            "impact": "Assessment coverage is incomplete for these categories.",
            "remediation": "Re-run with the relevant phases enabled or note as out-of-scope in the SoW.",
            "mrs_score": 20,
        })

    ctx.log("OK", "compliance_coverage",
            f"OWASP mapped {report['totals']['mapped']}/{len(findings)} | "
            f"{len(cwe_counts)} distinct CWEs | {len(gaps)} coverage gap(s) → compliance_coverage.html")
