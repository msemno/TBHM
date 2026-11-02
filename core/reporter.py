"""TBHM v4.2.1 multi-audience and final technical report renderer.

The primary deliverable is REPORT_final.md / REPORT_final.html. Every strictly
confirmed vulnerability includes a summary, proof of concept, confirmed steps
to reproduce, evidence, security impact, remediation, and retest criteria.
Supported-but-not-fully-verified records and leads are separated explicitly.
"""
from __future__ import annotations

import csv
import hashlib
import html
import json
import re
import shlex
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from core import exploitability
from core.version import VERSION, SEMANTIC_VERSION
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": "#7c1d1d", "HIGH": "#a83232", "MEDIUM": "#c97a18",
    "LOW": "#458a3b", "INFO": "#3b6ea5",
}
SEVERITY_BG = {
    "CRITICAL": "#fff0f0", "HIGH": "#fff5f5", "MEDIUM": "#fffaf0",
    "LOW": "#f3faf3", "INFO": "#f0f5fa",
}


class Reporter:
    def __init__(self, ctx):
        self.ctx = ctx
        self.out = Path(ctx.output)

    @staticmethod
    def _cvss_obj(value):
        if isinstance(value, dict):
            return value
        if value in (None, ""):
            return {}
        try:
            return {"score": float(value), "vector": ""}
        except Exception:
            return {"score": str(value), "vector": ""}

    @staticmethod
    def _assessment(finding: dict) -> dict:
        # Cached enrichment may add context, but cannot authenticate a class.
        computed = exploitability.assess(finding)
        enrichment = finding.get("enrichment") or {}
        cached = enrichment.get("exploitability") if isinstance(enrichment, dict) else None
        if not isinstance(cached, dict):
            cached = finding.get("exploitability")
        if isinstance(cached, dict):
            return {**cached, **{k: computed[k] for k in ("confirmation_status", "exploitability_status") if k in computed}}
        return computed

    @staticmethod
    def _confidence_score(finding: dict, assessment: dict) -> float:
        value = finding.get("confidence")
        if isinstance(value, (int, float)):
            return max(0.0, min(float(value), 1.0))
        text = str(value or "").strip().upper()
        table = {
            "NONE": 0.0, "VERY LOW": 0.15, "LOW": 0.25,
            "MEDIUM": 0.55, "MODERATE": 0.55, "HIGH": 0.82,
            "VERY HIGH": 0.92, "CONFIRMED": 1.0,
        }
        if text in table:
            return table[text]
        strength = str(assessment.get("evidence_strength") or "").strip().lower()
        return {"none": 0.0, "weak": 0.25, "moderate": 0.55,
                "strong": 0.82, "conclusive": 1.0}.get(strength, 0.5)

    @staticmethod
    def _dependency_filter_match(finding: dict):
        enrichment = finding.get("enrichment") or {}
        if not isinstance(enrichment, dict):
            return None
        vi = enrichment.get("vulnerability_intelligence") or {}
        if not isinstance(vi, dict):
            return None
        records = vi.get("records") or []
        values = [r.get("dep_filter_match") for r in records
                  if isinstance(r, dict) and r.get("dep_filter_match") is not None]
        return any(values) if values else None

    def _groups(self, findings):
        confirmed, supported, leads = [], [], []
        threshold = max(0.0, min(float(getattr(self.ctx.args, "confidence_threshold", 0.0) or 0.0), 1.0))
        dep_expr = str(getattr(self.ctx.args, "dep_filter", "") or "").strip()
        for f in findings:
            assessment = self._assessment(f)
            status = assessment.get("confirmation_status", "UNCONFIRMED")
            confidence = self._confidence_score(f, assessment)
            is_dependency = (
                str(f.get("phase") or "") in {"sbom", "code_intel", "code_security_tooling", "source_orchestration_tooling"}
                and any(x in str(f.get("title") or "").lower() for x in ("depend", "component", "package", "cve"))
            )
            dep_match = self._dependency_filter_match(f) if dep_expr and is_dependency else None
            if dep_match is False:
                # A dependency filter is a prioritisation gate, not evidence
                # deletion.  Non-matching records stay in the leads appendix.
                leads.append(f)
            elif status == "CONFIRMED" and confidence >= threshold:
                confirmed.append(f)
            elif status == "CONFIRMED":
                supported.append(f)
            elif status == "SUPPORTED":
                supported.append(f)
            else:
                leads.append(f)
        return confirmed, supported, leads

    def write_all(self):
        findings = self.ctx.storage.all_findings()
        try:
            from core import cwe_cvss
            for f in findings:
                cwe_cvss.enrich(f)
        except Exception:
            pass
        self._write_final_markdown(findings)
        if not getattr(self.ctx.args, "no_html", False):
            self._write_final_html(findings)
        self._write_confirmed(findings)
        self._write_leads(findings)
        self._write_executive(findings)
        self._write_manager(findings)
        self._write_developer(findings)
        self._write_defender(findings)
        self._write_json(findings)
        self._write_sarif(findings)
        self._write_csv(findings)
        self._write_per_finding_kits(findings)
        self._write_methodology_audit(findings)

    # ------------------------------------------------------------------
    # Primary final report
    # ------------------------------------------------------------------
    def _counts(self, findings):
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _lifecycle_summary(self) -> dict:
        """Return typed test/evidence/campaign counts for honest reporting."""
        summary = {
            "test_executions": 0, "test_statuses": {}, "observations": 0,
            "candidates": 0, "validation_attempts": 0, "validation_results": {},
            "campaigns": 0, "operations": 0, "operation_statuses": {},
            "detection_outcomes": 0, "cleanup_actions": 0,
        }
        try:
            conn = self.ctx.storage.conn
            summary["test_executions"] = conn.execute("SELECT COUNT(*) c FROM test_executions").fetchone()["c"]
            summary["test_statuses"] = {r["status"]: r["c"] for r in conn.execute(
                "SELECT status,COUNT(*) c FROM test_executions GROUP BY status").fetchall()}
            summary["observations"] = conn.execute("SELECT COUNT(*) c FROM observations").fetchone()["c"]
            summary["candidates"] = conn.execute("SELECT COUNT(*) c FROM candidates").fetchone()["c"]
            summary["validation_attempts"] = conn.execute("SELECT COUNT(*) c FROM validation_attempts").fetchone()["c"]
            summary["validation_results"] = {r["result"]: r["c"] for r in conn.execute(
                "SELECT result,COUNT(*) c FROM validation_attempts GROUP BY result").fetchall()}
            summary["campaigns"] = conn.execute("SELECT COUNT(*) c FROM redteam_campaigns").fetchone()["c"]
            summary["operations"] = conn.execute("SELECT COUNT(*) c FROM redteam_operations").fetchone()["c"]
            summary["operation_statuses"] = {r["status"]: r["c"] for r in conn.execute(
                "SELECT status,COUNT(*) c FROM redteam_operations GROUP BY status").fetchall()}
            summary["detection_outcomes"] = conn.execute("SELECT COUNT(*) c FROM detection_outcomes").fetchone()["c"]
            summary["cleanup_actions"] = conn.execute("SELECT COUNT(*) c FROM cleanup_actions").fetchone()["c"]
        except Exception:
            pass
        return summary

    def _top_concerns_md(self, findings, n=5):
        """Compatibility helper retained from the legacy audience renderer."""
        top = [f for f in findings if (f.get("severity") or "").upper() in {"CRITICAL", "HIGH"}][:n]
        if not top:
            return "- No confirmed Critical or High issue in this run."
        rows = []
        for finding in top:
            assessment = self._assessment(finding)
            asset = finding.get("url") or finding.get("target") or "asset not recorded"
            impact = str(assessment.get("security_impact") or finding.get("impact") or "Impact not recorded.")[:350]
            rows.append(f"- **[{finding.get('severity')}] {finding.get('title')}** — `{asset}` — {impact}")
        return "\n".join(rows)

    @staticmethod
    def _md_anchor(value: str) -> str:
        return re.sub(r"[^a-z0-9 -]", "", value.lower()).strip().replace(" ", "-")

    def _finding_id(self, finding, index):
        return f"TBHM-{index:03d}"

    def _summary_table(self, findings, start_index=1):
        lines = [
            "| ID | Severity | Confirmation | Exploitability | CWE | Affected asset | Finding |",
            "|---|---|---|---|---|---|---|",
        ]
        for offset, f in enumerate(findings, start=start_index):
            a = self._assessment(f)
            title = str(f.get("title") or "").replace("|", "\\|")[:100]
            asset = str(f.get("url") or f.get("target") or "").replace("|", "\\|")[:80]
            lines.append(
                f"| {self._finding_id(f, offset)} | {f.get('severity','INFO')} | "
                f"{a.get('confirmation_status','UNKNOWN')} | {a.get('exploitability_status','UNKNOWN')} | "
                f"{f.get('cwe') or '-'} | `{asset}` | {title} |"
            )
        if not findings:
            lines.append("| - | - | - | - | - | - | No findings in this category |")
        return "\n".join(lines)

    def _finding_markdown(self, f, display_id: str, confirmed_section: bool) -> str:
        a = self._assessment(f)
        cvss = self._cvss_obj(f.get("cvss"))
        steps = a.get("confirmed_steps") or []
        prerequisites = a.get("attack_prerequisites") or []
        reasons = a.get("confirmation_reasons") or []
        refs = f.get("references_json") or f.get("references") or []
        if isinstance(refs, str):
            try: refs = json.loads(refs)
            except Exception: refs = [refs] if refs.strip() else []

        poc = str(a.get("proof_of_concept") or "No safe reproducer available.")
        evidence = str(f.get("evidence") or "No evidence text stored.")[:12000]
        status_label = "Confirmed Steps to Reproduce" if confirmed_section else "Validation Steps Required"
        lines = [
            f"### {display_id} - [{f.get('severity','INFO')}] {f.get('title','Finding')}",
            "",
            "#### Summary",
            str(a.get("summary") or f.get("description") or f.get("title") or ""),
            "",
            "#### Classification and Scope",
            f"- **Confirmation status:** {a.get('confirmation_status','UNKNOWN')}",
            f"- **Exploitability:** {a.get('exploitability_status','UNKNOWN')}",
            f"- **Evidence strength:** {a.get('evidence_strength','unknown')}",
            f"- **Severity:** {f.get('severity','INFO')}",
            f"- **Confidence:** {f.get('confidence','UNKNOWN')}",
            f"- **CWE:** {f.get('cwe') or 'Not assigned'}",
            f"- **CVSS:** {cvss.get('score','Not assigned')} {cvss.get('vector','')}",
            f"- **Phase:** `{f.get('phase','')}`",
            f"- **Affected asset:** `{f.get('url') or f.get('target') or 'Not recorded'}`",
            f"- **Method / parameter:** `{f.get('method') or '-'} / {f.get('parameter') or '-'}`",
            f"- **Assessed access outcome:** `{a.get('access_level','unknown')}`",
            "",
            "#### Exploitability and Possible Access Path",
            str(a.get("attack_scenario") or "No access path was demonstrated."),
            "",
            "**Prerequisites:**",
        ]
        lines.extend([f"- {item}" for item in prerequisites] or ["- Not established."])
        lines.extend([
            "",
            "#### Proof of Concept",
            "```text",
            poc[:8000],
            "```",
            "",
            f"#### {status_label}",
        ])
        lines.extend([f"{i}. {step}" for i, step in enumerate(steps, start=1)] or ["1. No reliable reproduction steps were produced."])
        lines.extend([
            "",
            "#### Confirmation Basis",
        ])
        lines.extend([f"- {reason}" for reason in reasons] or ["- No explicit confirmation basis was recorded."])
        lines.extend([
            "",
            "#### Evidence",
            "```text",
            evidence,
            "```",
            "",
            "#### Security Impact",
            str(a.get("security_impact") or f.get("impact") or "Impact was not established."),
            "",
            "#### Remediation",
            str(a.get("remediation") or f.get("remediation") or "Remediation guidance was not recorded."),
            "",
            "#### Retest Criteria",
            str(a.get("retest_criteria") or "Repeat the reproduction steps and negative controls after remediation."),
        ])
        if refs:
            lines.extend(["", "#### References"])
            lines.extend([f"- {r}" for r in refs[:30]])
        lines.extend(["", "---", ""])
        return "\n".join(lines)

    def _write_final_markdown(self, findings):
        confirmed, supported, leads = self._groups(findings)
        confirmed_counts = self._counts(confirmed)
        total_counts = self._counts(findings)
        lifecycle = self._lifecycle_summary()
        targets = ", ".join(self.ctx.targets) or "Not recorded"
        report_date = datetime.now(timezone.utc).isoformat()
        posture = (
            "CRITICAL" if confirmed_counts.get("CRITICAL", 0) else
            "HIGH RISK" if confirmed_counts.get("HIGH", 0) else
            "MODERATE RISK" if confirmed_counts.get("MEDIUM", 0) else
            "NO CONFIRMED HIGH-IMPACT ISSUE IN THIS RUN"
        )
        toc = [
            "1. [Executive Summary](#1-executive-summary)",
            "2. [Scope and Engagement Context](#2-scope-and-engagement-context)",
            "3. [Methodology and Confirmation Standard](#3-methodology-and-confirmation-standard)",
            "4. [Findings Summary](#4-findings-summary)",
            "5. [Confirmed Vulnerabilities](#5-confirmed-vulnerabilities)",
            "6. [Supported Findings Requiring Final Verification](#6-supported-findings-requiring-final-verification)",
            "7. [Unconfirmed Leads and Observations](#7-unconfirmed-leads-and-observations)",
            "8. [Prioritized Remediation Roadmap](#8-prioritized-remediation-roadmap)",
            "9. [Retest and Closure Criteria](#9-retest-and-closure-criteria)",
            "10. [Conclusion](#10-conclusion)",
        ]
        lines = [
            "# TBHM Security Assessment - Final Technical Report",
            "",
            f"**TBHM version:** {VERSION}  ",
            f"**Generated:** {report_date}  ",
            f"**Targets:** {targets}  ",
            f"**Profile:** `{self.ctx.profile['name']}`  ",
            "",
            "## Table of Contents",
            *toc,
            "",
            "## 1. Executive Summary",
            "",
            f"TBHM identified **{len(confirmed)} strictly confirmed vulnerability/vulnerabilities**, "
            f"**{len(supported)} evidence-supported finding(s) that still require final verification**, "
            f"and **{len(leads)} unconfirmed lead(s)/observation(s)**. The overall confirmed posture for this run is **{posture}**.",
            "",
            f"Confirmed severity distribution: **{confirmed_counts['CRITICAL']} Critical, {confirmed_counts['HIGH']} High, "
            f"{confirmed_counts['MEDIUM']} Medium, {confirmed_counts['LOW']} Low, {confirmed_counts['INFO']} Informational**.",
            "",
            "Only records with explicit verifier metadata and reproducible successful evidence are presented as confirmed. Scanner output, imported evidence, static indicators, and LLM analysis cannot confirm a vulnerability by themselves.",
            "",
            "### Executive Priorities",
        ]
        lines.extend(self._top_concerns_md(confirmed, n=5).splitlines())
        lines.extend([
            "",
            "## 2. Scope and Engagement Context",
            "",
            f"- **Targets:** {targets}",
            f"- **Profile:** `{self.ctx.profile['name']}`",
            f"- **Run started:** {self.ctx.start_ts}",
            f"- **Authorization reference:** {getattr(self.ctx.args, 'bug_bounty_program', None) or getattr(self.ctx.args, 'roe_ticket', None) or 'Not supplied to the report renderer'}",
            "- **Safety model:** scope checks, bounded execution, timeouts, non-destructive defaults, evidence redaction, and explicit separation between confirmed findings and leads.",
            "",
            "## 3. Methodology and Confirmation Standard",
            "",
            "TBHM combines reconnaissance, web/API testing, source and dependency analysis, enterprise/AD review, mobile/cloud/firmware checks, reverse engineering, verification, correlation, and multi-audience reporting. Reverse engineering follows an iterative static/dynamic methodology: rapid triage, headless static analysis, imported controlled-sandbox evidence, bounded CFG/symbolic analysis, then correlation.",
            "",
            "A record is **CONFIRMED** only when a versioned assertion passes, its negative control passes, repeatability succeeds, and an explicit verifier stores the result. A record is **SUPPORTED** when evidence is meaningful but that chain is incomplete. Imported scanner output, static code patterns, LLM output, liveness checks, and sandbox reports without controlled proof remain **UNCONFIRMED**.",
            "",
            "### Typed Evidence Lifecycle",
            f"- Test executions: **{lifecycle['test_executions']}** — statuses: `{json.dumps(lifecycle['test_statuses'], sort_keys=True)}`",
            f"- Observations: **{lifecycle['observations']}**; candidates: **{lifecycle['candidates']}**; validation attempts: **{lifecycle['validation_attempts']}**",
            f"- Validation results: `{json.dumps(lifecycle['validation_results'], sort_keys=True)}`",
            f"- Red-team campaigns: **{lifecycle['campaigns']}**; operations: **{lifecycle['operations']}**; detection outcomes: **{lifecycle['detection_outcomes']}**; cleanup records: **{lifecycle['cleanup_actions']}**",
            "- High-impact red-team operations are approval-gated and import-only; their absence is reported as not executed, never safe.",
            "",
            "## 4. Findings Summary",
            "",
            "### All Records",
            f"Total records: **{len(findings)}** - {total_counts['CRITICAL']} Critical, {total_counts['HIGH']} High, {total_counts['MEDIUM']} Medium, {total_counts['LOW']} Low, {total_counts['INFO']} Informational.",
            "",
            self._summary_table(findings),
            "",
            "## 5. Confirmed Vulnerabilities",
            "",
        ])
        if not confirmed:
            lines.append("No vulnerability met the strict confirmation standard in this run. This does not mean the target is safe; supported findings and leads still require review.")
        for i, f in enumerate(confirmed, start=1):
            lines.append(self._finding_markdown(f, self._finding_id(f, i), True))

        lines.extend(["", "## 6. Supported Findings Requiring Final Verification", "", self._summary_table(supported)])
        base = len(confirmed) + 1
        for i, f in enumerate(supported, start=base):
            lines.append(self._finding_markdown(f, self._finding_id(f, i), False))

        lines.extend(["", "## 7. Unconfirmed Leads and Observations", "", "These records are not client-reportable vulnerabilities until independently reproduced.", "", self._summary_table(leads)])
        for i, f in enumerate(leads, start=base + len(supported)):
            lines.append(self._finding_markdown(f, self._finding_id(f, i), False))

        lines.extend([
            "",
            "## 8. Prioritized Remediation Roadmap",
            "",
            "1. Remediate confirmed Critical and High vulnerabilities first and preserve evidence for retest.",
            "2. Complete the final verification steps for Supported findings before accepting or rejecting them.",
            "3. Review unconfirmed leads in risk order; close each with a documented valid/false-positive/duplicate decision.",
            "4. Add regression tests for every confirmed weakness and validate compiler/platform mitigations for binary findings.",
            "5. Re-run TBHM with the same scope and compare results after fixes.",
            "",
            "## 9. Retest and Closure Criteria",
            "",
            "A finding is closed only when the original proof no longer succeeds, negative controls behave correctly, no equivalent bypass remains, and the fix is verified in the deployed environment. Store the retest request/response or sandbox evidence with the finding ID.",
            "",
            "## 10. Conclusion",
            "",
            f"This report separates **{len(confirmed)} confirmed**, **{len(supported)} supported**, and **{len(leads)} unconfirmed** records. The report should be reviewed by a qualified tester before external delivery, especially for business-logic, binary, AD, mobile, cloud, and imported-tool findings.",
            "",
        ])
        (self.out / "REPORT_final.md").write_text("\n".join(lines), encoding="utf-8")

    def _finding_html(self, f, display_id: str, confirmed: bool) -> str:
        a = self._assessment(f)
        cvss = self._cvss_obj(f.get("cvss"))
        steps = "".join(f"<li>{html.escape(str(x))}</li>" for x in (a.get("confirmed_steps") or []))
        prereq = "".join(f"<li>{html.escape(str(x))}</li>" for x in (a.get("attack_prerequisites") or []))
        reasons = "".join(f"<li>{html.escape(str(x))}</li>" for x in (a.get("confirmation_reasons") or []))
        label = "Confirmed Steps to Reproduce" if confirmed else "Validation Steps Required"
        return f"""
<section class="finding" id="{html.escape(display_id.lower())}" style="border-left-color:{SEVERITY_COLORS.get(f.get('severity'),'#777')}">
<h3>{html.escape(display_id)} - [{html.escape(f.get('severity','INFO'))}] {html.escape(f.get('title','Finding'))}</h3>
<div class="tags"><span>{html.escape(a.get('confirmation_status','UNKNOWN'))}</span><span>{html.escape(a.get('exploitability_status','UNKNOWN'))}</span><span>{html.escape(f.get('cwe') or 'No CWE')}</span></div>
<h4>Summary</h4><p>{html.escape(str(a.get('summary') or ''))}</p>
<table><tr><th>Affected asset</th><td><code>{html.escape(str(f.get('url') or f.get('target') or ''))}</code></td></tr>
<tr><th>CVSS</th><td>{html.escape(str(cvss.get('score','')))} {html.escape(str(cvss.get('vector','')))}</td></tr>
<tr><th>Phase</th><td><code>{html.escape(str(f.get('phase','')))}</code></td></tr>
<tr><th>Access outcome</th><td><code>{html.escape(str(a.get('access_level','unknown')))}</code></td></tr></table>
<h4>Exploitability and Possible Access Path</h4><p>{html.escape(str(a.get('attack_scenario') or ''))}</p><ul>{prereq}</ul>
<h4>Proof of Concept</h4><pre>{html.escape(str(a.get('proof_of_concept') or ''))}</pre>
<h4>{label}</h4><ol>{steps}</ol>
<h4>Confirmation Basis</h4><ul>{reasons}</ul>
<h4>Evidence</h4><pre>{html.escape(str(f.get('evidence') or '')[:12000])}</pre>
<h4>Security Impact</h4><p>{html.escape(str(a.get('security_impact') or ''))}</p>
<h4>Remediation</h4><p>{html.escape(str(a.get('remediation') or ''))}</p>
<h4>Retest Criteria</h4><p>{html.escape(str(a.get('retest_criteria') or ''))}</p>
</section>"""

    def _write_html(self, findings):
        """Backward-compatible alias for the legacy audience HTML renderer."""
        return self._write_final_html(findings)

    def _write_final_html(self, findings):
        confirmed, supported, leads = self._groups(findings)
        counts = self._counts(findings)
        cards = "".join(
            f'<div class="card" style="border-left-color:{SEVERITY_COLORS[s]};background:{SEVERITY_BG[s]}"><b>{counts[s]}</b><span>{s}</span></div>'
            for s in SEVERITY_ORDER
        )
        sections = []
        for i, f in enumerate(confirmed, 1): sections.append(self._finding_html(f, self._finding_id(f, i), True))
        start = len(confirmed) + 1
        for i, f in enumerate(supported, start): sections.append(self._finding_html(f, self._finding_id(f, i), False))
        start += len(supported)
        for i, f in enumerate(leads, start): sections.append(self._finding_html(f, self._finding_id(f, i), False))
        body = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TBHM Final Security Report</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;max-width:1180px;margin:0 auto;padding:28px;color:#202124;line-height:1.55}} nav{{position:sticky;top:0;background:white;padding:10px;border-bottom:1px solid #ddd;z-index:2}} nav a{{margin-right:14px}} h1,h2{{color:#15364a}} .cards{{display:flex;gap:12px;flex-wrap:wrap}} .card{{min-width:125px;padding:14px;border-left:6px solid;border-radius:6px}} .card b{{font-size:28px;display:block}} .card span{{font-size:12px}} .finding{{margin:22px 0;padding:18px;border:1px solid #ddd;border-left:6px solid;border-radius:6px}} .tags span{{display:inline-block;background:#eef2f5;padding:3px 8px;margin-right:6px;border-radius:12px;font-size:12px}} table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ddd;padding:7px;text-align:left;vertical-align:top}} th{{background:#f5f7f8}} pre{{white-space:pre-wrap;word-break:break-word;background:#f6f8fa;padding:12px;border-radius:4px;max-height:520px;overflow:auto}} code{{word-break:break-all}} @media print{{nav{{display:none}} .finding{{break-inside:avoid}}}}
</style></head><body>
<nav><a href="#executive">Executive Summary</a><a href="#methodology">Methodology</a><a href="#confirmed">Confirmed</a><a href="#supported">Supported</a><a href="#leads">Leads</a></nav>
<h1>TBHM Security Assessment - Final Technical Report</h1><p><b>Version:</b> {VERSION}<br><b>Targets:</b> {html.escape(', '.join(self.ctx.targets))}<br><b>Profile:</b> {html.escape(self.ctx.profile['name'])}<br><b>Generated:</b> {datetime.now(timezone.utc).isoformat()}</p>
<section id="executive"><h2>Executive Summary</h2><p><b>{len(confirmed)}</b> strictly confirmed, <b>{len(supported)}</b> supported pending final verification, and <b>{len(leads)}</b> unconfirmed leads.</p><div class="cards">{cards}</div></section>
<section id="methodology"><h2>Methodology and Confirmation Standard</h2><p>TBHM uses an evidence-driven workflow across web/API, source, enterprise, mobile, cloud, firmware, and reverse engineering. Only explicit verifier metadata plus reproducible successful evidence can produce CONFIRMED status. Static indicators, imports, scanner records, imported evidence, and LLM analysis are not sufficient alone.</p></section>
<h2 id="confirmed">Confirmed Vulnerabilities ({len(confirmed)})</h2>{''.join(sections[:len(confirmed)]) or '<p>None met the strict confirmation standard.</p>'}
<h2 id="supported">Supported Findings Requiring Final Verification ({len(supported)})</h2>{''.join(sections[len(confirmed):len(confirmed)+len(supported)]) or '<p>None.</p>'}
<h2 id="leads">Unconfirmed Leads and Observations ({len(leads)})</h2>{''.join(sections[len(confirmed)+len(supported):]) or '<p>None.</p>'}
<h2>Prioritized Remediation Roadmap</h2><ol><li>Fix confirmed Critical/High issues.</li><li>Finish verification for Supported findings.</li><li>Review and disposition each lead.</li><li>Add regression tests and repeat the same proof after remediation.</li></ol>
</body></html>"""
        (self.out / "REPORT_final.html").write_text(body, encoding="utf-8")
        (self.out / "REPORT.html").write_text(body, encoding="utf-8")

    # ------------------------------------------------------------------
    # Audience-specific reports
    # ------------------------------------------------------------------
    def _write_confirmed(self, findings):
        confirmed, _, _ = self._groups(findings)
        lines = ["# Confirmed Vulnerabilities", "", "Only findings that meet the strict v4.1.0 confirmation standard appear here.", ""]
        for i, f in enumerate(confirmed, 1):
            lines.append(self._finding_markdown(f, self._finding_id(f, i), True))
        if not confirmed: lines.append("No findings met the strict confirmation standard.")
        (self.out / "REPORT_confirmed.md").write_text("\n".join(lines), encoding="utf-8")

    def _write_leads(self, findings):
        _, supported, leads = self._groups(findings)
        lines = ["# Findings Requiring Validation", "", "Supported and unconfirmed records are not presented as proven vulnerabilities.", "", "## Supported", self._summary_table(supported), "", "## Unconfirmed Leads", self._summary_table(leads)]
        (self.out / "REPORT_leads.md").write_text("\n".join(lines), encoding="utf-8")

    def _qualified_posture(self, confirmed):
        """A narrow, evidence-bounded posture statement.

        It intentionally describes only strictly confirmed findings from this
        run and never labels the organization itself "safe" or "reasonable".
        """
        severities = {(f.get("severity") or "INFO").upper() for f in confirmed}
        if "CRITICAL" in severities:
            return "Urgent confirmed risk — at least one Critical issue requires immediate risk-owner review."
        if "HIGH" in severities:
            return "Material confirmed risk — High-impact remediation should be prioritized."
        if "MEDIUM" in severities:
            return "Confirmed security weaknesses exist and require a tracked remediation plan."
        if confirmed:
            return "Only Low/Informational issues met the strict confirmation standard in this run."
        return "No issue met the strict confirmation standard in this run; this is not evidence of safety."

    def _load_branch_matrix(self):
        """Load the legacy playbook branch matrix when governance produced it."""
        path = self.out / "redteam" / "00_governance" / "branch_matrix.json"
        try:
            return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
        except Exception:
            return None

    @staticmethod
    def _phase_to_branch_map():
        """Best-effort phase-to-playbook mapping used only for honest coverage status."""
        return {
            "preflight": "BR01", "redteam_governance": "BR02", "coverage_map": "BR02",
            "recon": "BR05", "ports": "BR05", "cname_takeover": "BR25",
            "external_perimeter_tooling": "BR05", "corporate_osint": "BR05",
            "osint_depth_collectors": "BR05", "internal_network_safe": "BR04",
            "network_firewall_tooling": "BR04", "ad_identity_safe": "BR06",
            "add_net_ad": "BR06", "internal_ad_tooling": "BR06",
            "ad_access_assessment": "BR06", "identity_security_tooling": "BR06",
            "lateral_movement_paths": "BR06", "iot_cctv_safe": "BR13",
            "wireless_physical_soc": "BR12", "social_engineering_governance": "BR21",
            "ot_ics_safe": "BR27", "discovery": "BR09", "smart_crawl": "BR09",
            "deep_crawl": "BR09", "backend_map": "BR10", "content_discovery": "BR09",
            "spec_scan": "BR10", "api_fuzz": "BR10", "code_scan": "BR18",
            "code_intel": "BR18", "sast_tooling": "BR18", "code_security_tooling": "BR18",
            "source_orchestration_tooling": "BR18", "mobile_scan": "BR11",
            "mobile_tooling": "BR11", "mobile_reverse_extended": "BR11",
            "ci_cd_supply_chain_security": "BR18", "firmware_reverse_safe": "BR19",
            "firmware_tooling_extended": "BR19",
            "reverse_triage": "BR19", "reverse_static_analysis": "BR19",
            "reverse_dynamic_evidence": "BR19", "reverse_symbolic_analysis": "BR19",
            "reverse_correlation": "BR19", "reverse_engineering_tooling": "BR19",
            "protected_routes": "BR09", "vuln_scan": "BR09", "nuclei_extended": "BR09",
            "custom_nuclei": "BR09", "vuln_scan_extended": "BR09",
            "infra_exposure": "BR08", "deep_scan": "BR09", "web_scanner_tooling": "BR09",
            "audit": "BR09", "atlassian_audit": "BR16", "injections": "BR09",
            "add_sqli": "BR09", "waf_evasion_ssrf": "BR09", "smuggling": "BR09",
            "authenticated_session_model": "BR30", "access_control": "BR09",
            "auth_advanced": "BR30", "auth_modern_review": "BR30", "mfa_bypass_safe": "BR30",
            "api_specific": "BR10", "graphql_audit": "BR10", "interface_probe": "BR10",
            "modern_protocols_discovery": "BR10", "ai_redteam_safe": "BR20",
            "ai_llm_tooling": "BR20", "llm_agent_tool_call_abuse": "BR20",
            "upload_race": "BR09", "business_logic": "BR09", "cache_deception": "BR09",
            "pdf_injection": "BR09", "cloud_recon": "BR16", "cloud_recon_extended": "BR16",
            "iac_drift": "BR16", "k8s_recon_safe": "BR16", "cloud_inventory_safe": "BR16",
            "cloud_posture_tooling": "BR16", "cloud_identity_path_analysis": "BR16",
            "console_leaks": "BR18", "api_key_pivot": "BR18", "client_platform": "BR09",
            "secrets_misc": "BR18", "browser_extension_audit": "BR18", "web3": "BR10",
            "attack_path": "BR06", "controlled_validation_plane": "BR02",
            "purple_team_validation": "BR31", "compliance_coverage": "BR02",
            "compliance_reporting_extended": "BR02", "playbook_integration": "BR02",
            "data_analysis_intelligence": "BR02", "ai_supervision": "BR20",
        }

    def _branch_status_from_findings(self, matrix, findings):
        """Restore the detailed conservative branch table from v2.23-v3.8."""
        branches = (matrix or {}).get("branches") or (matrix or {}).get("matrix") or []
        if not isinstance(branches, list):
            return []
        touched = {}
        mapping = self._phase_to_branch_map()
        for finding in findings:
            branch = mapping.get(str(finding.get("phase") or ""))
            if branch:
                touched[branch] = touched.get(branch, 0) + 1
        rows = []
        for branch in branches:
            if not isinstance(branch, dict):
                continue
            bid = str(branch.get("id") or branch.get("branch") or "unknown")
            title = str(branch.get("title") or branch.get("name") or "Untitled branch")
            automation = str(branch.get("automation") or "checklist")
            count = touched.get(bid, 0)
            if count:
                status = f"Tested (partial, automated) — {count} finding(s)"
            elif automation == "partial":
                status = "Not Tested — automation available, no evidence yet"
            else:
                status = "Not Tested — manual/checklist only"
            rows.append((bid, title, automation, status))
        return rows

    def _governance_summary(self):
        """Read governance/coverage artifacts when the relevant phases ran."""
        base = self.out / "redteam" / "00_governance"
        result = {
            "available": False, "branches": None, "subtopics": None,
            "tested_subtopics": None, "manual_or_untested": None, "files": [],
        }
        objective = base / "objective_coverage_map.json"
        branch = base / "branch_matrix.json"
        for candidate in (branch, objective, base / "redteam_coverage_matrix.csv",
                          base / "high_risk_approval_register.csv"):
            if candidate.exists():
                result["files"].append(candidate.relative_to(self.out).as_posix())
        if objective.is_file():
            try:
                data = json.loads(objective.read_text(errors="ignore"))
                result["branches"] = int(data.get("n_branches") or 0)
                result["subtopics"] = int(data.get("n_subtopics") or 0)
                result["tested_subtopics"] = int(data.get("subtopics_with_automated_evidence") or 0)
                result["manual_or_untested"] = max(
                    0, result["subtopics"] - result["tested_subtopics"])
                result["available"] = True
            except Exception:
                pass
        if branch.is_file() and not result["available"]:
            try:
                data = json.loads(branch.read_text(errors="ignore"))
                branches = data.get("branches") or data.get("matrix") or []
                result["branches"] = len(branches) if isinstance(branches, list) else None
                result["available"] = True
            except Exception:
                pass
        return result

    def _write_executive(self, findings):
        confirmed, supported, leads = self._groups(findings)
        counts = self._counts(confirmed)
        top = [f for f in confirmed if f.get("severity") in {"CRITICAL", "HIGH"}][:5]
        generated = datetime.now(timezone.utc).isoformat()
        lines = [
            "# Executive Summary", "",
            f"**Generated:** {generated}  ",
            f"**Targets:** {', '.join(self.ctx.targets)}  ",
            f"**Profile:** `{self.ctx.profile['name']}`  ",
            f"**Evidence-bounded posture:** {self._qualified_posture(confirmed)}  ",
            f"**Confirmed findings:** {len(confirmed)} ({counts['CRITICAL']} Critical, {counts['HIGH']} High, {counts['MEDIUM']} Medium, {counts['LOW']} Low)  ",
            f"**Supported pending verification:** {len(supported)}  ",
            f"**Unconfirmed leads:** {len(leads)}", "",
            "> This posture describes only strictly confirmed evidence from the tested scope. "
            "Untested branches, unavailable tools, and environment-specific logic remain residual risk.", "",
            "## Top Confirmed Concerns", "",
        ]
        lines.extend([
            f"- **[{f.get('severity')}] {f.get('title')}** — "
            f"`{f.get('url') or f.get('target') or 'asset not recorded'}` — "
            f"{self._assessment(f).get('security_impact','')[:350]}" for f in top
        ] or ["- No confirmed Critical or High issue in this run."])
        lines.extend([
            "", "## Executive Actions", "",
            "1. Assign a risk owner to each confirmed finding and prioritize Critical/High impact first.",
            "2. Complete the independent verification chain for Supported findings before treating them as proven.",
            "3. Review untested/manual coverage and leads without interpreting their absence as safety.",
            "4. Agree remediation deadlines from business impact and implementation scope; TBHM does not invent fixed severity-to-time SLAs.",
            "5. Retest using the documented proof, negative controls, and closure criteria.",
        ])
        (self.out / "REPORT_executive.md").write_text("\n".join(lines), encoding="utf-8")

    def _write_manager(self, findings):
        confirmed, supported, leads = self._groups(findings)
        lines = [
            "# Management Report", "",
            f"**Targets:** {', '.join(self.ctx.targets)}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Evidence-bounded posture:** {self._qualified_posture(confirmed)}", "",
            "## Status", "",
            f"- Confirmed: {len(confirmed)}",
            f"- Supported pending verification: {len(supported)}",
            f"- Unconfirmed leads: {len(leads)}", "",
            "## Planning Rule", "",
            "Severity represents security impact, not engineering effort. Implementation complexity and deadlines must be assigned per finding by the responsible engineering and risk owners; no fixed severity-to-days estimate is generated.",
            "", "## Confirmed Findings",
        ]
        for f in confirmed:
            a = self._assessment(f)
            lines.extend([
                f"### [{f.get('severity')}] {f.get('title')}",
                f"- **Where:** `{f.get('url') or f.get('target')}`",
                f"- **Business/Security impact:** {a.get('security_impact')}",
                f"- **Required action:** {a.get('remediation')}",
                "- **Implementation complexity:** Requires owner/engineering assessment against the affected architecture.",
                "",
            ])
        if not confirmed:
            lines.append("No strictly confirmed vulnerability in this run.")
        lines.extend(["", "## Verification Backlog", "", self._summary_table(supported + leads)])
        (self.out / "REPORT_manager.md").write_text("\n".join(lines), encoding="utf-8")

    def _write_developer(self, findings):
        confirmed, supported, leads = self._groups(findings)
        lines = ["# Developer Report - Full Technical Detail", "", f"Generated: {datetime.now(timezone.utc).isoformat()}", f"Profile: `{self.ctx.profile['name']}`", f"Targets: {', '.join(self.ctx.targets)}", "", "## Table of Contents", "- Confirmed findings", "- Supported findings", "- Leads", "", "## Methodology", "", "TBHM v4.2.1 performs evidence-grounded confirmation; provenance-aware corporate OSINT and entity analysis; offline authenticated-role modeling; EPSS/KEV/OSV enrichment; read-only identity/cloud/mobile adapters; an approval-gated validation register; purple-team telemetry mapping; and a five-stage reverse-engineering workflow. The local AI plane learns only from sanitized T3 run artifacts, remains non-authoritative, proposes changes for human review, and cannot execute tools, alter scope/status/severity, or apply code.", "", "## Confirmed Findings"]
        index = 1
        for f in confirmed:
            lines.append(self._finding_markdown(f, self._finding_id(f, index), True)); index += 1
        lines.extend(["", "## Supported Findings"])
        for f in supported:
            lines.append(self._finding_markdown(f, self._finding_id(f, index), False)); index += 1
        lines.extend(["", "## Unconfirmed Leads"])
        for f in leads:
            lines.append(self._finding_markdown(f, self._finding_id(f, index), False)); index += 1
        (self.out / "REPORT_developer.md").write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def _defender_ioc_for(finding) -> str:
        phase = str(finding.get("phase") or "")
        mapping = {
            "injections": "SQL/template/script/command metacharacters followed by unusual 4xx/5xx, timing, or response-body changes.",
            "add_sqli": "Repeated quote, boolean, error, or time-delay probes against the same parameter and endpoint.",
            "waf_evasion_ssrf": "Encoded loopback/private/link-local destinations, alternate IP representations, or suspicious outbound DNS/HTTP callbacks.",
            "access_control": "The same session or identity requesting object identifiers owned by another user or role.",
            "authenticated_session_model": "Cross-role request reuse, inconsistent authorization outcomes, or privileged endpoints reached from lower-privilege sessions.",
            "auth_advanced": "JWT decode/signature failures, MFA-state skips, session fixation, or direct transitions from login to privileged resources.",
            "auth_modern_review": "Unexpected OAuth/OIDC/SAML redirect, audience, issuer, nonce, state, or token-validation failures.",
            "api_specific": "GraphQL introspection, unusual field combinations, webhook replay, or high-volume API schema probing.",
            "graphql_audit": "Introspection, alias/batch amplification, suggestion leakage, and authorization failures on nested fields.",
            "upload_race": "Double extensions, MIME mismatches, rapid upload/use/delete sequences, or unexpected executable-content handling.",
            "secrets_misc": "Requests for .env, .git, backups, debug/status endpoints, source maps, or sensitive configuration files.",
            "vuln_scan": "Nuclei-like rapid template requests and repeated probes for known vulnerable paths.",
            "nuclei_extended": "Bursts of tagged CVE/exposure/misconfiguration probes across many endpoints.",
            "reverse_dynamic_evidence": "Crash signatures, suspicious API calls, file/registry modification, process spawning, or unexpected network connections from the analyzed process.",
            "reverse_static_analysis": "Static references to dangerous process, memory, credential, persistence, or networking APIs; validate runtime reachability.",
            "ad_access_assessment": "Unsigned SMB, cleartext LDAP, excessive directory privileges, anonymous binds, or authentication anomalies.",
            "identity_security_tooling": "Certificate-template abuse indicators, risky identity grants, legacy authentication, or privileged role changes.",
            "cloud_identity_path_analysis": "New trust relationships, wildcard permissions, privilege-escalation API sequences, or cross-account role assumption.",
            "ci_cd_supply_chain_security": "Workflow changes, unpinned actions, self-hosted runner exposure, unsigned artifacts, or secret access from untrusted build contexts.",
            "corporate_osint": "No direct IOC; use exposed asset/identity candidates to strengthen brand, identity, and external-attack-surface monitoring.",
            "osint_depth_collectors": "No direct IOC; monitor newly identified assets, leaked references, and DNS/registration changes after human scope validation.",
        }
        return mapping.get(
            phase,
            "Alert on attempts matching the documented proof and affected asset, then correlate authentication, endpoint, network, and application telemetry.",
        )

    def _write_defender(self, findings):
        confirmed, supported, _ = self._groups(findings)
        lines = [
            "# Defender Report - Indicators and Detection Guidance", "",
            "Detection recommendations are based on confirmed and supported findings. Static/import/OSINT observations remain contextual leads.", "",
        ]
        for finding in confirmed + supported:
            assessment = self._assessment(finding)
            asset = finding.get("url") or finding.get("target") or "not recorded"
            lines.extend([
                f"## [{finding.get('severity')}] {finding.get('title')}",
                f"- **Affected asset:** `{asset}`",
                f"- **Confirmation:** {assessment.get('confirmation_status')}",
                f"- **Look for:** {self._defender_ioc_for(finding)}",
                f"- **Possible outcome:** {assessment.get('access_level')}",
                f"- **Evidence reference:** `{finding.get('phase')}` / finding ID `{finding.get('id')}`",
                "",
            ])
        if len(lines) <= 4:
            lines.append("No actionable confirmed or supported finding was available.")
        (self.out / "REPORT_defender.md").write_text("\n".join(lines), encoding="utf-8")

    # ------------------------------------------------------------------
    # Machine-readable formats
    # ------------------------------------------------------------------
    def _write_json(self, findings):
        from core.version import source_fingerprint
        confirmed, supported, leads = self._groups(findings)
        out = {
            "tool": "TBHM", "version": VERSION, "started_at": self.ctx.start_ts,
            'source_build_sha256':source_fingerprint(),
            'report_snapshot_at':datetime.now(timezone.utc).isoformat(),
            'execution_status':getattr(self.ctx, 'phase_state', {}).get('run_status', 'snapshot'),
            'phase_outcomes':getattr(self.ctx, 'phase_state', {}).get('phase_outcomes', {}),
            'execution_note':'Report snapshot precedes final sealing; execution_ledger.json is authoritative for final run completion. Phase completion is not vulnerability-test coverage.',
            "profile": self.ctx.profile["name"], "targets": self.ctx.targets,
            "summary": {"confirmed": len(confirmed), "supported": len(supported), "unconfirmed": len(leads)},
            "evidence_lifecycle": self._lifecycle_summary(),
            "findings": findings, "severity_counts": self._counts(findings),
        }
        payload = json.dumps(out, indent=2, default=str)
        (self.out / "report.json").write_text(payload, encoding="utf-8")
        # Uppercase compatibility writer requested by older consumers.
        (self.out / "REPORT.json").write_text(payload, encoding="utf-8")

    def _write_sarif(self, findings):
        """Write a deterministic SARIF 2.1.0 result with provenance and stable fingerprints."""
        rules, results = {}, []
        for f in findings:
            rid = str(f.get("cwe") or f.get("phase") or "tbhm").replace(" ", "-")
            title = str(f.get("title") or "finding")
            rules.setdefault(rid, {
                "id": rid, "name": re.sub(r"[^A-Za-z0-9_.-]+", "-", title)[:80] or "finding",
                "shortDescription": {"text": title[:120]},
                "fullDescription": {"text": str(f.get("description") or title)[:1000]},
                "defaultConfiguration": {"level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(f.get("severity"), "note")},
                "properties": {"tags": [x for x in [f.get("phase"), f.get("cwe")] if x], "cwe": f.get("cwe", "")},
            })
            a = self._assessment(f)
            asset = str(f.get("url") or f.get("target") or "")
            fingerprint_basis = "|".join(str(f.get(k) or "") for k in ("phase", "title", "target", "url", "cwe"))
            fingerprint = hashlib.sha256(fingerprint_basis.encode("utf-8", errors="ignore")).hexdigest()
            result = {
                "ruleId": rid,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(f.get("severity"), "note"),
                "message": {"text": f"{title}: {str(a.get('summary') or f.get('description') or '')[:1000]}"},
                "partialFingerprints": {"tbhm/v1": fingerprint},
                "properties": {
                    "severity": f.get("severity"), "confidence": f.get("confidence"),
                    "confirmation_status": a.get("confirmation_status"),
                    "exploitability_status": a.get("exploitability_status"),
                    "access_level": a.get("access_level"),
                    "cvss": self._cvss_obj(f.get("cvss")).get("vector", ""),
                    "phase": f.get("phase"), "finding_id": f.get("id"),
                },
            }
            if asset:
                result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": asset, "uriBaseId": "TARGETROOT"}}}]
            results.append(result)
        run_id = hashlib.sha256(f"{self.ctx.start_ts}|{self.ctx.profile.get('name')}|{self.ctx.targets}".encode()).hexdigest()[:24]
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "automationDetails": {"id": f"TBHM/{run_id}"},
                "tool": {"driver": {
                    "name": "TBHM", "fullName": "The Bug Hunter Master",
                    "informationUri": "https://local.invalid/tbhm", "version": VERSION,
                    "semanticVersion": SEMANTIC_VERSION, "rules": list(rules.values()),
                }},
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": str(self.ctx.start_ts),
                    "commandLine": "TBHM invocation redacted; see local run metadata",
                    "properties": {"profile": self.ctx.profile.get("name"), "target_count": len(self.ctx.targets)},
                }],
                "originalUriBaseIds": {"TARGETROOT": {"uri": "file:///"}},
                "results": results,
                "properties": {"confirmation_model": "CONFIRMED/SUPPORTED/UNCONFIRMED", "evidence_source": "TBHM native finding store"},
            }],
        }
        payload = json.dumps(sarif, indent=2, default=str)
        (self.out / "report.sarif").write_text(payload, encoding="utf-8")
        (self.out / "REPORT.sarif").write_text(payload, encoding="utf-8")

    def _write_csv(self, findings):
        cols = ["id", "severity", "confirmation_status", "exploitability_status", "access_level", "title", "cwe", "cvss_score", "cvss_vector", "target", "url", "method", "confidence", "phase", "summary", "security_impact", "remediation"]
        rows = []
        for f in findings:
            a = self._assessment(f); cvss = self._cvss_obj(f.get("cvss"))
            rows.append([f.get("id"), f.get("severity"), a.get("confirmation_status"), a.get("exploitability_status"), a.get("access_level"), f.get("title"), f.get("cwe"), cvss.get("score"), cvss.get("vector"), f.get("target"), f.get("url"), f.get("method"), f.get("confidence"), f.get("phase"), a.get("summary"), a.get("security_impact"), a.get("remediation")])
        for name in ("report.csv", "REPORT.csv"):
            with (self.out / name).open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle); writer.writerow(cols); writer.writerows(rows)

    # ------------------------------------------------------------------
    # Per-finding evidence/reproducer kits
    # ------------------------------------------------------------------
    def _write_per_finding_kits(self, findings):
        root = self.out / "PER-FINDING"
        root.mkdir(exist_ok=True)
        used = set()
        for index, finding in enumerate(findings, start=1):
            if str(finding.get("severity") or "INFO").upper() == "INFO":
                continue
            stable_basis = "|".join(str(finding.get(key) or "") for key in (
                "id", "phase", "title", "target", "url", "method", "parameter"
            ))
            stable_id = str(finding.get("id") or hashlib.sha256(stable_basis.encode(
                "utf-8", errors="ignore")).hexdigest()[:12])
            slug = self._slug(str(finding.get("title") or "finding"))[:50] or "finding"
            dirname = f"{str(finding.get('severity') or 'INFO').upper()}_{slug}_{self._slug(stable_id)}"
            if dirname in used:
                dirname = f"{dirname}_{index:03d}"
            used.add(dirname)
            directory = root / dirname
            directory.mkdir(exist_ok=True)
            self._write_kit(finding, directory, stable_id=stable_id)

    @staticmethod
    def _request_headers(finding: dict) -> dict:
        headers = finding.get("headers") or finding.get("request_headers") or {}
        if isinstance(headers, dict):
            return {str(k): str(v) for k, v in headers.items() if k and v is not None}
        if isinstance(headers, str):
            parsed = {}
            for line in headers.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    if key.strip():
                        parsed[key.strip()] = value.strip()
            return parsed
        return {}

    @classmethod
    def _synth_http_request(cls, finding: dict) -> str:
        method = str(finding.get("method") or "GET").upper()
        url = str(finding.get("url") or finding.get("target") or "").strip()
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        headers = cls._request_headers(finding)
        headers.setdefault("Host", parsed.netloc)
        headers.setdefault("User-Agent", f"TBHM-Reproducer/{VERSION}")
        payload = finding.get("payload")
        if payload not in (None, "") and method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json" if isinstance(payload, (dict, list)) else "application/x-www-form-urlencoded"
            body = json.dumps(payload, ensure_ascii=False) if isinstance(payload, (dict, list)) else str(payload)
        else:
            body = ""
        lines = [f"{method} {path} HTTP/1.1"]
        lines.extend(f"{key}: {value}" for key, value in headers.items())
        lines.extend(["", body])
        return "\r\n".join(lines).rstrip() + "\r\n"

    def _write_kit(self, finding, directory, stable_id=None):
        assessment = self._assessment(finding)
        method = str(finding.get("method") or "GET").upper()
        url = str(finding.get("url") or "").strip()
        target = str(finding.get("target") or "").strip()
        http_url = url if url.startswith(("http://", "https://")) else (
            target if target.startswith(("http://", "https://")) else ""
        )
        http_finding = dict(finding)
        if http_url:
            http_finding["url"] = http_url
        payload = finding.get("payload") or ""
        poc = str(assessment.get("proof_of_concept") or "No safe reproducer was generated.")
        phase = str(finding.get("phase") or "")
        status = str(assessment.get("confirmation_status") or "UNCONFIRMED")
        mutating = method in {"POST", "PUT", "PATCH", "DELETE"}
        warning = (
            "# SAFE-WRITES WARNING: this reproducer uses a mutating HTTP method.\n"
            "# Run it only against an explicitly authorized in-scope target after\n"
            "# reviewing side effects, cleanup, rate limits, and notification risk.\n"
            if mutating else ""
        )

        if http_url:
            try:
                from core import curl_reproducer
                curl = str(curl_reproducer.build(http_finding) or "").strip()
            except Exception:
                curl = ""
            if not curl:
                curl = f"curl -i -sk -X {shlex.quote(method)} {shlex.quote(http_url)}"
                if payload and mutating:
                    body = json.dumps(payload, ensure_ascii=False) if isinstance(payload, (dict, list)) else str(payload)
                    curl += f" --data {shlex.quote(body[:4000])}"
            curl_text = (
                "#!/bin/sh\nset -eu\n"
                f"# Reproduce: {finding.get('title') or 'finding'}\n"
                f"# Finding ID: {stable_id or finding.get('id') or 'unassigned'}\n"
                f"# Confirmation: {status}\n"
                f"{warning}{curl}\n"
            )
            curl_path = directory / "curl.sh"
            curl_path.write_text(curl_text, encoding="utf-8")

            headers = self._request_headers(http_finding)
            if payload and mutating and not any(key.lower() == "content-type" for key in headers):
                headers["Content-Type"] = "application/json" if isinstance(payload, (dict, list)) else "application/x-www-form-urlencoded"
            data_expr = "None"
            if payload and mutating:
                data_expr = repr(json.dumps(payload, ensure_ascii=False) if isinstance(payload, (dict, list)) else str(payload)[:4000])
            py_lines = [
                "#!/usr/bin/env python3",
                f'"""Bounded HTTP reproducer for: {str(finding.get("title") or "finding").replace(chr(34), chr(39))}"""',
                "import sys",
                "import requests",
                "",
                f"URL = {http_url!r}",
                f"METHOD = {method!r}",
                f"HEADERS = {headers!r}",
                f"DATA = {data_expr}",
                "",
                "def main() -> int:",
                "    response = requests.request(",
                "        METHOD, URL, headers=HEADERS, data=DATA, timeout=30,",
                "        allow_redirects=False, verify=False,",
                "    )",
                "    print(f'Status: {response.status_code}')",
                "    print(f'Length: {len(response.content)}')",
                "    print(response.text[:4000])",
                "    return 0",
                "",
                "if __name__ == '__main__':",
                "    raise SystemExit(main())",
                "",
            ]
            py_path = directory / "reproducer.py"
            if warning:
                py_text = "\n".join([py_lines[0], warning.rstrip(), *py_lines[1:]])
            else:
                py_text = "\n".join(py_lines)
            py_path.write_text(py_text, encoding="utf-8")

            raw_request = self._synth_http_request(http_finding)
            (directory / "request.http").write_text(raw_request, encoding="utf-8", newline="")
            (directory / "burp_request.txt").write_text(raw_request, encoding="utf-8", newline="")

            parsed = urlparse(http_url)
            query = []
            if parsed.query:
                from urllib.parse import parse_qsl
                query = [{"key": key, "value": value} for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
            postman_headers = [{"key": k, "value": v, "type": "text"} for k, v in headers.items()]
            request_obj = {
                "method": method,
                "header": postman_headers,
                "url": {
                    "raw": http_url,
                    "protocol": parsed.scheme,
                    "host": parsed.hostname.split(".") if parsed.hostname else [],
                    "port": str(parsed.port) if parsed.port else "",
                    "path": [part for part in parsed.path.split("/") if part],
                    "query": query,
                },
                "description": f"TBHM {status} reproducer. Review authorization and side effects before use.",
            }
            if payload and mutating:
                body = json.dumps(payload, ensure_ascii=False) if isinstance(payload, (dict, list)) else str(payload)
                request_obj["body"] = {"mode": "raw", "raw": body}
            postman = {
                "info": {
                    "name": f"TBHM - {finding.get('title') or 'Finding'}",
                    "description": f"Finding {stable_id or finding.get('id') or 'unassigned'}; confirmation {status}.",
                    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                },
                "item": [{"name": str(finding.get("title") or "Reproduce finding"), "request": request_obj, "response": []}],
            }
            (directory / "postman_collection.json").write_text(
                json.dumps(postman, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            for executable in (curl_path, py_path):
                try:
                    executable.chmod(executable.stat().st_mode | 0o111)
                except OSError:
                    pass
        elif phase.startswith("reverse_") or phase in {"reverse_engineering_tooling", "firmware_reverse_safe", "firmware_tooling_extended"}:
            helper_path = directory / "artifact_provenance.sh"
            if target:
                helper = (
                    "#!/bin/sh\nset -eu\n"
                    f"ARTIFACT={shlex.quote(target)}\n"
                    "printf '%s\\n' 'Static artifact provenance only; the artifact is not executed.'\n"
                    "sha256sum -- \"$ARTIFACT\"\n"
                    "file -- \"$ARTIFACT\"\n"
                )
            else:
                helper = (
                    "#!/bin/sh\nset -eu\n"
                    "printf '%s\\n' 'No local artifact path was recorded. Review finding.json and evidence.'\n"
                )
            helper_path.write_text(helper, encoding="utf-8")
            try:
                helper_path.chmod(helper_path.stat().st_mode | 0o111)
            except OSError:
                pass
            (directory / "POC.txt").write_text(poc + "\n", encoding="utf-8")
        else:
            (directory / "POC.txt").write_text(poc + "\n", encoding="utf-8")

        steps = assessment.get("confirmed_steps") or []
        step_text = "\n".join(f"{index}. {step}" for index, step in enumerate(steps, 1)) or "1. Complete the validation steps documented in the main report."
        reasons = "\n".join(f"- {reason}" for reason in (assessment.get("confirmation_reasons") or [])) or "- Not established."
        prerequisites = "\n".join(f"- {item}" for item in (assessment.get("attack_prerequisites") or [])) or "- Explicit authorization and an in-scope test asset."
        workbook = f"""# Reproduction Workbook - {finding.get('title') or 'Finding'}

**Finding ID:** `{stable_id or finding.get('id') or 'unassigned'}`  
**Confirmation:** {assessment.get('confirmation_status')}  
**Exploitability:** {assessment.get('exploitability_status')}  
**Severity:** {finding.get('severity')}  
**Affected asset:** `{finding.get('url') or finding.get('target') or 'Not recorded'}`

## Authorization and Setup
{prerequisites}

- Confirm the target, account, role, time window, request rate, and write permissions are inside the Rules of Engagement.
- Capture request/response pairs, timestamps, identities/roles, and cleanup evidence.
- For mutating actions, use disposable test data and document rollback before execution.

## Summary
{assessment.get('summary') or finding.get('description') or finding.get('title') or ''}

## Proof of Concept
```text
{poc}
```

## Confirmed Steps to Reproduce / Validation Steps
{step_text}

## Confirmation Basis
{reasons}

## Expected Evidence
{finding.get('evidence') or 'No evidence text was stored; inspect the referenced phase artifact.'}

## Possible Access Path
{assessment.get('attack_scenario') or 'No access path was demonstrated.'}

## Security Impact
{assessment.get('security_impact') or finding.get('impact') or 'Impact requires validation.'}

## Remediation
{assessment.get('remediation') or finding.get('remediation') or 'Remediation requires engineering review.'}

## Cleanup
- Revert test records, uploads, role changes, tokens, callbacks, and temporary accounts created for validation.
- Record the cleanup result and preserve only redacted evidence.

## Retest Criteria
{assessment.get('retest_criteria') or 'The original proof fails, negative controls behave correctly, and no equivalent bypass remains.'}
"""
        (directory / "WORKBOOK.md").write_text(workbook, encoding="utf-8")
        dump = dict(finding)
        dump["display_id"] = stable_id or finding.get("id")
        dump["exploitability_assessment"] = assessment
        (directory / "finding.json").write_text(
            json.dumps(dump, indent=2, default=str, ensure_ascii=False), encoding="utf-8"
        )

    # ------------------------------------------------------------------
    # Methodology audit
    # ------------------------------------------------------------------
    def _write_methodology_audit(self, findings):
        confirmed, supported, leads = self._groups(findings)
        phases = sorted({str(f.get("phase")) for f in findings})
        reverse_count = sum(1 for f in findings if str(f.get("phase", "")).startswith("reverse_"))
        governance = self._governance_summary()
        lifecycle = self._lifecycle_summary()
        rate = self.ctx.profile.get("rate_limit", {}) or {}
        hard = self.ctx.profile.get("hard_limits", {}) or {}
        lines = [
            "# Methodology Audit", "",
            f"**TBHM version:** {VERSION}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Profile:** `{self.ctx.profile['name']}`",
            f"**Targets:** {', '.join(self.ctx.targets)}", "",
            "## Confirmation Standard", "",
            "- CONFIRMED: explicit verifier metadata plus reproducible successful evidence and appropriate negative controls.",
            "- SUPPORTED: meaningful evidence exists but the independent verification chain is incomplete.",
            "- UNCONFIRMED: scanner/import/static/LLM/heuristic observation requiring reproduction.",
            "- Static analysis, imported evidence, and LLM output cannot self-confirm exploitability.",
            "", "## Authorization, Scope, and Safety Controls", "",
            f"- Active probes configured: `{self.ctx.profile.get('active_probes', 'profile-defined')}`",
            f"- Write/mutating requests allowed: `{bool(getattr(self.ctx.args, 'allow_writes', False))}`",
            f"- Effective global request rate: `{rate.get('global_rps', 'not set')}` requests/second",
            f"- Effective per-target rate: `{rate.get('per_target_rps', 'not set')}` requests/second",
            f"- Framework maximum global rate: `{hard.get('max_global_rps', 'not recorded')}`",
            "- Scope allowlists and exclusions are enforced before new discovery requests and at finding/endpoint persistence boundaries where supported.",
            "- Dynamic binary execution is not performed by TBHM; only operator-approved, hash-bound evidence is imported.",
            "", "## Run Results", "",
            f"- Confirmed: {len(confirmed)}",
            f"- Supported: {len(supported)}",
            f"- Unconfirmed: {len(leads)}",
            f"- Reverse-engineering records: {reverse_count}",
            f"- Typed test executions: {lifecycle['test_executions']} — {json.dumps(lifecycle['test_statuses'], sort_keys=True)}",
            f"- Observations / candidates / validation attempts: {lifecycle['observations']} / {lifecycle['candidates']} / {lifecycle['validation_attempts']}",
            f"- Red-team campaigns / operations: {lifecycle['campaigns']} / {lifecycle['operations']}",
            f"- Detection outcomes / cleanup actions: {lifecycle['detection_outcomes']} / {lifecycle['cleanup_actions']}",
            "", "## Phases Producing Evidence", "",
        ]
        lines.extend([f"- `{phase}`" for phase in phases] or ["- None"])
        lines.extend(["", "## Governance and Objective Coverage", ""])
        branch_matrix = self._load_branch_matrix()
        branch_rows = self._branch_status_from_findings(branch_matrix, findings) if branch_matrix else []
        if governance["available"]:
            if governance.get("branches") is not None:
                lines.append(f"- Playbook branches represented: {governance['branches']}")
            if governance.get("subtopics") is not None:
                lines.extend([
                    f"- Objective/subtopic records: {governance['subtopics']}",
                    f"- Subtopics with automated evidence: {governance['tested_subtopics']}",
                    f"- Manual or untested subtopics: {governance['manual_or_untested']}",
                ])
            lines.append("- Coverage status is conservative: Not Tested is never reported as Safe.")
            if governance["files"]:
                lines.append("- Detailed governance artifacts: " + ", ".join(f"`{f}`" for f in governance["files"]))
        else:
            lines.extend([
                "- No branch/objective coverage artifact was generated in this run.",
                "- This commonly means the governance/coverage phases were not selected; missing coverage must not be interpreted as safety.",
            ])
        if branch_rows:
            lines.extend([
                "", "### Detailed Playbook Branch Status", "",
                "The status table is deliberately conservative. Automated evidence means partial coverage only; an untouched branch remains Not Tested and is never labeled Safe.",
                "",
                "| Branch | Title | Automation | Status in this run |",
                "|---|---|---|---|",
            ])
            for branch_id, title, automation, status in branch_rows:
                safe_title = str(title).replace("|", "\\|")
                safe_status = str(status).replace("|", "\\|")
                lines.append(f"| {branch_id} | {safe_title} | {automation} | {safe_status} |")
            tested = sum(1 for _, _, _, status in branch_rows if str(status).startswith("Tested"))
            lines.extend([
                "",
                f"**Coverage summary:** {tested}/{len(branch_rows)} branches have partial automated evidence in this run; {len(branch_rows) - tested} remain manual or untested.",
            ])
        lines.extend([
            "", "## Corporate Intelligence, Standards, Data and Validation Artifacts", "",
        ])
        artifact_specs = [
            ("Toolchain readiness", "01_toolchain_readiness/toolchain_readiness.json"),
            ("OPSEC preflight", "02_opsec_preflight/opsec_preflight.json"),
            ("Engagement objectives", "03_engagement_objectives/engagement_objectives.json"),
            ("Standards/feed readiness", "04_standards_knowledge/standards_knowledge.json"),
            ("Corporate OSINT graph", "10_corporate_osint/corporate_osint_summary.json"),
            ("Identity posture", "18_identity_security_tooling/identity_security_summary.json"),
            ("Authenticated role matrix", "42_authenticated_session_model/authorization_candidates.json"),
            ("Cloud posture", "77_cloud_posture_tooling/cloud_posture_summary.json"),
            ("Vulnerability intelligence", "96_vulnerability_intelligence/vulnerability_intelligence.json"),
            ("Controlled validation", "103_controlled_validation_plane/controlled_validation_summary.json"),
            ("Purple-team validation", "101_purple_team_validation/purple_team_summary.json"),
            ("Data/graph analysis", "105_data_analysis_intelligence/analysis_summary.json"),
            ("AI supervision", "106_ai_supervision/ai_supervision.json"),
        ]
        found_artifacts = 0
        for label, rel in artifact_specs:
            path = self.out / rel
            if path.is_file():
                found_artifacts += 1
                lines.append(f"- **{label}:** `{rel}`")
        if not found_artifacts:
            lines.append("- No capability-depth artifact was generated in this run; this is a coverage limitation, not a pass result.")
        lines.extend([
            "- OSINT-discovered assets remain candidates and are not automatically promoted into active scope.",
            "- EPSS/KEV/OSV, graph correlation, scanner output and local-model advice cannot change confirmation status by themselves.",
            "- C2, phishing, coercion, credential operations, disruptive wireless/OT actions and dynamic malware execution remain external, human-approved workflows with imported evidence only.",
        ])
        lines.extend([
            "", "## Reverse Engineering Methodology", "",
            "1. Rapid identification, canonical artifact hashes, entropy, strings, imports/exports, and capability triage.",
            "2. Headless static analysis through Ghidra, IDA, Radare2/Rizin, capa, and normalized JSON/SARIF imports.",
            "3. Dynamic debugger/instrumentation/sandbox evidence import; TBHM does not execute the sample.",
            "4. Bounded angr CFG/function analysis and import of symbolic/taint evidence without exploit-input synthesis.",
            "5. Correlation by canonical artifact identity followed by the global exploitability assessment.",
            "", "## Manual Validation and Residual Risk", "",
            "- Absence of a finding is not proof of safety.",
            "- Business logic, multi-account authorization, social/physical controls, and environment-specific exploitability often require manual testing.",
            "- Static source or binary indicators do not prove runtime reachability.",
            "- Imported sandbox and scanner reports require provenance and independent reproduction.",
            "- Unavailable tools, blocked routes, authentication gaps, and untested branches remain explicit residual risk.",
            "- The generated report requires qualified human review before external delivery.",
        ])
        (self.out / "METHODOLOGY_AUDIT.md").write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9_-]+", "_", value).strip("_")[:60]
