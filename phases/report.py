"""Phase: report - generates layered reports and per-finding reproducer kits."""
from __future__ import annotations

from core.reporter import Reporter


def _ensure_local_llm_enrichment(ctx) -> None:
    """Run integrated local triage before reporting when requested."""
    cancelled = getattr(getattr(ctx, 'runner', None), '_cancel_event', None)
    if cancelled is not None and cancelled.is_set():
        ctx.log('INFO', 'report', 'model enrichment deferred after cancellation; writing partial report')
        return
    if not getattr(ctx.args, "local_llm", False):
        return
    if ctx.storage.is_phase_done("local_llm_triage"):
        return
    if getattr(ctx, '_local_llm_triage_attempted', False):
        ctx.log('INFO', 'report', 'using the local-LLM artifacts from this run; unresolved reviews remain incomplete')
        return
    try:
        from phases import local_llm_triage
        ctx.log("INFO", "report", "running integrated local-LLM enrichment before report generation")
        local_llm_triage.run(ctx)
        ledger = getattr(ctx, 'execution_ledger', None)
        if not getattr(ctx, 'phase_state', {}).get('local_llm_required_failed') and not (ledger and ledger.issues(ledger.current_phase)):
            ctx.storage.mark_phase_done("local_llm_triage")
    except Exception as exc:
        ctx.log("WARN", "report", f"integrated local-LLM enrichment failed: {exc}")
        if getattr(ctx.args, "local_llm_required", False):
            ctx.phase_state["local_llm_required_failed"] = str(exc)


def _ensure_exploitability_assessment(ctx) -> None:
    """Ensure every finding has PoC, confirmation, steps, impact and remediation."""
    if getattr(ctx.args, "no_exploitability_assessment", False):
        return
    # Re-run idempotently at report time because phases after the scheduled
    # assessment can add late findings (coverage, playbook, summaries, etc.).
    # This guarantees the final renderer sees an assessment for every record.
    try:
        from phases import exploitability_assessment
        ctx.log("INFO", "report", "running evidence-grounded exploitability assessment before report generation")
        exploitability_assessment.run(ctx)
        ctx.storage.mark_phase_done("exploitability_assessment")
    except Exception as exc:
        ctx.log("WARN", "report", f"exploitability assessment failed: {exc}")


def run(ctx):
    _ensure_local_llm_enrichment(ctx)
    _ensure_exploitability_assessment(ctx)
    reporter = Reporter(ctx)
    reporter.write_all()
    from core.operator_view import write as write_operator_view
    write_operator_view(ctx)
    final_html = ctx.output/'REPORT_final.html'
    if final_html.is_file():
        text = final_html.read_text(encoding='utf-8')
        link = '<p><a href="OPERATOR.html">Open operator evidence review</a></p>'
        final_html.write_text(text.replace('</body>', link+'</body>') if '</body>' in text else text+link, encoding='utf-8')
    ctx.log("OK", "report", f"reports written to {ctx.output}")
    ctx.log("OK", "report", "  - REPORT_final.md / REPORT_final.html")
    ctx.log("OK", "report", "  - REPORT_executive.md")
    ctx.log("OK", "report", "  - REPORT_manager.md")
    ctx.log("OK", "report", "  - REPORT_developer.md")
    ctx.log("OK", "report", "  - REPORT_defender.md")
    ctx.log("OK", "report", "  - REPORT_confirmed.md / REPORT_leads.md")
    ctx.log("OK", "report", "  - METHODOLOGY_AUDIT.md")
    ctx.log("OK", "report", "  - report.json / report.csv / report.sarif")
    ctx.log('OK', 'report', '  - OPERATOR.html / operator_queue.json / evidence_graph.json')
