"""Run-lifecycle observer.

Wired into the orchestrator as three touch-points (not an ordered phase):
    on_run_start(ctx)                 - once, before the phase loop
    before_phase / after_phase        - around every phase
    on_run_end(ctx, status)           - once, after report

Design constraints from the architecture doc:
  * It records STRUCTURED events, it does not call the model after every log line.
  * The model is invoked only on triggers: a phase failed, resource pressure
    crossed a threshold, or the final whole-run analysis at the end.
  * It is strictly advisory: it writes to the run's llm_analysis/ dir and to the
    portable AI store. It never mutates findings, severity, confirmation, scope,
    or code.
  * Every method is defensive: any failure here is swallowed so a scan is never
    broken by the co-pilot.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path


def _psutil_pressure() -> dict | None:
    try:
        import psutil
        return {"ram_percent": psutil.virtual_memory().percent,
                "cpu_percent": psutil.cpu_percent(interval=None)}
    except Exception:
        return None


class RunObserver:
    def __init__(self, *, store, embedder, vector_index, advisor, proposal_gate,
                 audit, runtime, log=lambda *a: None):
        self.store = store
        self.embedder = embedder
        self.vindex = vector_index
        self.advisor = advisor
        self.gate = proposal_gate
        self.audit = audit
        self.runtime = runtime
        self.log = log
        self.run_id: int | None = None
        self.run_uid = "run-" + uuid.uuid4().hex[:10]
        self._model_ok = False
        self._ram_threshold = 92.0
        self._cancelled = lambda: False
        self._last_embedding_progress = 0.0

    # -- lifecycle ------------------------------------------------------------
    def on_run_start(self, ctx) -> None:
        try:
            event = getattr(getattr(ctx, "runner", None), "_cancel_event", None)
            self._cancelled = event.is_set if event is not None else lambda: False
            self.vindex.runtime_cancelled = self._cancelled
            args = getattr(ctx, "args", None)
            profile = getattr(ctx, "profile", {}) or {}
            self.run_id = self.store.start_run(
                run_uid=self.run_uid,
                tbhm_version=getattr(ctx, "_ai_tbhm_version", "unknown"),
                profile=profile.get("name") if isinstance(profile, dict) else str(profile),
                intensity=getattr(args, "intensity", "") if args else "",
                target_count=len(getattr(ctx, "targets", []) or []))
            self.audit.record("run.start", self.run_uid,
                              {"targets": len(getattr(ctx, "targets", []) or [])})
            try:
                self._model_ok = self.runtime.client.available()[0] if self.runtime else False
            except Exception:
                self._model_ok = False
            # Load past mistakes so this run is primed to avoid repeating them.
            try:
                ctx._ai_known_mistakes = self.store.known_mistakes(limit=200)
                if ctx._ai_known_mistakes:
                    self.log("INFO", "ai-observer",
                             f"loaded {len(ctx._ai_known_mistakes)} known mistake pattern(s) from prior runs")
            except Exception:
                ctx._ai_known_mistakes = []
            self.log("INFO", "ai-observer",
                     f"run {self.run_uid} registered (model_ready={self._model_ok})")
        except Exception as e:
            self.log("WARN", "ai-observer", f"on_run_start skipped: {e}")

    def before_phase(self, ctx, phase: str) -> None:
        try:
            ctx._ai_current_phase = phase
            ctx._ai_phase_findings_before = self._finding_count(ctx)
            try:
                from core.ai_plane.run_learning import snapshot
                ctx._ai_phase_artifacts_before = snapshot(ctx.output)
            except Exception:
                ctx._ai_phase_artifacts_before = {}
            if self.run_id is not None:
                self.store.add_event(run_id=self.run_id, phase=phase, event="start")
        except Exception:
            pass

    def after_phase(self, ctx, phase: str, ok: bool, elapsed: float) -> None:
        try:
            if self.run_id is None:
                return
            before = getattr(ctx, "_ai_phase_findings_before", 0)
            after = self._finding_count(ctx)
            pressure = _psutil_pressure()
            if not ok:
                self.store.add_event(run_id=self.run_id, phase=phase, event="failed",
                                     detail="phase raised an exception", duration_s=elapsed)
                self.audit.record("phase.failed", phase, {"run": self.run_uid})
                self._maybe_triage(ctx, phase, "phase failed with an exception")
            else:
                self.store.add_event(run_id=self.run_id, phase=phase, event="success",
                                     detail=f"new_findings={after - before}", duration_s=elapsed)
            artifact_summary = {}
            try:
                from core.ai_plane.run_learning import ingest_phase_artifacts
                self.log("INFO", "ai-observer", f"storing sanitized artifacts for {phase}")
                self._last_embedding_progress = time.monotonic()
                self.store.add_event(run_id=self.run_id, phase=phase, event="artifacts_started")
                artifact_summary = ingest_phase_artifacts(
                    store=self.store, vector_index=self.vindex, embedder=self.embedder,
                    run_uid=self.run_uid, phase=phase, output_root=ctx.output,
                    before=getattr(ctx, "_ai_phase_artifacts_before", {}) or {},
                    cancelled=self._cancelled, progress=self._embedding_progress)
                vector = artifact_summary.get("vector", {})
                state = vector.get("status", "unknown")
                if state in {"pending", "deferred"}:
                    self.store.add_event(run_id=self.run_id, phase=phase,
                                         event="vector_"+state, detail=json.dumps(vector))
                self.log("INFO", "ai-observer",
                         f"memory {phase}: stored={artifact_summary.get('indexed_files', 0)} "
                         f"vectors_updated={vector.get('updated_rows', 0)} "
                         f"pending={vector.get('pending_rows', 0)} status={state}")
                if artifact_summary.get("indexed_files"):
                    self.store.add_event(
                        run_id=self.run_id, phase=phase,
                        event="artifacts_indexed" if state == "complete" else "artifacts_stored",
                        detail=json.dumps({**{k: artifact_summary.get(k) for k in
                                             ("indexed_files", "added_chunks", "removed_chunks")},
                                           "vector": vector}),
                        duration_s=0.0)
                elif ok and after == before:
                    self.store.add_event(run_id=self.run_id, phase=phase, event="zero_output",
                                         detail="no new findings or textual artifacts", duration_s=elapsed)
            except Exception as exc:
                self.log("WARN", "ai-observer", f"artifact learning skipped for {phase}: {exc}")
            if pressure and pressure["ram_percent"] >= self._ram_threshold:
                self.store.add_event(run_id=self.run_id, phase=phase, event="pressure",
                                     detail=json.dumps(pressure))
                self.log("WARN", "ai-observer",
                         f"resource pressure after {phase}: RAM {pressure['ram_percent']}%")
        except Exception:
            pass

    def on_run_end(self, ctx, status: str) -> None:
        try:
            if self.run_id is not None:
                self.store.end_run(self.run_id, status)
            self._mirror_findings(ctx)
            self._ingest_run_log(ctx)
            self._final_analysis(ctx)
            self._record_run_mistakes(ctx)
            self._direction_plan(ctx)
            self._learning_review(ctx)
            self._capture_scenarios(ctx)
            self.audit.record("run.end", self.run_uid, {"status": status})
        except Exception as e:
            self.log("WARN", "ai-observer", f"on_run_end skipped: {e}")

    # -- internals ------------------------------------------------------------
    def finalize_status(self, status):
        """Persist the final seal/CI outcome without repeating inference work."""
        if self.run_id is not None:
            self.store.end_run(self.run_id, status)
        self.audit.record('run.finalized', self.run_uid, {'status':status})

    def _embedding_progress(self, done, total):
        now = time.monotonic()
        if done == total or now-self._last_embedding_progress >= 4:
            self.log("INFO", "ai-observer", f"runtime embedding batch: {done}/{total}")
            self._last_embedding_progress = now

    def _capture_scenarios(self, ctx):
        source = getattr(ctx.args, 'ai_scenario_context', None)
        if not source:
            return
        try:
            from core.research_input import load
            from core.ai_plane.scenarios import ScenarioMemory
            from core.ai_plane.scenario_import import capture_findings
            settings = load(source, 64000)
            memory = ScenarioMemory(self.store, self.audit)
            result = capture_findings(memory, ctx, self.run_uid, settings)
            self.store.add_event(run_id=self.run_id, phase='run_learning', event='scenarios_pending', detail=json.dumps(result))
            from core.ai_plane.learning_cli import dashboard
            (ctx.output/'LEARNING.html').write_text(dashboard(memory, settings['project_id']), encoding='utf-8')
            (ctx.output/'learning_overview.json').write_text(json.dumps(memory.overview(settings['project_id']), indent=2)+'\n')
            from core.operator_view import write as operator_view
            operator_view(ctx)
        except Exception as exc:
            from core.ai_plane.sanitizer import scrub
            self.store.add_event(run_id=self.run_id, phase='run_learning', event='learning_failed', detail=scrub(str(exc), 1000))
            self.log('WARN', 'ai-observer', 'Scenario capture failed; the event is recorded for deliberate retry.')

    def _finding_count(self, ctx) -> int:
        try:
            return len(ctx.storage.all_findings()) if hasattr(ctx.storage, "all_findings") else 0
        except Exception:
            return 0

    def _maybe_triage(self, ctx, phase: str, reason: str) -> None:
        """On a failure, record a short structured note. Model call is optional and
        bounded; it produces advisory text only, never a code change on its own."""
        if not self._model_ok:
            return
        # kept intentionally minimal: no per-failure LLM spam during a run.
        return

    def _mirror_findings(self, ctx) -> None:
        """Copy confirmed/supported findings into the portable AI store for
        cross-run learning. Titles/where only; classification preserved."""
        try:
            findings = ctx.storage.all_findings() if hasattr(ctx.storage, "all_findings") else []
        except Exception:
            findings = []
        from core.ai_plane.sanitizer import scrub
        from core.ai_plane.findings import confirmation_status
        for f in findings:
            st = confirmation_status(f)
            if st not in ("CONFIRMED", "SUPPORTED"):
                continue
            try:
                self.store.mirror_finding(
                    run_id=self.run_id, finding_uid=str(f.get("id") or ""),
                    classification=f.get("finding_class"), confirmation_status=st,
                    severity=f.get("severity"), phase=f.get("phase"),
                    title=scrub(f.get("title", ""), 200),
                    where_ref=scrub(f.get("url") or f.get("target") or "", 200),
                    confidence=f.get("confidence"), meta_json="{}")
            except Exception:
                continue

    def _final_analysis(self, ctx) -> None:
        if self._cancelled():
            if self.run_id is not None:
                self.store.add_event(run_id=self.run_id, phase="run_learning",
                                     event="analysis_deferred", detail="scan cancellation requested")
            self.log("INFO", "ai-observer", "final model advisory deferred after cancellation")
            return
        if not self._model_ok:
            self.log("INFO", "ai-observer", "final analysis skipped (model not ready)")
            return
        from core.ai_plane.sanitizer import controlled_state, scrub
        from core.ai_plane.findings import confirmation_status
        try:
            findings = ctx.storage.all_findings() if hasattr(ctx.storage, "all_findings") else []
        except Exception:
            findings = []
        # Strict confirmation standard: only CONFIRMED/SUPPORTED go in, resolved
        # from enrichment or computed via exploitability.assess().
        brief = []
        for f in findings:
            st = confirmation_status(f)
            if st in ("CONFIRMED", "SUPPORTED"):
                brief.append({"title": scrub(f.get("title", ""), 160),
                              "status": st, "severity": f.get("severity"),
                              "where": scrub(f.get("url") or f.get("target") or "", 160),
                              "phase": f.get("phase")})
        try:
            result = self.advisor.analyze_run(controlled_state(ctx), brief[:40])
        except Exception as e:
            self.log("WARN", "ai-observer", f"final analysis failed: {e}")
            return
        out = ctx.output / "llm_analysis"
        out.mkdir(exist_ok=True)
        (out / "ai_plane_run_analysis.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8")
        (out / "AI_PLANE_ANALYSIS.md").write_text(_render_md(result), encoding="utf-8")
        self.log("OK", "ai-observer",
                 f"final advisory written ({len(result.get('correlations', []))} correlations)")

    def _learning_review(self, ctx) -> None:
        """Turn this run's failure patterns into lesson *candidates* (never
        auto-approved). Approval is an operator action."""
        try:
            if self.run_id is None:
                return
            fails = self.store.query(
                "SELECT phase, COUNT(*) AS n FROM phase_events "
                "WHERE run_id=? AND event='failed' GROUP BY phase", (self.run_id,))
            for r in fails:
                cand = (f"Phase '{r['phase']}' failed during run {self.run_uid}. If this "
                        f"recurs across runs, investigate its error handling and inputs "
                        f"before treating its absence of findings as 'clean'.")
                self.store.add_lesson_candidate(
                    candidate=cand, based_on_runs=[self.run_uid],
                    evidence_count=int(r["n"]), confidence=0.4)
        except Exception:
            pass

    def _ingest_run_log(self, ctx) -> None:
        """Ingest this run's own (sanitized) log stream so the co-pilot learns
        from the logs, not just from evidence files."""
        try:
            from core.ai_plane.run_learning import ingest_run_log
            result = ingest_run_log(
                store=self.store, vector_index=self.vindex, embedder=self.embedder,
                run_uid=self.run_uid, output_root=ctx.output,
                cancelled=self._cancelled, progress=self._embedding_progress)
            if result.get("indexed_logs") and self.run_id is not None:
                self.store.add_event(
                    run_id=self.run_id, phase="run_log", event="log_ingested",
                    detail=json.dumps({k: result.get(k) for k in
                                       ("indexed_logs", "added_chunks", "removed_chunks")}))
        except Exception as exc:
            self.log("WARN", "ai-observer", f"run-log ingestion skipped: {exc}")

    def _record_run_mistakes(self, ctx) -> None:
        """Record this run's mistake signatures (failed phases, and findings the
        operator/tool marked false-positive) so future runs don't repeat them.
        Advisory memory only — it never suppresses a finding on its own."""
        try:
            if self.run_id is None:
                return
            # 1) failed phases -> phase_error patterns
            for r in self.store.query(
                    "SELECT phase, COUNT(*) AS n FROM phase_events "
                    "WHERE run_id=? AND event='failed' GROUP BY phase", (self.run_id,)):
                self.store.record_mistake(
                    kind="phase_error", pattern=str(r["phase"]),
                    detail=f"phase failed {r['n']} time(s)", run_uid=self.run_uid)
            # 2) operator-rejected findings -> false_positive patterns
            try:
                from core.ai_plane.findings import confirmation_status
                findings = ctx.storage.all_findings() if hasattr(ctx.storage, "all_findings") else []
            except Exception:
                findings = []
            from core.ai_plane.sanitizer import scrub
            for f in findings:
                fp = (str(f.get("finding_class") or "").lower() in {"false_positive", "rejected", "dropped"}
                      or bool(f.get("false_positive")) or str(f.get("status") or "").lower() == "rejected")
                if not fp:
                    continue
                pattern = f"{f.get('phase','')}:{f.get('cwe') or f.get('finding_class') or 'fp'}"
                self.store.record_mistake(
                    kind="false_positive", pattern=pattern,
                    detail=scrub(f.get("title", ""), 200), run_uid=self.run_uid)
            # 3) Deterministic source-grounding gate warnings become review
            # candidates, never approved lessons or technical verdict labels.
            allowed = {
                'source_quote_not_in_supplied_source',
                'source_counterevidence_requires_exact_source_quote',
                'comment_claim_conflicts_with_python_source_tokens',
                'counterevidence_conflicts_with_model_source_relation',
                'counterclaim_requires_independent_unquoted_shell_review',
            }
            observed = {}
            for row in (getattr(ctx, '_llm_review_quality_warnings', []) or [])[:100]:
                if not isinstance(row, dict) or type(row.get('finding_id')) is not int:
                    continue
                for code in row.get('codes', []) if isinstance(row.get('codes'), list) else []:
                    if isinstance(code, str) and code in allowed:
                        observed.setdefault(code, set()).add(row['finding_id'])
            for code, finding_ids in sorted(observed.items()):
                self.store.record_mistake(
                    kind='model_grounding', pattern='refutation:'+code,
                    detail='A source-grounding check rejected or qualified model advice.',
                    run_uid=self.run_uid)
                candidate = ('Refutation source-grounding warning: '+code+'. '
                             'Review the supplied source and a controlled negative test; '
                             'a model interpretation or absent runtime context is not proof. '
                             'Do not change scanner findings from this candidate.')
                self.store.add_lesson_candidate(
                    candidate=candidate, based_on_runs=[self.run_uid],
                    evidence_count=len(finding_ids), confidence=None)
                self.audit.record('llm.grounding-warning', self.run_uid,
                                  {'code': code, 'finding_ids': sorted(finding_ids),
                                   'lesson_state': 'candidate', 'proof_authority': False})
        except Exception as exc:
            self.log("WARN", "ai-observer", f"mistake-ledger update skipped: {exc}")

    def _direction_plan(self, ctx) -> None:
        """Produce an advisory prioritized next-step plan over past + present, and
        file it as a PENDING proposal for operator approval. Nothing is selected or
        executed; the plan recommends direction only."""
        if self._cancelled():
            if self.run_id is not None:
                self.store.add_event(run_id=self.run_id, phase="run_learning",
                                     event="direction_deferred", detail="scan cancellation requested")
            return
        if not self._model_ok:
            return
        from core.ai_plane.sanitizer import controlled_state, scrub
        from core.ai_plane.findings import confirmation_status
        try:
            findings = ctx.storage.all_findings() if hasattr(ctx.storage, "all_findings") else []
        except Exception:
            findings = []
        brief = []
        for f in findings:
            st = confirmation_status(f)
            if st in ("CONFIRMED", "SUPPORTED"):
                brief.append({"title": scrub(f.get("title", ""), 160), "status": st,
                              "severity": f.get("severity"),
                              "where": scrub(f.get("url") or f.get("target") or "", 160),
                              "phase": f.get("phase")})
        history = {
            "recent_runs": self.store.recent_runs_digest(limit=8),
            "recurring_failures": self.store.recurring_failures(limit=15),
            "cross_run_finding_themes": self.store.cross_run_finding_themes(limit=15),
            "approved_lessons": self.store.approved_lessons_list(limit=40),
            "known_mistakes_to_avoid": self.store.known_mistakes(limit=60),
        }
        try:
            plan = self.advisor.plan_next_steps(controlled_state(ctx), brief[:40], history)
        except Exception as e:
            self.log("WARN", "ai-observer", f"next-step planning failed: {e}")
            return
        out = ctx.output / "llm_analysis"
        out.mkdir(exist_ok=True)
        (out / "ai_plane_next_steps.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
        (out / "NEXT_STEPS.md").write_text(_render_plan_md(plan), encoding="utf-8")
        # File as a PENDING proposal so it enters the human accept/reject workflow.
        try:
            rec_phases = [p.get("phase") for p in plan.get("recommended_next_phases", []) if p.get("phase")]
            skip_phases = [p.get("phase") for p in plan.get("skip_phases", []) if p.get("phase")]
            self.gate.create(
                problem="Advisory next-step engagement direction (recommended phases/targets).",
                evidence=[{"situation": plan.get("situation", "")},
                          {"recommended_next_phases": rec_phases},
                          {"skip_phases": skip_phases},
                          {"avoid_repeating": plan.get("avoid_repeating", [])}],
                affected_files=[],  # direction plan: no source patch
                patch_text="",
                expected_benefit=plan.get("operator_decision_required", "Operator chooses the next direction."),
                risks=["Advisory only. Selecting phases requires explicit operator opt-in (--ai-apply-plan)."])
            self.log("OK", "ai-observer",
                     f"next-step plan written; filed as a pending proposal ({len(rec_phases)} recommended phase(s))")
        except Exception as e:
            self.log("WARN", "ai-observer", f"could not file direction proposal: {e}")


def _render_plan_md(plan: dict) -> str:
    md = ["# AI Co-pilot — Next-Step Plan (advisory, operator-gated)", "",
          "> Advisory direction over past + present runs. It recommends what to look at "
          "next; it selects nothing and runs nothing. Apply only via explicit operator "
          "opt-in (`--ai-apply-plan`) after approving the proposal.", "",
          "## Situation", "", plan.get("situation", ""), ""]
    pt = plan.get("prioritized_targets") or []
    if pt:
        md += ["## Prioritized targets", ""]
        for t in pt:
            md.append(f"- **{t.get('target','')}** ({t.get('value','')}) — {t.get('why','')}")
        md.append("")
    rec = plan.get("recommended_next_phases") or []
    if rec:
        md += ["## Recommended next phases", ""]
        for p in rec:
            md.append(f"- `{p.get('phase','')}` — {p.get('why','')}")
        md.append("")
    skip = plan.get("skip_phases") or []
    if skip:
        md += ["## Phases to skip", ""]
        for p in skip:
            md.append(f"- `{p.get('phase','')}` — {p.get('why','')}")
        md.append("")
    avoid = plan.get("avoid_repeating") or []
    if avoid:
        md += ["## Avoid repeating (from the mistake ledger)", ""] + [f"- {a}" for a in avoid] + [""]
    if plan.get("operator_decision_required"):
        md += ["## Operator decision required", "", plan.get("operator_decision_required", "")]
    return "\n".join(md)


def _render_md(result: dict) -> str:
    md = ["# AI Co-pilot — Whole-Run Analysis (advisory)", "",
          "> Produced by the local co-pilot over the whole run. Advisory only. It does "
          "not confirm findings, change classifications, scope, or code.", "",
          "## Overall", "", result.get("overall_summary", ""), "",
          "## Risk narrative", "", result.get("risk_narrative", ""), ""]
    corr = result.get("correlations") or []
    if corr:
        md += ["## Correlations", ""]
        for c in corr:
            md.append(f"- **{c.get('theme','')}** — {c.get('why','')}")
            for t in (c.get("finding_titles") or [])[:8]:
                md.append(f"    - {t}")
        md.append("")
    vn = result.get("verify_next") or []
    if vn:
        md += ["## Suggested verification (operator judgement required)", ""]
        for v in vn:
            md.append(f"- **{v.get('target','')}** — {v.get('what_to_check','')}  \n  _why:_ {v.get('why','')}")
        md.append("")
    gaps = result.get("coverage_gaps") or []
    if gaps:
        md += ["## Possible coverage gaps", ""] + [f"- {g}" for g in gaps]
    return "\n".join(md)
