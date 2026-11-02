"""Phase: llm_run_analysis (v3.9.3-new)

Whole-run analysis by the local model. Where local_llm_triage enriches ONE
finding at a time, this phase runs once near the end and reasons over the entire
run: it correlates findings across phases, assesses the overall picture, and
prioritizes what a human should verify next.

Strictly advisory and non-agentic, same safety envelope as local_llm_triage:
  * Loopback-only Ollama; redirects rejected; inputs redacted and bounded.
  * The model CANNOT call tools, run commands, generate payloads, change any
    finding's classification/severity, or promote anything to confirmed. Its
    output is written to a separate advisory report and never mutates findings.
  * Requires --local-llm (off by default). Skips cleanly if the model is absent.

Output:
  llm_analysis/run_analysis.json  structured analysis
  llm_analysis/RUN_ANALYSIS.md    human-readable narrative
"""
from __future__ import annotations

import json
from collections import Counter

from core import redteam_utils as RT
from core.llm_local import LocalLLMConfig, OllamaClient, redact_text, runtime_from_args

_SYSTEM = """You are a defensive security analyst embedded in the TBHM assessment
framework. You are given a REDACTED summary of one authorized security scan:
finding counts by severity/phase, the confirmed findings, and the discovered
surface. Your job is to help the human operator reason about the run.

Return STRICT JSON with exactly these keys:
  "overall_summary": 2-3 sentence plain assessment of what this run found.
  "risk_narrative": a short paragraph on the most important risk theme, grounded
      ONLY in the supplied findings (do not invent findings).
  "correlations": array of {"theme": str, "finding_titles": [str], "why": str} —
      groups of findings that likely relate (same asset, same root cause, or a
      plausible chain). Reference only titles that appear in the input.
  "verify_next": array of {"target": str, "what_to_check": str, "why": str} —
      prioritized manual verification suggestions for the operator. Describe WHAT
      to check, not how to exploit. No payloads, no commands, no bypass steps.
  "coverage_gaps": array of str — surface or checks that look under-tested.

HARD RULES: Do not produce exploit payloads, credential attacks, shell commands,
bypass techniques, persistence, lateral movement, or any offensive instructions.
Do not claim anything is confirmed/exploitable beyond what the input states. If
the input is thin, say so rather than speculating."""


def _build_summary(ctx, findings) -> dict:
    sev = Counter(f.get("severity", "INFO") for f in findings)
    phase = Counter(f.get("phase", "?") for f in findings)
    # v3.9.4: strict confirmation standard. finding_class=="confirmed"/verified
    # is NOT the v3.9.2+ standard and let source observations in as if proven.
    # is_confirmed() reads the persisted exploitability assessment or computes it
    # via exploitability.assess() — the same authoritative rule the report uses.
    from core.ai_plane.findings import is_confirmed
    confirmed = [f for f in findings if is_confirmed(f)]
    # redact + bound each confirmed finding to title/where/impact only
    conf_brief = []
    for f in confirmed[:40]:
        conf_brief.append({
            "title": redact_text(f.get("title", ""), 160),
            "severity": f.get("severity"),
            "where": redact_text(f.get("url") or f.get("target") or "", 160),
            "phase": f.get("phase"),
        })
    # discovered surface counts (no raw URLs beyond a small sample)
    surf = {}
    for rel, key in (("correlation/unified_surface.txt", "correlated_urls"),
                     ("recon/alive.txt", "live_hosts"),
                     ("recon/js_endpoints.txt", "js_endpoints"),
                     ("code/endpoints.txt", "code_endpoints")):
        f = ctx.output / rel
        try:
            surf[key] = len([l for l in ctx.runner.read_lines(f) if l.strip()]) if f.exists() else 0
        except Exception:
            surf[key] = 0
    return {
        "severity_counts": dict(sev),
        "phase_counts": dict(phase),
        "confirmed_count": len(confirmed),
        "confirmed_findings": conf_brief,
        "surface": surf,
        "total_findings": len(findings),
    }


def run(ctx):
    if not getattr(ctx.args, "local_llm", False):
        return
    findings = ctx.storage.all_findings() if hasattr(ctx.storage, "all_findings") else []
    if not findings:
        ctx.log("INFO", "llm_run_analysis", "no findings to analyze")
        return

    try:
        runtime = getattr(ctx, "local_llm_runtime", None) or runtime_from_args(ctx.args)
        client = runtime.client
        ok, why = client.available()
        if not ok:
            ctx.log("WARN", "llm_run_analysis", f"local model unavailable: {why}")
            return
    except Exception as e:
        ctx.log("WARN", "llm_run_analysis", f"local LLM init failed: {e}")
        return

    summary = _build_summary(ctx, findings)
    user = ("Here is the redacted summary of one authorized scan. Analyze it per "
            "your instructions and return the required JSON.\n\n"
            + json.dumps(summary, indent=2))

    try:
        raw = client.chat_json(_SYSTEM, redact_text(user, 12000))
    except Exception as e:
        ctx.log("WARN", "llm_run_analysis", f"local model analysis failed: {e}")
        return
    # v3.9.4: validate types before rendering. Previously a model returning e.g.
    # {"correlations": "none"} made the Markdown loop iterate over characters and
    # call .get() on a str. validate() coerces each field to its schema shape.
    from core.ai_plane.advisor import validate, RUN_ANALYSIS_SCHEMA
    result = validate(raw, RUN_ANALYSIS_SCHEMA)

    out = ctx.output / "llm_analysis"
    out.mkdir(exist_ok=True)
    (out / "run_analysis.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    # human-readable, clearly marked as advisory / non-authoritative
    md = ["# Local Model Run Analysis (advisory)", "",
          "> Generated by the local model over the whole run. Advisory only — it does "
          "not confirm findings, change classifications, or replace verification.", "",
          "## Overall", "", str(result.get("overall_summary", "")), "",
          "## Risk narrative", "", str(result.get("risk_narrative", "")), ""]
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
    (out / "RUN_ANALYSIS.md").write_text("\n".join(md), encoding="utf-8")

    # v3.9.4: do NOT persist this as a finding. It is an informational coverage
    # summary; saving it caused finding_class to tag it 'confirmed' and the
    # exploitability engine to surface it under "Supported Findings Requiring
    # Final Verification". The advisory lives only in llm_analysis/RUN_ANALYSIS.md.
    ctx.log("OK", "llm_run_analysis",
            f"advisory analysis written ({len(corr)} correlation(s), {len(vn)} suggestion(s)) "
            f"— informational, not saved as a finding")
