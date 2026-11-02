"""
Phase: fp_review

Writes a human-readable markdown file listing every finding the tool dropped
as a "false positive" so the user can manually re-review. Sometimes:

  - The tool was right (FB pixel, chrome-extension://) → ignore
  - The tool was wrong (legitimate finding suppressed by aggressive filtering)
    → user catches the missed bug

Output: <output_dir>/false_positives_review.md

Each entry shows:
  - WHY the tool dropped it (which filter, what reason)
  - The original finding details
  - A curl command to re-verify manually
  - A verdict checkbox the user can fill in

Also writes JSONL at <output_dir>/dropped_findings.jsonl for programmatic
re-import (e.g. piping into another tool).
"""
from __future__ import annotations
import json
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

from core import curl_reproducer


def run(ctx):
    dropped = ctx.storage.all_dropped()
    if not dropped:
        ctx.log("INFO", "fp_review", "no dropped findings — nothing to review")
        return

    # 1. JSONL — programmatic / re-import
    jsonl_path = ctx.output / "dropped_findings.jsonl"
    with open(jsonl_path, "w") as f:
        for d in dropped:
            # full_finding_json holds the original full record
            try:
                original = json.loads(d.get("full_finding_json") or "{}")
            except Exception:
                original = {}
            row = {
                "dropped_at":  d.get("dropped_at"),
                "drop_reason": d.get("drop_reason"),
                "drop_source": d.get("drop_source"),
                "original":    original,
            }
            f.write(json.dumps(row, default=str) + "\n")

    # 2. Markdown — human review
    md_path = ctx.output / "false_positives_review.md"
    _write_md(dropped, md_path, ctx)

    # 3. FR-106 — clean false_positives.md register (table grouped by reason)
    from collections import Counter
    by_reason = Counter(d.get("drop_reason", "unspecified") for d in dropped)
    lines = ["# False-positive register (FR-106)", "",
             f"_Auto-generated. {len(dropped)} finding(s) suppressed before the report._", "",
             "## Suppression reasons", "",
             "| Count | Reason |", "|---:|---|"]
    for reason, n in by_reason.most_common():
        lines.append(f"| {n} | {reason} |")
    lines += ["", "## Detail", "",
              "| Finding | Scanner/Phase | Target | Auto-drop reason |",
              "|---|---|---|---|"]
    for d in dropped[:500]:
        try:
            original = json.loads(d.get("full_finding_json") or "{}")
        except Exception:
            original = {}
        tgt = (original.get("target") or original.get("url") or original.get("path") or "")[:60]
        title = (d.get("title") or original.get("title") or "")[:70]
        lines.append(f"| {title} | {d.get('drop_source','')}/{d.get('phase','')} "
                     f"| {tgt} | {d.get('drop_reason','')} |")
    (ctx.output / "false_positives.md").write_text("\n".join(lines))

    # per-source breakdown for the log
    from collections import Counter as _C
    src = _C(d.get("drop_source", "?") for d in dropped)
    ctx.log("OK", "fp_review",
            f"fp_review: {len(dropped)} suppressed ("
            + ", ".join(f"{k}={v}" for k, v in src.most_common())
            + f") → false_positives.md + dropped_findings.jsonl")


def _write_md(dropped: list[dict], md_path, ctx):
    # Group by drop reason for easier triage
    by_reason = defaultdict(list)
    for d in dropped:
        by_reason[d.get("drop_reason") or "(unknown)"].append(d)

    lines = []
    lines.append("# False Positives — Manual Review")
    lines.append("")
    lines.append(f"_Scan output: {ctx.output}_  ")
    lines.append(f"_Generated: {datetime.utcnow().isoformat()}Z_")
    lines.append("")
    lines.append(f"The tool **dropped {len(dropped)} candidate finding(s)** "
                 f"because the noise filter classified them as not-worth-reporting "
                 f"(third-party hosts, browser extensions, SPA fallback pages, etc). "
                 f"This file lists them all so you can manually re-review and rescue "
                 f"any real bugs the tool mistakenly suppressed.")
    lines.append("")
    lines.append("## How to use this file")
    lines.append("")
    lines.append("For each entry below:")
    lines.append("")
    lines.append("1. Read the **WHY DROPPED** field — does the reason make sense for this URL?")
    lines.append("2. Run the **curl** command and inspect the response yourself.")
    lines.append("3. If you think the tool was wrong, mark the checkbox `[x] keep` "
                 "and move the entry into your real findings list manually.")
    lines.append("4. If you agree it's noise, mark `[x] confirmed FP` and ignore.")
    lines.append("")
    lines.append("**Quick filters** (Ctrl+F friendly):")
    lines.append("")
    for reason, items in by_reason.items():
        lines.append(f"- `{reason}` — {len(items)} entries")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Per-reason sections
    n = 1
    for reason, items in by_reason.items():
        lines.append(f"## 🔍 Drop reason: `{reason}` ({len(items)} findings)")
        lines.append("")
        # Sort by severity (CRITICAL/HIGH first) so user reviews highest-impact dropped findings first
        items.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                                   "LOW": 3, "INFO": 4}.get(x.get("severity", "INFO"), 5))
        for d in items[:200]:    # cap per reason at 200
            lines.append(f"### {n}. [{d.get('severity', '?')}] {d.get('title', '(no title)')}")
            lines.append("")
            lines.append("- [ ] keep (tool was wrong — this looks real)")
            lines.append("- [ ] confirmed FP (tool was right — ignore)")
            lines.append("")
            lines.append(f"**URL:** `{d.get('url', '(no url)')}`  ")
            lines.append(f"**Method:** `{d.get('method') or 'GET'}`  ")
            lines.append(f"**Phase:** `{d.get('phase', '?')}`  ")
            lines.append(f"**Drop source:** `{d.get('drop_source', '?')}`  ")
            lines.append(f"**Why dropped:** _{d.get('drop_reason', '?')}_")
            lines.append("")
            if d.get("parameter"):
                lines.append(f"**Parameter:** `{d['parameter']}`  ")
            if d.get("payload"):
                lines.append(f"**Payload:** `{d['payload'][:200]}`  ")
            if d.get("evidence"):
                ev = (d["evidence"] or "")[:500].replace("\n", " ")
                lines.append(f"**Evidence:** {ev}")
                lines.append("")

            # Build a curl for the user to re-verify
            try:
                orig = json.loads(d.get("full_finding_json") or "{}")
            except Exception:
                orig = {}
            try:
                curl_cmd = curl_reproducer.build(orig)
            except Exception:
                curl_cmd = f"curl -i -sk '{d.get('url', '')}'"
            if curl_cmd:
                lines.append("**Re-verify:**")
                lines.append("```bash")
                lines.append(curl_cmd)
                lines.append("```")
                lines.append("")
            lines.append("---")
            lines.append("")
            n += 1
        if len(items) > 200:
            lines.append(f"_({len(items) - 200} more entries truncated; "
                          f"see `dropped_findings.jsonl` for all)_")
            lines.append("")

    # Final hints
    lines.append("## What to look for")
    lines.append("")
    lines.append("Most dropped findings ARE legitimate noise. But pay extra attention to:")
    lines.append("")
    lines.append("- **HIGH/CRITICAL findings dropped due to 'third-party host'** — "
                 "if the third party is one YOU own (a forgotten subdomain you control), "
                 "the bug is real.")
    lines.append("- **Findings on hosts that match your target's name with a typo** — "
                 "`atlassain` instead of `atlassian` etc. Often it's a typosquatted "
                 "domain set up by an attacker or a forgotten internal asset.")
    lines.append("- **CDN findings** — sometimes the CDN's misconfiguration is YOUR "
                 "responsibility because YOU configured the CDN.")
    lines.append("")
    lines.append("Anything you decide to keep should be moved into a real bug report "
                 "with a proper reproducer.")

    md_path.write_text("\n".join(lines))
