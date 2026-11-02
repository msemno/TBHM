"""Coverage derived from test executions, including negative and blocked tests."""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict


def run(ctx):
    rows = ctx.storage.all_test_executions()
    out = ctx.output / "evidence" / "test_coverage_ledger"
    out.mkdir(parents=True, exist_ok=True)
    by_status = Counter(str(x.get("status") or "unknown") for x in rows)
    by_phase = defaultdict(Counter)
    for row in rows:
        by_phase[str(row.get("phase") or "unknown")][str(row.get("status") or "unknown")] += 1
    phase_rows = []
    for phase, counts in sorted(by_phase.items()):
        phase_rows.append({"phase": phase, "tests": sum(counts.values()), **dict(counts)})
    fields = sorted({k for row in phase_rows for k in row} or {"phase", "tests"})
    with (out / "coverage_by_phase.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore"); writer.writeheader(); writer.writerows(phase_rows)
    payload = {
        "total_tests": len(rows), "status_counts": dict(by_status), "phase_counts": phase_rows,
        "semantics": {
            "passed": "security invariant held", "failed-security-control": "security invariant was violated",
            "inconclusive": "evidence insufficient", "blocked": "policy/scope/control blocked execution",
            "not-authorized": "authorization absent", "not-applicable": "test not applicable",
            "tool-error": "tool/runtime failure", "manual-review-required": "human decision required",
        },
    }
    (out / "coverage_ledger.json").write_text(json.dumps(payload, indent=2, default=str))
    ctx.log("OK", "test_coverage_ledger", f"{len(rows)} test execution record(s)")
