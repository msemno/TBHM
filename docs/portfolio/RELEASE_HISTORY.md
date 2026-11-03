# TBHM release evolution (documented highlights)

This page maps historical and current *documented* functionality. It is not a full changelog of every feature, nor a claim that all historical features were developed or tested by the current repository owner.

## Earlier capabilities retained by the 4.2.x line

The 4.2.7 publication README describes inherited offline OpenAPI/HAR observation analysis, baseline differences, permission-aware Android manifest inventory, offline Slither JSON import, conservative taint/soft-404 handling, gated same-asset chain hypotheses, shared 429/503 cooldown behavior, `OPERATOR.html`, a persisted review queue, typed evidence export and labeled-fixture metrics. Its existing 4.2.0 docs contain fuller rationale.

## 4.2.7: release-specific engineering themes

| Theme | Described change | Why it matters |
| --- | --- | --- |
| Checkov and njsscan adapters | Distinguish failed result records from passed/diagnostic metadata | Prevent result-channel pollution |
| API discovery / anonymous routes | Avoid declaring vulnerabilities from HTTP success, size or route name alone | Reduce overconfident reports |
| Source analysis | Distinguish declarations/inventory from reachable executable behavior | Reduce heuristic false positives |
| Model transport | Separate inference budgets and apply bounded calls / failure circuits | Model availability must not dominate target time |
| Network authorization | Explicit IP/CIDR scope and packet-rate controls for port scans | Prevent hostname-based authority confusion |
| Dispatcher | Optional bounded model-prioritized phase windows | Keep operational scheduling auditable |
| Capability matching | Handle missing and compound inputs explicitly | Missing inputs remain visible as gaps |
| Compatibility | Preserve explicit model selection and verified local dependency identity | Avoid silent setup drift |

The review calls these **incremental directions**, not universal guarantees. Read `docs/review-v4.2.7/ROOT_CAUSE_REPORT.md` and the release's current architecture guide.

## Next milestones (proposed, not completed)

- Add verified, public, synthetic demo scenarios with sanitized sample output.
- Add CI and security-check workflow with explicit pass/fail evidence.
- Produce real-model held-out evaluation and detailed latency/false-positive data.
- Expand scope and browser containment tests for each supported external integration.
- Build a published contribution/provenance table backed by commits.

Do not treat this aspirational list as released functionality.
