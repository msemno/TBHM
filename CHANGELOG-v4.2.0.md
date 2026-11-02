# TBHM 4.2.0 — research-driven evidence and local review

- Extend the delivered 4.1.0 tree; retain all baseline paths, CLI options and 145 dispatched phase names. No new runtime dependency or model weight is bundled.
- Fix Python taint overwrite/control-flow/shell handling, invalid sanitizer assumptions, AST sink association and explicit source analysis coverage. Make soft-404 suppression conservative and run-scoped.
- Add bounded offline OpenAPI 2.0/3.0/3.1 inventory, inherited security/parameters/local refs, operation/security/schema change review and HAR observation inventory. Public documentation alone is INFO.
- Add decoded Android component/permission/SDK/deep-link inventory. Defaults and binary component semantics remain unknown without sufficient input.
- Fix Web3 unbrokered GETs and overbroad prose/hash secret matches. Ordinary read APIs become INFO; add native Slither JSON import as static review leads.
- Add opt-in sequential, grounded local-AI refutation advice. Bind response IDs to batches, reject unsupported citations/verdicts, and store CWE/CVSS as suggestions. Required incomplete AI review fails the run while preserving reports.
- Enforce --chain-simulate; require distinct records on one normalized asset. Remove synthetic high-severity chain findings and recursive attack_path inputs. Export typed evidence and candidate root-cause groups without deleting findings.
- Generate OPERATOR.html and operator_queue.json from persisted evidence and real artifact links. Add explicit labeled-fixture metrics with unresolved states.
- Compose target-free local workflows, correct repository intent attributes, block offline maintenance downloads, and add shared 429/503 host cooldown without retry.
- Include all eight input hashes, 109 applicability decisions, 64 research class boundaries, primary-source corrections, full CLI/phase/catalog reference, upgrade guidance and a deferred roadmap.

Intentional compatibility changes: heuristic chain narratives no longer create extra vulnerability records; model suggestions no longer populate authoritative CWE/CVSS fields; malformed inputs/required AI omissions and incomplete decoded component inventories have explicit partial/error behavior. Earlier reports and code remain in history; current limits are documented in docs/UPGRADE-v4.2.0.md.
