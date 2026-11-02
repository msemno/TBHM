# Implemented and deferred work

| Workstream | Change | Validation |
|---|---|---|
| Supported transport broker | Native/fixed isolated child, atomic request and accepted-body reservations, pacing, cooldown, scope/policy/TLS gates | `tests/test_brokered_http_v423.py`: 7 tests; actual CLI workflow; 5 replayable transport scenarios |
| Delivery privacy | Sealed-snapshot integrity, encoded canaries, bounded ZIP/tar/gzip, opaque/budget uncertainty, enforcement flag | `tests/test_privacy_audit_v423.py`: 6 tests; fail-on-incomplete CLI case; 5 replayable privacy scenarios |
| LLM research inputs | Conservative external-result normalization; rights/hash/split hygiene and revocable retrieval cards | `tests/test_llm_research_v423.py`: 8 tests; combined offline sealed-report workflow |
| Preserved architecture | Protected core hashes/controller AST; narrow guarded hooks; opt-in routing; typed registry | `tests/test_flow_contract_v423.py`: 4 tests; measured compatibility |
| End-to-end integration | Existing reports, observations, sealing and exit semantics | `integration_test_v423_workflows.py`: 3 tests |

The five new groups contain 28 unittest cases. The full suite passes 58 groups
and 312 unittest cases, compared with the 4.2.2 record of 53 groups/284 cases.

No silent fallback permits an unsupported broker driver, a network child in
offline mode, ungraded evaluator confirmation, unreviewed retrieval card, or a
privacy-audit clean verdict when coverage is incomplete. Failures retain review
artifacts through existing phase failure/report behavior.

Global traffic metering, complete sensitive-writer closure, additional proof
classes, admin/tenant/write workflows, representative field calibration, full
standards coverage, real-model benchmarking and training remain deferred.
`ROADMAP.md` records the missing acceptance criteria and conflicting constraints.
