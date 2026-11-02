# Deferred development roadmap

This release does not label deferred ideas as implemented. Priorities are relative engineering decisions, not a calendar or payout forecast.

| Priority / workstream | Prerequisites | Acceptance evidence | Resource/maintenance cost |
|---|---|---|---|
| P1 — More strict proof classes | Per-class capture/assertion schemas, benign marker and negative-control design | Vulnerable/secure/inconclusive fixtures, replay/tamper/context rejection, report/CI integration | Medium/high; each class requires separate semantic review |
| P1 — Representative labeled evaluation | Human-reviewed project findings across languages and programs, consented redacted examples | Precision/recall by class and source, uncertainty, held-out data, false-negative review | High ongoing labeling effort; no universal score from 18 snippets |
| P1 — Stateful API authorization workflows | Approved test accounts, tenant/object fixtures, application policy and reversible mutations | Baseline/mutation/negative/repeat captures accepted by strict contracts | High application-specific effort |
| P2 — Origin attribution | Separately scoped IPs, current provider APIs, Host/SNI-aware transport, ownership evidence | Same/different-host and shared-host/CDN controls; no automatic scope expansion | Medium/high; provider costs and changing CDN behavior |
| P2 — Full semantic source analysis | Maintained language parsers, CFG/call graph, context-sensitive models and library summaries | Real-project vulnerable/secure cases including aliases, closures, sanitizers and cross-file flows | High CPU/modeling/maintenance cost |
| P2 — API schema and change semantics | Versioned JSON Schema engine, local-reference resolver, valid operation examples | Official conformance suites, unsupported constructs explicit, no remote fetch by default | Medium; 3.2+ and schema dialect changes need ongoing work |
| P2 — Optional scanner contracts | Pinned tested tool versions and disposable representative projects | Successful output normalization, failure/version/timeout cases and actual runtime results | Medium/high across 507 catalog registrations |
| P2 — Surface monitoring | Stable asset/endpoint snapshot format, reviewed policy change flow, durable scheduler | Added/removed/changed scope-aware assets, resumable jobs, cancellation and no stale authorization | Medium; scheduling alone is not safe monitoring |
| P2 — Android binary components/effective policy | AXML/resource decoder, SDK-aware policy model, permission resource fixtures | Binary/decoded parity; component authorization verified separately on devices | Medium/high; Android version/resource complexity |
| P3 — Mobile runtime and firmware emulation | Lab devices/VMs, tool/service contracts, scoped network isolation, per-target setup | Reproducible lab results, clean/failed/unknown outcomes, resource/cancellation checks | High RAM/disk/time and target-specific maintenance |
| P3 — Web3 compiler/symbolic/fuzzing | Pinned compilers, reviewed build hooks, contract invariants, local chain/fork fixtures | Reproduced invariant failures with negative controls and explicit chain semantics | High; several languages/toolchains are separate projects |
| P3 — Multi-model agents/distributed workers | Measured quality gain, budget enforcement, trusted tools, durable tasks, host hard quotas | Held-out quality/latency/RSS benchmarks, queue/cancellation/isolation tests | High; unsuitable as an unmeasured local default |

Automatic model suppression, automatic scope expansion, generic stealth/IP rotation defaults, unsupported zero-FP/earnings promises and automatic credential-dump/persistence chains are rejected as default release behavior. Existing explicitly governed plan/import capabilities remain within their current contracts.
