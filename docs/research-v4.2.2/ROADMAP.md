# Remaining work after 4.2.2

| Priority | Capability | Current status | Exact prerequisite / acceptance |
|---|---|---|---|
| P0 | Global online child/browser/native request and byte ledger | Open; native replay shares existing request policy only | Enforced broker/sandbox adapters, cross-process accounting, denied-origin and over-budget socket/contact tests; fail closed for incompatible scanners |
| P0 | OS offline egress boundary | Implemented and tested on Linux x86-64 through seccomp; not a network namespace | Maintain syscall/ABI coverage, validate additional kernels/platforms before support, add independent packet tracing; no cross-platform claim |
| P0 | Full sensitive writer closure | Partial: text/SQLite delivery sanitizer plus existing writer boundaries | Review all writers and opaque formats, producer lifecycle and binary artifacts; extend canary matrix beyond supported text/SQLite; do not infer privacy from file hashes |
| P0 | All vulnerability-class proof contracts | Still only access control, sensitive exposure and open redirect | Separate semantic verifiers plus live vulnerable/patched/benign/negative/repeat/tamper fixtures for SQLi, XSS, SSRF, SSTI, traversal, deserialization, sessions and CSRF |
| P1 | Blind SSRF confirmation | Existing local OAST is corroboration only | Attributable approved reachable callback infrastructure, request-bound signed correlation, fresh nonce for each role/repeat, scanner/prefetch false-correlation controls |
| P1 | Multi-account API workflows | Implemented for explicit read-only private-object BOLA; broader workflows open | Owned admin/tenant fixtures, function authorization, controlled reversible writes, cleanup assertions and token lifecycle; no inferred production object IDs |
| P1 | Representative detector metrics/calibration | Eight synthetic runtime API cases plus prior proof/taint sets | Licensed independently labeled vulnerable/secure projects and held-out classes; thresholds calibrated without hiding missing predictions |
| P1 | Full standards coverage | Existing narrow WSTG/API/ASVS mapping retained | Versioned requirement-level executed-case links, explicit MASVS/MASTG fixtures; catalogs alone never count as testing |
| P2 | LLM security/quality benchmark | Advisory model flow retained; run-context symlink boundary repaired | Licensed source corpus, fixed grounded output tasks, injection/leak/citation tests and real model latency/RAM/VRAM measurements |
| P3 | Fine-tuning | Deferred; no authorized training dataset supplied | Provenance, reuse rights, consent, deidentification, project-disjoint split, held-out scoring and benefit over deterministic/RAG-only baseline |
| P3 | Multi-model/distributed/mobile/firmware/Web3 runtime expansion | Deferred | Separate lab runtimes, pinned toolchains, measured value and resource budgets; do not ship unconnected wrappers |

The fixed behavior is incremental engineering. This release does not claim to
close every requested high-level-scanner floor. No external target scan,
third-party secret validation, platform submission or training job was run.
