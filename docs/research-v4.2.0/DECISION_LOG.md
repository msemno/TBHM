# Improvement decision log — 4.2.0

The machine-readable matrix records all 109 grouped decisions with exact sources, baseline/current status, quality, feasibility, priority, code paths and verification. Duplicate recommendations were consolidated; this is not a count of implemented detectors.

## Fix

- G014 — **Advisory LLM suggestions must not become authoritative CWE/CVSS**: Store suggestions inside non-authoritative enrichment rather than filling main classification fields. Keep the general storage API for explicit human/tool enrichment.
- G015 — **Strict response binding to the current batch**: Reject boolean/non-integer, duplicate and foreign IDs; record omissions and required-mode failures.
- G049 — **Sink-specific sanitizer handling and mitigation evidence**: Stop considering arbitrary escape/validate words as sanitizers. Numeric conversion on the whole tracked value is the narrow modeled control; other control contexts remain review leads.
- G050 — **Bind AST flow to the correct sink/CWE/location**: Match the sink line and CWE, retain source file/line/function metadata for context. File-level route reachability is still supporting context, not runtime sink proof.
- G086 — **Frontend prose, hashes and ordinary read RPC are vulnerabilities**: Remove arbitrary 12-word/64-hex secret matches. Require key/seed assignment context and redact values. Read block-number/IPFS-version endpoints become INFO observations.
- G095 — **Co-occurrence, hypothesis and verified path remain different**: Honor --chain-simulate, require distinct records on one asset, list missing preconditions and never claim a verified transition.

## Implement

- G012 — **Refute-first review of candidate findings**: Opt-in sequential counterevidence review with exact finding IDs and supplied evidence references. All verdicts remain advisory.
- G029 — **Measure precision/recall and unresolved coverage honestly**: Explicit labels and predictions, per-category confusion counts, undefined denominators and unresolved/missing predictions.
- G062 — **Offline OpenAPI/Swagger intake with inherited security and parameters**: Extend the existing spec phase. Support bounded Swagger 2.0/OpenAPI 3.0/3.1, local parameter/request-body refs and root/operation security semantics. Never follow remote refs.
- G073 — **Structured exported components, permissions, SDK and deep links**: Permission inheritance, explicit enabled/exported values, provider read/write permissions and URI/path markers. Defaults/resources stay unknown; no blanket exported-component vulnerability.
- G094 — **Canonical assets before correlating findings**: Normalize exact host identity, prefer actual URL host, distinguish local artifacts; never merge sibling domains or infer scope from DNS/certificates.
- G101 — **One operator view derived from persisted state**: Searchable review queue, evidence state, advisory review status, real artifact links and ledger outcome counts. No simulated progress or fake coverage percentage.

## Implement bounded subset

- G013 — **Cross-file source context retrieval**: Read the recorded source location and one-hop local Python imports only. Confine paths, reject symlinks, cap bytes and redact excerpts. This is not whole-project semantic RAG.

## Implement bounded diff

- G063 — **API operation/security/schema change review**: Compare operations, security, parameter/body structures and shared-schema hashes. Full JSON Schema semantic equivalence and breaking-change reasoning are not implemented.

## Implement inventory comparison

- G064 — **Compare declared APIs with HAR observations**: Method/path/declared-host and server-prefix matches only. No token/body copying or replay, no assumption that an observed endpoint was security tested.

## Implement conservative candidates

- G097 — **Evidence-driven deduplication by root cause**: Stable title-independent candidate keys suggest review. They do not delete, consolidate or prove a shared cause; site-wide authorization logic can require manual grouping.

## Implement broker cooldown

- G034 — **429/503 backoff and stop controls**: Shared host cooldown honors bounded Retry-After without retries or long blocking sleeps. Child scanners and browsers retain their own controls.

## Extend existing

- G009 — **SQLite-backed graph instead of mandatory Neo4j**: Use dependency-free typed exports and candidate groups; no new graph service is required. GraphML/STIX support already exists in the entity graph.

## Defer

- G005 — **Distributed scanner workers and task queues**: Requires authenticated worker contracts, cancellation, durable queue semantics and multi-tenant isolation. No evidence of need on the stated local hardware.
- G018 — **Use small and large models as a confidence cascade**: No calibrated routing threshold or measured local accuracy. Sequential single-model advice fits current resource constraints better.
- G019 — **Parallel multi-agent debate/Mixture-of-Agents**: Would multiply memory and latency without an independent quality evaluation. A paper result is not a guarantee for this tool or model.
- G024 — **Inference engines vLLM/SGLang/TensorRT and MTP/speculative decoding**: Research-engine comparisons do not establish a compatible or efficient local deployment. Preserve the existing tested Ollama API boundary.
- G025 — **LLM-generated payloads, scanner templates or automatic attack execution**: No automatic model-to-execution path is added. Existing typed plan/import modes remain available within their current contracts.
- G043 — **Direct Host/SNI origin verification**: Requires separate IP authorization, SNI/Host compatibility, body/certificate controls and negative baselines. A matching favicon or certificate does not prove ownership.
- G075 — **Binary AXML component semantics without a decoder**: Existing AAPT boolean support is retained. Component inventory is explicitly incomplete without decoded XML instead of guessing from strings.
- G088 — **Execute Slither compiler pipeline automatically**: Solidity compilation and arbitrary project build hooks need a disposable environment and pinned toolchain. Import support is not live scanner execution.
- G089 — **Echidna/Medusa/Foundry invariant fuzzing and fork simulation**: Requires contract-specific invariants, compiler versions, RPC/fork fixtures and budgeted harness execution. No generic confirmed oracle or flash-loan detector is claimed.
- G090 — **Mythril/Manticore symbolic contract execution**: State explosion, compiler/chain semantics and validation costs exceed a trustworthy dependency-free release addition.
- G091 — **Solidity/Vyper/Rust/Move/Cairo universal analysis**: Do not substitute generic regex scans for language-specific contract semantics. Slither import covers its supported output only.

## Reject

- G016 — **LLM agreement or a failed reproduction confirms/refutes a bug**: Model agreement is not independent captured proof. Failed reproduction, timeout and unavailable context remain unresolved, not false-positive verdicts.
- G017 — **Automatically discard model-identified false positives**: Conflicts with the master prompt and cautious blueprint. Preserve findings and show counterevidence for operator review.
- G047 — **Universal stealth/IP rotation or aggressive evasion defaults**: Program policy, identification and rate ceilings remain authoritative; there is no evidence that stealth or automatic proxy rotation is generally permitted or improves quality.

