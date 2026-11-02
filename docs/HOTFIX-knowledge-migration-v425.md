# TBHM 4.2.5 public knowledge and legacy migration build

The first observed source-only AI run persisted two pending scenarios but was incomplete: triage/refutation and report phase warnings were followed by an observer read timeout. The run-scoped Requests guard demonstrably capped a configured 180-second local model request at 30 seconds. It also applied the scanner proxy to the permitted local model service. This build preserves bounded inference timeouts (30–900 seconds) only for the configured loopback model API, and keeps those prompts off the scanner proxy. Ordinary target traffic retains its 30-second cap, response limits, redirect rejection, scope and write policy.

An attempted triage is reused by the report within that process instead of automatically repeating incomplete refutation. Enrichment and refutation errors are logged separately; failed required reviews remain incomplete. The exact historical refutation error is not established without that run's JSON artifact. No validation requirement was relaxed to make the small model pass. The banner now uses the central 4.2.5 identity.

## Public reference catalog

`scripts/knowledge_catalog.py` reads operator-downloaded CVE JSON 5.x records, CWE XML/ZIP and Markdown/text methodologies. Records stay in an independent SQLite/FTS5 catalog in the AI home. Large CVE ingestion makes no model/embedding calls. Reports identify the local snapshot, revision, hashes, selection window, counts and partial/interrupted states. Complete later imports withdraw removed records from retrieval. Rejected/reserved CVEs and deprecated CWE entries cannot become active search references.

Default CVE selection is the union of identifier years in the requested interval and older identifiers published during that interval. Future publication dates are excluded. CNA and ADP data and references are considered; raw source hashes and relative paths remain available for vendor/version checks. Long records have explicitly marked excerpt truncation. FTS queries are literal, bounded, read-only during inference, and time limited. This is lexical public-reference RAG, separate from the existing embedding index over tool source and reviewed project-scoped scenario memory.

Triage records supplied reference identities/hashes. The advisor can include public excerpts in run analysis and next-step proposals. These data cannot change classification, severity, deterministic proof, scope or execution. `--no-ai-knowledge` permits a baseline without this new catalog. It does not turn off existing learning. Existing held-out learning jobs are not silently supplemented with the public catalog; evaluation design must independently address source/answer leakage.

The default catalog is included via a consistent SQLite snapshot in AI backups. An external `--ai-knowledge-db` path requires separate backup. Bulk data and model weights are not redistributed in the release.

## Legacy preservation

`scripts/stage_legacy_backup.py` validates/stages archives into a new private directory, rejecting path escapes, links, special members, collisions and size overruns. It reports counts and audit consistency without executing archived code or merging memory. `scripts/legacy_learning_candidates.py` lists legacy run identifiers and exports selected observations using explicit per-run/project permission. No prior confirmation, severity, approval or training label is transferred. Applying an individually reviewed ingestion plan still creates pending/quarantined scenarios with training disabled.

Source indexing now prunes directories carrying a run database, execution ledger or AI-home marker, and avoids symlink files/directories. This fixes the demonstrated class of arbitrary run-output folders entering a source index. It is not a claim that every possible unmarked sensitive file can be recognized. Keep run outputs and public mirrors outside the code tree.

## Validation

- Full packaged suite: **73/73 script groups**, including **416 unittest cases**. Full result file: `validation-knowledge-v425/full-suite-results.json`.
- Fourteen added cases cover snapshot updates/rejections/deletions, partial imports, publication-window edge cases, bounded/quoted FTS, CWE entity refusal, methodology chunking, advisor/triage consumption, immutable finding authority, portable catalog backup/restore, legacy extraction containment and permission-bound pending exports, local timeout/proxy separation, report reuse, and source-index exclusions.
- Two supplied legacy AI snapshots were copied into isolated homes and opened using the additive schema-6 migration. Counts were preserved and both audit chains remained intact (62 and 1 entries). The private databases are not distributed. Only count/hash inspection summaries are included.
- A finite resource experiment imported **3000 generated synthetic parser records** in approximately **1.038 seconds**, with process peak RSS **32.8 MiB** and a **5,693,440-byte** catalog in this environment. This is not a production-scale throughput or model-accuracy benchmark.
- No full live CVE/CWE mirror could be downloaded from the build environment. Production-source ingestion, Windows GPU inference with this build, and comparative held-out model effectiveness require validation on the operator's system. No improvement in real vulnerability detection accuracy is asserted.
- Existing installer/ParamSpider and environment-independent regression fixes remain included. The existing 145 phase identities and CLI contracts are retained, with two compatible optional knowledge flags added.

The operator guide has source download, migration, project permission, review, comparison, routine restart and backup instructions. Fine-tuning remains optional and unexecuted; persistent reviewed memory, evidence-grounded reasoning, self-evaluation, proposal governance and rollback retain their existing implementation.
