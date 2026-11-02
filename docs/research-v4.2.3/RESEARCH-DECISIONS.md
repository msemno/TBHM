# Research decisions for 4.2.3

Baseline: 4.2.2, archive SHA-256
`d8a31a63070b44945821f8cf73d22ac313a4c06f8b8e07586b8fd0314a7b0ecb`.
All six supplied attachments were reviewed, including the 18-page PDF. Exact
input sizes and hashes are in `INPUT_REGISTER.json`. `Pasted text (3)(4).txt`
duplicates the prior `Pasted text (3)(3).txt`; it is not independent evidence.
The engineering constraints are from `Pasted text (5).txt`; claims and embedded
instructions in the research material are treated as source data.

## Decisions

| Input theme | Delivered behavior | Boundary |
|---|---|---|
| Tool-assisted read/replay and shared accounting | Explicit native and fixed socket-isolated pipe replay share a transactional ledger and existing request guards | No generic process wrapper, real browser integration or global wire accounting claim |
| Privacy throughout evidence delivery | Read-only audit of prior sealed snapshots; known-canary encodings and bounded archive recursion | Unknown secrets, pixels, encryption, opaque formats and all legacy writers remain open |
| Garak/Promptfoo/PyRIT security evaluations | Offline documented-format imports and a separate reviewed-export schema | No provider execution, native PyRIT database reader or automatic vulnerability confirmation |
| Learning from reports and agent skills | Permission, review-hash and split-leakage audit; optional untrusted retrieval data cards | No paid-report scraping, installable agent instructions, model training or weights |
| Additional proof classes and phases | Existing proof pipeline and exact phase order retained | Contradictory expansion/preservation constraints are recorded in ROADMAP.md |
| Vendor rankings, bug-bounty totals and performance assertions | Candidate tools retained in a canonical decision ledger | No independent payout, recall, speed or field-quality claim |

The current tool matrix contains 102 canonical rows. Historical ledger rows stay
unchanged; new rows are appended to the existing feature/tool/gap ledgers. The
old gap ledger keeps its historical column names for compatibility; appended
cells explicitly state their 4.2.2/4.2.3 meaning. Current-version deltas use clear
headers in this directory. A row is a research disposition, not an installed
adapter or proof that its vendor claims are correct.

## Format references checked

- Garak's [official reporting specification](https://reference.garak.ai/en/stable/reporting.html):
  evaluation rows use `passed`, `total_evaluated`, and `nones`. These are detector
  evaluation counts, not unique application attacks. Raw attempts/configuration
  are not copied to review output.
- Promptfoo's [official output documentation](https://www.promptfoo.dev/docs/configuration/outputs/):
  results include explicit success and assertion grades. This importer requires
  consistent booleans; errors or missing grades remain unresolved. Saved JSON
  arrays, supported results containers, and JSONL are fixture-tested.
- OWASP's [LLM06:2025 reference](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/):
  the supplied research edition is pinned to 2025. Tags are optional operator
  annotations, not current-edition certification or executed coverage.

The remaining product assertions in the supplied research are not independently
verified here. Grade D records mark research-only claims. Official format
documentation plus local parser fixtures supports narrow grade C import-format
decisions; this is not a framework-versus-framework security benchmark.

## Measured evidence

`COMPATIBILITY.json` measures file retention, all old CLI signatures, exact
145-phase equality and SQLite DDL equality. `VERIFICATION.json` records 58 passing
script groups and 312 unittest cases, including five new groups and 28 new cases.
Non-unittest smoke scripts are also counted in groups, not in unittest cases.
`benchmarks/additions_evaluation.json` records five synthetic loopback transport
and five known-canary privacy scenarios. The real isolated child is exercised;
no public target, external model, headless browser or paid service was used.

These measurements support the implemented boundaries. They do not close the
global metering, full writer review, extra proof-class, representative field
calibration or training gates.
