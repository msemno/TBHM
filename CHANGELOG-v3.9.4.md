# CHANGELOG v3.9.4 — AI Control Plane + resume/evidence correctness

## New: AI Control Plane (portable, non-authoritative co-pilot)

A separate control plane (`core/ai_plane/`) — not a scan phase, not a
self-modifying agent. Observes TBHM via structured events, retrieves TBHM's own
source for grounding (RAG), and proposes (never applies) changes. Reuses the
existing loopback-only, redirect-rejecting, secret-redacting LLM boundary.

- **Portable memory** in `$TBHM_AI_HOME` (default `~/.local/share/tbhm-ai`),
  entirely outside the tool tree, so it survives ZIP replacement / laptop moves.
- **SQLite is the source of truth**; the vector index is a rebuildable `.npz`
  cache regenerated from the chunk table. No native deps (numpy brute-force
  cosine); Ollama embeddings with a deterministic fallback so it never blocks.
- **Delta indexer**: hashes the source manifest and re-chunks/re-embeds only
  changed files (AST-aware Python chunking). A new ZIP is a delta, not a relearn.
- **Trust levels T0–T4** with untrusted-data fencing for T3/T4 (prompt-injection
  resistant knowledge channel).
- **Propose-and-approve gate** + **tamper-evident hash-chained audit**. Approval
  archives a proposal; it is never auto-applied to the tree.
- **Run observer** (`--ai-observe`): records phase events, mirrors
  CONFIRMED/SUPPORTED findings into the portable store, writes a whole-run
  advisory, and files lesson *candidates* (never auto-approved).
- **Commands**: `--ai-init`, `--ai-doctor`, `--ai-sync-tool`, `--ai-review-delta`,
  `--ai-migrate`, `--ai-regression-check`, `--ai-backup`, `--ai-restore`,
  `--ai-ingest-resource|note|folder`, `--ai-proposals`, `--ai-approve|reject`,
  `--ai-verify-audit`, `--ai-baseline`, `--ai-index-tool`.
- Installer hook: `INSTALL_OLLAMA=1 INSTALL_AI=1 ./install.sh`.
- New dep: `numpy`. Optional: `tldextract` (bundled fallback works without it).
- Full offline integration test: `integration_test_ai_plane.py` (no model/network).

## Fixes (from the v3.9.3 audit list, verified against source)

- **Resume no longer skips crashed phases.** The main loop marked a phase `done`
  even after it raised, so `--resume` silently skipped failed work. Now success
  vs. failure is tracked; only genuinely completed phases are marked done.
  Added `storage.set_phase_state()`; `is_phase_done()` treats only
  `done`/`succeeded` as skippable. (`tbhm.py`, `core/storage.py`)
- **`llm_run_analysis` now uses the strict confirmation standard.** It selected
  "confirmed" via `finding_class`/`verified`, letting source observations in as
  proven. It now uses the authoritative status resolved from the persisted
  exploitability assessment (or computed via `exploitability.assess()`).
- **`llm_run_analysis` output is schema-validated** before rendering, so a wrong
  type (e.g. `correlations` returned as a string) can no longer crash the
  Markdown renderer.
- **`llm_run_analysis` no longer pollutes the findings set.** It previously saved
  an INFO finding that `finding_class` tagged `confirmed` and the exploitability
  engine surfaced as SUPPORTED. It is now advisory-only (no `save_finding`).
- **INFO records can no longer be promoted to confirmed/SUPPORTED.** Root cause:
  `finding_class.classify()` defaulted INFO-severity records to `confirmed`, and
  `exploitability._confirmation` (which has no INFO special-case) then promoted
  them to SUPPORTED — so coverage summaries from `js_analysis` (endpoints),
  `deep_crawl`, `surface_correlation`, and the local-model advisory leaked into
  "Supported Findings Requiring Final Verification". Fix: `classify()` now returns
  `lead` for any INFO-severity finding. This is a severity-level rule, chosen over
  a phase-level one on purpose: `js_analysis` emits both an INFO coverage record
  AND genuine LOW/MEDIUM hardcoded-secret findings, so a phase-level rule would
  have downgraded the secret findings too. With the severity rule, INFO coverage
  becomes a lead while `js_analysis` secret findings keep their v3.9.3
  classification. (`core/finding_class.py`)
- **Public-suffix scope bug fixed.** `get_root_domains()` used a naive
  last-two-labels heuristic, so `app.example.co.uk` collapsed to `co.uk` and put
  every `*.co.uk` host in scope. Replaced with a registrable-domain resolver
  (uses `tldextract` if present; otherwise a bundled multi-label suffix set).
  Verified: `unrelated.co.uk` stays `unrelated.co.uk`. (`core/targets.py`)

## Not yet addressed in this drop (tracked for follow-up)

The remaining items from the audit — static taint `mitigated` vs
`unsanitized_static_lead` in `core/code_intel.py`; `js_analysis` pre-request
scope enforcement; `deep_crawl` passive-profile gating, 404 handling, and
post-redirect base URL; `surface_correlation` not consuming hosts.txt/urls.txt;
`reverse_correlation` artifact identity; correlated-endpoint exclusion checks —
are real and file/line-referenced in the accompanying review, but are separate
phase-logic patches and are intentionally not bundled with the AI plane change.
