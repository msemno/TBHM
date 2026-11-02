# TBHM 4.2.4 → high-level scanner: FINISH-ALL program prompt

## ROLE
Senior application-security engineer extending TBHM, a fail-closed, approval-gated,
import-only bug-bounty/pentest scanner. Python is the authoritative control plane; the Go
executor is optional. EXTEND the delivered TBHM-4.2.4 tree across a sequence of
backward-compatible incremental releases until every gate below is closed. Never rewrite;
every change is additive, proven by fixtures, and recorded in the research ledgers.

## BASELINE FACTS (4.2.4 — do not regress)
- 741 files, 145 dispatched phases (fixed names+ordinals), 463 CLI actions.
- Regression: 66 groups / 352 unittests pass. Keep green every release.
- Strict proof-v2 classes already DONE: access_control, sensitive_data_exposure,
  open_redirect, path_traversal, bfla. (core/strict_classes_v424.py, core/proof_contracts.py,
  core/assertion_engine.py, core/finding_class.py, phases/controlled_validation_plane.py.)
- Transport: core/request_guard.py, core/http_policy.py, core/scoped_http.py,
  core/brokered_http.py (pipe-v1 isolated child), core/pinned_transport.py (DNS-pin, rebind-safe),
  core/oast.py (loopback-only, corroboration not confirmation).
- Offline: core/offline_isolation.py (Linux seccomp, fail-closed).
- Metrics: core/quality_evaluation.py (4-cell + inconclusive + Wilson intervals + split-leakage).
- Flow guards already in place — EXTEND these, do not bypass: knowledge/proof_behavior_v423.json
  (behavioral equivalence of existing proof classes), knowledge/phase_cli_contract_v423.json,
  knowledge/flow_contract_v422.json (now behavioral, not pure hash-freeze).

## DEFINITION OF DONE (the finish line)
Every one of these RELEASE_INFO.safety_model flags flips to true WITH measured evidence,
or is replaced by a precise true sub-statement:
- external_scanner_traffic_globally_metered: true
- global_wire_enforcement: true
- offline_is_os_network_namespace: true (or a stated equivalent OS boundary per platform)
- all_sensitive_writers_reviewed: true
- all_vulnerability_classes_auto_confirmable: true  (for the SCOPED class list in M3–M6)
Plus: held-out (non-synthetic) calibrated metrics exist; WSTG/API-Top-10/ASVS/MASVS mapping is
requirement-level executed-case. Until all are true, release_status stays "incremental".

## REVISED FLOW-PRESERVATION CONTRACT (the one that works — additive, not frozen)
ALLOWED and REQUIRED:
- Proof modules (proof_contracts.py, assertion_engine.py, finding_class.py, strict_classes_*.py)
  MUST grow to add new classes. Guard them with knowledge/proof_behavior_*.json behavioral
  vectors (existing classes produce IDENTICAL verdicts on the golden/benign/missing-control/
  tampered/replayed/unrelated vectors) — NOT source-hash freezes.
- You MAY append new phases AFTER the existing order. Invariant = existing_phase_prefix_unchanged
  (first 145 names+ordinals+behavior identical); appended_phases listed explicitly.
- Additive SQLite columns/tables only; existing DDL stays backward-readable.
FORBIDDEN:
- Removing/renaming any phase or CLI action, or changing an existing argument contract.
- Editing controller dispatch / Runner / Ctx / scope-rate-offline gate / an EXISTING proof
  class's logic in any way that changes its output on current vectors.
- Any path bypassing the scope/rate/cooldown gate, offline filter, pinned transport, or proof-v2.
- New runtime dependency, bundled model weight, or vendor proprietary code.

## HARD CONSTRAINTS (carried, non-negotiable)
LLM advisory only (never authoritative CWE/CVSS; agreement ≠ proof). No scope expansion
(ASN/CIDR/sibling/apex/favicon/cert). No stealth/rotation defaults. No zero-FP/payout claims;
every metric states labeled scope and "unresolved ≠ clean". Extract competitor PATTERNS only,
no vendor runtime/code. Offline = zero external DNS/HTTP from any process. New confirmation
work is approval-gated, owned-asset only, read-only unless an explicit reversible-write contract
with cleanup assertions is approved.

## THE REUSABLE CLASS RECIPE (apply identically to every new strict class)
For each vulnerability class X, deliver as one additive unit:
1. A semantic verifier in the proof pipeline defining failure_conditions +
   negative_control_conditions. HTTP status / reflection / scanner / model NEVER confirm.
2. A capture contract requiring: known-valid baseline + mutation + denied/missing control +
   (class-appropriate) anonymous/cross-actor control + ≥2 distinct repeats, with distinct
   credential fingerprints where identity matters. Blind classes additionally require a bound,
   signed OAST callback (M5 infra).
3. Fixtures: vulnerable, patched/benign-lookalike (FP bait), negative-control, repeat — local,
   reproducible, loopback where network is needed.
4. Proof vectors added to knowledge/proof_behavior_*.json (positive/benign/missing-control/
   tampered/replayed/unrelated-class) — all must pass.
5. A confusion matrix in VERIFICATION.json via core/quality_evaluation.py (4 cells + inconclusive
   + Wilson interval + coverage), scoped-labeled.
6. Ledger rows: GAP_MATRIX.csv, FEATURE_DECISIONS.csv, ROADMAP.md update.
Add X to safety_model.strict_classes only after 1–6 pass.

## MILESTONES (execute in order; one compatible release each)

### M1 — Close containment  → flips external_scanner_traffic_globally_metered, global_wire_enforcement, offline_is_os_network_namespace
- Extend core/brokered_http.py + core/request_guard.py into a cross-process request+BYTE+host
  ledger covering native, pipe-v1, headless browser, AND spawned child scanners. Child scanners
  route through an enforced broker/sandbox or are strict-mode-incompatible (fail closed).
  Count wire bytes, not just decoded body bytes.
- Browser contexts (phases/smart_crawl.py etc.) count + scope-gate through the same ledger.
- Offline: add a true OS network namespace (or per-platform equivalent) on top of the seccomp
  filter; validate additional kernels; add independent packet-trace evidence.
- Accept: loopback test with a child scanner + headless pass shows shared wire-byte counter,
  denied-origin>0 / actual-contact=0 out of scope, over-budget abort before dispatch; packet
  trace shows zero egress under offline on each supported platform.

### M2 — Full sensitive-writer closure  → flips all_sensitive_writers_reviewed
- Inventory EVERY writer and opaque/binary format (producer lifecycle included); route raw
  artifacts into sealed storage; extend the canary matrix beyond text/SQLite to all formats.
  Do not infer privacy from file hashes.
- Files: core/runner.py, core/storage.py, core/evidence_redaction.py, core/evidence_manifest.py,
  core/delivery_privacy_audit.py.
- Accept: planted canaries (all encodings) appear in NO delivered surface; per-writer review
  table complete; mutation tests cover every sealed file.

### M3 — Server-side injection proof classes  (recipe ×)  SQLi, command injection, SSTI, LFI/RFI (extend path_traversal), XXE
- Static (taint) + approved pinned replay confirmation; OAST for blind/error-less variants.
- Accept per class: vulnerable→receipt, benign→inconclusive, tampered/wrong-class→refused;
  confusion matrix published.

### M4 — Client/web proof classes  (recipe ×)  reflected/stored/DOM XSS, CRLF/header injection, CORS misconfig, CSRF
- DOM XSS needs the scope-gated headless pass + execution evidence; CSRF needs state-change proof
  under the reversible-write contract.

### M5 — Attributable OAST + blind classes  → enables blind SSRF/XSS/RCE confirmation
- Extend core/oast.py beyond loopback to an attributable, approved, reachable callback with
  request-bound signed correlation, fresh nonce per role/repeat, and scanner/prefetch
  false-correlation controls. Still approval-gated and scope-bound.
- Accept: blind-SSRF/stored-blind-XSS fixtures confirmed only via bound signed callback; stray/
  prefetch callback rejected; no callback → inconclusive.

### M6 — Broader API authorization flows  (extends core/api_authorization.py)
- Add BOLA(object) alongside existing BFLA, function-level authz, owned admin/tenant fixtures,
  controlled REVERSIBLE writes with cleanup assertions, and token-lifecycle checks. No inferred
  production object IDs; no unapproved writes.
- When M3–M6 scoped classes all pass → flip all_vulnerability_classes_auto_confirmable (scoped).

### M7 — Representative field calibration  (depends on operator-supplied data)
- Ingest licensed, independently labeled vulnerable/secure real projects; calibrate
  fp_engine.py/scoring.py thresholds; report precision/recall/Wilson by class on HELD-OUT data
  without hiding missing predictions. If no licensed data is available, STOP and mark DEFERRED
  with the exact data requirement — never substitute synthetic for field metrics.

### M8 — Full standards coverage
- Requirement-level executed-case links: OWASP WSTG IDs, API Security Top 10 2023 (API1–API10),
  ASVS verification reqs, MASVS/MASTG fixtures. Catalogs never count as testing.
- Files: core/compliance_catalog.py, phases/compliance_coverage.py, knowledge/.

## EXECUTION MODEL
- One backward-compatible incremental release per milestone (or per class batch). Each release:
  regenerate RELEASE_VALIDATION.json + manifest + SBOM to the new version; prove the
  compatibility block (removed_files=[], removed_cli_actions=[],
  changed_existing_argument_signatures=[], existing_phase_prefix_unchanged=true,
  sqlite_schema_equal=true); update VERIFICATION.json, GAP_MATRIX.csv, FEATURE_DECISIONS.csv,
  ROADMAP.md, and a FIXES note.
- Keep the behavioral guards green every release (proof_behavior_*.json, phase_cli_contract_*).
- Any item needing live third-party/paid/field access → STOP, mark DEFERRED with the exact
  prerequisite. Never fabricate evidence or claim field accuracy from synthetic corpora.

## DELIVERABLES per release
(a) additive patch, (b) new fixtures + tests, (c) measured result (confusion matrix / wire-byte
or packet log), (d) ledger rows, (e) regenerated validation/compat/manifest, (f) the updated
safety_model with any flag it flipped and the evidence path.

## OUTPUT FORMAT
Per milestone: the diff, the tests, the measurement, the flipped flag(s) with evidence, and the
compatibility block. End each release by printing the safety_model flag table (name → true/false
→ evidence) so progress toward DONE is visible. When every DONE flag is true, print a final
"high-level-scanner gate closure" summary citing each flag's evidence file.

## DONE CHECK (gate script to ship as scripts/check_done.py)
Assert: all five DONE flags true; every scoped class in strict_classes has fixtures+vectors+
matrix+behavioral-guard; held-out metrics present (or explicitly DEFERRED with reason);
standards mapping is requirement-level. Exit nonzero if any assertion fails.