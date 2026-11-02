# TBHM 4.2.5 — validated incremental release

Actual source development from the supplied 4.2.4 release, with the original archive preserved. The master learning specification remains authoritative and the additional scanner roadmap remains open where evidence is incomplete.

## Results

| Measure | 4.2.4 baseline | 4.2.5 |
|---|---:|---:|
| Regression script groups passing | 66 / 66 | 72 / 72 |
| Unit tests in those groups | 352 | 397 |
| Existing CLI signatures retained | 463 | 463; four compatible additions |
| Dispatched phase identities/order | 145 | 145, unchanged |
| Strict proof classes in their declared scope | 5 | 6, including controlled two-tenant BOLA |
| Paired legacy proof vectors unchanged | — | 62 / 62 |
| New BOLA golden/adversarial vectors | unsupported | 42 |

Within the new engine, plain lexical retrieval selects the expected case for 0/8 queries; reviewed-feedback ranking selects it for 8/8. This compares two 4.2.5 configurations, not a real-model comparison against the old binary. The retrieval set deliberately contains ambiguous lexical decoys. This is an actual comparison of two fixed retrieval configurations on that synthetic set. It does not establish real-model effectiveness. The accompanying triage comparison uses an explicitly identified deterministic surrogate solely to exercise evaluation, approval, promotion and rollback. Real-model effectiveness is **UNVERIFIED**; representative field calibration is **DEFERRED**.

## Implemented

- Three reproduced defect areas fixed: private legacy model-context leakage/trust labeling, proposal path traversal/symlink decisions, and core installer acceptance without a manifest. Generic archive and source-tree analysis retain their old contracts.
- Persistent reviewed scenarios in the existing portable AI-plane store, bounded project-scoped RAG, reviewed mistake feedback, hash-bound provenance, expiry/revocation, split hygiene and optional permission-gated training-data export/validation.
- Independent labeled evaluation with full denominators and abstentions, citation validity, classification, probability calibration, resource measurements and failure examples.
- Evidence-backed candidate comparison, existing proposal approval, bounded retrieval-configuration promotion and rollback. No source/proof/scope/weight mutation capability.
- Durable bounded learning queue, one inference worker per store, explicit retry/cancel/recovery, context limits and recorded resource/model failures.
- Seven authenticated captures for owned two-tenant BOLA: owner baseline, challenger mutation, missing-object control, valid challenger-object control, anonymous denial and two repeats. Patched denial is disproved; public, expired, reflection and wrong-tenant fixtures remain inconclusive. Imported labels cannot confirm findings.
- Origin/tenant/object evidence associations that preserve each finding and never assert a verified exploit chain.
- Opt-in current-run scenario capture and a local learning view linked into `OPERATOR.html`, tested together with the final evidence seal. A real version-5 AI database survives the additive migration; restoring its pre-upgrade backup is tested.

## Safety-model finish-line flags

| Flag | Value | Evidence / remaining gap |
|---|---|---|
| `external_scanner_traffic_globally_metered` | false | `TRANSPORT_COVERAGE.csv`: arbitrary online scanner traffic remains outside the shared broker |
| `global_wire_enforcement` | false | Existing broker counts accepted decoded bodies; no universal wire-byte meter |
| `offline_is_os_network_namespace` | false | Tested inherited Linux seccomp boundary retained; no namespace or independent cross-kernel packet-trace claim |
| `all_sensitive_writers_reviewed` | false | `SOURCE_INVENTORY.json` and `NEW_WRITER_REVIEW.csv`; full opaque-format/producer closure remains open |
| `all_vulnerability_classes_auto_confirmable` | false | Six declared controlled contracts; other classes remain inconclusive/manual |

The high-level scanner completion gate intentionally exits 1. The separate incremental release acceptance gate passes. No all-milestone completion claim is made.

## Inspect and reproduce

- `VERIFICATION.json`, `TEST_RESULTS.json`, `COMPATIBILITY.json` and `SECURITY_BEFORE.json` / `SECURITY_AFTER.json` contain measured results.
- `benchmarks/proof_evaluation.json` contains the paired class comparison; `benchmarks/learning_evaluation.json` contains retrieval and surrogate workflow evidence, including resources.
- `PATCH_VALIDATION.json` records a binary-capable source patch applied cleanly to the original baseline and matched byte-for-byte. The patch is `changes.patch`; generated release metadata is supplied in the full distribution.
- `FRESH_INSTALL.json` records clean extraction, an OS-isolated offline installation, installed CLI/integration checks and source-hash correspondence.
- `docs/UPGRADE-v4.2.5.md` and `docs/LEARNING-v4.2.5.md` contain installation, operator plans, schema/provenance, evaluation, promotion/rollback, training-data and resource guidance.
- `ROADMAP.md` retains M1–M8 and precise prerequisites for deferred work.

No training framework, model weight, new runtime dependency, paid service or third-party target test was introduced. Current-process measurements do not substitute for actual Kali/VMware/model benchmarks.
