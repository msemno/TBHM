# TBHM 4.2.5

A validated incremental source release based on 4.2.4. The master learning specification controls this release; the scanner roadmap remains the subsequent milestone plan.

- Fixed private legacy run artifacts entering an unscoped model context labeled trusted. Generic advice now receives aggregate history counts; reviewed scenario retrieval has explicit project/public-sharing authorization and untrusted-data framing.
- Fixed proposal parent-path and symlink decisions. Proposal approval still archives intent and never applies source code.
- Fixed the core installer accepting a tree without a release manifest. The new `require_manifest` option is enabled by installer/release commands; generic archive and tree-analysis contracts remain compatible.
- Extended the existing portable AI store with six additive tables: scenarios, hash-bound reviews, predictions, frozen evaluations, retrieval configurations and durable learning jobs. Version-5 data survives migration and remains readable by legacy readers.
- Added reviewed scenario ingestion, project-scoped bounded retrieval, mistake-aware ranking, independent labeled evaluation, citation checks, calibrated probability scoring, permission-gated training-data preparation and revocation checks.
- Added tested proposal → approval → promotion → rollback for bounded retrieval configuration only. Baseline configuration, evaluated configuration and frozen source hashes must match. Scanner/proof/scope authority and model weights cannot be promoted through this interface.
- Added a bounded queue (32 outstanding jobs per project; one inference worker per database), explicit retry/cancel/recovery, resource preflight and recorded failures. No training framework or model weight is bundled.
- Added `--ai-learning`, `--approve-ai-learning`, `--ai-learning-output`, and opt-in run capture using `--ai-scenario-context`. Existing 463 argument signatures and 145 phase identities are retained.
- Added a seven-capture controlled two-tenant BOLA read contract. A valid challenger-object read, anonymous denial, missing-object control and two repeats supplement the owner/challenger pair. Only exact reviewed JSON canary objects are supported.

Measured evidence and scope: `docs/research-v4.2.5/VERIFICATION.json`. Real-model effectiveness, representative field calibration, universal transport/wire metering, full writer closure, external OAST, broad injection proofs and full standards execution remain open. `scripts/check_done.py` correctly exits nonzero until the high-level scanner finish line is satisfied.
