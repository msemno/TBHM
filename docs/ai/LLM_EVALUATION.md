# AI evaluation and evidence boundary

Real Ollama model output, installed model digests, Windows GPU state and the AI
memory database were not supplied as inspectable bytes. Real model security
reasoning remains UNVERIFIED. No training, weight changes or semantic acceptance
claim is made. Retrieval/catalog initialization is not fine-tuning.

The supplied repair's Python source-token/AST grounding and exact quotations,
shell counterclaim guards, typed planner checks and advisory-only proposals were
reconciled into source. The supplied independent acceptance utility is preserved
as scripts/tbhm_ai_acceptance.py. Its executed self-test reports four native
controls, self_test_passed=true, model_quality_evaluated=false and
training_executed=false. This is deliberately not a model-acceptance result.

The 80 supplied repair regression cases cover source grounding, active/commented
and misleading source, missing context, quoted/unquoted shell input, per-finding
response binding, strict JSON schemas, planner cross-field validation, controlled
loopback protocol responses, embeddings, cancellation and durable memory.
These use fixtures/replayed model responses. Raw model claims and rejected
guard warnings remain distinguishable; guards do not convert the model's original
mistake into a correct raw answer or grant findings proof authority.

| Measure | Actual evidence |
|---|---|
| Native active/fixed/commented control correctness | Four acceptance self-test controls |
| Guard and planner behavior | Executable supplied repair tests and local protocol fixtures |
| Raw real-model classification error rate | NOT MEASURED: no live model/response dataset |
| Guard-blocked real-model error rate | NOT MEASURED; fixture rejection behavior is tested |
| Security reasoning accepted | false |
| Generation / embedding transport | Tested against owned loopback protocol fixtures |
| Windows GPU placement | Not observed here; doctor distinguishes API inventory from /api/ps VRAM |
| Retrieval quality improvement | Not claimed; no changed embedding algorithm promoted |
| Full 32,762-row original backlog repaired | Not claimed: original database/cache absent |
| Persistent scenario permissions/isolation | Existing scenario/revocation/independent-label regressions retained |

Runtime maintenance keeps completed vectors on a later failure, checks finite
dimensions, retains pending SQLite rows and refuses incompatible model-space
changes. The strict-reindex helper's full-text character-weighted pooling remains
an explicit maintenance approximation. It requires an independent held-out
Recall@K/MRR comparison before a quality improvement can be asserted.

For live model evaluation, run the included acceptance tool against the actual
locked model and retain raw responses, native labels and guarded decisions. For
Kali endpoint diagnosis, use scripts/tbhm_connection_doctor.py; --probe-inference
is explicit. No supervisor is stopped, listener killed, model pulled or service
exposed by these diagnostics.
