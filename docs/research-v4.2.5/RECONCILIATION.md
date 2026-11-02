# Requirements reconciled before implementation

| Conflict | Applied decision |
|---|---|
| Finish-all milestones vs v4.2.5 learning priority | Master specification controls; implement P0 defects, reviewed learning/evaluation and one complete feasible API proof; preserve M1–M8 |
| Source/behavior freeze vs defect fixes | Only reproduced security defects change legacy behavior; proof behavior is measured, not source-hash frozen |
| Identical database schemas vs learning persistence | Run schema unchanged; AI schema v5→v6 adds six tables and two indexes; old table DDL/rows preserved and rollback backup tested |
| All classes confirmed vs unprovable results | Six scoped contracts only; ambiguous/unsupported evidence remains inconclusive/manual |
| Namespace-specific flag vs equivalent containment | Preserve tested inherited Linux seccomp boundary and describe it precisely; namespace/global-wire flags stay false |
| Milestone completion vs executable evidence | No broad finish-line flag is flipped; the done gate intentionally fails |
| Automatic self-improvement vs deterministic authority | Promote bounded retrieval settings only after comparison plus operator approval; no code/proof/scope/weight mutation |
| Training ambition vs 6 GB VM | Reviewed RAG first; data preparation optional; no mandatory weights/framework/GPU/runtime training |

Baseline dependencies were installed from the supplied hash-locked wheels. An initial extraction lost executable bits; restoring archive permissions brought all 66 legacy groups green before candidate work was accepted. Release-identity assertions were updated to 4.2.5; the assertions and all behavioral test cases were retained.
