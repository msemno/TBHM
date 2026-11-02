# TBHM 4.2.1 — bounded engineering / evidence accuracy patch

The 4.2.0 implementation is preserved and extended (not rewritten). All original 450 CLI actions and 145 dispatched phase names remain intact; no breaking SQLite migration is introduced.

- New `core/oast.py`: opt-in local callback service with distinct per-attempt tokens and bounded signed-event export; no auto-confirmation.
- Integrated scoped, explicitly approved loopback laboratory OAST observations into `waf_evasion_ssrf`. Legacy implicit internal/cloud metadata probe dispatch disabled.
- Added standards execution mapping to existing compliance catalog without removing old public functions. Phase completion no longer creates a `tested-clean` category by itself.
- Added proof contract fixture evaluator for three established classes, separate tamper-refusal checks, and explicit unsupported class list.
- Fixed `egress_canary` `--offline` behavior and restored Go binary executable bit in the Linux ZIP.
- New tests and evidence-forward research/integration matrix; release metadata updated.

**Known blockers:** arbitrary child-scanner traffic metering/OS offline namespace; remaining per-class proof verifiers; multi-actor API fixtures; full standards mapping; representative detector metrics; model training and live-bounty performance. No claim of a complete high-level autonomous scanner.
