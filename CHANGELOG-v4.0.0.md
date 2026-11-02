# TBHM v4.0.0 — Unified Safe Release

Release identity: `4.0.0-unified-safe`.

## Merge lineage

- **Common ancestor:** v3.9.7.3 installer-stability.
- **Control-plane base:** v3.9.7.3 lifecycle / Go-safe upgrade (authoritative).
- **Capability donor:** v3.9.7.5-FULL (which already subsumes the v3.9.7.4
  firmware-analysis branch).

This is a real three-way merge against the shared ancestor, not a branch
selection. Where both branches modified the same file, changes were combined so
that neither the lifecycle safety behaviour nor the newer capabilities were lost.

## Preserved from the lifecycle control plane

- Strict lead / supported / confirmed evidence classifier; nothing is promoted to
  confirmed without an explicit verification result.
- Negative-control and repeated-proof requirements; strict finding validation and
  a test-coverage ledger.
- Program-policy, identity-plan and workflow-plan bug-bounty workspace
  (targetless: reviewed local inputs only).
- Red-team campaign control: campaign/operation/detection/cleanup register with
  fail-closed approval binding.
- Optional argv-only Go subprocess executor with Python authoritative fallback.
- Bounded output capture (`capture_mode` tail/full/none, `stdout_path` streaming)
  and Linux process-group termination.
- Secret redaction in logs; non-authoritative AI control plane.

## Preserved and restored from the capability donor

- Firmware container identification, validated unblob→binwalk→SquashFS extraction
  chain, pre-extracted rootfs support and confined static rootfs audit.
- ELF inventory, architecture and hardening review; firmware account/key/service
  and web/CGI review; EMBA and RouterSploit safe import boundaries.
- Universal normalized decompiler/P-code reverse IR; bounded interprocedural
  taint; JavaScript→Java/Kotlin→JNI→native cross-language correlation.
- Explicitly gated disposable container/QEMU sandbox lifecycle; runtime→function
  dynamic mapping; bounded symbolic/concolic input proposals; fuzz-harness
  proposals; crash import, reproduction planning, deduplication and minimization.
- Function-level binary diff; content-addressed campaign deduplication;
  UEFI/driver/protocol/hardware family analysis.
- Complete in-scope JavaScript analysis with source-map recovery; ZAP/import URL
  feedback into the JavaScript phase; package verification and release manifest.

## Merge resolutions of note

- `tbhm.py` — unioned CLI flags, `PHASE_ORDER`, `_LOCAL_ONLY_PHASES`,
  `direct_phase_sets` and `local_inputs` so both the campaign/workflow flags and
  the reverse/firmware flags drive targetless phase selection.
- `finding_class.py` — kept the stricter lifecycle classifier and added
  `reverse_dynamic_evidence` and `firmware_tooling_extended` to the observation
  set so their output is treated as leads, not auto-confirmed.
- `firmware_reverse_safe.py` — took the deep firmware implementation and
  re-applied the lifecycle bounded-output patterns (streaming strings to disk,
  `capture_mode="tail"` on binwalk) so multi-gigabyte images are never buffered
  whole in memory.
- `web_scanner_tooling.py` — took the URL/JavaScript feedback rewrite and
  re-applied the lifecycle `capture_mode="tail"` bound on the ZAP baseline call.

## AI co-pilot — cross-run learning (advisory, human-gated)

The portable AI control plane (database outside the tool tree, survives ZIP
replacement and upgrades) is now on by default and learns every run:

- Learns from the logs: the run's own log stream is ingested each run, sanitized
  and secret-redacted before storage.
- Cross-run memory: past runs, recurring failures, finding themes and approved
  lessons persist outside the tree. A pre-v4 home migrates in place with no data
  loss, so past + present are always available.
- Prioritized next-step plan: at end of run it writes an advisory `NEXT_STEPS.md`
  and files it as a PENDING proposal — direction only; it selects and runs nothing.
- Mistake / false-positive ledger: failed phases and flagged false positives are
  recorded and surfaced at the start of the next run. It never silently suppresses
  a finding; active suppression stays a separate operator-approved lesson.
- Operator-gated application: `--ai-apply-plan` narrows a run to an APPROVED plan's
  phases, only among phases the profile already authorizes — never expands scope,
  adds unsafe phases, or auto-applies. Approval alone does not apply
  (`applied: false`). New commands: `--ai-mistakes`, `--ai-lesson-approve`,
  `--ai-apply-plan`.

The co-pilot remains non-authoritative: it never sets confirmation or severity,
never changes scope or code, never calls tools or emits payloads; its model runs
loopback-only with redaction. With no local model it still records events, ingests
logs and updates the ledger — only model-written advisories are skipped.

## Safety boundaries (unchanged)

No automatic exploitation, credential theft, persistence, C2 startup, destructive
testing, AI-directed shell execution or uncontrolled active RouterSploit execution
is introduced by this merge. High-impact reverse, firmware and red-team operations
remain bounded, import-only and approval-gated; Python remains the authoritative,
fail-closed control plane.

## Validation

- `python -m compileall` clean across the tree.
- All 17 packaged integration tests pass.
- `tbhm.py --help` and `--list-profiles` succeed; all 7 profiles load.
- 90 core modules and 145 phase modules import without cross-branch breakage.
- Every dispatched phase resolves to a `phases/<name>.py` module with `run()`.
- `RELEASE_MANIFEST-v4.0.0.json` regenerated; package verification passes against
  the v4 tree.
