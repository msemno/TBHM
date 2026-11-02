# Verification report — TBHM 4.2.0

The authoritative 4.1.0 baseline installed from its bundled locked wheels and passed **41/41** original script groups. The updated candidate passes **44/44** script groups with one worker, including all earlier groups and **40 new unittest methods** in three new script groups. Some methods contain multiple paired/subtest controls; these are not inflated into an overall detector-coverage count.

## What was actually exercised

- Python taint vulnerable/secure/unknown cases, reassignment, branches, finally paths, shadowed conversions, subprocess shell semantics, SQL binding and invalid sanitizers.
- API inheritance/security alternatives, local refs/cycles/remote refs, schema change hashes, HAR host/base-path comparison, malformed/oversized/cyclic inputs and bounded reference expansion.
- Android permissions/signature declaration/inheritance, disabled/exported/unknown components, deep links and existing explicit XML/AAPT boolean controls.
- Web3 ordinary prose/hash negatives, redacted assignment candidates, Slither error/partial/dedup and static-lead persistence.
- Exact graph assets, distinct hypothesis steps, enforced chain flag, preserved source findings and no synthetic severity inflation.
- Strict AI IDs/evidence references/advisory-only stored metadata, bounded source imports/path/symlink/redaction controls and a loopback Ollama-compatible HTTP fixture through the real CLI.
- Real loopback HTTP 429/503 responses and shared broker cooldown without implicit retry. Existing TLS/proxy/redirect/proof/tamper/archive/runner cancellation/Go-backend regressions remain included.
- Combined target-free source/mobile/API/Slither workflow through storage, final reports, operator queue and sealed delivery; malformed input yields a partial report and nonzero run.
- Explicit-label confusion metrics, undefined denominators, missing/unlabeled predictions and input-content resume fingerprints.

## Scope of the result

No real model weights, public scan targets, provider credentials, mobile devices, firmware emulation, production WAF, cloud account or deployed smart contract was exercised. Optional scanner CLI compatibility and real-world precision remain unverified. Browser checks cover search/navigation and desktop/mobile overflow for the static playbook and generated operator page; they are not cross-browser certification.

The 18 deliberately selected artificial taint snippets yielded TP=5, FP=5, FN=4, TN=4 on the baseline and TP=9, FP=0, FN=0, TN=9 on the new engine. This is a regression corpus for the repaired engine, **not** independent project-level accuracy or a whole-report false-positive claim. Regex-only candidates can still remain.

## Timing and test integrity

One intermediate parallel run during concurrent browser/package work exceeded an unchanged 3-second runner assertion at 3.098 seconds. The final candidate suite ran without competing workloads and passed; no timeout assertion was relaxed. Historical tests with literal release-version expectations were updated to 4.2.0; no existing group or behavior assertion was removed.

## Reproduce

```bash
./.venv/bin/python scripts/validate_v4_release.py
./.venv/bin/python scripts/run_tests.py --workers 1
./.venv/bin/python scripts/evaluate_taint_fixtures.py --output-dir /absolute/path/evaluation
```

Per-group results and the execution-content digest are in `VERIFICATION.json`. The final ZIP is separately extracted, installed, integrity/import-validated and run through the complete suite. Final archive hash and results are recorded in the separately delivered verification JSON, avoiding a self-referential archive hash.
