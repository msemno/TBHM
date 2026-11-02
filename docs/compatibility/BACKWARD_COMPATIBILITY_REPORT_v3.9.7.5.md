# TBHM v3.9.7.5 Backward-Compatibility Report

## Verdict

v3.9.7.5 is source- and CLI-additive against the supplied v3.9.7.3 and v3.9.7.4 FULL archives. The comparison found no removed packaged path, CLI option string, phase name or public top-level Python class/function.

One behavior is intentionally tightened for safety: EMBA emulation/full may no longer execute directly on the analyst host after confirmation alone. It requires an already-present TBHM sandbox image plus explicit isolated-execution confirmation. Static/SBOM host mode remains available.

## Comparison summary

| Baseline | Files | Candidate files at comparison | CLI option strings | Candidate CLI strings | Phases | Candidate phases | Removed files/options/phases |
|---|---:|---:|---:|---:|---:|---:|---|
| v3.9.7.3 | 395 | 448 | 319 | 405 | 129 | 141 | 0 / 0 / 0 |
| v3.9.7.4 FULL | 416 | 448 | 332 | 405 | 130 | 141 | 0 / 0 / 0 |

## New phases relative to v3.9.7.4 FULL

- `package_verification`
- `reverse_campaign_index`
- `reverse_crash_triage`
- `reverse_cross_language`
- `reverse_diff_analysis`
- `reverse_dynamic_mapping`
- `reverse_family_analysis`
- `reverse_fuzzing`
- `reverse_ir_analysis`
- `reverse_sandbox_analysis`
- `reverse_taint_analysis`

## Compatibility methodology

- ZIP member paths were normalized below each archive root.
- Generated caches and bytecode were excluded from the candidate inventory.
- `argparse.add_argument()` option strings were compared through Python AST parsing.
- `PHASE_ORDER` values were parsed from `tbhm.py`.
- Public top-level Python functions and classes were compared for every common Python path.
- Modified files were byte-hash compared.
- The complete bundled regression suite was then executed.

## External-tool compatibility

Ghidra, angr, EMBA, QEMU, UEFI, mobile and protocol frameworks remain optional external runtimes. Their absence does not remove the dependency-free fallback, evidence imports or static family inventory. RouterSploit remains catalog/import-only.

## Exact machine-readable comparison

See `docs/compatibility/BACKWARD_COMPATIBILITY_COMPARISON_v3.9.7.5.json`.
