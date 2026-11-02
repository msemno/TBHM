# TBHM v3.9.7.4 Validation Report

**Release:** `3.9.7.4-universal-reverse`  
**Validation date:** 22 July 2026  
**Status:** Release-candidate validation passed; final archive revalidation is recorded below.

## Validation scope

This validation covers backward compatibility with v3.9.7.3, the repaired
firmware workflow, the new reverse-engineering adapters, release metadata,
static safety boundaries, and clean local execution without a fabricated
network target.

## Static validation

| Check | Result |
|---|---|
| Complete Python bytecode compilation | PASS |
| `install.sh` and `run-bg.sh` syntax | PASS |
| JSON parsing | PASS — 31 files before final manifest generation |
| YAML parsing | PASS — 40 files |
| CLI help generation | PASS |
| Main doctor JSON | PASS |
| Doctor release identity | PASS — `3.9.7.4-universal-reverse` |
| Unrestricted `shell=True` in new firmware/reverse files | PASS — none found |

## Compatibility inventory

| Measure | v3.9.7.3 | v3.9.7.4 | Result |
|---|---:|---:|---|
| Primary CLI options | 319 | 332 | All historical options retained |
| Ordered phases | 129 | 130 | All historical phases retained |
| Added phase | — | `firmware_tooling_extended` | Additive |
| Added CLI options | — | 13 | Additive |

The only historical file absent from the clean release tree is a generated
Python bytecode cache. No historical source, data, profile, documentation,
payload, wordlist, or template file was removed.

## Test matrix

All 15 bundled integration scripts passed. Across those scripts there are 149
named regression tests: 128 class-based unit-test methods and 21 historical
function-style tests, in addition to the custom end-to-end checks performed by
the add-on and AI-plane scripts.

The matrix includes:

- historical CLI, phase, symbol, file and catalog retention;
- reverse fallback behavior;
- report and confirmation-state compatibility;
- installer isolation and dependency handling;
- relative firmware-path extraction;
- binwalk root compatibility;
- failed `unsquashfs` to `sasquatch` fallback;
- extracted-rootfs symlink confinement;
- public certificate versus private-key classification;
- commented service-line handling;
- firmware package/SBOM inventory;
- static update-chain leads;
- binary prioritization;
- EMBA static command construction and emulation approval gate;
- RouterSploit static catalog behavior with no module execution;
- firmware, rootfs, EMBA-import and binary-only local workflows without a fake
  network target.

## Safety validation

- Reverse phases do not execute submitted binaries.
- RouterSploit integration parses source metadata and imports operator-provided
  results only; it never loads or launches RouterSploit modules.
- EMBA is not run unless `--emba` is supplied.
- EMBA emulation additionally requires `--emba-emulation` and
  `--confirm-isolated-execution`.
- Imported findings remain observations or leads until independent validation
  satisfies TBHM confirmation rules.
- Rootfs reads use containment checks and do not follow firmware-controlled
  links into the analyst host.

## External-tool limitation

The internal adapters, commands, parsers, gates and fixtures were tested in this
build environment. A complete live run of every optional third-party platform
— including EMBA, FirmAE, FIRMADYNE, FACT and RouterSploit — was not performed
because those large external environments were not installed here. RouterSploit
execution is intentionally outside the adapter's design.

## Final packaged-archive verification

<!-- FINAL_ARCHIVE_VALIDATION -->
PASS. The release archive was extracted into a new directory and independently
revalidated. All 407 manifest-listed files matched their SHA-256 hashes and
executable-mode declarations. Compilation, shell syntax, JSON/YAML parsing,
CLI help, doctor identity and all 15 integration scripts passed from the clean
extraction.
