# TBHM v4.0.0 Validation Report

Release: `4.0.0-unified-safe`. Archive root: `TBHM-v4.0.0-unified-safe`.

## Structural

- Real three-way merge of installer-stability (ancestor), lifecycle/Go-safe
  (control-plane base) and v3.9.7.5-FULL (capability donor). Superset of all
  prior branches: 0 historical files, CLI options, phases, profile entries or
  tool IDs dropped.

## Automated checks (run via `scripts/validate_v4_release.py`)

- Python `compileall`: clean across the tree.
- Import sweep: all core and phase modules import; zero failures.
- Phase coverage: every dispatched phase resolves to a `phases/<name>.py` with
  `run()` (`preflight` is inline by design).
- Manifest: `RELEASE_MANIFEST-v4.0.0.json` verified by `core.package_verifier`;
  tree and ZIP both pass with zero issues.
- Integration suite: 17 of 17 packaged suites pass.

## Post-audit remediations included in this build

- **JS secret → pivot flow (P0):** `js_analysis` now hands live secret
  candidates to `api_key_pivot` through a run-scoped **sealed** vault
  (`core/secret_vault.py`) — encrypted at rest, decrypted only in-process during
  the same run, key shredded at `evidence_finalize`. Findings stay redacted; no
  plaintext secret file is written. Adversarial test confirms ciphertext at rest
  and correct in-run recovery.
- **APK/IPA extraction (P0):** `phases/mobile_scan.py` extracts through
  `core/safe_archive.py`, which blocks path traversal, absolute paths, symlink
  members and decompression bombs (per-file, total-size, file-count and
  compression-ratio caps). Adversarial APK test confirms all hostile members are
  contained while legitimate content extracts.
- **`ranked.json` (P1):** `js_analysis` emits the legacy
  `js_analysis/ranked.json` (url + value score + reasons) alongside the newer
  usefulness index for older plugins/dashboards.
- **Legacy shadow replay (P1):** available behind opt-in `--legacy-shadow-replay`
  in the verify phase; advisory only, never confirms a finding on its own, so the
  strict v4 lifecycle remains the default.
- **Release identity:** runtime version identifiers (reverse/firmware evidence
  `version`, notifier, AI runtime context, installer/repair scripts, feed-updater
  user agent) now derive from `core.version`. "Introduced in vX" provenance
  comments are left historically accurate.
- **API compatibility:** `web_scanner_tooling.import_file_count()` preserves the
  old int return; `finding_class.CONFIRMED_MARKERS` and the `js_analysis`
  numeric caps are retained as unused import-compat constants.
- **Release tooling:** `scripts/build_v4_release_manifest.py` (with `--check`)
  and `scripts/validate_v4_release.py` added. Stale
  `FULL_PACKAGE_SHA256SUMS.txt` removed; `RELEASE_MANIFEST-v4.0.0.json` is the
  authoritative integrity record.

## Intentional behavior differences (not regressions)

- v4 does not confirm findings from confidence, `verified=True` alone, evidence
  keywords or scanner prose. Confirmation requires structured, repeatable proof;
  otherwise findings stay candidate/supported/inconclusive. This is the default
  and is not reverted.

## Environment note

The Go executor (`bin/tbhm-go-executor`, `tooling/go_executor`) is carried
verbatim from the validated lifecycle source; rebuild on Kali with
`scripts/build_go_executor.sh`. Python remains the authoritative fallback.
