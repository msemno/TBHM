# TBHM v3.9.7.3 — Installer Stability

Release date: 2026-07-19

## Purpose

This release preserves the v3.9.7.2 scanning, phase, reporting, evidence and compatibility behavior while repairing the full installation path observed on Kali Linux with Python 3.13.

## Fixed

- Corrected the installer/runtime version banner.
- Isolated every optional Python application in its own virtual environment under `TBHM_TOOL_HOME`.
- Removed optional-tool installation into the shared distro/user Python environment.
- Added explicit interpreter gates for Giskard, ModelScan, whylogs and SuzieQ.
- Corrected SuzieQ executable discovery and whylogs library classification.
- Made a missing declared CLI after package installation a truthful failure.
- Moved npm global packages to the user-owned `~/.local` prefix.
- Added `--locked` to Cargo installation recipes.
- Disabled the archived/invalid kubeaudit auto-install recipe while retaining compatibility metadata.
- Corrected apt package-state detection to require `install ok installed`.
- Added apt repository preflight, dependency simulation, bounded transient retry, IPv4 fallback and explicit unavailable/incompatible statuses.
- Isolated Playwright and added system-Chromium fallback support.
- Added an official-script Syft path into `~/.local/bin`.
- Corrected Ruby gem and Composer executable exposure.
- Replaced the privileged TruffleHog curl-to-shell pipeline with a bounded temporary-file installation into `~/.local/bin`.
- Added isolated runtime bridges for angr, Playwright and DuckDB.
- Added `scripts/installer_doctor.py`.
- Added `scripts/repair_legacy_python_environment.py`, plan-only by default.
- Added `scripts/data/duckdb_export.py`.
- Added 20 offline installer regression tests.

## Compatibility

- All 385 packaged v3.9.7.2 paths are preserved.
- All 319 `tbhm.py` CLI options are preserved. The project-wide parser inventory preserves all 332 v3.9.7.2 option strings and adds seven helper-script options.
- All 129 phase modules are preserved; no phase was added, removed or reordered by this installer-only release.
- Four source/test helper paths are added before release documentation and manifest generation.
- No scanner, report, evidence contract, profile or safety boundary was intentionally removed.

## Important recovery note

A machine that already ran the v3.9.7.2 full installer may contain shared-user Python conflicts. First run:

```bash
python3 scripts/installer_doctor.py
python3 scripts/repair_legacy_python_environment.py
```

Review the plan before using `--apply`. The cleanup helper intentionally does not uninstall or downgrade shared dependency libraries.
