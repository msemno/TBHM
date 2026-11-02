# TBHM v3.9.7.3 Backward-Compatibility Report

Baseline: `TBHM-v3.9.7.2-historical-coverage-restored`  
Final: `TBHM-v3.9.7.3-installer-stability`

## Measured source compatibility

- Baseline packaged paths: **385**
- Missing baseline paths: **0**
- Added implementation/test paths before release docs/manifests: **4**
- Baseline project-wide CLI option strings: **332**
- Missing baseline CLI option strings: **0**
- Baseline phase modules: **129**
- Missing phase modules: **0**
- Added phase modules: **0**

The seven additional argument strings measured across the entire Python tree belong to the new installer/diagnostic helper scripts. The primary `tbhm.py` parser remains exactly **319** options in both releases; the project-wide inventory grows from 332 to 339 with zero removals.

## Added paths

- `integration_test_v3973_installer.py`
- `scripts/data/duckdb_export.py`
- `scripts/installer_doctor.py`
- `scripts/repair_legacy_python_environment.py`

## Behavioral compatibility

No scan phase, reporting output, evidence path, profile, schema consumer, safe-plan restriction or historical regression fixture was intentionally removed. The release changes how optional dependencies are installed and located. This is a correctness and host-integrity improvement; existing globally installed tools remain discoverable, while legacy shared-user pip launchers are not treated as proof of a healthy isolated installation.

## Breaking changes

There are no intentional `tbhm.py` CLI or phase breaking changes. A deprecated kubeaudit auto-install command is no longer executed because the upstream recipe is archived/invalid; its catalog/import compatibility remains. Unsupported Python/tool combinations are now skipped instead of being attempted.
