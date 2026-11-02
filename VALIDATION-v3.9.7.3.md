# TBHM v3.9.7.3 Validation Record

Validation date: 2026-07-19

## Source and configuration

- Python compileall: PASS
- JSON parsing: PASS
- YAML parsing: PASS
- Shell syntax (`bash -n`): PASS
- Primary CLI help smoke test: PASS
- Capability-status smoke test: PASS
- Installer doctor JSON generation: PASS
- Legacy cleanup plan JSON generation: PASS
- Static search for unrestricted `shell=True`: PASS
- Static search for embedded private-key blocks: PASS

## Installer planning

The full `all-safe` catalog plan selected 489 catalog entries. It produced 63 planned installers, 418 policy/no-recipe skips, four interpreter-incompatible skips, three unavailable installer-runtime skips, one deprecated skip, and zero generic failures in the offline build environment.

## Regression suites

All 14 integration scripts passed:

- `integration_test_addons.py`
- `integration_test_ai_plane.py`
- `integration_test_historical_regressions_v3971.py` — 21 tests
- `integration_test_v391_safe.py`
- `integration_test_v392.py`
- `integration_test_v393.py`
- `integration_test_v3941.py`
- `integration_test_v395.py` — 13 tests
- `integration_test_v396.py` — 11 tests
- `integration_test_v3961.py` — 12 tests
- `integration_test_v3971.py` — 13 tests
- `integration_test_v3972.py` — 9 tests
- `integration_test_v3973_installer.py` — 20 tests
- `integration_test_v39_safe.py`

## Compatibility

- 385/385 baseline v3.9.7.2 packaged paths preserved before release-document additions.
- 319/319 `tbhm.py` CLI options preserved; 332/332 project-wide v3.9.7.2 option strings preserved.
- 129/129 phase modules preserved.
- Zero missing baseline paths, primary CLI options or phase modules.

## Installation-test limitation

Automated tests did not perform a full live network installation of every external apt, npm, pip, Cargo, Go, Ruby and Composer dependency. Such results depend on current repositories, mirrors, OS packages and network access. The installer now preflights and records those states instead of claiming that unavailable or incompatible tools installed successfully.

## Final package verification

- ZIP integrity (`zip -T`): PASS.
- 394/394 manifest-listed file hashes matched after a fresh extraction.
- Full 14-script integration matrix passed again from the fresh extraction.
- Clean-extraction all-safe installer plan: 63 planned, 418 policy skips, four interpreter-incompatible skips, three unavailable-runtime skips, one deprecated skip, zero failures.
- Packaged cache/log/collected-result exclusion check: PASS.
