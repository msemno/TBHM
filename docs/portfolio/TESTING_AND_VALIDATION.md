# Test strategy and evidence interpretation

## What was reported as validated (2 November 2026 source preparation)

| Check | Reported evidence | Boundary |
| --- | --- | --- |
| Package manifest | All 1,232 final entries verified in publication tree | Local byte inventory, not independent signature |
| Local initial Git staging | 1,233 files including manifest; no unexpected paths | Local commit, not remote publication |
| Fresh local clone | Offline wheel install and dependency check passed | No external scanners/real model exercised |
| Python modules | Compile and import checks passed | Runtime path correctness depends on inputs |
| Dispatcher registry | 145 phase names resolve to `run()` modules | Not 145 live execution results |
| Publication-preparation regression | 88/88 script groups reported passed in kit review | Specific reviewed build only |
| Gitleaks controls | Positive, negative and nested-archive controls passed in supplied Kali logs | Pattern detection, not absence of all secrets |

**Caution:** these statuses come from the *supplied publication kit and command log*, not a new run performed on the eventual GitHub checkout. They must be refreshed after substantive source or manifest changes.

## Reproduce locally

```bash
cd "$HOME/publish/TBHM"
./tbhm --version
.venv/bin/python -m pip check
.venv/bin/python scripts/validate_v4_release.py
.venv/bin/python scripts/run_tests.py --source . --workers 1 \
  --output "$HOME/tbhm-work/publication/full-regression-v427.json"
```

The full regression command can take longer than simple import/manifest validation; inspect the resulting JSON rather than inferring success from a prompt or one log line.

## Important test families

The supplied release documentation names tampered/replayed proof, forged captures, DB reopen/redaction, loopback HTTP boundary, delivery snapshot consistency, parser classification, and verified controls for supported findings. Those are grouped by *behavior*, not claimed as separate live-target achievements. Use actual test files in `tests/` and the release review artifacts to ground further claims.

## When adding a documentation-only overlay

The included overlay applier requires every current manifest entry to match **before** applying any documentation changes. It adds this documentation, saves the previous README, updates only their metadata and the release manifest, and re-verifies file contents. It does not claim to have re-executed the full test suite. Re-run the built-in validator and review the Git diff on Kali after application.

## CI design before claiming it

A future GitHub Actions setup could run installation validation, static checks, unit/regression subsets, manifest integrity, and secret scanning with controlled fixture handling. **This pack does not add a pipeline or claim that CI passed.** Make a separate CI PR with branch protection, minimal workflow permissions, reproducible runner/architecture, pinned actions and a documented test matrix. Record whether an external-tool test actually ran or was skipped.
