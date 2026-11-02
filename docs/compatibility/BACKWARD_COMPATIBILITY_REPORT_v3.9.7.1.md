# TBHM v3.9.7.1 Backward-Compatibility Report

Baseline: `3.9.6-enterprise-control-plane`  
Final: `3.9.7.1-backward-compatibility`

## Measured summary

- Files: 322 baseline, 365 final; 0 missing original paths.
- CLI option strings: 300 baseline, 330 final; 0 missing.
- Ordered phases: 124 baseline, 129 final; 0 missing and 5 added.
- Zero unintentional removals target: **PASS**

## New phases

- `integration_adapter_proposal`
- `osint_api_collectors`
- `passive_wireless_inventory`
- `safe_plan_execution`
- `session_beacon_import`

## Added compatibility aliases

- REPORT.json -> report.json equivalent
- REPORT.csv -> report.csv equivalent
- REPORT.sarif -> report.sarif equivalent
- legacy reporter helpers
- legacy scanner sev/walk wrappers
- legacy reverse import_json/static_strings wrappers

## Intentionally hardened behavior

- Malformed Nuclei YAML no longer counts as a usable template.
- Header-based admin bypass requires a direct /admin control differential.
- Sensitive-file probes reject same-host catch-all responses and generic HTML shells.
- Canonical profile ordering ensures preflight precedes operational phases and report/finalization remains last.

## Missing baseline contracts

- Paths: none
- CLI options: none
- Phases: none
- Report paths: none
- Schema identifiers: none

## Known breaking changes

- None identified in the supplied v3.9.6 public path, CLI, phase, output, or schema surface. The stricter false-positive behavior above is intentional correctness hardening.
