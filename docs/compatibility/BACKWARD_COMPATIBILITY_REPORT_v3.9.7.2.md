# TBHM v3.9.7.2 Backward-Compatibility Report

Immediate baseline: `3.9.7.1-backward-compatibility`  
Historical implementation baseline: original `3.9.6-enterprise-control-plane`  
Final: `3.9.7.2-historical-coverage-restored`

## Contract preservation

- No file from the packaged v3.9.7.1 tree was removed.
- All 330 v3.9.7.1 CLI option strings remain available; two opt-in code-scan options were added.
- All 129 v3.9.7.1 phases remain, with unchanged canonical ordering.
- Existing report, evidence, compliance, cloud-IAM, and OCSF paths remain available.
- The legacy capability-registry filename remains the default compatibility path; its internal registry version is 3.9.7.2.

## Added CLI options

- `--code-scan-data-files`
- `--code-scan-extra-extensions LIST`

Both are disabled unless explicitly selected.

## Output compatibility fixes

- Compliance records include both modern and historical field names.
- Historical CSV columns are retained.
- A legacy compliance summary is additive and does not replace the authoritative summary.
- OCSF fallback UIDs remain stable for findings without explicit IDs.
- Cloud IAM continues to write `cloud_identity_paths.json`.

## Intentional behavior changes

- CI/CD scans regain historical file classes and rules.
- Cloud IAM analyzes all matching providers in a file rather than selecting one.
- Data/document secret and sink review is available only through explicit opt-in and is more conservative than the old implementation.

## Known breaking changes

None identified in the supplied path, CLI, phase, profile, report-path, or schema surface. Stricter redaction and lead-only handling in the opt-in data/document mode are intentional safety improvements.
